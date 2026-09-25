//! Closed registry for every advertised SQL and privileged apply path.

use super::*;
use oraclemcp_db::{CatalogBindKind, ReadQueryProvenance};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolRoute {
    NoSql,
    CallerOrServerRead,
    CatalogRead,
    TemporaryDml,
    PrivilegedApply,
}

fn registered_route(name: &str) -> Option<ToolRoute> {
    use ToolRoute::{CallerOrServerRead as Read, CatalogRead, NoSql, PrivilegedApply as Apply};
    Some(match name {
        "oracle_list_profiles" | "oracle_switch_profile" | "switch_database" => NoSql,
        // These report connection metadata through ping/describe, not SQL.
        "oracle_connection_info" | "current_database" => NoSql,
        "oracle_set_session_level" | "enable_writes" | "disable_writes" => Apply,
        "oracle_query"
        | "query"
        | "oracle_semantic_search"
        | "oracle_diff"
        | "oracle_sample_rows"
        | "oracle_read_clob"
        | "get_clob"
        | "oracle_explain_plan" => Read,
        // The preview executes guarded DML under a savepoint and rolls it
        // back; it does not issue a read query to the provenance connection.
        "oracle_preview_dml" => ToolRoute::TemporaryDml,
        "oracle_preview_sql"
        | "preview_sql"
        | "oracle_execute"
        | "execute_approved"
        | "deploy_ddl"
        | "oracle_compile_object"
        | "compile_object"
        | "compile_with_warnings"
        | "oracle_create_or_replace"
        | "create_or_replace"
        | "oracle_patch_source"
        | "patch_package"
        | "patch_view"
        | "read_patch_preview" => Apply,
        "synthetic_write_without_apply_gate" => Apply,
        "oracle_checkpoint" | "oracle_undo_to" => NoSql,
        "oracle_list_schemas"
        | "list_schemas"
        | "oracle_schema_inspect"
        | "list_objects"
        | "get_schema"
        | "oracle_search_objects"
        | "oracle_orient"
        | "oracle_describe"
        | "describe_table"
        | "oracle_describe_index"
        | "describe_index"
        | "oracle_describe_trigger"
        | "describe_trigger"
        | "oracle_describe_view"
        | "describe_view"
        | "oracle_get_ddl"
        | "get_ddl"
        | "oracle_get_source"
        | "get_object_source"
        | "oracle_compile_errors"
        | "get_errors"
        | "oracle_search_source"
        | "oracle_plscope_inspect"
        | "oracle_top_queries"
        | "oracle_plan_timeline"
        | "oracle_db_health" => CatalogRead,
        "oracle_plsql_parse"
        | "oracle_plsql_analyze"
        | "oracle_plsql_what_breaks"
        | "oracle_plsql_lineage"
        | "oracle_lineage"
        | "oracle_plsql_sast"
        | "oracle_plsql_doc" => NoSql,
        "oracle_plsql_live_snapshot" | "oracle_plsql_blast_radius" => CatalogRead,
        _ => return None,
    })
}

fn registry_accepts(name: &str, reclassified_at_apply: bool) -> Result<(), &'static str> {
    match registered_route(name) {
        None => Err("unregistered path"),
        Some(ToolRoute::PrivilegedApply) if !reclassified_at_apply => {
            Err("privileged path has no apply-time reclassification")
        }
        Some(_) => Ok(()),
    }
}

fn validate_dispatched_provenance(
    route: Option<ToolRoute>,
    tagged_before: usize,
    untagged_before: usize,
    log: &ProvenanceLog,
) -> Result<(), &'static str> {
    if log.untagged.load(Ordering::SeqCst) > untagged_before {
        return Err("dispatch issued untagged SQL");
    }
    let route = route.ok_or("unregistered path")?;
    let tagged_after = log.tags.lock().expect("provenance log").len();
    if matches!(
        route,
        ToolRoute::CallerOrServerRead | ToolRoute::CatalogRead
    ) && tagged_after == tagged_before
    {
        return Err("DB read route issued no provenance-tagged query");
    }
    Ok(())
}

#[derive(Default)]
struct ProvenanceLog {
    tags: Mutex<Vec<ReadQueryProvenance>>,
    untagged: AtomicUsize,
}

struct ProvenanceCheckingConn(Arc<ProvenanceLog>);

#[async_trait::async_trait(?Send)]
impl OracleConnection for ProvenanceCheckingConn {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        OneRowMock.describe(cx).await
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.0.untagged.fetch_add(1, Ordering::SeqCst);
        OneRowMock.query_rows(cx, sql, binds).await
    }

    async fn query_rows_with_provenance(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        provenance: ReadQueryProvenance,
        _serialize_opts: Option<&SerializeOptions>,
    ) -> Result<Vec<OracleRow>, DbError> {
        self.0.tags.lock().expect("provenance log").push(provenance);
        OneRowMock.query_rows(cx, sql, binds).await
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

fn catalog_binds(id: CatalogQueryId) -> Vec<OracleBind> {
    id.spec()
        .binds
        .0
        .iter()
        .map(|kind| match kind {
            CatalogBindKind::Text | CatalogBindKind::NullableText => {
                OracleBind::String("SYNTHETIC".to_owned())
            }
            CatalogBindKind::Integer | CatalogBindKind::NullableInteger => OracleBind::I64(1),
        })
        .collect()
}

#[test]
fn every_sql_path_goes_through_the_read_executor() {
    let advertised = crate::registry::tool_registry().tools;
    let runtime_names = crate::registry::tool_names();
    let registry_names = advertised
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        runtime_names
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        registry_names,
        "tool_names and the runtime descriptor registry must describe the same surface"
    );
    let log = Arc::new(ProvenanceLog::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ProvenanceCheckingConn(Arc::clone(&log))),
        Some("dev".to_owned()),
        read_write_level(),
    );
    for name in runtime_names {
        let route = registered_route(name);
        assert!(
            route.is_some(),
            "runtime tool {name} has no route registration"
        );
        let tagged_before = log.tags.lock().expect("provenance log").len();
        let untagged_before = log.untagged.load(Ordering::SeqCst);

        // Exercise the real in-process dispatch path with the same synthetic,
        // schema-valid arguments used by the registry routing tests. A refusal
        // is acceptable, but a raw SQL call or a read route that never reaches
        // the provenance-aware connection is not.
        let result = dispatcher.dispatch(name, args_for(name));
        if name == "oracle_plan_timeline" {
            let error = result.expect_err("no license attestation must refuse plan history");
            assert_eq!(error.error_class, ErrorClass::PolicyDenied);
            assert_eq!(
                log.tags.lock().expect("provenance log").len(),
                tagged_before,
                "unlicensed plan history must refuse before catalog SQL"
            );
            assert_eq!(
                log.untagged.load(Ordering::SeqCst),
                untagged_before,
                "unlicensed plan history must not issue untagged SQL"
            );
            continue;
        }
        validate_dispatched_provenance(route, tagged_before, untagged_before, &log)
            .unwrap_or_else(|error| panic!("{name}: {error}; dispatch={result:?}"));
    }
    assert_eq!(log.untagged.load(Ordering::SeqCst), 0);
    assert!(!log.tags.lock().expect("provenance log").is_empty());
}

#[test]
fn unregistered_sql_path_fails_the_registry() {
    let log = Arc::new(ProvenanceLog::default());
    let conn = ProvenanceCheckingConn(Arc::clone(&log));
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    let untagged_before = log.untagged.load(Ordering::SeqCst);
    let tagged_before = log.tags.lock().expect("provenance log").len();
    runtime.block_on(async {
        let cx = Cx::current().expect("runtime installs a current Cx");
        // This is the planted regression route: it bypasses the executor and
        // reaches the instrumented connection with raw query_rows.
        conn.query_rows(&cx, "SELECT 1 FROM dual", &[])
            .await
            .expect("the raw mock connection records the planted untagged call");
    });
    assert_eq!(log.untagged.load(Ordering::SeqCst), untagged_before + 1);
    assert_eq!(
        validate_dispatched_provenance(
            registered_route("synthetic_unregistered_tool"),
            tagged_before,
            untagged_before,
            &log,
        ),
        Err("dispatch issued untagged SQL"),
        "the same registry audit used for runtime tools must reject the planted raw route"
    );
}

#[test]
fn every_catalog_query_id_is_registered() {
    let ids = CatalogQueryId::ALL;
    for (index, id) in ids.iter().enumerate() {
        assert!(
            !ids[..index].contains(id),
            "catalog query registry repeats {id:?}"
        );
    }
    assert!(ids.iter().all(|id| {
        let spec = id.spec();
        !spec.sql.is_empty() && spec.sql.starts_with("SELECT ")
    }));

    let log = Arc::new(ProvenanceLog::default());
    let conn = ProvenanceCheckingConn(Arc::clone(&log));
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("runtime installs a current Cx");
        for id in ids {
            run_catalog_query(&cx, &conn, id, &catalog_binds(id))
                .await
                .unwrap_or_else(|error| panic!("{id:?}: {error}"));
        }
    });
    let tags = log.tags.lock().expect("provenance log");
    assert_eq!(tags.len(), ids.len());
    for (actual, id) in tags.iter().zip(ids) {
        assert_eq!(*actual, ReadQueryProvenance::Catalog(id));
    }
    assert_eq!(log.untagged.load(Ordering::SeqCst), 0);
}

#[test]
fn privileged_paths_reclassify_at_apply() {
    for name in [
        "oracle_execute",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
        "oracle_set_session_level",
        "enable_writes",
        "disable_writes",
        "execute_approved",
        "deploy_ddl",
        "compile_object",
        "compile_with_warnings",
        "create_or_replace",
        "patch_package",
        "patch_view",
        "read_patch_preview",
    ] {
        assert_eq!(registered_route(name), Some(ToolRoute::PrivilegedApply));
        assert!(registry_accepts(name, true).is_ok());
        assert!(
            crate::registry::tool_names().contains(&name),
            "apply path {name} is absent from the advertised registry"
        );
    }
}

#[test]
fn synthetic_privileged_path_without_reclassification_fails() {
    assert_eq!(
        registry_accepts("synthetic_write_without_apply_gate", false),
        Err("privileged path has no apply-time reclassification")
    );
}
