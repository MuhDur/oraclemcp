//! Bounded, current-container DDL system-trigger collection. ALL_TRIGGERS alone
//! never proves DATABASE-trigger absence; the authoritative snapshot uses DBA_TRIGGERS.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use asupersync::Cx;
use oraclemcp_guard::ddl_closure::*;
use oraclemcp_guard::mutation_closure::{
    MutationComputation, MutationDatabaseIdentity, MutationUnavailableReason as Unknown,
};
use oraclemcp_guard::{RoutineEffect, RoutineEffectsV1};
use sha2::{Digest, Sha256};

use crate::mutation_closure::{
    MutationEffectOracle, MutationRoutineUse, read_mutation_routine_source,
};
use crate::{
    CatalogQueryId, OracleConnection, OracleRow, read_closure_database_identity, run_catalog_query,
};

/// A bounded snapshot includes a sentinel row; exhausting it is Unknown.
pub const MAX_DDL_TRIGGER_ROWS: usize = 256;
const MAX_SOURCE_ROWS: usize = 16_384;
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    let mut hash = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut hash, "{byte:02x}").expect("String write");
    }
    hash
}

fn rows_digest(rows: &[OracleRow]) -> String {
    let mut canonical: Vec<Vec<u8>> = rows
        .iter()
        .map(|row| {
            let cells: BTreeMap<_, _> = row
                .columns
                .iter()
                .map(|(name, cell)| (name, (cell, cell.source_length)))
                .collect();
            serde_json::to_vec(&cells).expect("serializable catalog cells")
        })
        .collect();
    canonical.sort();
    digest(&serde_json::to_vec(&canonical).expect("serializable rows"))
}

fn optional(row: &OracleRow, column: &str) -> Result<Option<String>, Unknown> {
    let cell = row.cell(column).ok_or(Unknown::CatalogIncomplete)?;
    if cell.bytes.is_some()
        || cell.structured.is_some()
        || cell.structured_contract_version.is_some()
        || cell.nested_result.is_some()
        || cell
            .source_length
            .is_some_and(|length| length > cell.value.as_deref().unwrap_or("").chars().count())
    {
        return Err(Unknown::CatalogIncomplete);
    }
    Ok(cell.value.clone())
}

fn required(row: &OracleRow, column: &str) -> Result<String, Unknown> {
    optional(row, column)?
        .filter(|value| !value.is_empty())
        .ok_or(Unknown::CatalogIncomplete)
}

fn hash_is_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn event_set(text: &str) -> Result<BTreeSet<DdlEvent>, Unknown> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err(Unknown::CatalogIncomplete);
    }
    let mut result = BTreeSet::new();
    let mut database_event = false;
    for event in normalized.split(" OR ") {
        if let Some(event) = DdlEvent::from_catalog(event) {
            if !result.insert(event) {
                return Err(Unknown::CatalogIncomplete);
            }
        } else if matches!(
            event,
            "LOGON"
                | "LOGOFF"
                | "STARTUP"
                | "SHUTDOWN"
                | "SERVERERROR"
                | "DB_ROLE_CHANGE"
                | "SUSPEND"
                | "CLONE"
                | "UNPLUG"
                | "SET CONTAINER"
        ) {
            database_event = true;
        } else {
            return Err(Unknown::UnsupportedMechanism);
        }
    }
    if database_event && !result.is_empty() {
        return Err(Unknown::UnsupportedMechanism);
    }
    Ok(result)
}

fn selected_trigger(
    row: &OracleRow,
    closure: &DdlEffectClosureV1,
) -> Result<Option<DdlTriggerFact>, Unknown> {
    let status = required(row, "STATUS")?;
    if status == "DISABLED" {
        return Ok(None);
    }
    if status != "ENABLED" {
        return Err(Unknown::CatalogIncomplete);
    }
    let scope = match required(row, "BASE_OBJECT_TYPE")?.as_str() {
        "SCHEMA" => DdlTriggerScope::Schema,
        "DATABASE" => DdlTriggerScope::Database,
        _ => return Err(Unknown::CatalogIncomplete),
    };
    // A SCHEMA trigger belongs to TABLE_OWNER, which can differ from OWNER.
    // It fires for the connected schema, not the DDL target's object owner:
    // https://docs.oracle.com/en/database/oracle/oracle-database/21/lnpls/CREATE-TRIGGER-statement.html
    let schema = optional(row, "TABLE_OWNER")?;
    if scope == DdlTriggerScope::Schema {
        if schema.as_deref().is_none_or(str::is_empty) {
            return Err(Unknown::CatalogIncomplete);
        }
        if schema != closure.session_user {
            return Ok(None);
        }
    }
    let events = event_set(&required(row, "TRIGGERING_EVENT")?)?;
    if !events.contains(&closure.event) && !events.contains(&DdlEvent::Ddl) {
        return Ok(None);
    }
    let timing = required(row, "TRIGGER_TYPE")?;
    if !matches!(timing.as_str(), "BEFORE EVENT" | "AFTER EVENT")
        // Oracle emits the fixed-width catalog discriminator as "PL/SQL     ".
        // Keep its original bytes in metadata_sha256; normalize only padding.
        || required(row, "ACTION_TYPE")?.trim_end_matches(' ') != "PL/SQL"
        || required(row, "CROSSEDITION")? != "NO"
    {
        return Err(Unknown::UnsupportedMechanism);
    }
    let predicate =
        DdlPredicate::from_catalog(optional(row, "WHEN_CLAUSE")?.as_deref(), &closure.object);
    Ok(Some(DdlTriggerFact {
        owner: required(row, "OWNER")?,
        name: required(row, "TRIGGER_NAME")?,
        object_id: 0,
        last_ddl_time: String::new(),
        scope,
        schema,
        timing,
        events,
        status,
        predicate,
        metadata_sha256: rows_digest(std::slice::from_ref(row)),
        source_sha256: None,
        routine_closure_fingerprint: None,
        effects: RoutineEffectsV1::new([RoutineEffect::Unknown]),
        computation: MutationComputation::Unavailable {
            reason: Unknown::EffectProofUnavailable,
        },
    }))
}

async fn context(cx: &Cx, conn: &dyn OracleConnection) -> Result<(String, String), Unknown> {
    let rows = run_catalog_query(cx, conn, CatalogQueryId::DdlSessionContext, &[])
        .await
        .map_err(|_| Unknown::CatalogUnreadable)?;
    let [row] = rows.as_slice() else {
        return Err(Unknown::CatalogIncomplete);
    };
    Ok((
        required(row, "SESSION_USER")?,
        required(row, "CURRENT_SCHEMA")?,
    ))
}

async fn snapshot(cx: &Cx, conn: &dyn OracleConnection) -> Result<Vec<OracleRow>, Unknown> {
    let rows = run_catalog_query(
        cx,
        conn,
        CatalogQueryId::DdlTriggers,
        &[((MAX_DDL_TRIGGER_ROWS + 1) as i64).into()],
    )
    .await
    .map_err(|_| Unknown::CatalogUnreadable)?;
    if rows.len() > MAX_DDL_TRIGGER_ROWS {
        return Err(Unknown::RowCapExhausted);
    }
    Ok(rows)
}

/// Collect with a consumer-supplied engine binding, preserving typed uncertainty.
/// A profile without positive DATABASE-trigger visibility gets Unknown even
/// when it can read its own SCHEMA triggers. Consumers recollect at apply.
pub async fn collect_ddl_effect_closure(
    cx: &Cx,
    conn: &dyn OracleConnection,
    event: DdlEvent,
    object: DdlObject,
    container: &str,
    effects: &dyn MutationEffectOracle,
) -> DdlEffectClosureV1 {
    let mut closure = DdlEffectClosureV1::new(event, object);
    if container.is_empty()
        || event == DdlEvent::Ddl
        || [
            &closure.object.owner,
            &closure.object.name,
            &closure.object.object_type,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 128 || value.contains('\0'))
    {
        closure.unavailable.insert(Unknown::InvalidInput);
        return closure;
    }
    if let Err(reason) = collect(cx, conn, container, effects, &mut closure).await {
        closure.unavailable.insert(reason);
    }
    closure
}

async fn collect(
    cx: &Cx,
    conn: &dyn OracleConnection,
    container: &str,
    effects: &dyn MutationEffectOracle,
    closure: &mut DdlEffectClosureV1,
) -> Result<(), Unknown> {
    let identity = read_closure_database_identity(cx, conn)
        .await
        .map_err(|_| Unknown::CatalogUnreadable)?;
    if identity.container != container {
        return Err(Unknown::IdentityMismatch);
    }
    closure.database = Some(MutationDatabaseIdentity {
        dbid: identity.dbid.clone(),
        container: identity.container.clone(),
        edition: identity.edition.clone(),
    });
    let session = context(cx, conn).await?;
    closure.session_user = Some(session.0.clone());
    closure.current_schema = Some(session.1.clone());
    let rows = snapshot(cx, conn).await?;
    closure.database_triggers_visible = true;
    closure.catalog_row_count = rows.len() as u32;
    closure.catalog_sha256 = Some(rows_digest(&rows));
    let mut seen = BTreeSet::new();
    let mut source_rows = 0usize;
    let mut source_bytes = 0usize;
    for row in &rows {
        let mut fact = match selected_trigger(row, closure) {
            Ok(Some(fact)) => fact,
            Ok(None) => continue,
            Err(reason) => {
                closure.unavailable.insert(reason);
                continue;
            }
        };
        if !seen.insert((fact.owner.clone(), fact.name.clone())) {
            return Err(Unknown::CatalogIncomplete);
        }
        let result = async {
            let mut source =
                read_mutation_routine_source(cx, conn, &fact.owner, &fact.name, "TRIGGER", None)
                    .await?;
            source.use_context = MutationRoutineUse::DdlTrigger;
            fact.object_id = source.object_id;
            fact.last_ddl_time = source.last_ddl_time.clone();
            fact.source_sha256 = Some(source.source_sha256.clone());
            source_rows = source_rows.saturating_add(source.source_line_count);
            source_bytes = source_bytes.saturating_add(source.source.len());
            if source_rows > MAX_SOURCE_ROWS || source_bytes > MAX_SOURCE_BYTES {
                return Err(Unknown::ClosureCapExhausted);
            }
            if matches!(fact.predicate, DdlPredicate::Unknown { .. }) {
                return Err(Unknown::UnsupportedMechanism);
            }
            let proof = effects.prove_source(cx, conn, &source).await?;
            if proof.source_sha256 != source.source_sha256
                || proof.use_context != MutationRoutineUse::DdlTrigger
                || !hash_is_valid(&proof.closure_fingerprint)
            {
                return Err(Unknown::EffectSourceMismatch);
            }
            fact.effects = proof.effects;
            fact.routine_closure_fingerprint = Some(proof.closure_fingerprint);
            if fact
                .effects
                .iter()
                .any(|effect| effect == RoutineEffect::Unknown)
            {
                return Err(Unknown::EffectProofUnavailable);
            }
            let mut fresh =
                read_mutation_routine_source(cx, conn, &fact.owner, &fact.name, "TRIGGER", None)
                    .await?;
            fresh.use_context = MutationRoutineUse::DdlTrigger;
            if source != fresh {
                return Err(Unknown::EffectSourceMismatch);
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => fact.computation = MutationComputation::Computed,
            Err(reason) => {
                fact.computation = MutationComputation::Unavailable { reason };
                closure.unavailable.insert(reason);
            }
        }
        closure.triggers.push(fact);
    }
    if rows_digest(&snapshot(cx, conn).await?) != closure.catalog_sha256.clone().unwrap_or_default()
        || context(cx, conn).await? != session
        || read_closure_database_identity(cx, conn)
            .await
            .map_err(|_| Unknown::CatalogUnreadable)?
            != identity
    {
        return Err(Unknown::EffectSourceMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation_closure::{MutationRoutineProof, MutationRoutineSource};
    use crate::{DbError, OracleBackend, OracleBind, OracleCell, OracleConnectionInfo};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn row(cells: &[(&str, Option<&str>)]) -> OracleRow {
        OracleRow {
            columns: cells
                .iter()
                .map(|(key, value)| {
                    (
                        (*key).into(),
                        OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                    )
                })
                .collect(),
        }
    }

    fn trigger(event: &str) -> OracleRow {
        row(&[
            ("OWNER", Some("OWNER_OF_TRIGGER")),
            ("TRIGGER_NAME", Some("DDL_TR")),
            ("TABLE_OWNER", Some("APP")),
            ("BASE_OBJECT_TYPE", Some("SCHEMA")),
            ("TRIGGER_TYPE", Some("BEFORE EVENT")),
            ("TRIGGERING_EVENT", Some(event)),
            ("STATUS", Some("ENABLED")),
            ("ACTION_TYPE", Some("PL/SQL")),
            ("WHEN_CLAUSE", None),
            ("CROSSEDITION", Some("NO")),
        ])
    }

    fn set(row: &mut OracleRow, column: &str, value: &str) {
        row.columns
            .iter_mut()
            .find(|(key, _)| key == column)
            .unwrap()
            .1 = OracleCell::new("VARCHAR2", Some(value.into()));
    }

    #[derive(Default)]
    struct Catalog {
        rows: Vec<OracleRow>,
        denied: bool,
        source_missing: bool,
        source_changes: bool,
        catalog_changes: bool,
        source_reads: AtomicUsize,
        snapshot_reads: AtomicUsize,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for Catalog {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn ping(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn execute(&self, _: &Cx, _: &str, _: &[OracleBind]) -> Result<u64, DbError> {
            panic!("collector must not execute DDL")
        }
        async fn commit(&self, _: &Cx) -> Result<(), DbError> {
            panic!("collector must not commit")
        }
        async fn rollback(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn query_rows(
            &self,
            _: &Cx,
            sql: &str,
            _: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if sql == CatalogQueryId::ClosureIdentity.spec().sql {
                return Ok(vec![row(&[
                    ("DBID", Some("1")),
                    ("CONTAINER_NAME", Some("FREEPDB1")),
                    ("EDITION_NAME", Some("ORA$BASE")),
                ])]);
            }
            if sql == CatalogQueryId::DdlSessionContext.spec().sql {
                return Ok(vec![row(&[
                    ("SESSION_USER", Some("APP")),
                    ("CURRENT_SCHEMA", Some("OTHER")),
                ])]);
            }
            if sql == CatalogQueryId::DdlTriggers.spec().sql {
                if self.denied {
                    return Err(DbError::ServerQuery(
                        "ORA-00942: table or view does not exist".into(),
                    ));
                }
                let mut rows = self.rows.clone();
                if self.snapshot_reads.fetch_add(1, Ordering::Relaxed) > 0 && self.catalog_changes {
                    rows.clear();
                }
                return Ok(rows);
            }
            if sql == CatalogQueryId::ClosureMemberObject.spec().sql {
                return Ok(vec![row(&[
                    ("OBJECT_ID", Some("42")),
                    ("LAST_DDL_TIME", Some("2026-10-31T00:00:00")),
                    ("STATUS", Some("VALID")),
                ])]);
            }
            if sql == CatalogQueryId::ClosureCompilerSettings.spec().sql {
                return Ok(vec![row(&[
                    ("PLSQL_OPTIMIZE_LEVEL", Some("2")),
                    ("PLSQL_CODE_TYPE", Some("INTERPRETED")),
                    ("PLSQL_DEBUG", Some("FALSE")),
                    ("PLSQL_WARNINGS", Some("DISABLE:ALL")),
                    ("PLSQL_CCFLAGS", None),
                    ("NLS_LENGTH_SEMANTICS", Some("BYTE")),
                    ("PLSCOPE_SETTINGS", Some("IDENTIFIERS:NONE")),
                ])]);
            }
            if sql == CatalogQueryId::ClosureSource.spec().sql {
                if self.source_missing {
                    return Ok(vec![]);
                }
                let changed =
                    self.source_reads.fetch_add(1, Ordering::Relaxed) > 0 && self.source_changes;
                return Ok(vec![row(&[
                    ("LINE", Some("1")),
                    (
                        "TEXT",
                        Some(if changed {
                            "TRIGGER DDL_TR BEFORE CREATE ON SCHEMA BEGIN NULL; NULL; END;\n"
                        } else {
                            "TRIGGER DDL_TR BEFORE CREATE ON SCHEMA BEGIN NULL; END;\n"
                        }),
                    ),
                ])]);
            }
            panic!("unexpected catalog query: {sql}");
        }
    }

    struct Effects {
        wrong_source: bool,
    }
    #[async_trait::async_trait(?Send)]
    impl MutationEffectOracle for Effects {
        async fn prove_source(
            &self,
            _: &Cx,
            _: &dyn OracleConnection,
            source: &MutationRoutineSource,
        ) -> Result<MutationRoutineProof, Unknown> {
            assert_eq!(source.use_context, MutationRoutineUse::DdlTrigger);
            Ok(MutationRoutineProof {
                use_context: source.use_context,
                source_sha256: if self.wrong_source {
                    "e".repeat(64)
                } else {
                    source.source_sha256.clone()
                },
                closure_fingerprint: "d".repeat(64),
                effects: RoutineEffectsV1::new([RoutineEffect::ReadDb]),
                mutations: Vec::new(),
            })
        }
    }

    fn collect_test(catalog: &Catalog, effects: &Effects) -> DdlEffectClosureV1 {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("Cx");
            collect_ddl_effect_closure(
                &cx,
                catalog,
                DdlEvent::Create,
                DdlObject {
                    owner: "OTHER".into(),
                    name: "T".into(),
                    object_type: "TABLE".into(),
                },
                "FREEPDB1",
                effects,
            )
            .await
        })
    }

    fn supported(rows: Vec<OracleRow>) -> DdlEffectClosureV1 {
        collect_test(
            &Catalog {
                rows,
                ..Default::default()
            },
            &Effects {
                wrong_source: false,
            },
        )
    }

    #[test]
    fn ddl_closure_catch_all_ddl_trigger_fires_for_create() {
        let closure = supported(vec![trigger("DDL")]);
        assert!(closure.is_complete());
        assert_eq!(closure.triggers.len(), 1);
        assert_eq!(closure.triggers[0].events, BTreeSet::from([DdlEvent::Ddl]));
    }

    #[test]
    fn ddl_closure_before_create_on_schema_collected() {
        let mut row = trigger("CREATE OR ALTER ");
        set(&mut row, "ACTION_TYPE", "PL/SQL     ");
        let closure = supported(vec![row]);
        assert_eq!(
            closure.admit(),
            Ok(oraclemcp_guard::OperatingLevel::ReadOnly)
        );
        assert_eq!(closure.triggers[0].owner, "OWNER_OF_TRIGGER");
        assert_eq!(closure.triggers[0].schema.as_deref(), Some("APP"));
        assert_ne!(closure.session_user, closure.current_schema);
        assert_ne!(closure.object.owner, closure.session_user.clone().unwrap());
    }

    #[test]
    fn ddl_closure_disabled_trigger_excluded() {
        let mut row = trigger("DDL");
        set(&mut row, "STATUS", "DISABLED");
        let closure = supported(vec![row]);
        assert!(closure.triggers.is_empty());
        assert_eq!(
            closure.admit(),
            Ok(oraclemcp_guard::OperatingLevel::ReadOnly)
        );
    }

    #[test]
    fn ddl_closure_database_trigger_invisible_is_unknown() {
        let closure = collect_test(
            &Catalog {
                denied: true,
                ..Default::default()
            },
            &Effects {
                wrong_source: false,
            },
        );
        assert!(!closure.database_triggers_visible);
        assert_eq!(closure.admit(), Err(DdlClosureRefusal::Unknown));
    }

    #[test]
    fn ddl_closure_database_trigger_collected_and_unrelated_event_excluded() {
        let mut db = trigger("CREATE");
        set(&mut db, "BASE_OBJECT_TYPE", "DATABASE");
        set(&mut db, "TABLE_OWNER", "UNRELATED");
        let mut other = trigger("DROP");
        set(&mut other, "TRIGGER_NAME", "OTHER");
        let closure = supported(vec![db, other]);
        assert!(closure.is_complete());
        assert_eq!(closure.triggers.len(), 1);
        assert_eq!(closure.triggers[0].scope, DdlTriggerScope::Database);
    }

    #[test]
    fn ddl_closure_missing_or_unknown_trigger_facts_are_unknown() {
        for column in [
            "STATUS",
            "BASE_OBJECT_TYPE",
            "TABLE_OWNER",
            "TRIGGER_TYPE",
            "TRIGGERING_EVENT",
            "ACTION_TYPE",
            "WHEN_CLAUSE",
            "CROSSEDITION",
        ] {
            let mut incomplete = trigger("CREATE");
            incomplete.columns.retain(|(name, _)| name != column);
            assert_eq!(
                supported(vec![incomplete]).admit(),
                Err(DdlClosureRefusal::Unknown),
                "{column}"
            );
        }
        for (column, value) in [
            ("STATUS", "UNKNOWN"),
            ("TRIGGER_TYPE", "INSTEAD OF"),
            ("TRIGGERING_EVENT", "FUTURE_EVENT"),
            ("ACTION_TYPE", "CALL"),
            ("WHEN_CLAUSE", "APP.F() = 1"),
            ("CROSSEDITION", "FORWARD"),
        ] {
            let mut row = trigger("CREATE");
            set(&mut row, column, value);
            assert_eq!(
                supported(vec![row]).admit(),
                Err(DdlClosureRefusal::Unknown),
                "{column}"
            );
        }
    }

    #[test]
    fn ddl_closure_source_effect_and_catalog_changes_are_unknown() {
        for catalog in [
            Catalog {
                rows: vec![trigger("CREATE")],
                source_missing: true,
                ..Default::default()
            },
            Catalog {
                rows: vec![trigger("CREATE")],
                source_changes: true,
                ..Default::default()
            },
            Catalog {
                rows: vec![trigger("CREATE")],
                catalog_changes: true,
                ..Default::default()
            },
        ] {
            assert_eq!(
                collect_test(
                    &catalog,
                    &Effects {
                        wrong_source: false
                    }
                )
                .admit(),
                Err(DdlClosureRefusal::Unknown)
            );
        }
        let catalog = Catalog {
            rows: vec![trigger("CREATE")],
            ..Default::default()
        };
        assert_eq!(
            collect_test(&catalog, &Effects { wrong_source: true }).admit(),
            Err(DdlClosureRefusal::Unknown)
        );
    }

    #[test]
    fn ddl_closure_row_cap_and_truncated_when_clause_are_unknown() {
        let closure = supported(vec![trigger("CREATE"); MAX_DDL_TRIGGER_ROWS + 1]);
        assert!(closure.unavailable.contains(&Unknown::RowCapExhausted));
        let mut truncated = trigger("CREATE");
        let cell = &mut truncated
            .columns
            .iter_mut()
            .find(|(name, _)| name == "WHEN_CLAUSE")
            .unwrap()
            .1;
        cell.value = Some("ora_dict_obj_name = 'T'".into());
        cell.source_length = Some(4000);
        assert_eq!(
            supported(vec![truncated]).admit(),
            Err(DdlClosureRefusal::Unknown)
        );
    }
}
