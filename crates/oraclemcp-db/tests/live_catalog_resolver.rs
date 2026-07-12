//! Mock-free live checks for the Oracle dictionary resolver.

#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::{
    AuthAdapter, CatalogInvalidation, OracleCatalogResolver, OracleCatalogResolverCache,
    OracleConnectOptions, OracleConnection, RustOracleConnection, read_catalog_resolve_context,
    resolved_relations_read_purity,
};
use oraclemcp_guard::{
    CatalogGeneration, CatalogObjectKind, CatalogResolver, Purity, RawName, RawNamePart,
    Resolution, StatementRelation, StatementScope, SyntacticRole,
};

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime installs Cx");
        body(cx).await
    })
}

#[test]
fn live_relation_column_and_hidden_effect_proof_use_exact_dictionary_identity() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(&cx).await else {
            return;
        };
        let relation = name(&["dual"], SyntacticRole::FromFactor);
        let value = name(&["d", "dummy"], SyntacticRole::ValuePosition);
        let scope = StatementScope {
            aliases: vec![RawNamePart::unquoted("d")],
            common_table_expressions: Vec::new(),
            relations: vec![StatementRelation {
                name: relation.clone(),
                alias: Some(RawNamePart::unquoted("d")),
            }],
        };
        let cache = OracleCatalogResolverCache::new();
        let context = cache
            .preload(&cx, &conn, &[relation.clone(), value.clone()], scope)
            .await
            .expect("live relation and column preload");
        let Resolution::Resolved(table) = cache.resolve(&relation, &context) else {
            panic!("DUAL relation must resolve");
        };
        let Resolution::Resolved(column) = cache.resolve(&value, &context) else {
            panic!("D.DUMMY must resolve as a column");
        };
        assert_eq!(table.kind, CatalogObjectKind::Table);
        assert_eq!(column.kind, CatalogObjectKind::Column);
        assert_eq!(
            column.container.as_ref().map(|item| item.name.as_str()),
            Some("DUAL")
        );
        assert_eq!(column.identity, table.identity);
        assert_eq!(
            resolved_relations_read_purity(&cx, &conn, std::slice::from_ref(table.as_ref()))
                .await
                .expect("live hidden-effect proof"),
            Purity::ProvenReadOnly
        );
    });
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        auth_adapter: AuthAdapter::Password,
        ..Default::default()
    }
}

async fn connect_or_skip(cx: &Cx) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, test_opts()).await {
        Ok(connection) => Some(connection),
        Err(error) => {
            eprintln!(
                "[live-xe] SKIP live_catalog_resolver: no reachable Oracle ({error}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
            );
            None
        }
    }
}

fn name(parts: &[&str], role: SyntacticRole) -> RawName {
    RawName::new(parts.iter().map(|part| RawNamePart::unquoted(*part)), role)
}

async fn execute_ddl(cx: &Cx, conn: &dyn OracleConnection, sql: &str) {
    conn.execute(cx, sql, &[])
        .await
        .unwrap_or_else(|error| panic!("live adversarial resolver fixture failed: {error}: {sql}"));
}

async fn execute_cleanup(cx: &Cx, conn: &dyn OracleConnection, sql: &str) {
    let _ = conn.execute(cx, sql, &[]).await;
}

async fn scalar_i64(cx: &Cx, conn: &dyn OracleConnection, sql: &str, column: &str) -> i64 {
    let rows = conn
        .query_rows(cx, sql, &[])
        .await
        .unwrap_or_else(|error| panic!("live adversarial resolver query failed: {error}: {sql}"));
    let [row] = rows.as_slice() else {
        panic!(
            "live adversarial resolver query returned {} rows: {sql}",
            rows.len()
        );
    };
    row.parse_i64(column)
        .unwrap_or_else(|| panic!("live adversarial resolver query omitted {column}: {sql}"))
}

async fn cleanup_adversarial_fixture(cx: &Cx, conn: &dyn OracleConnection, current_schema: &str) {
    execute_cleanup(
        cx,
        conn,
        "BEGIN DBMS_RLS.DROP_POLICY(USER, 'ORACLEMCP_RES6_VPD', 'ORACLEMCP_RES6_POLICY'); EXCEPTION WHEN OTHERS THEN NULL; END;",
    )
    .await;
    for sql in [
        "DROP SYNONYM ORACLEMCP_RES6_REMOTE",
        "DROP SYNONYM ORACLEMCP_RES6_FN_ALIAS",
        "DROP SYNONYM ORACLEMCP_RES6_PKG_ALIAS",
        "DROP VIEW ORACLEMCP_RES6_VIEW",
        "DROP TABLE ORACLEMCP_RES6_VPD PURGE",
        "DROP TABLE ORACLEMCP_RES6_LOG PURGE",
        "DROP FUNCTION ORACLEMCP_RES6_POLICY_FN",
        "DROP FUNCTION ORACLEMCP_RES6_HIDDEN_FN",
        "DROP FUNCTION ORACLEMCP_RES6_TARGET_A",
        "DROP FUNCTION ORACLEMCP_RES6_TARGET_B",
        "DROP FUNCTION ORACLEMCP_RES6_MEMBER",
        "DROP PACKAGE ORACLEMCP_RES6_PKG",
    ] {
        execute_cleanup(cx, conn, sql).await;
    }
    execute_cleanup(cx, conn, &format!("DROP PACKAGE {current_schema}")).await;
}

#[test]
fn live_dictionary_resolution_preserves_identity_quotes_synonyms_and_overloads() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(&cx).await else {
            return;
        };
        conn.ping(&cx).await.expect("live resolver ping");

        let generation = CatalogGeneration(17);
        let context =
            read_catalog_resolve_context(&cx, &conn, generation, StatementScope::default())
                .await
                .expect("live resolution context");
        let dual = name(&["dual"], SyntacticRole::FromFactor);
        let sys_dual = name(&["sys", "dual"], SyntacticRole::FromFactor);
        let quoted_lower_dual =
            RawName::new([RawNamePart::quoted("dual")], SyntacticRole::FromFactor);
        let put_line = name(
            &["sys", "dbms_output", "put_line"],
            SyntacticRole::CallWithArgs,
        );
        let get_lines = name(
            &["sys", "dbms_output", "get_lines"],
            SyntacticRole::CallWithArgs,
        );
        let column_conflict = name(&["dummy"], SyntacticRole::ValuePosition);
        let missing = name(&["oraclemcp_missing_object"], SyntacticRole::FromFactor);
        let remote = name(&["dual"], SyntacticRole::FromFactor)
            .with_db_link(RawNamePart::unquoted("warehouse"));
        let requested = vec![
            dual.clone(),
            sys_dual.clone(),
            quoted_lower_dual.clone(),
            put_line.clone(),
            get_lines.clone(),
            column_conflict.clone(),
            missing.clone(),
            remote.clone(),
        ];
        let resolver = OracleCatalogResolver::load(&cx, &conn, &requested, &context)
            .await
            .expect("live dictionary snapshot");

        let Resolution::Resolved(dual_object) = resolver.resolve(&dual, &context) else {
            panic!("public DUAL synonym must resolve");
        };
        assert_eq!(dual_object.owner, "SYS");
        assert_eq!(dual_object.name, "DUAL");
        assert_eq!(dual_object.kind, CatalogObjectKind::Table);
        assert_eq!(dual_object.synonym_chain.len(), 1);
        assert!(dual_object.identity.object_id > 0);

        let Resolution::Resolved(sys_dual_object) = resolver.resolve(&sys_dual, &context) else {
            panic!("SYS.DUAL must resolve directly");
        };
        assert!(sys_dual_object.synonym_chain.is_empty());
        assert_eq!(sys_dual_object.identity, dual_object.identity);
        assert_eq!(
            resolver.resolve(&quoted_lower_dual, &context),
            Resolution::Unresolved
        );

        let Resolution::Resolved(put_line_object) = resolver.resolve(&put_line, &context) else {
            panic!("SYS.DBMS_OUTPUT.PUT_LINE must resolve");
        };
        assert_eq!(
            put_line_object.container.as_ref().unwrap().name,
            "DBMS_OUTPUT"
        );
        assert_eq!(put_line_object.kind, CatalogObjectKind::Procedure);
        assert!(!put_line_object.overloads.is_empty());

        let Resolution::Resolved(get_lines_object) = resolver.resolve(&get_lines, &context) else {
            panic!("SYS.DBMS_OUTPUT.GET_LINES must resolve");
        };
        assert!(get_lines_object.overloads.len() >= 2);

        assert_eq!(
            resolver.resolve(&column_conflict, &context),
            Resolution::Unresolved
        );
        assert_eq!(resolver.resolve(&missing, &context), Resolution::Unresolved);
        assert!(matches!(
            resolver.resolve(&remote, &context),
            Resolution::Remote { .. }
        ));

        let mut stale = context.clone();
        stale.generation = CatalogGeneration(generation.0 + 1);
        assert_eq!(resolver.resolve(&dual, &stale), Resolution::Unresolved);
    });
}

#[test]
fn live_adversarial_resolver_corpus_fails_closed_and_invalidates_stale_evidence() {
    if std::env::var("ORACLEMCP_RESOLVER_ADVERSARIAL").as_deref() != Ok("1") {
        eprintln!(
            "[live-xe] SKIP resolver adversarial DDL corpus: set \
             ORACLEMCP_RESOLVER_ADVERSARIAL=1 with throwaway DBA-capable credentials"
        );
        return;
    }
    run_with_cx(|cx| async move {
        const FIXTURE_USER: &str = "ORACLEMCP_RES6_USER";
        const FIXTURE_PASSWORD: &str = "Resolver6_Test_Pw_42";
        let admin = RustOracleConnection::connect(&cx, test_opts())
            .await
            .expect("explicit resolver adversarial run requires a reachable Oracle");
        let admin_context = read_catalog_resolve_context(
            &cx,
            &admin,
            CatalogGeneration(1),
            StatementScope::default(),
        )
        .await
        .expect("adversarial admin context");
        cleanup_adversarial_fixture(&cx, &admin, &admin_context.current_schema).await;
        execute_cleanup(&cx, &admin, &format!("DROP USER {FIXTURE_USER} CASCADE")).await;
        execute_ddl(
            &cx,
            &admin,
            &format!("CREATE USER {FIXTURE_USER} IDENTIFIED BY \"{FIXTURE_PASSWORD}\""),
        )
        .await;
        execute_ddl(
            &cx,
            &admin,
            &format!("ALTER USER {FIXTURE_USER} ENABLE EDITIONS"),
        )
        .await;
        execute_ddl(
            &cx,
            &admin,
            &format!(
                "GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, \
                 CREATE SYNONYM, UNLIMITED TABLESPACE TO {FIXTURE_USER}"
            ),
        )
        .await;
        execute_ddl(
            &cx,
            &admin,
            &format!("GRANT EXECUTE_CATALOG_ROLE TO {FIXTURE_USER}"),
        )
        .await;
        let mut fixture_opts = test_opts();
        fixture_opts.username = Some(FIXTURE_USER.to_owned());
        fixture_opts.password = Some(FIXTURE_PASSWORD.to_owned());
        let conn = RustOracleConnection::connect(&cx, fixture_opts)
            .await
            .expect("connect edition-enabled adversarial fixture user");
        let initial_context = read_catalog_resolve_context(
            &cx,
            &conn,
            CatalogGeneration(1),
            StatementScope::default(),
        )
        .await
        .expect("live adversarial resolution context");
        let current_schema = initial_context.current_schema.clone();
        assert!(
            !current_schema.is_empty()
                && current_schema.len() <= 128
                && current_schema
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'#')),
            "dictionary CURRENT_SCHEMA must be safe to reuse as an unquoted fixture identifier"
        );
        cleanup_adversarial_fixture(&cx, &conn, &current_schema).await;

        execute_ddl(&cx, &conn, "CREATE TABLE ORACLEMCP_RES6_LOG (ID NUMBER)").await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE FUNCTION ORACLEMCP_RES6_HIDDEN_FN RETURN NUMBER AUTHID DEFINER AS \
             PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO ORACLEMCP_RES6_LOG VALUES (1); \
             COMMIT; RETURN 1; END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE VIEW ORACLEMCP_RES6_VIEW AS \
             SELECT ORACLEMCP_RES6_HIDDEN_FN() AS MARKER FROM DUAL",
        )
        .await;
        execute_ddl(&cx, &conn, "CREATE TABLE ORACLEMCP_RES6_VPD (ID NUMBER)").await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE FUNCTION ORACLEMCP_RES6_POLICY_FN( \
                 SCHEMA_NAME VARCHAR2, OBJECT_NAME VARCHAR2) RETURN VARCHAR2 AUTHID DEFINER AS \
             PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO ORACLEMCP_RES6_LOG VALUES (2); \
             COMMIT; RETURN '1=1'; END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "BEGIN DBMS_RLS.ADD_POLICY(OBJECT_SCHEMA => USER, \
                 OBJECT_NAME => 'ORACLEMCP_RES6_VPD', POLICY_NAME => 'ORACLEMCP_RES6_POLICY', \
                 FUNCTION_SCHEMA => USER, POLICY_FUNCTION => 'ORACLEMCP_RES6_POLICY_FN', \
                 STATEMENT_TYPES => 'SELECT'); END;",
        )
        .await;

        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE PACKAGE ORACLEMCP_RES6_PKG AS \
                 FUNCTION ZERO RETURN NUMBER; \
                 FUNCTION ZERO(P_VALUE NUMBER) RETURN NUMBER; \
             END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE SYNONYM ORACLEMCP_RES6_PKG_ALIAS FOR ORACLEMCP_RES6_PKG",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE FUNCTION ORACLEMCP_RES6_TARGET_A RETURN NUMBER AS \
             BEGIN RETURN 1; END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE FUNCTION ORACLEMCP_RES6_TARGET_B RETURN NUMBER AS \
             BEGIN RETURN 2; END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE SYNONYM ORACLEMCP_RES6_FN_ALIAS FOR ORACLEMCP_RES6_TARGET_A",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE SYNONYM ORACLEMCP_RES6_REMOTE FOR SYS.DUAL@ORACLEMCP_RES6_LINK",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE FUNCTION ORACLEMCP_RES6_MEMBER RETURN NUMBER AS \
             BEGIN RETURN 3; END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            &format!(
                "CREATE OR REPLACE PACKAGE {current_schema} AS \
                 FUNCTION ORACLEMCP_RES6_MEMBER RETURN NUMBER; END;"
            ),
        )
        .await;

        let hidden_view = name(&["oraclemcp_res6_view"], SyntacticRole::FromFactor);
        let vpd_table = name(&["oraclemcp_res6_vpd"], SyntacticRole::FromFactor);
        let package_member = name(
            &["oraclemcp_res6_pkg_alias", "zero"],
            SyntacticRole::ValuePosition,
        );
        let function_alias = name(&["oraclemcp_res6_fn_alias"], SyntacticRole::ValuePosition);
        let remote_synonym = name(&["oraclemcp_res6_remote"], SyntacticRole::FromFactor);
        let collision = name(
            &[current_schema.as_str(), "oraclemcp_res6_member"],
            SyntacticRole::ValuePosition,
        );
        let requested = [
            hidden_view.clone(),
            vpd_table.clone(),
            package_member.clone(),
            function_alias.clone(),
            remote_synonym.clone(),
            collision.clone(),
        ];
        let resolver = OracleCatalogResolver::load(&cx, &conn, &requested, &initial_context)
            .await
            .expect("load live adversarial dictionary evidence");

        let Resolution::Resolved(view) = resolver.resolve(&hidden_view, &initial_context) else {
            panic!("hidden-write view identity must resolve before purity rejects it");
        };
        assert_eq!(view.kind, CatalogObjectKind::View);
        assert_eq!(
            resolved_relations_read_purity(&cx, &conn, std::slice::from_ref(view.as_ref()))
                .await
                .expect("view purity proof"),
            Purity::Unknown,
            "views remain unknown because their query can invoke autonomous functions"
        );

        let Resolution::Resolved(table) = resolver.resolve(&vpd_table, &initial_context) else {
            panic!("VPD table identity must resolve before policy proof rejects it");
        };
        assert_eq!(table.kind, CatalogObjectKind::Table);
        assert_eq!(
            resolved_relations_read_purity(&cx, &conn, std::slice::from_ref(table.as_ref()))
                .await
                .expect("VPD purity proof"),
            Purity::Unknown,
            "enabled SELECT VPD policy must prevent a read-only proof"
        );
        assert_eq!(
            scalar_i64(
                &cx,
                &conn,
                "SELECT COUNT(*) AS SIDE_EFFECTS FROM ORACLEMCP_RES6_LOG",
                "SIDE_EFFECTS",
            )
            .await,
            0,
            "dictionary proof must not execute hidden view or VPD functions"
        );

        let Resolution::Resolved(member) = resolver.resolve(&package_member, &initial_context)
        else {
            panic!("unshadowed paren-less synonym package member must resolve");
        };
        assert_eq!(member.kind, CatalogObjectKind::Function);
        assert_eq!(
            member.container.as_ref().unwrap().name,
            "ORACLEMCP_RES6_PKG"
        );
        assert_eq!(
            member.overloads.len(),
            1,
            "required-input overload is excluded"
        );
        assert_eq!(member.identity.edition, initial_context.edition);
        assert_eq!(member.synonym_chain.len(), 1);

        let Resolution::Resolved(first_target) =
            resolver.resolve(&function_alias, &initial_context)
        else {
            panic!("synonym-hidden zero-argument function must resolve");
        };
        assert_eq!(first_target.name, "ORACLEMCP_RES6_TARGET_A");
        assert!(matches!(
            resolver.resolve(&remote_synonym, &initial_context),
            Resolution::Remote { .. }
        ));
        assert!(matches!(
            resolver.resolve(&collision, &initial_context),
            Resolution::Ambiguous { .. }
        ));

        let cache = OracleCatalogResolverCache::new();
        let synonym_before = cache
            .preload(
                &cx,
                &conn,
                std::slice::from_ref(&function_alias),
                StatementScope::default(),
            )
            .await
            .expect("preload first synonym target");
        let Resolution::Resolved(before_target) = cache.resolve(&function_alias, &synonym_before)
        else {
            panic!("first synonym target must be cached");
        };
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE SYNONYM ORACLEMCP_RES6_FN_ALIAS FOR ORACLEMCP_RES6_TARGET_B",
        )
        .await;
        cache.invalidate(CatalogInvalidation::Synonym);
        assert_eq!(
            cache.resolve(&function_alias, &synonym_before),
            Resolution::Unresolved
        );
        let synonym_after = cache
            .preload(
                &cx,
                &conn,
                std::slice::from_ref(&function_alias),
                StatementScope::default(),
            )
            .await
            .expect("preload replacement synonym target");
        let Resolution::Resolved(after_target) = cache.resolve(&function_alias, &synonym_after)
        else {
            panic!("replacement synonym target must resolve");
        };
        assert_eq!(before_target.name, "ORACLEMCP_RES6_TARGET_A");
        assert_eq!(after_target.name, "ORACLEMCP_RES6_TARGET_B");
        assert_ne!(before_target.identity, after_target.identity);

        let overload_before = cache
            .preload(
                &cx,
                &conn,
                std::slice::from_ref(&package_member),
                StatementScope::default(),
            )
            .await
            .expect("preload package overloads");
        let Resolution::Resolved(before_overloads) =
            cache.resolve(&package_member, &overload_before)
        else {
            panic!("initial package overloads must resolve");
        };
        assert_eq!(before_overloads.overloads.len(), 1);
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE PACKAGE ORACLEMCP_RES6_PKG AS \
                 FUNCTION ZERO RETURN NUMBER; \
                 FUNCTION ZERO(P_VALUE VARCHAR2 DEFAULT NULL) RETURN NUMBER; \
             END;",
        )
        .await;
        execute_ddl(
            &cx,
            &conn,
            "CREATE OR REPLACE SYNONYM ORACLEMCP_RES6_PKG_ALIAS FOR ORACLEMCP_RES6_PKG",
        )
        .await;
        cache.invalidate(CatalogInvalidation::Overload);
        assert_eq!(
            cache.resolve(&package_member, &overload_before),
            Resolution::Unresolved
        );
        let overload_after = cache
            .preload(
                &cx,
                &conn,
                std::slice::from_ref(&package_member),
                StatementScope::default(),
            )
            .await
            .expect("preload changed package overloads");
        let Resolution::Resolved(after_overloads) = cache.resolve(&package_member, &overload_after)
        else {
            panic!("changed package overloads must resolve");
        };
        assert_eq!(after_overloads.overloads.len(), 2);

        execute_ddl(&cx, &conn, "ALTER SESSION SET CURRENT_SCHEMA = SYS").await;
        cache.invalidate(CatalogInvalidation::CurrentSchema);
        assert_eq!(
            cache.resolve(&package_member, &overload_after),
            Resolution::Unresolved
        );
        let dual = name(&["dual"], SyntacticRole::FromFactor);
        let changed_schema = cache
            .preload(
                &cx,
                &conn,
                std::slice::from_ref(&dual),
                StatementScope::default(),
            )
            .await
            .expect("preload after CURRENT_SCHEMA change");
        assert_eq!(changed_schema.current_schema, "SYS");
        assert!(matches!(
            cache.resolve(&dual, &changed_schema),
            Resolution::Resolved(_)
        ));
        execute_ddl(
            &cx,
            &conn,
            &format!("ALTER SESSION SET CURRENT_SCHEMA = {current_schema}"),
        )
        .await;

        cleanup_adversarial_fixture(&cx, &conn, &current_schema).await;
        drop(conn);
        execute_ddl(
            &cx,
            &admin,
            &format!("ALTER USER {FIXTURE_USER} ACCOUNT LOCK"),
        )
        .await;
    });
}

#[test]
fn live_statement_scope_shadows_dictionary_objects() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(&cx).await else {
            return;
        };
        let dual = name(&["dual"], SyntacticRole::FromFactor);
        let scope = StatementScope {
            aliases: vec![RawNamePart::unquoted("dual")],
            common_table_expressions: Vec::new(),
            relations: Vec::new(),
        };
        let context = read_catalog_resolve_context(&cx, &conn, CatalogGeneration(19), scope)
            .await
            .expect("scoped live context");
        let resolver =
            OracleCatalogResolver::load(&cx, &conn, std::slice::from_ref(&dual), &context)
                .await
                .expect("scoped dictionary snapshot");
        assert_eq!(resolver.resolve(&dual, &context), Resolution::Unresolved);
    });
}

#[test]
fn live_cache_invalidation_rejects_stale_positive_and_negative_evidence() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(&cx).await else {
            return;
        };
        let cache = OracleCatalogResolverCache::new();
        let dual = name(&["dual"], SyntacticRole::FromFactor);
        let missing = name(
            &["oraclemcp_generation_scoped_missing_object"],
            SyntacticRole::FromFactor,
        );
        let old = cache
            .preload(
                &cx,
                &conn,
                &[dual.clone(), missing.clone()],
                StatementScope::default(),
            )
            .await
            .expect("live generation-one cache load");
        assert!(matches!(
            cache.resolve(&dual, &old),
            Resolution::Resolved(_)
        ));
        assert_eq!(cache.resolve(&missing, &old), Resolution::Unresolved);
        assert_eq!(cache.len(), 2, "negative answers are cached too");

        let next = cache.invalidate(CatalogInvalidation::Reconnect);
        assert_eq!(next.0, old.generation.0 + 1);
        assert!(cache.is_empty());
        assert_eq!(cache.resolve(&dual, &old), Resolution::Unresolved);

        let current = cache
            .preload(
                &cx,
                &conn,
                std::slice::from_ref(&dual),
                StatementScope::default(),
            )
            .await
            .expect("live cache reload after invalidation");
        assert_eq!(current.generation, next);
        assert!(matches!(
            cache.resolve(&dual, &current),
            Resolution::Resolved(_)
        ));
    });
}
