//! Mock-free live checks for the Oracle dictionary resolver.

#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::{
    AuthAdapter, CatalogInvalidation, OracleCatalogResolver, OracleCatalogResolverCache,
    OracleConnectOptions, OracleConnection, RustOracleConnection, read_catalog_resolve_context,
};
use oraclemcp_guard::{
    CatalogGeneration, CatalogObjectKind, CatalogResolver, RawName, RawNamePart, Resolution,
    StatementScope, SyntacticRole,
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
fn live_statement_scope_shadows_dictionary_objects() {
    run_with_cx(|cx| async move {
        let Some(conn) = connect_or_skip(&cx).await else {
            return;
        };
        let dual = name(&["dual"], SyntacticRole::FromFactor);
        let scope = StatementScope {
            aliases: vec![RawNamePart::unquoted("dual")],
            common_table_expressions: Vec::new(),
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
