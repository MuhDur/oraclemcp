use super::*;

#[test]
fn package_effects_reject_implicit_commit_mixes_and_unknown_dynamic_sql() {
    use oraclemcp_guard::{OperatingLevel, RoutineEffectsV1};
    assert_eq!(
        package_effects_level(&RoutineEffectsV1::new([RoutineEffect::Dml])),
        Ok(OperatingLevel::ReadWrite)
    );
    assert_eq!(
        package_effects_level(&RoutineEffectsV1::new([RoutineEffect::Ddl])),
        Ok(OperatingLevel::Ddl)
    );
    for effects in [
        vec![RoutineEffect::Dml, RoutineEffect::Ddl],
        vec![RoutineEffect::Dml, RoutineEffect::Admin],
        vec![RoutineEffect::Ddl, RoutineEffect::DynamicSql],
        vec![RoutineEffect::Admin],
    ] {
        assert!(package_effects_level(&RoutineEffectsV1::new(effects)).is_err());
    }
}

#[test]
fn package_literal_projection_preserves_source_order_and_duplicate_events() {
    let source = "BEGIN EXECUTE IMMEDIATE 'CREATE TABLE Z(ID NUMBER)'; EXECUTE IMMEDIATE 'CREATE TABLE A(ID NUMBER)'; EXECUTE IMMEDIATE 'CREATE TABLE Z(ID NUMBER)'; END;";
    let parsed = crate::plsql_tools::on_engine_stack(|| {
        parse_with_backend(
            source,
            FileId::new(1),
            &Antlr4RustBackend::new(),
            &ParseOptions::default(),
        )
    })
    .unwrap();
    assert!(parsed.is_clean());
    assert!(!parsed.was_recovered());
    let literals = source_literals(&parsed, 0).unwrap();
    let z = "CREATE TABLE Z(ID NUMBER)".to_owned();
    let a = "CREATE TABLE A(ID NUMBER)".to_owned();
    assert_eq!(
        source_ordered_literal_sql(&literals, vec![a.clone(), z.clone(), z.clone()]).unwrap(),
        vec![z.clone(), a.clone(), z.clone()]
    );
    assert!(
        source_ordered_literal_sql(&literals, vec![z, a]).is_err(),
        "an omitted duplicate must not become a smaller closure"
    );
}

#[test]
#[ignore = "requires the local FREE23 lab"]
fn custom_tool_live_package_source_and_scalar_wrapper() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("oraclemcp::mutation_closure=debug")
        .try_init();
    use oraclemcp_db::{OracleConnectOptions, OracleRoutineArg, RustOracleConnection};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let options = OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN").unwrap(),
        username: Some(std::env::var("ORACLEMCP_TEST_USER").unwrap()),
        password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap()),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    };
    assert!(options.connect_string.starts_with("localhost:1523/"));
    let reactor = asupersync::runtime::reactor::create_reactor().unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .unwrap();
    runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let conn = RustOracleConnection::connect(&cx, options).await.unwrap();
            let context = oraclemcp_db::read_catalog_resolve_context(&cx, &conn, Default::default(), Default::default()).await.unwrap();
            let owner = &context.connected_schema;
            assert!(simple(owner));
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
            let name = format!("OMCP_P1013_{nonce:X}");
            conn.execute(&cx, &format!("CREATE OR REPLACE PACKAGE \"{owner}\".\"{name}\" AUTHID DEFINER AS FUNCTION INC(PX NUMBER) RETURN NUMBER; END;"), &[]).await.unwrap();
            let outcome: Result<(), String> = async {
                conn.execute(&cx, &format!("CREATE OR REPLACE PACKAGE BODY \"{owner}\".\"{name}\" AS FUNCTION INC(PX NUMBER) RETURN NUMBER IS BEGIN RETURN PX + 1; END; END;"), &[]).await.map_err(|e| e.to_string())?;
                let mut source = read_mutation_routine_source(&cx, &conn, owner, &name, "PACKAGE BODY", Some("INC")).await.map_err(|e| format!("source: {e:?}"))?;
                source.use_context = MutationRoutineUse::CustomToolCall;
                let config = format!(r#"[[tool]]
name = "app_increment"
description = "Live source-backed scalar"
closure_sha256 = "{}"
routine = {{ owner = "{owner}", package = "{name}", member = "INC", subprogram_id = {} }}
args = [{{ oracle_type = "NUMBER", direction = "RETURN", bind_name = "result" }}, {{ oracle_name = "PX", oracle_type = "NUMBER", direction = "IN", bind_name = "x" }}]
params = [{{ name = "x", type = "integer", required = true }}]
"#, "a".repeat(64), source.subprogram_id.unwrap());
                let def = oraclemcp_core::parse_tools_file(&config).map_err(|e| e.to_string())?.remove(0);
                let proof = EngineMutationEffects.prove_package_call(&cx, &conn, &source, &def.args).await.map_err(|e| format!("package proof: {e:?}"))?;
                if oraclemcp_guard::admit(&proof.proof.effects, oraclemcp_guard::AdmissionContext::CustomToolCall) != Ok(oraclemcp_guard::OperatingLevel::ReadOnly) { return Err("pure arithmetic package was not proven READ_ONLY".into()); }
                let rows = run_catalog_query(&cx, &conn, CatalogQueryId::MemberArguments, &[owner.as_str().into(), name.as_str().into(), "INC".into(), 257_i64.into()]).await.map_err(|e| e.to_string())?;
                let wrapper = oraclemcp_core::package_call_wrapper(&def, &rows).map_err(|e| e.to_string())?;
                let result = conn.call_routine(&cx, &wrapper.sql, &[oraclemcp_db::OracleRoutineArg::input(oraclemcp_db::OracleBind::I64(41)).map_err(|e| e.to_string())?, OracleRoutineArg::return_output(2, 1, 22)]).await.map_err(|e| e.to_string())?;
                if result.out_binds().len() != 1 || result.out_binds()[0].value.as_deref() != Some("42") { return Err(format!("unexpected scalar output: {:?}", result.out_binds())); }
                Ok(())
            }.await;
            conn.execute(&cx, &format!("DROP PACKAGE \"{owner}\".\"{name}\""), &[]).await.expect("remove run-owned package fixture");
            conn.close(&cx).await.unwrap();
            outcome.unwrap();
        });
}

fn statements(source: &str) -> Vec<plsql_ir::Statement> {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("policy.sql"), source).unwrap();
    let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
        project_root: project.path().to_owned(),
        cache: plsql_engine::CacheConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    run.invocation_index
        .units
        .get("APP.PF")
        .unwrap()
        .statements
        .clone()
}

#[test]
fn policy_predicate_returns_require_complete_top_level_coverage() {
    for body in [
        "BEGIN RETURN NULL; END;",
        "BEGIN RETURN '1=1'; END;",
        "BEGIN RETURN '1 = 1'; END;",
    ] {
        let source = format!(
            "CREATE OR REPLACE FUNCTION APP.PF(S VARCHAR2, O VARCHAR2) RETURN VARCHAR2 IS {body}"
        );
        let statements = statements(&source);
        assert_eq!(constant_policy_returns(&source, &statements), Ok(1));
    }
    for body in [
        "BEGIN RETURN 'APP.LOG_HIT() = 1'; END;",
        "BEGIN IF S = 'X' THEN RETURN NULL; END IF; RETURN '1=1'; END;",
        "BEGIN IF S = 'X' THEN RETURN 'APP.LOG_HIT() = 1'; END IF; RETURN NULL; END;",
        "BEGIN RETURN NULL; EXCEPTION WHEN OTHERS THEN RETURN 'APP.LOG_HIT() = 1'; END;",
        "BEGIN RETURN ''; END;",
    ] {
        let source = format!(
            "CREATE OR REPLACE FUNCTION APP.PF(S VARCHAR2, O VARCHAR2) RETURN VARCHAR2 IS {body}"
        );
        let statements = statements(&source);
        assert_eq!(
            constant_policy_returns(&source, &statements),
            Err(Unknown::EffectProofUnavailable),
            "{body}"
        );
    }
}
