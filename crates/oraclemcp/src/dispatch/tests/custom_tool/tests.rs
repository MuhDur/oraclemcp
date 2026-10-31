use super::*;
use oraclemcp_audit::HmacSha256Key;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CaptureCatalog {
    capture_at: Option<usize>,
    reads: AtomicUsize,
}
#[async_trait::async_trait(?Send)]
impl OracleConnection for CaptureCatalog {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("unexpected ping")
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        panic!("unexpected describe")
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let at = self
            .capture_at
            .expect("masked output must refuse before catalog I/O");
        let index = self.reads.fetch_add(1, Ordering::SeqCst);
        let expected = if index == 0 {
            CatalogQueryId::Objects
        } else {
            CatalogQueryId::Synonyms
        };
        assert_eq!(sql, expected.spec().sql);
        assert_eq!(
            binds[0],
            OracleBind::String(if index == 2 { "PUBLIC" } else { "CALLER" }.into())
        );
        assert_eq!(binds[1], OracleBind::String("APP".into()));
        Ok(if index == at {
            vec![OracleRow {
                columns: Default::default(),
            }]
        } else {
            Vec::new()
        })
    }
    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        panic!("candidate must not execute")
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("unexpected commit")
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("unexpected rollback")
    }
    async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[test]
fn custom_dispatch_default_stack_refusal_has_no_database_io() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let dispatcher = OracleDispatcher::new(Box::new(CaptureCatalog {
            capture_at: None,
            reads: AtomicUsize::new(0),
        }));
        match ToolDispatch::dispatch(
            &dispatcher,
            &cx,
            DispatchContext::default(),
            "app_missing",
            json!({}),
        )
        .await
        {
            Outcome::Err(error) => assert_eq!(error.error_class, ErrorClass::InvalidArguments),
            other => panic!("unknown custom tool must refuse: {other:?}"),
        }
    }));
}

#[test]
fn unrelated_write_gate_does_not_activate_pending_package_tools() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let mut dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(CaptureCatalog {
                capture_at: None,
                reads: AtomicUsize::new(0),
            }),
            None,
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );
        dispatcher.state.get_mut().unwrap().custom_catalog = ActiveCustomCatalog::new(
            2,
            CustomToolCatalog::with_pending(Vec::new(), vec![signed_definition()]),
        );
        match ToolDispatch::dispatch(
            &dispatcher,
            &cx,
            DispatchContext::default(),
            "oracle_execute",
            json!({"sql":"UPDATE APP.T SET C=1"}),
        )
        .await
        {
            Outcome::Err(error) => {
                assert_eq!(error.error_class, ErrorClass::OperatingLevelTooLow)
            }
            other => panic!("write must refuse before metadata: {other:?}"),
        }
    }));
}

#[test]
fn custom_tool_name_capture_checks_object_private_synonym_and_public_synonym() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for at in 0..3 {
                let catalog = CaptureCatalog {
                    capture_at: Some(at),
                    reads: AtomicUsize::new(0),
                };
                let error = check_package_name_capture(&cx, &catalog, "CALLER", "APP")
                    .await
                    .unwrap_err();
                assert_eq!(error.error_class, ErrorClass::PolicyDenied);
                assert!(error.message.contains("CUSTOM_TOOL_NAME_CAPTURE"));
                assert_eq!(catalog.reads.load(Ordering::SeqCst), at + 1);
            }
        });
}

#[test]
fn custom_tool_masked_profile_refuses_each_output_channel_before_io() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            use oraclemcp_core::PackageOracleType;
            let cx = Cx::current().unwrap();
            let key = HmacSha256Key::new(b"package-call-test-key-01234567890".to_vec()).unwrap();
            for channel in [
                "return",
                "out",
                "inout",
                "ref_cursor",
                "implicit",
                "dbms_output",
            ] {
                let mut def = signed_definition().definition().clone();
                if channel != "return" {
                    def.args
                        .retain(|arg| arg.direction == PackageArgDirection::In);
                }
                match channel {
                    "out" | "ref_cursor" => {
                        let mut slot = signed_definition().definition().args[0].clone();
                        slot.direction = PackageArgDirection::Out;
                        slot.oracle_name = Some("PR".into());
                        if channel == "ref_cursor" {
                            slot.oracle_type = PackageOracleType::RefCursor;
                        }
                        def.args.push(slot);
                    }
                    "inout" => def.args[0].direction = PackageArgDirection::InOut,
                    "implicit" => def.implicit_results = true,
                    "dbms_output" => def.capture_dbms_output = true,
                    _ => {}
                }
                def.signature = Some(oraclemcp_core::sign(&def, &key));
                let signed = oraclemcp_core::prepare_package_definition(&def, &key).unwrap();
                let catalog = CaptureCatalog {
                    capture_at: None,
                    reads: AtomicUsize::new(0),
                };
                let error = collect_package_plan(
                    &cx,
                    &catalog,
                    &signed,
                    OperatingLevel::Admin,
                    true,
                    false,
                )
                .await
                .unwrap_err();
                assert_eq!(error.error_class, ErrorClass::PolicyDenied, "{channel}");
                assert!(
                    error.message.contains("CUSTOM_TOOL_MASKED_OUTPUT"),
                    "{channel}"
                );
                assert_eq!(catalog.reads.load(Ordering::SeqCst), 0);
            }
        });
}

fn signed_definition() -> SignedPackageDefinition {
    let mut def = oraclemcp_core::parse_tools_file(&format!(r#"[[tool]]
name = "app_increment"
description = "Pinned scalar test"
closure_sha256 = "{}"
routine = {{ owner = "APP", package = "PKG", member = "INC", subprogram_id = 1 }}
args = [{{oracle_type="NUMBER", direction="RETURN", bind_name="result"}}, {{oracle_name="PX", oracle_type="NUMBER", direction="IN", bind_name="x"}}]
params = [{{name="x", type="integer", required=true}}]
"#, "a".repeat(64))).unwrap().remove(0);
    let key = HmacSha256Key::new(b"package-call-test-key-01234567890".to_vec()).unwrap();
    def.signature = Some(oraclemcp_core::sign(&def, &key));
    oraclemcp_core::prepare_package_definition(&def, &key).unwrap()
}

fn plan() -> PackageCallPlan {
    let signed = signed_definition();
    let mut bindings = signed.definition().args.clone();
    bindings.swap(0, 1);
    PackageCallPlan {
        signed,
        wrapper: PackageCallWrapper {
            sql: "DECLARE p NUMBER; BEGIN p := :x; :result := APP.PKG.INC(PX => p); END;".into(),
            bindings,
        },
        required_level: OperatingLevel::ReadWrite,
        effects: oraclemcp_guard::RoutineEffectsV1::new([oraclemcp_guard::RoutineEffect::Dml]),
        literal_sql: Vec::new(),
        facts_digest: [7; 32],
        callback_digests: vec!["b".repeat(64)],
        ddl_closures: Vec::new(),
        compile_observation: false,
    }
}

#[test]
fn package_confirmation_commits_to_inputs_definition_effects_and_callbacks() {
    let plan = plan();
    let parsed = package_call_args(&plan, &json!({"x":41})).unwrap();
    let generations = ImpactGenerations {
        profile: 3,
        lane: 9,
    };
    let (_, original) = package_approval(&plan, &parsed, generations, false).unwrap();
    let changed = package_call_args(&plan, &json!({"x":42})).unwrap();
    assert_ne!(
        original,
        package_approval(&plan, &changed, generations, false)
            .unwrap()
            .1
    );
    let changed = package_call_args(&plan, &json!({"x":41,"commit":true})).unwrap();
    assert_ne!(
        original,
        package_approval(&plan, &changed, generations, false)
            .unwrap()
            .1
    );
    assert_ne!(
        original,
        package_approval(&plan, &parsed, generations, true)
            .unwrap()
            .1
    );
    let mut changed = plan.clone();
    changed.facts_digest[0] ^= 1;
    assert_ne!(
        original,
        package_approval(&changed, &parsed, generations, false)
            .unwrap()
            .1
    );
    let mut changed = plan.clone();
    changed.effects =
        oraclemcp_guard::RoutineEffectsV1::new([oraclemcp_guard::RoutineEffect::ReadDb]);
    assert_ne!(
        original,
        package_approval(&changed, &parsed, generations, false)
            .unwrap()
            .1
    );
    let mut changed = plan.clone();
    changed.callback_digests.clear();
    assert_ne!(
        original,
        package_approval(&changed, &parsed, generations, false)
            .unwrap()
            .1
    );
    assert_ne!(
        original,
        package_approval(
            &plan,
            &parsed,
            ImpactGenerations {
                profile: 4,
                lane: 9
            },
            false
        )
        .unwrap()
        .1
    );
}

#[test]
fn package_ddl_commitment_uses_the_collector_bytes_and_binds_every_event() {
    use oraclemcp_guard::impact_binding::DecisiveField;
    let mut plan = plan();
    plan.effects = oraclemcp_guard::RoutineEffectsV1::new([oraclemcp_guard::RoutineEffect::Ddl]);
    plan.required_level = OperatingLevel::Ddl;
    let args = package_call_args(&plan, &json!({"x":41,"commit":true})).unwrap();
    let generations = ImpactGenerations {
        profile: 3,
        lane: 9,
    };
    assert!(package_approval(&plan, &args, generations, false).is_err());
    let fingerprint = "ab".repeat(32);
    plan.ddl_closures
        .push(decode_package_digest(&fingerprint).unwrap());
    let (binding, one) = package_approval(&plan, &args, generations, false).unwrap();
    assert_eq!(
        binding
            .decisive
            .action_fields
            .get(&DecisiveField::DdlEffectClosure),
        Some(&FieldStatus::Computed { value: [0xab; 32] })
    );
    plan.ddl_closures.push([0xcd; 32]);
    let (many_binding, many) = package_approval(&plan, &args, generations, false).unwrap();
    let Some(FieldStatus::Computed { value }) = many_binding
        .decisive
        .action_fields
        .get(&DecisiveField::DdlEffectClosure)
    else {
        panic!("composite must be computed")
    };
    assert_eq!(
        hex_bytes(value),
        "7e31d05206c7ae4984368f6aa04297da21161a48063281620d970f9507da4bab"
    );
    assert_ne!(one, many);
    let original = plan.clone();
    for change in ["reorder", "drop", "replace"] {
        let mut changed = original.clone();
        match change {
            "reorder" => changed.ddl_closures.reverse(),
            "drop" => {
                changed.ddl_closures.pop();
            }
            _ => changed.ddl_closures[1][0] ^= 1,
        }
        let fresh = package_approval(&changed, &args, generations, false)
            .unwrap()
            .1;
        assert_ne!(many, fresh, "{change}");
        let store = ExecGrantStore::new();
        let binding = ExecGrantBinding {
            session_id: "session".into(),
            lane_id: "lane".into(),
            subject_id: "operator".into(),
            generation: 3,
        };
        let token =
            issue_confirmation_grant(&store, &binding, Some("test"), &many, OperatingLevel::Ddl);
        let error = consume_confirmation_grant(ConfirmationGrantRequest {
            material: &fresh,
            required_level: OperatingLevel::Ddl,
            active_profile: Some("test"),
            grants: &store,
            binding: &binding,
            confirm: Some(&token),
            challenge_message: "preview required",
            suggested_tool: "app_increment",
            next_step: "preview again",
        })
        .unwrap_err();
        assert_eq!(error.error_class, ErrorClass::RepreviewRequired, "{change}");
        assert!(
            consume_confirmation_grant(ConfirmationGrantRequest {
                material: &many,
                required_level: OperatingLevel::Ddl,
                active_profile: Some("test"),
                grants: &store,
                binding: &binding,
                confirm: Some(&token),
                challenge_message: "preview required",
                suggested_tool: "app_increment",
                next_step: "preview again"
            })
            .is_ok(),
            "failed revalidation must not consume the unchanged approval"
        );
    }
    assert!(decode_package_digest(&"z".repeat(64)).is_err());
}

#[test]
fn package_scoped_execution_is_terminal_and_values_cannot_add_output_controls() {
    let plan = plan();
    let error = package_call_args(&plan, &json!({"x":41,"scoped_grant":"sgr1.fake"}))
        .err()
        .unwrap();
    assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
    assert_eq!(
        error,
        write_auth_error(WriteAuthRefusal::GrantEnforcementUnavailable)
    );
    for key in ["confirm", "token", "confirmation_token"] {
        let mut input = json!({"x":41});
        input[key] = json!("sgr1.fake");
        let error = package_call_args(&plan, &input).err().unwrap();
        assert_eq!(
            error,
            write_auth_error(WriteAuthRefusal::GrantEnforcementUnavailable)
        );
    }
    for input in [
        json!({"x":41,"hold":true}),
        json!({"x":41,"capture_dbms_output":true}),
        json!({"x":41,"result":7}),
    ] {
        assert_eq!(
            package_call_args(&plan, &input).err().unwrap().error_class,
            ErrorClass::InvalidArguments
        );
    }
}

#[test]
fn package_native_output_retains_names_and_refuses_missing_or_oversize_slots() {
    let plan = plan();
    let output = oraclemcp_db::ExecuteOutcome::new(
        0,
        vec![oraclemcp_db::OracleCell::new("NUMBER", Some("42".into()))],
    );
    assert_eq!(
        package_result(&plan, &output).unwrap()["rows"][0]["result"],
        json!("42")
    );
    assert!(package_result(&plan, &oraclemcp_db::ExecuteOutcome::new(0, vec![])).is_err());
    let mut limited = plan;
    limited.wrapper.bindings[1].max_bytes = 1;
    assert!(package_result(&limited, &output).is_err());
}

#[test]
fn custom_package_terminal_effect_survives_late_deadline_and_output_failure() {
    for response in [
        json!({"package_call":true,"executed":true,"committed":true}),
        json!({"package_call":true,"executed":true,"non_transactional_effect":true}),
    ] {
        assert!(response_reports_terminal_effect("app_increment", &response));
    }
    for response in [
        json!({"status":"confirmation_required"}),
        json!({"package_call":true,"executed":true,"committed":false}),
        json!({"rows":[{"package_call":true,"executed":true,"committed":true}]}),
    ] {
        assert!(!response_reports_terminal_effect(
            "app_increment",
            &response
        ));
    }
    for outcome in [
        StatementOutcome::Committed,
        StatementOutcome::CommitUnknown,
        StatementOutcome::DdlOutcomeUnknown,
    ] {
        assert!(error_reports_terminal_effect(
            &package_unavailable("native output/finalization failed")
                .with_statement_outcome(outcome)
        ));
    }
    assert!(!error_reports_terminal_effect(&package_unavailable(
        "refused before execution"
    )));
}

#[cfg(feature = "plsql-intelligence")]
struct ObservedNativeConnection {
    inner: oraclemcp_db::RustOracleConnection,
    calls: Arc<SyncMutex<Vec<(String, String)>>>,
    closes: Arc<AtomicUsize>,
}
#[cfg(feature = "plsql-intelligence")]
#[async_trait::async_trait(?Send)]
impl OracleConnection for ObservedNativeConnection {
    fn backend(&self) -> OracleBackend {
        self.inner.backend()
    }
    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.ping(cx).await
    }
    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.inner.describe(cx).await
    }
    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.inner.query_rows(cx, sql, binds).await
    }
    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        self.inner.execute(cx, sql, binds).await
    }
    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.commit(cx).await
    }
    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.rollback(cx).await
    }
    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.close(cx).await?;
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        self.inner.call_timeout()
    }
    fn set_call_timeout(&self, value: Option<Duration>) -> Result<(), DbError> {
        self.inner.set_call_timeout(value)
    }
    fn request_deadline(&self, cx: &Cx) -> Result<Option<Time>, DbError> {
        self.inner.request_deadline(cx)
    }
    fn set_request_deadline(&self, cx: &Cx, value: Option<Time>) -> Result<(), DbError> {
        self.inner.set_request_deadline(cx, value)
    }
    fn request_quota(&self, cx: &Cx) -> Result<Option<DbRequestQuota>, DbError> {
        self.inner.request_quota(cx)
    }
    fn set_request_quota(&self, cx: &Cx, value: Option<DbRequestQuota>) -> Result<(), DbError> {
        self.inner.set_request_quota(cx, value)
    }
    async fn call_routine(
        &self,
        cx: &Cx,
        sql: &str,
        args: &[oraclemcp_db::OracleRoutineArg],
    ) -> Result<oraclemcp_db::ExecuteOutcome, DbError> {
        let info = self.inner.describe(cx).await?;
        let identity = (
            info.sid
                .ok_or_else(|| DbError::Query("native SID unavailable".into()))?,
            info.serial_number
                .ok_or_else(|| DbError::Query("native serial unavailable".into()))?,
        );
        self.calls.lock().unwrap().push(identity);
        self.inner.call_routine(cx, sql, args).await
    }
}

#[cfg(feature = "plsql-intelligence")]
async fn native_dispatch(
    dispatcher: &OracleDispatcher,
    cx: &Cx,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    match ToolDispatch::dispatch(dispatcher, cx, DispatchContext::default(), name, args).await {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(error.message),
        other => Err(format!(
            "native package dispatch did not complete: {other:?}"
        )),
    }
}

#[cfg(feature = "plsql-intelligence")]
#[test]
#[ignore = "requires the local FREE23 lab; validates the wrapper's qualified intrinsic calls"]
fn custom_package_live_builtin_input_conversions() {
    use oraclemcp_db::{OracleConnectOptions, OracleRoutineArg, RustOracleConnection};
    let options = OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN").unwrap(),
        username: Some(std::env::var("ORACLEMCP_TEST_USER").unwrap()),
        password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap()),
        call_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    };
    assert!(options.connect_string.starts_with("localhost:1523/"));
    let reactor = asupersync::runtime::reactor::create_reactor().unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .unwrap();
    runtime.block_on(Box::pin(async move {
            let cx=Cx::current().unwrap();let conn=RustOracleConnection::connect(&cx,options).await.unwrap();
            let context=oraclemcp_db::read_catalog_resolve_context(&cx,&conn,Default::default(),Default::default()).await.unwrap();
            check_package_name_capture(&cx,&conn,&context.current_schema,"SYS").await.unwrap();
            let outcome:Result<(),String>=async {
                for (sql,input,expected) in [
                    (r#"DECLARE v DATE; BEGIN v := SYS.STANDARD.TO_DATE(:1,'FXYYYY-MM-DD"T"HH24:MI:SS','NLS_DATE_LANGUAGE=American'); :2 := SYS.STANDARD.TO_CHAR(v,'YYYY-MM-DD"T"HH24:MI:SS'); END;"#,"2026-10-31T14:15:16","2026-10-31T14:15:16"),
                    (r#"DECLARE v TIMESTAMP(9); BEGIN v := SYS.STANDARD.TO_TIMESTAMP(:1,'FXYYYY-MM-DD"T"HH24:MI:SS.FF9','NLS_DATE_LANGUAGE=American'); :2 := SYS.STANDARD.TO_CHAR(v,'YYYY-MM-DD"T"HH24:MI:SS.FF9'); END;"#,"2026-10-31T14:15:16.123456789","2026-10-31T14:15:16.123456789"),
                    ("DECLARE v RAW(8); BEGIN v := SYS.STANDARD.HEXTORAW(:1); :2 := SYS.STANDARD.RAWTOHEX(v); END;","CAFE","CAFE"),
                ] {
                    let result=conn.call_routine(&cx,sql,&[OracleRoutineArg::input(OracleBind::String(input.into())).unwrap(),OracleRoutineArg::output(1,1,128)]).await.map_err(|e|e.to_string())?;
                    if result.out_binds().len()!=1 || result.out_binds()[0].value.as_deref()!=Some(expected) {return Err(format!("intrinsic conversion result {:?}",result.out_binds()));}
                }
                Ok(())
            }.await;
            conn.close(&cx).await.unwrap();outcome.unwrap();
        }));
}

#[cfg(feature = "plsql-intelligence")]
#[test]
#[ignore = "requires the local FREE23 lab; creates only run-owned package/table fixtures"]
fn custom_package_live_activation_scalar_out_dml_and_fresh_ddl() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("oraclemcp::mutation_closure=debug")
        .try_init();
    use oraclemcp_audit::{MemoryAuditSink, SigningKey};
    use oraclemcp_db::{OracleConnectOptions, RustOracleConnection};
    use std::time::{SystemTime, UNIX_EPOCH};
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
    runtime.block_on(Box::pin(async move {
            let cx=Cx::current().unwrap();
            let setup=RustOracleConnection::connect(&cx,options.clone()).await.unwrap();
            let context=oraclemcp_db::read_catalog_resolve_context(&cx,&setup,Default::default(),Default::default()).await.unwrap();
            let owner=&context.connected_schema;
            let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
            let package=format!("OMCP_CP_{nonce:X}"); let table=format!("OMCP_CT_{nonce:X}"); let created=format!("OMCP_CD_{nonce:X}");
            setup.execute(&cx,&format!("CREATE TABLE \"{owner}\".\"{table}\" (ID NUMBER)"),&[]).await.unwrap();
            let outcome:Result<(),String>=Box::pin(async {
                setup.execute(&cx,&format!("CREATE PACKAGE \"{owner}\".\"{package}\" AUTHID DEFINER AS FUNCTION INC(PX NUMBER) RETURN NUMBER; PROCEDURE GET_OUT(PT OUT VARCHAR2); PROCEDURE INS(PX NUMBER); PROCEDURE MAKE_TABLE; END;"),&[]).await.map_err(|e|e.to_string())?;
                // Run-owned ordinary identifiers exercise the engine's proven
                // SQL grammar; quoted SQL inside a routine remains Unknown.
                if !owner.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_') { return Err("fixture requires an ordinary uppercase schema name".into()); }
                setup.execute(&cx,&format!("CREATE PACKAGE BODY \"{owner}\".\"{package}\" AS FUNCTION INC(PX NUMBER) RETURN NUMBER IS BEGIN RETURN PX+1; END; PROCEDURE GET_OUT(PT OUT VARCHAR2) IS BEGIN PT := 'scalar OUT'; END; PROCEDURE INS(PX NUMBER) IS BEGIN INSERT INTO {owner}.{table} (ID) VALUES(PX); END; PROCEDURE MAKE_TABLE IS BEGIN EXECUTE IMMEDIATE 'CREATE TABLE {owner}.{created} (ID NUMBER)'; END; END;"),&[]).await.map_err(|e|e.to_string())?;
                let key=HmacSha256Key::new(b"live-package-call-key-0123456789".to_vec()).unwrap();
                let mut pending=Vec::new();
                for (name,member,args,params) in [
                    ("live_inc","INC",r#"[{oracle_type="NUMBER",direction="RETURN",bind_name="result"},{oracle_name="PX",oracle_type="NUMBER",direction="IN",bind_name="x"}]"#,r#"[{name="x",type="integer",required=true}]"#),
                    ("live_out","GET_OUT",r#"[{oracle_name="PT",oracle_type="VARCHAR2",direction="OUT",bind_name="text",max_bytes=64}]"#,"[]"),
                    ("live_ins","INS",r#"[{oracle_name="PX",oracle_type="NUMBER",direction="IN",bind_name="x"}]"#,r#"[{name="x",type="integer",required=true}]"#),
                    ("live_ddl","MAKE_TABLE","[]","[]"),
                ] {
                    let mut source=oraclemcp_db::mutation_closure::read_mutation_routine_source(&cx,&setup,owner,&package,"PACKAGE BODY",Some(member)).await.map_err(|e|format!("{member} source: {e:?}"))?;
                    source.use_context=oraclemcp_db::mutation_closure::MutationRoutineUse::CustomToolCall;
                    let config=format!("[[tool]]\nname=\"{name}\"\ndescription=\"Native activation fixture\"\nclosure_sha256=\"{}\"\nroutine={{owner=\"{owner}\",package=\"{package}\",member=\"{member}\",subprogram_id={}}}\nargs={args}\nparams={params}\n", "a".repeat(64),source.subprogram_id.unwrap());
                    let mut def=oraclemcp_core::parse_tools_file(&config).map_err(|e|e.to_string())?.remove(0);
                    let proof=Box::pin(crate::mutation_closure::EngineMutationEffects.prove_package_call(&cx,&setup,&source,&def.args)).await.map_err(|e|format!("{member} effects: {e:?}"))?;
                    def.closure_sha256=Some(proof.proof.closure_fingerprint);
                    def.signature=Some(oraclemcp_core::sign(&def,&key));
                    pending.push(oraclemcp_core::prepare_package_definition(&def,&key).unwrap());
                    if member=="INC" {
                        let mut bad=def.clone();bad.name="live_bad_pin".into();bad.closure_sha256=Some("0".repeat(64));bad.signature=Some(oraclemcp_core::sign(&bad,&key));
                        pending.push(oraclemcp_core::prepare_package_definition(&bad,&key).unwrap());
                        let mut above=def.clone();above.name="live_above_max".into();above.declared_level=Some("ADMIN".into());above.signature=Some(oraclemcp_core::sign(&above,&key));
                        pending.push(oraclemcp_core::prepare_package_definition(&above,&key).unwrap());
                    }
                }
                let catalog=CustomToolCatalog::with_pending(Vec::new(),pending);
                if !catalog.is_empty() { return Err("pending package definitions were advertised".into()); }
                let connector_options=options.clone();
                let called=Arc::new(SyncMutex::new(Vec::new()));let closed=Arc::new(AtomicUsize::new(0));
                let observed_calls=Arc::clone(&called);let observed_closes=Arc::clone(&closed);
                let dirty_sql=format!("INSERT INTO {owner}.{table} (ID) VALUES(-99)");
                let connector:Arc<ProfileConnector>=Arc::new(move |cx,_profile| {
                    let options=connector_options.clone();let calls=Arc::clone(&observed_calls);let closes=Arc::clone(&observed_closes);let dirty_sql=dirty_sql.clone();
                    Box::pin(async move {
                        let inner=RustOracleConnection::connect(cx,options).await?;
                        // A real uncommitted canary on the returned connection
                        // must be cleared before Oracle's implicit DDL commit.
                        inner.execute(cx,&dirty_sql,&[]).await?;
                        Ok(ProfileConnectionBundle::new(Box::new(ObservedNativeConnection{inner,calls,closes}),None))
                    })
                });
                let mut level=SessionLevelState::new(OperatingLevel::Ddl,false); level.set_current_level(OperatingLevel::Ddl).unwrap();
                let auditor=Arc::new(Auditor::new(Box::new(MemoryAuditSink::new()),SigningKey::new("native-package",b"native-package-audit-key-0123456789".to_vec()).unwrap()));
                let primary=RustOracleConnection::connect(&cx,options.clone()).await.map_err(|e|e.to_string())?;
                let primary_info=primary.describe(&cx).await.map_err(|e|e.to_string())?;
                let primary_identity=(primary_info.sid.ok_or("primary SID unavailable")?,primary_info.serial_number.ok_or("primary serial unavailable")?);
                let dispatcher=OracleDispatcher::new_switchable_with_custom_tools(Box::new(primary),Some("native-package".into()),level,connector,catalog,None).with_auditor(auditor);
                let surface=dispatcher.surface_state_with_cx(&cx,DispatchContext::default(),McpSurfaceDetail::LevelOnly).await.map_err(|e|e.message)?;
                if surface.custom_catalog.tools.len()!=4 {
                    let state=dispatcher.state.lock(&cx).await.unwrap();
                    return Err(format!("expected four activated tools; plans={:?}",state.custom_catalog.package_plans));
                }
                let bad=native_dispatch(&dispatcher,&cx,"live_bad_pin",json!({"x":41})).await.unwrap_err();
                if !bad.contains("CUSTOM_TOOL_CLOSURE_PIN_MISMATCH"){return Err(format!("wrong-pin definition did not refuse at activation: {bad}"));}
                let above=native_dispatch(&dispatcher,&cx,"live_above_max",json!({"x":41})).await.unwrap_err();
                if !above.contains("profile ceiling"){return Err(format!("above-ceiling definition did not refuse at activation: {above}"));}
                if surface.custom_catalog.tools.iter().find(|tool|tool.name=="live_inc").and_then(|tool|tool.required_level)!=Some(OperatingLevel::ReadOnly){return Err("pure tool listing lacks required_level READ_ONLY".into());}
                dispatcher.state.lock(&cx).await.unwrap().level.set_current_level(OperatingLevel::ReadOnly).unwrap();
                let call=native_dispatch(&dispatcher,&cx,"live_inc",json!({"x":41})).await?;
                if call["rows"][0]["result"]!=json!("42") { return Err(format!("scalar result {call}")); }
                let call=native_dispatch(&dispatcher,&cx,"live_out",json!({})).await?;
                if call["rows"][0]["text"]!=json!("scalar OUT") { return Err(format!("OUT result {call}")); }
                dispatcher.state.lock(&cx).await.unwrap().level.set_current_level(OperatingLevel::ReadWrite).unwrap();
                let preview=native_dispatch(&dispatcher,&cx,"live_ins",json!({"x":47})).await?;
                if preview["status"]!="confirmation_required" { return Err(format!("missing DML preview {preview}")); }
                let token=preview["confirmation_token"].as_str().ok_or("missing token")?;
                let rolled=native_dispatch(&dispatcher,&cx,"live_ins",json!({"x":47,"confirm":token})).await?;
                if rolled["status"]!="rolled_back" { return Err(format!("DML did not roll back: {rolled}")); }
                let count=setup.query_rows(&cx,&format!("SELECT COUNT(*) AS N FROM \"{owner}\".\"{table}\""),&[]).await.map_err(|e|e.to_string())?;
                if count[0].parse_i64("N")!=Some(0) { return Err("rollback-default DML persisted".into()); }
                if native_dispatch(&dispatcher,&cx,"live_ins",json!({"x":47,"confirm":token})).await.is_ok() { return Err("single-use token replay succeeded".into()); }
                dispatcher.state.lock(&cx).await.unwrap().level.set_current_level(OperatingLevel::Ddl).unwrap();
                let preview=native_dispatch(&dispatcher,&cx,"live_ddl",json!({"commit":true})).await?;
                let token=preview["confirmation_token"].as_str().ok_or("missing DDL token")?;
                let applied=native_dispatch(&dispatcher,&cx,"live_ddl",json!({"commit":true,"confirm":token})).await?;
                if applied["session_discarded"]!=true || applied["irreversible"]!=true { return Err(format!("DDL custody result {applied}")); }
                let observed=called.lock().unwrap().clone();
                if observed.len()!=1 || observed[0]==primary_identity || closed.load(Ordering::SeqCst)!=1 {return Err(format!("one-shot wire/close evidence is wrong: calls={observed:?}, primary={primary_identity:?}, closes={}",closed.load(Ordering::SeqCst)));}
                let count=setup.query_rows(&cx,&format!("SELECT COUNT(*) AS N FROM \"{owner}\".\"{table}\""),&[]).await.map_err(|e|e.to_string())?;
                if count[0].parse_i64("N")!=Some(0) {return Err("DDL implicitly committed the connection factory's uncommitted canary".into());}
                setup.query_rows(&cx,&format!("SELECT ID FROM \"{owner}\".\"{created}\""),&[]).await.map_err(|e|format!("fresh DDL table absent: {e}"))?;
                let state=dispatcher.state.lock(&cx).await.unwrap(); close_conn_cleanup(&cx,state.conn.as_ref()).await.map_err(|e|e.to_string())?;
                Ok(())
            }).await;
            for sql in [format!("DROP PACKAGE \"{owner}\".\"{package}\""),format!("DROP TABLE \"{owner}\".\"{created}\" PURGE"),format!("DROP TABLE \"{owner}\".\"{table}\" PURGE")] {
                if let Err(error)=setup.execute(&cx,&sql,&[]).await && ![Some(4043),Some(942)].contains(&error.clone().into_envelope().ora_code) { panic!("native fixture cleanup failed: {error}"); }
            }
            setup.close(&cx).await.unwrap(); outcome.unwrap();
        }));
}
