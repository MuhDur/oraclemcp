//! Unit tests for the `oraclemcp` binary, relocated verbatim from the former
//! inline `#[cfg(test)] mod tests` block in `main.rs`, so the CLI flow there
//! stays readable. Reached via `#[cfg(test)] #[path = "main_tests.rs"] mod tests;`
//! at the crate root, so `super::*` still resolves to `main.rs`. Top-level items
//! are de-indented one level by rustfmt; every raw-string fixture stays
//! byte-identical (rustfmt never rewrites inside raw string literals).

use super::*;
use oraclemcp_audit::{AuditRecord, DbEvidence};
use oraclemcp_config::HttpOAuthConfig;

fn self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

fn target_tmp_file(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../target/tmp/oraclemcp-main-tests");
    fs::create_dir_all(&path).expect("test temp dir exists");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    path.push(format!("{}-{}-{name}", std::process::id(), nanos));
    path
}

#[test]
fn runtime_profile_selection_does_not_resolve_secret_refs() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            schema_version = 1
            default_profile = "prod"

            [[profiles]]
            name = "prod"
            connect_string = "prod.example:1521/service"
            username = "APP_USER"
            credential_ref = "env:ORACLEMCP_TEST_UNSET_DB_PASSWORD"

            [profiles.oci]
            wallet_password_ref = "env:ORACLEMCP_TEST_UNSET_WALLET_PASSWORD"
            "#,
    )
    .expect("valid config");

    let selected = select_runtime_profile_from_config(&cfg, None)
        .expect("metadata selection does not touch secret backends")
        .expect("default profile selected");
    assert_eq!(selected.name, "prod");
    assert_eq!(selected.level.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(
        selected.request_timeout,
        Some(std::time::Duration::from_secs(30))
    );
}

#[test]
fn http_listen_refused_without_allow_no_auth() {
    let err = http_listen_guard(false, false, false, "127.0.0.1:7070", false).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
}

// ── A8 multi-profile audit reachability (the keystone) ──────────────────

#[test]
fn reachable_ceiling_spans_writable_exposed_profile_with_readonly_startup() {
    // Per-profile opt-out: both profiles are exposed (neither sets
    // mcp_exposed=false). The startup profile is read-only, but a writable
    // profile is reachable — so a switch to it can run writes, and the
    // reachable ceiling must reflect that.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "ro_start"
            connect_string = "localhost:1521/FREEPDB1"
            mcp_exposed = true

            [[profiles]]
            name = "writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            mcp_exposed = true
            "#,
    )
    .expect("config parses");
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    assert_eq!(
        max_reachable_write_ceiling(&cfg, &active),
        OperatingLevel::Ddl
    );
}

#[test]
fn reachable_ceiling_ignores_explicitly_hidden_writable_profile() {
    // Per-profile opt-out: a writable profile explicitly hidden with
    // `mcp_exposed = false` is not servable (the agent can never switch to
    // it), so it does not raise the reachable ceiling.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "ro_exposed"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "hidden_writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "READ_WRITE"
            mcp_exposed = false
            "#,
    )
    .expect("config parses");
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    assert_eq!(
        max_reachable_write_ceiling(&cfg, &active),
        OperatingLevel::ReadOnly
    );
}

#[test]
fn reachable_ceiling_spans_all_profiles_by_default() {
    // Per-profile opt-out default: with no profile hidden, all profiles are
    // servable, so a writable one raises the reachable ceiling even though
    // the server started on a read-only profile.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "ro_start"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "READ_WRITE"
            "#,
    )
    .expect("config parses");
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    assert_eq!(
        max_reachable_write_ceiling(&cfg, &active),
        OperatingLevel::ReadWrite
    );
}

#[test]
fn exposed_profiles_summary_lists_exposed_and_counts_hidden() {
    // E5 boot notice (visibility only): exposed profiles are listed with
    // their ceiling; an explicitly hidden one is counted, not named.
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "prod_admin"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            mcp_exposed = false
            "#,
    )
    .expect("config parses");
    let summary = exposed_profiles_summary(&cfg);
    assert!(summary.contains("dev [ReadOnly]"), "{summary}");
    assert!(summary.contains("1 hidden"), "{summary}");
    assert!(
        !summary.contains("prod_admin"),
        "a hidden profile must not be named: {summary}"
    );
}

#[test]
fn build_auditor_fails_closed_when_a_switchable_profile_can_write() {
    // The A8 keystone: a read-only startup profile + a writable exposed
    // profile + NO audit key must fail closed at startup (so the writable
    // profile can never be switched into and run writes UNAUDITED). This is
    // the case the old single-profile check missed. Assumes a clean env
    // (no ORACLEMCP_AUDIT_KEY), as the rest of the suite does.
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let audit = AuditConfig::default(); // no key_ref
    match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
        Err((code, _)) => assert_eq!(code, "ORACLEMCP_AUDIT_KEY_REQUIRED"),
        Ok(_) => panic!("must fail closed: write reachable, no key"),
    }
}

#[test]
fn build_auditor_installs_when_writable_profile_has_a_key() {
    // With a signing key configured, a writable reachable profile installs
    // an auditor (so the writable profile, after a switch, is audited).
    let dir = target_tmp_file("a8-audit");
    fs::create_dir_all(&dir).expect("tmp dir");
    let audit = AuditConfig {
        path: Some(dir.join("audit.jsonl")),
        key_ref: Some("literal:test-signing-key-material".to_owned()),
        ..AuditConfig::default()
    };
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
        Ok(auditor) => assert!(
            auditor.is_some(),
            "an auditor must be installed when a write level is reachable"
        ),
        Err((code, msg)) => panic!("auditor should build with a key: {code}: {msg}"),
    }
}

#[test]
fn build_auditor_optional_when_only_read_only_is_reachable() {
    // Read-only everywhere reachable + no key: auditor is optional (None).
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let audit = AuditConfig::default();
    match build_auditor(
        &audit,
        &active,
        OperatingLevel::ReadOnly,
        &SystemSecretResolver,
    ) {
        Ok(auditor) => assert!(auditor.is_none()),
        Err((code, msg)) => panic!("read-only-only needs no key: {code}: {msg}"),
    }
}

#[test]
fn build_write_intent_log_fails_closed_on_unresolved_restart_intent() {
    let root = target_tmp_file("cx-c1-write-intents");
    {
        let log = WriteIntentLog::open(&root).expect("open intent log");
        let binding = oraclemcp_guard::ExecGrantBinding::new("sess-1", "lane-1", "principal-1", 1);
        let intent = oraclemcp_core::WriteIntent::new(oraclemcp_core::WriteIntentDetails {
            idempotency_key_material: "grant-1",
            subject: "profile:dev",
            active_profile: Some("dev"),
            tool: "oracle_execute",
            sql: "UPDATE employees SET name = name WHERE employee_id = 100",
            required_level: OperatingLevel::ReadWrite,
            binding: &binding,
        });
        log.append_pending(intent).expect("append pending intent");
    }

    match build_write_intent_log_at(&root, OperatingLevel::ReadWrite) {
        Err((code, message)) => {
            assert_eq!(code, "ORACLEMCP_WRITE_INTENT_IN_DOUBT");
            assert!(message.contains("unresolved intent"), "{message}");
            assert!(message.contains("sql_hash=sha256:"), "{message}");
        }
        Ok(_) => panic!("writable startup must fail closed with an unresolved intent"),
    }
}

#[test]
fn http_listen_loopback_allowed_with_allow_no_auth() {
    assert!(http_listen_guard(true, false, false, "127.0.0.1:7070", false).is_ok());
    assert!(http_listen_guard(true, false, true, "[::1]:7070", false).is_ok());
}

#[test]
fn http_listen_loopback_allowed_with_oauth_or_mtls() {
    assert!(http_listen_guard(false, true, false, "127.0.0.1:7070", false).is_ok());
    assert!(http_listen_guard(false, true, true, "127.0.0.1:7070", false).is_ok());
}

#[test]
fn http_listen_non_loopback_refused_without_remote_optin() {
    let err = http_listen_guard(true, false, false, "0.0.0.0:7070", false).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED");
    let err = http_listen_guard(false, true, true, "192.168.1.10:7070", false).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED");
}

#[test]
fn http_listen_non_loopback_allowed_with_remote_optin() {
    assert!(http_listen_guard(true, false, false, "0.0.0.0:7070", true).is_ok());
    assert!(http_listen_guard(false, true, true, "0.0.0.0:7070", true).is_ok());
}

#[test]
fn http_listen_auth_refusal_precedes_remote_check() {
    let err = http_listen_guard(false, false, true, "0.0.0.0:7070", true).unwrap_err();
    assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
}

#[test]
fn http_cli_oauth_builds_enforced_transport_config() {
    let args = HttpServeArgs {
        allowed_hosts: vec!["mcp.example.com".to_owned()],
        allowed_origins: vec!["https://client.example.com".to_owned()],
        json_response: true,
        stateful: true,
        oauth_resource: Some("https://mcp.example.com/mcp".to_owned()),
        oauth_issuers: vec!["https://idp.example.com".to_owned()],
        oauth_authorization_servers: vec!["https://idp.example.com".to_owned()],
        oauth_required_scopes: vec!["oracle:read".to_owned()],
        oauth_hs256_secret_ref: Some("literal:test-secret".to_owned()),
        ..Default::default()
    };
    let http = apply_http_cli_overrides(HttpConfig::default(), &args);
    let cfg = http_transport_config_from_merged(http, false, &SystemSecretResolver)
        .expect("valid OAuth transport config");

    assert!(cfg.transport.oauth.is_some());
    assert_eq!(
        cfg.transport.resource_metadata.as_ref().expect("metadata")["resource"],
        serde_json::json!("https://mcp.example.com/mcp")
    );
    assert_eq!(cfg.transport.allowed_hosts, ["mcp.example.com"]);
    assert_eq!(
        cfg.transport.allowed_origins,
        ["https://client.example.com"]
    );
    assert!(cfg.transport.json_response);
    assert!(cfg.transport.stateful);
    assert!(cfg.transport.single_principal_guard.is_some());
    assert!(cfg.tls.is_none());
}

#[test]
fn http_oauth_literal_secret_is_rejected_for_protected_profiles() {
    let http = HttpConfig {
        oauth: Some(HttpOAuthConfig {
            resource: Some("https://mcp.example.com/mcp".to_owned()),
            allowed_issuers: vec!["https://idp.example.com".to_owned()],
            authorization_servers: vec!["https://idp.example.com".to_owned()],
            required_scopes: vec!["oracle:read".to_owned()],
            hs256_secret_ref: Some("literal:test-secret".to_owned()),
            metadata_url: None,
        }),
        ..Default::default()
    };

    let err = http_transport_config_from_merged(http, true, &SystemSecretResolver)
        .expect_err("protected profile rejects literal OAuth secret");
    assert_eq!(err.0, "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID");
    assert!(err.1.contains("plaintext literal credential is forbidden"));
    assert!(!err.1.contains("test-secret"));
}

#[test]
fn stateless_http_read_workers_do_not_head_of_line_block() {
    struct ControlDispatch;

    impl ToolDispatch for ControlDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async {
                DispatchOutcome::Ok(serde_json::json!({
                    "control": true
                }))
            })
        }
    }

    struct BlockingReadDispatch {
        started: std::sync::mpsc::Sender<()>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl ToolDispatch for BlockingReadDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                self.started.send(()).expect("test observer is alive");
                let (lock, cvar) = &*self.release;
                let mut released = lock.lock().expect("release mutex not poisoned");
                while !*released {
                    released = cvar.wait(released).expect("release mutex not poisoned");
                }
                DispatchOutcome::Ok(serde_json::json!({
                    "schemas": []
                }))
            })
        }
    }

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new({
        let release = Arc::clone(&release);
        move |_profile| {
            let started = started_tx.clone();
            let release = Arc::clone(&release);
            Arc::new(move |_cx: &Cx, _lane_context: &LaneContext| {
                let dispatch: Arc<dyn ToolDispatch> = Arc::new(BlockingReadDispatch {
                    started: started.clone(),
                    release: Arc::clone(&release),
                });
                Box::pin(async move { Ok(dispatch) })
            })
        }
    });
    let control_lane = LaneRuntime::spawn("test-stateless-control", Arc::new(ControlDispatch), 4);
    let dispatch = Arc::new(HttpStatelessReadDispatch::new(
        control_lane,
        Some("dev".to_owned()),
        2,
        read_factory,
    ));

    let mut handles = Vec::new();
    for _ in 0..2 {
        let dispatch = Arc::clone(&dispatch);
        handles.push(std::thread::spawn(move || {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("test runtime builds");
            runtime.block_on(async move {
                let cx = Cx::current().expect("test runtime installs Cx");
                let outcome = dispatch
                    .dispatch(
                        &cx,
                        oraclemcp_core::DispatchContext::default()
                            .with_principal_key("oauth:reader"),
                        "oracle_list_schemas",
                        serde_json::json!({ "max_rows": 1 }),
                    )
                    .await;
                assert!(matches!(outcome, DispatchOutcome::Ok(_)));
            });
        }));
    }

    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("first read worker starts");
    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("second read worker starts without waiting for first to finish");

    let (lock, cvar) = &*release;
    *lock.lock().expect("release mutex not poisoned") = true;
    cvar.notify_all();
    for handle in handles {
        handle.join().expect("read worker caller joins");
    }
}

#[test]
fn stateless_http_profile_switch_closes_read_workers() {
    struct SwitchControlDispatch;

    impl ToolDispatch for SwitchControlDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                if name == "oracle_switch_profile" {
                    DispatchOutcome::Ok(serde_json::json!({
                        "active_profile": "prod"
                    }))
                } else {
                    DispatchOutcome::Ok(serde_json::json!({
                        "control": name
                    }))
                }
            })
        }
    }

    struct ProfileReadDispatch {
        profile: Option<String>,
        seen: std::sync::mpsc::Sender<Option<String>>,
        closed: std::sync::mpsc::Sender<DispatchCloseReason>,
    }

    impl ToolDispatch for ProfileReadDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            _name: &'a str,
            _args: serde_json::Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                self.seen
                    .send(self.profile.clone())
                    .expect("test profile observer is alive");
                DispatchOutcome::Ok(serde_json::json!({
                    "schemas": []
                }))
            })
        }

        fn close<'a>(
            &'a self,
            _cx: &'a Cx,
            reason: DispatchCloseReason,
        ) -> oraclemcp_core::DispatchCloseFuture<'a> {
            self.closed
                .send(reason)
                .expect("test close observer is alive");
            Box::pin(async { Ok(()) })
        }
    }

    let (profile_tx, profile_rx) = std::sync::mpsc::channel();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new(move |profile| {
        let seen = profile_tx.clone();
        let closed = closed_tx.clone();
        Arc::new(move |_cx: &Cx, _lane_context: &LaneContext| {
            let dispatch: Arc<dyn ToolDispatch> = Arc::new(ProfileReadDispatch {
                profile: profile.clone(),
                seen: seen.clone(),
                closed: closed.clone(),
            });
            Box::pin(async move { Ok(dispatch) })
        })
    });
    let control_lane = LaneRuntime::spawn(
        "test-stateless-switch-control",
        Arc::new(SwitchControlDispatch),
        4,
    );
    let dispatch =
        HttpStatelessReadDispatch::new(control_lane, Some("dev".to_owned()), 1, read_factory);

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("test runtime installs Cx");
        let first = dispatch
            .dispatch(
                &cx,
                oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                "oracle_list_schemas",
                serde_json::json!({ "max_rows": 1 }),
            )
            .await;
        assert!(matches!(first, DispatchOutcome::Ok(_)));

        let switched = dispatch
            .dispatch(
                &cx,
                oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                "oracle_switch_profile",
                serde_json::json!({ "profile": "prod" }),
            )
            .await;
        assert!(matches!(switched, DispatchOutcome::Ok(_)));

        let second = dispatch
            .dispatch(
                &cx,
                oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                "oracle_list_schemas",
                serde_json::json!({ "max_rows": 1 }),
            )
            .await;
        assert!(matches!(second, DispatchOutcome::Ok(_)));
    });

    assert_eq!(
        profile_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("first read records startup profile"),
        Some("dev".to_owned())
    );
    assert_eq!(
        closed_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("profile switch closes old read lane"),
        DispatchCloseReason::RuntimeDrop
    );
    assert_eq!(
        profile_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("next read records switched profile"),
        Some("prod".to_owned())
    );
}

#[test]
fn http_tls_material_builds_native_tls_config() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, _client_ca_key) = self_signed_cert();
    let cert_path = target_tmp_file("server.pem");
    let key_path = target_tmp_file("server.key");
    let client_ca_path = target_tmp_file("client-ca.pem");
    fs::write(&cert_path, server_cert).expect("server cert fixture");
    fs::write(&key_path, server_key).expect("server key fixture");
    fs::write(&client_ca_path, client_ca).expect("client CA fixture");

    let args = HttpServeArgs {
        tls_cert: Some(cert_path.clone()),
        tls_key: Some(key_path),
        mtls_client_ca: Some(client_ca_path.clone()),
        mtls_client_fingerprints: vec![
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        ],
        ..Default::default()
    };
    let http = apply_http_cli_overrides(HttpConfig::default(), &args);
    assert_eq!(
        http.tls
            .as_ref()
            .and_then(|tls| tls.client_ca_path.as_deref()),
        Some(client_ca_path.as_path())
    );

    let cfg = http_transport_config_from_merged(http, false, &SystemSecretResolver)
        .expect("native TLS listener config builds");
    assert!(cfg.tls.is_some());
    assert!(cfg.mtls_required);
    assert!(!cfg.transport.mtls_clients.is_empty());
}

#[test]
fn stub_connection_returns_an_envelopable_error() {
    let stub = stub::StubConnection::new(oraclemcp_db::DbError::Connect(
        "listener refused the connection".to_owned(),
    ));
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    let err = runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        stub.ping(&cx).await.expect_err("stub always errors")
    });
    // It maps to a structured envelope (no panic).
    let _ = err.into_envelope();
}

#[test]
fn stdout_exit_treats_broken_pipe_as_success_path() {
    let code = stdout_exit(
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")),
        ExitCode::from(2),
    );
    assert_eq!(format!("{code:?}"), "ExitCode(unix_exit_status(0))");
}

#[test]
fn doctor_process_exit_code_matches_cli_contract() {
    let ok = oraclemcp_core::DoctorReport {
        checks: Vec::new(),
        profile_caps: None,
        auth_capabilities: None,
        service_health: None,
        service_unit_caps: None,
        fix: None,
    };
    assert_eq!(doctor_process_exit_code(&ok), 0);

    let failed = oraclemcp_core::DoctorReport {
        checks: vec![oraclemcp_core::CheckResult {
            id: 1,
            name: "example".to_owned(),
            status: oraclemcp_core::CheckStatus::Fail,
            detail: "failed".to_owned(),
            fix: None,
            failure_class: None,
            auth_mode: None,
            wallet_error: None,
            ora_code: None,
        }],
        profile_caps: None,
        auth_capabilities: None,
        service_health: None,
        service_unit_caps: None,
        fix: None,
    };
    let process_code = doctor_process_exit_code(&failed);
    assert_eq!(process_code, 2);
    assert_eq!(
        failed.to_json_with_exit_code(i32::from(process_code))["exit_code"],
        serde_json::json!(2)
    );
    let fix_report = failed.with_fix_report();
    assert_eq!(doctor_process_exit_code(&fix_report), 2);
}

#[test]
fn doctor_sensitive_values_include_connect_material() {
    let opts = OracleConnectOptions {
        connect_string: "dbhost:1521/private_service".to_owned(),
        username: Some("APP_USER".to_owned()),
        password: Some("super_secret".to_owned()),
        auth_adapter: oraclemcp_db::AuthAdapter::Proxy {
            proxy_user: "MCP_PROXY".to_owned(),
            target_schema: "APP_OWNER".to_owned(),
        },
        wallet_location: Some("/home/operator/private-wallet".into()),
        wallet_password: Some("wallet_secret".to_owned()),
        ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
        use_iam_token: true,
        iam_token: Some("iam.jwt.token".to_owned()),
        app_context: vec![(
            "private-namespace".to_owned(),
            "private-key".to_owned(),
            "private-value".to_owned(),
        )],
        session_identity: Some(oraclemcp_db::OracleSessionIdentity {
            program: Some("private-program".to_owned()),
            machine: Some("private-machine".to_owned()),
            os_user: Some("private-os-user".to_owned()),
            terminal: Some("private-terminal".to_owned()),
            module: Some("private-module".to_owned()),
            action: Some("private-action".to_owned()),
            client_identifier: Some("private-client-id".to_owned()),
            client_info: Some("private-client-info".to_owned()),
            driver_name: Some("private-driver".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let values = doctor_sensitive_values(&opts);
    for expected in [
        "dbhost:1521/private_service",
        "APP_USER",
        "super_secret",
        "MCP_PROXY",
        "APP_OWNER",
        "/home/operator/private-wallet",
        "wallet_secret",
        "CN=private-db,O=Example,C=US",
        "iam.jwt.token",
        "private-program",
        "private-machine",
        "private-os-user",
        "private-terminal",
        "private-module",
        "private-action",
        "private-client-id",
        "private-client-info",
        "private-driver",
        "private-namespace",
        "private-key",
        "private-value",
    ] {
        assert!(values.iter().any(|value| value == expected), "{values:?}");
    }
}

#[test]
fn wallet_password_ref_uses_profile_secret_resolution_policy() {
    let secret = resolve_profile_secret(
        "wallet_password_ref",
        "dev",
        Some("literal:wallet"),
        false,
        &SystemSecretResolver,
    )
    .expect("dev literal")
    .expect("secret");
    assert_eq!(secret, "wallet");

    let err = resolve_profile_secret(
        "wallet_password_ref",
        "prod",
        Some("literal:wallet"),
        true,
        &SystemSecretResolver,
    )
    .expect_err("protected literal rejected");
    assert!(err.to_string().contains("wallet_password_ref"));
    assert!(
        err.to_string()
            .contains("plaintext literal credential is forbidden")
    );
}

#[test]
fn profile_secret_resolution_errors_do_not_echo_secret_locators() {
    let err = resolve_profile_secret(
        "wallet_password_ref",
        "prod",
        Some("env:PRIVATE_WALLET_PASSWORD_NAME"),
        true,
        &SystemSecretResolver,
    )
    .expect_err("missing env var");
    let rendered = err.to_string();
    assert!(rendered.contains("wallet_password_ref"));
    assert!(rendered.contains("secret not found"));
    assert!(!rendered.contains("PRIVATE_WALLET_PASSWORD_NAME"));
    assert!(!rendered.contains("env:"));

    let err = resolve_profile_secret(
        "credential_ref",
        "prod",
        Some("noscheme-secret-ref"),
        true,
        &SystemSecretResolver,
    )
    .expect_err("malformed ref");
    let rendered = err.to_string();
    assert!(rendered.contains("credential_ref"));
    assert!(rendered.contains("malformed secret reference"));
    assert!(!rendered.contains("noscheme-secret-ref"));
}

#[test]
fn doctor_connection_error_uses_agent_envelope_message() {
    let message = doctor_connection_error(oraclemcp_db::DbError::UnsupportedAuth(
        "connection profile `missing_ro` not found".to_owned(),
    ));
    assert_eq!(message, "connection profile `missing_ro` not found");
}

#[test]
fn doctor_profile_auth_capabilities_are_metadata_only() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            schema_version = 1

            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"

            [profiles.proxy_auth]
            proxy_user = "APP_USER"
            target_schema = "APP_OWNER"

            [[profiles]]
            name = "iam"
            connect_string = "tcps://private.example/svc"
            username = "IAM_USER"

            [profiles.oci]
            wallet_location = "/wallets/private"
            use_iam_token = true

            [[profiles]]
            name = "external"
            connect_string = "tcps://private.example/svc"

            [profiles.oci]
            wallet_location = "/wallets/private"
            wallet_password_ref = "env:WALLET_PASSWORD"
            "#,
    )
    .expect("valid config");

    let proxy = doctor_auth_capabilities_for_profile(cfg.profile("proxy").unwrap());
    assert_eq!(proxy.selected, DoctorAuthModeKind::Proxy);
    let iam = doctor_auth_capabilities_for_profile(cfg.profile("iam").unwrap());
    assert_eq!(iam.selected, DoctorAuthModeKind::IamToken);
    let external = doctor_auth_capabilities_for_profile(cfg.profile("external").unwrap());
    assert_eq!(external.selected, DoctorAuthModeKind::ExternalWallet);

    let serialized = serde_json::to_string(&serde_json::json!([proxy, iam, external]))
        .expect("auth capabilities serialize");
    for forbidden in [
        "APP_USER",
        "APP_OWNER",
        "ORACLE_PASSWORD",
        "WALLET_PASSWORD",
        "/wallets/private",
        "private.example",
        "FREEPDB1",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "{forbidden} leaked: {serialized}"
        );
    }
    for expected in [
        "\"driver\":\"thin\"",
        "\"selected\":\"proxy\"",
        "\"selected\":\"iam_token\"",
        "\"selected\":\"external_wallet\"",
        "\"support\":\"unsupported_in_thin\"",
    ] {
        assert!(
            serialized.contains(expected),
            "{expected} missing from {serialized}"
        );
    }
}

#[test]
fn profiles_json_reports_non_secret_metadata() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            schema_version = 1
            default_profile = "dev"

            [[profiles]]
            name = "dev"
            description = "Development profile"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"
            max_level = "READ_ONLY"
            default_level = "READ_ONLY"
            require_signed_tools = true
            dashboard_ddl_workbench = true
            sdu = 32768

            [profiles.oci]
            wallet_location = "/wallets/private"
            wallet_password_ref = "env:WALLET_PASSWORD"
            ssl_server_cert_dn = "CN=private-db"

            [profiles.proxy_auth]
            proxy_user = "APP_USER"
            target_schema = "APP_OWNER"

            [profiles.drcp]
            pooled = true
            connection_class = "PRIVATE_CLASS"
            purity = "reuse"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "tenant_id"
            value = "tenant-123"
            "#,
    )
    .expect("valid config");

    let out = profiles_json(&cfg);
    assert_eq!(out["ok"], serde_json::json!(true));
    assert_eq!(out["profile_count"], serde_json::json!(1));
    assert_eq!(out["has_default_profile"], serde_json::json!(true));
    assert_eq!(out["profiles"][0]["name"], serde_json::json!("dev"));
    assert_eq!(out["profiles"][0]["is_default"], serde_json::json!(true));
    assert_eq!(
        out["profiles"][0]["require_signed_tools"],
        serde_json::json!(true)
    );
    assert_eq!(
        out["profiles"][0]["dashboard_ddl_workbench"],
        serde_json::json!(true)
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(!serialized.contains("APP_USER"));
    assert!(!serialized.contains("APP_OWNER"));
    assert!(!serialized.contains("ORACLE_PASSWORD"));
    assert!(!serialized.contains("WALLET_PASSWORD"));
    assert!(!serialized.contains("/wallets/private"));
    assert!(!serialized.contains("CN=private-db"));
    assert!(!serialized.contains("credential_ref"));
    assert!(!serialized.contains("wallet_password_ref"));
    assert!(!serialized.contains("proxy_auth"));
    assert!(!serialized.contains("target_schema"));
    assert!(!serialized.contains("PRIVATE_CLASS"));
    assert!(!serialized.contains("drcp"));
    assert!(!serialized.contains("ORACLEMCP_CTX"));
    assert!(!serialized.contains("tenant_id"));
    assert!(!serialized.contains("tenant-123"));
    assert!(!serialized.contains("app_context"));
    assert!(!serialized.contains("FREEPDB1"));
    assert!(!serialized.contains("connect_string"));
}

#[test]
fn resolved_secret_material_is_absent_from_rendered_surfaces() {
    let resolved_db_secret = "resolved-db-secret-not-in-config";
    let resolved_wallet_secret = "resolved-wallet-secret-not-in-config";
    let resolved_audit_secret = "resolved-audit-secret-not-in-config";
    let credential_ref = "keyring:prod/app";
    let wallet_ref = "file:/run/secrets/oracle-wallet";

    let cfg = OracleMcpConfig::from_toml_str(&format!(
        r#"
            schema_version = 1

            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            username = "APP_USER"
            credential_ref = "{credential_ref}"

            [profiles.oci]
            wallet_password_ref = "{wallet_ref}"
            "#
    ))
    .expect("valid config");
    let profile_json = serde_json::to_string(&profiles_json(&cfg)).expect("profile json");

    let opts = OracleConnectOptions {
        connect_string: "prod:1521/svc".to_owned(),
        username: Some("APP_USER".to_owned()),
        password: Some(resolved_db_secret.to_owned()),
        wallet_password: Some(resolved_wallet_secret.to_owned()),
        iam_token: Some("resolved-iam-token-not-in-config".to_owned()),
        ..OracleConnectOptions::default()
    };
    let options_debug = format!("{opts:?}");

    let connection_info = oraclemcp_db::OracleConnectionInfo {
        session_user: Some("APP_USER".to_owned()),
        current_schema: Some("APP".to_owned()),
        ..Default::default()
    };
    let connection_info_json = serde_json::to_string(&connection_info).expect("conn json");

    let signing_key = SigningKey::new("test-key", resolved_audit_secret.as_bytes().to_vec());
    let signing_key_debug = format!("{signing_key:?}");
    let audit_record = oraclemcp_audit::AuditRecord::chained_signed(
        &oraclemcp_audit::AuditEntryDraft {
            subject: oraclemcp_audit::AuditSubject::new("subject", "hash"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_query".to_owned(),
            sql: "select 1 from dual".to_owned(),
            danger_level: "READ_ONLY".to_owned(),
            decision: oraclemcp_audit::AuditDecision::Allowed,
            rows_affected: None,
            outcome: oraclemcp_audit::AuditOutcome::Succeeded,
        },
        1,
        oraclemcp_audit::GENESIS_HASH,
        "2026-06-30T00:00:00Z".to_owned(),
        &signing_key,
    );
    let audit_json = serde_json::to_string(&audit_record).expect("audit json");

    for rendered in [
        profile_json.as_str(),
        options_debug.as_str(),
        connection_info_json.as_str(),
        signing_key_debug.as_str(),
        audit_json.as_str(),
    ] {
        for forbidden in [
            resolved_db_secret,
            resolved_wallet_secret,
            resolved_audit_secret,
            "resolved-iam-token-not-in-config",
            credential_ref,
            wallet_ref,
        ] {
            assert!(
                !rendered.contains(forbidden),
                "rendered surface leaked {forbidden}: {rendered}"
            );
        }
    }
}

fn audit_record_for_db_evidence_summary(seq: u64, db_evidence: Option<DbEvidence>) -> AuditRecord {
    let key = SigningKey::new("test-key", b"db-evidence-summary-key".to_vec());
    AuditRecord::chained_signed(
        &oraclemcp_audit::AuditEntryDraft {
            subject: AuditSubject::new("oauth", "subject-hash"),
            db_evidence,
            cancel: None,
            tool: "oracle_execute".to_owned(),
            sql: format!("DELETE FROM private_table WHERE secret_id = {seq}"),
            danger_level: "GUARDED".to_owned(),
            decision: oraclemcp_audit::AuditDecision::Allowed,
            rows_affected: Some(1),
            outcome: oraclemcp_audit::AuditOutcome::Succeeded,
        },
        seq,
        oraclemcp_audit::GENESIS_HASH,
        format!("2026-07-02T00:00:{seq:02}Z"),
        &key,
    )
}

#[test]
fn audit_db_evidence_summary_correlates_signed_session_tags() {
    let records = vec![
        audit_record_for_db_evidence_summary(
            1,
            Some(DbEvidence {
                availability: Some("captured".to_owned()),
                db_unique_name: Some("ORCL23A".to_owned()),
                service_name: Some("freepdb1".to_owned()),
                instance_name: Some("free".to_owned()),
                session_user: Some("APP".to_owned()),
                sid: Some("101".to_owned()),
                serial_number: Some("202".to_owned()),
                client_identifier: Some("oauth-subject".to_owned()),
                module: Some("oraclemcp-test".to_owned()),
                action: Some("execute".to_owned()),
                ..DbEvidence::default()
            }),
        ),
        audit_record_for_db_evidence_summary(2, None),
    ];

    let summary = audit_db_evidence_summary(&records);
    assert_eq!(summary.status, "correlated");
    assert_eq!(summary.records, 2);
    assert_eq!(summary.with_db_evidence, 1);
    assert_eq!(summary.captured, 1);
    assert_eq!(summary.correlated, 1);
    assert_eq!(summary.with_session_tags, 1);
    assert_eq!(summary.missing, 1);

    let payload = audit_db_evidence_payload(&summary);
    assert_eq!(payload["source"], serde_json::json!("signed_audit_records"));
    assert_eq!(payload["live_database_query"], serde_json::json!(false));
    assert_eq!(
        payload["sample_correlations"][0]["seq"],
        serde_json::json!(1)
    );
    assert_eq!(
        payload["sample_correlations"][0]["sid"],
        serde_json::json!("101")
    );
    assert_eq!(
        payload["sample_correlations"][0]["serial_number"],
        serde_json::json!("202")
    );
    let rendered = serde_json::to_string(&payload).expect("payload json");
    assert!(!rendered.contains("DELETE"));
    assert!(!rendered.contains("private_table"));
    assert!(!rendered.contains("secret_id"));
}

#[test]
fn audit_db_evidence_summary_degrades_when_evidence_unavailable() {
    let records = vec![
        audit_record_for_db_evidence_summary(1, Some(DbEvidence::unavailable("describe_failed"))),
        audit_record_for_db_evidence_summary(2, None),
    ];

    let summary = audit_db_evidence_summary(&records);
    assert_eq!(summary.status, "degraded");
    assert_eq!(summary.degraded_reason, Some("db_evidence_unavailable"));
    assert_eq!(summary.records, 2);
    assert_eq!(summary.with_db_evidence, 1);
    assert_eq!(summary.unavailable, 1);
    assert_eq!(summary.missing, 1);
    assert_eq!(summary.correlated, 0);
    assert_eq!(summary.unavailable_reasons, vec!["describe_failed"]);
    assert!(audit_db_evidence_text(&summary).contains("DEGRADED"));
}

#[test]
fn profiles_text_handles_empty_config() {
    let cfg = OracleMcpConfig::from_toml_str("").expect("empty config is valid");
    let text = profiles_text(&cfg);
    assert!(text.contains("no profiles configured"));
    assert!(text.contains("ORACLEMCP_CONFIG"));
}

#[test]
fn setup_payload_is_generic_and_client_ready() {
    let out = setup_payload(
        "tenant_ro",
        "APP_PASSWORD",
        "/opt/oraclemcp-wrapper",
        Some("/opt/oraclemcp-wrapper"),
        "/etc/oraclemcp/profiles.toml",
        "/etc/oraclemcp/tools.d",
    );
    assert_eq!(out["ok"], serde_json::json!(true));
    assert_eq!(out["kind"], serde_json::json!("oraclemcp_setup"));
    assert!(
        out["profiles_toml"]
            .as_str()
            .expect("profiles_toml")
            .contains("credential_ref = \"env:APP_PASSWORD\"")
    );
    let profiles_toml = out["profiles_toml"].as_str().expect("profiles_toml");
    let cfg = OracleMcpConfig::from_toml_str(profiles_toml).expect("setup profiles TOML parses");
    assert_eq!(cfg.default_profile.as_deref(), Some("tenant_ro"));
    let profile = cfg.profile("tenant_ro").expect("starter profile exists");
    assert_eq!(profile.max_level(), OperatingLevel::ReadOnly);
    assert_eq!(profile.default_level(), OperatingLevel::ReadOnly);
    assert!(!profiles_toml.contains("wallet_password_ref"));
    assert!(!profiles_toml.contains("[profiles.oci]"));
    assert!(!profiles_toml.contains("[profiles.drcp]"));
    assert!(!profiles_toml.contains("[profiles.proxy_auth]"));
    assert!(!profiles_toml.contains("[[profiles.app_context]]"));
    assert!(!profiles_toml.contains("[profiles.session_identity]"));
    assert_eq!(
        out["paths"]["full_profile_example"],
        serde_json::json!("oraclemcp.example.toml")
    );
    assert_eq!(
        out["claude_mcp_json"]["mcpServers"]["oracle"]["command"],
        serde_json::json!("/opt/oraclemcp-wrapper")
    );
    assert!(
        out["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains("tenant_ro")
    );
    assert_eq!(
        out["http_client_credentials"]["serve_args"],
        serde_json::json!([
            "serve",
            "--listen",
            "127.0.0.1:7070",
            "--client-credentials",
            "--profile",
            "tenant_ro"
        ])
    );
    assert_eq!(
        out["http_client_credentials"]["claude_mcp_add"],
        serde_json::json!([
            "claude",
            "mcp",
            "add",
            "oracle",
            "--transport",
            "http",
            "http://127.0.0.1:7070/mcp"
        ])
    );
    assert!(
        out["http_client_credentials"]["secret_rule"]
            .as_str()
            .expect("secret rule")
            .contains("never in profiles.toml")
    );
    assert!(
        out["custom_tool_toml"]
            .as_str()
            .expect("custom tool template")
            .contains("oraclemcp sign-tool")
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(serialized.contains("dbhost.example.com"));
    assert!(!serialized.contains("literal:"));
    // Explicit wrapper flow: the payload must say the wrapper has to exist first.
    assert_eq!(
        out["paths"]["wrapper"],
        serde_json::json!("/opt/oraclemcp-wrapper")
    );
    assert!(
        out["snippet_command"]["source"]
            .as_str()
            .expect("snippet command source")
            .contains("the wrapper must exist")
    );
    assert!(serialized.contains("create the wrapper first"));
}

/// Field-test bead `.3`: without `--wrapper-path` the snippets must point at
/// the real resolved binary — never the historical `~/.local/bin/oraclemcp-local`
/// wrapper that nothing ever creates.
#[test]
fn setup_payload_default_snippets_use_the_real_binary_not_a_wrapper() {
    let binary = setup_snippet_command();
    let out = setup_payload(
        "tenant_ro",
        "APP_PASSWORD",
        &binary,
        None,
        "/etc/oraclemcp/profiles.toml",
        "/etc/oraclemcp/tools.d",
    );
    assert_eq!(
        out["claude_mcp_json"]["mcpServers"]["oracle"]["command"],
        serde_json::json!(binary)
    );
    assert!(
        out["codex_config_toml"]
            .as_str()
            .expect("codex config")
            .contains(&format!("command = \"{binary}\"")),
        "Codex TOML must use the same command as the Claude JSON snippet"
    );
    assert_eq!(out["paths"]["wrapper"], serde_json::Value::Null);
    assert_eq!(
        out["snippet_command"]["source"],
        serde_json::json!("resolved oraclemcp binary")
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(
        !serialized.contains("oraclemcp-local"),
        "default setup output must never advertise the uncreated wrapper path"
    );
    // Install hints must match the supported channels (field-test bead `.4`).
    assert!(
        out["install"]["one_line"]
            .as_str()
            .expect("one-line install")
            .contains("install.sh")
    );
    assert_eq!(
        out["install"]["self_update"],
        serde_json::json!("oraclemcp self-update")
    );
    assert_eq!(
        out["install"]["cargo_binstall"],
        serde_json::json!("cargo binstall oraclemcp")
    );
    assert!(
        out["install"]["source_build"]
            .as_str()
            .expect("source build hint")
            .starts_with("cargo +nightly-2026-05-11 install oraclemcp"),
        "source build must carry the nightly pin; plain cargo install fails on stable"
    );
    assert!(
        !serialized.contains("\"cargo install oraclemcp\""),
        "bare cargo install (stable) must not be advertised"
    );
}

#[test]
fn json_alias_is_accepted_before_and_after_subcommand() {
    let before = Cli::try_parse_from(["oraclemcp", "--json", "profiles"]).expect("parse");
    assert!(before.robot_json);
    assert!(matches!(before.command, Some(Command::Profiles)));

    let after = Cli::try_parse_from(["oraclemcp", "profiles", "--json"]).expect("parse");
    assert!(after.robot_json);
    assert!(matches!(after.command, Some(Command::Profiles)));
}

#[test]
fn setup_and_sign_tool_commands_parse() {
    let setup = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "setup",
        "--write",
        "--profile",
        "tenant_ro",
        "--credential-env",
        "APP_PASSWORD",
    ])
    .expect("parse setup");
    assert!(setup.robot_json);
    assert!(matches!(
        setup.command,
        Some(Command::Setup {
            write: true,
            ref profile,
            ref credential_env,
            ..
        }) if profile == "tenant_ro" && credential_env == "APP_PASSWORD"
    ));

    let self_update = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "self-update",
        "--dry-run",
        "--version",
        "0.6.6",
        "--verify",
        "require",
        "--no-service",
    ])
    .expect("parse self-update");
    assert!(self_update.robot_json);
    assert!(matches!(
        self_update.command,
        Some(Command::SelfUpdate(SelfUpdateCliArgs {
            ref version,
            ref verify,
            dry_run: true,
            no_service: true,
            ..
        })) if version == "0.6.6" && verify.as_deref() == Some("require")
    ));

    let sign = Cli::try_parse_from([
        "oraclemcp",
        "sign-tool",
        "tools.toml",
        "--tool",
        "app_lookup",
    ])
    .expect("parse sign-tool");
    assert!(matches!(
        sign.command,
        Some(Command::SignTool {
            ref path,
            ref tool,
        }) if path == Path::new("tools.toml") && tool.as_deref() == Some("app_lookup")
    ));
}

#[test]
fn audit_verify_with_db_evidence_command_parses() {
    let audit = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "audit",
        "verify",
        "audit.jsonl",
        "--with-db-evidence",
    ])
    .expect("parse audit verify");
    assert!(audit.robot_json);
    assert!(matches!(
        audit.command,
        Some(Command::Audit {
            command: AuditCommand::Verify {
                ref file,
                key_id: None,
                with_db_evidence: true,
            }
        }) if file == Path::new("audit.jsonl")
    ));
}

#[test]
fn dashboard_command_parses() {
    let dashboard = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "dashboard",
        "--url",
        "http://127.0.0.1:7777",
        "--no-open",
    ])
    .expect("parse dashboard");
    assert!(dashboard.robot_json);
    assert!(matches!(
        dashboard.command,
        Some(Command::Dashboard {
            ref url,
            no_open: true,
        }) if url == "http://127.0.0.1:7777"
    ));
}

#[test]
fn om_alias_argv0_aware_parses_dashboard_help() {
    assert_eq!(
        display_binary_name_from_argv0(Some(std::ffi::OsStr::new("/usr/local/bin/om"))),
        "om"
    );
    assert_eq!(
        display_binary_name_from_argv0(Some(std::ffi::OsStr::new("OM.exe"))),
        "om"
    );
    assert_eq!(
        display_binary_name_from_argv0(Some(std::ffi::OsStr::new("/usr/local/bin/oraclemcp",))),
        "oraclemcp"
    );
    assert_eq!(display_binary_name_from_argv0(None), "oraclemcp");

    let matches = cli_command("om")
        .try_get_matches_from([
            "om",
            "--json",
            "dashboard",
            "--url",
            "http://127.0.0.1:7777",
            "--no-open",
        ])
        .expect("parse om dashboard");
    let dashboard = Cli::from_arg_matches(&matches).expect("build cli from alias matches");
    assert!(dashboard.robot_json);
    assert!(matches!(
        dashboard.command,
        Some(Command::Dashboard {
            ref url,
            no_open: true,
        }) if url == "http://127.0.0.1:7777"
    ));

    let mut help = Vec::new();
    cli_command("om")
        .write_long_help(&mut help)
        .expect("render om help");
    let help = String::from_utf8(help).expect("help is utf8");
    assert!(help.contains("Usage: om "));
    assert!(!help.contains("Usage: oraclemcp"));
    assert!(bare_invocation_hint("om").contains("`om serve`"));
    assert!(bare_invocation_hint("om").contains("`om doctor`"));
    assert!(bare_invocation_hint("om").contains("`om capabilities`"));
}

#[test]
fn service_commands_parse() {
    let install = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "service",
        "install",
        "--dry-run",
        "--listen",
        "127.0.0.1:7070",
        "--profile",
        "dev_ro",
        "--allow-no-auth",
        "--client-credentials",
        "--skip-linger",
    ])
    .expect("parse service install");
    assert!(install.robot_json);
    assert!(matches!(
        install.command,
        Some(Command::Service {
            command: ServiceCliCommand::Install(ServiceInstallCliArgs {
                ref listen,
                ref profile,
                allow_no_auth: true,
                client_credentials: true,
                skip_linger: true,
                dry_run: true,
                ..
            })
        }) if listen == "127.0.0.1:7070" && profile.as_deref() == Some("dev_ro")
    ));

    let uninstall = Cli::try_parse_from(["oraclemcp", "service", "uninstall", "--yes"])
        .expect("parse service uninstall");
    assert!(matches!(
        uninstall.command,
        Some(Command::Service {
            command: ServiceCliCommand::Uninstall(ServiceMutationCliArgs { yes: true, .. })
        })
    ));

    let status =
        Cli::try_parse_from(["oraclemcp", "service", "status"]).expect("parse service status");
    assert!(matches!(
        status.command,
        Some(Command::Service {
            command: ServiceCliCommand::Status(ServiceReadCliArgs { .. })
        })
    ));

    let logs = Cli::try_parse_from(["oraclemcp", "service", "logs", "--lines", "25"])
        .expect("parse service logs");
    assert!(matches!(
        logs.command,
        Some(Command::Service {
            command: ServiceCliCommand::Logs(ServiceLogsCliArgs { lines: 25, .. })
        })
    ));

    let restart = Cli::try_parse_from(["oraclemcp", "service", "restart", "--dry-run"])
        .expect("parse service restart");
    assert!(matches!(
        restart.command,
        Some(Command::Service {
            command: ServiceCliCommand::Restart(ServiceMutationCliArgs { dry_run: true, .. })
        })
    ));

    let backup = Cli::try_parse_from([
        "oraclemcp",
        "service",
        "backup",
        "--output",
        "/tmp/oraclemcp-backup",
        "--dry-run",
    ])
    .expect("parse service backup");
    assert!(matches!(
        backup.command,
        Some(Command::Service {
            command: ServiceCliCommand::Backup(ServiceBackupCliArgs {
                ref output,
                dry_run: true,
                ..
            })
        }) if output.as_deref() == Some(Path::new("/tmp/oraclemcp-backup"))
    ));

    let restore = Cli::try_parse_from([
        "oraclemcp",
        "service",
        "restore",
        "/tmp/oraclemcp-backup",
        "--key_id",
        "2026-q2",
        "--dry-run",
    ])
    .expect("parse service restore");
    assert!(matches!(
        restore.command,
        Some(Command::Service {
            command: ServiceCliCommand::Restore(ServiceRestoreCliArgs {
                ref backup,
                ref key_id,
                dry_run: true,
                ..
            })
        }) if backup == Path::new("/tmp/oraclemcp-backup")
            && key_id.as_deref() == Some("2026-q2")
    ));
}

#[test]
fn client_credential_commands_parse() {
    let issue = Cli::try_parse_from([
        "oraclemcp",
        "--json",
        "clients",
        "issue",
        "--label",
        "Claude Desktop",
        "--scope",
        "oracle:read",
        "--scope",
        "oracle:execute",
    ])
    .expect("parse client issue");
    assert!(issue.robot_json);
    assert!(matches!(
        issue.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Issue(ClientCredentialIssueCliArgs {
                ref label,
                ref scopes,
            })
        }) if label == "Claude Desktop"
            && scopes == &vec!["oracle:read".to_owned(), "oracle:execute".to_owned()]
    ));

    let issue_default_scope =
        Cli::try_parse_from(["oraclemcp", "clients", "issue", "--label", "Claude Desktop"])
            .expect("parse client issue with default scope");
    assert!(matches!(
        issue_default_scope.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Issue(ClientCredentialIssueCliArgs {
                ref scopes,
                ..
            })
        }) if scopes == &vec!["oracle:read".to_owned()]
    ));

    let rotate = Cli::try_parse_from([
        "oraclemcp",
        "client-credentials",
        "rotate",
        "client-0123456789abcdef0123456789abcdef",
    ])
    .expect("parse client rotate");
    assert!(matches!(
        rotate.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Rotate(ClientCredentialIdCliArgs {
                ref client_id,
            })
        }) if client_id == "client-0123456789abcdef0123456789abcdef"
    ));

    let revoke = Cli::try_parse_from([
        "oraclemcp",
        "clients",
        "revoke",
        "client-0123456789abcdef0123456789abcdef",
    ])
    .expect("parse client revoke");
    assert!(matches!(
        revoke.command,
        Some(Command::Clients {
            command: ClientCredentialCliCommand::Revoke(ClientCredentialIdCliArgs {
                ref client_id,
            })
        }) if client_id == "client-0123456789abcdef0123456789abcdef"
    ));
}

#[test]
fn robot_docs_guide_is_available_with_or_without_guide_subcommand() {
    let bare = Cli::try_parse_from(["oraclemcp", "robot-docs"]).expect("parse");
    assert!(matches!(
        bare.command,
        Some(Command::RobotDocs { command: None })
    ));

    let explicit = Cli::try_parse_from(["oraclemcp", "robot-docs", "guide"]).expect("parse");
    assert!(matches!(
        explicit.command,
        Some(Command::RobotDocs {
            command: Some(RobotDocsCommand::Guide)
        })
    ));
}

#[test]
fn agent_ergonomics_drift_guard_pins_capabilities_schema() {
    let out = capabilities_payload();
    for key in [
        "server_name",
        "server_version",
        "protocol_version",
        "tools",
        "operating_level",
        "transports",
        "connection",
        "features",
        "cli_contract",
        "mcp_cli_dashboard_parity",
    ] {
        assert!(out.get(key).is_some(), "missing capabilities key {key}");
    }
    assert_eq!(
        out["cli_contract"]["contract_version"],
        serde_json::json!(1)
    );
    assert_eq!(
        out["cli_contract"]["structured_output"]["alias"],
        serde_json::json!("--json")
    );
    assert_eq!(
        out["cli_contract"]["binary_names"],
        serde_json::json!(["oraclemcp", "om"])
    );

    let exit_codes = out["cli_contract"]["exit_codes"]
        .as_array()
        .expect("exit code dictionary");
    for code in [0, 1, 2, 3, 4] {
        assert!(
            exit_codes
                .iter()
                .any(|entry| entry["code"] == serde_json::json!(code)),
            "missing exit code {code}: {exit_codes:?}"
        );
    }
    assert!(
        serde_json::to_string(&out["cli_contract"])
            .expect("json")
            .contains("--dry-run")
    );

    let parity = out["mcp_cli_dashboard_parity"]["matrix"]
        .as_array()
        .expect("parity matrix");
    assert_eq!(parity.len(), 7);
    for id in [
        "discovery",
        "profile_inventory",
        "diagnostics",
        "guarded_sql",
        "schema_explorer",
        "service_and_auth",
        "audit",
    ] {
        let row = parity
            .iter()
            .find(|row| row["id"] == serde_json::json!(id))
            .unwrap_or_else(|| panic!("missing parity row {id}: {parity:?}"));
        assert_eq!(row["status"], serde_json::json!("aligned"));
        for face in ["cli", "mcp", "dashboard"] {
            assert!(
                row[face]
                    .as_array()
                    .is_some_and(|values| !values.is_empty()),
                "{id} has no {face} surface"
            );
        }
    }
}

#[test]
fn agent_ergonomics_drift_guard_pins_help_footer() {
    for binary_name in ["oraclemcp", "om"] {
        let mut help = Vec::new();
        cli_command(binary_name)
            .write_long_help(&mut help)
            .expect("render help");
        let help = String::from_utf8(help).expect("help utf8");
        assert!(help.contains(&format!("Usage: {binary_name} ")));
        assert!(help.contains("Agent surfaces:"));
        assert!(help.contains("--json"));
        assert!(help.contains("oraclemcp --json capabilities"));
        assert!(help.contains("oraclemcp robot-docs guide"));
        assert!(help.contains("oraclemcp --json service install --dry-run"));
        assert!(help.contains("service mutations require --yes"));
    }
}

#[test]
fn robot_docs_guide_outputs_agent_workflows() {
    let text = robot_docs::robot_docs_guide_text();
    assert!(text.contains("oraclemcp robot-docs guide"));
    assert!(text.contains("oracle_preview_sql"));
    assert!(text.contains("oracle_execute"));
    assert!(text.contains("READ_ONLY < READ_WRITE < DDL < ADMIN"));

    let out = robot_docs::robot_docs_guide_json();
    assert_eq!(out["ok"], serde_json::json!(true));
    assert_eq!(
        out["structured_output"]["alias"],
        serde_json::json!("--json")
    );
    assert_eq!(
        out["cli_contract"]["exit_codes"][4]["code"],
        serde_json::json!(4)
    );
    assert_eq!(
        out["mcp_cli_dashboard_parity"]["status"],
        serde_json::json!("aligned")
    );
    assert!(text.contains("MCP / CLI / dashboard parity"));
    assert!(text.contains("Exit codes: 0 success"));
    assert!(text.contains("Client smoke tests"));
    assert!(text.contains("oraclemcp --json setup --profile <profile>"));
    assert!(text.contains("Always-on service"));
    assert!(text.contains("oraclemcp --json service install --dry-run --profile <profile>"));
    assert!(
        text.contains("oraclemcp service install --yes --client-credentials --profile <profile>")
    );
    assert!(text.contains("Thin diagnostics"));
    assert!(text.contains("does not need Oracle Instant Client"));
    assert!(text.contains("Result materialization"));
    assert!(
        serde_json::to_string(&out)
            .expect("json")
            .contains("custom_tool_signing")
    );
    assert!(text.contains("MCP tools/list"));
    assert_eq!(
        out["tool_schema_contract"]["strict_client_safe"],
        serde_json::json!(
            "tool parameter schemas avoid top-level oneOf, anyOf, allOf, enum, and not"
        )
    );
    assert_eq!(
        out["client_setup"]["stdio"]["argv"],
        serde_json::json!([
            "oraclemcp",
            "serve",
            "--profile",
            "<profile>",
            "--allow-no-auth"
        ])
    );
    assert_eq!(
        out["client_setup"]["smoke_tests"][1]["mcp_method"],
        serde_json::Value::Null
    );
    assert_eq!(
        out["client_setup"]["smoke_tests"][2]["mcp_method"],
        serde_json::json!("tools/list")
    );
    assert_eq!(
        out["diagnostic_flow"][5]["argv"],
        serde_json::json!(["oraclemcp", "--json", "capabilities"])
    );
    assert_eq!(
        out["diagnostic_flow"][6]["argv"],
        serde_json::json!(["oraclemcp", "--json", "service", "status"])
    );
    assert_eq!(
        out["first_commands"][0]["argv"],
        serde_json::json!(["oraclemcp", "--json", "setup", "--profile", "<profile>"])
    );
    assert_eq!(
        out["first_commands"][1]["argv"],
        serde_json::json!(["oraclemcp", "--json", "profiles"])
    );
    assert_eq!(
        out["first_commands"][3]["argv"],
        serde_json::json!([
            "oraclemcp",
            "--json",
            "doctor",
            "--online",
            "--profile",
            "<profile>"
        ])
    );
    assert_eq!(
        out["first_commands"][5]["argv"],
        serde_json::json!([
            "oraclemcp",
            "--json",
            "service",
            "install",
            "--dry-run",
            "--profile",
            "<profile>"
        ])
    );
    assert_eq!(
        out["client_setup"]["service"]["status"]["argv"],
        serde_json::json!(["oraclemcp", "--json", "service", "status"])
    );
    assert_eq!(
        out["safety_model"]["levels"],
        serde_json::json!(["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"])
    );
    assert_eq!(
        out["thin_diagnostics"]["driver"],
        serde_json::json!(
            "pure-Rust oracledb thin driver; no Oracle Instant Client, ODPI-C, libclntsh, or C toolchain required"
        )
    );
    assert!(
        out["thin_diagnostics"]["secret_handling"]
            .as_str()
            .expect("secret handling text")
            .contains("wallet paths")
    );
    assert!(
        out["result_materialization"]["ref_cursors"]
            .as_str()
            .expect("ref cursor text")
            .contains("nested result objects")
    );
    assert!(
        serde_json::to_string(&out)
            .expect("json")
            .contains("oracle_preview_sql")
    );
}

fn custom_def(name: &str) -> CustomToolDef {
    CustomToolDef {
        name: name.to_owned(),
        description: "Test custom tool".to_owned(),
        sql: Some("SELECT 1 FROM dual".to_owned()),
        call: None,
        params: Vec::new(),
        output_mode: oraclemcp_core::OutputMode::Rows,
        declared_level: None,
        signature: None,
    }
}

#[test]
fn custom_tool_names_cannot_duplicate_or_shadow_advertised_tools() {
    let err = validate_custom_tool_names(&[custom_def("app_lookup"), custom_def("app_lookup")])
        .expect_err("duplicate custom names rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("duplicate custom tool name"));

    let err = validate_custom_tool_names(&[custom_def("query")])
        .expect_err("compatibility alias collision rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("collides"));
}

#[test]
fn build_server_advertises_the_registered_tools_plus_capabilities() {
    let conn = open_connection(OracleConnectOptions::default());
    let server = build_server(
        conn,
        None,
        None,
        default_read_only_level(),
        ServerBuildOptions {
            transport: ServerTransportMode::Stdio,
            custom_catalog: CustomToolCatalog::default(),
            auditor: None,
            write_intents: None,
            secret_resolver: Arc::new(SystemSecretResolver),
            request_timeout: OracleConnectOptions::default().call_timeout,
            metrics: None,
            profile_drain: ProfileDrainState::default(),
        },
    );
    // The capabilities report carries the registry's tools.
    let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, false);
    assert_eq!(caps.tools.len(), registry::tool_names().len());
    // Smoke: the server clones (it is Clone) — proves it is fully built.
    let _ = server.clone();
}
