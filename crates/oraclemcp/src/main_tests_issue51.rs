//! #51 (handshake before the audit/service locks) unit tests, split out of
//! `main_tests.rs` to keep that file within its size ratchet
//! (`scripts/oraclemcp_arch_fitness_lint.sh`).

use super::*;

/// #51: a profile that can reach a write level never executes a tool without
/// the audit sink it requires. Neither a missing key (fatal, before the
/// transport) nor another instance's writer lock (typed, per call) lets the
/// stdio opener connect or build a dispatcher.
#[test]
fn writable_profile_never_runs_without_audit_sink() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = tempfile::tempdir().expect("audit tempdir");
    let audit_path = root.path().join("audit/audit.jsonl");
    let config_with = |audit: &str| {
        OracleMcpConfig::from_toml_str(&format!(
            r#"
                {audit}

                [[profiles]]
                name = "writable"
                connect_string = "localhost:1521/FREEPDB1"
                max_level = "READ_WRITE"
                mcp_exposed = true
            "#
        ))
        .expect("config parses")
    };
    let resolver: Arc<dyn SecretResolver> = Arc::new(oraclemcp_auth::EnvLookupSecretResolver::new(
        |name: &str| (name == "T77_AUDIT_KEY").then(|| "K".repeat(32)),
    ));
    let level = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    let connects = Arc::new(AtomicUsize::new(0));
    let opener_for = |config: OracleMcpConfig| {
        let reachable_ceiling = max_reachable_write_ceiling(&config, &level);
        assert_eq!(reachable_ceiling, OperatingLevel::ReadWrite);
        let counted = Arc::clone(&connects);
        stdio_opener(
            StdioOpenerInputs {
                config,
                secret_resolver: Arc::clone(&resolver),
                level: level.clone(),
                reachable_ceiling,
                query_cost_budget_enabled: false,
                connection_plan: RuntimeConnectionPlan::Profile("writable".to_owned()),
                custom_catalog: CustomToolCatalog::default(),
                active_profile: Some("writable".to_owned()),
                strict_custom_tools: false,
                request_timeout: None,
                max_query_cost: None,
                cumulative_query_cost_budget: None,
                result_masking: None,
                sql_policy: None,
                exports: Arc::new(ExportRegistry::new()),
            },
            Box::new(move |_plan, _config, _resolver| {
                counted.fetch_add(1, Ordering::SeqCst);
                stub_runtime_connections(DbError::Connect("test never connects".to_owned()))
            }),
        )
    };

    // No signing key: a fatal refusal before the transport, nothing connected.
    let error = DeferredDispatch::start(opener_for(config_with(&format!(
        "[audit]\npath = {:?}",
        audit_path.display().to_string()
    ))))
    .map(|_| ())
    .expect_err("a write-reachable profile without an audit key must not start");
    assert!(
        error.message.starts_with("ORACLEMCP_AUDIT_KEY_REQUIRED: "),
        "{}",
        error.message
    );
    assert_eq!(connects.load(Ordering::SeqCst), 0);

    // Keyed, but another writer holds the sink: every tools/call is refused
    // typed with the holder's pid, and nothing connects.
    create_private_audit_dir(audit_path.parent().expect("parent")).expect("private audit dir");
    let _holder = oraclemcp_audit::FileAuditSink::open(&audit_path).expect("holder takes lock");
    let keyed = config_with(&format!(
        "[audit]\npath = {:?}\nkey_ref = \"env:T77_AUDIT_KEY\"",
        audit_path.display().to_string()
    ));
    let (dispatch, lock) = DeferredDispatch::start(opener_for(keyed)).expect("not fatal");
    let lock = lock.expect("the held audit lock defers the open");
    assert_eq!(lock.code(), "ORACLEMCP_AUDIT_LOG_LOCKED");
    let server = server_shell(
        OperatingLevel::ReadWrite,
        ServerTransportMode::Stdio,
        Vec::new(),
        Arc::new(dispatch),
        Arc::new(ExportRegistry::new()),
    );
    let listed = server
        .handle_jsonrpc_request(
            serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}),
            None,
        )
        .expect("tools/list response");
    assert!(
        listed["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "discovery answers from the static registry while locked: {listed}"
    );
    for id in 2..4 {
        let called = server
            .handle_jsonrpc_request(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {
                        "name": "oracle_execute",
                        "arguments": {"sql": "delete from t77 where id = 1"}
                    }
                }),
                None,
            )
            .expect("tools/call response");
        let text = called.to_string();
        assert!(text.contains("ORACLEMCP_AUDIT_LOG_LOCKED"), "{text}");
        // The pid hint is Unix-only: Windows' mandatory LockFileEx lock blocks
        // the contender's read of the holder's lock file (see sink.rs
        // read_holder_pid); the typed refusal itself holds everywhere.
        #[cfg(unix)]
        assert!(
            text.contains(&format!("(pid {})", std::process::id())),
            "names the holder pid: {text}"
        );
    }
    assert_eq!(
        connects.load(Ordering::SeqCst),
        0,
        "no connection while the audit sink is unavailable"
    );
}

/// Release manifest case `rel012_i51_second_instance` (#51): a second serve
/// sharing a held audit log completes the handshake, answers every tool call
/// with the typed lock refusal naming the holder, and leaves the holder's log
/// untouched (no fork). Once the holder releases, the next call opens the
/// sink and connects. The process-level proof with two real executables is
/// `tests/w4_runtime_issue51.rs`. Run by the manifest-bound wrapper
/// `tests::second_serve_instance_reports_audit_lock_issue_51`.
pub(super) fn second_serve_instance_reports_audit_lock() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = tempfile::tempdir().expect("audit tempdir");
    let audit_path = root.path().join("audit/audit.jsonl");
    create_private_audit_dir(audit_path.parent().expect("parent")).expect("private audit dir");
    let holder = oraclemcp_audit::FileAuditSink::open(&audit_path).expect("instance 1 holds");
    let held_log = std::fs::read(&audit_path).expect("holder's log");

    let config = OracleMcpConfig::from_toml_str(&format!(
        "[audit]\npath = {:?}\nkey_ref = \"env:I51_AUDIT_KEY\"",
        audit_path.display().to_string()
    ))
    .expect("config parses");
    let resolver: Arc<dyn SecretResolver> = Arc::new(oraclemcp_auth::EnvLookupSecretResolver::new(
        |name: &str| (name == "I51_AUDIT_KEY").then(|| "I".repeat(32)),
    ));
    let level = default_read_only_level();
    let connects = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connects);
    let exports = Arc::new(ExportRegistry::new());
    let opener = stdio_opener(
        StdioOpenerInputs {
            reachable_ceiling: max_reachable_write_ceiling(&config, &level),
            config,
            secret_resolver: resolver,
            level,
            query_cost_budget_enabled: false,
            connection_plan: RuntimeConnectionPlan::Stub(DbError::Connect(
                "offline unit test".to_owned(),
            )),
            custom_catalog: CustomToolCatalog::default(),
            active_profile: None,
            strict_custom_tools: false,
            request_timeout: None,
            max_query_cost: None,
            cumulative_query_cost_budget: None,
            result_masking: None,
            sql_policy: None,
            exports: Arc::clone(&exports),
        },
        Box::new(move |plan, config, resolver| {
            counted.fetch_add(1, Ordering::SeqCst);
            open_runtime_connection_plan(plan, config, true, resolver)
        }),
    );
    let (dispatch, lock) = DeferredDispatch::start(opener).expect("a held lock is not fatal");
    assert_eq!(
        lock.as_ref().map(StartupLock::code),
        Some("ORACLEMCP_AUDIT_LOG_LOCKED")
    );
    let server = server_shell(
        OperatingLevel::ReadOnly,
        ServerTransportMode::Stdio,
        Vec::new(),
        Arc::new(dispatch),
        exports,
    );
    let rpc = |request: serde_json::Value| {
        server
            .handle_jsonrpc_request(request, None)
            .expect("a response")
    };
    let initialize = rpc(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "i51", "version": "0"}}
    }));
    assert_eq!(
        initialize["result"]["serverInfo"]["name"], "oraclemcp",
        "{initialize}"
    );
    let tools = rpc(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "oracle_query")),
        "{tools}"
    );
    let query = |id: u64| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "oracle_query", "arguments": {"sql": "SELECT 1 FROM dual"}}
        })
    };
    let locked = rpc(query(3)).to_string();
    assert!(locked.contains("ORACLEMCP_AUDIT_LOG_LOCKED"), "{locked}");
    // Unix-only pid hint: Windows' mandatory LockFileEx lock blocks reading
    // the holder's lock file (sink.rs read_holder_pid).
    #[cfg(unix)]
    assert!(
        locked.contains(&format!("(pid {})", std::process::id())),
        "the refusal names the holder: {locked}"
    );
    assert_eq!(connects.load(Ordering::SeqCst), 0, "nothing connected");
    assert_eq!(
        std::fs::read(&audit_path).expect("holder's log"),
        held_log,
        "the second instance never wrote the held log (no fork)"
    );

    drop(holder);
    let recovered = rpc(query(4)).to_string();
    assert!(
        !recovered.contains("ORACLEMCP_AUDIT_LOG_LOCKED"),
        "the next call opens the released sink: {recovered}"
    );
    assert_eq!(
        connects.load(Ordering::SeqCst),
        1,
        "connected once, after the lock"
    );
}
