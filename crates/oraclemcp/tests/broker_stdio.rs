//! Process-level local broker tests. The live case requires actual lab credentials.
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

struct Client {
    process: Child,
    input: ChildStdin,
    responses: Receiver<Value>,
}
impl Client {
    fn spawn(root: &Path, config: &Path, index: usize) -> Self {
        let password =
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "offline".into());
        Self::spawn_with_password(root, config, index, Some(&password))
    }
    fn spawn_with_password(
        root: &Path,
        config: &Path,
        index: usize,
        password: Option<&str>,
    ) -> Self {
        Self::spawn_with_auth(root, config, index, password, None, None)
    }
    fn spawn_with_auth(
        root: &Path,
        config: &Path,
        index: usize,
        password: Option<&str>,
        expected_token: Option<&str>,
        presented_token: Option<&str>,
    ) -> Self {
        Self::spawn_with_settings(
            root,
            config,
            index,
            password,
            expected_token,
            presented_token,
            |_| {},
        )
    }
    fn spawn_with_settings(
        root: &Path,
        config: &Path,
        index: usize,
        password: Option<&str>,
        expected_token: Option<&str>,
        presented_token: Option<&str>,
        configure: impl FnOnce(&mut Command),
    ) -> Self {
        let mut command = Command::new(test_binary());
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
            command.env_remove(key);
        }
        command
            .args(["serve", "--allow-no-auth", "--profile", "shared"])
            .env("ORACLEMCP_CONFIG", config)
            .env("XDG_STATE_HOME", root.join("state"))
            .env("BROKER_TEST_KEY", "synthetic-test-key-32-bytes-minimum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(password) = password {
            command.env("BROKER_TEST_PASSWORD", password);
        } else {
            command.env_remove("BROKER_TEST_PASSWORD");
        }
        if let Some(token) = expected_token {
            command.env("ORACLEMCP_STDIO_TOKEN", token);
        }
        configure(&mut command);
        let mut process = command.spawn().unwrap();
        let input = process.stdin.take().unwrap();
        let output = process.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let line = line.expect("MCP stdout read");
                let response: Value = serde_json::from_str(&line).expect("only MCP JSON on stdout");
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            process,
            input,
            responses,
        };
        let mut initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":format!("broker-test-{index}"),"version":"1"}}});
        if let Some(token) = presented_token {
            initialize["params"]["_meta"] = json!({"oraclemcp/initToken":token});
        }
        client.send(initialize);
        client
    }
    fn send(&mut self, frame: Value) {
        serde_json::to_writer(&mut self.input, &frame).unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
    }
    fn response(&self, id: i64) -> Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let response = self
                .responses
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("bounded MCP response");
            if response["id"] == id {
                return response;
            }
        }
    }
}
fn test_binary() -> std::ffi::OsString {
    std::env::var_os("ORACLEMCP_BROKER_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_oraclemcp").into())
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
fn config(root: &Path, live: bool) -> std::path::PathBuf {
    config_with_ceiling(root, live, "READ_WRITE")
}
fn config_with_ceiling(root: &Path, live: bool, ceiling: &str) -> std::path::PathBuf {
    let path = root.join("profiles.toml");
    let dsn = if live {
        std::env::var("ORACLEMCP_TEST_DSN").expect("live test requires ORACLEMCP_TEST_DSN")
    } else {
        "localhost:1/unavailable".into()
    };
    let user = if live {
        std::env::var("ORACLEMCP_TEST_USER").expect("live test requires ORACLEMCP_TEST_USER")
    } else {
        "synthetic".into()
    };
    let source = format!(
        r#"schema_version = 2
 default_profile = "shared"
 [audit]
 path = {}
 key_ref = "env:BROKER_TEST_KEY"
 [[profiles]]
 name = "shared"
 connect_string = {}
 username = {}
 credential_ref = "env:BROKER_TEST_PASSWORD"
 max_level = {}
 default_level = "READ_ONLY"
 call_timeout_seconds = 10
 "#,
        json!(root.join("audit.jsonl").to_str().unwrap()),
        json!(dsn),
        json!(user),
        json!(ceiling)
    );
    std::fs::write(&path, source).unwrap();
    path
}
fn five_clients(live: bool) {
    let root = tempfile::tempdir().unwrap();
    let path = config(root.path(), live);
    let mut clients: Vec<_> = (0..5)
        .map(|index| Client::spawn(root.path(), &path, index))
        .collect();
    for client in &mut clients {
        let initialized = client.response(1);
        assert!(initialized.get("result").is_some(), "{initialized}");
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":if live {"oracle_query"} else {"oracle_capabilities"},"arguments":if live {json!({"sql":"SELECT 73 AS BROKER_VALUE FROM dual"})} else {json!({})}}}));
    }
    for client in &clients {
        let response = client.response(2);
        let text = response.to_string();
        assert!(!text.contains("LOCKED"), "{response}");
        if live {
            assert_eq!(response["result"]["isError"], false, "{response}");
            assert!(text.contains("73"), "{response}");
        } else {
            assert_eq!(response["result"]["isError"], true, "{response}");
            assert_eq!(
                response["result"]["structuredContent"]["error_class"], "CONNECTION_FAILED",
                "{response}"
            );
        }
    }
    if live {
        clients[0].send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oracle_set_session_level","arguments":{"level":"READ_WRITE","ttl_seconds":60}}}));
        let preview = clients[0].response(3);
        let token = preview["result"]["structuredContent"]["confirmation"]["confirm"]
            .as_str()
            .expect("real elevation grant")
            .to_owned();
        clients[1].send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"oracle_set_session_level","arguments":{"level":"READ_WRITE","ttl_seconds":60,"execute":true,"confirm":token}}}));
        let stolen = clients[1].response(4);
        assert_eq!(
            stolen["result"]["isError"], true,
            "cross-session token accepted: {stolen}"
        );
        clients[0].send(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"oracle_set_session_level","arguments":{"level":"READ_WRITE","ttl_seconds":60,"execute":true,"confirm":token}}}));
        let applied = clients[0].response(5);
        assert_eq!(
            applied["result"]["structuredContent"]["changed"], true,
            "own grant must survive planted theft: {applied}"
        );
        clients[1].send(json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"oracle_set_session_level","arguments":{"level":"READ_WRITE","ttl_seconds":60}}}));
        let second = clients[1].response(6);
        assert_eq!(
            second["result"]["structuredContent"]["session"]["current_level"], "READ_ONLY",
            "elevation leaked: {second}"
        );
        for (index, client) in clients.iter_mut().enumerate().skip(1) {
            let preview_id = 10 + index as i64;
            client.send(json!({"jsonrpc":"2.0","id":preview_id,"method":"tools/call","params":{"name":"oracle_set_session_level","arguments":{"level":"READ_WRITE","ttl_seconds":60}}}));
            let preview = client.response(preview_id);
            let token = preview["result"]["structuredContent"]["confirmation"]["confirm"]
                .as_str()
                .expect("independent grant");
            client.send(json!({"jsonrpc":"2.0","id":20+index,"method":"tools/call","params":{"name":"oracle_set_session_level","arguments":{"level":"READ_WRITE","ttl_seconds":60,"execute":true,"confirm":token}}}));
            let applied = client.response(20 + index as i64);
            assert_eq!(
                applied["result"]["structuredContent"]["changed"], true,
                "{applied}"
            );
        }
    }
    let locator = root.path().join("state/oraclemcp/broker.json");
    let locator: Value = serde_json::from_slice(&std::fs::read(locator).unwrap()).unwrap();
    let broker_pid = locator["pid"].as_u64().unwrap();
    #[cfg(target_os = "linux")]
    {
        // Keep proxies alive while checking their actual election children.
        // A success-before-child-exit race must not leave losing spawns as
        // zombies for the rest of the MCP session.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let zombies: Vec<_> = clients
                .iter()
                .flat_map(|client| {
                    let pid = client.process.id();
                    let children =
                        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
                            .unwrap();
                    children
                        .split_whitespace()
                        .filter_map(|child| {
                            let stat =
                                std::fs::read_to_string(format!("/proc/{child}/stat")).ok()?;
                            let (_, fields) = stat.rsplit_once(") ")?;
                            (fields.split_whitespace().next() == Some("Z"))
                                .then(|| child.to_owned())
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            if zombies.is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "unreaped broker children: {zombies:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(
        clients
            .iter()
            .all(|client| u64::from(client.process.id()) != broker_pid)
    );
    drop(clients);
    // Broker owns the configured audit file until its idle timeout, so keep
    // the directory valid while it performs transport cleanup.
    std::thread::sleep(Duration::from_secs(2));
    if live {
        let records: Vec<Value> = std::fs::read_to_string(root.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(
            !records.is_empty(),
            "interleaved clients must write audit records"
        );
        for record in &records {
            let subject = &record["subject"];
            let identity = subject["stable_id"]
                .as_str()
                .expect("every audit record has an identity");
            assert!(
                identity.contains(":session:"),
                "record lacks its broker session: {record}"
            );
            assert!(
                identity.starts_with(if cfg!(unix) { "uid:" } else { "pid:" }),
                "record lacks kernel peer identity: {record}"
            );
            assert!(
                subject["client_id"]
                    .as_str()
                    .is_some_and(|client| client.contains("broker-test-")),
                "record lacks MCP clientInfo: {record}"
            );
        }
        let elevated: Vec<_> = records
            .iter()
            .filter(|record| {
                record["tool"] == "oracle_set_session_level" && record["outcome"] == "SUCCEEDED"
            })
            .collect();
        assert_eq!(
            elevated.len(),
            5,
            "one successful elevation per distinct session: {records:?}"
        );
        let identities: std::collections::HashSet<_> = elevated
            .iter()
            .map(|record| {
                record["subject"]["stable_id"]
                    .as_str()
                    .expect("kernel peer and session identity")
            })
            .collect();
        assert_eq!(identities.len(), 5, "distinct audit subjects");
        for index in 0..5 {
            assert!(elevated.iter().any(|record| {
                record["subject"]["client_id"]
                    .as_str()
                    .is_some_and(|value| value.contains(&format!("broker-test-{index}")))
            }));
        }
        let mut verify = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
            verify.env_remove(key);
        }
        let verified = verify
            .args([
                "--json",
                "audit",
                "verify",
                root.path().join("audit.jsonl").to_str().unwrap(),
            ])
            .env("ORACLEMCP_CONFIG", &path)
            .env("BROKER_TEST_KEY", "synthetic-test-key-32-bytes-minimum")
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "audit verification failed: {} {}",
            String::from_utf8_lossy(&verified.stdout),
            String::from_utf8_lossy(&verified.stderr)
        );
    }
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &broker_pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &broker_pid.to_string(), "/F"])
            .status()
            .unwrap()
            .success()
    );
}
#[test]
fn five_stdio_processes_auto_attach_without_a_live_database() {
    five_clients(false);
}

#[test]
fn http_listener_does_not_inherit_stdio_remote_bind_authorization() {
    let root = tempfile::tempdir().unwrap();
    let path = config(root.path(), false);
    let mut client = Client::spawn_with_settings(
        root.path(),
        &path,
        0,
        Some("offline"),
        None,
        None,
        |command| {
            command.env("ORACLEMCP_HTTP_ALLOW_REMOTE", "1");
        },
    );
    assert!(client.response(1).get("result").is_some());
    client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    client.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT 1 FROM dual"}}}));
    let response = client.response(2);
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["error_class"], "CONNECTION_FAILED",
        "{response}"
    );
    let mut command = Command::new(test_binary());
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
        command.env_remove(key);
    }
    let mut http = command
        .args([
            "--json",
            "serve",
            "--listen",
            "0.0.0.0:0",
            "--allow-no-auth",
            "--profile",
            "shared",
        ])
        .env("ORACLEMCP_CONFIG", &path)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("BROKER_TEST_KEY", "synthetic-test-key-32-bytes-minimum")
        .env("BROKER_TEST_PASSWORD", "offline")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = http.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            http.kill().unwrap();
            http.wait().unwrap();
            panic!("HTTP launcher must not inherit a stdio client's remote-bind authorization");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(2));
    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let audit = std::fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
        if audit
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|record| record["tool"] == "lane_lifecycle")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "stdio close must finish auditing before fixture removal"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
#[cfg(feature = "live-xe")]
#[test]
fn five_stdio_processes_auto_attach_live_free23() {
    five_clients(true);
}

#[cfg(feature = "live-xe")]
#[test]
fn broker_death_returns_transient_then_respawns_without_replaying_call() {
    let root = tempfile::tempdir().unwrap();
    let path = config(root.path(), true);
    let mut client = Client::spawn(root.path(), &path, 0);
    assert!(client.response(1).get("result").is_some());
    client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    client.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT COUNT(*) FROM all_objects a CROSS JOIN all_objects b CROSS JOIN all_objects c"}}}));
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        client.responses.try_recv().is_err(),
        "long-running request must still be pending before broker termination"
    );
    let locator_path = root.path().join("state/oraclemcp/broker.json");
    let locator: Value = serde_json::from_slice(&std::fs::read(&locator_path).unwrap()).unwrap();
    let old_pid = locator["pid"].as_u64().unwrap();
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-KILL", &old_pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &old_pid.to_string(), "/F"])
            .status()
            .unwrap()
            .success()
    );
    let lost = client.response(2);
    assert_eq!(
        lost["result"]["structuredContent"]["error_class"], "TRANSIENT",
        "{lost}"
    );
    let recovery_started = std::time::Instant::now();
    client.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT 91 AS AFTER_BROKER_RESTART FROM dual"}}}));
    let recovered = client.response(3);
    assert_eq!(recovered["result"]["isError"], false, "{recovered}");
    assert!(recovered.to_string().contains("91"), "{recovered}");
    assert!(
        recovery_started.elapsed() < Duration::from_secs(8),
        "recovery must not queue behind a replay of the old 10-second-budget query"
    );
    let replacement: Value = serde_json::from_slice(&std::fs::read(locator_path).unwrap()).unwrap();
    let new_pid = replacement["pid"].as_u64().unwrap();
    assert_ne!(old_pid, new_pid);
    // A replay of the pending COUNT would serialize ahead of this SELECT
    // on the fresh lane and violate this stricter recovery latency assertion.
    drop(client);
    std::thread::sleep(Duration::from_secs(2));
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &new_pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &new_pid.to_string(), "/F"])
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(feature = "live-xe")]
fn call(client: &mut Client, id: i64, tool: &str, arguments: Value) -> Value {
    client.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}}));
    client.response(id)
}
#[cfg(feature = "live-xe")]
fn elevate(client: &mut Client, id: i64, level: &str) {
    let preview = call(
        client,
        id,
        "oracle_set_session_level",
        json!({"level":level,"ttl_seconds":120}),
    );
    let token = preview["result"]["structuredContent"]["confirmation"]["confirm"]
        .as_str()
        .expect("elevation preview grant");
    let applied = call(
        client,
        id + 1,
        "oracle_set_session_level",
        json!({"level":level,"ttl_seconds":120,"execute":true,"confirm":token}),
    );
    assert_eq!(
        applied["result"]["structuredContent"]["session"]["current_level"], level,
        "{applied}"
    );
}
#[cfg(feature = "live-xe")]
fn execute(
    client: &mut Client,
    id: i64,
    sql: &str,
    binds: Value,
    commit: bool,
    hold: bool,
) -> Value {
    let preview = call(
        client,
        id,
        "oracle_preview_sql",
        json!({"sql":sql,"binds":binds,"commit":commit,"hold":hold}),
    );
    let token = preview["result"]["structuredContent"]["execute_confirmation"]["confirm"]
        .as_str()
        .expect("statement preview grant");
    let applied = call(
        client,
        id + 1,
        "oracle_execute",
        json!({"sql":sql,"binds":binds,"commit":commit,"hold":hold,"confirm":token}),
    );
    assert_eq!(
        applied["result"]["structuredContent"]["executed"], true,
        "{applied}"
    );
    applied
}
#[cfg(feature = "live-xe")]
fn count(client: &mut Client, id: i64, sql: &str, binds: Value) -> u64 {
    let response = call(client, id, "oracle_query", json!({"sql":sql,"binds":binds}));
    assert_eq!(response["result"]["isError"], false, "{response}");
    response["result"]["structuredContent"]["rows"][0]["N"]
        .as_str()
        .expect("Oracle NUMBER text")
        .parse()
        .unwrap()
}

#[cfg(feature = "live-xe")]
#[test]
fn two_live_stdio_clients_isolate_cancellation_and_keep_sibling_available() {
    let root = tempfile::tempdir().unwrap();
    let path = config(root.path(), true);
    let mut a = Client::spawn(root.path(), &path, 0);
    let mut b = Client::spawn(root.path(), &path, 1);
    for client in [&mut a, &mut b] {
        assert!(client.response(1).get("result").is_some());
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }
    a.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT COUNT(*) FROM all_objects a CROSS JOIN all_objects b CROSS JOIN all_objects c"}}}));
    std::thread::sleep(Duration::from_millis(500));
    assert!(a.responses.try_recv().is_err(), "A must still be executing");
    // An identical JSON-RPC ID belongs to B's own session, never A's request.
    b.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"synthetic cross-session cancellation attempt"}}));
    assert_eq!(
        count(&mut b, 2, "SELECT 83 AS N FROM dual", json!([])),
        83,
        "a sibling must serve real Oracle work while A is busy"
    );
    assert!(
        a.responses.try_recv().is_err(),
        "B's cancellation must not terminate A's request"
    );
    a.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"cancel own synthetic long-running query"}}));
    let cancelled = a.response(2);
    assert_eq!(
        cancelled["result"]["structuredContent"]["error_class"], "REQUEST_CANCELLED",
        "{cancelled}"
    );
    assert_eq!(count(&mut b, 3, "SELECT 89 AS N FROM dual", json!([])), 89);
    let locator: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("state/oraclemcp/broker.json")).unwrap(),
    )
    .unwrap();
    let pid = locator["pid"].as_u64().unwrap().to_string();
    drop(a);
    drop(b);
    std::thread::sleep(Duration::from_secs(2));
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &pid, "/F"])
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(feature = "live-xe")]
#[test]
fn two_live_stdio_clients_commit_independent_write_intents() {
    let root = tempfile::tempdir().unwrap();
    let path = config_with_ceiling(root.path(), true, "DDL");
    let mut a = Client::spawn(root.path(), &path, 0);
    let mut b = Client::spawn(root.path(), &path, 1);
    for client in [&mut a, &mut b] {
        assert!(client.response(1).get("result").is_some());
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        elevate(client, 2, "DDL");
    }
    // Both stores have consumed exactly one level grant. Their next raw grant
    // IDs have the same broker PID/counter; the durable identities must differ.
    execute(
        &mut a,
        4,
        "CREATE OR REPLACE VIEW SG_BROKER_INTENT_A AS SELECT 31 AS V FROM dual",
        json!([]),
        true,
        false,
    );
    execute(
        &mut b,
        4,
        "CREATE OR REPLACE VIEW SG_BROKER_INTENT_B AS SELECT 37 AS V FROM dual",
        json!([]),
        true,
        false,
    );
    assert_eq!(
        count(
            &mut a,
            6,
            "SELECT COUNT(*) AS N FROM all_views v WHERE v.owner = USER AND v.view_name = 'SG_BROKER_INTENT_A' AND v.text_vc LIKE '%31%'",
            json!([])
        ),
        1
    );
    assert_eq!(
        count(
            &mut b,
            6,
            "SELECT COUNT(*) AS N FROM all_views v WHERE v.owner = USER AND v.view_name = 'SG_BROKER_INTENT_B' AND v.text_vc LIKE '%37%'",
            json!([])
        ),
        1
    );
    // Reusable, synthetic views avoid accumulating a new fixture per run.
    let locator: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("state/oraclemcp/broker.json")).unwrap(),
    )
    .unwrap();
    let pid = locator["pid"].as_u64().unwrap().to_string();
    drop(a);
    drop(b);
    std::thread::sleep(Duration::from_secs(2));
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &pid, "/F"])
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(feature = "live-xe")]
#[test]
fn held_dml_stays_in_its_own_stdio_session_and_rolls_back() {
    let root = tempfile::tempdir().unwrap();
    let path = config_with_ceiling(root.path(), true, "DDL");
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let table = format!("SG_BROKER_I_{:016X}", u64::from_le_bytes(nonce));
    // Always create a fresh fixture, so local reruns exercise the same DDL path
    // as a clean CI database instead of hiding it behind an existing table.
    let mut setup = Client::spawn(root.path(), &path, 2);
    assert!(setup.response(1).get("result").is_some());
    setup.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    elevate(&mut setup, 2, "DDL");
    execute(
        &mut setup,
        5,
        &format!("CREATE TABLE {table} (RUN_ID VARCHAR2(64) PRIMARY KEY)"),
        json!([]),
        true,
        false,
    );
    drop(setup);
    // Let the freshly committed table definition settle before either client
    // can pin its read-only snapshot. This is fixture setup, not a read retry.
    std::thread::sleep(Duration::from_secs(2));
    // Both isolation sessions must start after fixture DDL commits. Reusing
    // the setup session would retain a snapshot older than the new definition.
    let mut a = Client::spawn(root.path(), &path, 0);
    assert!(a.response(1).get("result").is_some());
    a.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    elevate(&mut a, 2, "DDL");
    let described = call(&mut a, 7, "oracle_describe", json!({"table":table}));
    assert_eq!(described["result"]["isError"], false, "{described}");
    assert!(described.to_string().contains("RUN_ID"));
    let mut b = Client::spawn(root.path(), &path, 1);
    assert!(b.response(1).get("result").is_some());
    b.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let lowered = call(
        &mut a,
        8,
        "oracle_set_session_level",
        json!({"level":"READ_WRITE","action":"apply"}),
    );
    assert_eq!(
        lowered["result"]["structuredContent"]["session"]["current_level"], "READ_WRITE",
        "{lowered}"
    );
    let checkpoint = call(
        &mut a,
        9,
        "oracle_checkpoint",
        json!({"name":"BROKER_ISOLATION"}),
    );
    assert_eq!(checkpoint["result"]["isError"], false, "{checkpoint}");
    let run_id = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let held = execute(
        &mut a,
        10,
        &format!("INSERT INTO {table} (RUN_ID) VALUES (:1)"),
        json!([run_id]),
        false,
        true,
    );
    assert_eq!(
        held["result"]["structuredContent"]["committed"], false,
        "{held}"
    );
    let select = format!("SELECT COUNT(*) AS N FROM {table} WHERE RUN_ID = :1");
    assert_eq!(
        count(&mut a, 12, &select, json!([run_id])),
        1,
        "own pending DML visible to A"
    );
    assert_eq!(
        count(&mut b, 12, &select, json!([run_id])),
        0,
        "pending DML must be invisible to B"
    );
    let status = call(
        &mut b,
        13,
        "oracle_set_session_level",
        json!({"action":"status"}),
    );
    assert_eq!(
        status["result"]["structuredContent"]["session"]["current_level"], "READ_ONLY",
        "{status}"
    );
    let sibling_undo = call(
        &mut b,
        14,
        "oracle_undo_to",
        json!({"name":"BROKER_ISOLATION"}),
    );
    assert_eq!(
        sibling_undo["result"]["isError"], true,
        "B must not undo A's checkpoint: {sibling_undo}"
    );
    let undo = call(&mut a, 15, "oracle_undo_to", json!({}));
    assert_eq!(undo["result"]["isError"], false, "{undo}");
    assert_eq!(count(&mut a, 16, &select, json!([run_id])), 0);
    assert_eq!(count(&mut b, 16, &select, json!([run_id])), 0);
    elevate(&mut a, 18, "DDL");
    execute(
        &mut a,
        20,
        &format!("DROP TABLE {table} PURGE"),
        json!([]),
        true,
        false,
    );
    let locator: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("state/oraclemcp/broker.json")).unwrap(),
    )
    .unwrap();
    let pid = locator["pid"].as_u64().unwrap().to_string();
    drop(a);
    drop(b);
    std::thread::sleep(Duration::from_secs(2));
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &pid, "/F"])
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(feature = "live-xe")]
#[test]
fn live_http_default_sessions_share_profile_capacity_across_principals() {
    http_stdio_coexistence(false, false);
}

#[cfg(feature = "live-xe")]
#[test]
fn live_http_attaches_while_two_stdio_clients_remain_active() {
    http_stdio_coexistence(true, false);
}

#[cfg(all(feature = "live-xe", unix))]
#[test]
fn live_sigkill_http_launcher_allows_immediate_replacement() {
    http_stdio_coexistence(false, true);
}

#[cfg(feature = "live-xe")]
fn http_stdio_coexistence(stdio_first: bool, kill_frontend: bool) {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    const OAUTH_KEY: &str = "synthetic-broker-oauth-signing-key-32bytes";
    let root = tempfile::tempdir().unwrap();
    let path = config(root.path(), true);
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let resource = format!("http://{address}/mcp");
    let mut source = std::fs::read_to_string(&path).unwrap();
    source.push_str(&format!("\n[http]\njson_response = true\n[http.oauth]\nresource = {}\nallowed_issuers = [\"https://broker-test.invalid\"]\nauthorization_servers = [\"https://broker-test.invalid\"]\nhs256_secret_ref = \"env:BROKER_OAUTH_KEY\"\n", json!(resource)));
    std::fs::write(&path, source).unwrap();
    let mut stdio = Vec::new();
    if stdio_first {
        for index in 0..2 {
            let mut client = Client::spawn(root.path(), &path, index);
            assert!(client.response(1).get("result").is_some());
            client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
            stdio.push(client);
        }
    }
    let mut command = Command::new(test_binary());
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
        command.env_remove(key);
    }
    command
        .args([
            "--json",
            "serve",
            "--listen",
            &address.to_string(),
            "--profile",
            "shared",
        ])
        .env("ORACLEMCP_CONFIG", &path)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("BROKER_TEST_KEY", "synthetic-test-key-32-bytes-minimum")
        .env(
            "BROKER_TEST_PASSWORD",
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap(),
        )
        .env("BROKER_OAUTH_KEY", OAUTH_KEY)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if stdio_first {
        let mut wrong = command
            .env("BROKER_TEST_PASSWORD", "synthetic-wrong-http-password")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = wrong.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                wrong.kill().unwrap();
                wrong.wait().unwrap();
                panic!("wrong-password HTTP launcher must refuse before listening");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(2));
        let mut errors = String::new();
        wrong
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut errors)
            .unwrap();
        let error: Value = errors
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|frame| frame["kind"] == "error")
            .expect("typed HTTP credential refusal");
        assert_eq!(error["error"]["error_class"], "POLICY_DENIED", "{error}");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("ORACLEMCP_BROKER_CREDENTIAL_MISMATCH"),
            "{error}"
        );
        assert!(!errors.contains("synthetic-wrong-http-password"));
        assert!(
            TcpStream::connect(address).is_err(),
            "refused HTTP launcher must not bind"
        );
        command
            .env(
                "BROKER_TEST_PASSWORD",
                std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap(),
            )
            .stderr(Stdio::inherit());
    }
    if !stdio_first && !kill_frontend {
        // The spawning HTTP client's diagnostic pipe disappears with that
        // client. Its detached broker must still serve replacement clients.
        command.stderr(Stdio::piped());
    }
    let process = command.spawn().unwrap();
    struct HttpProcess(Child);
    impl Drop for HttpProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut process = HttpProcess(process);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(address).is_ok() {
            break;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "HTTP server exited during startup"
        );
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
    if !stdio_first && !kill_frontend {
        // Exercise loss of the spawning client's diagnostic pipe while its
        // broker is still serving. Holding an unread pipe open instead can
        // fill it with real connection diagnostics and block the fixture.
        drop(process.0.stderr.take());
    }
    if !stdio_first {
        for index in 0..2 {
            let mut client = Client::spawn(root.path(), &path, index);
            let initialized = client.response(1);
            assert!(
                initialized.get("result").is_some(),
                "HTTP owner must accept stdio: {initialized}"
            );
            client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
            stdio.push(client);
        }
    }
    for (index, client) in stdio.iter_mut().enumerate() {
        client.send(json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":format!("SELECT {} AS STDIO_VALUE FROM dual", 74+index)}}}));
    }
    let request = |token: &str,
                   session: Option<&str>,
                   frame: Value|
     -> (u16, Vec<(String, String)>, Value) {
        let body = frame.to_string();
        let session = session
            .map(|id| format!("mcp-session-id: {id}\r\n"))
            .unwrap_or_default();
        let method = if frame.is_null() { "DELETE" } else { "POST" };
        let raw = format!(
            "{method} /mcp HTTP/1.1\r\nhost: {address}\r\nauthorization: Bearer {token}\r\n{session}mcp-protocol-version: 2025-11-25\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").expect("HTTP response");
        let status = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = headers
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let data = body
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .next_back()
            .unwrap_or(body);
        (
            status,
            headers,
            if data.trim().is_empty() {
                Value::Null
            } else if status == 404 {
                Value::String(data.to_owned())
            } else {
                serde_json::from_str(data).expect("JSON or SSE payload")
            },
        )
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut sessions = Vec::new();
    let mut tokens = Vec::new();
    for index in 0..9 {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"at+jwt"}"#);
        let claims = json!({"iss":"https://broker-test.invalid","aud":resource,"exp":now+600,"iat":now,"sub":format!("principal-{index}"),"client_id":format!("http-client-{index}"),"jti":format!("test-{index}"),"scope":"oracle:admin"});
        let unsigned = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let token = format!(
            "{unsigned}.{}",
            URL_SAFE_NO_PAD.encode(oraclemcp_audit::hmac_sha256(
                OAUTH_KEY.as_bytes(),
                unsigned.as_bytes()
            ))
        );
        let (status, headers, initialized) = request(
            &token,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":format!("http-client-{index}"),"version":"1"}}}),
        );
        assert_eq!(status, 200, "{initialized}");
        let session = headers
            .iter()
            .find(|(name, _)| name == "mcp-session-id")
            .expect("HTTP is stateful without opt-in")
            .1
            .clone();
        assert!(sessions.iter().all(|existing| existing != &session));
        sessions.push(session.clone());
        tokens.push(token.clone());
        let (status, headers, response) = request(
            &token,
            Some(&session),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT 47 AS HTTP_BROKER_VALUE FROM dual"}}}),
        );
        if index < 8 {
            assert_eq!(status, 200, "{response}");
            assert_eq!(response["result"]["isError"], false, "{response}");
            assert!(
                response.to_string().contains("47"),
                "real FREE23 rows: {response}"
            );
        } else {
            assert_eq!(status, 429, "{response}");
            assert_eq!(
                response["result"]["structuredContent"]["error_class"], "AT_CAPACITY",
                "{response}"
            );
            assert!(headers.iter().any(|(name, _)| name == "retry-after"));
        }
    }
    for (index, client) in stdio.iter().enumerate() {
        let response = client.response(20);
        assert_eq!(response["result"]["isError"], false, "{response}");
        assert!(
            response.to_string().contains(&(74 + index).to_string()),
            "{response}"
        );
        assert!(!response.to_string().contains("LOCKED"));
    }
    for password in [Some("synthetic-deliberately-wrong-password"), None] {
        let client = Client::spawn_with_password(root.path(), &path, 3, password);
        let response = client.response(1);
        assert_eq!(
            response["error"]["data"]["error_class"], "POLICY_DENIED",
            "{response}"
        );
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("ORACLEMCP_BROKER_CREDENTIAL_MISMATCH"),
            "{response}"
        );
        assert!(
            !response
                .to_string()
                .contains("synthetic-deliberately-wrong-password")
        );
    }
    for client in &mut stdio {
        client.send(json!({"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT 76 AS SURVIVING_VALUE FROM dual"}}}));
        let response = client.response(21);
        assert_eq!(response["result"]["isError"], false, "{response}");
    }
    let password = std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap();
    for presented in [None, Some("synthetic-wrong-init-token")] {
        let client = Client::spawn_with_auth(
            root.path(),
            &path,
            4,
            Some(&password),
            Some("synthetic-client-token"),
            presented,
        );
        let response = client.response(1);
        assert!(
            response.get("error").is_some(),
            "client-local init-token gate: {response}"
        );
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("init token"),
            "{response}"
        );
    }
    let mut authenticated = Client::spawn_with_auth(
        root.path(),
        &path,
        2,
        Some(&password),
        Some("synthetic-client-token"),
        Some("synthetic-client-token"),
    );
    assert!(authenticated.response(1).get("result").is_some());
    authenticated.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let response = call(
        &mut authenticated,
        22,
        "oracle_query",
        json!({"sql":"SELECT 77 AS AUTHENTICATED_VALUE FROM dual"}),
    );
    assert_eq!(response["result"]["isError"], false, "{response}");
    drop(authenticated);
    for (token, session) in tokens.iter().zip(&sessions) {
        let (status, _, response) = request(token, Some(session), Value::Null);
        assert_eq!(status, 202, "session close: {response}");
        let (status, _, response) = request(
            token,
            Some(session),
            json!({"jsonrpc":"2.0","id":99,"method":"tools/list"}),
        );
        assert_eq!(status, 404, "deleted session must be unusable: {response}");
    }
    #[cfg(unix)]
    {
        assert!(
            Command::new("kill")
                .args([
                    if kill_frontend { "-KILL" } else { "-TERM" },
                    &process.0.id().to_string()
                ])
                .status()
                .unwrap()
                .success()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "HTTP frontend must acknowledge bounded graceful shutdown"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        if !kill_frontend {
            assert!(status.success(), "graceful HTTP shutdown: {status}");
        }
        drop(process.0.stderr.take());
        if !kill_frontend {
            assert!(
                TcpStream::connect(address).is_err(),
                "frontend exit must acknowledge listener closure"
            );
        }
        // No idle wait or retry of the failed launcher: immediately replace it
        // on the same root and address while both stdio clients remain alive.
        process = HttpProcess(command.stderr(Stdio::piped()).spawn().unwrap());
        let stderr = process.0.stderr.take().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                eprintln!("{line}");
                if let Ok(value) = serde_json::from_str::<Value>(&line)
                    && (value["kind"] == "status" || value["kind"] == "error")
                {
                    let _ = ready_tx.send(value);
                }
            }
        });
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("replacement must take over promptly without a launcher retry");
        assert_eq!(ready["kind"], "status", "replacement launcher: {ready}");
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while TcpStream::connect(address).is_err() {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "replacement HTTP startup refused"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "replacement HTTP startup timed out"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let (status, headers, reply) = request(
            &tokens[0],
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"http-replacement","version":"1"}}}),
        );
        assert_eq!(status, 200, "{reply}");
        let session = &headers
            .iter()
            .find(|(name, _)| name == "mcp-session-id")
            .unwrap()
            .1;
        let (status, _, reply) = request(
            &tokens[0],
            Some(session),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT 79 AS REPLACEMENT_VALUE FROM dual"}}}),
        );
        assert_eq!(status, 200, "{reply}");
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert!(reply.to_string().contains("79"), "{reply}");
        let (status, _, reply) = request(&tokens[0], Some(session), Value::Null);
        assert_eq!(status, 202, "{reply}");
    }
    drop(process);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(address).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "HTTP launcher disconnect must stop its listener"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    for client in &mut stdio {
        let response = call(
            client,
            23,
            "oracle_query",
            json!({"sql":"SELECT 78 AS SURVIVING_STDIO_VALUE FROM dual"}),
        );
        assert_eq!(
            response["result"]["isError"], false,
            "closing HTTP must preserve stdio: {response}"
        );
    }
    drop(stdio);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let audit = std::fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
        let closed: Vec<Value> = audit
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|record| {
                record["tool"] == "lane_lifecycle"
                    && record["subject"]["authn_method"] == "local-ipc"
            })
            .collect();
        if [0, 1, 2].into_iter().all(|index| {
            closed.iter().any(|record| {
                record["subject"]["client_id"]
                    .as_str()
                    .is_some_and(|id| id.contains(&format!("broker-test-{index}")))
            })
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "stdio cleanup must be audited before removing fixture directory"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut verify = Command::new(test_binary());
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
        verify.env_remove(key);
    }
    let verified = verify
        .args([
            "--json",
            "audit",
            "verify",
            root.path().join("audit.jsonl").to_str().unwrap(),
        ])
        .env("ORACLEMCP_CONFIG", &path)
        .env("BROKER_TEST_KEY", "synthetic-test-key-32-bytes-minimum")
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "mixed audit chain verify: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[cfg(feature = "live-xe")]
#[test]
fn live_bad_first_credentials_do_not_pin_the_root_broker() {
    let root = tempfile::tempdir().unwrap();
    let path = config(root.path(), true);
    for password in [Some("synthetic-wrong-first-password"), None] {
        let wrong = Client::spawn_with_password(root.path(), &path, 91, password);
        let refusal = wrong.response(1);
        assert_eq!(
            refusal["error"]["data"]["error_class"], "POLICY_DENIED",
            "{refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains("ORACLEMCP_BROKER_CREDENTIAL_INVALID"),
            "{refusal}"
        );
        assert!(
            !refusal
                .to_string()
                .contains("synthetic-wrong-first-password")
        );
        assert!(
            !root.path().join("state/oraclemcp/broker.json").exists(),
            "invalid first credentials must never elect an owner"
        );
        drop(wrong);
    }
    let mut valid = Client::spawn(root.path(), &path, 92);
    assert!(
        valid.response(1).get("result").is_some(),
        "correct client must start immediately after a refused first client"
    );
    valid.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    valid.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"SELECT 92 AS CORRECT_FIRST_VALUE FROM dual"}}}));
    let response = valid.response(2);
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(response.to_string().contains("92"));
    drop(valid);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let records = std::fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
        if records.lines().any(|line| {
            let record: Value = serde_json::from_str(line).unwrap();
            record["tool"] == "lane_lifecycle"
                && record["subject"]["client_id"]
                    .as_str()
                    .is_some_and(|id| id.contains("broker-test-92"))
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "wait for owned session's durable cleanup before fixture removal"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
