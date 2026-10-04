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
        let mut command = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("ORACLEMCP_")) {
            command.env_remove(key);
        }
        command
            .args(["serve", "--allow-no-auth", "--profile", "shared"])
            .env("ORACLEMCP_CONFIG", config)
            .env("XDG_STATE_HOME", root.join("state"))
            .env("BROKER_TEST_KEY", "synthetic-test-key-32-bytes-minimum")
            .env(
                "BROKER_TEST_PASSWORD",
                std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "offline".into()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
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
        client.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":format!("broker-test-{index}"),"version":"1"}}}));
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
fn held_dml_stays_in_its_own_stdio_session_and_rolls_back() {
    let root = tempfile::tempdir().unwrap();
    let path = config_with_ceiling(root.path(), true, "DDL");
    let mut a = Client::spawn(root.path(), &path, 0);
    assert!(a.response(1).get("result").is_some());
    a.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    elevate(&mut a, 2, "DDL");
    let existing = count(
        &mut a,
        4,
        "SELECT COUNT(*) AS N FROM all_tables WHERE owner = USER AND table_name = 'SG_BROKER_ISOLATION'",
        json!([]),
    );
    assert!(existing <= 1);
    if existing == 0 {
        // One reusable synthetic fixture; all run-owned rows remain uncommitted.
        execute(
            &mut a,
            5,
            "CREATE TABLE SG_BROKER_ISOLATION (RUN_ID VARCHAR2(64) PRIMARY KEY)",
            json!([]),
            true,
            false,
        );
    }
    let described = call(
        &mut a,
        7,
        "oracle_describe",
        json!({"table":"SG_BROKER_ISOLATION"}),
    );
    assert_eq!(described["result"]["isError"], false, "{described}");
    assert!(described.to_string().contains("RUN_ID"));
    // Open B after fixture DDL commits, so its first read-only snapshot cannot
    // predate the table definition (Oracle otherwise correctly raises ORA-01466).
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
        "INSERT INTO SG_BROKER_ISOLATION (RUN_ID) VALUES (:1)",
        json!([run_id]),
        false,
        true,
    );
    assert_eq!(
        held["result"]["structuredContent"]["committed"], false,
        "{held}"
    );
    let select = "SELECT COUNT(*) AS N FROM SG_BROKER_ISOLATION WHERE RUN_ID = :1";
    assert_eq!(
        count(&mut a, 12, select, json!([run_id])),
        1,
        "own pending DML visible to A"
    );
    assert_eq!(
        count(&mut b, 12, select, json!([run_id])),
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
    assert_eq!(count(&mut a, 16, select, json!([run_id])), 0);
    assert_eq!(count(&mut b, 16, select, json!([run_id])), 0);
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
