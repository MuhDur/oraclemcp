#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().expect("poll service child").is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct HttpReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpReply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }
}

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oraclemcp-g6-live-service-{}-{stamp}-{label}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    root
}

fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let addr = listener.local_addr().expect("read loopback port");
    drop(listener);
    addr
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

fn write_live_config(root: &Path, dsn: &str, user: &str) -> PathBuf {
    let path = root.join("profiles.toml");
    let audit = root.join("audit.jsonl");
    let config = format!(
        r#"
schema_version = 2
default_profile = "live_xe"

[http]
json_response = true
stateful = true
dashboard_workbench = true

[audit]
path = {}

[[profiles]]
name = "live_xe"
description = "G6 live-XE service attach profile"
connect_string = {}
username = {}
credential_ref = "env:ORACLEMCP_TEST_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
call_timeout_seconds = 10
"#,
        toml_string(&audit.display().to_string()),
        toml_string(dsn),
        toml_string(user)
    );
    fs::write(&path, config).expect("write live-XE config");
    path
}

fn live_env() -> Option<(String, String, String)> {
    if std::env::var("ORACLEMCP_LIVE_XE").ok().as_deref() != Some("1") {
        eprintln!(
            "{}",
            json!({
                "contract": "G6",
                "requirement_id": "G6-LIVE-SERVICE-001",
                "lane": "service-attach",
                "subject": "live-xe",
                "sid": "not-opened",
                "profile": "live_xe",
                "level": "READ_ONLY",
                "grant": "none",
                "outcome": "not_run",
                "reason": "set ORACLEMCP_LIVE_XE=1 with ORACLEMCP_TEST_DSN/_USER/_PASSWORD"
            })
        );
        return None;
    }
    let dsn = std::env::var("ORACLEMCP_TEST_DSN").ok()?;
    let user = std::env::var("ORACLEMCP_TEST_USER").ok()?;
    let password = std::env::var("ORACLEMCP_TEST_PASSWORD").ok()?;
    Some((dsn, user, password))
}

fn spawn_service(
    addr: SocketAddr,
    config: &Path,
    runtime_dir: &Path,
    state_dir: &Path,
) -> ChildGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_oraclemcp"))
        .args([
            "--json",
            "serve",
            "--listen",
            &addr.to_string(),
            "--allow-no-auth",
            "--http-stateful",
            "--http-json-response",
            "--profile",
            "live_xe",
        ])
        .env(oraclemcp_config::CONFIG_PATH_ENV, config)
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env("XDG_STATE_HOME", state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live-XE service");
    ChildGuard { child }
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> std::io::Result<HttpReply> {
    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nhost: {addr}\r\naccept: application/json, text/event-stream, text/html\r\nconnection: close\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Ok(HttpReply {
        status,
        headers,
        body: body.to_owned(),
    })
}

fn wait_for_service(child: &mut ChildGuard, addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_status = None;
    loop {
        if let Some(status) = child.child.try_wait().expect("poll service child") {
            panic!("live-XE service exited before attach: {status}");
        }
        if let Ok(reply) = http_request(addr, "GET", "/readyz", &[], None) {
            last_status = Some(reply.status);
        }
        if last_status == Some(200) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "live-XE service did not report ready before timeout; last_status={last_status:?}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn json_output(mut command: Command, timeout: Duration) -> Output {
    let mut child = command.spawn().expect("spawn command");
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll command").is_some() {
            return child.wait_with_output().expect("collect command output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect killed output");
            panic!(
                "command timed out; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn initialize(addr: SocketAddr, client_name: &str) -> String {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": client_name, "version": "1.0" }
        }
    });
    let reply = http_request(
        addr,
        "POST",
        "/mcp",
        &[("content-type", "application/json")],
        Some(body.to_string().as_bytes()),
    )
    .expect("initialize HTTP request");
    assert_eq!(reply.status, 200, "initialize failed: {}", reply.body);
    reply
        .header("mcp-session-id")
        .expect("stateful initialize returns mcp-session-id")
        .to_owned()
}

fn sse_last_json(body: &str) -> Value {
    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|data| *data != "null")
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .next_back()
        .unwrap_or_else(|| panic!("SSE body did not contain a JSON event: {body}"))
}

fn tool_call(addr: SocketAddr, session_id: &str, id: u64, name: &str, arguments: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    });
    let reply = http_request(
        addr,
        "POST",
        "/mcp",
        &[
            ("content-type", "application/json"),
            ("mcp-session-id", session_id),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Some(body.to_string().as_bytes()),
    )
    .expect("tool HTTP request");
    assert_eq!(reply.status, 200, "{name} failed: {}", reply.body);
    sse_last_json(&reply.body)
}

fn dashboard_pairing_url(
    addr: SocketAddr,
    config: &Path,
    runtime_dir: &Path,
    state_dir: &Path,
) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    command
        .args([
            "--json",
            "dashboard",
            "--url",
            &format!("http://{addr}"),
            "--no-open",
        ])
        .env(oraclemcp_config::CONFIG_PATH_ENV, config)
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env("XDG_STATE_HOME", state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = json_output(command, Duration::from_secs(5));
    assert_eq!(
        output.status.code(),
        Some(0),
        "dashboard command failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("dashboard JSON")
}

fn path_from_url(url: &str) -> &str {
    let without_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .expect("dashboard URL has scheme");
    let slash = without_scheme
        .find('/')
        .expect("dashboard URL has path component");
    &without_scheme[slash..]
}

fn assert_no_secret_leak(value: &str, dsn: &str, user: &str, password: &str) {
    for forbidden in [
        dsn,
        user,
        password,
        "credential_ref",
        "ORACLEMCP_TEST_PASSWORD",
    ] {
        assert!(
            !value.contains(forbidden),
            "live attach output leaked sensitive marker {forbidden}: {value}"
        );
    }
}

#[test]
#[ignore = "live-xe: set ORACLEMCP_LIVE_XE=1 and ORACLEMCP_TEST_* to spawn a real service"]
fn live_xe_service_attachs_mcp_status_and_dashboard_without_mocks() {
    let Some((dsn, user, password)) = live_env() else {
        return;
    };
    let root = temp_root("service-attach");
    let runtime_dir = root.join("run");
    let state_dir = root.join("state");
    fs::create_dir_all(&runtime_dir).expect("create runtime dir");
    fs::create_dir_all(&state_dir).expect("create state dir");
    let config = write_live_config(&root, &dsn, &user);
    let addr = free_loopback_addr();
    let mut service = spawn_service(addr, &config, &runtime_dir, &state_dir);
    wait_for_service(&mut service, addr);

    let session_a = initialize(addr, "codex-g6-live");
    let session_b = initialize(addr, "claude-g6-live");
    let addr_a = addr;
    let codex = thread::spawn(move || {
        tool_call(
            addr_a,
            &session_a,
            11,
            "oracle_query",
            json!({
                "sql": "SELECT 1 AS ORACLEMCP_LIVE_ATTACH FROM dual",
                "max_rows": 1
            }),
        )
    });
    let claude = thread::spawn(move || {
        tool_call(
            addr,
            &session_b,
            12,
            "oracle_query",
            json!({
                "sql": "SELECT 2 AS ORACLEMCP_LIVE_ATTACH FROM dual",
                "max_rows": 1
            }),
        )
    });
    let codex_reply = codex.join().expect("codex live lane joins");
    let claude_reply = claude.join().expect("claude live lane joins");
    for reply in [&codex_reply, &claude_reply] {
        assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
        let rows = reply["result"]["structuredContent"]["rows"]
            .as_array()
            .expect("oracle_query returns rows");
        assert_eq!(rows.len(), 1, "{reply}");
    }

    let info_session = initialize(addr, "connection-info-g6");
    let info = tool_call(addr, &info_session, 13, "oracle_connection_info", json!({}));
    assert_eq!(
        info["result"]["structuredContent"]["active_profile"],
        json!("live_xe"),
        "{info}"
    );

    let mut status_cmd = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    status_cmd
        .args(["--json", "service", "status"])
        .env(oraclemcp_config::CONFIG_PATH_ENV, &config)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("XDG_STATE_HOME", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let status = json_output(status_cmd, Duration::from_secs(5));
    assert!(
        matches!(status.status.code(), Some(0 | 3)),
        "service status should return active or inactive-with-runtime metadata: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("service status JSON");
    assert_eq!(
        status_json["runtime_instance"]["state"],
        json!("present"),
        "{status_json}"
    );
    assert_eq!(
        status_json["runtime_instance"]["listen"],
        json!(addr.to_string()),
        "{status_json}"
    );

    let dashboard = dashboard_pairing_url(addr, &config, &runtime_dir, &state_dir);
    let dashboard_url = dashboard["url"].as_str().expect("dashboard URL");
    let pair = http_request(addr, "GET", path_from_url(dashboard_url), &[], None)
        .expect("dashboard pair request");
    assert_eq!(pair.status, 303, "pairing failed: {}", pair.body);
    let cookie = pair
        .header("set-cookie")
        .and_then(|cookie| cookie.split(';').next())
        .expect("pairing sets dashboard cookie")
        .to_owned();
    let origin = format!("http://{addr}");
    let session = http_request(
        addr,
        "GET",
        "/dashboard/session",
        &[
            ("cookie", &cookie),
            ("origin", &origin),
            ("sec-fetch-site", "same-origin"),
        ],
        None,
    )
    .expect("dashboard session request");
    assert_eq!(
        session.status, 200,
        "dashboard session failed: {}",
        session.body
    );
    let session_json: Value = serde_json::from_str(&session.body).expect("session JSON");
    assert_eq!(
        session_json["csrf_header"],
        json!("x-oraclemcp-csrf"),
        "{session_json}"
    );

    let combined =
        format!("{codex_reply}{claude_reply}{info}{status_json}{dashboard}{session_json}");
    assert_no_secret_leak(&combined, &dsn, &user, &password);
    eprintln!(
        "{}",
        json!({
            "contract": "G6",
            "requirement_id": "G6-LIVE-SERVICE-001",
            "lane": "codex-g6-live/claude-g6-live/dashboard",
            "subject": "loopback-live-operator",
            "sid": "live-service",
            "profile": "live_xe",
            "level": "READ_ONLY",
            "grant": "none",
            "outcome": "pass",
            "service": {
                "listen": addr.to_string(),
                "runtime_instance": "present"
            }
        })
    );
}
