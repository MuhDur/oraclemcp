#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

struct CleanMachineEnv {
    addr: SocketAddr,
    url: String,
    service_name: String,
    profile_a: String,
    profile_b: String,
    token_a: Option<String>,
    token_b: Option<String>,
    boot_id_before: String,
    boot_id_after: String,
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

#[derive(Debug)]
struct AgentProof {
    switch: Value,
    query: Value,
    info: Value,
}

fn clean_machine_not_enabled() {
    eprintln!(
        "{}",
        json!({
            "contract": "H5",
            "requirement_id": "H5-CLEAN-MACHINE-001",
            "lane": "clean-machine",
            "subject": "not-opened",
            "sid": "not-opened",
            "profile": "multi-db",
            "level": "READ_ONLY",
            "grant": "none",
            "outcome": "not_run",
            "reason": "set ORACLEMCP_CLEAN_MACHINE_E2E=1 and run scripts/e2e/clean_machine_e2e.sh"
        })
    );
}

fn current_boot_id() -> Option<String> {
    if let Ok(value) = std::env::var("ORACLEMCP_CLEAN_MACHINE_BOOT_ID_AFTER") {
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_loopback_http_url(url: &str) -> SocketAddr {
    let rest = url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("ORACLEMCP_CLEAN_MACHINE_URL must start with http://: {url}"));
    let authority = rest.split('/').next().unwrap_or(rest);
    let normalized = if let Some(port) = authority.strip_prefix("localhost:") {
        format!("127.0.0.1:{port}")
    } else if authority.starts_with("[::1]:") {
        authority.to_owned()
    } else {
        authority.to_owned()
    };
    let addr = normalized
        .parse::<SocketAddr>()
        .unwrap_or_else(|e| panic!("invalid ORACLEMCP_CLEAN_MACHINE_URL address {url}: {e}"));
    assert!(
        addr.ip().is_loopback(),
        "ORACLEMCP_CLEAN_MACHINE_URL must point at loopback: {url}"
    );
    addr
}

fn require_env() -> Option<CleanMachineEnv> {
    if std::env::var("ORACLEMCP_CLEAN_MACHINE_E2E").ok().as_deref() != Some("1") {
        clean_machine_not_enabled();
        return None;
    }
    let url = std::env::var("ORACLEMCP_CLEAN_MACHINE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:7070".to_owned());
    let addr = parse_loopback_http_url(&url);
    let service_name = std::env::var("ORACLEMCP_CLEAN_MACHINE_SERVICE_NAME")
        .unwrap_or_else(|_| "oraclemcp".into());
    let profile_a = std::env::var("ORACLEMCP_CLEAN_MACHINE_PROFILE_A")
        .expect("set ORACLEMCP_CLEAN_MACHINE_PROFILE_A");
    let profile_b = std::env::var("ORACLEMCP_CLEAN_MACHINE_PROFILE_B")
        .expect("set ORACLEMCP_CLEAN_MACHINE_PROFILE_B");
    assert_ne!(
        profile_a, profile_b,
        "H5 requires two distinct service profiles"
    );
    let boot_id_before = std::env::var("ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE").expect(
        "set ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE from --print-reboot-marker before reboot",
    );
    let boot_id_after = current_boot_id()
        .expect("current boot id unavailable; set ORACLEMCP_CLEAN_MACHINE_BOOT_ID_AFTER");
    assert_ne!(
        boot_id_before, boot_id_after,
        "H5 requires proof that verification ran after a reboot"
    );

    let allow_no_auth = std::env::var("ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH")
        .ok()
        .as_deref()
        == Some("1");
    let token_a = std::env::var("ORACLEMCP_CLEAN_MACHINE_BEARER_A").ok();
    let token_b = std::env::var("ORACLEMCP_CLEAN_MACHINE_BEARER_B").ok();
    if !allow_no_auth {
        assert!(
            token_a.as_deref().is_some_and(|token| !token.is_empty())
                && token_b.as_deref().is_some_and(|token| !token.is_empty()),
            "set ORACLEMCP_CLEAN_MACHINE_BEARER_A/B, or ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH=1 for local test services"
        );
    }

    Some(CleanMachineEnv {
        addr,
        url,
        service_name,
        profile_a,
        profile_b,
        token_a,
        token_b,
        boot_id_before,
        boot_id_after,
    })
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(String, String)],
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

fn auth_headers(token: Option<&str>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(token) = token
        && !token.is_empty()
    {
        headers.push(("authorization".to_owned(), format!("Bearer {token}")));
    }
    headers
}

fn mcp_headers(token: Option<&str>, session_id: Option<&str>) -> Vec<(String, String)> {
    let mut headers = auth_headers(token);
    headers.push(("content-type".to_owned(), "application/json".to_owned()));
    if let Some(session_id) = session_id {
        headers.push(("mcp-session-id".to_owned(), session_id.to_owned()));
        headers.push(("mcp-protocol-version".to_owned(), "2025-11-25".to_owned()));
    }
    headers
}

fn wait_for_ready(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_status = None;
    loop {
        if let Ok(reply) = http_request(addr, "GET", "/readyz", &[], None) {
            last_status = Some(reply.status);
        }
        if last_status == Some(200) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "clean-machine service did not report ready before timeout; last_status={last_status:?}"
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

fn service_status(service_name: &str) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    command
        .args(["--json", "service", "status", "--name", service_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = json_output(command, Duration::from_secs(10));
    assert_eq!(
        output.status.code(),
        Some(0),
        "service status must report active service; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("service status JSON")
}

fn dashboard_pairing_url(url: &str) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oraclemcp"));
    command
        .args(["--json", "dashboard", "--url", url, "--no-open"])
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

fn initialize(addr: SocketAddr, token: Option<&str>, client_name: &str) -> String {
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
        &mcp_headers(token, None),
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

fn tool_call(
    addr: SocketAddr,
    token: Option<&str>,
    session_id: &str,
    id: u64,
    name: &str,
    arguments: Value,
) -> Value {
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
        &mcp_headers(token, Some(session_id)),
        Some(body.to_string().as_bytes()),
    )
    .expect("tool HTTP request");
    assert_eq!(reply.status, 200, "{name} failed: {}", reply.body);
    sse_last_json(&reply.body)
}

fn agent_flow(
    addr: SocketAddr,
    token: Option<String>,
    session_id: String,
    profile: String,
    sql_value: u8,
    base_id: u64,
) -> AgentProof {
    let switch = tool_call(
        addr,
        token.as_deref(),
        &session_id,
        base_id,
        "oracle_switch_profile",
        json!({ "profile": profile }),
    );
    assert_eq!(switch["result"]["isError"], json!(false), "{switch}");
    let query = tool_call(
        addr,
        token.as_deref(),
        &session_id,
        base_id + 1,
        "oracle_query",
        json!({
            "sql": format!("SELECT {sql_value} AS ORACLEMCP_H5_CLEAN_MACHINE FROM dual"),
            "max_rows": 1
        }),
    );
    assert_eq!(query["result"]["isError"], json!(false), "{query}");
    let info = tool_call(
        addr,
        token.as_deref(),
        &session_id,
        base_id + 2,
        "oracle_connection_info",
        json!({}),
    );
    assert_eq!(info["result"]["isError"], json!(false), "{info}");
    AgentProof {
        switch,
        query,
        info,
    }
}

fn active_profile(info: &Value) -> &str {
    info["result"]["structuredContent"]["active_profile"]
        .as_str()
        .unwrap_or_else(|| panic!("missing active profile in connection_info: {info}"))
}

fn db_fingerprint(info: &Value) -> &str {
    info["result"]["structuredContent"]["metadata_cache_key"]["db_fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("missing db fingerprint in connection_info: {info}"))
}

fn cache_profile(info: &Value) -> &str {
    info["result"]["structuredContent"]["metadata_cache_key"]["profile"]
        .as_str()
        .unwrap_or_else(|| panic!("missing profile in metadata_cache_key: {info}"))
}

fn assert_no_secret_leak(value: &str, env: &CleanMachineEnv) {
    for forbidden in [env.token_a.as_deref(), env.token_b.as_deref()]
        .into_iter()
        .flatten()
        .filter(|secret| !secret.is_empty())
    {
        assert!(
            !value.contains(forbidden),
            "clean-machine output leaked bearer token marker"
        );
    }
}

#[test]
#[ignore = "live-xe clean-machine: run scripts/e2e/clean_machine_e2e.sh after reboot with two live DB profiles"]
fn clean_machine_rebooted_service_dashboard_two_agents_two_dbs_without_mocks() {
    let Some(env) = require_env() else {
        return;
    };

    let status = service_status(&env.service_name);
    assert_eq!(status["active"], json!(true), "{status}");
    assert_eq!(
        status["runtime_instance"]["state"],
        json!("present"),
        "{status}"
    );
    assert_eq!(
        status["runtime_instance"]["listen"],
        json!(env.addr.to_string()),
        "{status}"
    );
    wait_for_ready(env.addr);

    let dashboard = dashboard_pairing_url(&env.url);
    let dashboard_url = dashboard["url"].as_str().expect("dashboard URL");
    let pair = http_request(env.addr, "GET", path_from_url(dashboard_url), &[], None)
        .expect("dashboard pair request");
    assert_eq!(pair.status, 303, "pairing failed: {}", pair.body);
    let cookie = pair
        .header("set-cookie")
        .and_then(|cookie| cookie.split(';').next())
        .expect("pairing sets dashboard cookie")
        .to_owned();
    let session = http_request(
        env.addr,
        "GET",
        "/dashboard/session",
        &[
            ("cookie".to_owned(), cookie),
            ("origin".to_owned(), env.url.clone()),
            ("sec-fetch-site".to_owned(), "same-origin".to_owned()),
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

    let session_a = initialize(env.addr, env.token_a.as_deref(), "codex-h5-clean-machine");
    let session_b = initialize(env.addr, env.token_b.as_deref(), "claude-h5-clean-machine");
    let addr_a = env.addr;
    let addr_b = env.addr;
    let token_a = env.token_a.clone();
    let token_b = env.token_b.clone();
    let profile_a = env.profile_a.clone();
    let profile_b = env.profile_b.clone();
    let agent_a = thread::spawn(move || agent_flow(addr_a, token_a, session_a, profile_a, 1, 100));
    let agent_b = thread::spawn(move || agent_flow(addr_b, token_b, session_b, profile_b, 2, 200));
    let proof_a = agent_a.join().expect("agent A lane joins");
    let proof_b = agent_b.join().expect("agent B lane joins");

    assert_eq!(active_profile(&proof_a.info), env.profile_a, "{proof_a:?}");
    assert_eq!(active_profile(&proof_b.info), env.profile_b, "{proof_b:?}");
    assert_eq!(cache_profile(&proof_a.info), env.profile_a, "{proof_a:?}");
    assert_eq!(cache_profile(&proof_b.info), env.profile_b, "{proof_b:?}");
    assert_ne!(
        db_fingerprint(&proof_a.info),
        db_fingerprint(&proof_b.info),
        "H5 requires two configured profiles to resolve to distinct database identities"
    );

    let combined = format!(
        "{status}{dashboard}{session_json}{}{}{}{}{}{}",
        proof_a.switch, proof_a.query, proof_a.info, proof_b.switch, proof_b.query, proof_b.info
    );
    assert_no_secret_leak(&combined, &env);

    eprintln!(
        "{}",
        json!({
            "contract": "H5",
            "requirement_id": "H5-CLEAN-MACHINE-001",
            "lane": "codex-h5-clean-machine/claude-h5-clean-machine/dashboard",
            "subject": "loopback-clean-machine-operator",
            "sid": "rebooted-service",
            "profile": {
                "a": env.profile_a,
                "b": env.profile_b
            },
            "level": "READ_ONLY",
            "grant": "none",
            "outcome": "pass",
            "reboot": {
                "before": env.boot_id_before,
                "after": env.boot_id_after
            },
            "service": {
                "name": env.service_name,
                "listen": env.addr.to_string(),
                "runtime_instance": "present"
            },
            "db_fingerprint": {
                "a": db_fingerprint(&proof_a.info),
                "b": db_fingerprint(&proof_b.info)
            }
        })
    );
}
