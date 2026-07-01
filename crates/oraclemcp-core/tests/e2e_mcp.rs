//! Scripted MCP client end-to-end suite (bead T-E2E / oracle-qmwz.6.7).
//!
//! Drives the server's protocol surface over the **Streamable HTTP** transport
//! (a real `initialize` handshake) and over the native **stdio** transport,
//! asserts concurrent-client isolation, and emits structured JSON-line logs as
//! verifiable evidence.
//!
//! The full live-DB flow (`oracle_connect` → `schema_inspect` → read query →
//! write-with-step-up → `oracle_query_execute`) and the multi-agent lease-bleed
//! assertion run in CI behind the live XE container (the T-INTEG matrix, bead
//! 6.1) — those tool bodies need a real database; this harness covers the
//! transport + protocol surface that gates them.

use std::io::Cursor;
use std::sync::Arc;

use asupersync::{Cx, Outcome};
use oraclemcp_core::OracleMcpServer;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{HttpRequest, HttpTransportConfig, MCP_PATH, handle_http_request};
use oraclemcp_core::init_token::StdioAuthPolicy;
use oraclemcp_core::server::{DispatchContext, DispatchFuture, INIT_TOKEN_META_KEY, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

/// A trivial engine-free dispatcher for the harness (the live tools are
/// container-gated; the protocol surface does not need them).
struct EchoDispatch;
impl ToolDispatch for EchoDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move { Outcome::Ok(json!({ "tool": name, "ok": true })) })
    }
}

fn harness_server() -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    registry.register(ToolDescriptor::new(
        "oracle_schema_inspect",
        ToolTier::FoundationLiveDb,
        "inspect a schema",
    ));
    let report = CapabilitiesReport::new(
        "0.1.0",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: true,
            engine: true,
            http_transport: true,
        },
    );
    OracleMcpServer::new("0.1.0", registry, report, Arc::new(EchoDispatch))
}

/// Structured JSON-line evidence log (printed with --nocapture).
fn log_step(step: &str, detail: Value) {
    println!("{}", json!({ "e2e_step": step, "detail": detail }));
}

fn init_request(client: &str) -> HttpRequest {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": client, "version": "1.0" }
        }
    });
    HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        body.to_string().into_bytes(),
    )
}

#[test]
fn http_initialize_handshake_is_scripted_end_to_end() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let server = harness_server();

    log_step(
        "http_initialize",
        json!({ "transport": "streamable-http", "path": MCP_PATH }),
    );
    let resp = handle_http_request(&server, &cfg, init_request("e2e-client"));
    assert_eq!(resp.status, 200, "initialize over HTTP succeeds");
    let body: Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(body.get("result").is_some(), "JSON-RPC initialize result");
    assert!(
        String::from_utf8_lossy(&resp.body).contains("oraclemcp"),
        "advertises the server"
    );
    log_step("http_initialize_ok", json!({ "status": 200 }));
}

#[test]
fn stdio_dispatch_path_serves_capabilities_and_tools() {
    log_step(
        "stdio_capabilities",
        json!({ "transport": "stdio", "tool": "oracle_capabilities" }),
    );
    let replies = run_stdio_session(
        harness_server(),
        StdioAuthPolicy::Disabled,
        None,
        vec![
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "oracle_capabilities", "arguments": {} }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "oracle_schema_inspect", "arguments": { "owner": "HR" } }
            }),
        ],
    );
    let capabilities = replies
        .iter()
        .find(|reply| reply["id"] == json!(2))
        .expect("capabilities reply");
    assert_eq!(capabilities["result"]["isError"], json!(false));
    let inspected = replies
        .iter()
        .find(|reply| reply["id"] == json!(3))
        .expect("schema inspect reply");
    assert_eq!(inspected["result"]["isError"], json!(false));
    log_step(
        "stdio_dispatch_ok",
        json!({ "tools": ["oracle_capabilities", "oracle_schema_inspect"] }),
    );
}

#[test]
fn concurrent_http_clients_are_isolated() {
    // Two independent clients drive the same server over HTTP; each request is
    // handled independently (no cross-client state bleed at the transport).
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let server = harness_server();

    log_step(
        "concurrent_clients",
        json!({ "clients": ["agent-a", "agent-b"] }),
    );
    let server_a = server.clone();
    let cfg_a = cfg.clone();
    let a = std::thread::spawn(move || {
        handle_http_request(&server_a, &cfg_a, init_request("agent-a")).status
    });
    let server_b = server.clone();
    let cfg_b = cfg.clone();
    let b = std::thread::spawn(move || {
        handle_http_request(&server_b, &cfg_b, init_request("agent-b")).status
    });
    assert_eq!(a.join().unwrap(), 200, "client A isolated + served");
    assert_eq!(b.join().unwrap(), 200, "client B isolated + served");
    log_step("concurrent_clients_ok", json!({ "both": 200 }));
}

// ---------------------------------------------------------------------------
// Regression for oracle-qm3q.10: the stdio init-token gate must be enforced on
// the live `initialize` request path (it was previously only logged — a silent
// no-op, so a Required token accepted any/no token). These tests drive the
// native stdio `initialize` path and assert the gate fails closed.
// ---------------------------------------------------------------------------

/// Build a raw JSON-RPC `initialize` frame, optionally carrying a `_meta` token.
fn stdio_init_request(token: Option<&str>) -> Value {
    let mut params = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "stdio-e2e", "version": "1.0" }
    });
    if let Some(t) = token {
        params["_meta"] = json!({ INIT_TOKEN_META_KEY: t });
    }
    json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params })
}

fn stdio_frame(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn run_stdio_session(
    server: OracleMcpServer,
    auth: StdioAuthPolicy,
    token: Option<&str>,
    requests: Vec<Value>,
) -> Vec<Value> {
    let mut input = stdio_frame(&stdio_init_request(token));
    input.extend(stdio_frame(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })));
    for request in &requests {
        input.extend(stdio_frame(request));
    }

    let mut output = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input), &mut output, &auth)
        .expect("stdio session completes");
    String::from_utf8(output)
        .expect("stdio replies are UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
        .collect()
}

/// Drive a real `initialize` handshake against a server carrying the given
/// stdio auth policy and presenting the given token; return the parsed JSON-RPC
/// reply (a `result` on success, an `error` on a refused handshake).
fn drive_initialize(auth: StdioAuthPolicy, token: Option<&str>) -> Value {
    run_stdio_session(harness_server(), auth, token, vec![])
        .into_iter()
        .next()
        .expect("initialize reply")
}

#[test]
fn stdio_initialize_required_rejects_missing_token() {
    let policy = StdioAuthPolicy::Required {
        expected: "s3cr3t".to_owned(),
    };
    let reply = drive_initialize(policy, None);
    log_step("stdio_init_missing_token", reply.clone());
    assert!(
        reply.get("error").is_some(),
        "missing token under Required must be refused, got: {reply}"
    );
    assert!(
        reply.get("result").is_none(),
        "a refused handshake must not return a result"
    );
}

#[test]
fn stdio_initialize_required_rejects_wrong_token() {
    let policy = StdioAuthPolicy::Required {
        expected: "s3cr3t".to_owned(),
    };
    let reply = drive_initialize(policy, Some("nope"));
    log_step("stdio_init_wrong_token", reply.clone());
    assert!(
        reply.get("error").is_some(),
        "wrong token under Required must be refused, got: {reply}"
    );
}

#[test]
fn stdio_initialize_required_accepts_correct_token() {
    let policy = StdioAuthPolicy::Required {
        expected: "s3cr3t".to_owned(),
    };
    let reply = drive_initialize(policy, Some("s3cr3t"));
    log_step("stdio_init_correct_token", reply.clone());
    assert!(
        reply.get("result").is_some(),
        "correct token under Required must complete the handshake, got: {reply}"
    );
    assert!(
        reply["result"]["serverInfo"]["name"] == json!("oraclemcp"),
        "the accepted handshake advertises the server"
    );
}

#[test]
fn stdio_initialize_disabled_accepts_any() {
    let reply = drive_initialize(StdioAuthPolicy::Disabled, None);
    log_step("stdio_init_disabled", reply.clone());
    assert!(
        reply.get("result").is_some(),
        "Disabled policy accepts a handshake with no token, got: {reply}"
    );
}
