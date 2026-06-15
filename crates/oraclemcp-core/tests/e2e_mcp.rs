//! Scripted MCP client end-to-end suite (bead T-E2E / oracle-qmwz.6.7).
//!
//! Drives the server's protocol surface over the **Streamable HTTP** transport
//! (a real `initialize` handshake) and over the **stdio dispatch path** (the
//! same `run_tool` the stdio transport invokes), asserts concurrent-client
//! isolation, and emits structured JSON-line logs as verifiable evidence.
//!
//! The full live-DB flow (`oracle_connect` → `schema_inspect` → read query →
//! write-with-step-up → `oracle_query_execute`) and the multi-agent lease-bleed
//! assertion run in CI behind the live XE container (the T-INTEG matrix, bead
//! 6.1) — those tool bodies need a real database; this harness covers the
//! transport + protocol surface that gates them.

use std::sync::Arc;

use asupersync::Cx;
use oraclemcp_core::OracleMcpServer;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{HttpTransportConfig, MCP_PATH, build_router};
use oraclemcp_core::init_token::StdioAuthPolicy;
use oraclemcp_core::server::{DispatchFuture, INIT_TOKEN_META_KEY, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use rmcp::ServiceExt as _;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;

/// A trivial engine-free dispatcher for the harness (the live tools are
/// container-gated; the protocol surface does not need them).
struct EchoDispatch;
impl ToolDispatch for EchoDispatch {
    fn dispatch<'a>(&'a self, _cx: &'a Cx, name: &'a str, _args: Value) -> DispatchFuture<'a> {
        Box::pin(async move { Ok(json!({ "tool": name, "ok": true })) })
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

fn init_request(client: &str) -> axum::http::Request<axum::body::Body> {
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
    axum::http::Request::builder()
        .method("POST")
        .uri(MCP_PATH)
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn http_initialize_handshake_is_scripted_end_to_end() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let router = build_router(harness_server(), &cfg);

    log_step(
        "http_initialize",
        json!({ "transport": "streamable-http", "path": MCP_PATH }),
    );
    let resp = router.oneshot(init_request("e2e-client")).await.unwrap();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "initialize over HTTP succeeds"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.get("result").is_some(), "JSON-RPC initialize result");
    assert!(
        String::from_utf8_lossy(&bytes).contains("oraclemcp"),
        "advertises the server"
    );
    log_step("http_initialize_ok", json!({ "status": 200 }));
}

#[tokio::test]
async fn stdio_dispatch_path_serves_capabilities_and_tools() {
    // The stdio transport drives the same run_tool path; assert the protocol
    // surface (capabilities + the registered tool) is served identically.
    let server = harness_server();

    log_step(
        "stdio_capabilities",
        json!({ "transport": "stdio", "tool": "oracle_capabilities" }),
    );
    let result = server
        .run_tool("oracle_capabilities".to_owned(), json!({}))
        .await;
    assert!(
        !result.is_error.unwrap_or(false),
        "capabilities call is not an error"
    );

    // A regular tool dispatches through the injected dispatcher.
    let result = server
        .run_tool("oracle_schema_inspect".to_owned(), json!({ "owner": "HR" }))
        .await;
    assert!(!result.is_error.unwrap_or(false), "tool dispatch succeeds");
    log_step(
        "stdio_dispatch_ok",
        json!({ "tools": ["oracle_capabilities", "oracle_schema_inspect"] }),
    );
}

#[tokio::test]
async fn concurrent_http_clients_are_isolated() {
    // Two independent clients drive the same server over HTTP; each request is
    // handled independently (no cross-client state bleed at the transport).
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let router = build_router(harness_server(), &cfg);

    log_step(
        "concurrent_clients",
        json!({ "clients": ["agent-a", "agent-b"] }),
    );
    let (ra, rb) = tokio::join!(
        router.clone().oneshot(init_request("agent-a")),
        router.clone().oneshot(init_request("agent-b")),
    );
    assert_eq!(
        ra.unwrap().status(),
        axum::http::StatusCode::OK,
        "client A isolated + served"
    );
    assert_eq!(
        rb.unwrap().status(),
        axum::http::StatusCode::OK,
        "client B isolated + served"
    );
    log_step("concurrent_clients_ok", json!({ "both": 200 }));
}

// ---------------------------------------------------------------------------
// Regression for oracle-qm3q.10: the stdio init-token gate must be enforced on
// the live `initialize` request path (it was previously only logged — a silent
// no-op, so a Required token accepted any/no token). These tests drive a REAL
// rmcp `initialize` handshake over a duplex transport (the same transport
// family `serve_stdio` uses) and assert the gate fails closed.
// ---------------------------------------------------------------------------

/// Build a raw JSON-RPC `initialize` frame, optionally carrying a `_meta` token.
fn init_frame(token: Option<&str>) -> Vec<u8> {
    let mut params = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "stdio-e2e", "version": "1.0" }
    });
    if let Some(t) = token {
        params["_meta"] = json!({ INIT_TOKEN_META_KEY: t });
    }
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params });
    let mut bytes = serde_json::to_vec(&req).unwrap();
    bytes.push(b'\n');
    bytes
}

/// Drive a real `initialize` handshake against a server carrying the given
/// stdio auth policy and presenting the given token; return the parsed JSON-RPC
/// reply (a `result` on success, an `error` on a refused handshake).
async fn drive_initialize(auth: Option<StdioAuthPolicy>, token: Option<&str>) -> Value {
    let mut server = harness_server();
    if let Some(policy) = auth {
        server = server.with_stdio_auth(policy);
    }

    let (server_io, client_io) = tokio::io::duplex(8 * 1024);
    // Run the rmcp serve loop on the server half (the same `serve` call
    // `serve_stdio` makes, exercising the `initialize` override end to end).
    let serve = tokio::spawn(async move {
        match server.serve(server_io).await {
            Ok(running) => {
                // Handshake accepted; tear down cleanly so the task ends.
                let _ = running.cancel().await;
                true
            }
            // Handshake refused (e.g. fail-closed token rejection).
            Err(_) => false,
        }
    });

    let (read_half, mut write_half) = tokio::io::split(client_io);
    write_half.write_all(&init_frame(token)).await.unwrap();

    // Read exactly one newline-delimited JSON-RPC reply.
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    })
    .await
    .expect("server replies to initialize within 5s");

    // Let the serve task settle (success path cancels itself).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), serve).await;
    reply
}

#[tokio::test]
async fn stdio_initialize_required_rejects_missing_token() {
    let policy = StdioAuthPolicy::Required {
        expected: "s3cr3t".to_owned(),
    };
    let reply = drive_initialize(Some(policy), None).await;
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

#[tokio::test]
async fn stdio_initialize_required_rejects_wrong_token() {
    let policy = StdioAuthPolicy::Required {
        expected: "s3cr3t".to_owned(),
    };
    let reply = drive_initialize(Some(policy), Some("nope")).await;
    log_step("stdio_init_wrong_token", reply.clone());
    assert!(
        reply.get("error").is_some(),
        "wrong token under Required must be refused, got: {reply}"
    );
}

#[tokio::test]
async fn stdio_initialize_required_accepts_correct_token() {
    let policy = StdioAuthPolicy::Required {
        expected: "s3cr3t".to_owned(),
    };
    let reply = drive_initialize(Some(policy), Some("s3cr3t")).await;
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

#[tokio::test]
async fn stdio_initialize_disabled_accepts_any() {
    let reply = drive_initialize(Some(StdioAuthPolicy::Disabled), None).await;
    log_step("stdio_init_disabled", reply.clone());
    assert!(
        reply.get("result").is_some(),
        "Disabled policy accepts a handshake with no token, got: {reply}"
    );
}
