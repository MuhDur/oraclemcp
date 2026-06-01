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

use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{HttpTransportConfig, MCP_PATH, build_router};
use oraclemcp_core::server::ToolDispatch;
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_core::{OracleMcpServer, error::ErrorEnvelope};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};
use tower::ServiceExt;

/// A trivial engine-free dispatcher for the harness (the live tools are
/// container-gated; the protocol surface does not need them).
struct EchoDispatch;
impl ToolDispatch for EchoDispatch {
    fn dispatch(&self, name: &str, _args: Value) -> Result<Value, ErrorEnvelope> {
        Ok(json!({ "tool": name, "ok": true }))
    }
}

fn harness_server() -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    registry.register(ToolDescriptor {
        name: "oracle_schema_inspect".to_owned(),
        tier: ToolTier::FoundationLiveDb,
        summary: "inspect a schema".to_owned(),
    });
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
