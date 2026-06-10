//! End-to-end MCP suite for the engine-free `oraclemcp` server (Phase-E E-2b).
//!
//! Mirrors `oraclemcp-core/tests/e2e_mcp.rs`: drives THIS server — built from
//! the real [`oraclemcp::registry::tool_registry`] + [`OracleDispatcher`] over a
//! driver-free mock connection — over a `tokio::io::duplex` rmcp handshake using
//! raw newline-delimited JSON-RPC frames. Asserts the full protocol surface
//! offline (default features, no Oracle driver):
//!   - `initialize` completes and advertises `oraclemcp`,
//!   - `tools/list` advertises the read-only registry tools + `oracle_capabilities`,
//!   - `tools/call oracle_capabilities` returns the capability report,
//!   - a live tool call against an error-returning mock returns a STRUCTURED
//!     error envelope (isError + error_class), never a panic.

use std::sync::Arc;
use std::time::Duration;

use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry::{TOOL_NAMES, capabilities, tool_registry};
use oraclemcp_core::{CAPABILITIES_TOOL, OracleMcpServer};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleConnection, OracleConnectionInfo, OracleRow,
};
use rmcp::ServiceExt as _;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A driver-free mock whose every query fails with a classifiable ORA- error,
/// so a live tool call exercises the DbError -> ErrorEnvelope path offline.
struct FailingMock;
impl OracleConnection for FailingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }
    fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Execute("ORA-00942".to_owned()))
    }
    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

/// Build the real server surface over the given mock connection.
fn server_over(conn: Box<dyn OracleConnection>) -> OracleMcpServer {
    let registry = tool_registry();
    let caps = capabilities("0.1.0", true, false);
    OracleMcpServer::new(
        "0.1.0",
        registry,
        caps,
        Arc::new(OracleDispatcher::new(conn)),
    )
}

/// One newline-delimited JSON-RPC request frame.
fn frame(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

/// Drive a scripted MCP session against `server` over a duplex transport. Sends
/// `initialize`, the `initialized` notification, then each request in
/// `requests`; returns the JSON-RPC replies that carry an `id` (notifications
/// produce no reply), in order.
async fn run_session(server: OracleMcpServer, requests: Vec<Value>) -> Vec<Value> {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let serve = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });

    let (read_half, mut write_half) = tokio::io::split(client_io);

    // initialize (no auth policy attached -> the gate is a no-op).
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "oraclemcp-e2e", "version": "1.0" }
        }
    });
    write_half.write_all(&frame(&init)).await.unwrap();
    // initialized notification (no id -> no reply).
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    write_half.write_all(&frame(&initialized)).await.unwrap();
    for req in &requests {
        write_half.write_all(&frame(req)).await.unwrap();
    }

    // Read one reply per request carrying an id: the initialize + each request.
    let expected = 1 + requests.len();
    let mut reader = BufReader::new(read_half);
    let mut replies = Vec::with_capacity(expected);
    let read = async {
        for _ in 0..expected {
            let mut line = String::new();
            // A 0-length read means the stream closed before all replies — bail.
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            replies.push(serde_json::from_str::<Value>(&line).unwrap());
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("server replies within 10s");

    // Drop the writer to close the stream so the serve task ends, then settle.
    drop(write_half);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve).await;
    replies
}

#[tokio::test]
async fn initialize_completes_and_advertises_the_server() {
    let replies = run_session(server_over(Box::new(FailingMock)), vec![]).await;
    assert_eq!(replies.len(), 1, "initialize yields one reply");
    let init = &replies[0];
    assert!(init.get("result").is_some(), "initialize succeeds: {init}");
    assert_eq!(init["result"]["serverInfo"]["name"], json!("oraclemcp"));
}

#[tokio::test]
async fn tools_list_advertises_registry_tools_plus_capabilities() {
    let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![list_req]).await;
    let list = replies
        .iter()
        .find(|r| r["id"] == json!(2))
        .expect("tools/list reply present");
    let tools = list["result"]["tools"].as_array().expect("tools array");

    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    for name in TOOL_NAMES {
        assert!(
            names.contains(&name),
            "tools/list missing `{name}`: {names:?}"
        );
    }
    assert!(
        names.contains(&CAPABILITIES_TOOL),
        "tools/list must advertise the discovery tool: {names:?}"
    );
    assert_eq!(
        names.len(),
        TOOL_NAMES.len() + 1,
        "registry tools + oracle_capabilities, got {names:?}"
    );
    // oracle_capabilities appears exactly once (no dup with the registry).
    assert_eq!(
        names.iter().filter(|n| **n == CAPABILITIES_TOOL).count(),
        1,
        "oracle_capabilities advertised once"
    );

    for tool in tools {
        let schema = tool
            .get("inputSchema")
            .or_else(|| tool.get("input_schema"))
            .unwrap_or_else(|| panic!("{} must advertise inputSchema", tool["name"]));
        assert_eq!(
            schema["type"],
            json!("object"),
            "{} schema must be a top-level object",
            tool["name"]
        );
        for keyword in ["oneOf", "anyOf", "allOf", "enum", "not"] {
            assert!(
                schema.get(keyword).is_none(),
                "{} schema must not advertise top-level {keyword}",
                tool["name"]
            );
        }
    }
}

#[tokio::test]
async fn call_oracle_capabilities_returns_the_report() {
    let call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": CAPABILITIES_TOOL, "arguments": {} }
    });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![call]).await;
    let reply = replies
        .iter()
        .find(|r| r["id"] == json!(3))
        .expect("capabilities call reply present");
    let result = &reply["result"];
    assert_eq!(
        result["isError"],
        json!(false),
        "capabilities is not an error: {reply}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["server_name"], json!("oraclemcp"));
    assert_eq!(structured["protocol_version"], json!("2025-11-25"));
    // The advertised tool surface in the report is the registry surface.
    assert_eq!(
        structured["tools"].as_array().map(Vec::len),
        Some(TOOL_NAMES.len()),
        "capability report lists the registry tools"
    );
}

#[tokio::test]
async fn live_tool_offline_returns_a_structured_error_envelope_not_a_panic() {
    // The mock returns ORA-00942 -> the dispatch maps it to an OBJECT_NOT_FOUND
    // envelope; the server reports it as an isError tool result, never a crash.
    let call = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": { "name": "oracle_schema_inspect", "arguments": { "owner": "HR" } }
    });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![call]).await;
    let reply = replies
        .iter()
        .find(|r| r["id"] == json!(4))
        .expect("schema_inspect call reply present");
    let result = &reply["result"];
    assert_eq!(
        result["isError"],
        json!(true),
        "a failing live tool is a structured error: {reply}"
    );
    let structured = &result["structuredContent"];
    assert_eq!(structured["error_class"], json!("OBJECT_NOT_FOUND"));
    assert_eq!(structured["ora_code"], json!(942));
}
