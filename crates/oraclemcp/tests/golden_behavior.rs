//! Golden behavior harness for the shipped stdio-facing server surface.
//!
//! The server is driven over rmcp's newline-delimited stdio transport using
//! synthetic mock connections. Goldens freeze observable JSON-RPC replies
//! before the native transport rewrite work starts.

use std::sync::Arc;
use std::time::Duration;

use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry::{capabilities, tool_registry};
use oraclemcp_core::init_token::StdioAuthPolicy;
use oraclemcp_core::server::INIT_TOKEN_META_KEY;
use oraclemcp_core::{CAPABILITIES_TOOL, OracleMcpServer};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleCell, OracleConnection, OracleConnectionInfo,
    OracleRow,
};
use rmcp::ServiceExt as _;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

struct OneRowMock;
impl OracleConnection for OneRowMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }

    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            server_version: Some("23.0.0".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            read_only: false,
            read_only_reason: None,
            current_schema: Some("APP".to_owned()),
            current_edition: Some("ORA$BASE".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            module: Some("oraclemcp-golden".to_owned()),
            action: None,
            client_identifier: Some("agent".to_owned()),
            client_info: None,
            os_user: Some("operator".to_owned()),
            host: Some("workstation".to_owned()),
            machine: Some("workstation".to_owned()),
            terminal: None,
            program: Some("oraclemcp".to_owned()),
            client_driver: Some("oraclemcp-driver".to_owned()),
        })
    }

    fn query_rows(&self, _sql: &str, _binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Ok(vec![OracleRow {
            columns: vec![
                (
                    "OBJECT_NAME".to_owned(),
                    OracleCell::new("VARCHAR2", Some("EMPLOYEES".to_owned())),
                ),
                (
                    "OWNER".to_owned(),
                    OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                ),
                (
                    "ROW_COUNT".to_owned(),
                    OracleCell::new("NUMBER", Some("42".to_owned())),
                ),
            ],
        }])
    }

    fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }

    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

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

    fn query_rows(&self, _sql: &str, _binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }

    fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Execute("ORA-00942".to_owned()))
    }

    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }

    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

fn server_over(conn: Box<dyn OracleConnection>) -> OracleMcpServer {
    OracleMcpServer::new(
        "0.2.1",
        tool_registry(),
        capabilities("0.2.1", true, false),
        Arc::new(OracleDispatcher::new(conn)),
    )
}

fn initialize(id: i64, token: Option<&str>) -> Value {
    let mut params = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "oraclemcp-golden-stdio", "version": "1.0" }
    });
    if let Some(token) = token {
        params["_meta"] = json!({ INIT_TOKEN_META_KEY: token });
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": params,
    })
}

fn frame(message: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).expect("JSON-RPC frame serializes");
    bytes.push(b'\n');
    bytes
}

struct ClientEvent {
    name: &'static str,
    message: Value,
    expect_response: bool,
}

async fn read_stdio_reply<R>(reader: &mut BufReader<R>) -> Value
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .expect("server replies to scripted stdio request")
        .expect("read reply");
    assert!(
        !line.trim().is_empty(),
        "server returned a non-empty JSON-RPC reply"
    );
    serde_json::from_str::<Value>(&line).expect("reply is JSON")
}

async fn run_stdio_script(server: OracleMcpServer, init: Value, events: Vec<ClientEvent>) -> Value {
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let serve = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });

    let (read_half, mut write_half) = tokio::io::split(client_io);
    write_half
        .write_all(&frame(&init))
        .await
        .expect("write initialize");
    let expected_replies = 1 + events.iter().filter(|event| event.expect_response).count();
    let mut reader = BufReader::new(read_half);
    let mut responses = Vec::with_capacity(expected_replies);
    responses.push(read_stdio_reply(&mut reader).await);

    for event in &events {
        write_half
            .write_all(&frame(&event.message))
            .await
            .expect("write scripted event");
        if event.expect_response {
            responses.push(read_stdio_reply(&mut reader).await);
        }
    }

    drop(write_half);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve).await;

    json!({
        "initialize": init,
        "events": events
            .into_iter()
            .map(|event| json!({
                "name": event.name,
                "expect_response": event.expect_response,
                "message": event.message,
            }))
            .collect::<Vec<_>>(),
        "responses": responses,
    })
}

fn required_auth_server(conn: Box<dyn OracleConnection>) -> OracleMcpServer {
    server_over(conn).with_stdio_auth(StdioAuthPolicy::Required {
        expected: "expected-init-token".to_owned(),
    })
}

#[tokio::test]
async fn golden_stdio_init_token_failures() {
    let missing = run_stdio_script(
        required_auth_server(Box::new(OneRowMock)),
        initialize(1, None),
        vec![],
    )
    .await;
    let wrong = run_stdio_script(
        required_auth_server(Box::new(OneRowMock)),
        initialize(1, Some("wrong-init-token")),
        vec![],
    )
    .await;

    let actual = json!({
        "case": "stdio initialize fail-closed init-token errors",
        "expected_token": "expected-init-token",
        "transcripts": [
            { "name": "missing token", "transcript": missing },
            { "name": "wrong token", "transcript": wrong },
        ],
    });
    golden_support::assert_golden("stdio/init_token_failures", &actual);
}

#[tokio::test]
async fn golden_stdio_main_tool_transcript() {
    let transcript = run_stdio_script(
        required_auth_server(Box::new(OneRowMock)),
        initialize(1, Some("expected-init-token")),
        vec![
            ClientEvent {
                name: "initialized notification",
                expect_response: false,
                message: json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                }),
            },
            ClientEvent {
                name: "tools/list",
                expect_response: true,
                message: json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                }),
            },
            ClientEvent {
                name: "oracle_capabilities",
                expect_response: true,
                message: json!({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": { "name": CAPABILITIES_TOOL, "arguments": {} },
                }),
            },
            ClientEvent {
                name: "structured success envelope",
                expect_response: true,
                message: json!({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "oracle_query",
                        "arguments": {
                            "sql": "select object_name, owner from all_objects where rownum <= 1",
                            "max_rows": 1
                        }
                    },
                }),
            },
            ClientEvent {
                name: "unknown tool",
                expect_response: true,
                message: json!({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": { "name": "does_not_exist", "arguments": {} },
                }),
            },
        ],
    )
    .await;

    let actual = json!({
        "case": "stdio initialize, initialized notification, tools/list, oracle_capabilities, structured success, and unknown tool",
        "transcript": transcript,
    });
    golden_support::assert_golden("stdio/main_tool_transcript", &actual);
}

#[tokio::test]
async fn golden_stdio_structured_error_envelope() {
    let transcript = run_stdio_script(
        required_auth_server(Box::new(FailingMock)),
        initialize(1, Some("expected-init-token")),
        vec![
            ClientEvent {
                name: "initialized notification",
                expect_response: false,
                message: json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                }),
            },
            ClientEvent {
                name: "structured db error envelope",
                expect_response: true,
                message: json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "oracle_schema_inspect",
                        "arguments": { "owner": "HR" }
                    },
                }),
            },
        ],
    )
    .await;

    let actual = json!({
        "case": "stdio live tool maps Oracle failure to structured MCP tool error",
        "transcript": transcript,
    });
    golden_support::assert_golden("stdio/structured_error_envelope", &actual);
}
