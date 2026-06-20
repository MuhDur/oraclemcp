//! Golden behavior harness for the shipped stdio-facing server surface.
//!
//! The server is driven over the native newline-delimited JSON-RPC stdio
//! transport using synthetic mock connections. Goldens freeze observable
//! JSON-RPC replies for agent-facing compatibility.

use std::io::Cursor;
use std::sync::Arc;

use asupersync::Cx;
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry::{capabilities, tool_registry};
use oraclemcp_core::init_token::StdioAuthPolicy;
use oraclemcp_core::server::INIT_TOKEN_META_KEY;
use oraclemcp_core::{CAPABILITIES_TOOL, OracleMcpServer};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleCell, OracleConnection, OracleConnectionInfo,
    OracleRow,
};
use serde_json::{Value, json};

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

struct OneRowMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for OneRowMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            connection_strategy: Some("single_session".to_owned()),
            pool_open_connections: None,
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

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
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

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// Returns one synthetic row per fetched window so `oracle_query` truncates and
/// hands back a pagination cursor. The OFFSET/FETCH envelope is applied by
/// `read_query`; this mock ignores the SQL and always yields `fetch`-sized
/// windows, which is enough to exercise the opaque-cursor round trip.
struct PagedMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for PagedMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        // Always return 2 rows so a max_rows=1 page is truncated (the read path
        // fetches max_rows+1 to detect "more").
        Ok((0..2)
            .map(|i| OracleRow {
                columns: vec![(
                    "ID".to_owned(),
                    OracleCell::new("NUMBER", Some(i.to_string())),
                )],
            })
            .collect())
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

struct FailingMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for FailingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Execute("ORA-00942".to_owned()))
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

fn server_over(conn: Box<dyn OracleConnection>) -> OracleMcpServer {
    OracleMcpServer::new(
        "0.3.0",
        tool_registry(),
        capabilities("0.3.0", true, false),
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

fn run_stdio_script(
    server: OracleMcpServer,
    auth: StdioAuthPolicy,
    init: Value,
    events: Vec<ClientEvent>,
) -> Value {
    let mut input = Vec::new();
    input.extend(frame(&init));
    let expected_replies = 1 + events.iter().filter(|event| event.expect_response).count();

    for event in &events {
        input.extend(frame(&event.message));
    }

    let mut output = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input), &mut output, &auth)
        .expect("stdio script completes");
    let responses: Vec<Value> = String::from_utf8(output)
        .expect("stdio replies are UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
        .collect();
    assert_eq!(
        responses.len(),
        expected_replies,
        "script returned expected JSON-RPC replies"
    );

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

fn required_auth() -> StdioAuthPolicy {
    StdioAuthPolicy::Required {
        expected: "expected-init-token".to_owned(),
    }
}

#[test]
fn golden_stdio_init_token_failures() {
    let missing = run_stdio_script(
        server_over(Box::new(OneRowMock)),
        required_auth(),
        initialize(1, None),
        vec![],
    );
    let wrong = run_stdio_script(
        server_over(Box::new(OneRowMock)),
        required_auth(),
        initialize(1, Some("wrong-init-token")),
        vec![],
    );

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

#[test]
fn golden_stdio_main_tool_transcript() {
    let transcript = run_stdio_script(
        server_over(Box::new(OneRowMock)),
        required_auth(),
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
    );

    let actual = json!({
        "case": "stdio initialize, initialized notification, tools/list, oracle_capabilities, structured success, and unknown tool",
        "transcript": transcript,
    });
    golden_support::assert_golden("stdio/main_tool_transcript", &actual);
}

/// Drive one JSON-RPC request through a fresh stdio session (initialize +
/// initialized + the request) and return the request's reply. Used by the E2
/// pagination golden, which must extract a real opaque cursor from one reply to
/// build the next request — a thing the static-script harness cannot do.
fn one_request(server: &OracleMcpServer, request: Value) -> Value {
    let mut input = Vec::new();
    input.extend(frame(&initialize(1, Some("expected-init-token"))));
    input.extend(frame(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })));
    input.extend(frame(&request));
    let mut output = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input), &mut output, &required_auth())
        .expect("stdio session completes");
    let id = request["id"].clone();
    String::from_utf8(output)
        .expect("stdio replies are UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
        .find(|reply| reply["id"] == id)
        .expect("request reply present")
}

fn query_request(id: i64, cursor: Option<&str>) -> Value {
    let mut args = json!({
        "sql": "select id from all_objects",
        "max_rows": 1
    });
    if let Some(cursor) = cursor {
        args["cursor"] = json!(cursor);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": "oracle_query", "arguments": args },
    })
}

fn structured_cursor(reply: &Value) -> String {
    reply["result"]["structuredContent"]["next_cursor"]
        .as_str()
        .expect("truncated page carries an opaque next_cursor")
        .to_owned()
}

#[test]
fn golden_stdio_query_opaque_cursor_pagination() {
    // Page 1: truncated, opaque tamper-evident cursor.
    let page1 = one_request(&server_over(Box::new(PagedMock)), query_request(2, None));
    assert_eq!(
        page1["result"]["structuredContent"]["truncated"],
        json!(true)
    );
    let real_cursor = structured_cursor(&page1);
    // The cursor is opaque: it is NOT the raw "1" offset and carries a MAC tag.
    assert_ne!(real_cursor, "1", "cursor is opaque, not a raw offset");
    assert!(real_cursor.contains('.'), "cursor carries a MAC tag");

    // Page 2: replay the real cursor (round-trips to the next window).
    let page2 = one_request(
        &server_over(Box::new(PagedMock)),
        query_request(3, Some(&real_cursor)),
    );

    // Forged cursor: keep the MAC tag but bump the signed offset body. The MAC
    // covers the body, so this fails closed with a structured error envelope.
    let (_body, tag) = real_cursor.rsplit_once('.').expect("cursor has a tag");
    let forged_cursor = format!("9999.{tag}");
    let forged = one_request(
        &server_over(Box::new(PagedMock)),
        query_request(4, Some(&forged_cursor)),
    );
    assert_eq!(forged["result"]["isError"], json!(true));

    // Cross-statement replay: a cursor minted for one statement must not page a
    // different statement (it is bound to the statement hash).
    let other = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": {
                "sql": "select id from other_table",
                "max_rows": 1,
                "cursor": real_cursor,
            }
        },
    });
    let cross = one_request(&server_over(Box::new(PagedMock)), other);
    assert_eq!(cross["result"]["isError"], json!(true));

    let actual = json!({
        "case": "oracle_query opaque, tamper-evident pagination cursor: round-trip + forged-offset + cross-statement rejection",
        "page1_first_page": page1,
        "page2_resumed_with_real_cursor": page2,
        "forged_offset_rejected": forged,
        "cross_statement_cursor_rejected": cross,
    });
    golden_support::assert_golden("stdio/query_opaque_cursor_pagination", &actual);
}

/// Mock returning rows with CSV-significant content (a comma, a quote) so the
/// export escaping is exercised end-to-end.
struct ExportMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for ExportMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(vec![
            OracleRow {
                columns: vec![
                    (
                        "ID".to_owned(),
                        OracleCell::new("NUMBER", Some("1".to_owned())),
                    ),
                    (
                        "NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("alice".to_owned())),
                    ),
                ],
            },
            OracleRow {
                columns: vec![
                    (
                        "ID".to_owned(),
                        OracleCell::new("NUMBER", Some("2".to_owned())),
                    ),
                    (
                        "NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("bob, \"the builder\"".to_owned())),
                    ),
                ],
            },
        ])
    }
    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// A scripted polling source whose fingerprint advances on demand so the E1
/// golden can model "the watched resource changed".
struct GoldenPollingSource {
    fingerprints: std::sync::Mutex<std::collections::HashMap<String, String>>,
}
impl oraclemcp_core::subscriptions::PollingSource for GoldenPollingSource {
    fn poll(&self, uri: &str) -> Option<String> {
        self.fingerprints.lock().unwrap().get(uri).cloned()
    }
}

#[test]
fn golden_stdio_resource_subscribe_and_updated_notification() {
    use oraclemcp_core::subscriptions::{SubscribeSource, SubscriptionHub};

    let uri = "oracle://object/HR/PACKAGE/EMP_API";
    let source = Arc::new(GoldenPollingSource {
        fingerprints: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    source
        .fingerprints
        .lock()
        .unwrap()
        .insert(uri.to_owned(), "fp-v1".to_owned());

    struct Adapter(Arc<GoldenPollingSource>);
    impl oraclemcp_core::subscriptions::PollingSource for Adapter {
        fn poll(&self, uri: &str) -> Option<String> {
            self.0.poll(uri)
        }
    }
    let hub = Arc::new(SubscriptionHub::with_source(SubscribeSource::Polling(
        Box::new(Adapter(source.clone())),
    )));

    let build = || {
        OracleMcpServer::new(
            "0.3.0",
            tool_registry(),
            capabilities("0.3.0", true, false),
            Arc::new(OracleDispatcher::new(Box::new(OneRowMock))),
        )
        .with_subscriptions(Arc::clone(&hub))
    };

    // initialize advertises subscribe (a source is confirmed).
    let init_reply = one_request(
        &build(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );
    let _ = init_reply; // tools/list reply, not asserted here.

    // Subscribe (seeds the baseline fingerprint).
    let subscribe_reply = one_request(
        &build(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/subscribe",
            "params": { "uri": uri },
        }),
    );
    assert!(subscribe_reply["result"].is_object());

    // Build the server we will drive for the change scenario, then change the
    // resource and run a request whose post-flush carries resources/updated.
    let server = build();
    // Subscribe on THIS server instance (the hub is shared, but the baseline
    // fingerprint seed happens on subscribe).
    let mut input = Vec::new();
    input.extend(frame(&initialize(1, Some("expected-init-token"))));
    input.extend(frame(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    ));
    input.extend(frame(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/subscribe",
        "params": { "uri": uri },
    })));
    // The resource changes between the subscribe and the next request.
    // (Encoded by mutating the source, then polling, before the next frame.)
    {
        // Drain the first segment so the baseline is seeded.
        let mut out = Vec::new();
        server
            .serve_stdio_with_io(Cursor::new(input.clone()), &mut out, &required_auth())
            .expect("subscribe segment completes");
    }
    source
        .fingerprints
        .lock()
        .unwrap()
        .insert(uri.to_owned(), "fp-v2".to_owned());
    let changed = hub.poll_for_changes();
    assert_eq!(
        changed,
        vec![uri.to_owned()],
        "the polled change is detected"
    );

    // The next request flushes the queued notifications/resources/updated after
    // its response.
    let mut input2 = Vec::new();
    input2.extend(frame(&initialize(1, Some("expected-init-token"))));
    input2.extend(frame(
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    ));
    input2.extend(frame(
        &json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list" }),
    ));
    let mut out2 = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input2), &mut out2, &required_auth())
        .expect("post-change segment completes");
    let replies: Vec<Value> = String::from_utf8(out2)
        .expect("UTF-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("JSON"))
        .collect();
    let updated: Vec<&Value> = replies
        .iter()
        .filter(|r| r["method"] == json!("notifications/resources/updated"))
        .collect();
    assert_eq!(updated.len(), 1, "exactly one resources/updated flushed");
    assert_eq!(updated[0]["params"]["uri"], json!(uri));

    // Capabilities advertisement is the gate; capture an initialize reply.
    let init_capture = one_request_init(&build());

    let actual = json!({
        "case": "E1 resources/subscribe + polling-fallback resources/updated; subscribe advertised only when a change source is confirmed",
        "initialize_advertises_subscribe": init_capture["result"]["capabilities"]["resources"],
        "subscribe_reply": subscribe_reply,
        "post_change_segment_replies": replies,
    });
    golden_support::assert_golden("stdio/resource_subscribe_and_updated", &actual);
}

/// Drive just an `initialize` and return its reply.
fn one_request_init(server: &OracleMcpServer) -> Value {
    let mut input = Vec::new();
    input.extend(frame(&initialize(1, Some("expected-init-token"))));
    let mut output = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input), &mut output, &required_auth())
        .expect("initialize completes");
    String::from_utf8(output)
        .expect("UTF-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("JSON"))
        .next()
        .expect("initialize reply")
}

#[test]
fn golden_stdio_query_export_resource_and_resource_link() {
    // The dispatcher and server must share an export registry, so build the
    // server with `with_exports` and a dispatcher carrying the same registry.
    let exports = Arc::new(oraclemcp_core::ExportRegistry::new());
    let dispatcher = OracleDispatcher::new(Box::new(ExportMock)).with_exports(Arc::clone(&exports));
    let server = OracleMcpServer::with_exports(
        "0.3.0",
        tool_registry(),
        capabilities("0.3.0", true, false),
        Arc::new(dispatcher),
        exports,
    );

    // E3b: oracle_query with export=true returns a resource_link (no inline rows).
    let export_call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": {
                "sql": "select id, name from people",
                "export": true,
                "export_format": "csv"
            }
        },
    });
    let export_reply = one_request(&server, export_call);
    assert_eq!(export_reply["result"]["isError"], json!(false));
    let structured = &export_reply["result"]["structuredContent"];
    assert_eq!(structured["inlined"], json!(false));
    let export_uri = structured["export"]["uri"]
        .as_str()
        .expect("export uri present")
        .to_owned();
    assert!(export_uri.starts_with("oracle-export://"));
    assert_eq!(
        structured["resource_link"]["type"],
        json!("resource_link"),
        "E3b returns a resource_link content arm"
    );

    // E3: resources/read of the export uri returns the escaped CSV body.
    let read_reply = one_request(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": { "uri": export_uri },
        }),
    );
    let csv = read_reply["result"]["contents"][0]["text"]
        .as_str()
        .expect("export CSV body");
    assert_eq!(
        read_reply["result"]["contents"][0]["mimeType"],
        json!("text/csv")
    );
    assert!(csv.starts_with("ID,NAME\n"), "CSV header present");
    // RFC 4180 escaping: the comma + embedded quotes force quoting + doubling.
    assert!(
        csv.contains("\"bob, \"\"the builder\"\"\""),
        "CSV field with comma/quote is escaped: {csv}"
    );

    // E3: a forged export id (kept tag, edited body) fails closed (not found).
    let (_body, tag) = export_uri
        .strip_prefix("oracle-export://")
        .and_then(|id| id.rsplit_once('.'))
        .expect("export id has a tag");
    let forged_uri = format!("oracle-export://exp-9999.{tag}");
    let forged_read = one_request(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": { "uri": forged_uri },
        }),
    );
    assert!(
        forged_read["error"]["data"]["error_class"] == json!("OBJECT_NOT_FOUND"),
        "a forged export id reads as not-found: {forged_read}"
    );

    let actual = json!({
        "case": "oracle_query export=true returns a resource_link; resources/read serves the escaped CSV; a forged export id fails closed",
        "export_query_resource_link": export_reply,
        "resources_read_export": read_reply,
        "forged_export_id_rejected": forged_read,
    });
    golden_support::assert_golden("stdio/query_export_resource_and_resource_link", &actual);
}

#[test]
fn golden_stdio_structured_error_envelope() {
    let transcript = run_stdio_script(
        server_over(Box::new(FailingMock)),
        required_auth(),
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
    );

    let actual = json!({
        "case": "stdio live tool maps Oracle failure to structured MCP tool error",
        "transcript": transcript,
    });
    golden_support::assert_golden("stdio/structured_error_envelope", &actual);
}
