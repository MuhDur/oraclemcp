//! End-to-end MCP suite for the engine-free `oraclemcp` server (Phase-E E-2b).
//!
//! Mirrors `oraclemcp-core/tests/e2e_mcp.rs`: drives THIS server — built from
//! the real [`oraclemcp::registry::tool_registry`] + [`OracleDispatcher`] over a
//! driver-free mock connection — over the native newline-delimited JSON-RPC
//! stdio transport. Asserts the full protocol surface offline (default
//! features, no Oracle driver):
//!   - `initialize` completes and advertises `oraclemcp`,
//!   - `tools/list` advertises the read-only registry tools + `oracle_capabilities`,
//!   - `tools/call oracle_capabilities` returns the capability report,
//!   - a live tool call against an error-returning mock returns a STRUCTURED
//!     error envelope (isError + error_class), never a panic.

use std::io::Cursor;
use std::sync::Arc;

use asupersync::Cx;
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry::{capabilities, tool_names, tool_registry};
use oraclemcp_core::{
    CAPABILITIES_TOOL, DispatchContext, OracleMcpServer, ScopeGrant, StdioAuthPolicy,
};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleCell, OracleConnection, OracleConnectionInfo,
    OracleRow,
};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::{Value, json};

/// A driver-free mock whose every query fails with a classifiable ORA- error,
/// so a live tool call exercises the DbError -> ErrorEnvelope path offline.
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
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }
    async fn execute(&self, _cx: &Cx, s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        if s == oraclemcp_guard::SET_TRANSACTION_READ_ONLY {
            return Ok(0);
        }
        Err(DbError::Execute("ORA-00942".to_owned()))
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

struct SuccessfulQueryMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for SuccessfulQueryMock {
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
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(vec![OracleRow {
            columns: vec![(
                "OBJECT_COUNT".to_owned(),
                OracleCell::new("NUMBER", Some("42".to_owned())),
            )],
        }])
    }
    async fn execute(&self, _cx: &Cx, sql: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        // A1: the read path lazily issues `SET TRANSACTION READ ONLY` as a
        // defense-in-depth backstop. Accept exactly that statement; ANY other
        // execute on the read path is still an error (a read must not write).
        if sql == oraclemcp_guard::SET_TRANSACTION_READ_ONLY {
            return Ok(0);
        }
        Err(DbError::Execute("unexpected execute".to_owned()))
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// Build the real server surface over the given mock connection.
fn server_over(conn: Box<dyn OracleConnection>) -> OracleMcpServer {
    server_over_with_dispatch(Arc::new(OracleDispatcher::new(conn)))
}

fn server_over_with_level(
    conn: Box<dyn OracleConnection>,
    level: SessionLevelState,
) -> OracleMcpServer {
    server_over_with_dispatch(Arc::new(OracleDispatcher::new_with_profile_level(
        conn,
        Some("test_profile".to_owned()),
        level,
    )))
}

fn server_over_with_dispatch(dispatcher: Arc<dyn oraclemcp_core::ToolDispatch>) -> OracleMcpServer {
    let registry = tool_registry();
    let caps = capabilities("0.1.0", true, false);
    OracleMcpServer::new("0.1.0", registry, caps, dispatcher)
}

fn elevated_ddl_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
    level
        .set_current_level(OperatingLevel::Ddl)
        .expect("test level can be raised within ceiling");
    level
}

fn read_only_hidden_tools() -> &'static [&'static str] {
    &[
        "oracle_execute",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
        "oracle_explain_plan",
        "enable_writes",
        "disable_writes",
        "execute_approved",
        "compile_object",
        "compile_with_warnings",
        "create_or_replace",
        "patch_package",
        "patch_view",
        "deploy_ddl",
    ]
}

fn find_tool<'a>(catalog: &'a [Value], name: &str) -> &'a Value {
    catalog
        .iter()
        .find(|tool| tool["name"] == json!(name))
        .unwrap_or_else(|| panic!("{name} advertised"))
}

/// One newline-delimited JSON-RPC request frame.
fn frame(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

/// Drive a scripted MCP session against `server` over stdio. Sends
/// `initialize`, the `initialized` notification, then each request in
/// `requests`; returns the JSON-RPC replies that carry an `id` (notifications
/// produce no reply), in order.
fn run_session(server: OracleMcpServer, requests: Vec<Value>) -> Vec<Value> {
    let mut input = Vec::new();
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
    input.extend(frame(&init));
    // initialized notification (no id -> no reply).
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    input.extend(frame(&initialized));
    for req in &requests {
        input.extend(frame(req));
    }

    let mut output = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input), &mut output, &StdioAuthPolicy::Disabled)
        .expect("stdio session completes");
    String::from_utf8(output)
        .expect("stdio replies are UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
        .collect()
}

#[test]
fn oracle_query_structured_content_matches_advertised_output_schema_fields() {
    let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": { "sql": "SELECT object_count FROM dual" }
        }
    });
    let replies = run_session(
        server_over(Box::new(SuccessfulQueryMock)),
        vec![list_req, call_req],
    );
    let tools = replies
        .iter()
        .find(|reply| reply["id"] == json!(2))
        .expect("tools/list reply")["result"]["tools"]
        .as_array()
        .expect("tools array");
    let query_tool = tools
        .iter()
        .find(|tool| tool["name"] == json!("oracle_query"))
        .expect("oracle_query advertised");
    let required = query_tool["outputSchema"]["required"]
        .as_array()
        .expect("query outputSchema required array");

    let structured = &replies
        .iter()
        .find(|reply| reply["id"] == json!(3))
        .expect("oracle_query reply")["result"]["structuredContent"];
    for field in required {
        let field = field.as_str().expect("required field is a string");
        assert!(
            structured.get(field).is_some(),
            "structuredContent must include required outputSchema field {field}"
        );
    }
    assert_eq!(structured["rows"][0]["OBJECT_COUNT"], json!("42"));
    assert_eq!(
        query_tool["outputSchema"]["properties"]["rows"]["items"]["additionalProperties"]["oneOf"]
            [0]["type"],
        json!("string"),
        "Oracle NUMBER remains schema-compatible as a lossless string"
    );
}

#[test]
fn initialize_completes_and_advertises_the_server() {
    let replies = run_session(server_over(Box::new(FailingMock)), vec![]);
    assert_eq!(replies.len(), 1, "initialize yields one reply");
    let init = &replies[0];
    assert!(init.get("result").is_some(), "initialize succeeds: {init}");
    assert_eq!(init["result"]["serverInfo"]["name"], json!("oraclemcp"));
}

#[test]
fn tools_list_reflects_the_calling_session_level() {
    let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![list_req]);
    let list = replies
        .iter()
        .find(|r| r["id"] == json!(2))
        .expect("tools/list reply present");
    let tools = list["result"]["tools"].as_array().expect("tools array");

    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    let registry_tools = tool_names();
    for name in &registry_tools {
        if read_only_hidden_tools().contains(name) {
            assert!(
                !names.contains(name),
                "read-only tools/list must hide `{name}`: {names:?}"
            );
        } else {
            assert!(
                names.contains(name),
                "tools/list missing `{name}`: {names:?}"
            );
        }
    }
    assert!(
        names.contains(&CAPABILITIES_TOOL),
        "tools/list must advertise the discovery tool: {names:?}"
    );
    assert_eq!(
        names.len(),
        registry_tools.len() + 1 - read_only_hidden_tools().len(),
        "read-only registry tools + oracle_capabilities, got {names:?}"
    );
    // oracle_capabilities appears exactly once (no dup with the registry).
    assert_eq!(
        names.iter().filter(|n| **n == CAPABILITIES_TOOL).count(),
        1,
        "oracle_capabilities advertised once"
    );

    for tool in tools {
        assert!(
            tool.get("title")
                .and_then(Value::as_str)
                .is_some_and(|title| !title.is_empty()),
            "{} must advertise a title",
            tool["name"]
        );
        let annotations = tool
            .get("annotations")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{} must advertise annotations", tool["name"]));
        for hint in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(
                annotations.get(hint).is_some_and(Value::is_boolean),
                "{} annotation {hint} must be explicit",
                tool["name"]
            );
        }
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

    for name in ["oracle_query", "query"] {
        let output_schema = find_tool(tools, name)
            .get("outputSchema")
            .unwrap_or_else(|| panic!("{name} must advertise outputSchema"));
        assert_eq!(output_schema["type"], json!("object"));
        // E3: the inline-page and export arms share one output schema; only
        // columns + row_count are always required, while rows/truncated/
        // total_bytes (inline) and export/resource_link (export) are optional.
        assert_eq!(output_schema["required"], json!(["columns", "row_count"]));
        for field in [
            "rows",
            "truncated",
            "total_bytes",
            "export",
            "resource_link",
        ] {
            assert!(
                output_schema["properties"].get(field).is_some(),
                "{name} outputSchema must document the {field} field"
            );
        }
        assert_eq!(
            output_schema["properties"]["rows"]["items"]["additionalProperties"]["oneOf"][0]["type"],
            json!("string"),
            "{name} outputSchema must preserve NUMBER-as-string by default"
        );
    }

    let elevated = run_session(
        server_over_with_level(Box::new(FailingMock), elevated_ddl_level()),
        vec![json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })],
    );
    let elevated_tools = elevated
        .iter()
        .find(|r| r["id"] == json!(2))
        .expect("elevated tools/list reply")["result"]["tools"]
        .as_array()
        .expect("elevated tools array");
    let elevated_names: Vec<&str> = elevated_tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for name in [
        "oracle_execute",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
        "oracle_explain_plan",
        "deploy_ddl",
    ] {
        assert!(
            elevated_names.contains(&name),
            "elevated tools/list must advertise `{name}`: {elevated_names:?}"
        );
    }
    assert!(
        find_tool(elevated_tools, "oracle_execute")
            .get("outputSchema")
            .is_none(),
        "oracle_execute must not advertise the query/explain outputSchema"
    );
    assert_eq!(
        find_tool(elevated_tools, "oracle_explain_plan")["outputSchema"]["properties"]["diagnostic_write"]
            ["properties"]["required_level"]["enum"],
        json!(["READ_WRITE"])
    );
}

#[test]
fn tools_list_honors_request_scope_ceiling() {
    let server = server_over_with_level(Box::new(FailingMock), elevated_ddl_level());
    let grant = ScopeGrant(vec!["oracle:read".to_owned()]);
    let reply = server
        .handle_jsonrpc_request_with_context(
            json!({
                "jsonrpc": "2.0",
                "id": "scoped-tools",
                "method": "tools/list"
            }),
            Some(&StdioAuthPolicy::Disabled),
            DispatchContext::with_scope_grant(&grant),
        )
        .expect("tools/list reply");
    let tools = reply["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert!(names.contains(&"oracle_query"));
    for hidden in read_only_hidden_tools() {
        assert!(
            !names.contains(hidden),
            "oracle:read scope must hide `{hidden}` despite a DDL-capable profile"
        );
    }
}

#[test]
fn tools_list_static_dispatchers_keep_the_full_registry() {
    struct StaticDispatch;
    impl oraclemcp_core::ToolDispatch for StaticDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: oraclemcp_core::DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> oraclemcp_core::DispatchFuture<'a> {
            Box::pin(async move { asupersync::Outcome::Ok(json!({ "tool": name })) })
        }
    }
    let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let replies = run_session(
        server_over_with_dispatch(Arc::new(StaticDispatch)),
        vec![list_req],
    );
    let list = replies
        .iter()
        .find(|r| r["id"] == json!(2))
        .expect("tools/list reply present");
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for name in tool_names() {
        assert!(names.contains(&name), "static list missing `{name}`");
    }
    assert_eq!(names.len(), tool_names().len() + 1);
}

#[test]
fn tools_list_schema_contract_is_preserved_for_visible_tools() {
    let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![list_req]);
    let list = replies
        .iter()
        .find(|r| r["id"] == json!(2))
        .expect("tools/list reply present");
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == json!(name))
            .unwrap_or_else(|| panic!("{name} advertised"))
    };
    for name in ["oracle_query", "query"] {
        let output_schema = tool(name)
            .get("outputSchema")
            .unwrap_or_else(|| panic!("{name} must advertise outputSchema"));
        assert_eq!(output_schema["type"], json!("object"));
        // E3: the inline-page and export arms share one output schema; only
        // columns + row_count are always required, while rows/truncated/
        // total_bytes (inline) and export/resource_link (export) are optional.
        assert_eq!(output_schema["required"], json!(["columns", "row_count"]));
        for field in [
            "rows",
            "truncated",
            "total_bytes",
            "export",
            "resource_link",
        ] {
            assert!(
                output_schema["properties"].get(field).is_some(),
                "{name} outputSchema must document the {field} field"
            );
        }
        assert_eq!(
            output_schema["properties"]["rows"]["items"]["additionalProperties"]["oneOf"][0]["type"],
            json!("string"),
            "{name} outputSchema must preserve NUMBER-as-string by default"
        );
    }
}

#[test]
fn discovery_resources_reflect_the_calling_session_level() {
    let replies = run_session(
        server_over(Box::new(FailingMock)),
        vec![
            json!({
                "jsonrpc": "2.0",
                "id": "tools-resource",
                "method": "resources/read",
                "params": { "uri": "oracle://tools" }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "caps-resource",
                "method": "resources/read",
                "params": { "uri": "oracle://capabilities" }
            }),
        ],
    );
    let text_for = |id: &str| {
        replies
            .iter()
            .find(|reply| reply["id"] == json!(id))
            .expect("resource reply")["result"]["contents"][0]["text"]
            .as_str()
            .expect("resource text")
            .to_owned()
    };
    let tools_doc: Value = serde_json::from_str(&text_for("tools-resource")).expect("tools JSON");
    let tool_names: Vec<&str> = tools_doc["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    for hidden in read_only_hidden_tools() {
        assert!(
            !tool_names.contains(hidden),
            "oracle://tools must hide read-only-unreachable `{hidden}`"
        );
    }

    let caps_doc: Value =
        serde_json::from_str(&text_for("caps-resource")).expect("capabilities JSON");
    assert_eq!(caps_doc["operating_level"]["current"], json!("READ_ONLY"));
    let caps_names: Vec<&str> = caps_doc["tools"]
        .as_array()
        .expect("capability tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert!(!caps_names.contains(&"oracle_execute"));
}

#[test]
fn call_oracle_capabilities_returns_the_report() {
    let call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": CAPABILITIES_TOOL, "arguments": {} }
    });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![call]);
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
    assert_eq!(structured["operating_level"]["current"], json!("READ_ONLY"));
    assert_eq!(structured["operating_level"]["max"], json!("READ_ONLY"));
    assert_eq!(structured["operating_level"]["protected"], json!(false));
    assert_eq!(structured["connection"]["connected"], json!(true));
    let reported_tools = structured["tools"].as_array().expect("tools array");
    let reported_names: Vec<&str> = reported_tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    for hidden in read_only_hidden_tools() {
        assert!(
            !reported_names.contains(hidden),
            "capabilities must hide read-only-unreachable `{hidden}`: {reported_names:?}"
        );
    }
    assert_eq!(
        reported_tools.len(),
        tool_names().len() - read_only_hidden_tools().len(),
        "capability report lists the calling lane's reachable registry tools"
    );
}

#[test]
fn live_tool_offline_returns_a_structured_error_envelope_not_a_panic() {
    // The mock returns ORA-00942 -> the dispatch maps it to an OBJECT_NOT_FOUND
    // envelope; the server reports it as an isError tool result, never a crash.
    let call = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": { "name": "oracle_schema_inspect", "arguments": { "owner": "HR" } }
    });
    let replies = run_session(server_over(Box::new(FailingMock)), vec![call]);
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
