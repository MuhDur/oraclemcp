//! Spec-derived conformance tests for the native stdio MCP transport.
//!
//! Specification sources:
//! - Model Context Protocol: 2025-11-25
//! - JSON-RPC: 2.0

use std::io::Cursor;
use std::sync::Arc;

use asupersync::Cx;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::init_token::StdioAuthPolicy;
use oraclemcp_core::server::{DispatchContext, DispatchFuture, INIT_TOKEN_META_KEY, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_core::{CAPABILITIES_TOOL, OracleMcpServer};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const OVERSIZED_FRAME_LEN: usize = 1024 * 1024 + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequirementLevel {
    Must,
    Should,
}

struct Requirement {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    description: &'static str,
}

const REQUIREMENTS: &[Requirement] = &[
    Requirement {
        id: "MCP-STDIO-001",
        section: "Initialize",
        level: RequirementLevel::Must,
        description: "initialize returns the negotiated protocol version, server info, and tool capability",
    },
    Requirement {
        id: "MCP-STDIO-002",
        section: "Notifications",
        level: RequirementLevel::Must,
        description: "notifications/initialized produces no JSON-RPC response",
    },
    Requirement {
        id: "MCP-STDIO-003",
        section: "Tools",
        level: RequirementLevel::Must,
        description: "tools/list returns tool descriptors with MCP inputSchema objects",
    },
    Requirement {
        id: "MCP-STDIO-004",
        section: "Tools",
        level: RequirementLevel::Must,
        description: "tools/call returns content, structuredContent, and isError",
    },
    Requirement {
        id: "MCP-STDIO-005",
        section: "Tools",
        level: RequirementLevel::Must,
        description: "unknown tools are represented as MCP tool errors, not transport crashes",
    },
    Requirement {
        id: "JSONRPC-STDIO-001",
        section: "JSON-RPC errors",
        level: RequirementLevel::Must,
        description: "malformed JSON returns a parse error with null id",
    },
    Requirement {
        id: "JSONRPC-STDIO-002",
        section: "JSON-RPC errors",
        level: RequirementLevel::Must,
        description: "unknown methods return method-not-found and echo the request id",
    },
    Requirement {
        id: "JSONRPC-STDIO-003",
        section: "JSON-RPC errors",
        level: RequirementLevel::Must,
        description: "invalid params return invalid-params and echo the request id",
    },
    Requirement {
        id: "JSONRPC-STDIO-004",
        section: "JSON-RPC errors",
        level: RequirementLevel::Should,
        description: "oversized frames fail closed before JSON parsing",
    },
    Requirement {
        id: "JSONRPC-STDIO-005",
        section: "JSON-RPC errors",
        level: RequirementLevel::Should,
        description: "batch request arrays are explicitly rejected for stdio",
    },
    Requirement {
        id: "SEC-STDIO-001",
        section: "Security",
        level: RequirementLevel::Must,
        description: "init-token mismatch errors do not echo the presented token",
    },
];

struct EchoDispatch;
impl ToolDispatch for EchoDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            if name == "oracle_schema_inspect" {
                return Ok(json!({
                    "tool": name,
                    "ok": true,
                    "args": args,
                }));
            }
            Err(ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!("unknown tool: {name:?}"),
            ))
        })
    }
}

fn conformance_server() -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    registry.register(
        ToolDescriptor::new(
            "oracle_schema_inspect",
            ToolTier::FoundationLiveDb,
            "inspect a schema",
        )
        .with_input_schema(json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" }
            },
            "required": ["owner"],
            "additionalProperties": false
        })),
    );
    let report = CapabilitiesReport::new(
        "0.3.0",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: true,
            engine: false,
            http_transport: false,
        },
    );
    OracleMcpServer::new("0.3.0", registry, report, Arc::new(EchoDispatch))
}

fn frame(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("frame serializes");
    bytes.push(b'\n');
    bytes
}

fn initialize(token: Option<&str>) -> Value {
    let mut params = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "mcp-conformance", "version": "1.0" }
    });
    if let Some(token) = token {
        params["_meta"] = json!({ INIT_TOKEN_META_KEY: token });
    }
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": params
    })
}

fn run_frames(auth: StdioAuthPolicy, frames: Vec<Vec<u8>>) -> Vec<Value> {
    let mut input = Vec::new();
    for frame in frames {
        input.extend(frame);
    }
    let mut output = Vec::new();
    conformance_server()
        .serve_stdio_with_io(Cursor::new(input), &mut output, &auth)
        .expect("stdio conformance session completes");
    String::from_utf8(output)
        .expect("stdio replies are UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
        .collect()
}

fn run_script(requests: Vec<Value>) -> Vec<Value> {
    let mut frames = vec![frame(&initialize(None))];
    frames.push(frame(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })));
    for request in requests {
        frames.push(frame(&request));
    }
    run_frames(StdioAuthPolicy::Disabled, frames)
}

#[test]
fn conformance_requirement_matrix_is_accounted_for() {
    assert_eq!(REQUIREMENTS.len(), 11);
    let must = REQUIREMENTS
        .iter()
        .filter(|requirement| requirement.level == RequirementLevel::Must)
        .count();
    let should = REQUIREMENTS
        .iter()
        .filter(|requirement| requirement.level == RequirementLevel::Should)
        .count();
    assert_eq!(must, 9);
    assert_eq!(should, 2);
    let mut ids = REQUIREMENTS
        .iter()
        .map(|requirement| requirement.id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), REQUIREMENTS.len(), "requirement ids are unique");
    for requirement in REQUIREMENTS {
        assert!(
            !requirement.section.is_empty() && !requirement.description.is_empty(),
            "{} has section and description",
            requirement.id
        );
    }
}

#[test]
fn initialize_returns_mcp_2025_11_25_server_info_and_tools_capability() {
    let replies = run_script(vec![]);
    assert_eq!(replies.len(), 1);
    let result = &replies[0]["result"];
    assert_eq!(result["protocolVersion"], json!("2025-11-25"));
    assert_eq!(result["serverInfo"]["name"], json!("oraclemcp"));
    assert_eq!(result["serverInfo"]["version"], json!("0.3.0"));
    assert!(result["capabilities"]["tools"].is_object());
}

#[test]
fn initialized_notification_produces_no_response() {
    let replies = run_frames(
        StdioAuthPolicy::Disabled,
        vec![frame(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))],
    );
    assert!(replies.is_empty());
}

#[test]
fn tools_list_returns_input_schema_objects_and_echoes_string_ids() {
    let replies = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": "tools-1",
        "method": "tools/list"
    })]);
    let reply = replies
        .iter()
        .find(|reply| reply["id"] == json!("tools-1"))
        .expect("tools/list reply");
    let tools = reply["result"]["tools"]
        .as_array()
        .expect("tools/list result contains tools array");
    assert_eq!(tools[0]["name"], json!(CAPABILITIES_TOOL));
    for tool in tools {
        assert!(
            tool.get("input_schema").is_none(),
            "MCP uses inputSchema, not input_schema: {tool}"
        );
        assert_eq!(tool["inputSchema"]["type"], json!("object"));
    }
}

#[test]
fn tools_call_returns_structured_content_and_text_compatibility() {
    let replies = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "oracle_schema_inspect",
            "arguments": { "owner": "HR" }
        }
    })]);
    let result = &replies
        .iter()
        .find(|reply| reply["id"] == json!(2))
        .expect("tools/call reply")["result"];
    assert_eq!(result["isError"], json!(false));
    assert_eq!(
        result["structuredContent"]["tool"],
        json!("oracle_schema_inspect")
    );
    assert_eq!(result["structuredContent"]["args"]["owner"], json!("HR"));
    assert_eq!(
        result["content"][0]["text"],
        json!(result["structuredContent"].to_string())
    );
}

#[test]
fn unadvertised_tool_is_mcp_tool_error_not_jsonrpc_error() {
    let replies = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "does_not_exist",
            "arguments": {}
        }
    })]);
    let reply = replies
        .iter()
        .find(|reply| reply["id"] == json!(3))
        .expect("unknown tool reply");
    assert!(reply.get("error").is_none(), "tool errors stay in result");
    assert_eq!(reply["result"]["isError"], json!(true));
    assert_eq!(
        reply["result"]["structuredContent"]["error_class"],
        json!("INVALID_ARGUMENTS")
    );
}

#[test]
fn malformed_json_unknown_method_invalid_params_and_oversized_frames_fail_closed() {
    let malformed = run_frames(StdioAuthPolicy::Disabled, vec![b"{not json\n".to_vec()]);
    assert_eq!(malformed[0]["id"], Value::Null);
    assert_eq!(malformed[0]["error"]["code"], json!(JSONRPC_PARSE_ERROR));

    let unknown = run_frames(
        StdioAuthPolicy::Disabled,
        vec![frame(&json!({
            "jsonrpc": "2.0",
            "id": "unknown-1",
            "method": "oracle/not-a-method"
        }))],
    );
    assert_eq!(unknown[0]["id"], json!("unknown-1"));
    assert_eq!(unknown[0]["error"]["code"], json!(JSONRPC_METHOD_NOT_FOUND));

    let invalid_params = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": { "name": 7, "arguments": {} }
    })]);
    let invalid_reply = invalid_params
        .iter()
        .find(|reply| reply["id"] == json!(4))
        .expect("invalid params reply");
    assert_eq!(
        invalid_reply["error"]["code"],
        json!(JSONRPC_INVALID_PARAMS)
    );

    let oversized = run_frames(
        StdioAuthPolicy::Disabled,
        vec![vec![b'x'; OVERSIZED_FRAME_LEN]],
    );
    assert_eq!(oversized[0]["id"], Value::Null);
    assert_eq!(
        oversized[0]["error"]["code"],
        json!(JSONRPC_INVALID_REQUEST)
    );
}

#[test]
fn batch_requests_are_explicitly_rejected_for_stdio() {
    let replies = run_frames(
        StdioAuthPolicy::Disabled,
        vec![frame(&json!([
            { "jsonrpc": "2.0", "id": 1, "method": "tools/list" }
        ]))],
    );
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["id"], Value::Null);
    assert_eq!(replies[0]["error"]["code"], json!(JSONRPC_INVALID_REQUEST));
}

#[test]
fn init_token_mismatch_does_not_echo_presented_secret() {
    let presented = "do-not-echo-this-secret";
    let replies = run_frames(
        StdioAuthPolicy::Required {
            expected: "expected-token".to_owned(),
        },
        vec![frame(&initialize(Some(presented)))],
    );
    let response = replies[0].to_string();
    assert_eq!(replies[0]["error"]["code"], json!(JSONRPC_INVALID_REQUEST));
    assert!(
        !response.contains(presented),
        "token mismatch response must not echo presented token: {response}"
    );
}
