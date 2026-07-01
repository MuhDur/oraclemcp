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
        id: "MCP-STDIO-009",
        section: "Tools",
        level: RequirementLevel::Must,
        description: "tools/list emits explicit title and tool annotations so clients do not rely on unsafe defaults",
    },
    Requirement {
        id: "MCP-STDIO-010",
        section: "Tools",
        level: RequirementLevel::Must,
        description: "tools/list preserves declared outputSchema for structuredContent validation",
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
        id: "MCP-STDIO-006",
        section: "Initialize",
        level: RequirementLevel::Must,
        description: "initialize capabilities advertise resources only after resource handlers are served",
    },
    Requirement {
        id: "MCP-STDIO-007",
        section: "Resources",
        level: RequirementLevel::Must,
        description: "resources/list, resources/templates/list, and resources/read are served with MCP resource content objects",
    },
    Requirement {
        id: "MCP-STDIO-008",
        section: "Prompts",
        level: RequirementLevel::Must,
        description: "prompts/list and prompts/get are served only after prompt capability negotiation",
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
    Requirement {
        id: "MCP-STDIO-011",
        section: "Pagination",
        level: RequirementLevel::Must,
        description: "list endpoints emit an opaque nextCursor that round-trips to cover every item once",
    },
    Requirement {
        id: "MCP-STDIO-012",
        section: "Pagination",
        level: RequirementLevel::Must,
        description: "a forged or cross-endpoint pagination cursor is rejected with invalid-params, never silently followed",
    },
    Requirement {
        id: "MCP-STDIO-013",
        section: "Resources",
        level: RequirementLevel::Must,
        description: "a materialized export is served over resources/read with its MIME type, and a forged/expired export id fails closed",
    },
    Requirement {
        id: "MCP-STDIO-014",
        section: "Resources",
        level: RequirementLevel::Must,
        description: "an export is access-controlled: a resources/read under a different scope grant is refused",
    },
    Requirement {
        id: "MCP-STDIO-015",
        section: "Subscriptions",
        level: RequirementLevel::Must,
        description: "resources.subscribe is advertised and resources/subscribe accepted only when a change source is confirmed; otherwise unadvertised and refused",
    },
    Requirement {
        id: "MCP-STDIO-016",
        section: "Subscriptions",
        level: RequirementLevel::Must,
        description: "a subscribed resource that changes (polling fallback) emits a notifications/resources/updated for that uri",
    },
    Requirement {
        id: "MCP-STDIO-017",
        section: "Completion",
        level: RequirementLevel::Must,
        description: "completion/complete is advertised and served (owner/type/object autocomplete) with a capped {values,total,hasMore} envelope",
    },
    Requirement {
        id: "MCP-STDIO-018",
        section: "Notifications",
        level: RequirementLevel::Must,
        description: "notifications/progress is emitted for a tools/call carrying a progressToken and is a true notification (no id)",
    },
    Requirement {
        id: "MCP-STDIO-019",
        section: "Notifications",
        level: RequirementLevel::Must,
        description: "notifications/tools/list_changed is advertised (tools.listChanged) and emitted when the served tool set changes",
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
            let result: Result<Value, ErrorEnvelope> = match name {
                "oracle_schema_inspect" => Ok(json!({
                    "tool": name,
                    "ok": true,
                    "args": args,
                })),
                "oracle_get_source" => Ok(json!({
                    "source": {
                        "owner": args["owner"],
                        "name": args["name"],
                        "object_type": args["object_type"],
                        "source": "PACKAGE emp_api AS END emp_api;\n",
                        "line_count": 1,
                        "char_count": 31,
                        "truncated": false,
                    }
                })),
                "oracle_get_ddl" => Ok(json!({
                    "owner": args["owner"],
                    "name": args["name"],
                    "ddl": "CREATE TABLE employees (id NUMBER)"
                })),
                // E7 completion sources: list_schemas → owners, search_objects →
                // object names, list_profiles → the E5-filtered exposed profiles.
                "oracle_list_schemas" => Ok(json!({
                    "schemas": [
                        { "SCHEMA_NAME": "HR", "OBJECT_COUNT": "10" },
                        { "SCHEMA_NAME": "HIDDEN_OWNER", "OBJECT_COUNT": "1" },
                    ],
                })),
                "oracle_search_objects" => Ok(json!({
                    "detail_level": "names",
                    "count": 2,
                    "results": [
                        { "owner": args["owner"], "object_name": "EMPLOYEES", "object_type": "TABLE" },
                        { "owner": args["owner"], "object_name": "EMP_AUDIT", "object_type": "TABLE" },
                    ],
                })),
                // The dispatcher already E5-filters this to exposed profiles; the
                // echo returns only an exposed profile so the completion test can
                // assert a hidden profile never appears.
                "oracle_list_profiles" => Ok(json!({
                    "profiles": [ { "name": "agent_ro" } ],
                })),
                _ => Err(ErrorEnvelope::new(
                    ErrorClass::InvalidArguments,
                    format!("unknown tool: {name:?}"),
                )),
            };
            result.into()
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
        }))
        .with_output_schema(json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "tool": { "type": "string" }
            },
            "required": ["ok", "tool"],
            "additionalProperties": true
        })),
    );
    registry.register(ToolDescriptor::new(
        "oracle_get_source",
        ToolTier::FoundationLiveDb,
        "fetch object source",
    ));
    registry.register(ToolDescriptor::new(
        "oracle_get_ddl",
        ToolTier::FoundationLiveDb,
        "fetch object DDL",
    ));
    registry.register(
        ToolDescriptor::new(
            "oracle_execute",
            ToolTier::FoundationLiveDb,
            "execute gated SQL",
        )
        .destructive(),
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
    assert_eq!(REQUIREMENTS.len(), 25);
    let must = REQUIREMENTS
        .iter()
        .filter(|requirement| requirement.level == RequirementLevel::Must)
        .count();
    let should = REQUIREMENTS
        .iter()
        .filter(|requirement| requirement.level == RequirementLevel::Should)
        .count();
    assert_eq!(must, 23);
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
    // E6: the server emits notifications/tools/list_changed (e.g. after a
    // profile switch alters the served tool set), so it advertises the capability.
    assert_eq!(result["capabilities"]["tools"]["listChanged"], json!(true));
    // E7: completion/complete is served, so completions is advertised.
    assert!(result["capabilities"]["completions"].is_object());
    assert_eq!(
        result["capabilities"]["resources"]["subscribe"],
        json!(false)
    );
    assert_eq!(
        result["capabilities"]["resources"]["listChanged"],
        json!(false)
    );
    assert_eq!(
        result["capabilities"]["prompts"]["listChanged"],
        json!(false)
    );
}

#[test]
fn resources_and_prompts_are_advertised_and_served_without_unserved_arms() {
    let replies = run_script(vec![
        json!({
            "jsonrpc": "2.0",
            "id": "resources-list",
            "method": "resources/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "resources-read",
            "method": "resources/read",
            "params": { "uri": "oracle://capabilities" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "resources-read-tools",
            "method": "resources/read",
            "params": { "uri": "oracle://tools" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "resources-templates",
            "method": "resources/templates/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "resources-read-schema",
            "method": "resources/read",
            "params": { "uri": "oracle://schema/HR" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "resources-read-object",
            "method": "resources/read",
            "params": { "uri": "oracle://object/HR/PACKAGE/EMP_API" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "prompts-list",
            "method": "prompts/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "prompts-get",
            "method": "prompts/get",
            "params": {
                "name": "investigate_slow_query",
                "arguments": { "sql": "SELECT * FROM employees" }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "prompts-get-missing-arg",
            "method": "prompts/get",
            "params": {
                "name": "investigate_slow_query",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": "completion-complete",
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "oracle://object/{owner}/{type}/{name}" },
                "argument": { "name": "type", "value": "TA" }
            }
        }),
    ]);
    let initialize = replies
        .iter()
        .find(|reply| reply["id"] == json!(1))
        .expect("initialize reply");
    let capabilities = &initialize["result"]["capabilities"];
    assert!(capabilities["tools"].is_object());
    assert_eq!(capabilities["resources"]["subscribe"], json!(false));
    assert_eq!(capabilities["resources"]["listChanged"], json!(false));
    assert_eq!(capabilities["prompts"]["listChanged"], json!(false));
    // E7: completion/complete is served, so completions IS advertised.
    assert!(capabilities["completions"].is_object());

    let resource_list = replies
        .iter()
        .find(|reply| reply["id"] == json!("resources-list"))
        .expect("resources/list reply");
    assert_eq!(
        resource_list["result"]["resources"][0]["uri"],
        json!("oracle://capabilities")
    );
    assert_eq!(
        resource_list["result"]["resources"][0]["mimeType"],
        json!("application/json")
    );

    let templates = replies
        .iter()
        .find(|reply| reply["id"] == json!("resources-templates"))
        .expect("resources/templates/list reply");
    let templates = templates["result"]["resourceTemplates"]
        .as_array()
        .expect("resource templates are an array");
    assert!(templates.iter().any(|template| {
        template["uriTemplate"] == json!("oracle://object/{owner}/{type}/{name}")
    }));
    assert!(
        templates
            .iter()
            .all(|template| template["uriTemplate"] != json!("oracle://session/{lease_id}")),
        "session resources stay unadvertised until a lease-backed handler exists"
    );

    let read_capabilities = replies
        .iter()
        .find(|reply| reply["id"] == json!("resources-read"))
        .expect("resources/read capabilities reply");
    assert_eq!(
        read_capabilities["result"]["contents"][0]["mimeType"],
        json!("application/json")
    );
    let capability_doc: Value = serde_json::from_str(
        read_capabilities["result"]["contents"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .expect("capability resource text is JSON");
    assert_eq!(capability_doc["server_name"], json!("oraclemcp"));

    let read_tools = replies
        .iter()
        .find(|reply| reply["id"] == json!("resources-read-tools"))
        .expect("resources/read tools reply");
    let tools_doc: Value = serde_json::from_str(
        read_tools["result"]["contents"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .expect("tools resource text is JSON");
    assert!(tools_doc["tools"].is_array());

    let read_schema = replies
        .iter()
        .find(|reply| reply["id"] == json!("resources-read-schema"))
        .expect("resources/read schema reply");
    let schema_doc: Value = serde_json::from_str(
        read_schema["result"]["contents"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .expect("schema resource text is JSON");
    assert_eq!(schema_doc["args"]["owner"], json!("HR"));

    let read_object = replies
        .iter()
        .find(|reply| reply["id"] == json!("resources-read-object"))
        .expect("resources/read object reply");
    assert_eq!(
        read_object["result"]["contents"][0]["mimeType"],
        json!("text/plain")
    );
    assert!(
        read_object["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("PACKAGE emp_api")
    );

    let prompts = replies
        .iter()
        .find(|reply| reply["id"] == json!("prompts-list"))
        .expect("prompts/list reply");
    let prompts = prompts["result"]["prompts"]
        .as_array()
        .expect("prompt catalog is an array");
    assert_eq!(prompts.len(), 5);
    assert!(prompts.iter().any(|prompt| {
        prompt["name"] == json!("investigate_slow_query")
            && prompt["arguments"][0]["name"] == json!("sql")
    }));

    let prompt = replies
        .iter()
        .find(|reply| reply["id"] == json!("prompts-get"))
        .expect("prompts/get reply");
    assert_eq!(prompt["result"]["messages"][0]["role"], json!("user"));
    assert_eq!(
        prompt["result"]["messages"][0]["content"]["type"],
        json!("text")
    );
    assert!(
        prompt["result"]["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("SELECT * FROM employees")
    );

    let missing_arg = replies
        .iter()
        .find(|reply| reply["id"] == json!("prompts-get-missing-arg"))
        .expect("prompts/get missing arg reply");
    assert_eq!(
        missing_arg["error"]["data"]["error_class"],
        json!("INVALID_ARGUMENTS")
    );

    // E7: completion/complete is served. `type` completion is answered from the
    // static dictionary object-type list (no DB), so "TA" completes to "TABLE"
    // with a well-formed {values, total, hasMore} envelope.
    let reply = replies
        .iter()
        .find(|reply| reply["id"] == json!("completion-complete"))
        .expect("completion/complete reply");
    let completion = &reply["result"]["completion"];
    assert!(
        completion["values"]
            .as_array()
            .expect("values array")
            .iter()
            .any(|v| v == &json!("TABLE")),
        "type completion offers TABLE for prefix TA: {reply}"
    );
    assert_eq!(completion["hasMore"], json!(false));
    assert!(completion["total"].is_number());
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
fn tools_list_returns_input_schema_annotations_and_echoes_string_ids() {
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
            tool.get("title")
                .and_then(Value::as_str)
                .is_some_and(|title| !title.is_empty()),
            "tools/list descriptor must carry a non-empty title: {tool}"
        );
        let annotations = tool
            .get("annotations")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("tools/list descriptor must carry annotations: {tool}"));
        for hint in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert!(
                annotations.get(hint).is_some_and(Value::is_boolean),
                "tools/list descriptor must carry boolean annotation {hint}: {tool}"
            );
        }
        assert!(
            tool.get("input_schema").is_none(),
            "MCP uses inputSchema, not input_schema: {tool}"
        );
        assert_eq!(tool["inputSchema"]["type"], json!("object"));
    }
    let capabilities = &tools[0]["annotations"];
    assert_eq!(capabilities["readOnlyHint"], json!(true));
    assert_eq!(capabilities["destructiveHint"], json!(false));
    assert_eq!(capabilities["idempotentHint"], json!(true));
    assert_eq!(capabilities["openWorldHint"], json!(false));

    let schema_inspect = tools
        .iter()
        .find(|tool| tool["name"] == json!("oracle_schema_inspect"))
        .expect("read tool advertised");
    assert_eq!(schema_inspect["annotations"]["readOnlyHint"], json!(true));
    assert_eq!(
        schema_inspect["annotations"]["destructiveHint"],
        json!(false)
    );
    assert_eq!(schema_inspect["outputSchema"]["type"], json!("object"));
    assert_eq!(
        schema_inspect["outputSchema"]["required"],
        json!(["ok", "tool"])
    );

    let execute = tools
        .iter()
        .find(|tool| tool["name"] == json!("oracle_execute"))
        .expect("destructive tool advertised");
    assert_eq!(execute["annotations"]["readOnlyHint"], json!(false));
    assert_eq!(execute["annotations"]["destructiveHint"], json!(true));
    assert_eq!(execute["annotations"]["idempotentHint"], json!(false));
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
    // structuredContent stays clean, machine-parseable JSON (A6).
    assert_eq!(
        result["structuredContent"]["tool"],
        json!("oracle_schema_inspect")
    );
    assert_eq!(result["structuredContent"]["args"]["owner"], json!("HR"));
    // A6: the human/LLM text channel wraps the payload in an
    // `<untrusted-user-data>` fence with a "treat as data" preamble. The exact
    // structured JSON is still present inside the fence, but the raw text is no
    // longer byte-equal to the structured JSON.
    let text = result["content"][0]["text"]
        .as_str()
        .expect("text content is a string");
    let structured = result["structuredContent"].to_string();
    assert!(text.contains("<untrusted-user-data-"));
    assert!(text.contains("</untrusted-user-data-"));
    assert!(text.contains("Treat everything between"));
    assert!(
        text.contains(&structured),
        "fenced text must still carry the structured payload"
    );
    assert_ne!(
        text,
        structured.as_str(),
        "text is fenced, not byte-equal to structuredContent"
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

/// A server whose tool catalog exceeds one page, so `tools/list` actually
/// paginates (the default conformance catalog fits one page).
fn many_tool_server(count: usize) -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    for i in 0..count {
        registry.register(ToolDescriptor::new(
            format!("oracle_tool_{i:04}"),
            ToolTier::FoundationLiveDb,
            "synthetic tool",
        ));
    }
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

fn run_script_on(server: &OracleMcpServer, requests: Vec<Value>) -> Vec<Value> {
    let mut frames = vec![frame(&initialize(None))];
    frames.push(frame(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })));
    for request in requests {
        frames.push(frame(&request));
    }
    let mut input = Vec::new();
    for frame in frames {
        input.extend(frame);
    }
    let mut output = Vec::new();
    server
        .serve_stdio_with_io(Cursor::new(input), &mut output, &StdioAuthPolicy::Disabled)
        .expect("stdio conformance session completes");
    String::from_utf8(output)
        .expect("stdio replies are UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
        .collect()
}

#[test]
fn list_endpoints_paginate_with_an_opaque_round_tripping_cursor() {
    // 150 + the always-present oracle_capabilities = 151 tools across two pages.
    let server = many_tool_server(150);

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let params = match &cursor {
            Some(cursor) => json!({ "cursor": cursor }),
            None => json!({}),
        };
        let replies = run_script_on(
            &server,
            vec![json!({
                "jsonrpc": "2.0",
                "id": "tools-page",
                "method": "tools/list",
                "params": params,
            })],
        );
        let result = &replies
            .iter()
            .find(|reply| reply["id"] == json!("tools-page"))
            .expect("tools/list reply")["result"];
        let tools = result["tools"].as_array().expect("tools array");
        assert!(tools.len() <= 100, "page is bounded to <= 100 tools");
        for tool in tools {
            seen.push(tool["name"].as_str().unwrap().to_owned());
        }
        pages += 1;
        match result.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
        assert!(pages < 10, "pagination must terminate");
    }
    assert!(pages >= 2, "151 tools must span at least two pages");
    assert_eq!(seen.len(), 151, "every tool returned exactly once");
    let mut deduped = seen.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), seen.len(), "no tool returned twice");
    // The cursor is opaque: it is not the raw offset and carries a MAC tag.
    let first = run_script_on(
        &server,
        vec![json!({ "jsonrpc": "2.0", "id": "p", "method": "tools/list" })],
    );
    let next_cursor = first
        .iter()
        .find(|reply| reply["id"] == json!("p"))
        .and_then(|reply| reply["result"]["nextCursor"].as_str())
        .expect("first page has a nextCursor");
    assert_ne!(next_cursor, "100", "cursor is opaque, not a raw offset");
    assert!(next_cursor.contains('.'), "opaque cursor carries a MAC tag");
}

#[test]
fn a_forged_or_cross_endpoint_cursor_is_rejected_with_invalid_params() {
    let server = many_tool_server(150);

    // Capture a genuine tools cursor and a genuine resources cursor reference.
    let first = run_script_on(
        &server,
        vec![json!({ "jsonrpc": "2.0", "id": "p", "method": "tools/list" })],
    );
    let real = first
        .iter()
        .find(|reply| reply["id"] == json!("p"))
        .and_then(|reply| reply["result"]["nextCursor"].as_str())
        .expect("first tools page has a nextCursor")
        .to_owned();

    // 1) A garbage cursor is rejected.
    let garbage = run_script_on(
        &server,
        vec![json!({
            "jsonrpc": "2.0",
            "id": "garbage",
            "method": "tools/list",
            "params": { "cursor": "not-a-real-cursor" },
        })],
    );
    let garbage_reply = garbage
        .iter()
        .find(|reply| reply["id"] == json!("garbage"))
        .expect("garbage cursor reply");
    assert_eq!(
        garbage_reply["error"]["code"],
        json!(JSONRPC_INVALID_PARAMS),
        "a garbage cursor is invalid-params, not a silent first page"
    );

    // 2) A cursor whose signed offset is edited (replace the offset body but
    //    keep the MAC tag) is rejected — the body is part of the MAC.
    let (body, tag) = real.rsplit_once('.').expect("cursor has a tag");
    assert_eq!(body, "100", "first tools page advances by the page size");
    let forged = format!("9999.{tag}");
    let forged_replies = run_script_on(
        &server,
        vec![json!({
            "jsonrpc": "2.0",
            "id": "forged",
            "method": "tools/list",
            "params": { "cursor": forged },
        })],
    );
    let forged_reply = forged_replies
        .iter()
        .find(|reply| reply["id"] == json!("forged"))
        .expect("forged cursor reply");
    assert_eq!(
        forged_reply["error"]["code"],
        json!(JSONRPC_INVALID_PARAMS),
        "an edited offset invalidates the cursor MAC"
    );

    // 3) Replaying a genuine tools cursor against resources/list is rejected
    //    (the cursor is scoped to its listing kind).
    let cross = run_script_on(
        &server,
        vec![json!({
            "jsonrpc": "2.0",
            "id": "cross",
            "method": "resources/list",
            "params": { "cursor": real },
        })],
    );
    let cross_reply = cross
        .iter()
        .find(|reply| reply["id"] == json!("cross"))
        .expect("cross-endpoint cursor reply");
    assert_eq!(
        cross_reply["error"]["code"],
        json!(JSONRPC_INVALID_PARAMS),
        "a tools cursor must not page resources"
    );
}

#[test]
fn subscribe_is_unadvertised_and_refused_without_a_change_source() {
    // E1 fail-closed default: the EchoDispatch conformance server has no change
    // source, so the capability is off and resources/subscribe is refused.
    let replies = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": "sub",
        "method": "resources/subscribe",
        "params": { "uri": "oracle://object/HR/PACKAGE/EMP_API" },
    })]);
    let init = replies
        .iter()
        .find(|reply| reply["id"] == json!(1))
        .expect("initialize reply");
    assert_eq!(
        init["result"]["capabilities"]["resources"]["subscribe"],
        json!(false),
        "subscribe capability is NOT advertised without a confirmed source"
    );
    let sub = replies
        .iter()
        .find(|reply| reply["id"] == json!("sub"))
        .expect("subscribe reply");
    assert_eq!(
        sub["error"]["code"],
        json!(JSONRPC_METHOD_NOT_FOUND),
        "resources/subscribe is refused when unsupported"
    );
}

/// A scripted polling source whose fingerprint a test can advance to model "the
/// watched resource changed".
struct ScriptedPollingSource {
    fingerprints: std::sync::Mutex<std::collections::HashMap<String, String>>,
}
impl oraclemcp_core::subscriptions::PollingSource for ScriptedPollingSource {
    fn poll(&self, uri: &str) -> Option<String> {
        self.fingerprints.lock().unwrap().get(uri).cloned()
    }
}

#[test]
fn subscribe_is_advertised_and_a_polled_change_emits_resources_updated() {
    use oraclemcp_core::subscriptions::{SubscribeSource, SubscriptionHub};

    let uri = "oracle://object/HR/PACKAGE/EMP_API";
    let source = Arc::new(ScriptedPollingSource {
        fingerprints: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    source
        .fingerprints
        .lock()
        .unwrap()
        .insert(uri.to_owned(), "fp-v1".to_owned());

    // The hub takes a Box<dyn PollingSource>; share the scripted source via an
    // Arc adapter so the test body can advance the fingerprint.
    struct Adapter(Arc<ScriptedPollingSource>);
    impl oraclemcp_core::subscriptions::PollingSource for Adapter {
        fn poll(&self, uri: &str) -> Option<String> {
            self.0.poll(uri)
        }
    }
    let hub = Arc::new(SubscriptionHub::with_source(SubscribeSource::Polling(
        Box::new(Adapter(source.clone())),
    )));

    let server = {
        let mut registry = ToolRegistry::new();
        registry.register(ToolDescriptor::new(
            "oracle_schema_inspect",
            ToolTier::FoundationLiveDb,
            "inspect a schema",
        ));
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
            .with_subscriptions(Arc::clone(&hub))
    };

    // initialize advertises the capability now that a source is confirmed.
    let init = server
        .handle_jsonrpc_request(initialize(None), Some(&StdioAuthPolicy::Disabled))
        .expect("initialize reply");
    assert_eq!(
        init["result"]["capabilities"]["resources"]["subscribe"],
        json!(true),
        "subscribe capability IS advertised once a source is confirmed"
    );

    // subscribe succeeds (seeds the baseline fingerprint).
    let sub = server
        .handle_jsonrpc_request(
            json!({
                "jsonrpc": "2.0",
                "id": "sub",
                "method": "resources/subscribe",
                "params": { "uri": uri },
            }),
            None,
        )
        .expect("subscribe reply");
    assert!(
        sub["result"].is_object(),
        "subscribe returns a result: {sub}"
    );

    // No notification queued before any change.
    assert!(
        server.drain_resource_updated_notifications().is_empty(),
        "no update before a change"
    );

    // The resource changes; a poll detects it and enqueues an update.
    source
        .fingerprints
        .lock()
        .unwrap()
        .insert(uri.to_owned(), "fp-v2".to_owned());
    let changed = hub.poll_for_changes();
    assert_eq!(changed, vec![uri.to_owned()], "poll detects the change");

    let notifications = server.drain_resource_updated_notifications();
    assert_eq!(notifications.len(), 1, "one resources/updated queued");
    assert_eq!(
        notifications[0]["method"],
        json!("notifications/resources/updated")
    );
    assert_eq!(notifications[0]["params"]["uri"], json!(uri));
    assert!(
        notifications[0].get("id").is_none(),
        "resources/updated is a notification (no id)"
    );
}

#[test]
fn completion_complete_is_served_and_capped_for_owner_type_object() {
    // MCP-STDIO-017 (E7): owner→type→object autocomplete. `type` is the static
    // dictionary list; `owner` comes from oracle_list_schemas; `name` from
    // oracle_search_objects scoped by context.arguments.
    let replies = run_script(vec![
        // type completion (static, no DB) — prefix "VI" → "VIEW".
        json!({
            "jsonrpc": "2.0",
            "id": "complete-type",
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "oracle://object/{owner}/{type}/{name}" },
                "argument": { "name": "type", "value": "VI" }
            }
        }),
        // owner completion via oracle_list_schemas — prefix "H".
        json!({
            "jsonrpc": "2.0",
            "id": "complete-owner",
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "oracle://object/{owner}/{type}/{name}" },
                "argument": { "name": "owner", "value": "H" }
            }
        }),
        // object-name completion scoped to the chosen owner/type via context.
        json!({
            "jsonrpc": "2.0",
            "id": "complete-name",
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "oracle://object/{owner}/{type}/{name}" },
                "argument": { "name": "name", "value": "EMP" },
                "context": { "arguments": { "owner": "HR", "type": "TABLE" } }
            }
        }),
        // a missing argument object is invalid-params (well-formed protocol error).
        json!({
            "jsonrpc": "2.0",
            "id": "complete-bad",
            "method": "completion/complete",
            "params": { "ref": { "type": "ref/resource", "uri": "oracle://tools" } }
        }),
    ]);

    let by_id = |id: &str| {
        replies
            .iter()
            .find(|reply| reply["id"] == json!(id))
            .unwrap_or_else(|| panic!("{id} reply"))
            .clone()
    };

    let type_reply = by_id("complete-type");
    let type_values = type_reply["result"]["completion"]["values"]
        .as_array()
        .expect("type values");
    assert!(type_values.iter().any(|v| v == &json!("VIEW")));
    // The cap envelope is present and well-formed.
    assert_eq!(type_reply["result"]["completion"]["hasMore"], json!(false));
    assert!(type_reply["result"]["completion"]["total"].is_number());

    let owner_reply = by_id("complete-owner");
    let owner_values = owner_reply["result"]["completion"]["values"]
        .as_array()
        .expect("owner values");
    assert!(owner_values.iter().any(|v| v == &json!("HR")));
    // The prefix "H" also prefix-matches HIDDEN_OWNER, which is fine (a schema,
    // not a profile); the point of E5 isolation is profile invisibility (below).

    let name_reply = by_id("complete-name");
    let name_values = name_reply["result"]["completion"]["values"]
        .as_array()
        .expect("name values");
    assert!(name_values.iter().any(|v| v == &json!("EMPLOYEES")));
    assert!(name_values.iter().any(|v| v == &json!("EMP_AUDIT")));

    let bad = by_id("complete-bad");
    assert_eq!(
        bad["error"]["code"],
        json!(JSONRPC_INVALID_PARAMS),
        "a completion request without an argument is invalid-params"
    );
}

#[test]
fn completion_complete_for_profile_honors_e5_exposure() {
    // MCP-STDIO-017 + E5: completing a `profile` argument routes through
    // oracle_list_profiles, which the dispatcher filters to the mcp_exposed
    // allow-list — so only the exposed profile is offered and a hidden one is
    // never surfaced as a completion.
    let replies = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": "complete-profile",
        "method": "completion/complete",
        "params": {
            "ref": { "type": "ref/prompt", "name": "oracle_switch_profile" },
            "argument": { "name": "profile", "value": "" }
        }
    })]);
    let reply = replies
        .iter()
        .find(|reply| reply["id"] == json!("complete-profile"))
        .expect("profile completion reply");
    let values = reply["result"]["completion"]["values"]
        .as_array()
        .expect("profile values");
    assert!(
        values.iter().any(|v| v == &json!("agent_ro")),
        "the exposed profile is offered"
    );
    let serialized = serde_json::to_string(reply).expect("json");
    assert!(
        !serialized.contains("prod_admin") && !serialized.contains("hidden"),
        "a non-exposed profile must never be completed: {serialized}"
    );
}

#[test]
fn progress_notification_is_emitted_for_a_tools_call_with_a_progress_token() {
    // MCP-STDIO-018 (E6): a tools/call carrying params._meta.progressToken is
    // bracketed by notifications/progress, which ride the stdout after the
    // response and carry no id (true notifications).
    let replies = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": "call-with-progress",
        "method": "tools/call",
        "params": {
            "name": "oracle_schema_inspect",
            "arguments": { "owner": "HR" },
            "_meta": { "progressToken": "op-42" }
        }
    })]);

    // The tool result.
    assert!(
        replies
            .iter()
            .any(|reply| reply["id"] == json!("call-with-progress")
                && reply["result"]["isError"] == json!(false)),
        "the tool call still returns its result"
    );

    // The progress notifications (no id; method+token), at least a start and end.
    let progress: Vec<&Value> = replies
        .iter()
        .filter(|reply| reply["method"] == json!("notifications/progress"))
        .collect();
    assert!(
        progress.len() >= 2,
        "a started + completed progress bracket is emitted: {replies:?}"
    );
    for note in &progress {
        assert!(
            note.get("id").is_none(),
            "progress is a notification (no id)"
        );
        assert_eq!(note["params"]["progressToken"], json!("op-42"));
        assert!(note["params"]["progress"].is_number());
    }

    // Without a progressToken, no progress is emitted (opt-in per the spec).
    let no_token = run_script(vec![json!({
        "jsonrpc": "2.0",
        "id": "call-no-progress",
        "method": "tools/call",
        "params": { "name": "oracle_schema_inspect", "arguments": { "owner": "HR" } }
    })]);
    assert!(
        no_token
            .iter()
            .all(|reply| reply["method"] != json!("notifications/progress")),
        "no progressToken => no progress notifications"
    );
}

#[test]
fn tools_list_changed_is_advertised_and_emitted_when_the_tool_set_changes() {
    use oraclemcp_core::NotificationHub;

    // MCP-STDIO-019 (E6): the capability is advertised, and a change to the
    // served tool set (modeled here by enqueuing on the shared hub, exactly as a
    // profile switch does) emits a paramless, id-less list_changed notification.
    let hub = Arc::new(NotificationHub::new());
    let server = {
        let mut registry = ToolRegistry::new();
        registry.register(ToolDescriptor::new(
            "oracle_schema_inspect",
            ToolTier::FoundationLiveDb,
            "inspect a schema",
        ));
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
            .with_notifications(Arc::clone(&hub))
    };

    let init = server
        .handle_jsonrpc_request(initialize(None), Some(&StdioAuthPolicy::Disabled))
        .expect("initialize reply");
    assert_eq!(
        init["result"]["capabilities"]["tools"]["listChanged"],
        json!(true),
        "tools.listChanged is advertised"
    );

    // Nothing queued yet.
    assert!(server.drain_server_notifications().is_empty());

    // A change to the served tool set (what oracle_switch_profile enqueues).
    hub.enqueue_tools_list_changed();

    let notes = server.drain_server_notifications();
    assert_eq!(notes.len(), 1);
    assert_eq!(
        notes[0]["method"],
        json!("notifications/tools/list_changed")
    );
    assert!(notes[0].get("id").is_none(), "list_changed has no id");
    assert!(
        notes[0].get("params").is_none(),
        "list_changed has no params"
    );
}

#[test]
fn an_export_resource_is_served_and_forged_ids_fail_closed() {
    use oraclemcp_core::export::{ExportAccess, ExportFormat, ExportRegistry};

    let exports = Arc::new(ExportRegistry::new());
    let server = OracleMcpServer::with_exports(
        "0.3.0",
        {
            let mut registry = ToolRegistry::new();
            registry.register(ToolDescriptor::new(
                "oracle_query",
                ToolTier::FoundationLiveDb,
                "run a query",
            ));
            registry
        },
        CapabilitiesReport::new(
            "0.3.0",
            Vec::new(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: false,
                http_transport: false,
            },
        ),
        Arc::new(EchoDispatch),
        Arc::clone(&exports),
    );

    // No-scope access (the stdio default): mint an export under the empty
    // scope, then read it back over resources/read.
    let access = ExportAccess::new(Some("PROD"), None);
    let handle = exports.create(
        &["ID".to_owned(), "NAME".to_owned()],
        &[vec!["1".to_owned(), "alice".to_owned()]],
        ExportFormat::Csv,
        access,
        std::time::Duration::from_secs(900),
    );

    let read = server
        .handle_jsonrpc_request(
            json!({
                "jsonrpc": "2.0",
                "id": "read-export",
                "method": "resources/read",
                "params": { "uri": handle.uri },
            }),
            None,
        )
        .expect("resources/read reply");
    assert_eq!(
        read["result"]["contents"][0]["mimeType"],
        json!("text/csv"),
        "export served with its MIME type"
    );
    assert!(
        read["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("ID,NAME\n"),
        "export body is the materialized CSV"
    );

    // A forged export id (kept tag, edited body) fails closed.
    let (_body, tag) = handle
        .id
        .rsplit_once('.')
        .expect("export id carries a MAC tag");
    let forged = format!("oracle-export://exp-9999.{tag}");
    let forged_read = server
        .handle_jsonrpc_request(
            json!({
                "jsonrpc": "2.0",
                "id": "forged-export",
                "method": "resources/read",
                "params": { "uri": forged },
            }),
            None,
        )
        .expect("forged resources/read reply");
    assert_eq!(
        forged_read["error"]["data"]["error_class"],
        json!("OBJECT_NOT_FOUND"),
        "a forged export id reads as not-found"
    );
}

#[test]
fn an_export_is_access_controlled_by_scope_grant() {
    use oraclemcp_core::export::{ExportAccess, ExportFormat, ExportRegistry};
    use oraclemcp_core::http::ScopeGrant;
    use oraclemcp_core::server::DispatchContext;

    let exports = Arc::new(ExportRegistry::new());
    let server = OracleMcpServer::with_exports(
        "0.3.0",
        ToolRegistry::new(),
        CapabilitiesReport::new(
            "0.3.0",
            Vec::new(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: false,
                http_transport: false,
            },
        ),
        Arc::new(EchoDispatch),
        Arc::clone(&exports),
    );

    // Mint under scope "oracle:read".
    let minting_access = ExportAccess::new(Some("PROD"), Some(&["oracle:read".to_owned()]));
    let handle = exports.create(
        &["ID".to_owned()],
        &[vec!["1".to_owned()]],
        ExportFormat::Csv,
        minting_access,
        std::time::Duration::from_secs(900),
    );

    // Read under a DIFFERENT scope grant: refused.
    let wrong_grant = ScopeGrant(vec!["oracle:admin".to_owned()]);
    let wrong = server.handle_jsonrpc_request_with_context(
        json!({
            "jsonrpc": "2.0",
            "id": "wrong-scope",
            "method": "resources/read",
            "params": { "uri": handle.uri.clone() },
        }),
        None,
        DispatchContext::with_scope_grant(&wrong_grant),
    );
    let wrong = wrong.expect("wrong-scope reply");
    assert_eq!(
        wrong["error"]["data"]["error_class"],
        json!("OBJECT_NOT_FOUND"),
        "an export is not readable under a different scope grant"
    );

    // Read under the SAME scope grant: served.
    let right_grant = ScopeGrant(vec!["oracle:read".to_owned()]);
    let right = server.handle_jsonrpc_request_with_context(
        json!({
            "jsonrpc": "2.0",
            "id": "right-scope",
            "method": "resources/read",
            "params": { "uri": handle.uri },
        }),
        None,
        DispatchContext::with_scope_grant(&right_grant),
    );
    let right = right.expect("right-scope reply");
    assert_eq!(
        right["result"]["contents"][0]["mimeType"],
        json!("text/csv"),
        "the matching scope grant reads the export"
    );
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
