//! Golden behavior harness for the native HTTP and stdio transport surface.
//!
//! These tests intentionally compare observable protocol responses against
//! reviewed fixtures under `tests/golden/`. The fixtures are synthetic and
//! contain no real credentials or business data.

use std::sync::Arc;

use asupersync::Cx;
use oraclemcp_auth::ResourceServerConfig;
use oraclemcp_core::OracleMcpServer;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{
    HttpRequest, HttpResponse, HttpTransportConfig, MCP_PATH, OAuthEnforcement,
    PROTECTED_RESOURCE_METADATA_PATH, handle_http_request,
};
use oraclemcp_core::server::{DispatchFuture, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

struct EchoDispatch;
impl ToolDispatch for EchoDispatch {
    fn dispatch<'a>(&'a self, _cx: &'a Cx, name: &'a str, args: Value) -> DispatchFuture<'a> {
        Box::pin(async move { Ok(json!({ "tool": name, "args": args, "ok": true })) })
    }
}

fn harness_server() -> OracleMcpServer {
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
                "owner": { "type": "string" },
                "name_like": { "type": "string" }
            },
            "required": [],
            "additionalProperties": false
        })),
    );
    let report = CapabilitiesReport::new(
        "0.2.1",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: false,
            http_transport: true,
        },
    );
    OracleMcpServer::new("0.2.1", registry, report, Arc::new(EchoDispatch))
}

fn initialize_body(id: i64, client: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": client, "version": "1.0" }
        }
    })
}

fn json_post(path: &str, body: &Value) -> HttpRequest {
    request(
        "POST",
        path,
        default_post_headers(),
        body.to_string().into_bytes(),
    )
}

fn request(
    method: &str,
    path: &str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
) -> HttpRequest {
    HttpRequest::new(method, path, headers, body)
}

fn default_post_headers() -> Vec<(&'static str, String)> {
    vec![
        ("host", "127.0.0.1".to_owned()),
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
    ]
}

fn headers_with(extra: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    let mut headers = default_post_headers();
    headers.extend(
        extra
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    headers
}

fn capture_response(response: HttpResponse) -> Value {
    let content_type = response.header("content-type").map(str::to_owned);
    let headers = selected_headers(&response.headers);
    json!({
        "status": response.status,
        "headers": headers,
        "body": golden_support::body_value(content_type.as_deref(), &response.body),
    })
}

fn selected_headers(headers: &[(String, String)]) -> Value {
    let names = [
        "content-type",
        "cache-control",
        "www-authenticate",
        "allow",
        "mcp-session-id",
    ];
    let mut out = serde_json::Map::new();
    for name in names {
        if let Some((_, value)) = headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        {
            out.insert(name.to_owned(), Value::String(value.clone()));
        }
    }
    Value::Object(out)
}

fn session_id(response: &HttpResponse) -> String {
    response
        .header("mcp-session-id")
        .expect("stateful initialize returns Mcp-Session-Id")
        .to_owned()
}

fn oauth_enforcement() -> Arc<OAuthEnforcement> {
    Arc::new(OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        },
        verifier: Arc::new(oraclemcp_auth::Hs256Verifier {
            secret: b"synthetic-harness-key".to_vec(),
        }),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    })
}

#[test]
fn golden_http_stateless_initialize_json_response() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let server = harness_server();
    let body = initialize_body(1, "golden-http-json");

    let response = handle_http_request(&server, &cfg, json_post(MCP_PATH, &body));
    let actual = json!({
        "case": "stateless /mcp initialize returns direct JSON",
        "request": {
            "method": "POST",
            "path": MCP_PATH,
            "headers": default_post_headers(),
            "body": body,
        },
        "response": capture_response(response),
    });
    golden_support::assert_golden("http/stateless_initialize_json_response", &actual);
}

#[test]
fn golden_http_protected_resource_metadata() {
    let metadata = json!({
        "resource": "https://oraclemcp.example/mcp",
        "authorization_servers": ["https://idp.example"],
        "scopes_supported": ["oracle:read"],
    });
    let cfg = HttpTransportConfig {
        resource_metadata: Some(metadata.clone()),
        ..Default::default()
    };
    let req = request(
        "GET",
        PROTECTED_RESOURCE_METADATA_PATH,
        vec![("host", "127.0.0.1".to_owned())],
        Vec::new(),
    );

    let server = harness_server();
    let response = handle_http_request(&server, &cfg, req);
    let actual = json!({
        "case": "RFC 9728 protected-resource metadata stays publicly discoverable",
        "request": {
            "method": "GET",
            "path": PROTECTED_RESOURCE_METADATA_PATH,
            "headers": [["host", "127.0.0.1"]],
            "body": "",
        },
        "configured_metadata": metadata,
        "response": capture_response(response),
    });
    golden_support::assert_golden("http/protected_resource_metadata", &actual);
}

#[test]
fn golden_http_unauthorized_www_authenticate() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let server = harness_server();
    let body = initialize_body(1, "golden-http-unauthorized");

    let response = handle_http_request(&server, &cfg, json_post(MCP_PATH, &body));
    let actual = json!({
        "case": "OAuth-protected /mcp refuses missing bearer with WWW-Authenticate",
        "request": {
            "method": "POST",
            "path": MCP_PATH,
            "headers": default_post_headers(),
            "body": body,
        },
        "response": capture_response(response),
    });
    golden_support::assert_golden("http/unauthorized_www_authenticate", &actual);
}

#[test]
fn golden_http_host_and_origin_guards() {
    let init = initialize_body(1, "golden-http-guard");
    let server = harness_server();
    let host_response = handle_http_request(
        &server,
        &HttpTransportConfig::default(),
        request(
            "POST",
            MCP_PATH,
            vec![
                ("host", "attacker.example".to_owned()),
                ("content-type", "application/json".to_owned()),
                ("accept", "application/json, text/event-stream".to_owned()),
            ],
            init.to_string().into_bytes(),
        ),
    );

    let origin_cfg = HttpTransportConfig {
        allowed_origins: vec!["https://app.example".to_owned()],
        ..Default::default()
    };
    let origin_response = handle_http_request(
        &server,
        &origin_cfg,
        request(
            "POST",
            MCP_PATH,
            headers_with(&[("origin", "https://evil.example")]),
            init.to_string().into_bytes(),
        ),
    );

    let actual = json!({
        "case": "native DNS-rebinding Host guard and browser Origin allowlist",
        "requests": [
            {
                "name": "untrusted host",
                "method": "POST",
                "path": MCP_PATH,
                "headers": [
                    ["host", "attacker.example"],
                    ["content-type", "application/json"],
                    ["accept", "application/json, text/event-stream"]
                ],
                "body": init,
                "response": capture_response(host_response),
            },
            {
                "name": "forbidden origin",
                "method": "POST",
                "path": MCP_PATH,
                "headers": headers_with(&[("origin", "https://evil.example")]),
                "body": init,
                "response": capture_response(origin_response),
            }
        ]
    });
    golden_support::assert_golden("http/host_origin_guards", &actual);
}

#[test]
fn golden_http_stateful_streamable_session() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        ..Default::default()
    };
    let server = harness_server();

    let init = initialize_body(1, "golden-http-stateful");
    let init_response = handle_http_request(&server, &cfg, json_post(MCP_PATH, &init));
    assert_eq!(init_response.status, 200);
    let session_id = session_id(&init_response);
    let init_exchange = capture_response(init_response);

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let initialized_headers = headers_with(&[
        ("mcp-session-id", &session_id),
        ("mcp-protocol-version", "2025-11-25"),
    ]);
    let initialized_response = handle_http_request(
        &server,
        &cfg,
        request(
            "POST",
            MCP_PATH,
            initialized_headers.clone(),
            initialized.to_string().into_bytes(),
        ),
    );
    let initialized_exchange = capture_response(initialized_response);

    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    });
    let list_headers = headers_with(&[
        ("mcp-session-id", &session_id),
        ("mcp-protocol-version", "2025-11-25"),
    ]);
    let list_response = handle_http_request(
        &server,
        &cfg,
        request(
            "POST",
            MCP_PATH,
            list_headers.clone(),
            list.to_string().into_bytes(),
        ),
    );
    let list_exchange = capture_response(list_response);
    assert!(
        list_exchange["body"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["data"]["id"] == json!(2))),
        "stateful tools/list SSE response must include the JSON-RPC response event: {list_exchange}"
    );

    let delete_response = handle_http_request(
        &server,
        &cfg,
        request(
            "DELETE",
            MCP_PATH,
            vec![
                ("host", "127.0.0.1".to_owned()),
                ("mcp-session-id", session_id),
                ("mcp-protocol-version", "2025-11-25".to_owned()),
            ],
            Vec::new(),
        ),
    );

    let actual = json!({
        "case": "stateful Streamable HTTP session uses SSE, session header, initialized notification, and session-bound request",
        "exchanges": [
            {
                "name": "initialize",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": default_post_headers(),
                    "body": init,
                },
                "response": init_exchange,
            },
            {
                "name": "notifications/initialized",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": initialized_headers,
                    "body": initialized,
                },
                "response": initialized_exchange,
            },
            {
                "name": "tools/list",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": list_headers,
                    "body": list,
                },
                "response": list_exchange,
            },
            {
                "name": "delete session",
                "request": {
                    "method": "DELETE",
                    "path": MCP_PATH,
                    "headers": [
                        ["host", "127.0.0.1"],
                        ["mcp-session-id", "[SESSION_ID]"],
                        ["mcp-protocol-version", "2025-11-25"]
                    ],
                    "body": "",
                },
                "response": capture_response(delete_response),
            }
        ]
    });
    golden_support::assert_golden("http/stateful_streamable_session", &actual);
}
