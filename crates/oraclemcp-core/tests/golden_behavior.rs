//! Golden behavior harness for the current rmcp + axum transport surface.
//!
//! These tests intentionally compare observable protocol responses against
//! reviewed fixtures under `tests/golden/`. The fixtures are synthetic and
//! contain no real credentials or business data.

use std::sync::Arc;
use std::time::Duration;

use asupersync::Cx;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, Method, Request, StatusCode, header};
use oraclemcp_auth::ResourceServerConfig;
use oraclemcp_core::OracleMcpServer;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{
    HttpTransportConfig, MCP_PATH, OAuthEnforcement, PROTECTED_RESOURCE_METADATA_PATH, build_router,
};
use oraclemcp_core::server::{DispatchFuture, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};
use tower::ServiceExt;

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

fn json_post(path: &str, body: &Value) -> Request<Body> {
    request(
        Method::POST,
        path,
        default_post_headers(),
        Body::from(body.to_string()),
    )
}

fn request(
    method: Method,
    path: &str,
    headers: Vec<(&'static str, String)>,
    body: Body,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(body).expect("request builds")
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

async fn capture_response(response: axum::response::Response) -> Value {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let headers = selected_headers(response.headers());
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        axum::body::to_bytes(response.into_body(), 512 * 1024),
    )
    .await
    .expect("response body completes")
    .expect("response body reads");
    json!({
        "status": status.as_u16(),
        "headers": headers,
        "body": golden_support::body_value(content_type.as_deref(), &bytes),
    })
}

fn selected_headers(headers: &HeaderMap) -> Value {
    let names = [
        header::CONTENT_TYPE,
        header::CACHE_CONTROL,
        header::WWW_AUTHENTICATE,
        header::ALLOW,
        HeaderName::from_static("mcp-session-id"),
    ];
    let mut out = serde_json::Map::new();
    for name in names {
        if let Some(value) = headers.get(&name) {
            out.insert(
                name.as_str().to_ascii_lowercase(),
                Value::String(value.to_str().unwrap_or("<non-utf8>").to_owned()),
            );
        }
    }
    Value::Object(out)
}

fn session_id(headers: &HeaderMap) -> String {
    headers
        .get(HeaderName::from_static("mcp-session-id"))
        .and_then(|value| value.to_str().ok())
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

#[tokio::test]
async fn golden_http_stateless_initialize_json_response() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let router = build_router(harness_server(), &cfg);
    let body = initialize_body(1, "golden-http-json");

    let response = router.oneshot(json_post(MCP_PATH, &body)).await.unwrap();
    let actual = json!({
        "case": "stateless /mcp initialize returns direct JSON",
        "request": {
            "method": "POST",
            "path": MCP_PATH,
            "headers": default_post_headers(),
            "body": body,
        },
        "response": capture_response(response).await,
    });
    golden_support::assert_golden("http/stateless_initialize_json_response", &actual);
}

#[tokio::test]
async fn golden_http_protected_resource_metadata() {
    let metadata = json!({
        "resource": "https://oraclemcp.example/mcp",
        "authorization_servers": ["https://idp.example"],
        "scopes_supported": ["oracle:read"],
    });
    let cfg = HttpTransportConfig {
        resource_metadata: Some(metadata.clone()),
        ..Default::default()
    };
    let router = build_router(harness_server(), &cfg);
    let req = request(
        Method::GET,
        PROTECTED_RESOURCE_METADATA_PATH,
        vec![("host", "127.0.0.1".to_owned())],
        Body::empty(),
    );

    let response = router.oneshot(req).await.unwrap();
    let actual = json!({
        "case": "RFC 9728 protected-resource metadata stays publicly discoverable",
        "request": {
            "method": "GET",
            "path": PROTECTED_RESOURCE_METADATA_PATH,
            "headers": [["host", "127.0.0.1"]],
            "body": "",
        },
        "configured_metadata": metadata,
        "response": capture_response(response).await,
    });
    golden_support::assert_golden("http/protected_resource_metadata", &actual);
}

#[tokio::test]
async fn golden_http_unauthorized_www_authenticate() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let router = build_router(harness_server(), &cfg);
    let body = initialize_body(1, "golden-http-unauthorized");

    let response = router.oneshot(json_post(MCP_PATH, &body)).await.unwrap();
    let actual = json!({
        "case": "OAuth-protected /mcp refuses missing bearer with WWW-Authenticate",
        "request": {
            "method": "POST",
            "path": MCP_PATH,
            "headers": default_post_headers(),
            "body": body,
        },
        "response": capture_response(response).await,
    });
    golden_support::assert_golden("http/unauthorized_www_authenticate", &actual);
}

#[tokio::test]
async fn golden_http_host_and_origin_guards() {
    let init = initialize_body(1, "golden-http-guard");
    let host_response = build_router(harness_server(), &HttpTransportConfig::default())
        .oneshot(request(
            Method::POST,
            MCP_PATH,
            vec![
                ("host", "attacker.example".to_owned()),
                ("content-type", "application/json".to_owned()),
                ("accept", "application/json, text/event-stream".to_owned()),
            ],
            Body::from(init.to_string()),
        ))
        .await
        .unwrap();

    let origin_cfg = HttpTransportConfig {
        allowed_origins: vec!["https://app.example".to_owned()],
        ..Default::default()
    };
    let origin_response = build_router(harness_server(), &origin_cfg)
        .oneshot(request(
            Method::POST,
            MCP_PATH,
            headers_with(&[("origin", "https://evil.example")]),
            Body::from(init.to_string()),
        ))
        .await
        .unwrap();

    let actual = json!({
        "case": "rmcp DNS-rebinding Host guard and browser Origin allowlist",
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
                "response": capture_response(host_response).await,
            },
            {
                "name": "forbidden origin",
                "method": "POST",
                "path": MCP_PATH,
                "headers": headers_with(&[("origin", "https://evil.example")]),
                "body": init,
                "response": capture_response(origin_response).await,
            }
        ]
    });
    golden_support::assert_golden("http/host_origin_guards", &actual);
}

#[tokio::test]
async fn golden_http_stateful_streamable_session() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        ..Default::default()
    };
    let router = build_router(harness_server(), &cfg);

    let init = initialize_body(1, "golden-http-stateful");
    let init_response = router
        .clone()
        .oneshot(json_post(MCP_PATH, &init))
        .await
        .unwrap();
    assert_eq!(init_response.status(), StatusCode::OK);
    let session_id = session_id(init_response.headers());
    let init_exchange = capture_response(init_response).await;

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let initialized_headers = headers_with(&[
        ("mcp-session-id", &session_id),
        ("mcp-protocol-version", "2025-11-25"),
    ]);
    let initialized_response = router
        .clone()
        .oneshot(request(
            Method::POST,
            MCP_PATH,
            initialized_headers.clone(),
            Body::from(initialized.to_string()),
        ))
        .await
        .unwrap();
    let initialized_exchange = capture_response(initialized_response).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    });
    let list_headers = headers_with(&[
        ("mcp-session-id", &session_id),
        ("mcp-protocol-version", "2025-11-25"),
    ]);
    let list_response = router
        .clone()
        .oneshot(request(
            Method::POST,
            MCP_PATH,
            list_headers.clone(),
            Body::from(list.to_string()),
        ))
        .await
        .unwrap();
    let list_exchange = capture_response(list_response).await;
    assert!(
        list_exchange["body"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["data"]["id"] == json!(2))),
        "stateful tools/list SSE response must include the JSON-RPC response event: {list_exchange}"
    );

    let delete_response = router
        .oneshot(request(
            Method::DELETE,
            MCP_PATH,
            vec![
                ("host", "127.0.0.1".to_owned()),
                ("mcp-session-id", session_id),
                ("mcp-protocol-version", "2025-11-25".to_owned()),
            ],
            Body::empty(),
        ))
        .await
        .unwrap();

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
                "response": capture_response(delete_response).await,
            }
        ]
    });
    golden_support::assert_golden("http/stateful_streamable_session", &actual);
}
