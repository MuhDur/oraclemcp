//! The rmcp-backed MCP server (plan §2.5, §7.1, §8.1; bead P0-6).
//!
//! Replaces `plsql-mcp`'s hand-rolled JSON-RPC with the official `rmcp` SDK.
//! [`OracleMcpServer`] implements rmcp's [`ServerHandler`] over the dynamic
//! [`ToolRegistry`] + an injected [`ToolDispatch`], so engine and operator
//! tools register from the consumer side (the one-way boundary, §0). Engine
//! work stays synchronous behind `spawn_blocking` (§4.3): `call_tool` dispatches
//! on a blocking worker and never blocks the async executor.

use std::sync::Arc;

use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, Implementation, InitializeRequestParams,
    InitializeResult, ListToolsResult, Meta, PaginatedRequestParams, ProtocolVersion,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt};
use serde_json::{Map, Value};

use crate::capabilities::CapabilitiesReport;
use crate::init_token::StdioAuthPolicy;
use crate::tools::{ToolDescriptor, ToolRegistry};

/// The `_meta` field carrying the stdio init token on the `initialize` request.
/// The client places its shared token here so the server can gate the handshake
/// before any other request (§7.1). Kept namespaced to avoid colliding with
/// rmcp's reserved keys (e.g. `progressToken`).
pub const INIT_TOKEN_META_KEY: &str = "oraclemcp/initToken";

/// The zero-arg discovery tool name (§8.1).
pub const CAPABILITIES_TOOL: &str = "oracle_capabilities";

/// Synchronous tool dispatch, injected by the engine/operator side. Runs on a
/// blocking worker; returns the tool's structured JSON or an [`ErrorEnvelope`].
pub trait ToolDispatch: Send + Sync + 'static {
    /// Dispatch a tool call by name with JSON arguments.
    fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope>;
}

/// The rmcp server handler.
#[derive(Clone)]
pub struct OracleMcpServer {
    version: String,
    registry: Arc<ToolRegistry>,
    capabilities: Arc<CapabilitiesReport>,
    dispatcher: Arc<dyn ToolDispatch>,
    /// The resolved stdio init-token policy enforced on `initialize`. `None`
    /// for the HTTP path (already guarded by `oauth_guard`, §7.1); `Some` only
    /// when `serve_stdio` wires the stdio transport. Fail-closed: a `Required`
    /// policy refuses the handshake unless the client presents the token.
    auth: Option<Arc<StdioAuthPolicy>>,
}

impl OracleMcpServer {
    /// Build a server over a tool registry, capability report, and dispatcher.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        registry: ToolRegistry,
        capabilities: CapabilitiesReport,
        dispatcher: Arc<dyn ToolDispatch>,
    ) -> Self {
        OracleMcpServer {
            version: version.into(),
            registry: Arc::new(registry),
            capabilities: Arc::new(capabilities),
            dispatcher,
            auth: None,
        }
    }

    /// Attach the stdio init-token policy enforced on `initialize`. Used by
    /// [`serve_stdio`](Self::serve_stdio); exposed for tests that drive the
    /// handshake directly. The HTTP path leaves this `None` (it is guarded by
    /// `oauth_guard` instead, §7.1).
    #[must_use]
    pub fn with_stdio_auth(mut self, auth: StdioAuthPolicy) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    /// Map the registry descriptors to rmcp [`Tool`]s.
    fn rmcp_tools(&self) -> Vec<Tool> {
        let mut tools = Vec::with_capacity(self.registry.tools.len() + 1);
        // oracle_capabilities is always present even if not in the registry.
        tools.push(Tool::new(
            CAPABILITIES_TOOL,
            "Zero-arg entry point: tools, operating level + gates, connection/standby status, feature tiers, version.",
            empty_object_schema(),
        ));
        for d in &self.registry.tools {
            if d.name == CAPABILITIES_TOOL {
                continue;
            }
            tools.push(Tool::new(
                d.name.clone(),
                d.summary.clone(),
                descriptor_input_schema(d),
            ));
        }
        tools
    }

    /// Serve over stdio until the client disconnects. `auth` must already be
    /// resolved (the caller refuses to start when no token + no `--allow-no-auth`
    /// — §7.1); this records the posture, **arms the gate on the live request
    /// path** (the `initialize` override enforces it), and runs the rmcp loop.
    pub async fn serve_stdio(self, auth: &StdioAuthPolicy) -> std::io::Result<()> {
        match auth {
            StdioAuthPolicy::Required { .. } => {
                tracing::info!("stdio transport: init-token required");
            }
            StdioAuthPolicy::Disabled => {
                tracing::warn!("stdio transport: auth disabled (--allow-no-auth)");
            }
        }
        // Wire the policy onto the handler so `initialize` actually validates it
        // (without this the gate is a no-op: rmcp's default initialize accepts
        // unconditionally). See `check_init_token` / the `initialize` override.
        let server = self.with_stdio_auth(auth.clone());
        let service = server
            .serve((tokio::io::stdin(), tokio::io::stdout()))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        service
            .waiting()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }

    /// Validate the stdio init token presented in the `initialize` request's
    /// `_meta`, fail-closed. When no stdio policy is attached (the HTTP path),
    /// this is a no-op (`Ok`). When a `Required` policy is attached, a missing
    /// or mismatched token yields an `invalid_request` [`McpError`] so the
    /// handshake is refused before any tool is reachable (§7.1).
    ///
    /// Factored out of the `initialize` override so the gate is unit-testable
    /// without a live `RequestContext`.
    fn check_init_token(&self, meta: Option<&Meta>) -> Result<(), McpError> {
        let Some(policy) = self.auth.as_deref() else {
            return Ok(());
        };
        let presented = meta
            .and_then(|m| m.get(INIT_TOKEN_META_KEY))
            .and_then(Value::as_str);
        policy.validate(presented).map_err(|e| {
            tracing::warn!(error = %e, "stdio init-token rejected on initialize");
            McpError::invalid_request(e.to_string(), None)
        })
    }

    fn capabilities_result(&self) -> CallToolResult {
        let value = serde_json::to_value(&*self.capabilities).unwrap_or(Value::Null);
        tool_result_ok(value)
    }

    /// Run a tool by name + JSON args, returning a [`CallToolResult`]. Context-
    /// free so it is unit-testable without an rmcp `RequestContext`. Engine/DB
    /// dispatch runs on a blocking worker (§4.3); a join failure becomes a tool
    /// error, never a panic.
    pub async fn run_tool(&self, name: String, args: Value) -> CallToolResult {
        if name == CAPABILITIES_TOOL {
            return self.capabilities_result();
        }
        let dispatcher = Arc::clone(&self.dispatcher);
        match tokio::task::spawn_blocking(move || dispatcher.dispatch(&name, args)).await {
            Ok(Ok(value)) => tool_result_ok(value),
            Ok(Err(envelope)) => tool_result_err(&envelope),
            Err(e) => tool_result_err(&ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("dispatch task failed: {e}"),
            )),
        }
    }
}

impl ServerHandler for OracleMcpServer {
    // rmcp's ServerInfo (InitializeResult) is #[non_exhaustive], so it cannot be
    // built with a struct literal from this crate; Default + field assignment is
    // the only path. ProtocolVersion::default() is already the latest (2025-11-25).
    #[allow(clippy::field_reassign_with_default)]
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new("oraclemcp", self.version.clone())
            .with_title("Oracle MCP server")
            .with_description(
                "Safe-by-default Oracle Database MCP server with PL/SQL intelligence.",
            );
        info.instructions = Some(
            "Call oracle_capabilities first to discover tools, the current/max operating level, and connection status. Reads are frictionless; writes/DDL require a gated escalation."
                .to_owned(),
        );
        info
    }

    // Gate the handshake on the stdio init token BEFORE rmcp's default accepts
    // it (§7.1). The default `initialize` never consults a token, so without
    // this override a `StdioAuthPolicy::Required` gate is a silent no-op — any
    // client reaches `call_tool` unauthenticated. We validate first (fail-
    // closed), then fall through to the default behaviour (record peer info,
    // return `get_info()`).
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        // rmcp hoists the request's `_meta` into the RequestContext (the typed
        // `request.meta` is drained by the WithMeta deserializer), so the
        // presented token lives in `context.meta`.
        self.check_init_token(Some(&context.meta))?;
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request);
        }
        Ok(self.get_info())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.rmcp_tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let name = request.name.to_string();
        let args = request.arguments.map_or(Value::Null, Value::Object);
        Ok(self.run_tool(name, args).await)
    }
}

/// A permissive `{"type":"object"}` input schema.
fn empty_object_schema() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".to_owned(), Value::String("object".to_owned()));
    m
}

fn descriptor_input_schema(descriptor: &ToolDescriptor) -> Map<String, Value> {
    match descriptor.input_schema.as_ref() {
        Some(Value::Object(schema)) => schema.clone(),
        _ => empty_object_schema(),
    }
}

/// A success result carrying dual output: human/LLM text + structured JSON.
fn tool_result_ok(value: Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![Content::text(value.to_string())]);
    result.structured_content = Some(value);
    result
}

/// An error result: the agent-facing envelope as both text and structured JSON.
fn tool_result_err(envelope: &ErrorEnvelope) -> CallToolResult {
    let value = envelope.to_json();
    let mut result = CallToolResult::error(vec![Content::text(value.to_string())]);
    result.structured_content = Some(value);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::FeatureTiers;
    use crate::tools::{ToolDescriptor, ToolTier};
    use oraclemcp_error::ErrorClass;
    use oraclemcp_guard::OperatingLevel;

    struct EchoDispatcher;
    impl ToolDispatch for EchoDispatcher {
        fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope> {
            if name == "boom" {
                return Err(ErrorEnvelope::new(ErrorClass::Internal, "boom"));
            }
            Ok(serde_json::json!({ "echoed": name, "args": args }))
        }
    }

    fn server() -> OracleMcpServer {
        let mut registry = ToolRegistry::new();
        registry.register(
            ToolDescriptor::new("oracle_query", ToolTier::FoundationLiveDb, "run a query")
                .with_input_schema(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string" }
                    },
                    "required": ["sql"],
                    "additionalProperties": false
                })),
        );
        let caps = CapabilitiesReport::new(
            "0.1.0",
            registry.tools.clone(),
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: true,
                engine: true,
                http_transport: false,
            },
        );
        OracleMcpServer::new("0.1.0", registry, caps, Arc::new(EchoDispatcher))
    }

    #[test]
    fn lists_capabilities_tool_first_and_dedups() {
        let s = server();
        let tools = s.rmcp_tools();
        assert_eq!(tools[0].name, CAPABILITIES_TOOL);
        assert!(tools.iter().any(|t| t.name == "oracle_query"));
        // oracle_capabilities only appears once even if also registered.
        assert_eq!(
            tools.iter().filter(|t| t.name == CAPABILITIES_TOOL).count(),
            1
        );
    }

    #[test]
    fn rmcp_tools_preserve_descriptor_input_schemas() {
        let s = server();
        let tools = s.rmcp_tools();
        let query = tools
            .iter()
            .find(|t| t.name == "oracle_query")
            .expect("registered tool");
        assert_eq!(
            query.input_schema["properties"]["sql"]["type"],
            serde_json::json!("string")
        );
        assert_eq!(query.input_schema["required"], serde_json::json!(["sql"]));
    }

    #[test]
    fn get_info_advertises_tools_and_protocol() {
        let info = server().get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
        assert_eq!(info.server_info.name, "oraclemcp");
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn capabilities_result_is_the_report() {
        let s = server();
        let result = s.capabilities_result();
        assert_eq!(result.is_error, Some(false));
        let structured = result.structured_content.expect("structured");
        assert_eq!(structured["server_name"], serde_json::json!("oraclemcp"));
        assert_eq!(
            structured["protocol_version"],
            serde_json::json!("2025-11-25")
        );
    }

    #[tokio::test]
    async fn run_tool_dispatches_and_wraps_errors() {
        let s = server();
        let ok = s
            .run_tool("oracle_query".to_owned(), serde_json::json!({}))
            .await;
        assert_eq!(ok.is_error, Some(false));
        assert_eq!(
            ok.structured_content.unwrap()["echoed"],
            serde_json::json!("oracle_query")
        );

        let err = s.run_tool("boom".to_owned(), Value::Null).await;
        assert_eq!(err.is_error, Some(true));
        assert_eq!(
            err.structured_content.unwrap()["error_class"],
            serde_json::json!("INTERNAL")
        );
    }

    #[tokio::test]
    async fn run_tool_capabilities_returns_the_report() {
        let s = server();
        let result = s.run_tool(CAPABILITIES_TOOL.to_owned(), Value::Null).await;
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content.unwrap()["protocol_version"],
            serde_json::json!("2025-11-25")
        );
    }

    fn meta_with_token(token: &str) -> Meta {
        let mut m = Meta::new();
        m.insert(
            INIT_TOKEN_META_KEY.to_owned(),
            Value::String(token.to_owned()),
        );
        m
    }

    // Regression for oracle-qm3q.10: the `initialize` gate must consult the
    // resolved StdioAuthPolicy. Before the fix nothing called validate(), so a
    // Required token was a silent no-op (any/no token accepted). `check_init_token`
    // is the exact logic the `initialize` override runs.
    #[test]
    fn init_token_gate_rejects_missing_and_wrong_under_required() {
        let s = server().with_stdio_auth(StdioAuthPolicy::Required {
            expected: "s3cr3t".to_owned(),
        });

        // No _meta at all -> Missing -> refused (fail-closed).
        let err = s.check_init_token(None).expect_err("missing token refused");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_REQUEST);

        // _meta present but no token field -> still Missing.
        let empty = Meta::new();
        s.check_init_token(Some(&empty))
            .expect_err("empty _meta refused");

        // Wrong token -> Mismatch -> refused.
        let wrong = meta_with_token("nope");
        s.check_init_token(Some(&wrong))
            .expect_err("wrong token refused");

        // Correct token -> accepted.
        let right = meta_with_token("s3cr3t");
        s.check_init_token(Some(&right))
            .expect("correct token accepted");
    }

    #[test]
    fn init_token_gate_disabled_accepts_anything() {
        let s = server().with_stdio_auth(StdioAuthPolicy::Disabled);
        s.check_init_token(None).expect("disabled accepts no token");
        let any = meta_with_token("whatever");
        s.check_init_token(Some(&any))
            .expect("disabled accepts any token");
    }

    #[test]
    fn init_token_gate_no_policy_is_noop_for_http_path() {
        // HTTP path attaches no stdio policy; the gate must never block it
        // (oauth_guard enforces there instead).
        let s = server();
        s.check_init_token(None).expect("no policy -> no-op");
        let any = meta_with_token("ignored");
        s.check_init_token(Some(&any)).expect("no policy -> no-op");
    }
}
