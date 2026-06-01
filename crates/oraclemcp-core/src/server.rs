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
    CallToolRequestParams, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt};
use serde_json::{Map, Value};

use crate::capabilities::CapabilitiesReport;
use crate::init_token::StdioAuthPolicy;
use crate::tools::ToolRegistry;

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
        }
    }

    /// Map the registry descriptors to rmcp [`Tool`]s. Inputs are flat objects;
    /// each tool advertises a permissive `object` input schema (precise
    /// per-tool schemas land with each tool's bead).
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
                empty_object_schema(),
            ));
        }
        tools
    }

    /// Serve over stdio until the client disconnects. `auth` must already be
    /// resolved (the caller refuses to start when no token + no `--allow-no-auth`
    /// — §7.1); this records the posture and runs the rmcp loop.
    pub async fn serve_stdio(self, auth: &StdioAuthPolicy) -> std::io::Result<()> {
        match auth {
            StdioAuthPolicy::Required { .. } => {
                tracing::info!("stdio transport: init-token required");
            }
            StdioAuthPolicy::Disabled => {
                tracing::warn!("stdio transport: auth disabled (--allow-no-auth)");
            }
        }
        let service = self
            .serve((tokio::io::stdin(), tokio::io::stdout()))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        service
            .waiting()
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
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
        registry.register(ToolDescriptor {
            name: "oracle_query".to_owned(),
            tier: ToolTier::FoundationLiveDb,
            summary: "run a query".to_owned(),
        });
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
}
