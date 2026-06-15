//! The MCP server core (plan §2.5, §7.1, §8.1; bead P0-6).
//!
//! [`OracleMcpServer`] exposes a native stdio JSON-RPC transport and, until the
//! HTTP transport is migrated, an rmcp [`ServerHandler`] compatibility path over
//! the dynamic [`ToolRegistry`] + injected [`ToolDispatch`]. Tool dispatch is
//! Cx-aware so transports do not need ambient Tokio handles to preserve the
//! fail-closed tool surface.

use std::future::Future;
use std::io::{BufRead, BufReader, Read, Write};
use std::pin::Pin;
use std::sync::Arc;

use asupersync::Cx;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, InitializeRequestParams,
    InitializeResult, ListToolsResult, Meta, PaginatedRequestParams, ProtocolVersion,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde_json::{Map, Value, json};

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

const STDIO_MAX_FRAME_BYTES: usize = 1024 * 1024;
const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const SERVER_INSTRUCTIONS: &str = "Call oracle_capabilities first to discover tools, the current/max operating level, and connection status. Reads are frictionless; writes/DDL require a gated escalation.";

/// Boxed tool-dispatch future. This keeps [`ToolDispatch`] object-safe while
/// making runtime context explicit at the server boundary.
pub type DispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, ErrorEnvelope>> + Send + 'a>>;

/// Cx-aware tool dispatch, injected by the engine/operator side. Returns the
/// tool's structured JSON or an [`ErrorEnvelope`].
pub trait ToolDispatch: Send + Sync + 'static {
    /// Dispatch a tool call by name with JSON arguments in the supplied
    /// Asupersync context.
    fn dispatch<'a>(&'a self, cx: &'a Cx, name: &'a str, args: Value) -> DispatchFuture<'a>;
}

/// The MCP server surface shared by native stdio and the rmcp HTTP compatibility
/// path.
#[derive(Clone)]
pub struct OracleMcpServer {
    version: String,
    registry: Arc<ToolRegistry>,
    capabilities: Arc<CapabilitiesReport>,
    dispatcher: Arc<dyn ToolDispatch>,
    /// Temporary bridge for rmcp/Tokio callers until the native Asupersync
    /// transport beads replace this caller path. Native server code should call
    /// `run_tool_with_cx` with an explicit context.
    dispatch_runtime: Arc<Runtime>,
    /// The resolved stdio init-token policy used by the rmcp compatibility
    /// `initialize` override. Native stdio receives its policy explicitly at
    /// the transport boundary.
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
        let dispatch_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("Asupersync current-thread runtime builds for MCP dispatch");
        OracleMcpServer {
            version: version.into(),
            registry: Arc::new(registry),
            capabilities: Arc::new(capabilities),
            dispatcher,
            dispatch_runtime: Arc::new(dispatch_runtime),
            auth: None,
        }
    }

    /// Attach the stdio init-token policy enforced by the rmcp compatibility
    /// `initialize` override. Native stdio passes the policy directly to
    /// [`serve_stdio`](Self::serve_stdio).
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

    /// Map the registry descriptors to native MCP JSON tool descriptors.
    fn native_tools_json(&self) -> Vec<Value> {
        let mut tools = Vec::with_capacity(self.registry.tools.len() + 1);
        tools.push(json!({
            "name": CAPABILITIES_TOOL,
            "description": "Zero-arg entry point: tools, operating level + gates, connection/standby status, feature tiers, version.",
            "inputSchema": empty_object_schema(),
        }));
        for d in &self.registry.tools {
            if d.name == CAPABILITIES_TOOL {
                continue;
            }
            tools.push(json!({
                "name": d.name,
                "description": d.summary,
                "inputSchema": descriptor_input_schema(d),
            }));
        }
        tools
    }

    /// Serve over stdio until the client disconnects. `auth` must already be
    /// resolved (the caller refuses to start when no token + no `--allow-no-auth`
    /// — §7.1). This native line-delimited JSON-RPC loop keeps stdout pure MCP
    /// data and routes tool calls through explicit Asupersync contexts.
    pub fn serve_stdio(self, auth: &StdioAuthPolicy) -> std::io::Result<()> {
        match auth {
            StdioAuthPolicy::Required { .. } => {
                tracing::info!("stdio transport: init-token required");
            }
            StdioAuthPolicy::Disabled => {
                tracing::warn!("stdio transport: auth disabled (--allow-no-auth)");
            }
        }
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        self.serve_stdio_with_io(stdin.lock(), stdout.lock(), auth)
    }

    /// Serve a native stdio JSON-RPC session over arbitrary blocking IO. This
    /// is public for protocol/golden tests and intentionally does not depend on
    /// Tokio or rmcp transport types.
    pub fn serve_stdio_with_io<R, W>(
        &self,
        reader: R,
        mut writer: W,
        auth: &StdioAuthPolicy,
    ) -> std::io::Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut reader = BufReader::new(reader);
        let mut frame = Vec::new();
        loop {
            frame.clear();
            let read = reader.read_until(b'\n', &mut frame)?;
            if read == 0 {
                break;
            }
            if frame.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let response = if frame.len() > STDIO_MAX_FRAME_BYTES {
                Some(jsonrpc_error(
                    Value::Null,
                    JSONRPC_INVALID_REQUEST,
                    "JSON-RPC frame exceeds stdio limit",
                ))
            } else {
                self.handle_stdio_frame(&frame, auth)
            };
            if let Some(response) = response {
                write_jsonrpc_response(&mut writer, &response)?;
            }
        }
        Ok(())
    }

    /// Validate the stdio init token presented to the rmcp compatibility
    /// `initialize` request's `_meta`, fail-closed. When no stdio policy is
    /// attached (the HTTP path), this is a no-op (`Ok`). When a `Required`
    /// policy is attached, a missing or mismatched token yields an
    /// `invalid_request` [`McpError`] so the handshake is refused before any
    /// tool is reachable (§7.1).
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

    fn native_initialize_result_json(&self) -> Value {
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": "oraclemcp",
                "version": self.version,
                "title": "Oracle MCP server",
                "description": "Safe-by-default Oracle Database MCP server with PL/SQL intelligence.",
            },
            "instructions": SERVER_INSTRUCTIONS,
        })
    }

    fn capabilities_result_json(&self) -> Value {
        let value = serde_json::to_value(&*self.capabilities).unwrap_or(Value::Null);
        tool_result_ok_json(value)
    }

    fn advertises_tool(&self, name: &str) -> bool {
        name == CAPABILITIES_TOOL || self.registry.tools.iter().any(|t| t.name == name)
    }

    fn first_advertised_tool(&self, candidates: &[&str]) -> String {
        candidates
            .iter()
            .copied()
            .find(|candidate| self.advertises_tool(candidate))
            .unwrap_or(CAPABILITIES_TOOL)
            .to_owned()
    }

    fn recovery_tool_for(&self, class: ErrorClass) -> Option<String> {
        match class {
            ErrorClass::ConnectionFailed | ErrorClass::RuntimeStateRequired => {
                Some(self.first_advertised_tool(&[
                    "oracle_connection_info",
                    "oracle_list_profiles",
                    CAPABILITIES_TOOL,
                ]))
            }
            ErrorClass::OperatingLevelTooLow | ErrorClass::ChallengeRequired => {
                Some(self.first_advertised_tool(&[
                    "oracle_set_session_level",
                    "oracle_preview_sql",
                    CAPABILITIES_TOOL,
                ]))
            }
            ErrorClass::ObjectNotFound => Some(self.first_advertised_tool(&[
                "oracle_schema_inspect",
                "list_objects",
                CAPABILITIES_TOOL,
            ])),
            _ => None,
        }
    }

    fn sanitize_error_envelope(&self, mut envelope: ErrorEnvelope) -> ErrorEnvelope {
        if envelope
            .suggested_tool
            .as_deref()
            .is_some_and(|tool| self.advertises_tool(tool))
        {
            return envelope;
        }
        envelope.suggested_tool = self.recovery_tool_for(envelope.error_class);
        envelope
    }

    /// Run a tool by name + JSON args in an explicit Asupersync context,
    /// returning the native MCP `tools/call` result object.
    pub async fn run_tool_json_with_cx(&self, cx: &Cx, name: String, args: Value) -> Value {
        if name == CAPABILITIES_TOOL {
            return self.capabilities_result_json();
        }
        match self.dispatcher.dispatch(cx, &name, args).await {
            Ok(value) => tool_result_ok_json(value),
            Err(envelope) => tool_result_err_json(&self.sanitize_error_envelope(envelope)),
        }
    }

    /// Run a tool by name + JSON args in an explicit Asupersync context.
    pub async fn run_tool_with_cx(&self, cx: &Cx, name: String, args: Value) -> CallToolResult {
        call_tool_result_from_json(self.run_tool_json_with_cx(cx, name, args).await)
    }

    /// Run a tool by name + JSON args, returning a [`CallToolResult`]. This is
    /// the legacy rmcp/Tokio entrypoint; native Asupersync callers should prefer
    /// [`Self::run_tool_with_cx`].
    pub async fn run_tool(&self, name: String, args: Value) -> CallToolResult {
        if let Some(cx) = Cx::current() {
            return self.run_tool_with_cx(&cx, name, args).await;
        }

        let server = self.clone();
        let runtime = Arc::clone(&self.dispatch_runtime);
        // COMPAT-REMOVE(oraclemcp-w8-native-stdio-mcp-sk2, oraclemcp-w9-native-http-mcp-or0):
        // rmcp invokes this method from Tokio-owned transport tasks today.
        // Native transports call `run_tool_with_cx` and delete this bridge.
        match tokio::task::spawn_blocking(move || {
            runtime.block_on(async move {
                let Some(cx) = Cx::current() else {
                    let envelope = ErrorEnvelope::new(
                        ErrorClass::RuntimeStateRequired,
                        "Asupersync context was not installed for tool dispatch",
                    );
                    return call_tool_result_from_json(tool_result_err_json(&envelope));
                };
                server.run_tool_with_cx(&cx, name, args).await
            })
        })
        .await
        {
            Ok(result) => result,
            Err(e) => call_tool_result_from_json(tool_result_err_json(&ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("dispatch task failed: {e}"),
            ))),
        }
    }

    fn handle_stdio_frame(&self, frame: &[u8], auth: &StdioAuthPolicy) -> Option<Value> {
        let request = match serde_json::from_slice::<Value>(frame) {
            Ok(value) => value,
            Err(_) => {
                return Some(jsonrpc_error(
                    Value::Null,
                    JSONRPC_PARSE_ERROR,
                    "Parse error",
                ));
            }
        };
        self.handle_stdio_request(request, auth)
    }

    fn handle_stdio_request(&self, request: Value, auth: &StdioAuthPolicy) -> Option<Value> {
        let Value::Object(object) = request else {
            return Some(jsonrpc_error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "Invalid Request",
            ));
        };
        let id = object.get("id").cloned();
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return id.map(|id| jsonrpc_error(id, JSONRPC_INVALID_REQUEST, "Invalid Request"));
        };
        if object.get("jsonrpc") != Some(&Value::String("2.0".to_owned())) {
            return id.map(|id| jsonrpc_error(id, JSONRPC_INVALID_REQUEST, "Invalid Request"));
        }
        let id = id?;
        match method {
            "initialize" => Some(self.handle_stdio_initialize(id, object.get("params"), auth)),
            "notifications/initialized" => None,
            "tools/list" => Some(jsonrpc_result(
                id,
                json!({ "tools": self.native_tools_json() }),
            )),
            "tools/call" => Some(self.handle_stdio_tool_call(id, object.get("params"))),
            _ => Some(jsonrpc_error(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                "Method not found",
            )),
        }
    }

    fn handle_stdio_initialize(
        &self,
        id: Value,
        params: Option<&Value>,
        auth: &StdioAuthPolicy,
    ) -> Value {
        let presented = params
            .and_then(|params| params.get("_meta"))
            .and_then(|meta| meta.get(INIT_TOKEN_META_KEY))
            .and_then(Value::as_str);
        if let Err(e) = auth.validate(presented) {
            tracing::warn!(error = %e, "stdio init-token rejected on initialize");
            return jsonrpc_error(id, JSONRPC_INVALID_REQUEST, e.to_string());
        }
        jsonrpc_result(id, self.native_initialize_result_json())
    }

    fn handle_stdio_tool_call(&self, id: Value, params: Option<&Value>) -> Value {
        let Some(Value::Object(params)) = params else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "tools/call params must be an object",
            );
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "tools/call name must be a string",
            );
        };
        let args = match params.get("arguments") {
            Some(Value::Object(arguments)) => Value::Object(arguments.clone()),
            Some(Value::Null) | None => Value::Null,
            Some(_) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "tools/call arguments must be an object",
                );
            }
        };
        let result = self.dispatch_runtime.block_on(async {
            let Some(cx) = Cx::current() else {
                let envelope = ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "Asupersync context was not installed for tool dispatch",
                );
                return tool_result_err_json(&envelope);
            };
            self.run_tool_json_with_cx(&cx, name.to_owned(), args).await
        });
        jsonrpc_result(id, result)
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
        info.instructions = Some(SERVER_INSTRUCTIONS.to_owned());
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

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn jsonrpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into(),
        },
    })
}

fn write_jsonrpc_response<W: Write>(writer: &mut W, response: &Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *writer, response)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// A success result carrying dual output: human/LLM text + structured JSON.
fn tool_result_ok_json(value: Value) -> Value {
    tool_result_json(value, false)
}

/// An error result: the agent-facing envelope as both text and structured JSON.
fn tool_result_err_json(envelope: &ErrorEnvelope) -> Value {
    let value = envelope.to_json();
    tool_result_json(value, true)
}

fn tool_result_json(value: Value, is_error: bool) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": value.to_string(),
            }
        ],
        "structuredContent": value,
        "isError": is_error,
    })
}

fn call_tool_result_from_json(value: Value) -> CallToolResult {
    serde_json::from_value(value).expect("native tool result shape matches rmcp CallToolResult")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::FeatureTiers;
    use crate::tools::{ToolDescriptor, ToolTier};
    use oraclemcp_error::ErrorClass;
    use oraclemcp_guard::OperatingLevel;
    use std::io::Cursor;

    struct EchoDispatcher;
    impl ToolDispatch for EchoDispatcher {
        fn dispatch<'a>(&'a self, _cx: &'a Cx, name: &'a str, args: Value) -> DispatchFuture<'a> {
            Box::pin(async move {
                if name == "boom" {
                    return Err(ErrorEnvelope::new(ErrorClass::Internal, "boom"));
                }
                if name == "connect_fail" {
                    return Err(ErrorEnvelope::new(
                        ErrorClass::ConnectionFailed,
                        "connection unavailable",
                    ));
                }
                if name == "missing_object" {
                    return Err(ErrorEnvelope::new(
                        ErrorClass::ObjectNotFound,
                        "object not found",
                    ));
                }
                Ok(serde_json::json!({ "echoed": name, "args": args }))
            })
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

    fn server_with_tools(names: &[&str]) -> OracleMcpServer {
        let mut registry = ToolRegistry::new();
        for name in names {
            registry.register(ToolDescriptor::new(
                *name,
                ToolTier::FoundationLiveDb,
                "test tool",
            ));
        }
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

    fn stdio_frame(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).expect("frame serializes");
        bytes.push(b'\n');
        bytes
    }

    fn run_stdio_raw(server: &OracleMcpServer, input: Vec<u8>) -> Vec<Value> {
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
    fn capabilities_result_json_is_the_report() {
        let s = server();
        let result = s.capabilities_result_json();
        assert_eq!(result["isError"], serde_json::json!(false));
        let structured = &result["structuredContent"];
        assert_eq!(structured["server_name"], serde_json::json!("oraclemcp"));
        assert_eq!(
            structured["protocol_version"],
            serde_json::json!("2025-11-25")
        );
    }

    #[test]
    fn native_stdio_rejects_malformed_unknown_invalid_and_oversized_frames() {
        let s = server();

        let malformed = run_stdio_raw(&s, b"{not json\n".to_vec());
        assert_eq!(malformed[0]["id"], Value::Null);
        assert_eq!(
            malformed[0]["error"]["code"],
            serde_json::json!(JSONRPC_PARSE_ERROR)
        );

        let unknown = run_stdio_raw(
            &s,
            stdio_frame(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "u1",
                "method": "oracle/unknown"
            })),
        );
        assert_eq!(unknown[0]["id"], serde_json::json!("u1"));
        assert_eq!(
            unknown[0]["error"]["code"],
            serde_json::json!(JSONRPC_METHOD_NOT_FOUND)
        );

        let invalid_params = run_stdio_raw(
            &s,
            stdio_frame(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": { "name": 42 }
            })),
        );
        assert_eq!(invalid_params[0]["id"], serde_json::json!(9));
        assert_eq!(
            invalid_params[0]["error"]["code"],
            serde_json::json!(JSONRPC_INVALID_PARAMS)
        );

        let oversized = run_stdio_raw(&s, vec![b'x'; STDIO_MAX_FRAME_BYTES + 1]);
        assert_eq!(oversized[0]["id"], Value::Null);
        assert_eq!(
            oversized[0]["error"]["code"],
            serde_json::json!(JSONRPC_INVALID_REQUEST)
        );
    }

    #[test]
    fn native_stdio_notifications_do_not_receive_responses() {
        let s = server();
        let replies = run_stdio_raw(
            &s,
            stdio_frame(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })),
        );
        assert!(replies.is_empty(), "notifications produce no response");
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

    #[test]
    fn run_tool_with_cx_dispatches_without_tokio_bridge() {
        let s = server();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");
        let ok = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            s.run_tool_with_cx(&cx, "oracle_query".to_owned(), serde_json::json!({}))
                .await
        });
        assert_eq!(ok.is_error, Some(false));
        assert_eq!(
            ok.structured_content.unwrap()["echoed"],
            serde_json::json!("oracle_query")
        );
    }

    #[tokio::test]
    async fn run_tool_replaces_unadvertised_suggested_tools() {
        let s = server_with_tools(&["connect_fail", "oracle_query"]);
        let err = s.run_tool("connect_fail".to_owned(), Value::Null).await;
        let structured = err.structured_content.expect("structured error");
        assert_eq!(err.is_error, Some(true));
        assert_eq!(
            structured["error_class"],
            serde_json::json!("CONNECTION_FAILED")
        );
        assert_eq!(
            structured["suggested_tool"],
            serde_json::json!(CAPABILITIES_TOOL)
        );
    }

    #[tokio::test]
    async fn run_tool_preserves_advertised_suggested_tools() {
        let s = server_with_tools(&["missing_object", "oracle_schema_inspect"]);
        let err = s.run_tool("missing_object".to_owned(), Value::Null).await;
        let structured = err.structured_content.expect("structured error");
        assert_eq!(
            structured["suggested_tool"],
            serde_json::json!("oracle_schema_inspect")
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
