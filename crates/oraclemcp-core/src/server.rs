//! The MCP server core (plan §2.5, §7.1, §8.1; bead P0-6).
//!
//! [`OracleMcpServer`] exposes native MCP JSON-RPC helpers over the dynamic
//! [`ToolRegistry`] + injected [`ToolDispatch`]. Tool dispatch is Cx-aware so
//! transports do not need ambient runtime handles to preserve the fail-closed
//! tool surface.

use std::future::Future;
use std::io::{BufRead, BufReader, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use asupersync::Cx;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde_json::{Map, Value, json};

use crate::capabilities::CapabilitiesReport;
use crate::init_token::StdioAuthPolicy;
use crate::tools::{ToolDescriptor, ToolRegistry};

/// The `_meta` field carrying the stdio init token on the `initialize` request.
/// The client places its shared token here so the server can gate the handshake
/// before any other request (§7.1). Kept namespaced to avoid colliding with
/// MCP's reserved keys (e.g. `progressToken`).
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

/// Per-request authorization context supplied by transports.
#[derive(Clone, Copy, Debug, Default)]
pub struct DispatchContext<'a> {
    scope_grant: Option<&'a crate::http::ScopeGrant>,
}

impl<'a> DispatchContext<'a> {
    /// Build a context from a validated OAuth scope grant.
    #[must_use]
    pub fn with_scope_grant(scope_grant: &'a crate::http::ScopeGrant) -> Self {
        Self {
            scope_grant: Some(scope_grant),
        }
    }

    /// The validated OAuth scopes for this request, if any.
    #[must_use]
    pub fn scope_grant(self) -> Option<&'a crate::http::ScopeGrant> {
        self.scope_grant
    }
}

/// Cx-aware tool dispatch, injected by the engine/operator side. Returns the
/// tool's structured JSON or an [`ErrorEnvelope`].
pub trait ToolDispatch: Send + Sync + 'static {
    /// Dispatch a tool call by name with JSON arguments in the supplied
    /// Asupersync context.
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a>;
}

/// The MCP server surface shared by native stdio and HTTP transports.
#[derive(Clone)]
pub struct OracleMcpServer {
    version: String,
    registry: Arc<ToolRegistry>,
    tool_descriptors_json: Arc<OnceLock<Vec<Value>>>,
    tools_list_result_json: Arc<OnceLock<Value>>,
    capabilities: Arc<CapabilitiesReport>,
    dispatcher: Arc<dyn ToolDispatch>,
    dispatch_runtime: Arc<Runtime>,
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
        let registry = Arc::new(registry);
        OracleMcpServer {
            version: version.into(),
            registry,
            tool_descriptors_json: Arc::new(OnceLock::new()),
            tools_list_result_json: Arc::new(OnceLock::new()),
            capabilities: Arc::new(capabilities),
            dispatcher,
            dispatch_runtime: Arc::new(dispatch_runtime),
        }
    }

    /// Map the registry descriptors to native MCP JSON tool descriptors.
    #[must_use]
    pub fn tools_json(&self) -> Vec<Value> {
        self.tool_descriptors_json
            .get_or_init(|| tools_json_for_registry(&self.registry))
            .clone()
    }

    /// Build the native MCP `tools/list` result object.
    #[must_use]
    pub fn tools_list_result_json(&self) -> Value {
        self.tools_list_result_json
            .get_or_init(|| json!({ "tools": self.tools_json() }))
            .clone()
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
    /// Tokio or external transport types.
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

    /// Build the native MCP `initialize` result object.
    #[must_use]
    pub fn initialize_result_json(&self) -> Value {
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
        self.run_tool_json_with_context(cx, DispatchContext::default(), name, args)
            .await
    }

    /// Run a tool by name + JSON args in an explicit Asupersync context and
    /// transport authorization context.
    pub async fn run_tool_json_with_context(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
        name: String,
        args: Value,
    ) -> Value {
        if name == CAPABILITIES_TOOL {
            return self.capabilities_result_json();
        }
        match self.dispatcher.dispatch(cx, context, &name, args).await {
            Ok(value) => tool_result_ok_json(value),
            Err(envelope) => tool_result_err_json(&self.sanitize_error_envelope(envelope)),
        }
    }

    /// Run a tool by name + JSON args in an explicit Asupersync context.
    pub async fn run_tool_with_cx(&self, cx: &Cx, name: String, args: Value) -> Value {
        self.run_tool_json_with_cx(cx, name, args).await
    }

    /// Run a tool through the server-owned Asupersync runtime. Native blocking
    /// transports use this to keep request handling synchronous without Tokio.
    #[must_use]
    pub fn run_tool_blocking(&self, name: String, args: Value) -> Value {
        self.run_tool_blocking_with_context(DispatchContext::default(), name, args)
    }

    /// Run a tool through the server-owned Asupersync runtime with transport
    /// authorization context.
    #[must_use]
    pub fn run_tool_blocking_with_context(
        &self,
        context: DispatchContext<'_>,
        name: String,
        args: Value,
    ) -> Value {
        self.dispatch_runtime.block_on(async {
            let Some(cx) = Cx::current() else {
                let envelope = ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "Asupersync context was not installed for tool dispatch",
                );
                return tool_result_err_json(&envelope);
            };
            self.run_tool_json_with_context(&cx, context, name, args)
                .await
        })
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
        self.handle_jsonrpc_request(request, Some(auth))
    }

    /// Handle one parsed JSON-RPC request. `auth` is provided by stdio, where
    /// initialize is token-gated; HTTP uses transport auth instead and passes
    /// `None`.
    pub fn handle_jsonrpc_request(
        &self,
        request: Value,
        auth: Option<&StdioAuthPolicy>,
    ) -> Option<Value> {
        self.handle_jsonrpc_request_with_context(request, auth, DispatchContext::default())
    }

    /// Handle one parsed JSON-RPC request with a transport authorization
    /// context. HTTP uses this to apply OAuth scopes to `tools/call` dispatch.
    pub fn handle_jsonrpc_request_with_context(
        &self,
        request: Value,
        auth: Option<&StdioAuthPolicy>,
        context: DispatchContext<'_>,
    ) -> Option<Value> {
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
            "initialize" => Some(self.handle_initialize(id, object.get("params"), auth)),
            "notifications/initialized" => None,
            "tools/list" => Some(jsonrpc_result(id, self.tools_list_result_json())),
            "tools/call" => Some(self.handle_tool_call(id, object.get("params"), context)),
            _ => Some(jsonrpc_error(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                "Method not found",
            )),
        }
    }

    fn handle_initialize(
        &self,
        id: Value,
        params: Option<&Value>,
        auth: Option<&StdioAuthPolicy>,
    ) -> Value {
        if let Some(auth) = auth {
            let presented = params
                .and_then(|params| params.get("_meta"))
                .and_then(|meta| meta.get(INIT_TOKEN_META_KEY))
                .and_then(Value::as_str);
            if let Err(e) = auth.validate(presented) {
                tracing::warn!(error = %e, "stdio init-token rejected on initialize");
                return jsonrpc_error(id, JSONRPC_INVALID_REQUEST, e.to_string());
            }
        }
        jsonrpc_result(id, self.initialize_result_json())
    }

    fn handle_tool_call(
        &self,
        id: Value,
        params: Option<&Value>,
        context: DispatchContext<'_>,
    ) -> Value {
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
        let result = self.run_tool_blocking_with_context(context, name.to_owned(), args);
        jsonrpc_result(id, result)
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

fn tools_json_for_registry(registry: &ToolRegistry) -> Vec<Value> {
    let mut tools = Vec::with_capacity(registry.tools.len() + 1);
    tools.push(json!({
        "name": CAPABILITIES_TOOL,
        "description": "Zero-arg entry point: tools, operating level + gates, connection/standby status, feature tiers, version.",
        "inputSchema": empty_object_schema(),
    }));
    for d in &registry.tools {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::FeatureTiers;
    use crate::tools::{ToolDescriptor, ToolTier};
    use oraclemcp_error::ErrorClass;
    use oraclemcp_guard::OperatingLevel;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct EchoDispatcher;
    impl ToolDispatch for EchoDispatcher {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            args: Value,
        ) -> DispatchFuture<'a> {
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

    struct ActiveCallGuard {
        active: Arc<AtomicUsize>,
    }

    impl Drop for ActiveCallGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct TrackingCancelDispatcher {
        active: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    impl ToolDispatch for TrackingCancelDispatcher {
        fn dispatch<'a>(
            &'a self,
            cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            let active = self.active.clone();
            let calls = self.calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = ActiveCallGuard { active };
                cx.checkpoint_with("oraclemcp.test.tool-call.quiescence")
                    .map_err(|err| {
                        ErrorEnvelope::new(ErrorClass::Timeout, format!("cancelled: {err}"))
                    })?;
                Ok(serde_json::json!({ "completed": true }))
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
        run_stdio_raw_with_auth(server, input, &StdioAuthPolicy::Disabled)
    }

    fn run_stdio_raw_with_auth(
        server: &OracleMcpServer,
        input: Vec<u8>,
        auth: &StdioAuthPolicy,
    ) -> Vec<Value> {
        let mut output = Vec::new();
        server
            .serve_stdio_with_io(Cursor::new(input), &mut output, auth)
            .expect("stdio session completes");
        String::from_utf8(output)
            .expect("stdio replies are UTF-8")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("reply is JSON"))
            .collect()
    }

    fn run_tool_json(server: &OracleMcpServer, name: &str, args: Value) -> Value {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            server.run_tool_with_cx(&cx, name.to_owned(), args).await
        })
    }

    #[test]
    fn lists_capabilities_tool_first_and_dedups() {
        let s = server();
        let tools = s.tools_json();
        assert_eq!(tools[0]["name"], serde_json::json!(CAPABILITIES_TOOL));
        assert!(tools.iter().any(|t| t["name"] == "oracle_query"));
        // oracle_capabilities only appears once even if also registered.
        assert_eq!(
            tools
                .iter()
                .filter(|t| t["name"] == serde_json::json!(CAPABILITIES_TOOL))
                .count(),
            1
        );
    }

    #[test]
    fn tools_json_preserves_descriptor_input_schemas() {
        let s = server();
        let tools = s.tools_json();
        let query = tools
            .iter()
            .find(|t| t["name"] == "oracle_query")
            .expect("registered tool");
        assert_eq!(
            query["inputSchema"]["properties"]["sql"]["type"],
            serde_json::json!("string")
        );
        assert_eq!(query["inputSchema"]["required"], serde_json::json!(["sql"]));
    }

    #[test]
    fn tools_list_result_matches_advertised_tools_on_repeated_calls() {
        let s = server();
        let expected = serde_json::json!({ "tools": s.tools_json() });

        assert_eq!(s.tools_list_result_json(), expected);
        assert_eq!(s.tools_list_result_json(), expected);
    }

    #[test]
    fn initialize_result_advertises_tools_and_protocol() {
        let info = server().initialize_result_json();
        assert_eq!(info["protocolVersion"], serde_json::json!("2025-11-25"));
        assert_eq!(info["serverInfo"]["name"], "oraclemcp");
        assert!(info["capabilities"].get("tools").is_some());
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

    #[test]
    fn run_tool_dispatches_and_wraps_errors() {
        let s = server();
        let ok = run_tool_json(&s, "oracle_query", serde_json::json!({}));
        assert_eq!(ok["isError"], serde_json::json!(false));
        assert_eq!(
            ok["structuredContent"]["echoed"],
            serde_json::json!("oracle_query")
        );

        let err = run_tool_json(&s, "boom", Value::Null);
        assert_eq!(err["isError"], serde_json::json!(true));
        assert_eq!(
            err["structuredContent"]["error_class"],
            serde_json::json!("INTERNAL")
        );
    }

    #[test]
    fn run_tool_with_cx_dispatches_without_runtime_bridge() {
        let s = server();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");
        let ok = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            s.run_tool_with_cx(&cx, "oracle_query".to_owned(), serde_json::json!({}))
                .await
        });
        assert_eq!(ok["isError"], serde_json::json!(false));
        assert_eq!(
            ok["structuredContent"]["echoed"],
            serde_json::json!("oracle_query")
        );
    }

    #[test]
    fn cancelled_tool_call_returns_timeout_and_quiesces_active_work() {
        let mut registry = ToolRegistry::new();
        registry.register(ToolDescriptor::new(
            "oracle_query",
            ToolTier::FoundationLiveDb,
            "run a query",
        ));
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
        let active = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let s = OracleMcpServer::new(
            "0.1.0",
            registry,
            caps,
            Arc::new(TrackingCancelDispatcher {
                active: active.clone(),
                calls: calls.clone(),
            }),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");

        let response = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            cx.set_cancel_requested(true);
            s.run_tool_with_cx(&cx, "oracle_query".to_owned(), serde_json::json!({}))
                .await
        });

        assert_eq!(response["isError"], serde_json::json!(true));
        assert_eq!(
            response["structuredContent"]["error_class"],
            serde_json::json!("TIMEOUT")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "tool-call region must have no active work after cancellation resolves"
        );
    }

    #[test]
    fn run_tool_replaces_unadvertised_suggested_tools() {
        let s = server_with_tools(&["connect_fail", "oracle_query"]);
        let err = run_tool_json(&s, "connect_fail", Value::Null);
        let structured = &err["structuredContent"];
        assert_eq!(err["isError"], serde_json::json!(true));
        assert_eq!(
            structured["error_class"],
            serde_json::json!("CONNECTION_FAILED")
        );
        assert_eq!(
            structured["suggested_tool"],
            serde_json::json!(CAPABILITIES_TOOL)
        );
    }

    #[test]
    fn run_tool_preserves_advertised_suggested_tools() {
        let s = server_with_tools(&["missing_object", "oracle_schema_inspect"]);
        let err = run_tool_json(&s, "missing_object", Value::Null);
        let structured = &err["structuredContent"];
        assert_eq!(
            structured["suggested_tool"],
            serde_json::json!("oracle_schema_inspect")
        );
    }

    #[test]
    fn run_tool_capabilities_returns_the_report() {
        let s = server();
        let result = run_tool_json(&s, CAPABILITIES_TOOL, Value::Null);
        assert_eq!(result["isError"], serde_json::json!(false));
        assert_eq!(
            result["structuredContent"]["protocol_version"],
            serde_json::json!("2025-11-25")
        );
    }

    fn initialize_frame(token: Option<&str>) -> Vec<u8> {
        let mut params = serde_json::json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "unit", "version": "1.0" }
        });
        if let Some(token) = token {
            params["_meta"] = serde_json::json!({ INIT_TOKEN_META_KEY: token });
        }
        stdio_frame(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": params,
        }))
    }

    // Regression for oracle-qm3q.10: the `initialize` gate must consult the
    // resolved StdioAuthPolicy. Before the fix nothing called validate(), so a
    // Required token was a silent no-op (any/no token accepted).
    #[test]
    fn init_token_gate_rejects_missing_and_wrong_under_required() {
        let s = server();
        let auth = StdioAuthPolicy::Required {
            expected: "s3cr3t".to_owned(),
        };

        let missing = run_stdio_raw_with_auth(&s, initialize_frame(None), &auth);
        assert_eq!(
            missing[0]["error"]["message"],
            serde_json::json!("stdio init token missing from initialize request")
        );

        let wrong = run_stdio_raw_with_auth(&s, initialize_frame(Some("nope")), &auth);
        assert_eq!(
            wrong[0]["error"]["message"],
            serde_json::json!("stdio init token mismatch")
        );

        let right = run_stdio_raw_with_auth(&s, initialize_frame(Some("s3cr3t")), &auth);
        assert!(right[0].get("result").is_some());
    }

    #[test]
    fn init_token_gate_disabled_accepts_anything() {
        let s = server();
        let missing =
            run_stdio_raw_with_auth(&s, initialize_frame(None), &StdioAuthPolicy::Disabled);
        assert!(missing[0].get("result").is_some());

        let any = run_stdio_raw_with_auth(
            &s,
            initialize_frame(Some("whatever")),
            &StdioAuthPolicy::Disabled,
        );
        assert!(any[0].get("result").is_some());
    }
}
