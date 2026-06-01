#![forbid(unsafe_code)]
// ErrorEnvelope is the deliberate agent-facing error payload (§8.2); it is the
// `Err` of the dispatch contract throughout this crate. Boxing every
// `Result<_, ErrorEnvelope>` to satisfy `result_large_err` would add noise on
// cold error paths for no real benefit.
#![allow(clippy::result_large_err)]

//! The MCP protocol surface and tool-registry contract for the `oraclemcp`
//! server. In Phase A this hosts the JSON-RPC protocol, the loopback-safe
//! transports, the `ToolRegistry`/`Tool` contract, the trust-block injector
//! and the `doctor` report lifted from `plsql-mcp` (P0-0); P0-6 replaces the
//! hand-rolled protocol with `rmcp` and adds `oracle_capabilities`.
//!
//! Engine intelligence reaches this core by the engine-side code implementing
//! the registry's `Tool` contract — the core never reaches into engine
//! internals (the one-way boundary, §0 hard rule 1).

pub mod admission;
pub mod capabilities;
pub mod connect;
pub mod custom_tools;
pub mod doctor;
pub mod init_token;
pub mod query_execute;
pub mod resilience;
pub mod server;
pub mod session_tool;
pub mod shutdown;
pub mod tools;

pub use resilience::{
    CircuitBreaker, CircuitState, RetryPolicy, is_transient_error, run_with_timeout,
};
pub use server::{CAPABILITIES_TOOL, OracleMcpServer, ToolDispatch};
pub use shutdown::{CancelOutcome, ShutdownCoordinator, install_panic_hook};

pub use admission::{AdmissionController, AdmissionPermit};
pub use capabilities::{
    CapabilitiesReport, ConnectionStatus, FeatureTiers, OperatingLevelReport, PROTOCOL_VERSION,
};
pub use connect::{SessionContext, build_session_context, profile_to_options, session_level_state};
pub use custom_tools::{
    CustomToolDef, LoadError, LoadedTool, OutputMode, ParamDef, ParamType, ToolBody,
    classify_at_load, enforce_signature, load_tools, load_tools_for_profile, parse_tools_file,
    register_custom_tools, sign, verify_signature,
};
pub use doctor::{CheckResult, CheckStatus, DoctorContext, DoctorReport, run_doctor};
pub use init_token::{InitTokenError, STDIO_TOKEN_ENV, StdioAuthPolicy};
pub use query_execute::{ExecuteParams, StatementExecutor, oracle_query_execute};
pub use session_tool::{LeaseAcquirer, SessionAction, SessionDeps, oracle_session};
pub use tools::{ToolDescriptor, ToolRegistry, ToolTier};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
