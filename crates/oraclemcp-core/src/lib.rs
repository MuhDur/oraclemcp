#![forbid(unsafe_code)]

//! The MCP protocol surface and tool-registry contract for the `oraclemcp`
//! server. In Phase A this hosts the JSON-RPC protocol, the loopback-safe
//! transports, the `ToolRegistry`/`Tool` contract, the trust-block injector
//! and the `doctor` report lifted from `plsql-mcp` (P0-0); P0-6 replaces the
//! hand-rolled protocol with `rmcp` and adds `oracle_capabilities`.
//!
//! Engine intelligence reaches this core by the engine-side code implementing
//! the registry's `Tool` contract — the core never reaches into engine
//! internals (the one-way boundary, §0 hard rule 1).

pub mod tools;

pub use tools::{ToolDescriptor, ToolRegistry, ToolTier};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
