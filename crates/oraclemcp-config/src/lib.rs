#![forbid(unsafe_code)]

//! Layered configuration and connection profiles for the `oraclemcp` Oracle
//! MCP server (plan §5.9, §8.4; beads P0-1 scaffold, P0-2 figment config).
//!
//! Phase-A skeleton: the validated, versioned config struct (`figment`
//! precedence, `max_level`/`protected`/OCI fields, atomic reload) lands in
//! P0-2 as a cleanly-bounded module here, extractable to the published
//! `oraclemcp-config` crate at Phase E.

/// Re-export the shared agent-facing error envelope so config validation
/// failures speak the same contract as the rest of the core.
pub use oraclemcp_error as error;
