#![forbid(unsafe_code)]
// ErrorEnvelope-returning fns (the ToolDispatch contract) trip result_large_err;
// oraclemcp-core allows the same on its dispatch surface.
#![allow(clippy::result_large_err)]

//! Library surface of the engine-free `oraclemcp` server (Phase-E E-2b).
//!
//! The binary ([`main`](../main.rs)) is a thin CLI over this library: it builds
//! the [`registry::tool_registry`] + [`registry::capabilities`] and dispatches
//! the safe-by-default live-DB/config-inspection tools through
//! [`dispatch::OracleDispatcher`] on top of `oraclemcp-core`'s rmcp server.
//! Exposing these here (rather than as `bin`-private modules) lets the
//! integration suite drive the real server surface.

pub mod dispatch;
pub mod registry;
