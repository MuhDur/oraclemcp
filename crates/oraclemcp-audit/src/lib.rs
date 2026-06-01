#![forbid(unsafe_code)]

//! Out-of-band durable audit sink for the `oraclemcp` Oracle MCP server
//! (plan §5.13, §6.4; beads P0-1 scaffold, P1-4 durable audit).
//!
//! Phase-A skeleton. The durable sink (append-only file / SQLite with
//! fsync-before-execute, a monotonic-sequence-keyed hash chain, and the
//! in-band `DBMS_APPLICATION_INFO` markers lifted from `plsql-mcp`'s
//! `audit.rs`) lands in P1-4. This is the workspace LEAF the core/db/guard/auth
//! layers depend on, so it imports no other `oraclemcp-*` crate beyond the
//! shared error envelope.

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
