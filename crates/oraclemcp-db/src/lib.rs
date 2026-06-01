#![forbid(unsafe_code)]

//! Oracle connectivity for the `oraclemcp` server: the `OracleConnection`
//! trait and `RustOracleConnection` driver wrapper (lifted from
//! `plsql-catalog` in P0-3), an `r2d2-oracle` pool behind a `spawn_blocking`
//! boundary, the session-lease primitive (P0-4), and the deterministic
//! type/NLS serializer (P0-5) — plan §4.3, §5.1, §5.2.
//!
//! Phase-A skeleton. An `oracle::Connection` is never held across an `.await`
//! (compiler-enforced by ownership); all DB I/O crosses an explicit
//! `spawn_blocking` boundary.

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
