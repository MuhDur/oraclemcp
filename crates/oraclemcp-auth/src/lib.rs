#![forbid(unsafe_code)]

//! Authentication and step-up confirmation **delivery** for the `oraclemcp`
//! server: transport auth (stdio init-token HMAC, OAuth 2.1 resource-server
//! validation, mTLS), the human step-up confirmation gate (MCP elicitation
//! selector + poll/Task pattern), and secrets backends (keyring/Vault) —
//! plan §7; beads P1-9, P1-10.
//!
//! Phase-A skeleton. Depends one-way on `oraclemcp-guard` (auth mints
//! approvals into the guard's token/level types; the guard never depends on
//! auth — no cycle). The server validates tokens, never issues OAuth tokens.

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
