#![forbid(unsafe_code)]

//! Authentication and step-up confirmation **delivery** for the `oraclemcp`
//! server (plan §7; beads P1-9, P1-10). Depends one-way on `oraclemcp-guard`
//! (auth mints approvals into the guard's token/level types; the guard never
//! depends on auth — no cycle). The server validates tokens, never issues them.
//!
//! Today: the step-up confirmation delivery (MCP elicitation selector +
//! poll/Task). The OAuth 2.1 resource-server / mTLS transport auth (P1-9) builds
//! here on the same one-way dependency.

pub mod http_guard;
pub mod scope;
pub mod secrets;
pub mod stepup_delivery;

pub use http_guard::{HttpGuardError, HttpGuardPolicy, authority_is_loopback};
pub use scope::{apply_oauth_scopes, scope_to_level, scopes_ceiling};
pub use secrets::{Secret, SecretError, SecretRef, resolve_secret};
pub use stepup_delivery::{
    ChallengeRequired, ElicitationRequest, SelectorChoice, to_challenge_required, to_elicitation,
};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
