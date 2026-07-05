#![forbid(unsafe_code)]

//! Structured, agent-facing error envelope for the `oraclemcp` Oracle MCP
//! server (plan §8.2, bead P0-1).
//!
//! The contract: agent-facing failures are returned as an MCP tool result
//! with `isError: true` and an actionable [`ErrorEnvelope`] — **never** as an
//! opaque JSON-RPC numeric error code. Every envelope names a machine-stable
//! [`ErrorClass`], a human/LLM-readable `message`, and a concrete next step
//! (`suggested_tool`, `fuzzy_matches`, or `next_steps`). For example, an
//! Oracle `ORA-00942` becomes
//! `{ "isError": true, "error_class": "OBJECT_NOT_FOUND",
//!    "suggested_tool": "oracle_schema_inspect", "fuzzy_matches": [...] }`.
//!
//! This crate is a leaf of the `oraclemcp-*` core (it imports no other
//! workspace crate) so every layer can produce the same envelope shape
//! without a dependency cycle.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod fuzzy;
pub use fuzzy::{enrich_oracle_error, fuzzy_suggest, levenshtein};

/// Machine-stable classification of an agent-facing error.
///
/// Serialized as `SCREAMING_SNAKE_CASE` so the wire value is a stable string
/// an agent can branch on (`"OBJECT_NOT_FOUND"`, `"CHALLENGE_REQUIRED"`, …).
/// `#[non_exhaustive]` so new classes are additive, never breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorClass {
    /// Referenced schema object does not exist / is not visible (ORA-00942,
    /// ORA-04043). The agent should introspect, not retry verbatim.
    ObjectNotFound,
    /// The connected user lacks the required Oracle privilege (ORA-01031,
    /// ORA-01017, ORA-00942 on a privileged dictionary view).
    InsufficientPrivilege,
    /// The statement failed to parse / is not valid SQL or PL/SQL.
    SyntaxError,
    /// The server could not connect to / lost its connection to Oracle.
    ConnectionFailed,
    /// A tool was dispatched but requires runtime state that is absent — most
    /// often a live Oracle connection (the offline `RuntimeStateRequired`
    /// degradation contract).
    RuntimeStateRequired,
    /// The operation requires a human step-up confirmation that has not yet
    /// been granted; the agent should poll the issued task (§7.2).
    ChallengeRequired,
    /// A stateful operation (transaction, savepoint, DBMS_OUTPUT) was attempted
    /// without an active session lease (§5.1).
    LeaseRequired,
    /// The fail-closed classifier refused the statement outright (§5.3) — e.g.
    /// dynamic SQL via string concat, an unbalanced multi-statement batch.
    ForbiddenStatement,
    /// The required operating level exceeds the session's current level and the
    /// profile's gate has not been satisfied (§6.6).
    OperatingLevelTooLow,
    /// Admission control rejected the call before it touched the pool (§5.6).
    Busy,
    /// Capacity admission refused a new lane/connection before touching Oracle.
    AtCapacity,
    /// The request arguments were malformed or failed validation.
    InvalidArguments,
    /// A configured per-schema / `protected`-profile policy denied the call
    /// (§6.2).
    PolicyDenied,
    /// The call exceeded its deadline (call timeout / cancellation).
    Timeout,
    /// A transient, retryable Oracle/network condition (ORA-03113, ORA-12170…).
    Transient,
    /// An unexpected internal error; the agent cannot fix it by changing input.
    Internal,
}

impl ErrorClass {
    /// The default built-in tool an agent should reach for to recover from
    /// this class, if any.
    #[must_use]
    pub fn default_suggested_tool(self) -> Option<&'static str> {
        match self {
            ErrorClass::ObjectNotFound => Some("oracle_schema_inspect"),
            ErrorClass::OperatingLevelTooLow | ErrorClass::ChallengeRequired => {
                Some("oracle_session")
            }
            ErrorClass::RuntimeStateRequired | ErrorClass::ConnectionFailed => {
                Some("oracle_connect")
            }
            _ => None,
        }
    }

    /// Whether a caller may safely retry the *same* request later. Note this is
    /// about the error condition only; DML is never auto-retried regardless
    /// (§5.7) — that decision lives at the dispatch layer.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            ErrorClass::Busy | ErrorClass::AtCapacity | ErrorClass::Transient | ErrorClass::Timeout
        )
    }
}

/// The actionable, agent-facing error payload (plan §8.2).
///
/// `is_error` is serialized as `isError` to match the MCP tool-result shape.
/// Empty optional fields are omitted from the wire form so envelopes stay
/// terse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    /// Always `true`; marks the MCP tool result as an error.
    #[serde(rename = "isError")]
    pub is_error: bool,
    /// The machine-stable class.
    pub error_class: ErrorClass,
    /// Human/LLM-readable explanation. Never contains bind values or secrets.
    pub message: String,
    /// The originating Oracle `ORA-` code, when the error came from the DB.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ora_code: Option<i32>,
    /// The single best tool to call next.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suggested_tool: Option<String>,
    /// Near-miss candidates (e.g. similarly-named objects) for `ObjectNotFound`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fuzzy_matches: Vec<String>,
    /// Ordered, concrete remediation steps an agent can follow.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub next_steps: Vec<String>,
    /// For `Busy`/`Transient`: how long to wait before retrying.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retry_after_ms: Option<u64>,
}

impl ErrorEnvelope {
    /// Construct a new envelope of the given class with a message, deriving the
    /// default suggested tool for the class.
    #[must_use]
    pub fn new(error_class: ErrorClass, message: impl Into<String>) -> Self {
        ErrorEnvelope {
            is_error: true,
            error_class,
            message: message.into(),
            ora_code: None,
            suggested_tool: error_class.default_suggested_tool().map(str::to_owned),
            fuzzy_matches: Vec::new(),
            next_steps: Vec::new(),
            retry_after_ms: None,
        }
    }

    /// Attach the originating Oracle error code.
    #[must_use]
    pub fn with_ora_code(mut self, code: i32) -> Self {
        self.ora_code = Some(code);
        self
    }

    /// Override the suggested tool.
    #[must_use]
    pub fn with_suggested_tool(mut self, tool: impl Into<String>) -> Self {
        self.suggested_tool = Some(tool.into());
        self
    }

    /// Attach fuzzy near-miss candidates.
    #[must_use]
    pub fn with_fuzzy_matches(mut self, matches: Vec<String>) -> Self {
        self.fuzzy_matches = matches;
        self
    }

    /// Append a remediation step.
    #[must_use]
    pub fn with_next_step(mut self, step: impl Into<String>) -> Self {
        self.next_steps.push(step.into());
        self
    }

    /// Attach a retry-after hint (milliseconds).
    #[must_use]
    pub fn with_retry_after_ms(mut self, ms: u64) -> Self {
        self.retry_after_ms = Some(ms);
        self
    }

    /// Render as a `serde_json::Value` for embedding in an MCP tool result.
    ///
    /// # Panics
    /// Never in practice — the envelope is composed of plain owned data that
    /// always serializes; a failure would indicate a serde bug, which we
    /// surface as a deterministic fallback object rather than unwrapping.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "isError": true,
                "error_class": "INTERNAL",
                "message": "error envelope failed to serialize",
            })
        })
    }
}

/// Parse the leading `ORA-NNNNN` code from an Oracle error message, if present.
///
/// `"ORA-00942: table or view does not exist"` → `Some(942)`.
#[must_use]
pub fn parse_ora_code(message: &str) -> Option<i32> {
    let idx = message.find("ORA-")?;
    let digits: String = message[idx + 4..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<i32>().ok()
    }
}

/// Map a numeric Oracle error code to its [`ErrorClass`].
///
/// Conservative by design: anything not explicitly recognised falls to
/// [`ErrorClass::Internal`] (an honest "we don't classify this yet") rather
/// than guessing a friendlier class.
#[must_use]
pub fn classify_ora_code(code: i32) -> ErrorClass {
    match code {
        // Object resolution (handled before the 900..=999 syntax range so
        // ORA-00942 classifies as a missing object, not a syntax error).
        942 | 4043 => ErrorClass::ObjectNotFound,
        // Privilege / authentication — all TERMINAL (never auto-retried; not in
        // resilience.rs TRANSIENT_ORA_CODES), so a wrong password or a locked
        // account can never drive a reconnect loop that locks the account harder.
        //   1031 insufficient privileges · 1017 invalid credential · 1045 no
        //   CREATE SESSION · 28009 must connect AS SYSDBA/SYSOPER.
        // Account/password lifecycle (multi-pass 2026-07): these previously fell
        // through to Internal and were rewritten on the connect path to
        // `ConnectionFailed` with "verify the connect string … reconnect" —
        // confidently WRONG guidance (a reconnect never clears a locked account or
        // an expired password; a DBA unlock / password change is required).
        // Classifying them as a terminal auth failure stops the misdirection and
        // keeps them non-retryable; the raw `ORA-2800x`/`ORA-01005` message (e.g.
        // "the account is locked") is still surfaced verbatim so the agent /
        // operator sees the real cause.
        //   28000 account locked · 28001 password expired · 28002 grace period ·
        //   28011 password will expire soon · 1005 null password given.
        1031 | 1017 | 1045 | 28009 | 28000 | 28001 | 28002 | 28011 | 1005 => {
            ErrorClass::InsufficientPrivilege
        }
        // Read-only transaction violation (SET TRANSACTION READ ONLY, §6.3).
        1456 | 16000 => ErrorClass::ForbiddenStatement,
        // Connection / network — transient & retryable.
        3113 | 3114 | 12170 | 12541 | 12514 | 12537 | 12543 => ErrorClass::Transient,
        // Listener / session limits — admission backpressure.
        12519 | 18 | 20 => ErrorClass::Busy,
        // Syntax / parse family (942 already matched above).
        900..=999 => ErrorClass::SyntaxError,
        // Anything else from Oracle: not yet classified — honest Internal.
        _ => ErrorClass::Internal,
    }
}

/// Build an agent-facing envelope from a raw Oracle error message, classifying
/// the `ORA-` code and seeding the default suggested tool.
#[must_use]
pub fn envelope_from_oracle_message(message: &str) -> ErrorEnvelope {
    match parse_ora_code(message) {
        Some(code) => {
            let class = classify_ora_code(code);
            ErrorEnvelope::new(class, message.to_owned()).with_ora_code(code)
        }
        None => ErrorEnvelope::new(ErrorClass::Internal, message.to_owned()),
    }
}

/// Library-side error type for `?`-propagation across the `oraclemcp` core.
///
/// Distinct from [`ErrorEnvelope`]: this is the internal `Result` error;
/// [`OracleMcpError::into_envelope`] renders the agent-facing shape at the
/// tool boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OracleMcpError {
    /// A raw Oracle driver/DB error (its `ORA-` code is parsed on conversion).
    #[error("oracle error: {0}")]
    Oracle(String),
    /// A referenced object was not found; carries near-miss candidates.
    #[error("object not found: {name}")]
    ObjectNotFound {
        /// The object the caller asked for.
        name: String,
        /// Near-miss candidates for the agent to consider.
        fuzzy_matches: Vec<String>,
    },
    /// The connected user lacks a required privilege.
    #[error("insufficient privilege: {0}")]
    InsufficientPrivilege(String),
    /// The statement failed the fail-closed classifier.
    #[error("statement refused by guard: {0}")]
    ForbiddenStatement(String),
    /// A stateful operation needs a lease.
    #[error("session lease required: {0}")]
    LeaseRequired(String),
    /// Required operating level exceeds the current level.
    #[error("operating level too low: {0}")]
    OperatingLevelTooLow(String),
    /// A human step-up confirmation is required.
    #[error("challenge required: {0}")]
    ChallengeRequired(String),
    /// Live runtime state (e.g. an Oracle connection) is required.
    #[error("runtime state required: {0}")]
    RuntimeStateRequired(String),
    /// Admission control rejected the call.
    #[error("server busy")]
    Busy {
        /// Suggested wait before retrying.
        retry_after_ms: u64,
    },
    /// Invalid request arguments.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    /// A policy denied the call.
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    /// An internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl OracleMcpError {
    /// Render the agent-facing [`ErrorEnvelope`].
    #[must_use]
    pub fn into_envelope(self) -> ErrorEnvelope {
        match self {
            OracleMcpError::Oracle(msg) => envelope_from_oracle_message(&msg),
            OracleMcpError::ObjectNotFound {
                name,
                fuzzy_matches,
            } => ErrorEnvelope::new(
                ErrorClass::ObjectNotFound,
                format!("object not found: {name}"),
            )
            .with_fuzzy_matches(fuzzy_matches),
            OracleMcpError::InsufficientPrivilege(msg) => {
                ErrorEnvelope::new(ErrorClass::InsufficientPrivilege, msg)
            }
            OracleMcpError::ForbiddenStatement(msg) => {
                ErrorEnvelope::new(ErrorClass::ForbiddenStatement, msg)
            }
            OracleMcpError::LeaseRequired(msg) => {
                ErrorEnvelope::new(ErrorClass::LeaseRequired, msg)
                    .with_next_step("call oracle_session(acquire_lease) and pass the lease_id")
            }
            OracleMcpError::OperatingLevelTooLow(msg) => {
                ErrorEnvelope::new(ErrorClass::OperatingLevelTooLow, msg)
                    .with_next_step("call oracle_session(escalate, target=<level>)")
            }
            OracleMcpError::ChallengeRequired(msg) => {
                ErrorEnvelope::new(ErrorClass::ChallengeRequired, msg)
            }
            OracleMcpError::RuntimeStateRequired(msg) => {
                ErrorEnvelope::new(ErrorClass::RuntimeStateRequired, msg)
            }
            OracleMcpError::Busy { retry_after_ms } => {
                ErrorEnvelope::new(ErrorClass::Busy, "server busy")
                    .with_retry_after_ms(retry_after_ms)
            }
            OracleMcpError::InvalidArguments(msg) => {
                ErrorEnvelope::new(ErrorClass::InvalidArguments, msg)
            }
            OracleMcpError::PolicyDenied(msg) => ErrorEnvelope::new(ErrorClass::PolicyDenied, msg),
            OracleMcpError::Internal(msg) => ErrorEnvelope::new(ErrorClass::Internal, msg),
        }
    }
}

/// Convenience alias for fallible `oraclemcp` core operations.
pub type Result<T> = std::result::Result<T, OracleMcpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ora_code_extracts_leading_code() {
        assert_eq!(
            parse_ora_code("ORA-00942: table or view does not exist"),
            Some(942)
        );
        assert_eq!(
            parse_ora_code("foo ORA-1031: insufficient privileges"),
            Some(1031)
        );
        assert_eq!(parse_ora_code("no oracle code here"), None);
        assert_eq!(parse_ora_code("ORA-: malformed"), None);
    }

    #[test]
    fn classify_known_codes() {
        assert_eq!(classify_ora_code(942), ErrorClass::ObjectNotFound);
        assert_eq!(classify_ora_code(4043), ErrorClass::ObjectNotFound);
        assert_eq!(classify_ora_code(1031), ErrorClass::InsufficientPrivilege);
        assert_eq!(classify_ora_code(1456), ErrorClass::ForbiddenStatement);
        assert_eq!(classify_ora_code(3113), ErrorClass::Transient);
        assert_eq!(classify_ora_code(12519), ErrorClass::Busy);
        assert_eq!(classify_ora_code(923), ErrorClass::SyntaxError);
        assert_eq!(classify_ora_code(7777), ErrorClass::Internal);
    }

    #[test]
    fn account_lifecycle_codes_are_terminal_auth_not_retryable_connection_failures() {
        // multi-pass 2026-07: these must classify as a terminal auth failure, NOT
        // fall to Internal (which the connect path rewrites to a retry-oriented
        // ConnectionFailed with reconnect guidance). They must never be retryable.
        for code in [28000, 28001, 28002, 28011, 1005, 1017, 1045, 28009] {
            let class = classify_ora_code(code);
            assert_eq!(
                class,
                ErrorClass::InsufficientPrivilege,
                "ORA-{code:05} must be a terminal auth failure"
            );
            assert!(
                !class.is_retryable(),
                "auth failure ORA-{code:05} must never be retryable (no lockout amplification)"
            );
            // And never mis-guides the agent to reconnect.
            assert_eq!(class.default_suggested_tool(), None);
        }
        // A raw locked-account message classifies end-to-end without misdirection.
        let env = envelope_from_oracle_message("ORA-28000: the account is locked");
        assert_eq!(env.error_class, ErrorClass::InsufficientPrivilege);
        assert_eq!(env.ora_code, Some(28000));
    }

    #[test]
    fn object_not_found_envelope_golden() {
        let env = ErrorEnvelope::new(ErrorClass::ObjectNotFound, "object not found: EMPLOYES")
            .with_ora_code(942)
            .with_fuzzy_matches(vec!["EMPLOYEES".to_owned(), "EMPLOYEE".to_owned()]);
        let json = serde_json::to_value(&env).expect("serialize");
        assert_eq!(json["isError"], serde_json::json!(true));
        assert_eq!(json["error_class"], serde_json::json!("OBJECT_NOT_FOUND"));
        assert_eq!(json["ora_code"], serde_json::json!(942));
        assert_eq!(
            json["suggested_tool"],
            serde_json::json!("oracle_schema_inspect")
        );
        assert_eq!(
            json["fuzzy_matches"],
            serde_json::json!(["EMPLOYEES", "EMPLOYEE"])
        );
        // next_steps and retry_after_ms are omitted when empty.
        assert!(json.get("next_steps").is_none());
        assert!(json.get("retry_after_ms").is_none());
    }

    #[test]
    fn busy_envelope_carries_retry_after() {
        let env = OracleMcpError::Busy {
            retry_after_ms: 250,
        }
        .into_envelope();
        let json = serde_json::to_value(&env).expect("serialize");
        assert_eq!(json["error_class"], serde_json::json!("BUSY"));
        assert_eq!(json["retry_after_ms"], serde_json::json!(250));
    }

    #[test]
    fn oracle_message_roundtrips_through_envelope() {
        let env = OracleMcpError::Oracle("ORA-00942: table or view does not exist".to_owned())
            .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
        assert_eq!(env.ora_code, Some(942));
        assert_eq!(env.suggested_tool.as_deref(), Some("oracle_schema_inspect"));
    }

    #[test]
    fn envelope_serde_roundtrip_is_stable() {
        let env = ErrorEnvelope::new(ErrorClass::LeaseRequired, "needs a lease")
            .with_next_step("call oracle_session(acquire_lease)");
        let json = serde_json::to_string(&env).expect("serialize");
        let back: ErrorEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, back);
    }

    #[test]
    fn retryability_matches_class() {
        assert!(ErrorClass::Busy.is_retryable());
        assert!(ErrorClass::AtCapacity.is_retryable());
        assert!(ErrorClass::Transient.is_retryable());
        assert!(!ErrorClass::ObjectNotFound.is_retryable());
        assert!(!ErrorClass::ForbiddenStatement.is_retryable());
    }
}
