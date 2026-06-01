#![forbid(unsafe_code)]

//! Out-of-band durable audit for the `oraclemcp` server (plan §5.13, §6.4; bead
//! P1-4). The workspace LEAF the core/db/guard/auth layers depend on.
//!
//! The [`Auditor`] writes a tamper-evident, hash-chained record to an
//! out-of-band [`AuditSink`] (an append-only file — never the Oracle session
//! that runs the audited statement). For `Guarded`/`Destructive`/escalation
//! calls the record is **fsynced before the statement executes** (at-least-once
//! log, at-most-once execute); the monotonic sequence number, not the wall
//! timestamp, is the chain's order key (§5.10). Records carry the SQL SHA-256 +
//! a truncated preview, never bind values or secrets.

mod record;
mod sink;

pub use record::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, GENESIS_HASH, sha256_hex,
};
pub use sink::{AuditError, AuditSink, Auditor, FileAuditSink, MemoryAuditSink};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
