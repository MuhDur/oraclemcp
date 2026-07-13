#![forbid(unsafe_code)]

//! Out-of-band durable audit for the `oraclemcp` server (plan §5.13, §6.4; bead
//! P1-4). The workspace LEAF the core/db/guard/auth layers depend on.
//!
//! The [`Auditor`] writes a tamper-evident, hash-chained record to an
//! out-of-band [`AuditSink`] (an append-only file — never the Oracle session
//! that runs the audited statement). For `Guarded`/`Destructive`/escalation
//! calls the record is **fsynced before the statement executes** (at-least-once
//! log, at-most-once execute); the monotonic sequence number, not the wall
//! timestamp, is the chain's order key (§5.10). Current records carry exact and
//! normalized SQL hashes plus a fixed redaction marker, never SQL text, bind
//! values, or secrets. Historical schemas remain verifiable byte-for-byte.

mod anchor;
mod hmac;
mod keyring;
mod record;
mod rekor;
mod shipping;
mod shipping_spool;
mod sink;
mod unified;
mod verify;

pub use anchor::{
    ANCHOR_VERSION, AnchorFile, AnchorLoadError, AnchorReaderError, AnchorStatus, AnchorViolation,
    ChainAnchor, anchor_path_for, check_anchor, check_anchor_reader, load_anchor,
};
pub use hmac::{
    HmacSha256Key, HmacSha256KeyError, MIN_HMAC_SHA256_KEY_BYTES, ct_eq, hmac_sha256,
    hmac_sha256_hex,
};
pub use keyring::{AuditKeyring, AuditKeyringError};
pub use record::{
    AUDIT_SCHEMA_VERSION, AuditCancel, AuditCorrelation, AuditDecision, AuditEntryDraft,
    AuditOutcome, AuditRecord, AuditResultMaskingAction, AuditResultMaskingCertificate,
    AuditResultMaskingColumnDecision, AuditResultMaskingSource, AuditSubject, DbEvidence,
    GENESIS_HASH, SigningKey, SigningKeyError, normalized_sql_sha256, sha256_hex,
};
pub use rekor::{
    AsyncRekorAnchor, AuditChainHead, DEFAULT_REKOR_QUEUE_CAPACITY, MAX_REKOR_CHECKPOINT_BYTES,
    MAX_REKOR_ENTRY_BODY_BYTES, MAX_REKOR_PROOF_HASHES, RekorAnchorReceipt, RekorAnchorStatus,
    RekorCheckpointVerifier, RekorInclusionProof, RekorProofError, RekorSubmitError,
    RekorSubmitter,
};
pub use shipping::{
    ShippingAuditSink, ShippingError, ShippingForwarder, WormFileForwarder, cef_line, syslog_line,
};
pub use shipping_spool::{
    DEFAULT_SPOOL_MAX_RECORDS, DEFAULT_SPOOL_RETRY_INITIAL, DEFAULT_SPOOL_RETRY_MAX,
    DurableShippingForwarder, DurableShippingStatus, DurableShippingStatusHandle,
    DurableSpoolConfig,
};
pub use sink::{AuditError, AuditSink, Auditor, FileAuditSink, MemoryAuditSink};
pub use unified::{UnifiedAuditError, UnifiedAuditPolicy, is_simple_identifier};
pub use verify::{
    BrokenReason, JsonlError, MAX_AUDIT_LINE_LEN, ParseError, VerifyOutcome, parse_jsonl,
    verify_reader, verify_records,
};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
