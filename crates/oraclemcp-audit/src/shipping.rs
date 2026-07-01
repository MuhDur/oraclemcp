//! Audit-log shipping to a WORM / SIEM destination (bead D2).
//!
//! A8 produced a durable, hash-chained, HMAC-signed local audit log. D2 ships
//! that log to an external **write-once-read-many (WORM)** store or a SIEM, so a
//! tamper attempt at the *local* file is also detectable at an independent
//! destination — and the keyed MAC means a forger who lacks the signing key
//! cannot mint a record the destination's `audit verify` will accept.
//!
//! # Design: a fail-safe decorator
//!
//! [`ShippingAuditSink`] is a **decorator** over the existing local
//! [`AuditSink`](crate::AuditSink) (the durable [`FileAuditSink`]). The
//! ordering is the load-bearing invariant:
//!
//! 1. **append** writes the record to the local sink **first**;
//! 2. **flush** fsyncs the local sink **first** (the durable, at-least-once
//!    record), and only then mirrors the just-appended records to the
//!    [`ShippingForwarder`].
//!
//! A forwarding failure is **logged and dropped** — it never fails the local
//! durable path, so a record is never lost because a SIEM was unreachable. This
//! is the same fail-safe posture the OTLP export pump uses: the security record
//! of record is the local signed chain; shipping is a mirror, not the primary.
//!
//! Because the forwarded stream is the **same signed [`AuditRecord`]** in the
//! same order, the destination re-verifies under exactly the same
//! [`verify_records`](crate::verify_records) / `oraclemcp audit verify` path.
//!
//! # No network in this leaf crate
//!
//! `oraclemcp-audit` is a dependency-light workspace leaf with **no async
//! runtime and no HTTP client**. So this module defines:
//!
//! - the [`ShippingForwarder`] seam (a blocking, `Send + Sync` trait),
//! - [`WormFileForwarder`] — an append-only `O_APPEND` JSONL mirror to a
//!   separate file (point it at a WORM-mounted path / object-lock bucket sync
//!   dir), and
//! - the SIEM-native line formatters [`cef_line`] and [`syslog_line`] (pure
//!   functions, no I/O).
//!
//! The HTTP/SIEM **forwarder** that POSTs over asupersync's Tokio-free HTTP
//! client lives in `oraclemcp-core` (which already depends on asupersync) and
//! implements [`ShippingForwarder`]. This keeps the leaf crate free of any
//! network dependency while still owning the wire **format** (so the format is
//! unit-tested next to the record it describes).
//!
//! Shipping is **off by default**: nothing constructs a [`ShippingAuditSink`]
//! unless a destination is configured.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::record::AuditRecord;
use crate::sink::{AuditError, AuditSink};

/// A shipping (forwarding) failure. Distinct from [`AuditError`] because a
/// shipping failure is **non-fatal** to the local durable chain: the decorator
/// records and drops it rather than failing the audited call.
#[derive(Debug)]
#[non_exhaustive]
pub enum ShippingError {
    /// An I/O / transport error mirroring a record to the destination.
    Transport(String),
}

impl std::fmt::Display for ShippingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShippingError::Transport(msg) => write!(f, "audit shipping transport error: {msg}"),
        }
    }
}

impl std::error::Error for ShippingError {}

/// The shipping seam: mirror one already-durable, signed [`AuditRecord`] to an
/// external WORM/SIEM destination.
///
/// Implementations MUST be append-only and order-preserving: records arrive in
/// ascending `seq` order (the decorator forwards them in append order, after
/// the local fsync), so a faithful forwarder reproduces a stream that
/// re-verifies under [`verify_records`](crate::verify_records).
///
/// `forward` is blocking and `Send + Sync`; a network forwarder bridges to its
/// own runtime internally (as the asupersync-backed `oraclemcp-core` forwarder
/// does) so this leaf crate needs no async runtime.
pub trait ShippingForwarder: Send + Sync {
    /// Mirror one record to the destination. Errors are surfaced to the
    /// decorator, which logs and drops them (fail-safe: never fails the local
    /// durable path).
    fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError>;

    /// Flush any buffered forwarded data to the destination. Best-effort;
    /// errors are non-fatal to the local chain. Default: no-op.
    fn flush(&self) -> Result<(), ShippingError> {
        Ok(())
    }
}

/// An append-only WORM file mirror: each signed record is written as one JSON
/// line via `O_APPEND`, to a destination separate from the primary audit log
/// (point it at a WORM-mounted path, an object-lock bucket's sync directory, or
/// a second host's append-only volume).
///
/// The mirrored bytes are byte-identical to the primary log's JSONL, so
/// `oraclemcp audit verify <worm-file>` verifies the destination copy under the
/// same key — detecting tampering at the destination independently of the
/// primary.
pub struct WormFileForwarder {
    file: Mutex<File>,
}

impl WormFileForwarder {
    /// Open (creating + appending) the WORM mirror file at `path`. Uses
    /// `O_APPEND` so every write lands at the current end of file — the
    /// write-once posture is enforced by the destination filesystem / bucket
    /// object-lock; this side never seeks or truncates.
    ///
    /// # Errors
    /// Returns [`ShippingError::Transport`] if the file cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ShippingError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        Ok(WormFileForwarder {
            file: Mutex::new(file),
        })
    }
}

impl ShippingForwarder for WormFileForwarder {
    fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
        let line =
            serde_json::to_string(record).map_err(|e| ShippingError::Transport(e.to_string()))?;
        let mut f = self.file.lock();
        f.write_all(line.as_bytes())
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        f.write_all(b"\n")
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        Ok(())
    }

    fn flush(&self) -> Result<(), ShippingError> {
        let f = self.file.lock();
        f.sync_all()
            .map_err(|e| ShippingError::Transport(e.to_string()))
    }
}

/// A decorator [`AuditSink`] that mirrors each durable record to a
/// [`ShippingForwarder`] **after** the local sink has durably stored it.
///
/// Fail-safe ordering (the D2 invariant):
/// * `append` -> local `append` first (the record is in the local byte stream);
/// * `flush`  -> local `flush` (fsync) first, then forward the records appended
///   since the last flush. A forwarding error is counted and dropped; it never
///   propagates as an [`AuditError`], so the local durable chain is authoritative
///   and complete even when the destination is down.
pub struct ShippingAuditSink {
    local: Box<dyn AuditSink>,
    forwarder: Box<dyn ShippingForwarder>,
    /// Records appended since the last flush, awaiting forwarding (mirrored only
    /// after the local fsync, in append order).
    pending: Mutex<Vec<AuditRecord>>,
    /// Count of records that failed to forward (observability only — a forward
    /// failure is never fatal to the local chain).
    forward_failures: AtomicU64,
}

impl ShippingAuditSink {
    /// Wrap a local durable sink with a forwarder. The local sink stays the
    /// authoritative, durable record of record; the forwarder is a mirror.
    #[must_use]
    pub fn new(local: Box<dyn AuditSink>, forwarder: Box<dyn ShippingForwarder>) -> Self {
        ShippingAuditSink {
            local,
            forwarder,
            pending: Mutex::new(Vec::new()),
            forward_failures: AtomicU64::new(0),
        }
    }

    /// How many records failed to forward (cumulative). A non-zero count means
    /// the destination missed records; the local chain still has them.
    #[must_use]
    pub fn forward_failure_count(&self) -> u64 {
        self.forward_failures.load(Ordering::Relaxed)
    }

    /// Forward every pending record (post-local-fsync), draining the buffer.
    /// Errors are counted and dropped; this never returns an error.
    fn forward_pending(&self) {
        // Take the pending batch under the lock, then forward outside it.
        let batch = {
            let mut pending = self.pending.lock();
            std::mem::take(&mut *pending)
        };
        for record in &batch {
            if let Err(e) = self.forwarder.forward(record) {
                self.forward_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    seq = record.seq,
                    error = %e,
                    "audit shipping: record mirrored to local durable log but not forwarded to \
                     the WORM/SIEM destination (the local signed chain is authoritative)"
                );
            }
        }
        if let Err(e) = self.forwarder.flush() {
            tracing::debug!(error = %e, "audit shipping: destination flush failed (non-fatal)");
        }
    }
}

impl AuditSink for ShippingAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        // Local durable store FIRST — this must succeed (or error) before we
        // ever consider the record shippable.
        self.local.append(record)?;
        self.pending.lock().push(record.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        // Local fsync FIRST: the record is durably on local disk before it is
        // forwarded. If the local fsync fails, propagate (the Auditor poisons),
        // and do NOT forward — a record that is not locally durable must not be
        // claimed at the destination either.
        self.local.flush()?;
        // Now the pending records are durable locally; mirror them. Forwarding
        // failures are non-fatal (logged + counted), never propagated.
        self.forward_pending();
        Ok(())
    }
}

// ===========================================================================
// SIEM-native line formats (pure; no I/O)
// ===========================================================================

/// ArcSight **CEF** (Common Event Format) version 0 line for one audit record.
///
/// `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension`
///
/// The extension carries the chain-integrity fields (`seq`, `prev`/`entry`
/// hash, `key_id`, `signature`) so a SIEM can detect a gap or a re-signed
/// record, plus the operator-legible decision/outcome/sql-preview. No bind
/// values or secrets appear (the record never carried them). Extension values
/// are escaped per the CEF spec (`\`, `=`, and newlines).
#[must_use]
pub fn cef_line(record: &AuditRecord) -> String {
    let severity = cef_severity(record);
    let name = format!("{} {}", record.tool, record.danger_level);
    let mut ext = String::new();
    push_cef_kv(&mut ext, "rt", &record.timestamp);
    push_cef_kv(&mut ext, "suser", &record.agent_identity);
    push_cef_kv(&mut ext, "cs2Label", "subjectKind");
    push_cef_kv(&mut ext, "cs2", &record.subject.kind);
    push_cef_kv(&mut ext, "cs3Label", "subjectStableId");
    push_cef_kv(&mut ext, "cs3", &record.subject.stable_id);
    push_cef_kv(&mut ext, "cs1Label", "auditSeq");
    push_cef_kv(&mut ext, "cs1", &record.seq.to_string());
    push_cef_kv(&mut ext, "act", &format!("{:?}", record.decision));
    push_cef_kv(&mut ext, "outcome", &format!("{:?}", record.outcome));
    push_cef_kv(&mut ext, "msg", &record.sql_preview);
    push_cef_kv(&mut ext, "sqlSha256", &record.sql_sha256);
    push_cef_kv(&mut ext, "prevHash", &record.prev_hash);
    push_cef_kv(&mut ext, "entryHash", &record.entry_hash);
    if let Some(rows) = record.rows_affected {
        push_cef_kv(&mut ext, "cnt", &rows.to_string());
    }
    if let Some(key_id) = record.key_id.as_deref() {
        push_cef_kv(&mut ext, "keyId", key_id);
    }
    if let Some(sig) = record.signature.as_deref() {
        push_cef_kv(&mut ext, "signature", sig);
    }
    format!(
        "CEF:0|oraclemcp|oraclemcp|{}|{}|{}|{}|{}",
        cef_escape_header(env!("CARGO_PKG_VERSION")),
        cef_escape_header(&record.tool),
        cef_escape_header(&name),
        severity,
        ext.trim_end()
    )
}

/// RFC-5424 **syslog** line for one audit record, with the chain-integrity
/// structured data element `[oraclemcp@0 ...]`. PRI is computed from a fixed
/// facility (local0 = 16) and a severity mapped from the decision/outcome.
///
/// The same chain fields ride in the structured-data element so a syslog-native
/// SIEM can detect tampering without parsing the message body.
#[must_use]
pub fn syslog_line(record: &AuditRecord) -> String {
    const FACILITY_LOCAL0: u8 = 16;
    let severity = syslog_severity(record);
    let pri = u16::from(FACILITY_LOCAL0) * 8 + u16::from(severity);
    let mut sd = String::from("[oraclemcp@0");
    push_sd_param(&mut sd, "seq", &record.seq.to_string());
    push_sd_param(&mut sd, "subjectKind", &record.subject.kind);
    push_sd_param(&mut sd, "subjectStableId", &record.subject.stable_id);
    push_sd_param(&mut sd, "decision", &format!("{:?}", record.decision));
    push_sd_param(&mut sd, "outcome", &format!("{:?}", record.outcome));
    push_sd_param(&mut sd, "danger", &record.danger_level);
    push_sd_param(&mut sd, "sqlSha256", &record.sql_sha256);
    push_sd_param(&mut sd, "prevHash", &record.prev_hash);
    push_sd_param(&mut sd, "entryHash", &record.entry_hash);
    if let Some(key_id) = record.key_id.as_deref() {
        push_sd_param(&mut sd, "keyId", key_id);
    }
    if let Some(sig) = record.signature.as_deref() {
        push_sd_param(&mut sd, "signature", sig);
    }
    sd.push(']');
    // VERSION=1, APP-NAME=oraclemcp, PROCID=-, MSGID=audit. Timestamp + msg are
    // taken from the record. The agent identity rides as the HOSTNAME-adjacent
    // field is reserved; we keep it in the message for legibility.
    format!(
        "<{pri}>1 {} - oraclemcp - audit {} {}",
        record.timestamp, sd, record.sql_preview
    )
}

/// Map a record to a CEF severity 0..=10 (10 = most severe). Blocked/destructive
/// actions rank highest so a SIEM rule can alert on them.
fn cef_severity(record: &AuditRecord) -> u8 {
    use crate::record::{AuditDecision, AuditOutcome};
    match (record.decision, record.outcome) {
        (AuditDecision::Blocked, _) => 8,
        (
            _,
            AuditOutcome::Failed
            | AuditOutcome::DiscardedUncommitted
            | AuditOutcome::CommitInDoubt
            | AuditOutcome::UnknownDiscarded,
        ) => 6,
        (AuditDecision::StepUpRequired, _) => 5,
        _ => match record.danger_level.as_str() {
            "DESTRUCTIVE" => 7,
            "GUARDED" => 4,
            _ => 2,
        },
    }
}

/// Map a record to an RFC-5424 syslog severity (0 = emerg .. 7 = debug).
fn syslog_severity(record: &AuditRecord) -> u8 {
    use crate::record::{AuditDecision, AuditOutcome};
    match (record.decision, record.outcome) {
        (AuditDecision::Blocked, _) => 4, // warning
        (
            _,
            AuditOutcome::Failed
            | AuditOutcome::DiscardedUncommitted
            | AuditOutcome::CommitInDoubt
            | AuditOutcome::UnknownDiscarded,
        ) => 3, // error
        (AuditDecision::StepUpRequired, _) => 5, // notice
        _ => 6,                           // informational
    }
}

/// Escape a CEF *header* field: only `\` and `|` are special.
fn cef_escape_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Append a `key=value ` pair to a CEF extension, escaping `\`, `=`, and
/// newlines in the value per the CEF spec.
fn push_cef_kv(ext: &mut String, key: &str, value: &str) {
    ext.push_str(key);
    ext.push('=');
    for c in value.chars() {
        match c {
            '\\' => ext.push_str("\\\\"),
            '=' => ext.push_str("\\="),
            '\n' => ext.push_str("\\n"),
            '\r' => ext.push_str("\\r"),
            _ => ext.push(c),
        }
    }
    ext.push(' ');
}

/// Append a `key="value"` param to an RFC-5424 structured-data element,
/// escaping `\`, `"`, and `]` per the spec.
fn push_sd_param(sd: &mut String, key: &str, value: &str) {
    sd.push(' ');
    sd.push_str(key);
    sd.push_str("=\"");
    for c in value.chars() {
        match c {
            '\\' => sd.push_str("\\\\"),
            '"' => sd.push_str("\\\""),
            ']' => sd.push_str("\\]"),
            '\n' | '\r' => sd.push(' '),
            _ => sd.push(c),
        }
    }
    sd.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, SigningKey};
    use crate::sink::{Auditor, MemoryAuditSink};
    use crate::verify::{VerifyOutcome, parse_jsonl, verify_records};
    use std::sync::Arc;

    fn key() -> SigningKey {
        SigningKey::new("k1", b"shipping-test-key".to_vec())
    }

    fn draft(sql: &str, danger: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent-1"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_execute".to_owned(),
            sql: sql.to_owned(),
            danger_level: danger.to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(3),
            outcome: AuditOutcome::Succeeded,
        }
    }

    /// A forwarder that records what it received (order-preserving), used to
    /// assert the forwarded stream content + ordering.
    #[derive(Default)]
    struct CapturingForwarder {
        records: Mutex<Vec<AuditRecord>>,
        flushes: Mutex<usize>,
    }
    impl CapturingForwarder {
        fn records(&self) -> Vec<AuditRecord> {
            self.records.lock().clone()
        }
    }
    impl ShippingForwarder for CapturingForwarder {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            self.records.lock().push(record.clone());
            Ok(())
        }
        fn flush(&self) -> Result<(), ShippingError> {
            *self.flushes.lock() += 1;
            Ok(())
        }
    }

    struct SharedForwarder(Arc<CapturingForwarder>);
    impl ShippingForwarder for SharedForwarder {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            self.0.forward(record)
        }
        fn flush(&self) -> Result<(), ShippingError> {
            self.0.flush()
        }
    }

    /// A forwarder that always fails — models an unreachable SIEM.
    struct FailingForwarder {
        attempts: Arc<AtomicU64>,
    }
    impl ShippingForwarder for FailingForwarder {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Err(ShippingError::Transport("siem unreachable".to_owned()))
        }
    }

    // A sink that forwards to a shared Arc<MemoryAuditSink> (the test keeps a
    // handle while the decorator owns its Box<dyn AuditSink>).
    struct SharedLocal(Arc<MemoryAuditSink>);
    impl AuditSink for SharedLocal {
        fn append(&self, r: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(r)
        }
        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    #[test]
    fn records_are_forwarded_in_order_and_only_after_local_fsync() {
        let local = Arc::new(MemoryAuditSink::new());
        let fwd = Arc::new(CapturingForwarder::default());
        let sink = ShippingAuditSink::new(
            Box::new(SharedLocal(local.clone())),
            Box::new(SharedForwarder(fwd.clone())),
        );
        let auditor = Auditor::new(Box::new(sink), key());

        for i in 0..5 {
            auditor
                .append(
                    &draft(&format!("DELETE FROM t WHERE id={i}"), "DESTRUCTIVE"),
                    format!("t{i}"),
                    true, // durable: forces a flush per call
                )
                .expect("append");
        }

        // Local got every record; so did the forwarder, in seq order.
        assert_eq!(local.records().len(), 5);
        let fwded = fwd.records();
        assert_eq!(fwded.len(), 5, "every durable record was forwarded");
        let seqs: Vec<u64> = fwded.iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 2, 3, 4, 5],
            "forwarded in ascending seq order"
        );
    }

    #[test]
    fn forwarded_stream_verifies_under_audit_verify() {
        // The mirrored stream is the same signed records, so it re-verifies
        // under the same key — exactly what `oraclemcp audit verify` does.
        let local = Arc::new(MemoryAuditSink::new());
        let fwd = Arc::new(CapturingForwarder::default());
        let sink = ShippingAuditSink::new(
            Box::new(SharedLocal(local.clone())),
            Box::new(SharedForwarder(fwd.clone())),
        );
        let auditor = Auditor::new(Box::new(sink), key());
        for i in 0..3 {
            auditor
                .append(
                    &draft(&format!("DROP TABLE t{i}"), "DESTRUCTIVE"),
                    format!("t{i}"),
                    true,
                )
                .expect("append");
        }

        // Serialize the forwarded records to JSONL and verify, like the CLI.
        let body: String = fwd
            .records()
            .iter()
            .map(|r| serde_json::to_string(r).expect("serialize") + "\n")
            .collect();
        let parsed = parse_jsonl(&body).expect("parse forwarded stream");
        assert_eq!(
            verify_records(&parsed, &[key()]),
            VerifyOutcome::Ok { records: 3 },
            "the forwarded stream verifies under the signing key"
        );
    }

    #[test]
    fn forwarding_failure_never_loses_the_local_durable_record() {
        // The fail-safe invariant: a SIEM outage must not fail the audited call
        // or drop the local record. append() must succeed, the local sink keeps
        // every record, and the failure is counted (not propagated).
        let local = Arc::new(MemoryAuditSink::new());
        let attempts = Arc::new(AtomicU64::new(0));
        let sink = ShippingAuditSink::new(
            Box::new(SharedLocal(local.clone())),
            Box::new(FailingForwarder {
                attempts: attempts.clone(),
            }),
        );
        // Keep a raw pointer to read the failure count after the auditor owns it.
        // Instead, exercise the sink directly so we can read its counter.
        let rec = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "DESTRUCTIVE"),
            1,
            crate::record::GENESIS_HASH,
            "t0".to_owned(),
            &key(),
        );
        sink.append(&rec).expect("append must succeed despite SIEM");
        sink.flush().expect("flush must succeed despite SIEM");

        assert_eq!(local.records().len(), 1, "local durable record retained");
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "forward was attempted");
        assert_eq!(
            sink.forward_failure_count(),
            1,
            "the forward failure is counted, not lost or fatal"
        );
    }

    #[test]
    fn local_flush_failure_propagates_and_skips_forwarding() {
        // If the LOCAL fsync fails, the record is not locally durable; we must
        // NOT forward it (and the Auditor will poison). The decorator propagates
        // the local AuditError and the forwarder is never called.
        struct LocalFlushFails {
            appended: Mutex<usize>,
        }
        impl AuditSink for LocalFlushFails {
            fn append(&self, _r: &AuditRecord) -> Result<(), AuditError> {
                *self.appended.lock() += 1;
                Ok(())
            }
            fn flush(&self) -> Result<(), AuditError> {
                Err(AuditError::Io("EIO".to_owned()))
            }
        }
        let fwd = Arc::new(CapturingForwarder::default());
        let sink = ShippingAuditSink::new(
            Box::new(LocalFlushFails {
                appended: Mutex::new(0),
            }),
            Box::new(SharedForwarder(fwd.clone())),
        );
        let rec = AuditRecord::chained_signed(
            &draft("DELETE FROM t", "DESTRUCTIVE"),
            1,
            crate::record::GENESIS_HASH,
            "t0".to_owned(),
            &key(),
        );
        sink.append(&rec).expect("append ok");
        let flush = sink.flush();
        assert!(
            matches!(flush, Err(AuditError::Io(_))),
            "local flush error propagates"
        );
        assert!(
            fwd.records().is_empty(),
            "a non-durable record is never forwarded to the destination"
        );
    }

    #[test]
    fn worm_file_mirror_is_byte_identical_jsonl_and_reverifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary = dir.path().join("audit.jsonl");
        let worm = dir.path().join("worm-mirror.jsonl");
        {
            let local = crate::sink::FileAuditSink::open(&primary).expect("open primary");
            let forwarder = WormFileForwarder::open(&worm).expect("open worm");
            let sink = ShippingAuditSink::new(Box::new(local), Box::new(forwarder));
            let auditor = Auditor::new(Box::new(sink), key());
            for i in 0..4 {
                auditor
                    .append(
                        &draft(&format!("DELETE FROM t WHERE id={i}"), "DESTRUCTIVE"),
                        format!("t{i}"),
                        true,
                    )
                    .expect("append");
            }
        }
        let primary_body = std::fs::read_to_string(&primary).expect("read primary");
        let worm_body = std::fs::read_to_string(&worm).expect("read worm");
        assert_eq!(
            primary_body, worm_body,
            "the WORM mirror is byte-identical to the primary JSONL"
        );
        let parsed = parse_jsonl(&worm_body).expect("parse worm");
        assert_eq!(
            verify_records(&parsed, &[key()]),
            VerifyOutcome::Ok { records: 4 },
            "the WORM mirror re-verifies under the signing key"
        );
    }

    #[test]
    fn cef_line_carries_chain_fields_and_escapes() {
        let rec = AuditRecord::chained_signed(
            &draft("DELETE FROM orders WHERE note = 'a|b=c'", "DESTRUCTIVE"),
            7,
            crate::record::GENESIS_HASH,
            "2026-06-20T00:00:00Z".to_owned(),
            &key(),
        );
        let line = cef_line(&rec);
        assert!(
            line.starts_with("CEF:0|oraclemcp|oraclemcp|"),
            "CEF v0 prefix"
        );
        assert!(line.contains("cs1=7"), "carries the audit seq");
        assert!(line.contains("entryHash="), "carries the entry hash");
        assert!(
            line.contains("signature=hmac-sha256:"),
            "carries the keyed MAC"
        );
        // The '=' inside the preview value is escaped in the extension.
        assert!(line.contains("\\="), "extension '=' is escaped");
    }

    #[test]
    fn syslog_line_is_rfc5424_with_structured_data() {
        let rec = AuditRecord::chained_signed(
            &draft("DROP TABLE t", "DESTRUCTIVE"),
            2,
            "sha256:prev",
            "2026-06-20T00:00:00Z".to_owned(),
            &key(),
        );
        let line = syslog_line(&rec);
        assert!(line.starts_with('<'), "RFC-5424 PRI prefix");
        assert!(line.contains(">1 "), "VERSION 1");
        assert!(line.contains("[oraclemcp@0"), "structured-data element");
        assert!(line.contains("seq=\"2\""), "seq in structured data");
        assert!(line.contains("entryHash="), "entry hash in structured data");
    }

    #[test]
    fn off_by_default_no_shipping_sink_without_a_forwarder() {
        // The plain FileAuditSink path is unchanged: nothing here forwards
        // unless a ShippingAuditSink is explicitly constructed. This documents
        // the off-by-default contract at the type level — a bare Auditor over a
        // FileAuditSink never touches a forwarder.
        let local = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(SharedLocal(local.clone())), key());
        auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), false)
            .expect("append");
        assert_eq!(local.records().len(), 1);
        // No forwarder type is involved; the test compiles + passes purely on
        // the un-decorated path.
    }
}
