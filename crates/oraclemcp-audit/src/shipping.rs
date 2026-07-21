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
//! A forwarding/enqueue failure is non-fatal to the authoritative local chain.
//! Production network destinations are wrapped in
//! [`DurableShippingForwarder`](crate::DurableShippingForwarder): the decorator
//! durably enqueues after the local fsync, and a dedicated ordered worker owns
//! all slow network I/O and retries. A bounded-spool overflow is counted,
//! logged, and recorded in a durable gap indicator rather than silently lost.
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
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::record::{AuditRecord, BoundAuditVerdictCertificate};
use crate::sink::{AuditError, AuditSink, FileAuditSink, open_file_identity};

/// A shipping (forwarding) failure. Distinct from [`AuditError`] because a
/// shipping failure is **non-fatal** to the local durable chain: the decorator
/// records it rather than failing the audited call. Durable forwarders retain
/// destination failures for retry; a raw forwarder may drop a failed mirror.
#[derive(Debug)]
#[non_exhaustive]
pub enum ShippingError {
    /// An I/O / transport error mirroring a record to the destination.
    Transport(String),
    /// The WORM mirror resolves to the primary audit log's open filesystem
    /// object. Arming it would append every signed record twice and corrupt the
    /// local chain.
    AliasedPrimaryAuditLog,
}

impl std::fmt::Display for ShippingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShippingError::Transport(msg) => write!(f, "audit shipping transport error: {msg}"),
            ShippingError::AliasedPrimaryAuditLog => {
                f.write_str("WORM mirror aliases the primary audit log")
            }
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
/// `forward` is blocking and `Send + Sync`. Production network/file
/// destinations are wrapped in [`DurableShippingForwarder`](crate::DurableShippingForwarder),
/// whose dedicated worker owns this blocking call, so the audit mutex never
/// spans destination I/O and this leaf crate needs no async runtime.
pub trait ShippingForwarder: Send + Sync {
    /// Mirror one record to the destination. Errors are surfaced to the
    /// decorator, which logs and counts them (fail-safe: never fails the local
    /// durable path). Network implementations should be placed behind
    /// [`DurableShippingForwarder`](crate::DurableShippingForwarder).
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
/// primary. The opened handle is retained for the forwarder's lifetime; any
/// future rotation/reopen must construct a new forwarder and therefore repeats
/// the identity proof before another record can be mirrored.
pub struct WormFileForwarder {
    state: Mutex<WormFileState>,
}

struct WormFileState {
    file: File,
    last: Option<(u64, String)>,
}

impl WormFileForwarder {
    /// Open (creating + appending) the WORM mirror file at `path`, after proving
    /// its open filesystem identity differs from `primary`. Uses
    /// `O_APPEND` so every write lands at the current end of file — the
    /// write-once posture is enforced by the destination filesystem / bucket
    /// object-lock; this side never seeks or truncates.
    ///
    /// # Errors
    /// Returns [`ShippingError::Transport`] if either identity cannot be
    /// established or the mirror cannot be opened, and
    /// [`ShippingError::AliasedPrimaryAuditLog`] for any same-object alias.
    pub fn open_distinct(
        path: impl AsRef<Path>,
        primary: &FileAuditSink,
    ) -> Result<Self, ShippingError> {
        let primary_identity = primary
            .open_identity()
            .map_err(|error| ShippingError::Transport(error.to_string()))?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        let mirror_identity = open_file_identity(&file).map_err(|error| {
            ShippingError::Transport(format!("cannot establish WORM file identity: {error}"))
        })?;
        if mirror_identity == primary_identity {
            return Err(ShippingError::AliasedPrimaryAuditLog);
        }
        let mut body = String::new();
        (&file)
            .read_to_string(&mut body)
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        let records = crate::parse_jsonl(&body).map_err(|error| {
            ShippingError::Transport(format!("existing WORM mirror is malformed: {error}"))
        })?;
        let mut previous_hash = crate::GENESIS_HASH;
        for (index, record) in records.iter().enumerate() {
            let expected_seq = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
            if record.seq != expected_seq
                || record.prev_hash != previous_hash
                || !record.hash_is_valid()
            {
                return Err(ShippingError::Transport(format!(
                    "existing WORM mirror has a broken chain at sequence {}",
                    record.seq
                )));
            }
            previous_hash = &record.entry_hash;
        }
        let last = records
            .last()
            .map(|record| (record.seq, record.entry_hash.clone()));
        Ok(WormFileForwarder {
            state: Mutex::new(WormFileState { file, last }),
        })
    }
}

impl ShippingForwarder for WormFileForwarder {
    fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
        let mut state = self.state.lock();
        if let Some((last_seq, last_hash)) = state.last.as_ref() {
            if record.seq == *last_seq && record.entry_hash == *last_hash {
                // At-least-once spool replay after a crash between destination
                // acceptance and local acknowledgement. The exact signed tail
                // is already present; treating it as accepted keeps the WORM
                // chain byte-identical instead of appending a duplicate.
                return Ok(());
            }
            if record.seq != last_seq.saturating_add(1) || record.prev_hash != *last_hash {
                return Err(ShippingError::Transport(format!(
                    "WORM mirror expected sequence {} chained from its current tail, got {}",
                    last_seq.saturating_add(1),
                    record.seq
                )));
            }
        } else if record.seq != 1 || record.prev_hash != crate::GENESIS_HASH {
            return Err(ShippingError::Transport(format!(
                "empty WORM mirror expected sequence 1 chained from genesis, got {}",
                record.seq
            )));
        }
        if !record.hash_is_valid() {
            return Err(ShippingError::Transport(format!(
                "refusing structurally invalid signed record at sequence {}",
                record.seq
            )));
        }
        let line =
            serde_json::to_string(record).map_err(|e| ShippingError::Transport(e.to_string()))?;
        state
            .file
            .write_all(line.as_bytes())
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        state
            .file
            .write_all(b"\n")
            .map_err(|e| ShippingError::Transport(e.to_string()))?;
        state.last = Some((record.seq, record.entry_hash.clone()));
        Ok(())
    }

    fn flush(&self) -> Result<(), ShippingError> {
        let state = self.state.lock();
        state
            .file
            .sync_all()
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

    fn append_with_verdict_certificate(
        &self,
        record: &AuditRecord,
        certificate: &BoundAuditVerdictCertificate,
    ) -> Result<(), AuditError> {
        // The primary JSONL is authoritative and retains the certificate
        // envelope. The existing shipping forwarder mirrors the signed record
        // (whose core hash already authenticates that envelope) after the local
        // fsync, preserving its established WORM/SIEM contract.
        self.local
            .append_with_verdict_certificate(record, certificate)?;
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
/// record, plus the decision/outcome and schema-versioned `sql_preview` field.
/// Current v6+ records carry only a fixed redaction marker in that field;
/// historical v1-v5 records retain their signed bytes. Extension values are
/// escaped per the CEF spec (`\`, `=`, and newlines).
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
    if let Some(correlation) = record.correlation.as_ref() {
        push_cef_kv(&mut ext, "requestSha256", &correlation.request_sha256);
        if let Some(parent_seq) = correlation.parent_seq {
            push_cef_kv(&mut ext, "parentSeq", &parent_seq.to_string());
        }
    }
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
/// SIEM can detect tampering without parsing the message body. The MSG is a
/// literal-free tool/hash summary: it never re-emits the signed `sql_preview`
/// bytes retained by historical v1-v5 records. Control characters in the
/// summary are encoded so one record always remains one physical syslog line.
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
    if let Some(correlation) = record.correlation.as_ref() {
        push_sd_param(&mut sd, "requestSha256", &correlation.request_sha256);
        if let Some(parent_seq) = correlation.parent_seq {
            push_sd_param(&mut sd, "parentSeq", &parent_seq.to_string());
        }
    }
    push_sd_param(&mut sd, "danger", &record.danger_level);
    push_sd_param(&mut sd, "sqlSha256", &record.sql_sha256);
    push_sd_param(&mut sd, "prevHash", &record.prev_hash);
    push_sd_param(&mut sd, "entryHash", &record.entry_hash);
    if let Some(rows) = record.rows_affected {
        push_sd_param(&mut sd, "rowsAffected", &rows.to_string());
    }
    if let Some(key_id) = record.key_id.as_deref() {
        push_sd_param(&mut sd, "keyId", key_id);
    }
    if let Some(sig) = record.signature.as_deref() {
        push_sd_param(&mut sd, "signature", sig);
    }
    sd.push(']');
    let mut message = String::from("audit tool=\"");
    push_syslog_msg_text(&mut message, &record.tool);
    message.push_str("\" sql_sha256=\"");
    push_syslog_msg_text(&mut message, &record.sql_sha256);
    message.push('"');
    // VERSION=1, HOSTNAME=-, APP-NAME=oraclemcp, PROCID=-, MSGID=audit.
    // The HTTP request body supplies octet-counted framing; the standalone text
    // is also line-safe for collectors that split raw payloads on CR/LF.
    format!(
        "<{pri}>1 {} - oraclemcp - audit {} {}",
        record.timestamp, sd, message
    )
}

/// Append text to the RFC-5424 MSG without admitting a physical line/control
/// boundary. Backslash and quote are escaped to keep the summary unambiguous;
/// C0/C1 controls and DEL use Rust's ASCII escape spelling. Other Unicode is
/// preserved verbatim.
fn push_syslog_msg_text(message: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => message.push_str("\\\\"),
            '"' => message.push_str("\\\""),
            _ if c.is_control() => message.extend(c.escape_default()),
            _ => message.push(c),
        }
    }
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
/// Characters a downstream collector may treat as the end of a CEF record.
///
/// CR and LF are the obvious two. The rest are the remaining Unicode mandatory
/// line breaks (UAX #14): NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR, plus the
/// VT/FF controls. A collector that splits on any of them would see one audit
/// record as two — the local hash chain stays intact while the SIEM's view of
/// it does not, which is the whole risk (bead F-LOW AU2).
const fn is_record_separator(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

fn cef_escape_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            // The header has no escape form for a separator; the existing
            // behaviour folds it to a space, and every separator now folds the
            // same way rather than only CR and LF.
            c if is_record_separator(c) => out.push(' '),
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
            // `\n` and `\r` keep their spec escapes, byte-for-byte as before.
            '\n' => ext.push_str("\\n"),
            '\r' => ext.push_str("\\r"),
            // The other separators have no CEF escape form, so encode them in a
            // shape that survives transport and cannot terminate a record.
            c if is_record_separator(c) => {
                ext.push_str(&format!("\\u{:04x}", c as u32));
            }
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
            _ if c.is_control() => sd.extend(c.escape_default()),
            _ => sd.push(c),
        }
    }
    sd.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        AuditCorrelation, AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, AuditVerdict,
        AuditVerdictCertificate, AuditVerdictConstruct, AuditVerdictDerivationStep,
        AuditVerdictOperatingLevel, AuditVerdictRuleId, BoundAuditVerdictCertificate, SigningKey,
        compute_entry_hash_v1,
    };
    use crate::sink::{Auditor, MemoryAuditSink};
    use crate::verify::{VerifyOutcome, parse_jsonl, verify_records};
    use std::sync::Arc;

    fn key() -> SigningKey {
        SigningKey::new("k1", b"0123456789abcdef0123456789abcdef".to_vec()).expect("valid test key")
    }

    fn draft(sql: &str, danger: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent-1"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
            tool: "oracle_execute".to_owned(),
            sql: sql.to_owned(),
            danger_level: danger.to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(3),
            outcome: AuditOutcome::Succeeded,
        }
    }

    fn signed_legacy_v1_record(tool: &str, sql_preview: &str) -> AuditRecord {
        let timestamp = "2026-06-20T00:00:00Z";
        let agent_identity = "legacy-agent";
        let sql_sha256 = crate::sha256_hex(sql_preview.as_bytes());
        let danger_level = "GUARDED";
        let decision = AuditDecision::Allowed;
        let rows_affected = Some(1);
        let outcome = AuditOutcome::Succeeded;
        let entry_hash = compute_entry_hash_v1(
            1,
            timestamp,
            agent_identity,
            tool,
            &sql_sha256,
            sql_preview,
            danger_level,
            decision,
            rows_affected,
            outcome,
            crate::record::GENESIS_HASH,
        );
        let signing_key = key();
        AuditRecord {
            schema_version: 1,
            seq: 1,
            timestamp: timestamp.to_owned(),
            agent_identity: agent_identity.to_owned(),
            subject: AuditSubject::default(),
            db_evidence: None,
            cancel: None,
            correlation: None,
            result_masking: None,
            observed_scn: None,
            verdict_certificate_core_hash: None,
            tool: tool.to_owned(),
            sql_sha256,
            sql_normalized_sha256: String::new(),
            sql_preview: sql_preview.to_owned(),
            danger_level: danger_level.to_owned(),
            decision,
            rows_affected,
            outcome,
            prev_hash: crate::record::GENESIS_HASH.to_owned(),
            entry_hash: entry_hash.clone(),
            key_id: Some(signing_key.key_id().to_owned()),
            signature: Some(signing_key.sign(&entry_hash)),
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

    struct TestTee {
        first: Box<dyn ShippingForwarder>,
        second: Box<dyn ShippingForwarder>,
    }

    impl ShippingForwarder for TestTee {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            self.first.forward(record)?;
            self.second.forward(record)
        }

        fn flush(&self) -> Result<(), ShippingError> {
            self.first.flush()?;
            self.second.flush()
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
        assert_eq!(
            sink.forward_failure_count(),
            0,
            "new shipping sinks start with no forward failures"
        );
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
    fn append_with_verdict_certificate_is_buffered_and_forwarded_after_local_fsync() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Local {
            append_calls: Arc<AtomicUsize>,
            with_calls: Arc<AtomicUsize>,
            flushed: Arc<AtomicBool>,
        }

        impl AuditSink for Local {
            fn append(&self, _r: &AuditRecord) -> Result<(), crate::sink::AuditError> {
                self.append_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn append_with_verdict_certificate(
                &self,
                _r: &AuditRecord,
                _certificate: &BoundAuditVerdictCertificate,
            ) -> Result<(), crate::sink::AuditError> {
                self.with_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn flush(&self) -> Result<(), crate::sink::AuditError> {
                self.flushed.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let append_calls = Arc::new(AtomicUsize::new(0));
        let with_calls = Arc::new(AtomicUsize::new(0));
        let flushed = Arc::new(AtomicBool::new(false));
        let local = Local {
            append_calls: Arc::clone(&append_calls),
            with_calls: Arc::clone(&with_calls),
            flushed: Arc::clone(&flushed),
        };
        let forward = Arc::new(CapturingForwarder::default());
        let sink =
            ShippingAuditSink::new(Box::new(local), Box::new(SharedForwarder(forward.clone())));

        let derivation = AuditVerdictDerivationStep::new(
            AuditVerdictRuleId::R16,
            AuditVerdictConstruct::FinalSafe,
        )
        .expect("registered derivation");
        let mut record = AuditRecord::chained_signed(
            &draft("DELETE FROM users", "DESTRUCTIVE"),
            1,
            crate::record::GENESIS_HASH,
            "t-cf".to_owned(),
            &key(),
        );
        let certificate = AuditVerdictCertificate::new(
            "policy-1".to_owned(),
            vec![derivation],
            Some(AuditVerdictOperatingLevel::ReadOnly),
            None,
            record.sql_sha256.clone(),
            AuditVerdict::Safe,
        )
        .expect("valid verdict certificate");
        record.verdict_certificate_core_hash = Some(certificate.core_hash());
        let bound = certificate
            .bind_to_record(&record)
            .expect("certificate must match record");

        sink.append_with_verdict_certificate(&record, &bound)
            .expect("append with verdict certificate");
        assert_eq!(
            append_calls.load(Ordering::SeqCst),
            0,
            "verdict path must not route through append"
        );
        assert_eq!(
            with_calls.load(Ordering::SeqCst),
            1,
            "verdict certificate path must execute append_with_verdict_certificate"
        );
        assert_eq!(
            forward.records().len(),
            0,
            "local-only path must not ship before local durability"
        );
        assert!(!flushed.load(Ordering::SeqCst));

        sink.flush().expect("durable flush");
        assert!(flushed.load(Ordering::SeqCst));
        assert_eq!(forward.records().len(), 1);
        assert_eq!(forward.records()[0].seq, 1);
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
            let forwarder =
                WormFileForwarder::open_distinct(&worm, &local).expect("open distinct worm");
            let sink = ShippingAuditSink::new(Box::new(local), Box::new(forwarder));
            let auditor = Auditor::new(Box::new(sink), key());
            for i in 0..4 {
                auditor
                    .append(
                        &draft(
                            &format!("DELETE FROM t WHERE secret='QA31_WORM_SECRET_{i}'"),
                            "DESTRUCTIVE",
                        ),
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
        assert!(
            !primary_body.contains("QA31_WORM_SECRET"),
            "new v6 local/WORM JSONL must not persist source SQL literals"
        );
        let parsed = parse_jsonl(&worm_body).expect("parse worm");
        assert_eq!(
            verify_records(&parsed, &[key()]),
            VerifyOutcome::Ok { records: 4 },
            "the WORM mirror re-verifies under the signing key"
        );
    }

    #[test]
    fn worm_restart_replay_of_the_exact_tail_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("audit.jsonl");
        let worm_path = dir.path().join("worm.jsonl");
        let primary = crate::sink::FileAuditSink::open(&primary_path).expect("open primary");
        let first = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "DESTRUCTIVE"),
            1,
            crate::GENESIS_HASH,
            "t1".to_owned(),
            &key(),
        );
        {
            let worm = WormFileForwarder::open_distinct(&worm_path, &primary).expect("open worm");
            worm.forward(&first).expect("first delivery");
            worm.flush().expect("durable first delivery");
        }
        {
            let worm = WormFileForwarder::open_distinct(&worm_path, &primary).expect("reopen worm");
            worm.forward(&first).expect("idempotent replay");
            worm.flush().expect("flush replay");
        }
        let body = std::fs::read_to_string(&worm_path).expect("read worm");
        let records = parse_jsonl(&body).expect("valid worm chain");
        assert_eq!(records, vec![first], "replay must not append a duplicate");
    }

    #[test]
    fn worm_rejects_same_sequence_with_different_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("audit.jsonl");
        let worm_path = dir.path().join("worm.jsonl");
        let primary = crate::sink::FileAuditSink::open(&primary_path).expect("open primary");
        let first = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "DESTRUCTIVE"),
            1,
            crate::GENESIS_HASH,
            "t1".to_owned(),
            &key(),
        );
        let conflicting_tail = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2", "DESTRUCTIVE"),
            1,
            crate::GENESIS_HASH,
            "t2".to_owned(),
            &key(),
        );
        let mut different_sequence_same_hash = first.clone();
        different_sequence_same_hash.seq = 2;
        let worm = WormFileForwarder::open_distinct(&worm_path, &primary).expect("open worm");
        worm.forward(&first).expect("first delivery");
        let error = worm
            .forward(&conflicting_tail)
            .expect_err("same sequence with a different hash must not be idempotent");
        assert!(
            error.to_string().contains("expected sequence 2"),
            "unexpected WORM error: {error}"
        );
        let error = worm
            .forward(&different_sequence_same_hash)
            .expect_err("different sequence with the same tail hash must not be idempotent");
        assert!(
            error.to_string().contains("chained from its current tail"),
            "unexpected WORM error: {error}"
        );
    }

    #[test]
    fn worm_rejects_sequence_gap_and_wrong_previous_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("audit.jsonl");
        let worm_path = dir.path().join("worm.jsonl");
        let primary = crate::sink::FileAuditSink::open(&primary_path).expect("open primary");
        let first = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "DESTRUCTIVE"),
            1,
            crate::GENESIS_HASH,
            "t1".to_owned(),
            &key(),
        );
        let gap = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=3", "DESTRUCTIVE"),
            3,
            &first.entry_hash,
            "t3".to_owned(),
            &key(),
        );
        let wrong_prev = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2", "DESTRUCTIVE"),
            2,
            crate::GENESIS_HASH,
            "t2".to_owned(),
            &key(),
        );
        let worm = WormFileForwarder::open_distinct(&worm_path, &primary).expect("open worm");
        worm.forward(&first).expect("first delivery");
        for bad in [&gap, &wrong_prev] {
            let error = worm
                .forward(bad)
                .expect_err("WORM tail must require contiguous seq and prev_hash");
            assert!(
                error.to_string().contains("chained from its current tail"),
                "unexpected WORM error for seq {}: {error}",
                bad.seq
            );
        }
    }

    #[test]
    fn empty_worm_requires_first_record_chained_from_genesis() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("audit.jsonl");
        let worm_path = dir.path().join("worm.jsonl");
        let primary = crate::sink::FileAuditSink::open(&primary_path).expect("open primary");
        let seq_two = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2", "DESTRUCTIVE"),
            2,
            crate::GENESIS_HASH,
            "t2".to_owned(),
            &key(),
        );
        let wrong_genesis = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "DESTRUCTIVE"),
            1,
            "sha256:not-genesis",
            "t1".to_owned(),
            &key(),
        );
        let worm = WormFileForwarder::open_distinct(&worm_path, &primary).expect("open worm");
        for bad in [&seq_two, &wrong_genesis] {
            let error = worm
                .forward(bad)
                .expect_err("empty WORM mirror must start at seq=1 from genesis");
            assert!(
                error
                    .to_string()
                    .contains("empty WORM mirror expected sequence 1"),
                "unexpected WORM error for seq {}: {error}",
                bad.seq
            );
        }
    }

    #[test]
    fn worm_open_rejects_existing_mirror_chain_anomalies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("audit.jsonl");
        let primary = crate::sink::FileAuditSink::open(&primary_path).expect("open primary");
        let first = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "DESTRUCTIVE"),
            1,
            crate::GENESIS_HASH,
            "t1".to_owned(),
            &key(),
        );
        let seq_gap = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2", "DESTRUCTIVE"),
            2,
            crate::GENESIS_HASH,
            "t2".to_owned(),
            &key(),
        );
        let wrong_prev = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2", "DESTRUCTIVE"),
            2,
            "sha256:not-the-tail",
            "t2".to_owned(),
            &key(),
        );
        let mut invalid_hash = first.clone();
        invalid_hash.entry_hash.push('x');

        for (case, records) in [
            ("seq-gap", vec![seq_gap]),
            ("wrong-prev", vec![first.clone(), wrong_prev]),
            ("invalid-hash", vec![invalid_hash]),
        ] {
            let worm_path = dir.path().join(format!("worm-{case}.jsonl"));
            let body = records
                .iter()
                .map(|record| serde_json::to_string(record).expect("serialize") + "\n")
                .collect::<String>();
            std::fs::write(&worm_path, body).expect("seed malformed WORM");
            let error = match WormFileForwarder::open_distinct(&worm_path, &primary) {
                Err(error) => error,
                Ok(_) => panic!("malformed existing WORM mirror must fail closed"),
            };
            assert!(
                error.to_string().contains("broken chain"),
                "unexpected {case} error: {error}"
            );
        }
    }

    #[test]
    fn mixed_key_worm_and_siem_streams_preserve_order_and_signatures() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary_path = dir.path().join("audit.jsonl");
        let worm_path = dir.path().join("worm.jsonl");
        let capture = Arc::new(CapturingForwarder::default());
        let old_key = SigningKey::new("old", vec![0x41; 32]).expect("old key");
        let new_key = SigningKey::new("new", vec![0x42; 32]).expect("new key");

        {
            let local = crate::FileAuditSink::open(&primary_path).expect("old primary");
            let worm = WormFileForwarder::open_distinct(&worm_path, &local).expect("old worm");
            let tee = TestTee {
                first: Box::new(worm),
                second: Box::new(SharedForwarder(Arc::clone(&capture))),
            };
            let auditor = Auditor::new(
                Box::new(ShippingAuditSink::new(Box::new(local), Box::new(tee))),
                old_key.clone(),
            );
            for seq in 1..=2 {
                auditor
                    .append(
                        &draft(&format!("DELETE FROM t WHERE id={seq}"), "GUARDED"),
                        format!("t{seq}"),
                        true,
                    )
                    .expect("old append");
            }
        }

        let rotation =
            crate::AuditKeyring::new(new_key.clone(), [old_key.clone()]).expect("rotation keyring");
        {
            let local = crate::FileAuditSink::open(&primary_path).expect("new primary");
            let worm = WormFileForwarder::open_distinct(&worm_path, &local).expect("new worm");
            let tee = TestTee {
                first: Box::new(worm),
                second: Box::new(SharedForwarder(Arc::clone(&capture))),
            };
            let auditor = Auditor::new_with_keyring(
                Box::new(ShippingAuditSink::new(Box::new(local), Box::new(tee))),
                rotation.clone(),
            )
            .resume_from(&primary_path)
            .expect("mixed-key resume");
            for seq in 3..=4 {
                auditor
                    .append(
                        &draft(&format!("DELETE FROM t WHERE id={seq}"), "GUARDED"),
                        format!("t{seq}"),
                        true,
                    )
                    .expect("new append");
            }
        }

        let primary = std::fs::read_to_string(&primary_path).expect("primary body");
        let worm = std::fs::read_to_string(&worm_path).expect("worm body");
        assert_eq!(worm, primary, "WORM stream remains byte-identical");
        let records = parse_jsonl(&primary).expect("mixed stream");
        assert_eq!(
            records
                .iter()
                .map(|record| record.key_id.as_deref().unwrap())
                .collect::<Vec<_>>(),
            vec!["old", "old", "new", "new"]
        );
        assert_eq!(
            verify_records(&records, rotation.verification_keys()),
            VerifyOutcome::Ok { records: 4 }
        );

        let siem = capture.records();
        assert_eq!(
            siem.iter().map(|record| record.seq).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            verify_records(&siem, rotation.verification_keys()),
            VerifyOutcome::Ok { records: 4 },
            "SIEM records retain per-key signatures and chain order"
        );
    }

    #[test]
    fn worm_open_rejects_the_primary_file_without_appending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary = dir.path().join("audit.jsonl");
        let local = crate::sink::FileAuditSink::open(&primary).expect("open primary");
        let before = std::fs::metadata(&primary).expect("primary metadata").len();

        let error = match WormFileForwarder::open_distinct(&primary, &local) {
            Err(error) => error,
            Ok(_) => panic!("same open file must be rejected"),
        };
        assert!(matches!(error, ShippingError::AliasedPrimaryAuditLog));
        assert_eq!(
            std::fs::metadata(&primary).expect("primary metadata").len(),
            before,
            "identity rejection must not append or truncate the primary"
        );
    }

    #[test]
    fn worm_open_rejects_a_hard_link_to_the_primary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let primary = dir.path().join("audit.jsonl");
        let alias = dir.path().join("worm-hardlink.jsonl");
        let local = crate::sink::FileAuditSink::open(&primary).expect("open primary");
        std::fs::hard_link(&primary, &alias).expect("create hard-link alias");

        let error = match WormFileForwarder::open_distinct(&alias, &local) {
            Err(error) => error,
            Ok(_) => panic!("hard-link alias must be rejected"),
        };
        assert!(matches!(error, ShippingError::AliasedPrimaryAuditLog));
        assert_eq!(
            std::fs::metadata(&primary).expect("primary metadata").len(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn worm_open_rejects_a_symlink_to_the_primary() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let primary = dir.path().join("audit.jsonl");
        let alias = dir.path().join("worm-symlink.jsonl");
        let local = crate::sink::FileAuditSink::open(&primary).expect("open primary");
        symlink(&primary, &alias).expect("create symlink alias");

        let error = match WormFileForwarder::open_distinct(&alias, &local) {
            Err(error) => error,
            Ok(_) => panic!("symlink alias must be rejected"),
        };
        assert!(matches!(error, ShippingError::AliasedPrimaryAuditLog));
    }

    #[test]
    fn cef_line_carries_chain_fields_and_escapes() {
        let mut rec = AuditRecord::chained_signed(
            &draft("DELETE FROM orders WHERE note = 'a|b=c'", "DESTRUCTIVE"),
            7,
            crate::record::GENESIS_HASH,
            "2026-06-20T00:00:00Z".to_owned(),
            &key(),
        );
        // A legacy-shaped record may contain a raw preview. QA35 removes that
        // field from syslog MSG only; historical CEF still carries its signed
        // bytes, so keep this escaping proof independent of v6 construction.
        rec.sql_preview = "DELETE FROM orders WHERE note = 'a|b=c'".to_owned();
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
    fn siem_formats_carry_attempt_terminal_correlation_and_truthful_severity() {
        let mut failed = draft("POST /operator/v1/lanes/cancel", "OPERATOR");
        failed.decision = AuditDecision::Blocked;
        failed.outcome = AuditOutcome::Failed;
        failed.rows_affected = None;
        let record = AuditRecord::chained_signed_correlated(
            &failed,
            12,
            crate::record::GENESIS_HASH,
            "2026-07-11T00:00:00Z".to_owned(),
            &key(),
            Some(AuditCorrelation::terminal("sha256:request-12", 11)),
        );

        let cef = cef_line(&record);
        assert!(cef.contains("|8|"), "blocked CEF outcome is high severity");
        assert!(cef.contains("outcome=Failed"));
        assert!(cef.contains("requestSha256=sha256:request-12"));
        assert!(cef.contains("parentSeq=11"));

        let syslog = syslog_line(&record);
        assert!(syslog.starts_with("<132>1 "), "local0.warning PRI");
        assert!(syslog.contains("outcome=\"Failed\""));
        assert!(syslog.contains("requestSha256=\"sha256:request-12\""));
        assert!(syslog.contains("parentSeq=\"11\""));
    }

    #[test]
    fn new_v6_json_cef_and_syslog_never_carry_sql_sentinel() {
        let sentinel = "QA31_SIEM_SECRET_SENTINEL";
        let rec = AuditRecord::chained_signed(
            &draft(
                &format!("UPDATE users SET password='{sentinel}'"),
                "DESTRUCTIVE",
            ),
            1,
            crate::record::GENESIS_HASH,
            "2026-07-11T00:00:00Z".to_owned(),
            &key(),
        );
        let json = serde_json::to_string(&rec).expect("serialize current record");
        let cef = cef_line(&rec);
        let syslog = syslog_line(&rec);
        for (surface, rendered) in [("json", json), ("cef", cef), ("syslog", syslog)] {
            assert!(
                !rendered.contains(sentinel),
                "new v6 {surface} output leaked SQL source: {rendered}"
            );
        }
    }

    #[test]
    fn rows_affected_max_is_distinct_from_absent_in_json_cef_and_syslog() {
        let mut absent_draft = draft("DELETE FROM t", "DESTRUCTIVE");
        absent_draft.rows_affected = None;
        let absent = AuditRecord::chained_signed(
            &absent_draft,
            1,
            crate::record::GENESIS_HASH,
            "t1".to_owned(),
            &key(),
        );
        let mut max_draft = absent_draft;
        max_draft.rows_affected = Some(u64::MAX);
        let max = AuditRecord::chained_signed(
            &max_draft,
            1,
            crate::record::GENESIS_HASH,
            "t1".to_owned(),
            &key(),
        );

        let absent_json = serde_json::to_value(&absent).expect("serialize absent rows");
        let max_json = serde_json::to_value(&max).expect("serialize max rows");
        assert!(absent_json.get("rows_affected").is_none());
        assert_eq!(max_json["rows_affected"], serde_json::json!(u64::MAX));

        let absent_cef = cef_line(&absent);
        let max_cef = cef_line(&max);
        assert!(!absent_cef.contains("cnt="), "{absent_cef}");
        assert!(max_cef.contains("cnt=18446744073709551615"), "{max_cef}");

        let absent_syslog = syslog_line(&absent);
        let max_syslog = syslog_line(&max);
        assert!(!absent_syslog.contains("rowsAffected="), "{absent_syslog}");
        assert!(
            max_syslog.contains("rowsAffected=\"18446744073709551615\""),
            "{max_syslog}"
        );
    }

    #[test]
    fn structured_data_params_preserve_unicode_and_neutralize_controls() {
        let mut sd = String::from("[oraclemcp@0");
        push_sd_param(&mut sd, "tool", "oracle_éxecute_工具");
        push_sd_param(&mut sd, "msg", "line1\nline2\r\u{0007}]\"");
        sd.push(']');

        assert!(
            sd.contains("tool=\"oracle_éxecute_工具\""),
            "valid Unicode should remain readable in structured data: {sd}"
        );
        assert!(
            sd.contains("msg=\"line1 line2 "),
            "line breaks should be neutralized as spaces: {sd}"
        );
        assert!(sd.contains("\\u{7}"), "other controls are escaped: {sd}");
        assert!(sd.contains("\\]"), "closing bracket is escaped: {sd}");
        assert!(sd.contains("\\\""), "quote is escaped: {sd}");
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
    fn signed_legacy_syslog_record_cannot_inject_a_second_event() {
        let sentinel = "QA35_LEGACY_SQL_LITERAL";
        let sql = format!(
            "UPDATE t SET note='{sentinel}' /* first\r\n<165>1 forged-host forged-app - forged [x] forged */\0\t\u{1b}\u{7f}"
        );
        let tool = "oracle_éxecute_工具\r\n<165>1 forged-tool\0\t\u{1b}\u{7f}";
        let record = signed_legacy_v1_record(tool, &sql);
        assert_eq!(
            verify_records(std::slice::from_ref(&record), &[key()]),
            VerifyOutcome::Ok { records: 1 },
            "fixture is a genuinely signed and verifiable historical record"
        );

        let line = syslog_line(&record);
        assert_eq!(
            line.lines().count(),
            1,
            "one signed record must remain one line-oriented collector event: {line:?}"
        );
        assert!(
            !line
                .chars()
                .any(|c| matches!(c, '\0'..='\u{1f}' | '\u{7f}')),
            "RFC-5424 output must not carry C0 controls or DEL: {line:?}"
        );
        assert!(
            !line.contains(sentinel),
            "legacy SQL preview literals must not be re-emitted: {line}"
        );
        assert!(
            line.contains("oracle_éxecute_工具"),
            "valid Unicode in the literal-free event summary must survive: {line}"
        );
        assert!(
            line.contains("entryHash="),
            "chain hash remains in SD: {line}"
        );
        assert!(
            line.contains("sqlSha256=\"sha256:"),
            "SQL hash remains in SD: {line}"
        );
        assert!(
            line.contains("keyId=\"k1\""),
            "signing key id remains in SD: {line}"
        );
        assert!(
            line.contains("signature="),
            "signature remains in SD: {line}"
        );
        assert!(
            line.starts_with("<134>1 "),
            "allowed/succeeded event keeps local0 informational severity: {line}"
        );

        let collector_input = format!("{line}\n");
        assert_eq!(
            collector_input.lines().collect::<Vec<_>>().len(),
            1,
            "newline-delimited collector fixture must parse exactly one event"
        );
    }

    #[test]
    fn legacy_sql_dialects_and_comments_never_enter_syslog_msg() {
        for sql in [
            "UPDATE t SET value='ordinary'\n<165>1 forged ordinary",
            "UPDATE t SET value=N'national'\r<165>1 forged national",
            "UPDATE t SET value=q'[quoted\r\n<165>1 forged q quote]'",
            "UPDATE t SET value=1 /* multiline\n<165>1 forged comment */",
        ] {
            let record = signed_legacy_v1_record("oracle_execute", sql);
            assert_eq!(
                verify_records(std::slice::from_ref(&record), &[key()]),
                VerifyOutcome::Ok { records: 1 },
                "fixture must remain a valid signed v1 record: {sql:?}"
            );
            let line = syslog_line(&record);
            assert_eq!(line.lines().count(), 1, "{line:?}");
            assert!(!line.contains(sql), "legacy preview leaked: {line}");
            assert!(!line.contains("forged"), "legacy literal leaked: {line}");
        }
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

    #[test]
    fn shipping_error_display_names_transport_failures() {
        let msg = ShippingError::Transport("siem down".to_owned()).to_string();
        assert!(msg.contains("audit shipping transport error"), "{msg}");
        assert!(msg.contains("siem down"), "{msg}");
    }

    #[test]
    fn severity_mappings_cover_decision_outcome_and_danger() {
        let mut rec = AuditRecord::chained_signed(
            &draft("SELECT 1 FROM dual", "SAFE"),
            1,
            crate::record::GENESIS_HASH,
            "2026-06-20T00:00:00Z".to_owned(),
            &key(),
        );
        assert_eq!(cef_severity(&rec), 2);
        assert_eq!(syslog_severity(&rec), 6);

        rec.danger_level = "GUARDED".to_owned();
        assert_eq!(cef_severity(&rec), 4);
        rec.danger_level = "DESTRUCTIVE".to_owned();
        assert_eq!(cef_severity(&rec), 7);

        rec.decision = AuditDecision::StepUpRequired;
        assert_eq!(cef_severity(&rec), 5);
        assert_eq!(syslog_severity(&rec), 5);

        rec.decision = AuditDecision::Allowed;
        for outcome in [
            AuditOutcome::Failed,
            AuditOutcome::DiscardedUncommitted,
            AuditOutcome::CommitInDoubt,
            AuditOutcome::UnknownDiscarded,
        ] {
            rec.outcome = outcome;
            assert_eq!(cef_severity(&rec), 6, "{outcome:?}");
            assert_eq!(syslog_severity(&rec), 3, "{outcome:?}");
        }

        rec.decision = AuditDecision::Blocked;
        rec.outcome = AuditOutcome::Succeeded;
        assert_eq!(cef_severity(&rec), 8);
        assert_eq!(syslog_severity(&rec), 4);
    }

    #[test]
    fn syslog_pri_uses_local0_facility_and_mapped_severity() {
        let rec = AuditRecord::chained_signed(
            &draft("SELECT 1 FROM dual", "SAFE"),
            1,
            crate::record::GENESIS_HASH,
            "2026-06-20T00:00:00Z".to_owned(),
            &key(),
        );
        let line = syslog_line(&rec);
        assert!(
            line.starts_with("<134>1 "),
            "local0 facility 16 * 8 + informational severity 6: {line}"
        );

        let mut failed = rec.clone();
        failed.outcome = AuditOutcome::Failed;
        let line = syslog_line(&failed);
        assert!(
            line.starts_with("<131>1 "),
            "local0 facility 16 * 8 + error severity 3: {line}"
        );
    }

    /// Negative acceptance for bead F-LOW AU2: no character a collector may
    /// read as end-of-record survives into any CEF field, header or extension.
    ///
    /// The risk is not local corruption — the hash chain is unaffected — it is
    /// that a SIEM sees one signed audit record as two, so a forged tail can be
    /// attributed to a genuine chain.
    #[test]
    fn no_record_separator_survives_into_a_cef_field() {
        const SEPARATORS: [char; 7] = [
            '\n', '\r', '\u{0b}', '\u{0c}', '\u{85}', '\u{2028}', '\u{2029}',
        ];

        for separator in SEPARATORS {
            let mut rec = AuditRecord::chained_signed(
                &draft("SELECT 1 FROM dual", "READ_ONLY"),
                11,
                crate::record::GENESIS_HASH,
                "2026-06-20T00:00:00Z".to_owned(),
                &key(),
            );
            // Inject into a header field and an extension field at once: the
            // two escape paths are separate code and both must hold.
            rec.tool = format!("oracle{separator}query");
            rec.agent_identity = format!("agent{separator}two");
            rec.sql_preview = format!("SELECT{separator}1");

            let line = cef_line(&rec);
            assert!(
                !line.contains(separator),
                "U+{:04X} survived into the CEF line: {line:?}",
                separator as u32
            );
            assert_eq!(
                line.lines().count(),
                1,
                "the CEF record must stay one physical line for U+{:04X}",
                separator as u32
            );
        }
    }

    /// Positive acceptance: ordinary Unicode is not collateral damage, and the
    /// spec escapes that already existed are byte-identical.
    #[test]
    fn cef_escaping_keeps_ordinary_unicode_and_existing_escapes_byte_stable() {
        assert_eq!(cef_escape_header("é工具 ✅"), "é工具 ✅");

        let mut ext = String::new();
        push_cef_kv(&mut ext, "msg", "é工具 ✅");
        assert_eq!(ext, "msg=é工具 ✅ ");

        // The pre-existing delimiter escapes must not have shifted.
        let mut ext = String::new();
        push_cef_kv(&mut ext, "msg", "a\\b=c\nr\rd");
        assert_eq!(ext, r#"msg=a\\b\=c\nr\rd "#);

        // ...and the separators without a CEF escape form get an encoded one
        // rather than passing through raw.
        let mut ext = String::new();
        push_cef_kv(&mut ext, "msg", "a\u{2028}b\u{85}c");
        assert_eq!(ext, r"msg=a\u2028b\u0085c ");
    }

    #[test]
    fn cef_and_syslog_escaping_is_spec_specific() {
        assert_eq!(
            cef_escape_header(
                r#"tool\name|x
y"#
            ),
            r#"tool\\name\|x y"#
        );

        let mut ext = String::new();
        push_cef_kv(&mut ext, "msg", "a\\b=c\nr\rd");
        assert_eq!(ext, r#"msg=a\\b\=c\nr\rd "#);

        let mut sd = String::from("[oraclemcp@0");
        push_sd_param(&mut sd, "msg", "a\\b\"c]d\nx\ry\t\0\u{1b}\u{7f}");
        sd.push(']');
        assert_eq!(
            sd,
            r#"[oraclemcp@0 msg="a\\b\"c\]d x y\t\u{0}\u{1b}\u{7f}"]"#
        );

        let mut sd = String::from("[oraclemcp@0");
        push_sd_param(&mut sd, "unicode", "é工具");
        sd.push(']');
        assert_eq!(sd, r#"[oraclemcp@0 unicode="é工具"]"#);

        let mut msg = String::new();
        push_syslog_msg_text(&mut msg, "a\\b\"c\r\nx\t\0\u{1b}\u{7f}é工具");
        assert_eq!(msg, r#"a\\b\"c\r\nx\t\u{0}\u{1b}\u{7f}é工具"#);
    }
}
