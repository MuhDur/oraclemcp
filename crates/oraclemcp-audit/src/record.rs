//! The durable audit record + tamper-evidence hash chain (plan §5.13, §6.4).
//!
//! The **monotonic sequence number is the authoritative order key** for the
//! hash chain — never the wall-clock timestamp (a clock jump must not reorder
//! or collide entries, §5.10). Current records store SQL hashes plus a fixed
//! redaction marker, never SQL text, bind values, or secrets. Historical
//! schemas may contain a truncated SQL preview and remain verifiable
//! byte-for-byte.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hmac::{HmacSha256Key, HmacSha256KeyError};

const AUDIT_SCHEMA_V5: u16 = 5;
const AUDIT_SCHEMA_V6: u16 = 6;
const AUDIT_SCHEMA_V7: u16 = 7;

/// Stable, non-secret replacement for the historical raw-SQL preview field.
///
/// The serialized field remains present so old readers and mixed-version audit
/// chains keep working, but every newly constructed v6+ record stores only this
/// constant. A constant is deliberately used instead of a best-effort SQL
/// scrubber: malformed Oracle quoting, comments, or PL/SQL can never make source
/// text escape into the signed record.
pub(crate) const REDACTED_SQL_PREVIEW: &str = "<sql text redacted; see sql_sha256>";

/// Current on-disk audit record schema.
pub const AUDIT_SCHEMA_VERSION: u16 = AUDIT_SCHEMA_V7;

/// The guard decision being audited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditDecision {
    /// Allowed and run.
    Allowed,
    /// Required a step-up confirmation.
    StepUpRequired,
    /// Blocked by the guard / level gate.
    Blocked,
}

/// The outcome of an audited call (set in the post-execution record).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The statement has been logged but not yet executed (pre-execution record).
    Pending,
    /// Executed successfully.
    Succeeded,
    /// Execution failed.
    Failed,
    /// Rolled back (lease expiry / cancel / savepoint preview).
    RolledBack,
    /// The session was discarded while uncommitted work may have existed.
    DiscardedUncommitted,
    /// A commit was sent but the client could not prove whether Oracle accepted it.
    CommitInDoubt,
    /// The session state is unknown; it was discarded and must not be reused.
    UnknownDiscarded,
}

/// Compute `sha256:<hex>` of bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        push_hex_byte(&mut out, b);
    }
    out
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn legacy_schema_version() -> u16 {
    1
}

/// Compute `sha256:<hex>` of the SQL after a whitespace/case normalization
/// (trim, collapse internal runs of whitespace to a single space, lowercase).
///
/// This is a **hash-only** fingerprint (K5): unlike [`AuditRecord::sql_sha256`]
/// — which hashes the exact bytes — this collapses trivial whitespace/case
/// variants into one correlation bucket so repeated blocked attempts can be
/// grouped in a SIEM. This correlation-only fingerprint is deliberately
/// non-authoritative and may coalesce semantically distinct quoted identifiers
/// or literals. [`AuditRecord::sql_sha256`] preserves the exact statement
/// identity, and guard authorization never uses this normalized value. It has
/// no accompanying preview, so it adds no new literal-exposure surface beyond
/// the existing exact hash.
#[must_use]
pub fn normalized_sql_sha256(sql: &str) -> String {
    let normalized = sql
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    sha256_hex(normalized.as_bytes())
}

/// Server-derived subject identity for an audited action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSubject {
    /// Subject namespace, e.g. `profile`, `lane`, `oauth`, `system`.
    pub kind: String,
    /// Stable, non-secret identifier within `kind`.
    pub stable_id: String,
    /// Authentication method that established this subject, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authn_method: Option<String>,
    /// OAuth/mTLS client id, when known and non-secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// mTLS leaf certificate fingerprint, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
}

impl AuditSubject {
    /// Build a subject from server-derived, non-secret values.
    #[must_use]
    pub fn new(kind: impl Into<String>, stable_id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            stable_id: stable_id.into(),
            authn_method: None,
            client_id: None,
            thumbprint: None,
        }
    }

    /// Attach an authentication method.
    #[must_use]
    pub fn with_authn_method(mut self, authn_method: impl Into<String>) -> Self {
        self.authn_method = Some(authn_method.into());
        self
    }

    /// Attach a non-secret client id.
    #[must_use]
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Attach an mTLS leaf certificate fingerprint.
    #[must_use]
    pub fn with_thumbprint(mut self, thumbprint: impl Into<String>) -> Self {
        self.thumbprint = Some(thumbprint.into());
        self
    }

    /// Legacy string projection retained for older SIEM fields and v1 readers.
    #[must_use]
    pub fn legacy_agent_identity(&self) -> String {
        if self.kind.is_empty() {
            self.stable_id.clone()
        } else {
            format!("{}:{}", self.kind, self.stable_id)
        }
    }
}

impl Default for AuditSubject {
    fn default() -> Self {
        Self::new("unknown", "unknown")
    }
}

/// Optional database-observed evidence attached to an audit record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbEvidence {
    /// `captured` when live evidence was available, or a stable
    /// `db_evidence_unavailable:*` marker when the server could not read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    /// Redacted database fingerprint: `V$DATABASE.DB_UNIQUE_NAME`, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_unique_name: Option<String>,
    /// Redacted service name for the current session, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Redacted instance name for the current session, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_name: Option<String>,
    /// Oracle session user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_user: Option<String>,
    /// Oracle current user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_user: Option<String>,
    /// Oracle proxy user (`SYS_CONTEXT('USERENV','PROXY_USER')`), when proxy
    /// authentication is in effect and visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_user: Option<String>,
    /// Oracle current schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_schema: Option<String>,
    /// Current Oracle session id (`V$SESSION.SID`), when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Current Oracle session serial number (`V$SESSION.SERIAL#`), when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Oracle `CLIENT_IDENTIFIER`, if set by the served session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identifier: Option<String>,
    /// Oracle module, if set by the served session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Oracle action, if set by the served session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Database role from `V$DATABASE`, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_role: Option<String>,
    /// Database open mode from `V$DATABASE`, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_mode: Option<String>,
}

impl DbEvidence {
    /// Build a stable marker for cases where DB evidence was attempted but not
    /// available. The reason must be operator-safe; never put driver messages or
    /// connection material here.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: Some(format!("db_evidence_unavailable:{}", reason.into())),
            ..Self::default()
        }
    }
}

/// Optional structured cancellation/lifecycle reason attached to an audit
/// record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCancel {
    /// Stable cancellation kind, e.g. `User`, `Timeout`, or `Shutdown`.
    pub kind: String,
    /// Stable reason within that kind, e.g. `session_delete`.
    pub reason: String,
}

impl AuditCancel {
    /// Build a structured cancel/lifecycle marker.
    #[must_use]
    pub fn new(kind: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            reason: reason.into(),
        }
    }
}

/// Correlation metadata linking a pre-execution attempt to its terminal record.
///
/// `request_sha256` is an opaque server-generated request identifier, not a
/// hash of the request body (which may contain confirmation tokens or other
/// low-entropy sensitive values). The terminal record names the durable
/// attempt's sequence in `parent_seq`; the attempt itself leaves it absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCorrelation {
    /// Opaque, non-secret correlation identifier (`sha256:<hex>`).
    pub request_sha256: String,
    /// Sequence of the corresponding durable attempt record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_seq: Option<u64>,
}

impl AuditCorrelation {
    /// Create correlation metadata for a pre-execution attempt.
    #[must_use]
    pub fn attempt(request_sha256: impl Into<String>) -> Self {
        Self {
            request_sha256: request_sha256.into(),
            parent_seq: None,
        }
    }

    /// Create correlation metadata for a terminal record linked to `parent_seq`.
    #[must_use]
    pub fn terminal(request_sha256: impl Into<String>, parent_seq: u64) -> Self {
        Self {
            request_sha256: request_sha256.into(),
            parent_seq: Some(parent_seq),
        }
    }
}

/// One audit entry. `seq` + `prev_hash` + `entry_hash` form the tamper-evident
/// chain; `entry_hash` covers the seq and all content fields — including the
/// schema-versioned `sql_preview` field — so any edit or reorder breaks
/// verification.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// On-disk record schema version. Missing means v1 for pre-FN2 records.
    #[serde(default = "legacy_schema_version")]
    pub schema_version: u16,
    /// Monotonic sequence number — the authoritative order key.
    pub seq: u64,
    /// RFC-3339 wall timestamp (display/forensics only; NOT the order key).
    pub timestamp: String,
    /// Legacy string projection of the subject, retained for v1 compatibility.
    #[serde(default)]
    pub agent_identity: String,
    /// Structured server-derived subject identity.
    #[serde(default)]
    pub subject: AuditSubject,
    /// Optional database-observed evidence for correlating this record with
    /// Oracle session state. None for legacy/offline records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_evidence: Option<DbEvidence>,
    /// Optional structured cancellation/lifecycle reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel: Option<AuditCancel>,
    /// Optional attempt/terminal correlation metadata. Present on operator API
    /// records from schema v7 onward; absent on historical records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<AuditCorrelation>,
    /// The tool invoked.
    pub tool: String,
    /// `sha256:<hex>` of the exact SQL bytes (never the bind values).
    pub sql_sha256: String,
    /// `sha256:<hex>` of the **normalized** SQL (whitespace-collapsed,
    /// lowercased) — a hash-only fingerprint (K5) that lets repeated attempts
    /// with trivial whitespace/case variance correlate/dedupe. Empty for legacy
    /// v1–v3 records that predate the field; covered by the v4 chain hash.
    #[serde(default)]
    pub sql_normalized_sha256: String,
    /// Historical SQL-preview field. New v6+ records always contain a fixed
    /// redaction marker; v1-v5 records may contain a truncated raw preview.
    pub sql_preview: String,
    /// The classifier danger tier (as a string, to avoid a guard dep).
    pub danger_level: String,
    /// The guard decision.
    pub decision: AuditDecision,
    /// Rows affected (post-execution), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,
    /// The outcome.
    pub outcome: AuditOutcome,
    /// Hash of the previous entry (`"genesis"` for the first).
    pub prev_hash: String,
    /// Hash of this entry (covers seq + content + prev_hash).
    pub entry_hash: String,
    /// Identifier of the key that produced `signature` (rotation: an operator
    /// can roll the key while old records keep verifying under their own
    /// `key_id`). `None` only for legacy unsigned records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// `hmac-sha256:<hex>` keyed MAC over `entry_hash`. A bare SHA-256 chain is
    /// forgeable by recompute-from-genesis; this MAC binds the record to a key
    /// no forger holds. `None` only for legacy unsigned records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl std::fmt::Debug for AuditRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditRecord")
            .field("schema_version", &self.schema_version)
            .field("seq", &self.seq)
            .field("timestamp", &self.timestamp)
            .field("agent_identity", &self.agent_identity)
            .field("subject", &self.subject)
            .field("db_evidence", &self.db_evidence)
            .field("cancel", &self.cancel)
            .field("correlation", &self.correlation)
            .field("tool", &self.tool)
            .field("sql_sha256", &self.sql_sha256)
            .field("sql_normalized_sha256", &self.sql_normalized_sha256)
            .field("sql_preview", &"***redacted***")
            .field("danger_level", &self.danger_level)
            .field("decision", &self.decision)
            .field("rows_affected", &self.rows_affected)
            .field("outcome", &self.outcome)
            .field("prev_hash", &self.prev_hash)
            .field("entry_hash", &self.entry_hash)
            .field("key_id", &self.key_id)
            .field("signature", &self.signature)
            .finish()
    }
}

/// A keyed signing identity for the audit chain: an opaque `key_id` (stored in
/// each record for rotation) plus the secret HMAC key bytes (never serialized).
#[derive(Clone)]
pub struct SigningKey {
    key_id: String,
    key: HmacSha256Key,
}

impl SigningKey {
    /// Validate raw secret bytes and build a signing key.
    ///
    /// # Errors
    ///
    /// Returns [`HmacSha256KeyError`] when the secret is shorter than the
    /// minimum accepted HMAC-SHA256 key size.
    pub fn new(
        key_id: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> Result<Self, HmacSha256KeyError> {
        Ok(SigningKey {
            key_id: key_id.into(),
            key: HmacSha256Key::new(key)?,
        })
    }

    /// The key identifier recorded alongside each signature.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The `hmac-sha256:<hex>` signature over an `entry_hash`.
    #[must_use]
    pub fn sign(&self, entry_hash: &str) -> String {
        self.key.authenticate_hex(entry_hash.as_bytes())
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id)
            .field("key", &"***redacted***")
            .finish()
    }
}

/// The fields of an audit entry before the chain hashes are attached.
#[derive(Clone)]
pub struct AuditEntryDraft {
    /// Server-derived subject identity.
    pub subject: AuditSubject,
    /// Optional database-observed evidence.
    pub db_evidence: Option<DbEvidence>,
    /// Optional structured cancellation/lifecycle reason.
    pub cancel: Option<AuditCancel>,
    /// Tool name.
    pub tool: String,
    /// The exact SQL, retained only long enough to compute audit hashes.
    pub sql: String,
    /// Danger tier string.
    pub danger_level: String,
    /// The decision.
    pub decision: AuditDecision,
    /// Rows affected, if known.
    pub rows_affected: Option<u64>,
    /// The outcome.
    pub outcome: AuditOutcome,
}

impl std::fmt::Debug for AuditEntryDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditEntryDraft")
            .field("subject", &self.subject)
            .field("db_evidence", &self.db_evidence)
            .field("cancel", &self.cancel)
            .field("tool", &self.tool)
            .field("sql_sha256", &sha256_hex(self.sql.as_bytes()))
            .field("sql_normalized_sha256", &normalized_sql_sha256(&self.sql))
            .field("sql", &"***redacted***")
            .field("danger_level", &self.danger_level)
            .field("decision", &self.decision)
            .field("rows_affected", &self.rows_affected)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Max preview characters retained by historical v1-v5 records.
#[cfg(test)]
const PREVIEW_LEN: usize = 120;

impl AuditRecord {
    /// Build a chained, **signed** record from a draft, the assigned `seq`, the
    /// previous entry hash, and an RFC-3339 timestamp. The record's `entry_hash`
    /// is signed with `key`, and the `key_id` is recorded for rotation.
    #[must_use]
    pub fn chained_signed(
        draft: &AuditEntryDraft,
        seq: u64,
        prev_hash: &str,
        timestamp: String,
        key: &SigningKey,
    ) -> Self {
        Self::chained_signed_correlated(draft, seq, prev_hash, timestamp, key, None)
    }

    /// Build a signed v7 record with optional attempt/terminal correlation.
    #[must_use]
    pub fn chained_signed_correlated(
        draft: &AuditEntryDraft,
        seq: u64,
        prev_hash: &str,
        timestamp: String,
        key: &SigningKey,
        correlation: Option<AuditCorrelation>,
    ) -> Self {
        let mut record =
            Self::chained_unsigned_correlated(draft, seq, prev_hash, timestamp, correlation);
        record.signature = Some(key.sign(&record.entry_hash));
        record.key_id = Some(key.key_id().to_owned());
        record
    }

    /// Build a chained record from a draft, the assigned `seq`, the previous
    /// entry hash, and an RFC-3339 timestamp, leaving the keyed MAC unset.
    #[must_use]
    pub fn chained_unsigned(
        draft: &AuditEntryDraft,
        seq: u64,
        prev_hash: &str,
        timestamp: String,
    ) -> Self {
        Self::chained_unsigned_correlated(draft, seq, prev_hash, timestamp, None)
    }

    /// Build an unsigned v7 record with optional attempt/terminal correlation.
    #[must_use]
    pub fn chained_unsigned_correlated(
        draft: &AuditEntryDraft,
        seq: u64,
        prev_hash: &str,
        timestamp: String,
        correlation: Option<AuditCorrelation>,
    ) -> Self {
        let sql_sha256 = sha256_hex(draft.sql.as_bytes());
        let sql_normalized_sha256 = normalized_sql_sha256(&draft.sql);
        let sql_preview = REDACTED_SQL_PREVIEW.to_owned();
        let agent_identity = draft.subject.legacy_agent_identity();
        let entry_hash = compute_entry_hash_v7(
            seq,
            &timestamp,
            &agent_identity,
            &draft.subject,
            draft.db_evidence.as_ref(),
            draft.cancel.as_ref(),
            correlation.as_ref(),
            &draft.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            &sql_preview,
            &draft.danger_level,
            draft.decision,
            draft.rows_affected,
            draft.outcome,
            prev_hash,
        );
        AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            seq,
            timestamp,
            agent_identity,
            subject: draft.subject.clone(),
            db_evidence: draft.db_evidence.clone(),
            cancel: draft.cancel.clone(),
            correlation,
            tool: draft.tool.clone(),
            sql_sha256,
            sql_normalized_sha256,
            sql_preview,
            danger_level: draft.danger_level.clone(),
            decision: draft.decision,
            rows_affected: draft.rows_affected,
            outcome: draft.outcome,
            prev_hash: prev_hash.to_owned(),
            entry_hash,
            key_id: None,
            signature: None,
        }
    }

    /// Recompute this record's hash and check it matches `entry_hash` (used by
    /// chain verification). This is the **unkeyed** check: it proves the record
    /// has not been edited in place but NOT that it was not forged by a
    /// recompute-from-genesis. Pair it with [`Self::signature_is_valid`].
    #[must_use]
    pub fn hash_is_valid(&self) -> bool {
        let recomputed = if self.schema_version <= 1 {
            compute_entry_hash_v1(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.tool,
                &self.sql_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else if self.schema_version == 2 {
            compute_entry_hash_v2(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.subject,
                self.db_evidence.as_ref(),
                self.cancel.as_ref(),
                &self.tool,
                &self.sql_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else if self.schema_version == 3 {
            compute_entry_hash_v3(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.subject,
                self.db_evidence.as_ref(),
                self.cancel.as_ref(),
                &self.tool,
                &self.sql_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else if self.schema_version == 4 {
            compute_entry_hash_v4(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.subject,
                self.db_evidence.as_ref(),
                self.cancel.as_ref(),
                &self.tool,
                &self.sql_sha256,
                &self.sql_normalized_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else if self.schema_version == AUDIT_SCHEMA_V5 {
            compute_entry_hash_v5(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.subject,
                self.db_evidence.as_ref(),
                self.cancel.as_ref(),
                &self.tool,
                &self.sql_sha256,
                &self.sql_normalized_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else if self.schema_version == AUDIT_SCHEMA_V6 {
            compute_entry_hash_v6(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.subject,
                self.db_evidence.as_ref(),
                self.cancel.as_ref(),
                &self.tool,
                &self.sql_sha256,
                &self.sql_normalized_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else if self.schema_version == AUDIT_SCHEMA_V7 {
            compute_entry_hash_v7(
                self.seq,
                &self.timestamp,
                &self.agent_identity,
                &self.subject,
                self.db_evidence.as_ref(),
                self.cancel.as_ref(),
                self.correlation.as_ref(),
                &self.tool,
                &self.sql_sha256,
                &self.sql_normalized_sha256,
                &self.sql_preview,
                &self.danger_level,
                self.decision,
                self.rows_affected,
                self.outcome,
                &self.prev_hash,
            )
        } else {
            return false;
        };
        recomputed == self.entry_hash
    }

    /// Check this record's keyed MAC against `key`. A forger who recomputes the
    /// chain from genesis without the key cannot reproduce a valid signature,
    /// so this fails for any unsigned or wrong-key record.
    #[must_use]
    pub fn signature_is_valid(&self, key: &SigningKey) -> bool {
        let Some(signature) = self.signature.as_deref() else {
            return false;
        };
        key.key.verify_hex(self.entry_hash.as_bytes(), signature)
    }
}

/// Deterministically hash a v1 entry's seq + content + prev_hash. The seq leads,
/// so ordering is bound into the hash independently of the wall timestamp.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_entry_hash_v1(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    tool: &str,
    sql_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    for field in [
        timestamp,
        agent_identity,
        tool,
        sql_sha256,
        sql_preview,
        danger_level,
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(format!("{decision:?}").as_bytes());
    hasher.update(rows_affected.unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(format!("{outcome:?}").as_bytes());
    hasher.update(prev_hash.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        push_hex_byte(&mut out, b);
    }
    out
}

fn hash_str(hasher: &mut Sha256, field: &str) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field.as_bytes());
}

fn hash_opt_str(hasher: &mut Sha256, field: Option<&str>) {
    match field {
        Some(value) => {
            hasher.update([1]);
            hash_str(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_subject(hasher: &mut Sha256, subject: &AuditSubject) {
    hash_str(hasher, &subject.kind);
    hash_str(hasher, &subject.stable_id);
    hash_opt_str(hasher, subject.authn_method.as_deref());
    hash_opt_str(hasher, subject.client_id.as_deref());
    hash_opt_str(hasher, subject.thumbprint.as_deref());
}

fn hash_db_evidence_v2(hasher: &mut Sha256, evidence: Option<&DbEvidence>) {
    let Some(evidence) = evidence else {
        hasher.update([0]);
        return;
    };
    hasher.update([1]);
    hash_opt_str(hasher, evidence.session_user.as_deref());
    hash_opt_str(hasher, evidence.current_user.as_deref());
    hash_opt_str(hasher, evidence.current_schema.as_deref());
    hash_opt_str(hasher, evidence.client_identifier.as_deref());
    hash_opt_str(hasher, evidence.module.as_deref());
    hash_opt_str(hasher, evidence.action.as_deref());
    hash_opt_str(hasher, evidence.database_role.as_deref());
    hash_opt_str(hasher, evidence.open_mode.as_deref());
}

fn hash_db_evidence_v3(hasher: &mut Sha256, evidence: Option<&DbEvidence>) {
    let Some(evidence) = evidence else {
        hasher.update([0]);
        return;
    };
    hasher.update([1]);
    hash_opt_str(hasher, evidence.availability.as_deref());
    hash_opt_str(hasher, evidence.db_unique_name.as_deref());
    hash_opt_str(hasher, evidence.service_name.as_deref());
    hash_opt_str(hasher, evidence.instance_name.as_deref());
    hash_opt_str(hasher, evidence.session_user.as_deref());
    hash_opt_str(hasher, evidence.current_user.as_deref());
    hash_opt_str(hasher, evidence.proxy_user.as_deref());
    hash_opt_str(hasher, evidence.current_schema.as_deref());
    hash_opt_str(hasher, evidence.sid.as_deref());
    hash_opt_str(hasher, evidence.serial_number.as_deref());
    hash_opt_str(hasher, evidence.client_identifier.as_deref());
    hash_opt_str(hasher, evidence.module.as_deref());
    hash_opt_str(hasher, evidence.action.as_deref());
    hash_opt_str(hasher, evidence.database_role.as_deref());
    hash_opt_str(hasher, evidence.open_mode.as_deref());
}

fn hash_cancel(hasher: &mut Sha256, cancel: Option<&AuditCancel>) {
    let Some(cancel) = cancel else {
        hasher.update([0]);
        return;
    };
    hasher.update([1]);
    hash_str(hasher, &cancel.kind);
    hash_str(hasher, &cancel.reason);
}

/// Deterministically hash a v2 entry's seq + content + prev_hash, including the
/// structured subject, database-evidence, and cancellation/lifecycle fields.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash_v2(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(2_u16.to_be_bytes());
    hasher.update(seq.to_be_bytes());
    for field in [
        timestamp,
        agent_identity,
        tool,
        sql_sha256,
        sql_preview,
        danger_level,
    ] {
        hash_str(&mut hasher, field);
    }
    hash_subject(&mut hasher, subject);
    hash_db_evidence_v2(&mut hasher, db_evidence);
    hash_cancel(&mut hasher, cancel);
    hasher.update(format!("{decision:?}").as_bytes());
    hasher.update(rows_affected.unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(format!("{outcome:?}").as_bytes());
    hasher.update(prev_hash.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        push_hex_byte(&mut out, b);
    }
    out
}

/// Deterministically hash a v3 entry's seq + content + prev_hash. Schema 3
/// extends v2 DB evidence; verification keeps v2 hashing intact for existing
/// logs.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash_v3(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(3_u16.to_be_bytes());
    hasher.update(seq.to_be_bytes());
    for field in [
        timestamp,
        agent_identity,
        tool,
        sql_sha256,
        sql_preview,
        danger_level,
    ] {
        hash_str(&mut hasher, field);
    }
    hash_subject(&mut hasher, subject);
    hash_db_evidence_v3(&mut hasher, db_evidence);
    hash_cancel(&mut hasher, cancel);
    hasher.update(format!("{decision:?}").as_bytes());
    hasher.update(rows_affected.unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(format!("{outcome:?}").as_bytes());
    hasher.update(prev_hash.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        push_hex_byte(&mut out, b);
    }
    out
}

/// Deterministically hash a v4 entry's seq + content + prev_hash. Schema 4
/// extends v3 with the hash-only normalized-SQL fingerprint (K5); verification
/// keeps v1–v3 hashing intact so existing logs still verify unchanged.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash_v4(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_normalized_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(4_u16.to_be_bytes());
    hasher.update(seq.to_be_bytes());
    for field in [
        timestamp,
        agent_identity,
        tool,
        sql_sha256,
        sql_normalized_sha256,
        sql_preview,
        danger_level,
    ] {
        hash_str(&mut hasher, field);
    }
    hash_subject(&mut hasher, subject);
    hash_db_evidence_v3(&mut hasher, db_evidence);
    hash_cancel(&mut hasher, cancel);
    hasher.update(format!("{decision:?}").as_bytes());
    hasher.update(rows_affected.unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(format!("{outcome:?}").as_bytes());
    hasher.update(prev_hash.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        push_hex_byte(&mut out, b);
    }
    out
}

fn canonical_push_str(out: &mut Vec<u8>, field: &str) {
    let len = u64::try_from(field.len()).expect("audit string length fits u64");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field.as_bytes());
}

fn canonical_push_opt_str(out: &mut Vec<u8>, field: Option<&str>) {
    match field {
        Some(value) => {
            out.push(1);
            canonical_push_str(out, value);
        }
        None => out.push(0),
    }
}

fn canonical_push_subject(out: &mut Vec<u8>, subject: &AuditSubject) {
    canonical_push_str(out, &subject.kind);
    canonical_push_str(out, &subject.stable_id);
    canonical_push_opt_str(out, subject.authn_method.as_deref());
    canonical_push_opt_str(out, subject.client_id.as_deref());
    canonical_push_opt_str(out, subject.thumbprint.as_deref());
}

fn canonical_push_db_evidence(out: &mut Vec<u8>, evidence: Option<&DbEvidence>) {
    let Some(evidence) = evidence else {
        out.push(0);
        return;
    };
    out.push(1);
    for field in [
        evidence.availability.as_deref(),
        evidence.db_unique_name.as_deref(),
        evidence.service_name.as_deref(),
        evidence.instance_name.as_deref(),
        evidence.session_user.as_deref(),
        evidence.current_user.as_deref(),
        evidence.proxy_user.as_deref(),
        evidence.current_schema.as_deref(),
        evidence.sid.as_deref(),
        evidence.serial_number.as_deref(),
        evidence.client_identifier.as_deref(),
        evidence.module.as_deref(),
        evidence.action.as_deref(),
        evidence.database_role.as_deref(),
        evidence.open_mode.as_deref(),
    ] {
        canonical_push_opt_str(out, field);
    }
}

fn canonical_push_cancel(out: &mut Vec<u8>, cancel: Option<&AuditCancel>) {
    let Some(cancel) = cancel else {
        out.push(0);
        return;
    };
    out.push(1);
    canonical_push_str(out, &cancel.kind);
    canonical_push_str(out, &cancel.reason);
}

fn canonical_push_correlation(out: &mut Vec<u8>, correlation: Option<&AuditCorrelation>) {
    let Some(correlation) = correlation else {
        out.push(0);
        return;
    };
    out.push(1);
    canonical_push_str(out, &correlation.request_sha256);
    match correlation.parent_seq {
        Some(parent_seq) => {
            out.push(1);
            out.extend_from_slice(&parent_seq.to_be_bytes());
        }
        None => out.push(0),
    }
}

fn canonical_push_rows_affected(out: &mut Vec<u8>, rows_affected: Option<u64>) {
    match rows_affected {
        Some(rows) => {
            out.push(1);
            out.extend_from_slice(&rows.to_be_bytes());
        }
        None => out.push(0),
    }
}

const fn canonical_decision_tag(decision: AuditDecision) -> u8 {
    match decision {
        AuditDecision::Allowed => 0,
        AuditDecision::StepUpRequired => 1,
        AuditDecision::Blocked => 2,
    }
}

const fn canonical_outcome_tag(outcome: AuditOutcome) -> u8 {
    match outcome {
        AuditOutcome::Pending => 0,
        AuditOutcome::Succeeded => 1,
        AuditOutcome::Failed => 2,
        AuditOutcome::RolledBack => 3,
        AuditOutcome::DiscardedUncommitted => 4,
        AuditOutcome::CommitInDoubt => 5,
        AuditOutcome::UnknownDiscarded => 6,
    }
}

/// Canonical v5+ preimage. Every variable-length field is length-framed, every
/// optional field carries an explicit presence tag, and enums use stable numeric
/// tags rather than Rust `Debug` output. Keeping this as bytes before hashing
/// makes injectivity directly testable.
#[allow(clippy::too_many_arguments)]
fn canonical_entry(
    schema_version: u16,
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_normalized_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    for field in [
        timestamp,
        agent_identity,
        tool,
        sql_sha256,
        sql_normalized_sha256,
        sql_preview,
        danger_level,
    ] {
        canonical_push_str(&mut out, field);
    }
    canonical_push_subject(&mut out, subject);
    canonical_push_db_evidence(&mut out, db_evidence);
    canonical_push_cancel(&mut out, cancel);
    out.push(canonical_decision_tag(decision));
    canonical_push_rows_affected(&mut out, rows_affected);
    out.push(canonical_outcome_tag(outcome));
    canonical_push_str(&mut out, prev_hash);
    out
}

#[allow(clippy::too_many_arguments)]
fn canonical_entry_v5(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_normalized_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> Vec<u8> {
    canonical_entry(
        AUDIT_SCHEMA_V5,
        seq,
        timestamp,
        agent_identity,
        subject,
        db_evidence,
        cancel,
        tool,
        sql_sha256,
        sql_normalized_sha256,
        sql_preview,
        danger_level,
        decision,
        rows_affected,
        outcome,
        prev_hash,
    )
}

/// Deterministically hash a v5 entry using injective canonical framing.
/// Verification keeps the v1-v4 hash functions untouched so historical audit
/// evidence continues to verify byte-for-byte.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash_v5(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_normalized_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    sha256_hex(&canonical_entry_v5(
        seq,
        timestamp,
        agent_identity,
        subject,
        db_evidence,
        cancel,
        tool,
        sql_sha256,
        sql_normalized_sha256,
        sql_preview,
        danger_level,
        decision,
        rows_affected,
        outcome,
        prev_hash,
    ))
}

/// Deterministically hash a v6 entry using the same injective canonical framing
/// as v5, with the v6 schema tag and fail-closed redacted SQL field.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash_v6(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    tool: &str,
    sql_sha256: &str,
    sql_normalized_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    sha256_hex(&canonical_entry(
        AUDIT_SCHEMA_V6,
        seq,
        timestamp,
        agent_identity,
        subject,
        db_evidence,
        cancel,
        tool,
        sql_sha256,
        sql_normalized_sha256,
        sql_preview,
        danger_level,
        decision,
        rows_affected,
        outcome,
        prev_hash,
    ))
}

/// Deterministically hash a v7 entry, extending the injective v5+ framing with
/// optional attempt/terminal correlation metadata.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash_v7(
    seq: u64,
    timestamp: &str,
    agent_identity: &str,
    subject: &AuditSubject,
    db_evidence: Option<&DbEvidence>,
    cancel: Option<&AuditCancel>,
    correlation: Option<&AuditCorrelation>,
    tool: &str,
    sql_sha256: &str,
    sql_normalized_sha256: &str,
    sql_preview: &str,
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    let mut canonical = canonical_entry(
        AUDIT_SCHEMA_V7,
        seq,
        timestamp,
        agent_identity,
        subject,
        db_evidence,
        cancel,
        tool,
        sql_sha256,
        sql_normalized_sha256,
        sql_preview,
        danger_level,
        decision,
        rows_affected,
        outcome,
        prev_hash,
    );
    canonical_push_correlation(&mut canonical, correlation);
    sha256_hex(&canonical)
}

/// The genesis prev-hash for the first entry.
pub const GENESIS_HASH: &str = "genesis";

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn signed_record(seq: u64, prev_hash: &str, entry_hash: &str, signature: &str) -> AuditRecord {
        AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            seq,
            timestamp: "2026-07-08T00:00:00Z".to_owned(),
            agent_identity: "kani:subject".to_owned(),
            subject: AuditSubject::new("kani", "subject"),
            db_evidence: None,
            cancel: None,
            correlation: None,
            tool: "oracle_execute".to_owned(),
            sql_sha256: "sha256:sql".to_owned(),
            sql_normalized_sha256: "sha256:sql".to_owned(),
            sql_preview: REDACTED_SQL_PREVIEW.to_owned(),
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
            prev_hash: prev_hash.to_owned(),
            entry_hash: entry_hash.to_owned(),
            key_id: Some("kani-key".to_owned()),
            signature: Some(signature.to_owned()),
        }
    }

    #[kani::proof]
    fn signed_chain_step_links_successor_to_predecessor_and_mac_verifies() {
        let key = SigningKey::new("kani-key", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid Kani key");
        // Fixed HMAC-SHA256 vectors over the entry hashes below. Full
        // chained_signed construction remains pinned by unit and mutation tests;
        // this BMC harness isolates the chain step and MAC verifier.
        let first = signed_record(
            1,
            GENESIS_HASH,
            "sha256:first",
            "hmac-sha256:f647748194ba8967e69c7b3c506d7d87c324368fd2105fbcaab8717348a9914b",
        );
        let second = signed_record(
            2,
            &first.entry_hash,
            "sha256:second",
            "hmac-sha256:c68ad5a61a3a4c8b21ac2b0ea486bf910766a95b5b5e2fb424d344edd5d43fce",
        );

        assert_eq!(first.seq, 1);
        assert_eq!(first.prev_hash, GENESIS_HASH);
        assert_eq!(first.key_id.as_deref(), Some(key.key_id()));
        assert!(first.signature_is_valid(&key));

        assert_eq!(second.seq, first.seq + 1);
        assert_eq!(second.prev_hash, first.entry_hash);
        assert_eq!(second.key_id.as_deref(), Some(key.key_id()));
        assert!(second.signature_is_valid(&key));
        assert_ne!(second.entry_hash, first.entry_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn draft() -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent-1"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_query".to_owned(),
            sql: "DELETE FROM orders WHERE id = 1".to_owned(),
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        }
    }

    fn key() -> SigningKey {
        SigningKey::new("k1", b"0123456789abcdef0123456789abcdef".to_vec()).expect("valid test key")
    }

    fn v5_preimage_for(draft: &AuditEntryDraft, rows_affected: Option<u64>) -> Vec<u8> {
        let sql_sha256 = sha256_hex(draft.sql.as_bytes());
        let sql_normalized_sha256 = normalized_sql_sha256(&draft.sql);
        let sql_preview = draft.sql.chars().take(PREVIEW_LEN).collect::<String>();
        canonical_entry_v5(
            1,
            "t",
            &draft.subject.legacy_agent_identity(),
            &draft.subject,
            draft.db_evidence.as_ref(),
            draft.cancel.as_ref(),
            &draft.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            &sql_preview,
            &draft.danger_level,
            draft.decision,
            rows_affected,
            draft.outcome,
            GENESIS_HASH,
        )
    }

    fn signed_record_for_schema(
        schema_version: u16,
        seq: u64,
        prev_hash: &str,
        key: &SigningKey,
    ) -> AuditRecord {
        signed_record_for_schema_with_draft(&draft(), schema_version, seq, prev_hash, key)
    }

    fn signed_record_for_schema_with_draft(
        d: &AuditEntryDraft,
        schema_version: u16,
        seq: u64,
        prev_hash: &str,
        key: &SigningKey,
    ) -> AuditRecord {
        let timestamp = format!("t{seq}");
        let agent_identity = d.subject.legacy_agent_identity();
        let sql_sha256 = sha256_hex(d.sql.as_bytes());
        let sql_normalized_sha256 = normalized_sql_sha256(&d.sql);
        let sql_preview = if schema_version <= AUDIT_SCHEMA_V5 {
            d.sql.chars().take(PREVIEW_LEN).collect::<String>()
        } else {
            REDACTED_SQL_PREVIEW.to_owned()
        };
        let entry_hash = match schema_version {
            1 => compute_entry_hash_v1(
                seq,
                &timestamp,
                &agent_identity,
                &d.tool,
                &sql_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            2 => compute_entry_hash_v2(
                seq,
                &timestamp,
                &agent_identity,
                &d.subject,
                d.db_evidence.as_ref(),
                d.cancel.as_ref(),
                &d.tool,
                &sql_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            3 => compute_entry_hash_v3(
                seq,
                &timestamp,
                &agent_identity,
                &d.subject,
                d.db_evidence.as_ref(),
                d.cancel.as_ref(),
                &d.tool,
                &sql_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            4 => compute_entry_hash_v4(
                seq,
                &timestamp,
                &agent_identity,
                &d.subject,
                d.db_evidence.as_ref(),
                d.cancel.as_ref(),
                &d.tool,
                &sql_sha256,
                &sql_normalized_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            AUDIT_SCHEMA_V5 => compute_entry_hash_v5(
                seq,
                &timestamp,
                &agent_identity,
                &d.subject,
                d.db_evidence.as_ref(),
                d.cancel.as_ref(),
                &d.tool,
                &sql_sha256,
                &sql_normalized_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            AUDIT_SCHEMA_V6 => compute_entry_hash_v6(
                seq,
                &timestamp,
                &agent_identity,
                &d.subject,
                d.db_evidence.as_ref(),
                d.cancel.as_ref(),
                &d.tool,
                &sql_sha256,
                &sql_normalized_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            AUDIT_SCHEMA_V7 => compute_entry_hash_v7(
                seq,
                &timestamp,
                &agent_identity,
                &d.subject,
                d.db_evidence.as_ref(),
                d.cancel.as_ref(),
                None,
                &d.tool,
                &sql_sha256,
                &sql_normalized_sha256,
                &sql_preview,
                &d.danger_level,
                d.decision,
                d.rows_affected,
                d.outcome,
                prev_hash,
            ),
            other => panic!("unsupported test schema {other}"),
        };
        AuditRecord {
            schema_version,
            seq,
            timestamp,
            agent_identity,
            subject: d.subject.clone(),
            db_evidence: d.db_evidence.clone(),
            cancel: d.cancel.clone(),
            correlation: None,
            tool: d.tool.clone(),
            sql_sha256,
            sql_normalized_sha256: if schema_version >= 4 {
                sql_normalized_sha256
            } else {
                String::new()
            },
            sql_preview,
            danger_level: d.danger_level.clone(),
            decision: d.decision,
            rows_affected: d.rows_affected,
            outcome: d.outcome,
            prev_hash: prev_hash.to_owned(),
            signature: Some(key.sign(&entry_hash)),
            key_id: Some(key.key_id().to_owned()),
            entry_hash,
        }
    }

    fn assert_v5_mutation_breaks(
        base: &AuditRecord,
        label: &str,
        mutate: impl FnOnce(&mut AuditRecord),
    ) {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert!(
            !changed.hash_is_valid(),
            "v5 mutation of {label} must invalidate the canonical hash"
        );
    }

    #[test]
    fn signing_key_enforces_31_32_byte_boundary() {
        for len in [0, 1, 31] {
            SigningKey::new("k1", vec![0x5a; len])
                .expect_err("undersized audit signing key must fail closed");
        }
        SigningKey::new("k1", vec![0x5a; 32]).expect("32-byte audit signing key is valid");
        SigningKey::new("k1", vec![0x5a; 33]).expect("longer audit signing key is valid");
    }

    #[test]
    fn v6_hashes_exact_sql_without_storing_sql_text() {
        let r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert_eq!(r.schema_version, AUDIT_SCHEMA_VERSION);
        assert_eq!(r.subject, AuditSubject::new("agent", "agent-1"));
        assert_eq!(r.agent_identity, "agent:agent-1");
        assert_eq!(r.sql_sha256, sha256_hex(draft().sql.as_bytes()));
        assert_eq!(r.sql_preview, REDACTED_SQL_PREVIEW);
        assert!(!serde_json::to_string(&r).unwrap().contains("orders"));
        assert!(r.hash_is_valid());
        assert_eq!(r.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn db_evidence_is_hash_covered() {
        let mut d = draft();
        d.db_evidence = Some(DbEvidence {
            availability: Some("captured".to_owned()),
            db_unique_name: Some("ORCL23A".to_owned()),
            service_name: Some("freepdb1".to_owned()),
            instance_name: Some("free".to_owned()),
            session_user: Some("APP_USER".to_owned()),
            proxy_user: Some("MCP_PROXY".to_owned()),
            current_schema: Some("APP".to_owned()),
            sid: Some("123".to_owned()),
            serial_number: Some("456".to_owned()),
            client_identifier: Some("agent-a".to_owned()),
            ..DbEvidence::default()
        });
        let mut r = AuditRecord::chained_signed(
            &d,
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
            &key(),
        );
        assert!(r.hash_is_valid());
        r.db_evidence.as_mut().expect("db evidence").current_schema = Some("OTHER".to_owned());
        assert!(
            !r.hash_is_valid(),
            "tampered DB evidence must fail verification"
        );
    }

    #[test]
    fn schema2_db_evidence_hash_still_verifies() {
        let mut d = draft();
        d.db_evidence = Some(DbEvidence {
            session_user: Some("APP_USER".to_owned()),
            current_schema: Some("APP".to_owned()),
            client_identifier: Some("agent-a".to_owned()),
            ..DbEvidence::default()
        });
        let sql_sha256 = sha256_hex(d.sql.as_bytes());
        let sql_preview = d.sql.chars().take(PREVIEW_LEN).collect::<String>();
        let agent_identity = d.subject.legacy_agent_identity();
        let mut r = AuditRecord {
            schema_version: 2,
            seq: 1,
            timestamp: "2026-06-01T00:00:00Z".to_owned(),
            agent_identity,
            subject: d.subject.clone(),
            db_evidence: d.db_evidence.clone(),
            cancel: None,
            correlation: None,
            tool: d.tool.clone(),
            sql_sha256,
            sql_normalized_sha256: String::new(),
            sql_preview,
            danger_level: d.danger_level.clone(),
            decision: d.decision,
            rows_affected: d.rows_affected,
            outcome: d.outcome,
            prev_hash: GENESIS_HASH.to_owned(),
            entry_hash: String::new(),
            key_id: None,
            signature: None,
        };
        r.entry_hash = compute_entry_hash_v2(
            r.seq,
            &r.timestamp,
            &r.agent_identity,
            &r.subject,
            r.db_evidence.as_ref(),
            r.cancel.as_ref(),
            &r.tool,
            &r.sql_sha256,
            &r.sql_preview,
            &r.danger_level,
            r.decision,
            r.rows_affected,
            r.outcome,
            &r.prev_hash,
        );
        assert!(
            r.hash_is_valid(),
            "schema-2 records must keep verifying after schema-3 evidence expansion"
        );
    }

    #[test]
    fn cancel_reason_is_hash_covered() {
        let mut d = draft();
        d.cancel = Some(AuditCancel::new("User", "session_delete"));
        let mut r = AuditRecord::chained_signed(
            &d,
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
            &key(),
        );
        assert!(r.hash_is_valid());
        r.cancel.as_mut().expect("cancel").reason = "server_shutdown".to_owned();
        assert!(
            !r.hash_is_valid(),
            "tampered cancel reason must fail verification"
        );
    }

    #[test]
    fn v7_attempt_terminal_correlation_is_hash_covered() {
        let correlation = AuditCorrelation::terminal("sha256:request", 41);
        let mut record = AuditRecord::chained_signed_correlated(
            &draft(),
            42,
            GENESIS_HASH,
            "2026-07-11T00:00:00Z".to_owned(),
            &key(),
            Some(correlation),
        );
        assert_eq!(record.schema_version, AUDIT_SCHEMA_V7);
        assert!(record.hash_is_valid());
        assert_eq!(record.correlation.as_ref().unwrap().parent_seq, Some(41));

        record.correlation.as_mut().unwrap().parent_seq = Some(40);
        assert!(
            !record.hash_is_valid(),
            "editing the attempt/terminal link must invalidate the chain hash"
        );
    }

    #[test]
    fn tampering_breaks_the_hash() {
        let mut r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert!(r.hash_is_valid());
        r.danger_level = "SAFE".to_owned(); // someone downgrades the record
        assert!(!r.hash_is_valid(), "tampered record must fail verification");
    }

    #[test]
    fn unknown_schema_version_does_not_reuse_v3_hash() {
        let mut r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert!(r.hash_is_valid());
        r.schema_version = 99;
        assert!(
            !r.hash_is_valid(),
            "unknown schema versions must not verify as schema 3"
        );
    }

    #[test]
    fn tampering_with_sql_preview_breaks_the_hash() {
        // The fixed redaction marker is still hash-covered: an actor with write
        // access cannot replace it with a forged statement summary.
        let mut r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert!(r.hash_is_valid());
        assert_eq!(r.sql_preview, REDACTED_SQL_PREVIEW);
        r.sql_preview = "SELECT 1".to_owned();
        assert!(
            !r.hash_is_valid(),
            "tampered sql_preview must fail verification"
        );
    }

    #[test]
    fn long_sql_is_replaced_by_fixed_redaction_marker() {
        let mut d = draft();
        d.sql = "X".repeat(500);
        let r = AuditRecord::chained_unsigned(&d, 2, "sha256:prev", "t".to_owned());
        assert_eq!(r.sql_preview, REDACTED_SQL_PREVIEW);
        assert!(!serde_json::to_string(&r).unwrap().contains(&d.sql));
    }

    #[test]
    fn v6_redacts_oracle_literal_comment_identifier_and_malformed_sql_sentinels() {
        let cases = [
            (
                "UPDATE users SET password = 'QA31_ORDINARY_SECRET'",
                "QA31_ORDINARY_SECRET",
            ),
            (
                "UPDATE users SET password = N'QA31_NCHAR_SECRET'",
                "QA31_NCHAR_SECRET",
            ),
            (
                "UPDATE users SET password = q'[QA31_QQUOTE_SECRET]'",
                "QA31_QQUOTE_SECRET",
            ),
            (
                "SELECT \"QA31_QUOTED_IDENTIFIER\" FROM dual",
                "QA31_QUOTED_IDENTIFIER",
            ),
            (
                "DELETE FROM users WHERE customer_id = 3141592653589793",
                "3141592653589793",
            ),
            (
                "SELECT hextoraw('514133315F4845585F534543524554') FROM dual",
                "514133315F4845585F534543524554",
            ),
            (
                "UPDATE users SET active=0 -- QA31_LINE_COMMENT_SECRET",
                "QA31_LINE_COMMENT_SECRET",
            ),
            (
                "/* QA31_BLOCK_COMMENT_SECRET */ DELETE FROM users",
                "QA31_BLOCK_COMMENT_SECRET",
            ),
            (
                "BEGIN\n  SYS.DBMS_OUTPUT.PUT_LINE('QA31_PLSQL_SECRET');\nEND;",
                "QA31_PLSQL_SECRET",
            ),
            (
                "SELECT 'QA31_UNCLOSED_SECRET FROM dual",
                "QA31_UNCLOSED_SECRET",
            ),
            (
                "SELECT 1 /* QA31_UNCLOSED_COMMENT_SECRET",
                "QA31_UNCLOSED_COMMENT_SECRET",
            ),
        ];

        for (sql, sentinel) in cases {
            let mut d = draft();
            d.sql = sql.to_owned();
            let record = AuditRecord::chained_signed(&d, 1, GENESIS_HASH, "t".to_owned(), &key());
            assert_eq!(record.schema_version, AUDIT_SCHEMA_VERSION);
            assert_eq!(record.sql_preview, REDACTED_SQL_PREVIEW);
            assert_eq!(record.sql_sha256, sha256_hex(sql.as_bytes()));
            assert_eq!(record.sql_normalized_sha256, normalized_sql_sha256(sql));
            assert!(!serde_json::to_string(&record).unwrap().contains(sentinel));
            assert!(!format!("{record:?}").contains(sentinel));
            assert!(!format!("{d:?}").contains(sentinel));
            assert!(record.hash_is_valid());
            assert!(record.signature_is_valid(&key()));
        }
    }

    #[test]
    fn debug_redacts_historical_raw_preview_and_current_draft_sql() {
        let sentinel = "QA31_HISTORICAL_DEBUG_SECRET";
        let mut d = draft();
        d.sql = format!("UPDATE users SET password='{sentinel}'");
        let historical =
            signed_record_for_schema_with_draft(&d, AUDIT_SCHEMA_V5, 1, GENESIS_HASH, &key());
        assert!(historical.sql_preview.contains(sentinel));
        assert!(!format!("{historical:?}").contains(sentinel));
        assert!(!format!("{d:?}").contains(sentinel));
    }

    // ---- K5: normalized-SQL fingerprint (introduced in schema v4) ----

    #[test]
    fn normalized_fingerprint_collapses_whitespace_and_case() {
        // Two trivial variants of the SAME statement must share the normalized
        // fingerprint even though their exact-byte hashes differ.
        let mut a = draft();
        a.sql = "SELECT   *\nFROM  Orders WHERE Id = :id".to_owned();
        let mut b = draft();
        b.sql = "select * from orders where id = :id".to_owned();
        let ra = AuditRecord::chained_unsigned(&a, 1, GENESIS_HASH, "t".to_owned());
        let rb = AuditRecord::chained_unsigned(&b, 1, GENESIS_HASH, "t".to_owned());
        assert_eq!(ra.schema_version, AUDIT_SCHEMA_VERSION);
        assert!(ra.sql_normalized_sha256.starts_with("sha256:"));
        assert_eq!(
            ra.sql_normalized_sha256, rb.sql_normalized_sha256,
            "whitespace/case variants must share the normalized fingerprint"
        );
        assert_ne!(
            ra.sql_sha256, rb.sql_sha256,
            "the exact-byte hash must still distinguish the variants"
        );
    }

    #[test]
    fn normalized_fingerprint_is_hash_covered() {
        // The current chain hash must cover the normalized fingerprint: forging it
        // (e.g. to hide that a blocked attempt matched a known-bad statement)
        // must break verification.
        let mut r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert!(r.hash_is_valid());
        r.sql_normalized_sha256 = sha256_hex(b"something else");
        assert!(
            !r.hash_is_valid(),
            "tampered normalized fingerprint must fail verification"
        );
    }

    #[test]
    fn v3_records_still_verify_against_the_chain() {
        // A schema-3 record (no normalized fingerprint) written before the v4
        // bump must keep verifying byte-for-byte after the field is added.
        let d = draft();
        let sql_sha256 = sha256_hex(d.sql.as_bytes());
        let sql_preview = d.sql.chars().take(PREVIEW_LEN).collect::<String>();
        let agent_identity = d.subject.legacy_agent_identity();
        let entry_hash = compute_entry_hash_v3(
            1,
            "2026-06-01T00:00:00Z",
            &agent_identity,
            &d.subject,
            None,
            None,
            &d.tool,
            &sql_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        let r = AuditRecord {
            schema_version: 3,
            seq: 1,
            timestamp: "2026-06-01T00:00:00Z".to_owned(),
            agent_identity,
            subject: d.subject.clone(),
            db_evidence: None,
            cancel: None,
            correlation: None,
            tool: d.tool.clone(),
            sql_sha256,
            sql_normalized_sha256: String::new(),
            sql_preview,
            danger_level: d.danger_level.clone(),
            decision: d.decision,
            rows_affected: d.rows_affected,
            outcome: d.outcome,
            prev_hash: GENESIS_HASH.to_owned(),
            entry_hash,
            key_id: None,
            signature: None,
        };
        assert!(
            r.hash_is_valid(),
            "schema-3 records must keep verifying after the v4 field is added"
        );
    }

    #[test]
    fn pre_v4_json_without_field_deserializes() {
        // Older JSONL lines have no `sql_normalized_sha256`; #[serde(default)]
        // must let them deserialize (empty) so historical logs still load.
        let json = r#"{
            "schema_version": 3,
            "seq": 7,
            "timestamp": "2026-06-01T00:00:00Z",
            "agent_identity": "agent:agent-1",
            "subject": {"kind": "agent", "stable_id": "agent-1"},
            "tool": "oracle_query",
            "sql_sha256": "sha256:deadbeef",
            "sql_preview": "SELECT 1",
            "danger_level": "SAFE",
            "decision": "ALLOWED",
            "outcome": "SUCCEEDED",
            "prev_hash": "genesis",
            "entry_hash": "sha256:abc"
        }"#;
        let r: AuditRecord = serde_json::from_str(json).expect("legacy record deserializes");
        assert_eq!(r.schema_version, 3);
        assert_eq!(r.sql_normalized_sha256, "");
    }

    #[test]
    fn missing_schema_version_defaults_to_legacy_v1() {
        let json = r#"{
            "seq": 1,
            "timestamp": "2026-06-01T00:00:00Z",
            "agent_identity": "agent",
            "subject": {"kind": "unknown", "stable_id": "unknown"},
            "tool": "oracle_query",
            "sql_sha256": "sha256:deadbeef",
            "sql_preview": "SELECT 1",
            "danger_level": "SAFE",
            "decision": "ALLOWED",
            "outcome": "SUCCEEDED",
            "prev_hash": "genesis",
            "entry_hash": "sha256:abc"
        }"#;
        let r: AuditRecord = serde_json::from_str(json).expect("legacy record deserializes");
        assert_eq!(
            r.schema_version, 1,
            "absent schema_version must deserialize as legacy v1"
        );
    }

    #[test]
    fn subject_builders_preserve_identity_and_optional_auth_fields() {
        let subject = AuditSubject::new("oauth", "sub-123")
            .with_authn_method("mtls")
            .with_client_id("client-a")
            .with_thumbprint("sha256:thumb");
        assert_eq!(subject.kind, "oauth");
        assert_eq!(subject.stable_id, "sub-123");
        assert_eq!(subject.authn_method.as_deref(), Some("mtls"));
        assert_eq!(subject.client_id.as_deref(), Some("client-a"));
        assert_eq!(subject.thumbprint.as_deref(), Some("sha256:thumb"));
        assert_eq!(subject.legacy_agent_identity(), "oauth:sub-123");
    }

    #[test]
    fn unavailable_db_evidence_sets_stable_marker() {
        let evidence = DbEvidence::unavailable("privilege_denied");
        assert_eq!(
            evidence.availability.as_deref(),
            Some("db_evidence_unavailable:privilege_denied")
        );
        assert_eq!(evidence.session_user, None);
    }

    #[test]
    fn signing_key_debug_redacts_secret_material() {
        let sentinel = "do-not-print-this-signing-key-123";
        let key = SigningKey::new("kid", sentinel.as_bytes().to_vec()).expect("valid test key");
        let dbg = format!("{key:?}");
        assert!(dbg.contains("kid"), "{dbg}");
        assert!(dbg.contains("***redacted***"), "{dbg}");
        assert!(!dbg.contains(sentinel), "{dbg}");
    }

    #[test]
    fn versioned_hashes_cover_subject_and_db_evidence() {
        let mut d = draft();
        d.subject = AuditSubject::new("profile", "p1")
            .with_authn_method("password")
            .with_client_id("client-a")
            .with_thumbprint("sha256:a");
        d.db_evidence = Some(DbEvidence {
            availability: Some("captured".to_owned()),
            db_unique_name: Some("ORCL".to_owned()),
            service_name: Some("svc".to_owned()),
            instance_name: Some("inst".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: Some("PROXY".to_owned()),
            current_schema: Some("APP".to_owned()),
            sid: Some("1".to_owned()),
            serial_number: Some("2".to_owned()),
            client_identifier: Some("cid".to_owned()),
            module: Some("oraclemcp".to_owned()),
            action: Some("execute".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
        });
        let sql_sha256 = sha256_hex(d.sql.as_bytes());
        let sql_normalized_sha256 = normalized_sql_sha256(&d.sql);
        let sql_preview = d.sql.chars().take(PREVIEW_LEN).collect::<String>();
        let agent_identity = d.subject.legacy_agent_identity();

        let v1 = compute_entry_hash_v1(
            1,
            "t",
            &agent_identity,
            &d.tool,
            &sql_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        let v2 = compute_entry_hash_v2(
            1,
            "t",
            &agent_identity,
            &d.subject,
            d.db_evidence.as_ref(),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        let v3 = compute_entry_hash_v3(
            1,
            "t",
            &agent_identity,
            &d.subject,
            d.db_evidence.as_ref(),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        let v4 = compute_entry_hash_v4(
            1,
            "t",
            &agent_identity,
            &d.subject,
            d.db_evidence.as_ref(),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        let v5 = compute_entry_hash_v5(
            1,
            "t",
            &agent_identity,
            &d.subject,
            d.db_evidence.as_ref(),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        let v6 = compute_entry_hash_v6(
            1,
            "t",
            &agent_identity,
            &d.subject,
            d.db_evidence.as_ref(),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            REDACTED_SQL_PREVIEW,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        assert_eq!(
            v1,
            "sha256:f558f5ec49672e00a35ba625e6a59f96b7a4de9ca62bcd76ced8268fcb7b97a4"
        );
        assert_eq!(
            v2,
            "sha256:9579160d2f4634da3f4271ee80e5448bb43f8a073c84c6d2d8150dfe11492577"
        );
        assert_eq!(
            v3,
            "sha256:0b211dddb35d19774d3cf4f4e7da2d5277492362d080b0b4b085615cf84fcff1"
        );
        assert_eq!(
            v4,
            "sha256:94a62a27d6d7885f100df103b7c5d9102d77e49b584d6b19e60da15eab54da96"
        );
        assert_eq!(
            v5,
            "sha256:9325c4557119ddb4978d4b826c83aa63191c03b6ab906419590c7ce21c2251d1"
        );
        for hash in [&v1, &v2, &v3, &v4, &v5, &v6] {
            assert!(hash.starts_with("sha256:"), "{hash}");
            assert_eq!(hash.len(), "sha256:".len() + 64, "{hash}");
        }
        assert_ne!(v1, v2, "schema v2 must add subject/evidence coverage");
        assert_ne!(v2, v3, "schema v3 must add expanded DB evidence coverage");
        assert_ne!(v3, v4, "schema v4 must add normalized-SQL coverage");
        assert_ne!(v4, v5, "schema v5 must adopt canonical framing");
        assert_ne!(v5, v6, "schema v6 must bind the redacted representation");

        let mut changed_subject = d.subject.clone();
        changed_subject.client_id = Some("client-b".to_owned());
        let changed_v4 = compute_entry_hash_v4(
            1,
            "t",
            &changed_subject.legacy_agent_identity(),
            &changed_subject,
            d.db_evidence.as_ref(),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        assert_ne!(v4, changed_v4, "structured subject fields are hash-covered");

        let mut changed_evidence = d.db_evidence.clone().expect("evidence");
        changed_evidence.proxy_user = Some("OTHER_PROXY".to_owned());
        let changed_evidence_v4 = compute_entry_hash_v4(
            1,
            "t",
            &agent_identity,
            &d.subject,
            Some(&changed_evidence),
            d.cancel.as_ref(),
            &d.tool,
            &sql_sha256,
            &sql_normalized_sha256,
            &sql_preview,
            &d.danger_level,
            d.decision,
            d.rows_affected,
            d.outcome,
            GENESIS_HASH,
        );
        assert_ne!(
            v4, changed_evidence_v4,
            "expanded DB evidence fields are hash-covered"
        );
    }

    #[test]
    fn v5_rows_affected_presence_is_injective_and_roundtrips() {
        let cases = [None, Some(0), Some(42), Some(u64::MAX)];
        let mut hashes = Vec::new();
        for rows_affected in cases {
            let mut d = draft();
            d.rows_affected = rows_affected;
            let record =
                signed_record_for_schema_with_draft(&d, AUDIT_SCHEMA_V5, 1, GENESIS_HASH, &key());
            let json = serde_json::to_string(&record).expect("serialize v5 record");
            let roundtrip: AuditRecord =
                serde_json::from_str(&json).expect("deserialize v5 record");
            assert_eq!(roundtrip.rows_affected, rows_affected);
            assert!(roundtrip.hash_is_valid());
            assert!(roundtrip.signature_is_valid(&key()));
            hashes.push(record.entry_hash);
        }
        for left in 0..hashes.len() {
            for right in (left + 1)..hashes.len() {
                assert_ne!(
                    hashes[left], hashes[right],
                    "distinct rows_affected values must have distinct v5 hashes"
                );
            }
        }
    }

    #[test]
    fn v5_rows_affected_tamper_fails_hash_then_mac_after_recompute() {
        use crate::{BrokenReason, VerifyOutcome, verify_records};

        let signing_key = key();
        let record = signed_record_for_schema_with_draft(
            &draft(),
            AUDIT_SCHEMA_V5,
            1,
            GENESIS_HASH,
            &signing_key,
        );
        let mut edited = record.clone();
        edited.rows_affected = Some(u64::MAX);
        assert!(!edited.hash_is_valid());
        assert!(
            edited.signature_is_valid(&signing_key),
            "the old MAC still covers the stored old hash until the attacker recomputes it"
        );
        assert!(matches!(
            verify_records(&[edited.clone()], std::slice::from_ref(&signing_key)),
            VerifyOutcome::Broken {
                reason: BrokenReason::HashMismatch,
                ..
            }
        ));

        edited.entry_hash = compute_entry_hash_v5(
            edited.seq,
            &edited.timestamp,
            &edited.agent_identity,
            &edited.subject,
            edited.db_evidence.as_ref(),
            edited.cancel.as_ref(),
            &edited.tool,
            &edited.sql_sha256,
            &edited.sql_normalized_sha256,
            &edited.sql_preview,
            &edited.danger_level,
            edited.decision,
            edited.rows_affected,
            edited.outcome,
            &edited.prev_hash,
        );
        assert!(edited.hash_is_valid());
        assert!(!edited.signature_is_valid(&signing_key));
        assert!(matches!(
            verify_records(&[edited], std::slice::from_ref(&signing_key)),
            VerifyOutcome::Broken {
                reason: BrokenReason::SignatureMismatch,
                ..
            }
        ));
    }

    #[test]
    fn v5_canonical_hash_covers_every_serialized_semantic_field() {
        let mut d = draft();
        d.subject = AuditSubject::new("oauth", "subject")
            .with_authn_method("mtls")
            .with_client_id("client")
            .with_thumbprint("sha256:thumb");
        d.db_evidence = Some(DbEvidence {
            availability: Some("captured".to_owned()),
            db_unique_name: Some("ORCL".to_owned()),
            service_name: Some("svc".to_owned()),
            instance_name: Some("inst".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: Some("PROXY".to_owned()),
            current_schema: Some("APP".to_owned()),
            sid: Some("1".to_owned()),
            serial_number: Some("2".to_owned()),
            client_identifier: Some("cid".to_owned()),
            module: Some("oraclemcp".to_owned()),
            action: Some("execute".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
        });
        d.cancel = Some(AuditCancel::new("User", "session_delete"));
        d.rows_affected = Some(7);
        let base =
            signed_record_for_schema_with_draft(&d, AUDIT_SCHEMA_V5, 1, GENESIS_HASH, &key());

        for index in 0..3 {
            assert_v5_mutation_breaks(&base, "subject optional", |record| match index {
                0 => record.subject.authn_method = None,
                1 => record.subject.client_id = None,
                2 => record.subject.thumbprint = None,
                _ => unreachable!(),
            });
        }
        assert_v5_mutation_breaks(&base, "schema_version", |record| record.schema_version = 4);
        assert_v5_mutation_breaks(&base, "seq", |record| record.seq += 1);
        assert_v5_mutation_breaks(&base, "timestamp", |record| record.timestamp.push('x'));
        assert_v5_mutation_breaks(&base, "agent_identity", |record| {
            record.agent_identity.push('x');
        });
        assert_v5_mutation_breaks(&base, "subject kind", |record| {
            record.subject.kind.push('x')
        });
        assert_v5_mutation_breaks(&base, "subject stable_id", |record| {
            record.subject.stable_id.push('x');
        });
        assert_v5_mutation_breaks(&base, "db_evidence", |record| record.db_evidence = None);
        for index in 0..15 {
            assert_v5_mutation_breaks(&base, "database evidence optional", |record| {
                let evidence = record.db_evidence.as_mut().expect("fixture evidence");
                match index {
                    0 => evidence.availability = None,
                    1 => evidence.db_unique_name = None,
                    2 => evidence.service_name = None,
                    3 => evidence.instance_name = None,
                    4 => evidence.session_user = None,
                    5 => evidence.current_user = None,
                    6 => evidence.proxy_user = None,
                    7 => evidence.current_schema = None,
                    8 => evidence.sid = None,
                    9 => evidence.serial_number = None,
                    10 => evidence.client_identifier = None,
                    11 => evidence.module = None,
                    12 => evidence.action = None,
                    13 => evidence.database_role = None,
                    14 => evidence.open_mode = None,
                    _ => unreachable!(),
                }
            });
        }
        assert_v5_mutation_breaks(&base, "cancel", |record| record.cancel = None);
        assert_v5_mutation_breaks(&base, "tool", |record| record.tool.push('x'));
        assert_v5_mutation_breaks(&base, "sql_sha256", |record| record.sql_sha256.push('x'));
        assert_v5_mutation_breaks(&base, "sql_normalized_sha256", |record| {
            record.sql_normalized_sha256.push('x');
        });
        assert_v5_mutation_breaks(&base, "sql_preview", |record| record.sql_preview.push('x'));
        assert_v5_mutation_breaks(&base, "danger_level", |record| {
            record.danger_level.push('x')
        });
        assert_v5_mutation_breaks(&base, "decision", |record| {
            record.decision = AuditDecision::Blocked;
        });
        assert_v5_mutation_breaks(&base, "rows_affected presence", |record| {
            record.rows_affected = None;
        });
        assert_v5_mutation_breaks(&base, "rows_affected value", |record| {
            record.rows_affected = Some(u64::MAX);
        });
        assert_v5_mutation_breaks(&base, "outcome", |record| {
            record.outcome = AuditOutcome::Failed;
        });
        assert_v5_mutation_breaks(&base, "prev_hash", |record| record.prev_hash.push('x'));

        // key_id and signature are the unchanged MAC envelope rather than
        // entry-hash content. The verifier still fails closed when either is
        // removed.
        let mut missing_key_id = base.clone();
        missing_key_id.key_id = None;
        assert!(matches!(
            crate::verify_records(&[missing_key_id], &[key()]),
            crate::VerifyOutcome::Broken {
                reason: crate::BrokenReason::Unsigned,
                ..
            }
        ));
        let mut missing_signature = base;
        missing_signature.signature = None;
        assert!(matches!(
            crate::verify_records(&[missing_signature], &[key()]),
            crate::VerifyOutcome::Broken {
                reason: crate::BrokenReason::SignatureMismatch,
                ..
            }
        ));
    }

    #[test]
    fn v5_enum_tags_are_stable_and_unique() {
        assert_eq!(
            [
                canonical_decision_tag(AuditDecision::Allowed),
                canonical_decision_tag(AuditDecision::StepUpRequired),
                canonical_decision_tag(AuditDecision::Blocked),
            ],
            [0, 1, 2]
        );
        assert_eq!(
            [
                canonical_outcome_tag(AuditOutcome::Pending),
                canonical_outcome_tag(AuditOutcome::Succeeded),
                canonical_outcome_tag(AuditOutcome::Failed),
                canonical_outcome_tag(AuditOutcome::RolledBack),
                canonical_outcome_tag(AuditOutcome::DiscardedUncommitted),
                canonical_outcome_tag(AuditOutcome::CommitInDoubt),
                canonical_outcome_tag(AuditOutcome::UnknownDiscarded),
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn mixed_v1_through_v7_rotated_chain_verifies() {
        use crate::{VerifyOutcome, verify_records};

        let k1 = key();
        let k2 = SigningKey::new("k2", b"fedcba9876543210fedcba9876543210".to_vec())
            .expect("valid rotated key");
        let mut records = Vec::new();
        let mut prev_hash = GENESIS_HASH.to_owned();
        for schema_version in 1..=AUDIT_SCHEMA_VERSION {
            let signing_key = if schema_version <= 2 { &k1 } else { &k2 };
            let record = signed_record_for_schema(
                schema_version,
                u64::from(schema_version),
                &prev_hash,
                signing_key,
            );
            prev_hash.clone_from(&record.entry_hash);
            records.push(record);
        }
        assert_eq!(
            verify_records(&records, &[k1, k2]),
            VerifyOutcome::Ok { records: 7 }
        );
    }

    proptest! {
        #[test]
        fn v5_rows_affected_encoding_is_injective_before_hashing(
            left in any::<Option<u64>>(),
            right in any::<Option<u64>>(),
        ) {
            prop_assume!(left != right);
            let d = draft();
            prop_assert_ne!(v5_preimage_for(&d, left), v5_preimage_for(&d, right));
        }

        #[test]
        fn arbitrary_sql_is_replaced_by_fixed_v6_marker(sql in any::<String>()) {
            let mut d = draft();
            d.sql = sql.clone();
            let record = AuditRecord::chained_unsigned(&d, 1, GENESIS_HASH, "t".to_owned());
            prop_assert_eq!(record.schema_version, AUDIT_SCHEMA_VERSION);
            prop_assert_eq!(record.sql_preview.as_str(), REDACTED_SQL_PREVIEW);
            prop_assert_eq!(record.sql_sha256.as_str(), sha256_hex(sql.as_bytes()));
            prop_assert_eq!(
                record.sql_normalized_sha256.as_str(),
                normalized_sql_sha256(&sql)
            );
            prop_assert!(record.hash_is_valid());
        }
    }

    #[test]
    fn signed_record_verifies_under_its_key() {
        let r = AuditRecord::chained_signed(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
            &key(),
        );
        assert!(r.hash_is_valid());
        assert!(r.signature_is_valid(&key()));
        assert_eq!(r.key_id.as_deref(), Some("k1"));
        assert!(
            r.signature
                .as_deref()
                .is_some_and(|s| s.starts_with("hmac-sha256:"))
        );
    }

    #[test]
    fn wrong_key_fails_signature() {
        let r = AuditRecord::chained_signed(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
            &key(),
        );
        let attacker = SigningKey::new("k1", b"fedcba9876543210fedcba9876543210".to_vec())
            .expect("valid test key");
        assert!(
            !r.signature_is_valid(&attacker),
            "a record signed with one key must not verify under another"
        );
    }

    #[test]
    fn recompute_from_genesis_without_key_is_detected_by_mac() {
        // The forgery the bare hash chain cannot catch: an attacker edits a
        // record's content and recomputes entry_hash so hash_is_valid() passes.
        // Without the key they cannot produce a matching MAC.
        let mut forged = AuditRecord::chained_signed(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
            &key(),
        );
        // Forge the redacted field and recompute the (unkeyed) hash so the
        // bare-hash check would pass — but leave the old MAC in place.
        forged.sql_preview = "SELECT 1".to_owned();
        forged.entry_hash = compute_entry_hash_v7(
            forged.seq,
            &forged.timestamp,
            &forged.agent_identity,
            &forged.subject,
            forged.db_evidence.as_ref(),
            forged.cancel.as_ref(),
            forged.correlation.as_ref(),
            &forged.tool,
            &forged.sql_sha256,
            &forged.sql_normalized_sha256,
            &forged.sql_preview,
            &forged.danger_level,
            forged.decision,
            forged.rows_affected,
            forged.outcome,
            &forged.prev_hash,
        );
        assert!(
            forged.hash_is_valid(),
            "recompute-from-genesis defeats the bare hash chain"
        );
        assert!(
            !forged.signature_is_valid(&key()),
            "but the keyed MAC over the (now different) entry_hash must not verify"
        );
    }
}
