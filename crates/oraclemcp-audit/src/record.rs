//! The durable audit record + tamper-evidence hash chain (plan §5.13, §6.4).
//!
//! The **monotonic sequence number is the authoritative order key** for the
//! hash chain — never the wall-clock timestamp (a clock jump must not reorder
//! or collide entries, §5.10). Records store the SQL **SHA-256 + a truncated
//! preview**, never bind values or secrets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hmac::{ct_eq, hmac_sha256_hex};

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
}

/// Compute `sha256:<hex>` of bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// One audit entry. `seq` + `prev_hash` + `entry_hash` form the tamper-evident
/// chain; `entry_hash` covers the seq and all content fields — including the
/// operator-legible `sql_preview` — so any edit or reorder breaks verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonic sequence number — the authoritative order key.
    pub seq: u64,
    /// RFC-3339 wall timestamp (display/forensics only; NOT the order key).
    pub timestamp: String,
    /// The agent / session identity.
    pub agent_identity: String,
    /// The tool invoked.
    pub tool: String,
    /// `sha256:<hex>` of the exact SQL bytes (never the bind values).
    pub sql_sha256: String,
    /// A short, truncated preview of the SQL (no bind values / secrets).
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

/// A keyed signing identity for the audit chain: an opaque `key_id` (stored in
/// each record for rotation) plus the secret HMAC key bytes (never serialized).
#[derive(Clone)]
pub struct SigningKey {
    key_id: String,
    key: Vec<u8>,
}

impl SigningKey {
    /// Build a signing key from an id and the raw secret bytes.
    #[must_use]
    pub fn new(key_id: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        SigningKey {
            key_id: key_id.into(),
            key: key.into(),
        }
    }

    /// The key identifier recorded alongside each signature.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The `hmac-sha256:<hex>` signature over an `entry_hash`.
    #[must_use]
    pub fn sign(&self, entry_hash: &str) -> String {
        hmac_sha256_hex(&self.key, entry_hash.as_bytes())
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
#[derive(Clone, Debug)]
pub struct AuditEntryDraft {
    /// Agent / session identity.
    pub agent_identity: String,
    /// Tool name.
    pub tool: String,
    /// The exact SQL (hashed + previewed here; never stored verbatim).
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

/// Max preview characters retained from the SQL text.
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
        let mut record = Self::chained_unsigned(draft, seq, prev_hash, timestamp);
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
        let sql_sha256 = sha256_hex(draft.sql.as_bytes());
        let sql_preview: String = draft.sql.chars().take(PREVIEW_LEN).collect();
        let entry_hash = compute_entry_hash(
            seq,
            &timestamp,
            &draft.agent_identity,
            &draft.tool,
            &sql_sha256,
            &sql_preview,
            &draft.danger_level,
            draft.decision,
            draft.rows_affected,
            draft.outcome,
            prev_hash,
        );
        AuditRecord {
            seq,
            timestamp,
            agent_identity: draft.agent_identity.clone(),
            tool: draft.tool.clone(),
            sql_sha256,
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
        let recomputed = compute_entry_hash(
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
        );
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
        let expected = key.sign(&self.entry_hash);
        ct_eq(expected.as_bytes(), signature.as_bytes())
    }
}

/// Deterministically hash an entry's seq + content + prev_hash. The seq leads,
/// so ordering is bound into the hash independently of the wall timestamp.
#[allow(clippy::too_many_arguments)]
fn compute_entry_hash(
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
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The genesis prev-hash for the first entry.
pub const GENESIS_HASH: &str = "genesis";

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> AuditEntryDraft {
        AuditEntryDraft {
            agent_identity: "agent-1".to_owned(),
            tool: "oracle_query".to_owned(),
            sql: "DELETE FROM orders WHERE id = 1".to_owned(),
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        }
    }

    fn key() -> SigningKey {
        SigningKey::new("k1", b"audit-signing-key".to_vec())
    }

    #[test]
    fn record_hashes_and_previews_without_storing_sql_verbatim() {
        let r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert!(r.sql_sha256.starts_with("sha256:"));
        assert_eq!(r.sql_preview, "DELETE FROM orders WHERE id = 1");
        assert!(r.hash_is_valid());
        assert_eq!(r.prev_hash, GENESIS_HASH);
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
    fn tampering_with_sql_preview_breaks_the_hash() {
        // The only human-legible record of the statement must be hash-covered:
        // an actor with write access to the append-only log must not be able to
        // rewrite "DELETE FROM orders ..." -> "SELECT 1" without breaking
        // verification, even while leaving sql_sha256 / danger_level intact.
        let mut r = AuditRecord::chained_unsigned(
            &draft(),
            1,
            GENESIS_HASH,
            "2026-06-01T00:00:00Z".to_owned(),
        );
        assert!(r.hash_is_valid());
        assert_eq!(r.sql_preview, "DELETE FROM orders WHERE id = 1");
        r.sql_preview = "SELECT 1".to_owned(); // forge the only operator-legible field
        assert!(
            !r.hash_is_valid(),
            "tampered sql_preview must fail verification"
        );
    }

    #[test]
    fn long_sql_preview_truncates() {
        let mut d = draft();
        d.sql = "X".repeat(500);
        let r = AuditRecord::chained_unsigned(&d, 2, "sha256:prev", "t".to_owned());
        assert_eq!(r.sql_preview.chars().count(), PREVIEW_LEN);
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
        let attacker = SigningKey::new("k1", b"guessed-key".to_vec());
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
        // Forge the operator-legible field and recompute the (unkeyed) hash so
        // the bare-hash check would pass — but leave the old MAC in place.
        forged.sql_preview = "SELECT 1".to_owned();
        forged.entry_hash = compute_entry_hash(
            forged.seq,
            &forged.timestamp,
            &forged.agent_identity,
            &forged.tool,
            &forged.sql_sha256,
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
