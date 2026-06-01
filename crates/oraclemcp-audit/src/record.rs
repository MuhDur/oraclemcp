//! The durable audit record + tamper-evidence hash chain (plan §5.13, §6.4).
//!
//! The **monotonic sequence number is the authoritative order key** for the
//! hash chain — never the wall-clock timestamp (a clock jump must not reorder
//! or collide entries, §5.10). Records store the SQL **SHA-256 + a truncated
//! preview**, never bind values or secrets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
/// chain; `entry_hash` covers the seq and all content fields, so any edit or
/// reorder breaks verification.
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
    /// Build a chained record from a draft, the assigned `seq`, the previous
    /// entry hash, and an RFC-3339 timestamp.
    #[must_use]
    pub fn chained(draft: &AuditEntryDraft, seq: u64, prev_hash: &str, timestamp: String) -> Self {
        let sql_sha256 = sha256_hex(draft.sql.as_bytes());
        let sql_preview: String = draft.sql.chars().take(PREVIEW_LEN).collect();
        let entry_hash = compute_entry_hash(
            seq,
            &timestamp,
            &draft.agent_identity,
            &draft.tool,
            &sql_sha256,
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
        }
    }

    /// Recompute this record's hash and check it matches `entry_hash` (used by
    /// chain verification).
    #[must_use]
    pub fn hash_is_valid(&self) -> bool {
        let recomputed = compute_entry_hash(
            self.seq,
            &self.timestamp,
            &self.agent_identity,
            &self.tool,
            &self.sql_sha256,
            &self.danger_level,
            self.decision,
            self.rows_affected,
            self.outcome,
            &self.prev_hash,
        );
        recomputed == self.entry_hash
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
    danger_level: &str,
    decision: AuditDecision,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    for field in [timestamp, agent_identity, tool, sql_sha256, danger_level] {
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

    #[test]
    fn record_hashes_and_previews_without_storing_sql_verbatim() {
        let r = AuditRecord::chained(&draft(), 1, GENESIS_HASH, "2026-06-01T00:00:00Z".to_owned());
        assert!(r.sql_sha256.starts_with("sha256:"));
        assert_eq!(r.sql_preview, "DELETE FROM orders WHERE id = 1");
        assert!(r.hash_is_valid());
        assert_eq!(r.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn tampering_breaks_the_hash() {
        let mut r =
            AuditRecord::chained(&draft(), 1, GENESIS_HASH, "2026-06-01T00:00:00Z".to_owned());
        assert!(r.hash_is_valid());
        r.danger_level = "SAFE".to_owned(); // someone downgrades the record
        assert!(!r.hash_is_valid(), "tampered record must fail verification");
    }

    #[test]
    fn long_sql_preview_truncates() {
        let mut d = draft();
        d.sql = "X".repeat(500);
        let r = AuditRecord::chained(&d, 2, "sha256:prev", "t".to_owned());
        assert_eq!(r.sql_preview.chars().count(), PREVIEW_LEN);
    }
}
