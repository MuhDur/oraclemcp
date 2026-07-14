//! Asynchronous, non-admission-gating Rekor anchors for durable audit heads.
//!
//! Rekor requires a public-key signature over the submitted artifact. The audit
//! HMAC is deliberately not repurposed as that public identity, so an operator
//! supplies a [`RekorSubmitter`] backed by its own Sigstore/Rekor signer. This
//! module owns the safety boundary around that external work: only a durable
//! chain head is queued; Rekor latency/outage cannot delay or refuse an audit
//! append; and a returned receipt is independently checkable offline.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::AuditRecord;

/// Maximum jobs retained while an external Rekor signer is slow or unavailable.
pub const DEFAULT_REKOR_QUEUE_CAPACITY: usize = 8;
/// Bound a receipt's retained Rekor entry body. Audit heads are tiny; larger
/// responses are neither needed for verification nor safe to retain unbounded.
pub const MAX_REKOR_ENTRY_BODY_BYTES: usize = 16 * 1024;
/// Bound the number of Merkle siblings an offline receipt verifier will accept.
pub const MAX_REKOR_PROOF_HASHES: usize = 128;
/// Bound a signed checkpoint retained in a receipt.
pub const MAX_REKOR_CHECKPOINT_BYTES: usize = 16 * 1024;

/// A durable, redacted audit-chain head eligible for external anchoring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainHead {
    /// Hash-chain sequence number.
    pub seq: u64,
    /// Canonical `sha256:<lowercase hex>` entry hash of the durable record.
    pub entry_hash: String,
}

impl AuditChainHead {
    /// Construct the redacted head from an already durable audit record.
    #[must_use]
    pub fn from_record(record: &AuditRecord) -> Self {
        Self {
            seq: record.seq,
            entry_hash: record.entry_hash.clone(),
        }
    }

    /// Canonical bytes whose digest is submitted as the Rekor artifact hash.
    ///
    /// This is intentionally a fixed, redacted manifest — no SQL, bind values,
    /// identifiers, result data, or certificate derivation leaves the host.
    #[must_use]
    pub fn manifest_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"schema_version\":1,\"audit_seq\":{},\"audit_entry_hash\":\"{}\"}}",
            self.seq, self.entry_hash
        )
        .into_bytes()
    }

    /// The artifact hash a Rekor `hashedrekord`/DSSE submission must attest.
    #[must_use]
    pub fn manifest_sha256(&self) -> String {
        sha256_hex(&self.manifest_bytes())
    }
}

/// Rekor inclusion proof fields retained for later offline verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekorInclusionProof {
    /// Rekor entry UUID returned by the create-entry API.
    pub entry_uuid: String,
    /// Rekor log identifier that signed this entry.
    pub log_id: String,
    /// Entry position in the Rekor Merkle tree.
    pub log_index: u64,
    /// Unix time supplied by Rekor when it integrated the entry.
    pub integrated_time: u64,
    /// Exact decoded Rekor entry body used as the Merkle-tree leaf payload.
    /// It may contain public signature metadata and the head manifest digest,
    /// but never raw SQL because the manifest is hash-only.
    pub entry_body: Vec<u8>,
    /// Root hash (lowercase hex) for this inclusion proof.
    pub root_hash: String,
    /// Tree size represented by the proof.
    pub tree_size: u64,
    /// Merkle sibling hashes (lowercase hex), ordered leaf-to-root as Rekor v1
    /// returns them.
    pub hashes: Vec<String>,
    /// Rekor signed checkpoint / signed tree head for this root.
    pub checkpoint: String,
    /// Rekor signed-entry timestamp (SET) for the entry.
    pub signed_entry_timestamp: String,
}

/// A received Rekor inclusion receipt for a specific audit head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekorAnchorReceipt {
    /// The exact audit head whose manifest digest was submitted.
    pub head: AuditChainHead,
    /// Rekor's proof and signed evidence for that submission.
    pub proof: RekorInclusionProof,
}

/// Verify Rekor's signed checkpoint and signed-entry timestamp without network
/// access. Implementations own their independently retained Sigstore trust root.
pub trait RekorCheckpointVerifier: Send + Sync {
    /// Reject a checkpoint/SET that is not valid under the verifier's pinned
    /// Rekor public key and trust policy.
    fn verify_checkpoint(&self, proof: &RekorInclusionProof) -> Result<(), RekorProofError>;
}

impl RekorAnchorReceipt {
    /// Verify the proof offline and confirm it binds this exact audit head.
    ///
    /// The method verifies the RFC-6962-style Merkle path locally, checks that
    /// the published Rekor entry body carries the exact redacted head-manifest
    /// digest, then delegates signature validation to an independently trusted
    /// checkpoint verifier. It makes no network request and never trusts a
    /// server-side "anchored" flag.
    pub fn verify_offline(
        &self,
        checkpoint_verifier: &dyn RekorCheckpointVerifier,
    ) -> Result<(), RekorProofError> {
        validate_proof_shape(&self.proof)?;
        let manifest_sha256 = self.head.manifest_sha256();
        let manifest_hex = manifest_sha256
            .strip_prefix("sha256:")
            .expect("manifest_sha256 is constructed locally with a sha256 prefix");
        if !contains_ascii(&self.proof.entry_body, manifest_hex) {
            return Err(RekorProofError::HeadNotBoundToEntry);
        }

        let leaf_hash = rekor_leaf_hash(&self.proof.entry_body);
        let actual_root = inclusion_root(
            leaf_hash,
            self.proof.log_index,
            self.proof.tree_size,
            &self.proof.hashes,
        )?;
        let expected_root =
            parse_sha256_hex(&self.proof.root_hash).ok_or(RekorProofError::MalformedProof)?;
        if actual_root != expected_root {
            return Err(RekorProofError::MerkleRootMismatch);
        }
        checkpoint_verifier.verify_checkpoint(&self.proof)
    }
}

/// Failure to create a Rekor entry. Error classes are intentionally stable and
/// redact transport details, credentials, and the submitted payload.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RekorSubmitError {
    /// Rekor/signing transport was unavailable or timed out.
    #[error("Rekor submission unavailable")]
    Unavailable,
    /// Rekor or the configured signer refused the proposed entry.
    #[error("Rekor submission rejected")]
    Rejected,
    /// Rekor returned a receipt that could not be retained safely.
    #[error("Rekor submission returned malformed evidence")]
    MalformedReceipt,
}

/// Failure while checking a stored Rekor receipt without contacting Rekor.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RekorProofError {
    /// The receipt exceeds bounded storage/verification limits or has invalid fields.
    #[error("Rekor inclusion proof is malformed")]
    MalformedProof,
    /// The returned Rekor entry does not attest to this exact audit-head manifest.
    #[error("Rekor entry does not bind the audit chain head")]
    HeadNotBoundToEntry,
    /// The supplied Merkle siblings do not reconstruct Rekor's stated root.
    #[error("Rekor inclusion proof root does not verify")]
    MerkleRootMismatch,
    /// The signed checkpoint or signed-entry timestamp does not verify.
    #[error("Rekor signed checkpoint does not verify")]
    CheckpointSignatureInvalid,
}

/// Operator-provided Rekor client and signing boundary.
///
/// The implementation must submit `head.manifest_sha256()` in a real signed
/// Rekor entry (for example a `hashedrekord` or DSSE entry), decode the returned
/// entry body, and return its inclusion proof. It must enforce its own bounded
/// request timeout: this worker deliberately never lets Rekor I/O reach the
/// audit/admission path.
pub trait RekorSubmitter: Send + Sync + 'static {
    /// Submit one durable head and return the externally retained evidence.
    fn submit(&self, head: &AuditChainHead) -> Result<RekorAnchorReceipt, RekorSubmitError>;
}

/// Observable state for the non-blocking Rekor anchor worker.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RekorAnchorStatus {
    /// Heads accepted into the bounded asynchronous queue.
    pub enqueued: u64,
    /// Receipts returned by the configured Rekor submitter.
    pub anchored: u64,
    /// Submission failures. They never change audit admission behavior.
    pub failed: u64,
    /// Heads dropped because the bounded queue was full/disconnected.
    pub dropped: u64,
    /// Most recent accepted receipt, retained for operator export/offline verification.
    pub latest_receipt: Option<RekorAnchorReceipt>,
}

/// Cloneable, bounded asynchronous Rekor anchor queue.
#[derive(Clone)]
pub struct AsyncRekorAnchor {
    sender: SyncSender<AuditChainHead>,
    status: Arc<Mutex<RekorAnchorStatus>>,
}

impl AsyncRekorAnchor {
    /// Start a bounded worker that performs Rekor work outside audit admission.
    ///
    /// # Errors
    /// Returns [`RekorSubmitError::Rejected`] for an invalid zero capacity or
    /// when the background worker cannot be created.
    pub fn new(
        submitter: Box<dyn RekorSubmitter>,
        capacity: usize,
    ) -> Result<Self, RekorSubmitError> {
        if capacity == 0 {
            return Err(RekorSubmitError::Rejected);
        }
        let (sender, receiver) = sync_channel(capacity);
        let status = Arc::new(Mutex::new(RekorAnchorStatus::default()));
        let worker_status = Arc::clone(&status);
        thread::Builder::new()
            .name("audit-rekor-anchor".to_owned())
            .spawn(move || run_worker(receiver, submitter, worker_status))
            .map_err(|_| RekorSubmitError::Rejected)?;
        Ok(Self { sender, status })
    }

    /// Start the worker with the production queue bound.
    pub fn with_default_capacity(
        submitter: Box<dyn RekorSubmitter>,
    ) -> Result<Self, RekorSubmitError> {
        Self::new(submitter, DEFAULT_REKOR_QUEUE_CAPACITY)
    }

    /// Queue a durable head without waiting for signing, network, or Rekor.
    /// Queue pressure is observable in [`Self::status`] but deliberately never
    /// propagates to the caller: transparency anchoring is retrospective proof,
    /// not an admission condition.
    pub fn enqueue(&self, head: AuditChainHead) {
        match self.sender.try_send(head) {
            Ok(()) => {
                let mut status = self.status.lock();
                status.enqueued = status.enqueued.saturating_add(1);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                let mut status = self.status.lock();
                status.dropped = status.dropped.saturating_add(1);
            }
        }
    }

    /// Snapshot worker status without waiting for an external submission.
    #[must_use]
    pub fn status(&self) -> RekorAnchorStatus {
        self.status.lock().clone()
    }
}

fn run_worker(
    receiver: Receiver<AuditChainHead>,
    submitter: Box<dyn RekorSubmitter>,
    status: Arc<Mutex<RekorAnchorStatus>>,
) {
    for head in receiver {
        match submitter.submit(&head) {
            Ok(receipt) if receipt.head == head && validate_proof_shape(&receipt.proof).is_ok() => {
                let mut status = status.lock();
                status.anchored = status.anchored.saturating_add(1);
                status.latest_receipt = Some(receipt);
            }
            Ok(_) | Err(_) => {
                let mut status = status.lock();
                status.failed = status.failed.saturating_add(1);
            }
        }
    }
}

fn validate_proof_shape(proof: &RekorInclusionProof) -> Result<(), RekorProofError> {
    if proof.entry_uuid.is_empty()
        || proof.log_id.len() != 64
        || !proof.log_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || proof.entry_body.is_empty()
        || proof.entry_body.len() > MAX_REKOR_ENTRY_BODY_BYTES
        || proof.tree_size == 0
        || proof.log_index >= proof.tree_size
        || proof.hashes.len() > MAX_REKOR_PROOF_HASHES
        || proof.checkpoint.is_empty()
        || proof.checkpoint.len() > MAX_REKOR_CHECKPOINT_BYTES
        || proof.signed_entry_timestamp.is_empty()
        || parse_sha256_hex(&proof.root_hash).is_none()
        || proof
            .hashes
            .iter()
            .any(|hash| parse_sha256_hex(hash).is_none())
    {
        return Err(RekorProofError::MalformedProof);
    }
    Ok(())
}

fn inclusion_root(
    leaf_hash: [u8; 32],
    index: u64,
    tree_size: u64,
    hashes: &[String],
) -> Result<[u8; 32], RekorProofError> {
    fn recurse(
        leaf: [u8; 32],
        index: u64,
        size: u64,
        hashes: &[String],
    ) -> Result<[u8; 32], RekorProofError> {
        if size == 1 {
            return hashes
                .is_empty()
                .then_some(leaf)
                .ok_or(RekorProofError::MalformedProof);
        }
        let split = largest_power_of_two_less_than(size);
        let sibling = hashes.last().ok_or(RekorProofError::MalformedProof)?;
        let sibling = parse_sha256_hex(sibling).ok_or(RekorProofError::MalformedProof)?;
        let child = if index < split {
            let left = recurse(leaf, index, split, &hashes[..hashes.len() - 1])?;
            rekor_node_hash(left, sibling)
        } else {
            let right = recurse(
                leaf,
                index - split,
                size - split,
                &hashes[..hashes.len() - 1],
            )?;
            rekor_node_hash(sibling, right)
        };
        Ok(child)
    }

    if tree_size == 0 || index >= tree_size {
        return Err(RekorProofError::MalformedProof);
    }
    recurse(leaf_hash, index, tree_size, hashes)
}

fn largest_power_of_two_less_than(value: u64) -> u64 {
    let mut power = 1_u64 << (63 - value.leading_zeros());
    if power == value {
        power >>= 1;
    }
    power
}

fn rekor_leaf_hash(entry_body: &[u8]) -> [u8; 32] {
    sha256_bytes(&[&[0], entry_body])
}

fn rekor_node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    sha256_bytes(&[&[1], &left, &right])
}

fn sha256_bytes(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256_bytes(&[bytes]);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn parse_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn contains_ascii(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor, MemoryAuditSink,
        SigningKey,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Condvar, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    struct TestCheckpointVerifier;

    impl RekorCheckpointVerifier for TestCheckpointVerifier {
        fn verify_checkpoint(&self, _proof: &RekorInclusionProof) -> Result<(), RekorProofError> {
            Ok(())
        }
    }

    fn head() -> AuditChainHead {
        AuditChainHead {
            seq: 7,
            entry_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        }
    }

    fn receipt_for(head: AuditChainHead) -> RekorAnchorReceipt {
        let manifest = head.manifest_sha256();
        let body = format!("{{\"artifact_hash\":\"{}\"}}", &manifest[7..]).into_bytes();
        RekorAnchorReceipt {
            head,
            proof: RekorInclusionProof {
                entry_uuid: "entry-1".to_owned(),
                log_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                log_index: 0,
                integrated_time: 1,
                root_hash: hex_of(rekor_leaf_hash(&body)),
                tree_size: 1,
                hashes: Vec::new(),
                checkpoint: "signed-checkpoint".to_owned(),
                signed_entry_timestamp: "signed-entry-timestamp".to_owned(),
                entry_body: body,
            },
        }
    }

    #[test]
    fn receipt_offline_verification_binds_the_head_and_merkle_root() {
        let receipt = receipt_for(head());
        assert_eq!(receipt.verify_offline(&TestCheckpointVerifier), Ok(()));
    }

    #[test]
    fn receipt_rejects_an_entry_body_that_does_not_name_the_head_manifest() {
        let mut receipt = receipt_for(head());
        receipt.proof.entry_body = b"{\"artifact_hash\":\"different\"}".to_vec();
        receipt.proof.root_hash = hex_of(rekor_leaf_hash(&receipt.proof.entry_body));
        assert_eq!(
            receipt.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::HeadNotBoundToEntry)
        );
    }

    #[test]
    fn inclusion_root_and_proof_shape_reject_malformed_paths() {
        let leaf_hash = rekor_leaf_hash(b"leaf");
        let sibling = [3_u8; 32];
        let hashes = vec![hex_of(sibling)];
        assert_eq!(
            inclusion_root(leaf_hash, 0, 2, &hashes),
            Ok(rekor_node_hash(leaf_hash, sibling))
        );
        assert_eq!(
            inclusion_root(leaf_hash, 1, 2, &hashes),
            Ok(rekor_node_hash(sibling, leaf_hash))
        );
        assert_eq!(
            inclusion_root(leaf_hash, 0, 2, &[]),
            Err(RekorProofError::MalformedProof)
        );

        let mut malformed = receipt_for(head());
        malformed.proof.log_id = "too-short".to_owned();
        assert_eq!(
            malformed.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof)
        );
    }

    #[test]
    fn validate_proof_shape_rejects_noncanonical_and_extra_large_payloads() {
        let mut malformed = receipt_for(head());
        malformed.proof.log_id = "g".repeat(64);
        assert_eq!(
            malformed.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "non-hex log_id must be rejected"
        );

        let mut bad_checkpoint = receipt_for(head());
        bad_checkpoint.proof.checkpoint = "X".repeat(17_000);
        assert_eq!(
            bad_checkpoint.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "oversized checkpoint must be rejected"
        );
    }

    #[test]
    fn inclusion_root_reconstructs_expected_roots_for_non_power_of_two_trees() {
        let leaves = [
            rekor_leaf_hash(b"leaf-0"),
            rekor_leaf_hash(b"leaf-1"),
            rekor_leaf_hash(b"leaf-2"),
            rekor_leaf_hash(b"leaf-3"),
            rekor_leaf_hash(b"leaf-4"),
        ];
        let h01 = rekor_node_hash(leaves[0], leaves[1]);
        let h23 = rekor_node_hash(leaves[2], leaves[3]);
        let h0123 = rekor_node_hash(h01, h23);
        let expected_root = rekor_node_hash(h0123, leaves[4]);

        let proof_for_0 = vec![hex_of(leaves[1]), hex_of(h23), hex_of(leaves[4])];
        assert_eq!(
            inclusion_root(leaves[0], 0, 5, &proof_for_0),
            Ok(expected_root),
            "index 0 in tree size 5 must reconstruct the expected root"
        );

        let proof_for_2 = vec![hex_of(leaves[3]), hex_of(h01), hex_of(leaves[4])];
        assert_eq!(
            inclusion_root(leaves[2], 2, 5, &proof_for_2),
            Ok(expected_root),
            "index 2 in tree size 5 must reconstruct the expected root"
        );

        let proof_for_4 = vec![hex_of(h0123)];
        assert_eq!(
            inclusion_root(leaves[4], 4, 5, &proof_for_4),
            Ok(expected_root),
            "index 4 (rightmost singleton) in tree size 5 must reconstruct root"
        );

        assert_eq!(
            inclusion_root(leaves[4], 4, 5, &[]),
            Err(RekorProofError::MalformedProof),
            "truncated proof must fail for index 4 / tree size 5"
        );
    }

    #[test]
    fn largest_power_of_two_less_than_matches_expected_boundaries() {
        assert_eq!(largest_power_of_two_less_than(1), 0);
        assert_eq!(largest_power_of_two_less_than(2), 1);
        assert_eq!(largest_power_of_two_less_than(3), 2);
        assert_eq!(largest_power_of_two_less_than(4), 2);
        assert_eq!(largest_power_of_two_less_than(5), 4);
        assert_eq!(largest_power_of_two_less_than(6), 4);
        assert_eq!(largest_power_of_two_less_than(9), 8);
        assert_eq!(largest_power_of_two_less_than(17), 16);
    }

    struct BlockingOutage {
        started: Arc<AtomicBool>,
        gate: Arc<(StdMutex<bool>, Condvar)>,
    }

    impl RekorSubmitter for BlockingOutage {
        fn submit(&self, _head: &AuditChainHead) -> Result<RekorAnchorReceipt, RekorSubmitError> {
            self.started.store(true, Ordering::Release);
            let (lock, wake) = &*self.gate;
            let mut released = lock.lock().expect("test gate lock");
            while !*released {
                released = wake.wait(released).expect("test gate wait");
            }
            Err(RekorSubmitError::Unavailable)
        }
    }

    #[test]
    fn outage_enqueue_returns_without_waiting_for_the_background_submitter() {
        let started = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let anchor = AsyncRekorAnchor::new(
            Box::new(BlockingOutage {
                started: Arc::clone(&started),
                gate: Arc::clone(&gate),
            }),
            1,
        )
        .expect("worker starts");

        let began = Instant::now();
        anchor.enqueue(head());
        assert!(
            began.elapsed() < Duration::from_millis(50),
            "enqueue must not wait for a Rekor outage"
        );
        while !started.load(Ordering::Acquire) {
            thread::yield_now();
        }
        let (lock, wake) = &*gate;
        *lock.lock().expect("test gate lock") = true;
        wake.notify_all();
    }

    #[test]
    fn rekor_outage_never_delays_a_durable_audit_append() {
        let started = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let anchor = AsyncRekorAnchor::new(
            Box::new(BlockingOutage {
                started: Arc::clone(&started),
                gate: Arc::clone(&gate),
            }),
            1,
        )
        .expect("worker starts");
        let auditor = Auditor::new(
            Box::new(MemoryAuditSink::new()),
            SigningKey::new("test", b"0123456789abcdef0123456789abcdef".to_vec())
                .expect("valid test key"),
        )
        .with_rekor_anchor(anchor);
        let draft = AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
            tool: "oracle_execute".to_owned(),
            sql: "DELETE FROM t WHERE id = 1".to_owned(),
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        };

        let began = Instant::now();
        let record = auditor
            .append(&draft, "t0".to_owned(), true)
            .expect("durable append must not depend on Rekor availability");
        assert!(
            began.elapsed() < Duration::from_millis(250),
            "a Rekor outage must not delay a durable audit append"
        );
        assert_eq!(record.seq, 1);

        let deadline = Instant::now() + Duration::from_secs(1);
        while !started.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "background Rekor worker did not receive the durable head"
            );
            thread::yield_now();
        }
        let (lock, wake) = &*gate;
        *lock.lock().expect("test gate lock") = true;
        wake.notify_all();
    }

    fn hex_of(value: [u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for byte in value {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}
