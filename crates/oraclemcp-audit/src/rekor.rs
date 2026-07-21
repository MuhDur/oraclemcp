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
    /// but never raw SQL because the manifest is hash-only. Offline verification
    /// accepts only a supported Rekor v1 entry schema and its authoritative
    /// artifact-hash field.
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
    /// The method verifies the RFC-6962-style Merkle path locally, structurally
    /// checks that a supported Rekor entry's authoritative artifact-hash field
    /// equals the redacted head-manifest digest, then delegates signature
    /// validation to an independently trusted checkpoint verifier. It makes no
    /// network request and never trusts a server-side "anchored" flag.
    pub fn verify_offline(
        &self,
        checkpoint_verifier: &dyn RekorCheckpointVerifier,
    ) -> Result<(), RekorProofError> {
        validate_proof_shape(&self.proof)?;
        let manifest_sha256 = self.head.manifest_sha256();
        let manifest_hex = manifest_sha256
            .strip_prefix("sha256:")
            .expect("manifest_sha256 is constructed locally with a sha256 prefix");
        verify_entry_binds_manifest(&self.proof.entry_body, manifest_hex)?;

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorHashedRekordEntry {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: RekorHashedRekordSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorHashedRekordSpec {
    data: RekorHashData,
    // Signature contents are covered by Rekor's canonical entry and SET. This
    // binding check only needs to identify the unambiguous signed artifact hash.
    #[serde(rename = "signature")]
    _signature: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorDsseEntry {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: RekorDsseSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorDsseSpec {
    #[serde(rename = "envelopeHash")]
    _envelope_hash: RekorArtifactHash,
    #[serde(rename = "payloadHash")]
    payload_hash: RekorArtifactHash,
    #[serde(rename = "signatures")]
    _signatures: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorHashData {
    hash: RekorArtifactHash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekorArtifactHash {
    algorithm: String,
    value: String,
}

/// Require the manifest digest in the one schema-defined field that Rekor
/// canonicalizes into the entry body. A substring anywhere else is evidence of
/// nothing, and is deliberately rejected.
fn verify_entry_binds_manifest(
    entry_body: &[u8],
    expected_manifest_sha256: &str,
) -> Result<(), RekorProofError> {
    let entry: serde_json::Value =
        serde_json::from_slice(entry_body).map_err(|_| RekorProofError::MalformedProof)?;
    let Some(kind) = entry.get("kind").and_then(serde_json::Value::as_str) else {
        return Err(RekorProofError::HeadNotBoundToEntry);
    };

    let artifact_hash = match kind {
        // Rekor v1 serializes this type as `rekord`; accept the explicit
        // `hashedrekord` spelling too so both supported submitter encodings
        // bind the same authoritative `spec.data.hash` field.
        "rekord" | "hashedrekord" => {
            let entry: RekorHashedRekordEntry =
                serde_json::from_slice(entry_body).map_err(|_| RekorProofError::MalformedProof)?;
            if entry.api_version != "0.0.1"
                || !matches!(entry.kind.as_str(), "rekord" | "hashedrekord")
            {
                return Err(RekorProofError::HeadNotBoundToEntry);
            }
            entry.spec.data.hash
        }
        "dsse" => {
            let entry: RekorDsseEntry =
                serde_json::from_slice(entry_body).map_err(|_| RekorProofError::MalformedProof)?;
            if entry.api_version != "0.0.1" || entry.kind != "dsse" {
                return Err(RekorProofError::HeadNotBoundToEntry);
            }
            // The DSSE payload is the submitted artifact; `envelopeHash` binds
            // its signed container and cannot substitute for this manifest hash.
            entry.spec.payload_hash
        }
        _ => return Err(RekorProofError::HeadNotBoundToEntry),
    };

    if artifact_hash.algorithm == "sha256" && artifact_hash.value == expected_manifest_sha256 {
        Ok(())
    } else {
        Err(RekorProofError::HeadNotBoundToEntry)
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

#[cfg(test)]
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
        let body = hashedrekord_body(&manifest[7..]);
        receipt_with_body(head, body)
    }

    fn receipt_with_body(head: AuditChainHead, body: Vec<u8>) -> RekorAnchorReceipt {
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

    fn hashedrekord_body(manifest_sha256: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": manifest_sha256,
                    },
                },
                "signature": { "content": "signature" },
            },
        }))
        .expect("supported hashedrekord fixture serializes")
    }

    fn dsse_body(manifest_sha256: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "envelopeHash": {
                    "algorithm": "sha256",
                    "value": "11".repeat(32),
                },
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": manifest_sha256,
                },
                "signatures": [{ "signature": "signature", "verifier": "verifier" }],
            },
        }))
        .expect("supported DSSE fixture serializes")
    }

    #[test]
    fn receipt_offline_verification_binds_the_head_and_merkle_root() {
        let receipt = receipt_for(head());
        assert_eq!(receipt.verify_offline(&TestCheckpointVerifier), Ok(()));
    }

    /// `MerkleRootMismatch` had zero coverage before this: every existing
    /// negative test corrupts either the entry body (`HeadNotBoundToEntry`) or
    /// the proof's structural shape (`MalformedProof`), never a root hash that
    /// is well-formed sha256 hex but simply does not reconstruct from the leaf
    /// and siblings. This is the actual tamper-detection arithmetic — a
    /// malicious or buggy Rekor server (or MITM) that returns a bogus root
    /// alongside an otherwise-plausible proof must be caught here, not waved
    /// through because the earlier checks happened to pass.
    #[test]
    fn receipt_rejects_a_well_formed_root_hash_that_does_not_reconstruct() {
        let mut receipt = receipt_for(head());
        // Exactly 64 hex chars, same shape as a real sha256 digest, but not the
        // leaf hash the entry body actually recomputes to.
        receipt.proof.root_hash = "f".repeat(64);
        assert_eq!(
            receipt.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MerkleRootMismatch)
        );
    }

    #[test]
    fn receipt_rejects_an_entry_body_that_does_not_name_the_head_manifest() {
        let mut receipt = receipt_for(head());
        receipt.proof.entry_body = hashedrekord_body(&"00".repeat(32));
        receipt.proof.root_hash = hex_of(rekor_leaf_hash(&receipt.proof.entry_body));
        assert_eq!(
            receipt.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::HeadNotBoundToEntry)
        );
    }

    #[test]
    fn receipt_offline_verification_accepts_exact_dsse_payload_hash() {
        let expected = head();
        let body = dsse_body(&expected.manifest_sha256()[7..]);
        let receipt = receipt_with_body(expected, body);
        assert_eq!(receipt.verify_offline(&TestCheckpointVerifier), Ok(()));
    }

    #[test]
    fn receipt_rejects_digest_outside_authoritative_rekor_hash_field() {
        let expected = head();
        let manifest = expected.manifest_sha256();
        let mut body: serde_json::Value =
            serde_json::from_slice(&hashedrekord_body(&"00".repeat(32)))
                .expect("fixture is valid JSON");
        body["spec"]["signature"]["artifact_hash"] = serde_json::json!(&manifest[7..]);
        let receipt = receipt_with_body(
            expected,
            serde_json::to_vec(&body).expect("fixture serializes"),
        );
        assert_eq!(
            receipt.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::HeadNotBoundToEntry),
            "a digest in signature metadata cannot bind the submitted artifact"
        );
    }

    #[test]
    fn receipt_rejects_superstring_and_ambiguous_or_malformed_entry_bodies() {
        let expected = head();
        let manifest = expected.manifest_sha256();

        let superstring = receipt_with_body(
            expected.clone(),
            hashedrekord_body(&format!("{}00", &manifest[7..])),
        );
        assert_eq!(
            superstring.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::HeadNotBoundToEntry),
            "a hash superstring is not an exact artifact binding"
        );

        let conflicting_hash = "00".repeat(32);
        let duplicate_hash = [
            r#"{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha256","value":""#,
            &manifest[7..],
            r#"","value":""#,
            &conflicting_hash,
            r#""}},"signature":{}}}"#,
        ]
        .concat()
        .into_bytes();
        let duplicate_hash = receipt_with_body(expected.clone(), duplicate_hash);
        assert_eq!(
            duplicate_hash.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "duplicate authoritative hash fields are ambiguous"
        );

        let malformed = receipt_with_body(expected, b"not JSON".to_vec());
        assert_eq!(
            malformed.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof)
        );
    }

    #[test]
    fn receipt_rejects_a_valid_proof_bound_to_a_different_head() {
        let mut receipt = receipt_for(head());
        receipt.head = AuditChainHead {
            seq: 8,
            entry_hash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_owned(),
        };
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

    struct AcceptingSubmitter;

    impl RekorSubmitter for AcceptingSubmitter {
        fn submit(&self, head: &AuditChainHead) -> Result<RekorAnchorReceipt, RekorSubmitError> {
            Ok(receipt_for(head.clone()))
        }
    }

    struct MalformedSubmitter;

    impl RekorSubmitter for MalformedSubmitter {
        fn submit(&self, head: &AuditChainHead) -> Result<RekorAnchorReceipt, RekorSubmitError> {
            let mut receipt = receipt_for(head.clone());
            receipt.proof.root_hash =
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_owned();
            Ok(receipt)
        }
    }

    struct WrongHeadSubmitter;

    impl RekorSubmitter for WrongHeadSubmitter {
        fn submit(&self, head: &AuditChainHead) -> Result<RekorAnchorReceipt, RekorSubmitError> {
            let mut receipt = receipt_for(head.clone());
            receipt.head = AuditChainHead {
                seq: head.seq + 1,
                entry_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
            };
            Ok(receipt)
        }
    }

    struct EmptyBodySubmitter;

    impl RekorSubmitter for EmptyBodySubmitter {
        fn submit(&self, head: &AuditChainHead) -> Result<RekorAnchorReceipt, RekorSubmitError> {
            let mut receipt = receipt_for(head.clone());
            receipt.proof.entry_body = Vec::new();
            Ok(receipt)
        }
    }

    #[test]
    fn async_status_surfaces_queue_progress_and_successful_anchor_counts() {
        let anchor = AsyncRekorAnchor::new(Box::new(AcceptingSubmitter), 1).expect("worker starts");

        anchor.enqueue(head());
        let mut status = anchor.status();
        assert_eq!(status.enqueued, 1);

        let deadline = Instant::now() + Duration::from_secs(1);
        while status.anchored == 0 {
            assert!(
                Instant::now() < deadline,
                "worker should process a valid receipt"
            );
            thread::yield_now();
            status = anchor.status();
        }

        assert_eq!(status.anchored, 1);
        assert_eq!(status.failed, 0);
        assert_eq!(status.dropped, 0);
    }

    #[test]
    fn run_worker_does_not_anchor_malformed_receipts() {
        let anchor = AsyncRekorAnchor::new(Box::new(MalformedSubmitter), 1).expect("worker starts");

        anchor.enqueue(head());
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut status = anchor.status();
        while status.anchored == 0 && status.failed == 0 {
            assert!(
                Instant::now() < deadline,
                "worker should reject malformed receipt"
            );
            thread::yield_now();
            status = anchor.status();
        }

        assert_eq!(status.anchored, 0);
        assert_eq!(status.failed, 1);
        assert!(status.latest_receipt.is_none());
    }

    #[test]
    fn run_worker_rejects_receipts_for_mismatched_head() {
        let anchor = AsyncRekorAnchor::new(Box::new(WrongHeadSubmitter), 1).expect("worker starts");

        anchor.enqueue(head());
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut status = anchor.status();
        while status.anchored == 0 && status.failed == 0 {
            assert!(
                Instant::now() < deadline,
                "worker should reject mismatched-head receipt"
            );
            thread::yield_now();
            status = anchor.status();
        }

        assert_eq!(status.anchored, 0);
        assert_eq!(status.failed, 1);
        assert!(status.latest_receipt.is_none());
    }

    #[test]
    fn run_worker_rejects_receipts_with_empty_entry_body() {
        let anchor = AsyncRekorAnchor::new(Box::new(EmptyBodySubmitter), 1).expect("worker starts");

        anchor.enqueue(head());
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut status = anchor.status();
        while status.anchored == 0 && status.failed == 0 {
            assert!(
                Instant::now() < deadline,
                "worker should reject a receipt missing the entry body"
            );
            thread::yield_now();
            status = anchor.status();
        }

        assert_eq!(status.anchored, 0);
        assert_eq!(status.failed, 1);
        assert!(status.latest_receipt.is_none());
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
    fn manifest_bytes_is_stable_and_schema_versioned() {
        let bytes = head().manifest_bytes();
        assert_eq!(
            bytes,
            b"{\"schema_version\":1,\"audit_seq\":7,\"audit_entry_hash\":\"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}"
                .to_vec()
        );
    }

    #[test]
    fn rekor_limits_match_intended_contract_bounds() {
        assert_eq!(DEFAULT_REKOR_QUEUE_CAPACITY, 8);
        assert_eq!(MAX_REKOR_ENTRY_BODY_BYTES, 16 * 1024);
        assert_eq!(MAX_REKOR_PROOF_HASHES, 128);
        assert_eq!(MAX_REKOR_CHECKPOINT_BYTES, 16 * 1024);
    }

    #[test]
    fn validate_proof_shape_rejects_missing_required_proof_fields() {
        let mut missing_entry_uuid = receipt_for(head());
        missing_entry_uuid.proof.entry_uuid.clear();
        assert_eq!(
            missing_entry_uuid.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "missing entry_uuid must be rejected"
        );

        let mut missing_signed_entry_timestamp = receipt_for(head());
        missing_signed_entry_timestamp
            .proof
            .signed_entry_timestamp
            .clear();
        assert_eq!(
            missing_signed_entry_timestamp.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "missing signed_entry_timestamp must be rejected"
        );

        let mut missing_checkpoint = receipt_for(head());
        missing_checkpoint.proof.checkpoint.clear();
        assert_eq!(
            missing_checkpoint.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "missing checkpoint must be rejected"
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
    fn inclusion_root_reconstructs_expected_roots_for_tree_size_three() {
        let leaves = [
            rekor_leaf_hash(b"leaf-0"),
            rekor_leaf_hash(b"leaf-1"),
            rekor_leaf_hash(b"leaf-2"),
        ];
        let h01 = rekor_node_hash(leaves[0], leaves[1]);
        let expected_root = rekor_node_hash(h01, leaves[2]);

        let proof_for_index_0 = vec![hex_of(leaves[1]), hex_of(leaves[2])];
        assert_eq!(
            inclusion_root(leaves[0], 0, 3, &proof_for_index_0),
            Ok(expected_root),
            "index 0 in tree size 3 should reconstruct expected root"
        );

        let proof_for_index_2 = vec![hex_of(h01)];
        assert_eq!(
            inclusion_root(leaves[2], 2, 3, &proof_for_index_2),
            Ok(expected_root),
            "index 2 in tree size 3 should reconstruct expected root"
        );

        assert_eq!(
            inclusion_root(leaves[2], 3, 3, &proof_for_index_2),
            Err(RekorProofError::MalformedProof),
            "index outside tree-size should be rejected"
        );
    }

    #[test]
    fn inclusion_root_reconstructs_expected_roots_for_power_of_two_trees() {
        let leaves = [rekor_leaf_hash(b"leaf-0"), rekor_leaf_hash(b"leaf-1")];
        let expected_root = rekor_node_hash(leaves[0], leaves[1]);

        assert_eq!(
            inclusion_root(leaves[0], 0, 2, &[hex_of(leaves[1])]),
            Ok(expected_root),
            "index 0 in tree size 2 must reconstruct the expected root"
        );
        assert_eq!(
            inclusion_root(leaves[1], 1, 2, &[hex_of(leaves[0])]),
            Ok(expected_root),
            "index 1 in tree size 2 must reconstruct the expected root"
        );

        assert_eq!(
            inclusion_root(leaves[0], 0, 1, &[]),
            Ok(leaves[0]),
            "tree size 1 must return the leaf hash"
        );
        assert_eq!(
            inclusion_root(leaves[0], 0, 1, &[hex_of(leaves[1])]),
            Err(RekorProofError::MalformedProof),
            "malformed single-leaf proofs with siblings must be rejected"
        );
    }

    #[test]
    fn rekor_leaf_hash_is_domain_separated_by_zero_prefix() {
        let expected = sha256_bytes(&[&[0], b"leaf"]);
        assert_eq!(
            rekor_leaf_hash(b"leaf"),
            expected,
            "leaf hashes must remain tagged as zero-prefix RFC-6962 leaves"
        );
    }

    #[test]
    fn validate_proof_shape_rejects_bounds_and_encoding() {
        let mut zero_tree_size = receipt_for(head());
        zero_tree_size.proof.tree_size = 0;
        assert_eq!(
            zero_tree_size.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "zero Merkle tree_size must be rejected"
        );

        let mut index_out_of_range = receipt_for(head());
        index_out_of_range.proof.tree_size = 2;
        index_out_of_range.proof.log_index = 3;
        assert_eq!(
            index_out_of_range.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "log_index must be within [0, tree_size)"
        );

        let mut malformed_root = receipt_for(head());
        malformed_root.proof.root_hash = "00".repeat(63);
        assert_eq!(
            malformed_root.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "truncated root hash must be rejected"
        );

        let mut malformed_sibling = receipt_for(head());
        malformed_sibling.proof.hashes = vec!["zz".repeat(32)];
        assert_eq!(
            malformed_sibling.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "malformed sibling hash must be rejected"
        );

        let mut oversized_body = receipt_for(head());
        oversized_body.proof.entry_body = vec![0_u8; MAX_REKOR_ENTRY_BODY_BYTES + 1];
        assert_eq!(
            oversized_body.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "oversized entry body must be rejected"
        );

        let mut too_many_hashes = receipt_for(head());
        too_many_hashes
            .proof
            .hashes
            .resize(MAX_REKOR_PROOF_HASHES + 1, "aa".to_owned());
        assert_eq!(
            too_many_hashes.verify_offline(&TestCheckpointVerifier),
            Err(RekorProofError::MalformedProof),
            "too many sibling hashes must be rejected"
        );
    }

    #[test]
    fn validate_proof_shape_accepts_exactly_bound_size_limits() {
        let mut proof_boundary = receipt_for(head()).proof;
        proof_boundary.entry_body = vec![b'a'; MAX_REKOR_ENTRY_BODY_BYTES];
        proof_boundary.hashes = vec!["00".repeat(32); MAX_REKOR_PROOF_HASHES];
        proof_boundary.checkpoint = "x".repeat(MAX_REKOR_CHECKPOINT_BYTES);
        assert_eq!(
            validate_proof_shape(&proof_boundary),
            Ok(()),
            "boundary-sized proof payloads should still be accepted"
        );

        let mut oversized_hash = receipt_for(head()).proof;
        oversized_hash.hashes = vec!["00".repeat(32); MAX_REKOR_PROOF_HASHES + 1];
        assert_eq!(
            validate_proof_shape(&oversized_hash),
            Err(RekorProofError::MalformedProof),
            "proofs beyond the hash limit must be rejected"
        );
    }

    #[test]
    fn validate_proof_shape_directly_rejects_out_of_range_log_index() {
        // validate_proof_shape must reject log_index >= tree_size on its OWN — the
        // full verify_offline pipeline also catches this downstream in
        // inclusion_root, so a pipeline-level test masks a regression in this
        // shape guard. Assert the direct contract so the check stays enforced.
        let mut at_bound = receipt_for(head()).proof;
        at_bound.tree_size = 5;
        at_bound.log_index = 5; // == tree_size, i.e. outside [0, tree_size)
        assert_eq!(
            validate_proof_shape(&at_bound),
            Err(RekorProofError::MalformedProof),
            "log_index == tree_size must be rejected by validate_proof_shape"
        );

        let mut beyond = receipt_for(head()).proof;
        beyond.tree_size = 2;
        beyond.log_index = 7;
        assert_eq!(
            validate_proof_shape(&beyond),
            Err(RekorProofError::MalformedProof),
            "log_index > tree_size must be rejected by validate_proof_shape"
        );
    }

    #[test]
    fn rekor_node_hash_matches_rfc6962_known_answer() {
        // RFC 6962 interior node hash = SHA-256(0x01 || left || right). Pin it
        // against an INDEPENDENTLY computed digest (raw Sha256, not the function
        // under test) so a constant-returning mutant is caught — the inclusion
        // tests derive their expected root via rekor_node_hash itself (circular).
        let left = [0x11_u8; 32];
        let right = [0x22_u8; 32];
        let expected: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update([0x01_u8]);
            h.update(left);
            h.update(right);
            h.finalize().into()
        };
        assert_eq!(
            rekor_node_hash(left, right),
            expected,
            "rekor_node_hash must equal SHA-256(0x01 || left || right)"
        );
        // Guard against the specific constant mutants ([0;32] / [1;32]).
        assert_ne!(rekor_node_hash(left, right), [0_u8; 32]);
        assert_ne!(rekor_node_hash(left, right), [1_u8; 32]);
    }

    #[test]
    fn parse_sha256_hex_accepts_canonical_input_and_rejects_malformed_lengths() {
        let valid = "ab".repeat(32);
        assert!(
            parse_sha256_hex(&valid).is_some(),
            "canonical hex should parse"
        );
        assert!(
            parse_sha256_hex(&"ab".repeat(63)).is_none(),
            "short hex must be rejected"
        );
        assert!(
            parse_sha256_hex(&"ab".repeat(65)).is_none(),
            "long hex must be rejected"
        );
        assert!(
            parse_sha256_hex(&("g".repeat(64))).is_none(),
            "non-hex character must be rejected"
        );
    }

    #[test]
    fn contains_ascii_searches_for_exact_byte_windows() {
        let body = b"{\"artifact_hash\":\"sha256:beef\"}".as_slice();
        assert!(contains_ascii(body, "artifact_hash"));
        assert!(!contains_ascii(body, "missing_token"));
    }

    #[test]
    fn inclusion_root_reconstructs_expected_root_for_tree_size_six() {
        let leaves = [
            rekor_leaf_hash(b"leaf-0"),
            rekor_leaf_hash(b"leaf-1"),
            rekor_leaf_hash(b"leaf-2"),
            rekor_leaf_hash(b"leaf-3"),
            rekor_leaf_hash(b"leaf-4"),
            rekor_leaf_hash(b"leaf-5"),
        ];
        let h01 = rekor_node_hash(leaves[0], leaves[1]);
        let h23 = rekor_node_hash(leaves[2], leaves[3]);
        let h45 = rekor_node_hash(leaves[4], leaves[5]);
        let h0123 = rekor_node_hash(h01, h23);
        let expected_root = rekor_node_hash(h0123, h45);

        let proof_for_0 = vec![hex_of(leaves[1]), hex_of(h23), hex_of(h45)];
        assert_eq!(
            inclusion_root(leaves[0], 0, 6, &proof_for_0),
            Ok(expected_root),
            "index 0 in tree size 6 must reconstruct the expected root"
        );

        let proof_for_4 = vec![hex_of(leaves[5]), hex_of(h0123)];
        assert_eq!(
            inclusion_root(leaves[4], 4, 6, &proof_for_4),
            Ok(expected_root),
            "index 4 in right subtree of size 6 must reconstruct root"
        );

        let proof_for_5 = vec![hex_of(leaves[4]), hex_of(h0123)];
        assert_eq!(
            inclusion_root(leaves[5], 5, 6, &proof_for_5),
            Ok(expected_root),
            "index 5 in right subtree of size 6 must reconstruct root"
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
        assert_eq!(largest_power_of_two_less_than(1_u64 << 63), 1_u64 << 62);
        assert_eq!(largest_power_of_two_less_than(u64::MAX), 1_u64 << 63);
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
