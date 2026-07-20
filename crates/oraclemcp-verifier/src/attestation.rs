//! Signed test attestation: `test-attestation/v1` (plan §32.3, ADR-0012).
//!
//! A test attestation is a small, portable record binding **named tests** to
//! their **recorded outcomes** to a **keyed-MAC signature**, so "these tests
//! passed" stops being an unverifiable CI-log assertion and becomes evidence a
//! holder of an independently trusted MAC key can re-check. It deliberately
//! reuses the audit chain's signing machinery ([`SigningKey`], HMAC-SHA256 over
//! a `sha256:` digest) rather than inventing a new trust primitive. HMAC is
//! symmetric: this is not public-key verification, and anyone given the MAC
//! key can also forge documents.
//!
//! ## What the signature does — and does not — claim
//!
//! The frame is fixed and enforced at both signing and verification time (see
//! [`TEST_ATTESTATION_FRAME`]): a `PASS` records that a named check ran and
//! passed, while `SKIP` explicitly records that it did not run. It is evidence
//! of testing — never a proof of correctness, and never a claim about tests
//! that are not named. A producer cannot use this module to emit a document
//! with a broader claim, and a verifier rejects any altered frame.
//!
//! ## Wire format
//!
//! A signed attestation is a JSONL document of exactly two lines:
//!
//! 1. the payload object (`schema: "test-attestation/v1"`), and
//! 2. the signature object (`schema: "test-attestation-signature/v1"`)
//!    carrying `payload_sha256` = SHA-256 over the **exact bytes of line 1**,
//!    the signing `key_id`, and `signature` =
//!    `HMAC-SHA256(key, payload_sha256)` in the audit chain's
//!    `hmac-sha256:<hex>` rendering.
//!
//! Because the signed message is the exact payload line, no JSON
//! canonicalization is required to verify: hash the received bytes, compare,
//! check the MAC. Any byte-level tamper — reordered keys, whitespace, edited
//! outcomes — breaks `payload_sha256` and is rejected. (Payload fields are
//! still serialized in lexicographic order, mirroring the verdict-certificate
//! core, so producers are deterministic.)
//!
//! ## Fail-closed verification
//!
//! [`verify_test_attestation`] rejects every malformed, unverifiable, or
//! over-claiming document with a typed error. An attestation that cannot be
//! verified is never assumed valid.

use oraclemcp_audit::{SigningKey, sha256_hex};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Payload schema identifier (line 1 of the document).
pub const TEST_ATTESTATION_SCHEMA: &str = "test-attestation/v1";

/// Signature schema identifier (line 2 of the document).
pub const TEST_ATTESTATION_SIGNATURE_SCHEMA: &str = "test-attestation-signature/v1";

/// The fixed, honest claim every attestation carries (plan §3.4 wording rules).
///
/// Enforced on both sides: [`TestAttestation::from_draft`] always writes this
/// exact text, and [`verify_test_attestation`] rejects any document carrying a
/// different frame. The claim is deliberately narrow: evidence that named
/// tests ran with recorded outcomes — not a universal correctness claim.
pub const TEST_ATTESTATION_FRAME: &str = "Signed evidence that the named checks produced the \
     recorded PASS, FAIL, or explicit SKIP outcomes for the recorded commit and toolchain. A \
     PASS records that the named check ran and passed; a SKIP records that it did not run. \
     Evidence of testing, not a proof of correctness, and no claim about checks not named here.";

const MAX_TESTS: usize = 4096;
const MAX_ARTIFACTS: usize = 256;
const MAX_NAME_LEN: usize = 256;
const MAX_DETAIL_LEN: usize = 1024;
const MAX_COMMAND_LEN: usize = 1024;
const MAX_PATH_LEN: usize = 512;
const MAX_LABEL_LEN: usize = 100;

/// Recorded outcome of one named test, mirroring the repo-wide
/// entry-trace tri-state (`PASS`/`SKIP`/`FAIL`); there is no fourth value and
/// no "unknown" — an unknown outcome is a malformed attestation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TestOutcome {
    /// The named test ran and passed.
    #[serde(rename = "PASS")]
    Pass,
    /// The named test was skipped; `detail` should say why.
    #[serde(rename = "SKIP")]
    Skip,
    /// The named test ran and failed. Recording a failure honestly is a valid
    /// attestation; consumers gate on [`TestAttestation::all_tests_passed`].
    #[serde(rename = "FAIL")]
    Fail,
}

/// One named test (or named lane check) and its recorded outcome.
///
/// Field order is lexicographic so compact `serde_json` output is
/// JCS-equivalent, mirroring the verdict-certificate core.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedTest {
    /// Optional short, non-secret context ("kill=92.6% threshold=90").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The test or named-check identifier.
    pub name: String,
    /// The recorded outcome.
    pub outcome: TestOutcome,
}

/// A produced artifact the attested run left behind, bound by digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedArtifact {
    /// Repo-relative (or lane-relative) artifact path.
    pub path: String,
    /// Canonical `sha256:<64 lowercase hex>` digest of the artifact bytes.
    pub sha256: String,
}

/// The unsigned inputs a lane supplies; validated into a [`TestAttestation`].
#[derive(Clone, Debug)]
pub struct TestAttestationDraft {
    /// Lane slug, e.g. `coverage-baseline` or `mutation-safety`
    /// (`^[a-z0-9]+(-[a-z0-9]+)*$`).
    pub lane: String,
    /// Repository name the run executed in.
    pub repo: String,
    /// Full 40-hex commit the tests ran against.
    pub git_sha: String,
    /// Pinned toolchain identifier, e.g. `nightly-2026-05-11`.
    pub toolchain: String,
    /// The exact command that produced the outcomes.
    pub command: String,
    /// UTC creation instant, strict `YYYY-MM-DDTHH:MM:SSZ`.
    pub created_at: String,
    /// The named tests and their outcomes. Must be non-empty.
    pub tests: Vec<AttestedTest>,
    /// Digest-bound artifacts of the run. May be empty.
    pub artifacts: Vec<AttestedArtifact>,
}

/// A validated `test-attestation/v1` payload.
///
/// Constructed only through [`TestAttestation::from_draft`] (which pins the
/// schema and the honest frame) or by [`verify_test_attestation`] (which
/// re-validates every field after authentication). Fields are serialized in
/// lexicographic order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestAttestation {
    artifacts: Vec<AttestedArtifact>,
    command: String,
    created_at: String,
    frame: String,
    git_sha: String,
    lane: String,
    repo: String,
    schema: String,
    tests: Vec<AttestedTest>,
    toolchain: String,
}

/// Line 2 of the document: the detached keyed-MAC signature over line 1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestAttestationSignature {
    /// Identifier of the [`SigningKey`] that produced `signature`.
    pub key_id: String,
    /// `sha256:<hex>` over the exact bytes of the payload line.
    pub payload_sha256: String,
    /// Must be [`TEST_ATTESTATION_SIGNATURE_SCHEMA`].
    pub schema: String,
    /// `hmac-sha256:<hex>` over the `payload_sha256` string.
    pub signature: String,
}

/// A structurally invalid attestation payload (producer- and verifier-side).
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum TestAttestationFormatError {
    /// The payload names a schema this implementation does not produce.
    #[error("attestation schema is not {TEST_ATTESTATION_SCHEMA}")]
    UnsupportedSchema,
    /// The frame text differs from the fixed honest claim.
    #[error("attestation frame is not the fixed evidence-of-testing claim")]
    FrameMismatch,
    /// The lane is not a lowercase `a-z0-9` hyphen-separated slug.
    #[error("attestation lane is not a lowercase slug")]
    InvalidLane,
    /// The repo identifier is empty, too long, or has unsafe characters.
    #[error("attestation repo identifier is invalid")]
    InvalidRepo,
    /// The toolchain identifier is empty, too long, or has unsafe characters.
    #[error("attestation toolchain identifier is invalid")]
    InvalidToolchain,
    /// The command is empty, too long, or contains control characters.
    #[error("attestation command is invalid")]
    InvalidCommand,
    /// `created_at` is not strict `YYYY-MM-DDTHH:MM:SSZ` UTC.
    #[error("attestation created_at is not strict UTC YYYY-MM-DDTHH:MM:SSZ")]
    InvalidCreatedAt,
    /// `git_sha` is not exactly 40 lowercase hex characters.
    #[error("attestation git_sha is not 40 lowercase hex characters")]
    InvalidGitSha,
    /// The test list is empty or oversized — an attestation must name tests.
    #[error("attestation must name between 1 and {MAX_TESTS} tests")]
    InvalidTestCount,
    /// A test name is empty, too long, or contains control characters.
    #[error("attestation test name is invalid")]
    InvalidTestName,
    /// A test name occurs more than once, making its recorded outcome ambiguous.
    #[error("attestation test names must be unique")]
    DuplicateTestName,
    /// A test detail is too long or contains control characters.
    #[error("attestation test detail is invalid")]
    InvalidTestDetail,
    /// The artifact list is oversized.
    #[error("attestation lists more than {MAX_ARTIFACTS} artifacts")]
    InvalidArtifactCount,
    /// An artifact path is empty, too long, or contains control characters.
    #[error("attestation artifact path is invalid")]
    InvalidArtifactPath,
    /// An artifact path occurs more than once, making its digest ambiguous.
    #[error("attestation artifact paths must be unique")]
    DuplicateArtifactPath,
    /// An artifact digest is not canonical `sha256:<64 lowercase hex>`.
    #[error("attestation artifact digest is not canonical sha256")]
    InvalidArtifactDigest,
}

/// A document failed independent verification. Every variant is a rejection;
/// there is no "unverified but accepted" state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum TestAttestationVerificationError {
    /// The document is not exactly one payload line plus one signature line.
    #[error("attestation document is not a two-line payload+signature JSONL")]
    MalformedDocument,
    /// Line 1 is not a parseable payload object.
    #[error("attestation payload line is not valid JSON for the schema")]
    MalformedPayload,
    /// Line 1 parsed but fails payload validation (schema, frame, fields).
    #[error("attestation payload is invalid: {0}")]
    InvalidPayload(#[from] TestAttestationFormatError),
    /// Line 2 is not a parseable signature object.
    #[error("attestation signature line is not valid JSON for the schema")]
    MalformedSignature,
    /// Line 2 names a signature schema this verifier does not support.
    #[error("attestation signature schema is not {TEST_ATTESTATION_SIGNATURE_SCHEMA}")]
    UnsupportedSignatureSchema,
    /// The recorded payload digest does not match the received payload bytes.
    #[error("attestation payload digest does not match the payload line")]
    PayloadDigestMismatch,
    /// No trusted key matches the signature's claimed key identity.
    #[error("attestation signing key is not in the verifier's trusted key set")]
    UntrustedKey,
    /// More than one caller-supplied trusted key has the claimed identity.
    #[error("attestation signing key identity is ambiguous in the trusted key set")]
    AmbiguousKey,
    /// The trusted key cannot reproduce the keyed MAC.
    #[error("attestation signature is invalid")]
    SignatureInvalid,
}

/// The result of a successful independent verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTestAttestation {
    /// The authenticated, re-validated payload.
    pub attestation: TestAttestation,
    /// Which trusted key verified the document.
    pub key_id: String,
    /// The authenticated payload digest (`sha256:<hex>`).
    pub payload_sha256: String,
}

impl TestAttestation {
    /// Validate a draft into a payload carrying the pinned schema and frame.
    ///
    /// # Errors
    ///
    /// Returns the first [`TestAttestationFormatError`] the draft violates.
    pub fn from_draft(draft: TestAttestationDraft) -> Result<Self, TestAttestationFormatError> {
        let attestation = TestAttestation {
            artifacts: draft.artifacts,
            command: draft.command,
            created_at: draft.created_at,
            frame: TEST_ATTESTATION_FRAME.to_owned(),
            git_sha: draft.git_sha,
            lane: draft.lane,
            repo: draft.repo,
            schema: TEST_ATTESTATION_SCHEMA.to_owned(),
            tests: draft.tests,
            toolchain: draft.toolchain,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    /// Re-check every structural rule. Run by [`from_draft`](Self::from_draft)
    /// at production time and again by [`verify_test_attestation`] after
    /// deserializing untrusted bytes, so a hand-crafted document cannot smuggle
    /// an over-claiming frame or malformed field past the schema.
    fn validate(&self) -> Result<(), TestAttestationFormatError> {
        if self.schema != TEST_ATTESTATION_SCHEMA {
            return Err(TestAttestationFormatError::UnsupportedSchema);
        }
        if self.frame != TEST_ATTESTATION_FRAME {
            return Err(TestAttestationFormatError::FrameMismatch);
        }
        if !is_lane_slug(&self.lane) {
            return Err(TestAttestationFormatError::InvalidLane);
        }
        if !is_label(&self.repo) {
            return Err(TestAttestationFormatError::InvalidRepo);
        }
        if !is_label(&self.toolchain) {
            return Err(TestAttestationFormatError::InvalidToolchain);
        }
        if self.command.is_empty()
            || self.command.len() > MAX_COMMAND_LEN
            || has_control_chars(&self.command)
        {
            return Err(TestAttestationFormatError::InvalidCommand);
        }
        if !is_strict_utc_timestamp(&self.created_at) {
            return Err(TestAttestationFormatError::InvalidCreatedAt);
        }
        if self.git_sha.len() != 40
            || !self
                .git_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(TestAttestationFormatError::InvalidGitSha);
        }
        if self.tests.is_empty() || self.tests.len() > MAX_TESTS {
            return Err(TestAttestationFormatError::InvalidTestCount);
        }
        let mut test_names = HashSet::with_capacity(self.tests.len());
        for test in &self.tests {
            if test.name.is_empty()
                || test.name.len() > MAX_NAME_LEN
                || has_control_chars(&test.name)
            {
                return Err(TestAttestationFormatError::InvalidTestName);
            }
            if let Some(detail) = &test.detail
                && (detail.len() > MAX_DETAIL_LEN || has_control_chars(detail))
            {
                return Err(TestAttestationFormatError::InvalidTestDetail);
            }
            if !test_names.insert(test.name.as_str()) {
                return Err(TestAttestationFormatError::DuplicateTestName);
            }
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(TestAttestationFormatError::InvalidArtifactCount);
        }
        let mut artifact_paths = HashSet::with_capacity(self.artifacts.len());
        for artifact in &self.artifacts {
            if !is_safe_relative_path(&artifact.path) {
                return Err(TestAttestationFormatError::InvalidArtifactPath);
            }
            if !is_canonical_sha256(&artifact.sha256) {
                return Err(TestAttestationFormatError::InvalidArtifactDigest);
            }
            if !artifact_paths.insert(artifact.path.as_str()) {
                return Err(TestAttestationFormatError::DuplicateArtifactPath);
            }
        }
        Ok(())
    }

    /// `true` iff every named test's recorded outcome is `PASS`. A `SKIP` is
    /// deliberately *not* a pass: skipped evidence is absent evidence.
    #[must_use]
    pub fn all_tests_passed(&self) -> bool {
        self.tests
            .iter()
            .all(|test| test.outcome == TestOutcome::Pass)
    }

    /// Lane slug the attestation was produced by.
    #[must_use]
    pub fn lane(&self) -> &str {
        &self.lane
    }

    /// Repository the run executed in.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Commit the named tests ran against.
    #[must_use]
    pub fn git_sha(&self) -> &str {
        &self.git_sha
    }

    /// Pinned toolchain identifier recorded for the run.
    #[must_use]
    pub fn toolchain(&self) -> &str {
        &self.toolchain
    }

    /// The exact command that produced the outcomes.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// UTC creation instant.
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// The fixed honest frame text.
    #[must_use]
    pub fn frame(&self) -> &str {
        &self.frame
    }

    /// The named tests and their recorded outcomes.
    #[must_use]
    pub fn tests(&self) -> &[AttestedTest] {
        &self.tests
    }

    /// The digest-bound artifacts of the run.
    #[must_use]
    pub fn artifacts(&self) -> &[AttestedArtifact] {
        &self.artifacts
    }
}

/// Serialize and sign an attestation into its two-line JSONL document.
///
/// Line 1 is the compact payload JSON; line 2 binds it with
/// `payload_sha256` = [`sha256_hex`] over line 1's exact bytes and
/// `signature` = the audit-chain keyed MAC over that digest string — the same
/// [`SigningKey::sign`] call that signs an audit `entry_hash`.
#[must_use]
pub fn sign_test_attestation(attestation: &TestAttestation, key: &SigningKey) -> String {
    let payload_line = serde_json::to_string(attestation)
        .expect("attestation payload contains only infallibly serializable fields");
    let payload_sha256 = sha256_hex(payload_line.as_bytes());
    let signature = TestAttestationSignature {
        key_id: key.key_id().to_owned(),
        signature: key.sign(&payload_sha256),
        payload_sha256,
        schema: TEST_ATTESTATION_SIGNATURE_SCHEMA.to_owned(),
    };
    let signature_line = serde_json::to_string(&signature)
        .expect("attestation signature contains only infallibly serializable fields");
    format!("{payload_line}\n{signature_line}\n")
}

/// Offline-verify a two-line attestation document against caller-supplied,
/// independently trusted secret MAC keys.
///
/// Fail-closed: any structural defect, digest mismatch, unknown key, altered
/// frame, or MAC failure is a typed rejection. The function never falls back
/// to trusting the document's own claims.
///
/// # Errors
///
/// Returns the first [`TestAttestationVerificationError`] the document fails.
pub fn verify_test_attestation(
    document: &str,
    trusted_keys: &[SigningKey],
) -> Result<VerifiedTestAttestation, TestAttestationVerificationError> {
    // Strict LF-only, exactly payload + signature. A CR anywhere (CRLF
    // ambiguity) or any third line is a rejection, not a tolerance.
    if document.contains('\r') {
        return Err(TestAttestationVerificationError::MalformedDocument);
    }
    let body = document
        .strip_suffix('\n')
        .ok_or(TestAttestationVerificationError::MalformedDocument)?;
    let (payload_line, signature_line) = body
        .split_once('\n')
        .ok_or(TestAttestationVerificationError::MalformedDocument)?;
    if payload_line.is_empty() || signature_line.is_empty() || signature_line.contains('\n') {
        return Err(TestAttestationVerificationError::MalformedDocument);
    }

    let signature: TestAttestationSignature = serde_json::from_str(signature_line)
        .map_err(|_| TestAttestationVerificationError::MalformedSignature)?;
    if signature.schema != TEST_ATTESTATION_SIGNATURE_SCHEMA {
        return Err(TestAttestationVerificationError::UnsupportedSignatureSchema);
    }

    let attestation: TestAttestation = serde_json::from_str(payload_line)
        .map_err(|_| TestAttestationVerificationError::MalformedPayload)?;
    attestation.validate()?;

    let payload_sha256 = sha256_hex(payload_line.as_bytes());
    if signature.payload_sha256 != payload_sha256 {
        return Err(TestAttestationVerificationError::PayloadDigestMismatch);
    }

    let mut matching_keys = trusted_keys
        .iter()
        .filter(|key| key.key_id() == signature.key_id);
    let key = matching_keys
        .next()
        .ok_or(TestAttestationVerificationError::UntrustedKey)?;
    if matching_keys.next().is_some() {
        return Err(TestAttestationVerificationError::AmbiguousKey);
    }
    if !key.verify(&payload_sha256, &signature.signature) {
        return Err(TestAttestationVerificationError::SignatureInvalid);
    }

    Ok(VerifiedTestAttestation {
        attestation,
        key_id: signature.key_id,
        payload_sha256,
    })
}

fn has_control_chars(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn is_lane_slug(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_LABEL_LEN {
        return false;
    }
    let mut previous_was_hyphen = true; // forbid a leading hyphen
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_hyphen = false,
            b'-' if !previous_was_hyphen => previous_was_hyphen = true,
            _ => return false,
        }
    }
    !previous_was_hyphen // forbid a trailing hyphen
}

fn is_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_safe_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_PATH_LEN
        || has_control_chars(value)
        || value.starts_with('/')
        || value.contains('\\')
    {
        return false;
    }
    value
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

/// Strict structural `YYYY-MM-DDTHH:MM:SSZ` (UTC, no fractional seconds).
fn is_strict_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    let digit = |i: usize| bytes[i].is_ascii_digit();
    let all_digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
        .iter()
        .all(|&i| digit(i));
    if !(all_digits
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z')
    {
        return false;
    }
    let num = |a: usize, b: usize| (bytes[a] - b'0') as u32 * 10 + (bytes[b] - b'0') as u32;
    let year = (bytes[0] - b'0') as u32 * 1000
        + (bytes[1] - b'0') as u32 * 100
        + (bytes[2] - b'0') as u32 * 10
        + (bytes[3] - b'0') as u32;
    let (month, day) = (num(5, 6), num(8, 9));
    let (hour, minute, second) = (num(11, 12), num(14, 15), num(17, 18));
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    year != 0 && (1..=days_in_month).contains(&day) && hour < 24 && minute < 60 && second < 60
}
