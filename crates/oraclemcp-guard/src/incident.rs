//! The incident-artifact manifest (Arc E): the contract for what an `om incident
//! capture` bundle may contain, and the redaction that keeps it from becoming an
//! exfiltration channel.
//!
//! An incident bundle is a directory:
//!
//! ```text
//! <bundle>/
//!   manifest.json              — an [`IncidentManifest`] (this schema)
//!   cassettes/<lane>.jsonl     — the K6 recorded interactions for one lane
//!   config.redacted.toml       — the profile config with every secret left as a reference
//!   audit-tail.redacted.jsonl  — the redacted audit records around the incident
//! ```
//!
//! `manifest.json` is the only file this module defines. It names the other three
//! by relative path and content hash, so the bundle is self-describing and
//! tamper-evident without this crate having to parse them.
//!
//! # Three properties this schema exists to guarantee
//!
//! **1. It cannot become an exfiltration channel.** An incident is captured
//! around a refusal or a failure — exactly the moments when the interesting
//! bytes are a customer's SQL, their bind values, their connect string, their
//! wallet path. None of that may ever be persisted. Every free-text field is
//! reduced through the *same* redaction seam the Arc J corpus already proved
//! ([`crate::corpus::redact_sql`], [`crate::corpus::safe_why`]) — deliberately
//! not a second implementation, because a second redactor is a second thing to
//! get wrong. Every structured field is an allowlist: lane ids are bare
//! identifiers, subject ids are hashes, versions are version-shaped, and the
//! entry paths are the three fixed bundle names. A path field is the classic
//! place a wallet path or a connect string sneaks in, so paths are matched
//! against a closed pattern rather than merely sanitized.
//!
//! **2. A captured verdict is EVIDENCE, never an authorization input (SEC-1).**
//! [`CapturedVerdict`] records what the guard decided at capture time so an
//! operator can see it. It is deliberately inert: nothing in this module turns a
//! manifest into a [`GuardDecision`], and replay must call
//! [`reclassify_at_replay`] to derive the decision again from the statement. A
//! bundle that claims `SAFE` for a `DROP TABLE` re-classifies as destructive at
//! replay, because the stored verdict is never consulted.
//!
//! **3. The same incident yields the same artifact.** The manifest carries no
//! wall clock and no random id. Lanes and entries are canonically ordered, and
//! [`IncidentManifest::id`] is a content hash over every other field, so
//! capturing the same incident twice produces byte-identical JSON. The id is
//! also the tamper check: [`IncidentManifest::from_json`] re-validates every
//! field and recomputes the id, so a manifest edited on disk to smuggle a secret
//! back in is refused at load rather than believed because it is on disk.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::classifier::{Classifier, GuardDecision};
use crate::corpus::{CorpusRedactionError, redact_sql, safe_why, validate_redacted_sql};
use crate::levels::{DangerLevel, OperatingLevel};

pub use oraclemcp_error::ReasonCategory;

/// Version of the incident-manifest schema. Hashed into the id, so a schema
/// change cannot silently collide with a manifest written by an older build.
pub const INCIDENT_MANIFEST_VERSION: u16 = 1;

/// The manifest file inside a bundle.
pub const MANIFEST_FILE_NAME: &str = "manifest.json";
/// The redacted profile configuration inside a bundle.
pub const REDACTED_CONFIG_FILE_NAME: &str = "config.redacted.toml";
/// The redacted audit tail inside a bundle.
pub const REDACTED_AUDIT_TAIL_FILE_NAME: &str = "audit-tail.redacted.jsonl";
/// The directory holding one K6 cassette per captured lane.
pub const CASSETTE_DIR_NAME: &str = "cassettes";

/// Longest bundle a manifest may describe. A capture that wants more files than
/// this is not an incident, it is an export.
pub const MAX_BUNDLE_ENTRIES: usize = 64;
/// Longest lane list a manifest may describe.
pub const MAX_CAPTURED_LANES: usize = 32;
/// Longest accepted lane id / cassette stem.
pub const MAX_LANE_ID_CHARS: usize = 64;
/// Longest accepted version string.
pub const MAX_VERSION_CHARS: usize = 96;

/// Why a capture could not be represented as a manifest.
///
/// A closed vocabulary with no payload, for the same reason the corpus errors
/// carry none: an error that quoted the offending text would leak the very
/// secret the manifest was refused for, into whatever log or bug report the
/// error lands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IncidentManifestError {
    /// The statement could not be reduced to a safe skeleton.
    #[error("the captured statement did not survive redaction")]
    Statement(CorpusRedactionError),
    /// The `why` text is not drawn from the safe prose alphabet.
    #[error("the incident note is not safe prose")]
    UnsafeWhy,
    /// A lane id is not a bare, server-derived identifier.
    #[error("a lane id is not a bare identifier")]
    UnsafeLaneId,
    /// A subject id is not the `sha256:<hex>` hash form.
    #[error("a subject id is not a hash")]
    UnsafeSubjectId,
    /// A version string is not version-shaped (a path or connect string is not).
    #[error("a build version is not version-shaped")]
    UnsafeVersion,
    /// A bundle entry path is not one of the fixed bundle names.
    #[error("a bundle entry path is not an allowed bundle name")]
    PathNotAllowed,
    /// A bundle entry path does not match the kind it claims.
    #[error("a bundle entry path does not match its kind")]
    PathKindMismatch,
    /// A content hash is not the canonical `sha256:<hex>` wire form.
    #[error("a content hash is not a sha256 digest")]
    InvalidDigest,
    /// The bundle describes the same path twice, or lists no entries at all.
    #[error("the bundle entry list is empty or contains a duplicate path")]
    InvalidBundle,
    /// The manifest describes more lanes or entries than the schema admits.
    #[error("the manifest exceeds a schema bound")]
    TooLarge,
    /// The JSON is not an incident manifest of this schema version.
    #[error("the manifest is malformed or of an unsupported version")]
    Malformed,
    /// The manifest id does not match its content: it was edited after writing.
    #[error("the manifest id does not match its content")]
    IdMismatch,
}

impl From<CorpusRedactionError> for IncidentManifestError {
    fn from(error: CorpusRedactionError) -> Self {
        Self::Statement(error)
    }
}

/// What kind of event the bundle was captured around.
///
/// A closed vocabulary: the trigger is a fact about the server, never a place
/// for free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum IncidentTrigger {
    /// The guard refused a statement.
    Refusal,
    /// A governed operation reached Oracle and failed.
    Failure,
    /// A dispatch panicked.
    Panic,
    /// A session was quarantined with unknown state.
    Quarantine,
    /// An admission or capacity gate rejected the request.
    CapacityRejection,
}

/// What a bundle entry is. The kind fixes the path, not the other way round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BundleEntryKind {
    /// One K6 cassette, under `cassettes/`.
    Cassette,
    /// The redacted profile configuration.
    RedactedConfig,
    /// The redacted audit tail.
    RedactedAuditTail,
}

/// One file the bundle carries, named by relative path and content hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    /// What the file is.
    pub kind: BundleEntryKind,
    /// Bundle-relative path. Always one of the fixed bundle names.
    pub path: String,
    /// `sha256:<hex>` over the file's exact bytes.
    pub sha256: String,
    /// The file's size in bytes.
    pub bytes: u64,
}

/// One captured lane, identified the way the audit chain identifies it: by a
/// server-derived lane id and a hashed subject. Never by a username, and never
/// by a connect string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedLane {
    /// Server-derived lane id (a bare identifier).
    pub lane_id: String,
    /// `sha256:<hex>` (optionally `subject-sha256:<hex>`) of the subject key.
    pub subject_id_hash: String,
}

/// The build identity replay must reproduce to be faithful: the same server, the
/// same classifier ruleset, the same driver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    /// The `oraclemcp` server version.
    pub server: String,
    /// The guard build plus its rule-registry generation.
    pub classifier: String,
    /// The Oracle driver version.
    pub driver: String,
}

/// The guard's decision at capture time.
///
/// **Evidence, not authorization (SEC-1).** This exists so an operator can see
/// what the guard decided; it is never an input to a decision. Nothing in this
/// module converts a [`CapturedVerdict`] into a [`GuardDecision`], and replay
/// re-derives the decision with [`reclassify_at_replay`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedVerdict {
    /// The danger tier the classifier returned.
    pub danger: DangerLevel,
    /// The level it required, absent exactly when the verdict was forbidden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_level: Option<OperatingLevel>,
    /// The closed-vocabulary refusal category, when the decision had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_class: Option<ReasonCategory>,
}

/// The manifest at the root of an incident bundle.
///
/// Constructible only through [`IncidentManifest::capture`] and
/// [`IncidentManifest::from_json`], both of which redact, validate, and then
/// verify the content hash. There is no way to hand-build one with an
/// unredacted field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentManifest {
    /// Schema version. Hashed into `id`.
    pub schema_version: u16,
    /// `sha256:<hex>` content hash over every other field. Also the bundle id.
    pub id: String,
    /// What the bundle was captured around.
    pub trigger: IncidentTrigger,
    /// The seed the recorded run used, so replay is deterministic.
    pub seed: u64,
    /// The statement, reduced to its redacted skeleton. Never the raw SQL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_redacted: Option<String>,
    /// What the guard decided at capture time. Evidence only — see SEC-1 above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_verdict: Option<CapturedVerdict>,
    /// Short, non-secret prose describing the incident.
    pub why: String,
    /// The captured lanes, canonically ordered by lane id.
    pub lanes: Vec<CapturedLane>,
    /// The build replay must reproduce.
    pub build: BuildIdentity,
    /// The bundle's files, canonically ordered by (kind, path).
    pub entries: Vec<BundleEntry>,
}

/// The un-redacted capture input. Everything here is reduced or refused by
/// [`IncidentManifest::capture`]; nothing here reaches disk as given.
#[derive(Clone, Debug)]
pub struct IncidentCapture<'a> {
    /// What happened.
    pub trigger: IncidentTrigger,
    /// The seed the recorded run used.
    pub seed: u64,
    /// The raw statement, if the incident had one. Redacted before it is stored.
    pub statement: Option<&'a str>,
    /// The guard's decision at capture time, if it reached one.
    pub captured_verdict: Option<CapturedVerdict>,
    /// Free prose describing the incident. Reduced through the safe-prose gate.
    pub why: &'a str,
    /// The captured lanes.
    pub lanes: &'a [CapturedLane],
    /// The build identity.
    pub build: BuildIdentity,
    /// The bundle's files.
    pub entries: &'a [BundleEntry],
}

impl IncidentManifest {
    /// Redact a capture into a manifest, or refuse to make one.
    ///
    /// The only way a manifest comes into existence. The statement is reduced to
    /// its skeleton and re-lexed to prove nothing survived; the note must be safe
    /// prose; lane ids, subject hashes, versions, paths and digests must each
    /// match their closed pattern. Any failure returns an error and NO manifest —
    /// an incident that cannot be captured safely is simply not captured.
    pub fn capture(capture: IncidentCapture<'_>) -> Result<Self, IncidentManifestError> {
        let statement_redacted = capture.statement.map(redact_sql).transpose()?;
        if let Some(statement) = statement_redacted.as_deref() {
            validate_redacted_sql(statement)?;
        }
        let why = safe_why(capture.why).map_err(|_| IncidentManifestError::UnsafeWhy)?;

        if capture.lanes.len() > MAX_CAPTURED_LANES || capture.entries.len() > MAX_BUNDLE_ENTRIES {
            return Err(IncidentManifestError::TooLarge);
        }
        for lane in capture.lanes {
            validate_lane_id(&lane.lane_id)?;
            validate_subject_id_hash(&lane.subject_id_hash)?;
        }
        for version in [
            &capture.build.server,
            &capture.build.classifier,
            &capture.build.driver,
        ] {
            validate_version(version)?;
        }
        if capture.entries.is_empty() {
            return Err(IncidentManifestError::InvalidBundle);
        }
        for entry in capture.entries {
            validate_entry(entry)?;
        }

        // Canonical order, so the same incident yields the same bytes no matter
        // what order the capture site happened to walk its lanes and files in.
        let mut lanes = capture.lanes.to_vec();
        lanes.sort_by(|a, b| a.lane_id.cmp(&b.lane_id));
        let mut entries = capture.entries.to_vec();
        entries.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));
        if entries.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(IncidentManifestError::InvalidBundle);
        }

        let mut manifest = Self {
            schema_version: INCIDENT_MANIFEST_VERSION,
            id: String::new(),
            trigger: capture.trigger,
            seed: capture.seed,
            statement_redacted,
            captured_verdict: capture.captured_verdict,
            why,
            lanes,
            build: capture.build,
            entries,
        };
        manifest.id = manifest.content_id();
        Ok(manifest)
    }

    /// Serialize the manifest. Deterministic: no wall clock, no random id, and
    /// every collection is already canonically ordered.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a validated incident manifest always serializes")
    }

    /// Parse and RE-VALIDATE a manifest from disk.
    ///
    /// The stored text is not trusted. Every field is re-checked against the same
    /// postconditions a fresh capture must satisfy, and the id is recomputed: a
    /// manifest hand-edited to smuggle a secret back in — or one whose id no
    /// longer matches its content — is refused at load.
    pub fn from_json(json: &str) -> Result<Self, IncidentManifestError> {
        let manifest: Self =
            serde_json::from_str(json).map_err(|_| IncidentManifestError::Malformed)?;
        if manifest.schema_version != INCIDENT_MANIFEST_VERSION {
            return Err(IncidentManifestError::Malformed);
        }
        if let Some(statement) = manifest.statement_redacted.as_deref() {
            validate_redacted_sql(statement)?;
        }
        if safe_why(&manifest.why).map_err(|_| IncidentManifestError::UnsafeWhy)? != manifest.why {
            return Err(IncidentManifestError::UnsafeWhy);
        }
        if manifest.lanes.len() > MAX_CAPTURED_LANES || manifest.entries.len() > MAX_BUNDLE_ENTRIES
        {
            return Err(IncidentManifestError::TooLarge);
        }
        for lane in &manifest.lanes {
            validate_lane_id(&lane.lane_id)?;
            validate_subject_id_hash(&lane.subject_id_hash)?;
        }
        for version in [
            &manifest.build.server,
            &manifest.build.classifier,
            &manifest.build.driver,
        ] {
            validate_version(version)?;
        }
        if manifest.entries.is_empty() {
            return Err(IncidentManifestError::InvalidBundle);
        }
        for entry in &manifest.entries {
            validate_entry(entry)?;
        }
        if manifest.content_id() != manifest.id {
            return Err(IncidentManifestError::IdMismatch);
        }
        Ok(manifest)
    }

    /// Domain-separated content hash over every field except the id itself.
    fn content_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"oraclemcp:incident-manifest:v1\n");
        hasher.update(self.schema_version.to_be_bytes());
        hasher.update(self.seed.to_be_bytes());
        // Closed enums; their Debug is a stable, non-secret discriminant name.
        for field in [
            format!("{:?}", self.trigger),
            self.statement_redacted.clone().unwrap_or_default(),
            format!("{:?}", self.captured_verdict),
            self.why.clone(),
            format!("{:?}", self.build),
        ] {
            hasher.update([0x1f]);
            hasher.update(field.as_bytes());
        }
        for lane in &self.lanes {
            hasher.update([0x1e]);
            hasher.update(lane.lane_id.as_bytes());
            hasher.update([0x1f]);
            hasher.update(lane.subject_id_hash.as_bytes());
        }
        for entry in &self.entries {
            hasher.update([0x1d]);
            hasher.update(format!("{:?}", entry.kind).as_bytes());
            hasher.update([0x1f]);
            hasher.update(entry.path.as_bytes());
            hasher.update([0x1f]);
            hasher.update(entry.sha256.as_bytes());
            hasher.update([0x1f]);
            hasher.update(entry.bytes.to_be_bytes());
        }
        let mut id = String::from("sha256:");
        for byte in hasher.finalize() {
            use std::fmt::Write as _;
            let _ = write!(id, "{byte:02x}");
        }
        id
    }
}

/// Re-derive the decision at replay from the statement, ignoring whatever the
/// bundle claims the verdict was (SEC-1).
///
/// Replay never trusts a stored verdict: a bundle is an artifact an operator can
/// edit, and a captured `SAFE` on a `DROP TABLE` must not become an admission.
/// This is the *only* path from a manifest's statement back to a decision, and
/// it runs the live classifier every time.
#[must_use]
pub fn reclassify_at_replay(classifier: &Classifier, statement: &str) -> GuardDecision {
    classifier.classify(statement)
}

fn validate_lane_id(lane_id: &str) -> Result<(), IncidentManifestError> {
    let ok = !lane_id.is_empty()
        && lane_id.len() <= MAX_LANE_ID_CHARS
        && lane_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    ok.then_some(()).ok_or(IncidentManifestError::UnsafeLaneId)
}

fn validate_subject_id_hash(subject: &str) -> Result<(), IncidentManifestError> {
    let hex = subject
        .strip_prefix("subject-sha256:")
        .or_else(|| subject.strip_prefix("sha256:"))
        .ok_or(IncidentManifestError::UnsafeSubjectId)?;
    let ok = hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase());
    ok.then_some(())
        .ok_or(IncidentManifestError::UnsafeSubjectId)
}

/// A version is `name/1.2.3;key=value` shaped. A wallet path (`/etc/oracle/…`)
/// has an empty leading segment; a connect string (`host:1521/orcl`) has a
/// colon; a TNS descriptor has parentheses. None of them are version-shaped, so
/// none of them can ride into the bundle in a version field.
///
/// The part after a `/` must START WITH A DIGIT, because it is a version number.
/// Without that rule `system/hunter2` — a credential pair — is "name/name" and
/// passes, which is exactly the shape a leaked Oracle login has.
fn validate_version(version: &str) -> Result<(), IncidentManifestError> {
    if version.is_empty() || version.len() > MAX_VERSION_CHARS {
        return Err(IncidentManifestError::UnsafeVersion);
    }
    let (name, attributes) = match version.split_once(';') {
        Some((name, attributes)) => (name, Some(attributes)),
        None => (version, None),
    };
    let segment_ok = |segment: &str| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
    };
    let mut name_segments = name.split('/');
    let (Some(package), tail) = (name_segments.next(), name_segments.next()) else {
        return Err(IncidentManifestError::UnsafeVersion);
    };
    if !segment_ok(package) || name_segments.next().is_some() {
        return Err(IncidentManifestError::UnsafeVersion);
    }
    if let Some(number) = tail
        && !(segment_ok(number) && number.starts_with(|c: char| c.is_ascii_digit()))
    {
        return Err(IncidentManifestError::UnsafeVersion);
    }
    if let Some(attributes) = attributes {
        for attribute in attributes.split(';') {
            let Some((key, value)) = attribute.split_once('=') else {
                return Err(IncidentManifestError::UnsafeVersion);
            };
            if !segment_ok(key) || !segment_ok(value) {
                return Err(IncidentManifestError::UnsafeVersion);
            }
        }
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), IncidentManifestError> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or(IncidentManifestError::InvalidDigest)?;
    let ok = hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase());
    ok.then_some(()).ok_or(IncidentManifestError::InvalidDigest)
}

/// A bundle path is matched against the three fixed names, never merely
/// sanitized. `..`, an absolute path, a drive letter, a wallet path and a
/// connect string all fail the same way: they are not one of the three names.
fn validate_entry(entry: &BundleEntry) -> Result<(), IncidentManifestError> {
    validate_digest(&entry.sha256)?;
    let expected_kind = match entry.path.as_str() {
        REDACTED_CONFIG_FILE_NAME => BundleEntryKind::RedactedConfig,
        REDACTED_AUDIT_TAIL_FILE_NAME => BundleEntryKind::RedactedAuditTail,
        path => {
            let stem = path
                .strip_prefix(CASSETTE_DIR_NAME)
                .and_then(|rest| rest.strip_prefix('/'))
                .and_then(|rest| rest.strip_suffix(".jsonl"))
                .ok_or(IncidentManifestError::PathNotAllowed)?;
            // The stem is a lane id, so it is bare: no `..`, no separator, no dot.
            validate_lane_id(stem).map_err(|_| IncidentManifestError::PathNotAllowed)?;
            BundleEntryKind::Cassette
        }
    };
    if entry.kind != expected_kind {
        return Err(IncidentManifestError::PathKindMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE_WHY: &str = "the guard refused the operation and recorded the manifest";
    const SUBJECT_PREFIX: &str = "subject-sha256:";
    const DIGEST_PREFIX: &str = "sha256:";

    fn valid_subject_id() -> String {
        format!("{SUBJECT_PREFIX}{}", "a".repeat(64))
    }

    fn valid_entry_digest() -> String {
        format!("{DIGEST_PREFIX}{}", "a".repeat(64))
    }

    fn build_identity() -> BuildIdentity {
        BuildIdentity {
            server: "oraclemcp/0.9.0".to_owned(),
            classifier: "oraclemcp-guard/0.9.0;registry=1".to_owned(),
            driver: "oracledb/0.8.2".to_owned(),
        }
    }

    fn capture_request<'a>(
        statement: &'a str,
        why: &'a str,
        lanes: &'a [CapturedLane],
        entries: &'a [BundleEntry],
    ) -> IncidentCapture<'a> {
        IncidentCapture {
            trigger: IncidentTrigger::Refusal,
            seed: 0x5eed_0000_0000_0001,
            statement: Some(statement),
            captured_verdict: None,
            why,
            lanes,
            build: build_identity(),
            entries,
        }
    }

    fn lanes(count: usize) -> Vec<CapturedLane> {
        (0..count)
            .map(|idx| CapturedLane {
                lane_id: format!("lane-{idx}"),
                subject_id_hash: valid_subject_id(),
            })
            .collect()
    }

    fn cassette_entries(count: usize) -> Vec<BundleEntry> {
        (0..count)
            .map(|idx| BundleEntry {
                kind: BundleEntryKind::Cassette,
                path: format!("cassettes/lane-{idx}.jsonl"),
                sha256: valid_entry_digest(),
                bytes: 1,
            })
            .collect()
    }

    fn valid_capture_result(count_lanes: usize, count_entries: usize) -> IncidentManifest {
        let lanes = lanes(count_lanes);
        let entries = cassette_entries(count_entries);
        IncidentManifest::capture(capture_request(
            "SELECT 1 FROM dual",
            SAFE_WHY,
            &lanes,
            &entries,
        ))
        .expect("a bounded capture is admissible")
    }

    #[test]
    fn capture_rejects_too_many_lanes_before_accepting_any_entry() {
        let lanes = lanes(MAX_CAPTURED_LANES + 1);
        let entries = vec![BundleEntry {
            kind: BundleEntryKind::RedactedConfig,
            path: "config.redacted.toml".to_owned(),
            sha256: valid_entry_digest(),
            bytes: 1,
        }];

        let error = IncidentManifest::capture(capture_request(
            "SELECT 1 FROM dual",
            SAFE_WHY,
            &lanes,
            &entries,
        ))
        .unwrap_err();

        assert_eq!(error, IncidentManifestError::TooLarge);
    }

    #[test]
    fn capture_rejects_too_many_entries_before_binding_grant_outcome() {
        let lanes = lanes(1);
        let mut entries = cassette_entries(MAX_BUNDLE_ENTRIES + 1);
        let extra = BundleEntry {
            kind: BundleEntryKind::RedactedConfig,
            path: "config.redacted.toml".to_string(),
            sha256: valid_entry_digest(),
            bytes: 1,
        };
        entries.push(extra);

        let error = IncidentManifest::capture(capture_request(
            "SELECT 1 FROM dual",
            SAFE_WHY,
            &lanes,
            &entries,
        ))
        .unwrap_err();

        assert_eq!(error, IncidentManifestError::TooLarge);
    }

    #[test]
    fn capture_allows_exact_limit_vectors() {
        assert!(
            valid_capture_result(MAX_CAPTURED_LANES, 1)
                .content_id()
                .starts_with("sha256:")
        );
        assert!(
            valid_capture_result(1, MAX_BUNDLE_ENTRIES)
                .content_id()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn from_json_rejects_schema_version_mismatch() {
        let manifest = valid_capture_result(1, 1);
        let mut json: serde_json::Value =
            serde_json::from_str(&manifest.to_json()).expect("manifest is valid JSON");
        json["schema_version"] = serde_json::Value::from(INCIDENT_MANIFEST_VERSION + 1);

        let tampered = serde_json::to_string(&json).expect("can serialize tampered manifest");
        assert_eq!(
            IncidentManifest::from_json(&tampered).unwrap_err(),
            IncidentManifestError::Malformed
        );
    }

    #[test]
    fn from_json_rejects_too_many_lanes_or_entries_beyond_schema_caps() {
        let manifest = valid_capture_result(1, 1);
        let mut json: serde_json::Value =
            serde_json::from_str(&manifest.to_json()).expect("manifest is valid JSON");
        let lanes = json["lanes"].as_array_mut().expect("lanes are present");
        for _ in lanes.len()..=MAX_CAPTURED_LANES {
            lanes.push(lanes[0].clone());
        }
        let too_many_lanes = serde_json::to_string(&json).expect("serialize overfull lanes");
        assert_eq!(
            IncidentManifest::from_json(&too_many_lanes).unwrap_err(),
            IncidentManifestError::TooLarge
        );

        let mut json: serde_json::Value =
            serde_json::from_str(&manifest.to_json()).expect("manifest is valid JSON");
        let entries = json["entries"].as_array_mut().expect("entries are present");
        while entries.len() <= MAX_BUNDLE_ENTRIES {
            entries.push(entries[0].clone());
        }
        let too_many_entries = serde_json::to_string(&json).expect("serialize overfull entries");
        assert_eq!(
            IncidentManifest::from_json(&too_many_entries).unwrap_err(),
            IncidentManifestError::TooLarge
        );
    }

    #[test]
    fn from_json_accepts_exact_schema_limits_for_lanes_and_entries() {
        let manifest = valid_capture_result(MAX_CAPTURED_LANES, MAX_BUNDLE_ENTRIES);
        let json = manifest.to_json();
        assert_eq!(
            IncidentManifest::from_json(&json).expect("manifest at limits must round-trip"),
            manifest
        );
    }

    #[test]
    fn validate_subject_id_hash_rejects_64_char_nonhex_inputs() {
        let non_hex_subject = format!("{SUBJECT_PREFIX}{}", "g".repeat(64));
        assert_eq!(
            validate_subject_id_hash(&non_hex_subject),
            Err(IncidentManifestError::UnsafeSubjectId)
        );
        assert_eq!(
            validate_subject_id_hash("sha256:"),
            Err(IncidentManifestError::UnsafeSubjectId)
        );
    }

    #[test]
    fn validate_subject_id_hash_accepts_both_hash_prefixes() {
        let hashed_subject = format!("{SUBJECT_PREFIX}{}", "a".repeat(64));
        assert_eq!(validate_subject_id_hash(&hashed_subject), Ok(()));
        assert_eq!(
            validate_subject_id_hash(&format!("sha256:{}", "a".repeat(64))),
            Ok(())
        );
        assert_eq!(
            validate_subject_id_hash(&format!("subject-sha256:{}", "a".repeat(63))),
            Err(IncidentManifestError::UnsafeSubjectId)
        );
    }

    #[test]
    fn validate_digest_rejects_invalid_shape_even_if_prefix_is_sha256() {
        assert_eq!(
            validate_digest(&format!("{DIGEST_PREFIX}{}", "g".repeat(64))),
            Err(IncidentManifestError::InvalidDigest)
        );
        assert_eq!(
            validate_digest("md5:"),
            Err(IncidentManifestError::InvalidDigest)
        );
    }

    #[test]
    fn validate_digest_rejects_wrong_length_or_uppercase_hashes() {
        assert_eq!(
            validate_digest(&format!("{DIGEST_PREFIX}{}", "a".repeat(63))),
            Err(IncidentManifestError::InvalidDigest)
        );
        assert_eq!(
            validate_digest(&format!("{DIGEST_PREFIX}{}", "A".repeat(64))),
            Err(IncidentManifestError::InvalidDigest)
        );
    }

    #[test]
    fn validate_version_honors_length_and_shape_bounds() {
        let at_capacity = format!("pkg/{}", "1".repeat(92));
        assert_eq!(validate_version(&at_capacity), Ok(()));

        let too_long = format!("pkg/{}", "1".repeat(93));
        assert_eq!(
            validate_version(&too_long),
            Err(IncidentManifestError::UnsafeVersion)
        );

        assert_eq!(
            validate_version("pkg/name"),
            Err(IncidentManifestError::UnsafeVersion)
        );
    }

    #[test]
    fn validate_version_rejects_empty_and_invalid_attribute_shapes() {
        assert_eq!(
            validate_version(""),
            Err(IncidentManifestError::UnsafeVersion)
        );
        assert_eq!(
            validate_version("pkg/1;invalid-attr"),
            Err(IncidentManifestError::UnsafeVersion)
        );
        assert_eq!(
            validate_version("pkg/1;flag="),
            Err(IncidentManifestError::UnsafeVersion)
        );
    }
}
