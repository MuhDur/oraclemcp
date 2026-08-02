//! `om incident capture` (Arc E1): assemble an incident bundle, and refuse to
//! write one that leaks.
//!
//! The layout and the manifest are ADR 0011 / [`oraclemcp_guard::incident`].
//! This module is the part that touches the real material: the audit records,
//! the profile configuration and the recorded lane traffic around an incident.
//! Those are exactly the artifacts that carry a customer's SQL, their schema and
//! table names, their bind values, their service and database names, their
//! usernames, their connect strings and their wallet paths.
//!
//! # How a bundle is kept clean
//!
//! Three layers, in the order a byte meets them:
//!
//! 1. **One redaction path, not a second one.** Every statement — in the
//!    manifest and in every cassette frame — goes through the Arc J corpus
//!    redactor ([`oraclemcp_guard::corpus::redact_sql`]), which reduces it to a
//!    skeleton and then re-lexes it to prove nothing survived. There is no other
//!    way for SQL to enter a bundle.
//!
//! 2. **Allowlist projections, never denylist scrubbing.** The audit tail and
//!    the configuration are not "cleaned"; they are rebuilt from a fixed list of
//!    fields that are safe by construction. `db_evidence` (database, service,
//!    instance, session user, current schema, client identifier) is dropped
//!    *entirely* — every one of those is a customer identifier. `sql_preview` is
//!    dropped too: on records written before schema v6 it can still hold a
//!    truncated **raw** SQL preview. Connect strings, usernames, credential
//!    references and wallet paths are simply not among the fields a redacted
//!    config carries.
//!
//! 3. **A gate that does not trust layers 1 and 2.** The capture site declares
//!    the material it knows is sensitive — the raw SQL it saw, the bind
//!    renderings, the connect string, the wallet path, the usernames. The whole
//!    bundle is assembled **in memory**, every byte of every file is scanned for
//!    that material plus a small set of hard secret shapes, and only then is
//!    anything written to disk. A bundle that would leak is never created: the
//!    capture fails closed and no directory appears. That is what makes a later,
//!    well-meaning loosening of a projection a *test failure* instead of a leak.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use cap_std::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
#[cfg(unix)]
use cap_fs_ext::OpenOptionsMaybeDirExt as _;
use cap_fs_ext::{
    DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, DirBuilder as CapDirBuilder, OpenOptions as CapOpenOptions};
use oraclemcp_audit::AuditRecord;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_guard::classifier::{Classifier, ClassifierConfig};
use oraclemcp_guard::corpus::{CorpusRedactionError, redact_sql, safe_why, validate_redacted_sql};
use oraclemcp_guard::incident::{
    BuildIdentity, BundleEntry, BundleEntryKind, CASSETTE_DIR_NAME, CapturedLane, CapturedVerdict,
    IncidentCapture, IncidentManifest, IncidentManifestError, IncidentTrigger, MANIFEST_FILE_NAME,
    MAX_BUNDLE_ENTRIES, MAX_CAPTURED_LANES, MAX_LANE_ID_CHARS, REDACTED_AUDIT_TAIL_FILE_NAME,
    REDACTED_CONFIG_FILE_NAME,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Secret shapes that may never appear in a bundle, whatever the capture site
/// remembered to declare. Deliberately short and unambiguous: a longer list
/// would tempt someone to treat this as the defence, and it is only the backstop.
const FORBIDDEN_SHAPES: &[&str] = &[
    "cwallet.sso",
    "ewallet.p12",
    "tnsnames.ora",
    "sqlnet.ora",
    "(description=",
    "password=",
    "credential_ref",
];

/// Shortest declared token the gate will scan for. A one- or two-character
/// "secret" would match everywhere and make every capture fail.
const MIN_SENSITIVE_TOKEN_CHARS: usize = 4;

/// Maximum bytes in the complete bounded incident bundle, including its
/// manifest. Incident capture is diagnostic, not a bulk-export mechanism.
pub const MAX_INCIDENT_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes in any individual incident-bundle file.
pub const MAX_INCIDENT_ENTRY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bytes in one cassette frame or redacted audit JSONL record.
pub const MAX_INCIDENT_JSONL_RECORD_BYTES: usize = 64 * 1024;
/// Maximum cassette frames across the complete capture/replay operation.
pub const MAX_INCIDENT_CASSETTE_FRAMES: usize = 10_000;
/// Maximum redacted audit records in one incident bundle.
pub const MAX_INCIDENT_AUDIT_RECORDS: usize = 10_000;
/// Maximum configuration profiles projected into one diagnostic bundle.
pub const MAX_INCIDENT_CONFIG_PROFILES: usize = 4_096;
/// Maximum caller-declared sensitive tokens scanned by the final leak gate.
pub const MAX_INCIDENT_SENSITIVE_TOKENS: usize = 4_096;

/// Why an incident could not be captured.
///
/// [`Self::WouldLeak`] carries no payload, for the same reason the corpus and
/// manifest errors carry none: naming the leaked bytes in an error would put
/// them in the log that the error is written to.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IncidentCaptureError {
    /// A statement did not survive the Arc J redactor.
    #[error("a captured statement did not survive redaction")]
    Redaction(#[from] CorpusRedactionError),
    /// The manifest refused the capture.
    #[error("the incident manifest refused the capture: {0}")]
    Manifest(#[from] IncidentManifestError),
    /// The assembled bundle still contained material the capture site declared
    /// sensitive, or a forbidden secret shape. NOTHING was written.
    #[error("the assembled bundle would have leaked sensitive material; no bundle was written")]
    WouldLeak,
    /// One incident input, entry, or the complete bundle exceeded its fixed
    /// diagnostic-artifact budget. The error carries no rejected bytes.
    #[error("the incident bundle exceeds a fixed capture or replay bound")]
    TooLarge,
    /// The bundle could not be written, or a written file does not match the
    /// manifest.
    #[error("incident bundle io failed: {0}")]
    Io(String),
    /// A required incident-bundle file was absent. The operation is a fixed
    /// implementation label, never an operator-controlled path.
    #[error("incident bundle file is missing while attempting to {operation}")]
    MissingFile {
        /// Fixed operation label for the missing file.
        operation: &'static str,
    },
}

#[derive(Default)]
struct BoundedBundleFiles {
    files: BTreeMap<String, Vec<u8>>,
    total_bytes: usize,
}

impl BoundedBundleFiles {
    fn insert(&mut self, path: String, bytes: Vec<u8>) -> Result<(), IncidentCaptureError> {
        if bytes.len() > MAX_INCIDENT_ENTRY_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        let total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or(IncidentCaptureError::TooLarge)?;
        if total_bytes > MAX_INCIDENT_BUNDLE_BYTES || self.files.contains_key(&path) {
            return Err(IncidentCaptureError::TooLarge);
        }
        self.files.insert(path, bytes);
        self.total_bytes = total_bytes;
        Ok(())
    }
}

#[derive(Default)]
struct IncidentInputBudget {
    total_bytes: usize,
}

impl IncidentInputBudget {
    fn charge(&mut self, value: &str) -> Result<(), IncidentCaptureError> {
        if value.len() > MAX_INCIDENT_ENTRY_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(value.len())
            .ok_or(IncidentCaptureError::TooLarge)?;
        if self.total_bytes > MAX_INCIDENT_BUNDLE_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        Ok(())
    }
}

/// Why a captured incident could not be replayed safely.
///
/// The variants intentionally carry no artifact text or path. A replay error is
/// often copied into an operator ticket; returning the rejected bytes there
/// would turn a fail-closed parser into a disclosure path.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IncidentReplayError {
    /// The bundle failed its manifest/hash verification.
    #[error("the incident bundle could not be verified")]
    Capture(#[from] IncidentCaptureError),
    /// A cassette claimed to be redacted but did not survive the Arc J seam.
    #[error("the incident bundle contains an unsafe replay artifact")]
    UnsafeArtifact,
    /// One lane gave two cassette frames the same deterministic position.
    #[error("the incident bundle has ambiguous replay ordering")]
    AmbiguousOrdering,
    /// The deterministic runtime did not drain after replay.
    #[error("the deterministic replay runtime did not quiesce")]
    RuntimeNotQuiescent,
}

/// One fresh classification derived while replaying an incident cassette.
///
/// This deliberately contains only closed-vocabulary guard results. It does
/// not repeat the statement, tool text, captured verdict, configuration, or
/// audit tail, any of which could carry customer material in a tampered bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncidentReplayStep {
    /// The validated manifest lane that supplied this frame.
    pub lane_id: String,
    /// The lane-local, recorded order of the replayed frame.
    pub seq: u64,
    /// The current classifier's closed danger label.
    pub danger: String,
    /// The current classifier's required operating level, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_level: Option<String>,
    /// The current classifier's closed refusal category, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_class: Option<String>,
}

/// Deterministic, redaction-preserving result of replaying one bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncidentReplayReport {
    /// Content-addressed identity of the verified bundle.
    pub manifest_id: String,
    /// The exact LabRuntime seed used for this replay.
    pub seed: u64,
    /// The number of fresh classifications in [`Self::verdicts`].
    pub replayed_steps: usize,
    /// Freshly derived classifications, in canonical lane/sequence order.
    pub verdicts: Vec<IncidentReplayStep>,
    /// Digest of the redacted audit tail's exact bytes.
    pub audit_tail_sha256: String,
}

/// One recorded interaction in a lane's cassette.
///
/// The SQL is supplied **raw** and redacted here, so a cassette cannot become a
/// second way for a statement to reach disk unredacted.
#[derive(Clone, Debug)]
pub struct CassetteFrame<'a> {
    /// Monotonic position in the lane's recording.
    pub seq: u64,
    /// The tool that was called.
    pub tool: &'a str,
    /// The raw statement, if the frame had one.
    pub statement: Option<&'a str>,
    /// `sha256:<hex>` of the exact statement bytes, when the recorder computed one.
    pub sql_sha256: Option<&'a str>,
    /// The closed-vocabulary outcome label (`succeeded`, `refused`, …).
    pub outcome: &'a str,
}

/// One lane's recorded traffic.
#[derive(Clone, Debug)]
pub struct Cassette<'a> {
    /// The lane the frames belong to. Also the cassette's file stem.
    pub lane_id: &'a str,
    /// The frames, in recorded order.
    pub frames: &'a [CassetteFrame<'a>],
}

/// A redacted cassette frame, as written to `cassettes/<lane>.jsonl`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedCassetteFrame {
    /// Position in the recording.
    pub seq: u64,
    /// The tool that was called.
    pub tool: String,
    /// The statement, reduced to its redacted skeleton.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_redacted: Option<String>,
    /// The exact-bytes digest, which is a correlation handle, not the SQL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_sha256: Option<String>,
    /// The outcome label.
    pub outcome: String,
}

/// Everything the capture site knows about an incident.
#[derive(Debug)]
pub struct IncidentCaptureRequest<'a> {
    /// What happened.
    pub trigger: IncidentTrigger,
    /// The seed the recorded run used, so replay is deterministic.
    pub seed: u64,
    /// The raw statement at the centre of the incident, if there was one.
    pub statement: Option<&'a str>,
    /// What the guard decided. Evidence only — replay re-classifies (SEC-1).
    pub captured_verdict: Option<CapturedVerdict>,
    /// Short prose describing the incident.
    pub why: &'a str,
    /// The lanes involved, already identified by hash.
    pub lanes: &'a [CapturedLane],
    /// The build replay must reproduce.
    pub build: BuildIdentity,
    /// The audit records around the incident.
    pub audit_records: &'a [AuditRecord],
    /// The recorded lane traffic.
    pub cassettes: &'a [Cassette<'a>],
    /// The live configuration, projected down to its non-secret metadata.
    pub config: &'a OracleMcpConfig,
    /// Material the capture site KNOWS is sensitive: the raw SQL it saw, bind
    /// renderings, connect strings, usernames, wallet paths. The gate scans the
    /// assembled bundle for these exact bytes and refuses to write if any
    /// survives. Declaring more here can only make the capture stricter.
    pub sensitive: &'a [String],
}

fn validate_capture_inputs(
    request: &IncidentCaptureRequest<'_>,
) -> Result<(), IncidentCaptureError> {
    if request.audit_records.len() > MAX_INCIDENT_AUDIT_RECORDS
        || request.lanes.len() > MAX_CAPTURED_LANES
        || request.config.profiles.len() > MAX_INCIDENT_CONFIG_PROFILES
        || request.sensitive.len() > MAX_INCIDENT_SENSITIVE_TOKENS
        || request
            .cassettes
            .len()
            .checked_add(2)
            .is_none_or(|count| count > MAX_BUNDLE_ENTRIES)
    {
        return Err(IncidentCaptureError::TooLarge);
    }

    let mut budget = IncidentInputBudget::default();
    if let Some(statement) = request.statement {
        budget.charge(statement)?;
    }
    budget.charge(request.why)?;
    budget.charge(&request.build.server)?;
    budget.charge(&request.build.classifier)?;
    budget.charge(&request.build.driver)?;
    for lane in request.lanes {
        budget.charge(&lane.lane_id)?;
        budget.charge(&lane.subject_id_hash)?;
    }
    for token in request.sensitive {
        budget.charge(token)?;
    }
    for profile in &request.config.profiles {
        budget.charge(&profile.name)?;
        if let Some(description) = profile.description.as_deref() {
            budget.charge(description)?;
        }
    }

    let mut frame_count = 0usize;
    for cassette in request.cassettes {
        budget.charge(cassette.lane_id)?;
        frame_count = frame_count
            .checked_add(cassette.frames.len())
            .ok_or(IncidentCaptureError::TooLarge)?;
        if frame_count > MAX_INCIDENT_CASSETTE_FRAMES {
            return Err(IncidentCaptureError::TooLarge);
        }
        for frame in cassette.frames {
            let mut frame_bytes = 0usize;
            charge_record_field(&mut budget, &mut frame_bytes, frame.tool)?;
            if let Some(statement) = frame.statement {
                charge_record_field(&mut budget, &mut frame_bytes, statement)?;
            }
            if let Some(sql_sha256) = frame.sql_sha256 {
                charge_record_field(&mut budget, &mut frame_bytes, sql_sha256)?;
            }
            charge_record_field(&mut budget, &mut frame_bytes, frame.outcome)?;
        }
    }

    for record in request.audit_records {
        let mut record_bytes = 0usize;
        for value in [
            record.timestamp.as_str(),
            record.subject.kind.as_str(),
            record.subject.stable_id.as_str(),
            record.tool.as_str(),
            record.danger_level.as_str(),
            record.sql_sha256.as_str(),
            record.sql_normalized_sha256.as_str(),
            record.prev_hash.as_str(),
            record.entry_hash.as_str(),
        ] {
            charge_record_field(&mut budget, &mut record_bytes, value)?;
        }
        for value in [
            record.verdict_certificate_core_hash.as_deref(),
            record.key_id.as_deref(),
            record.signature.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            charge_record_field(&mut budget, &mut record_bytes, value)?;
        }
    }
    Ok(())
}

fn charge_record_field(
    budget: &mut IncidentInputBudget,
    record_bytes: &mut usize,
    value: &str,
) -> Result<(), IncidentCaptureError> {
    *record_bytes = record_bytes
        .checked_add(value.len())
        .ok_or(IncidentCaptureError::TooLarge)?;
    if *record_bytes > MAX_INCIDENT_JSONL_RECORD_BYTES {
        return Err(IncidentCaptureError::TooLarge);
    }
    budget.charge(value)
}

/// Assemble an incident bundle at `dir`, or refuse to write one.
///
/// The bundle is built in memory and gated before a single byte reaches disk, so
/// a capture that would leak leaves nothing behind — not even a partial
/// directory an operator might later attach to a bug report. The destination's
/// parent must already exist and must be protected against untrusted entry
/// replacement; capture never creates ancestor directories implicitly.
pub fn capture_bundle(
    dir: &Path,
    request: &IncidentCaptureRequest<'_>,
) -> Result<IncidentManifest, IncidentCaptureError> {
    validate_capture_inputs(request)?;

    let mut bundle = BoundedBundleFiles::default();

    bundle.insert(
        REDACTED_CONFIG_FILE_NAME.to_owned(),
        redacted_config_toml(request.config)?,
    )?;
    bundle.insert(
        REDACTED_AUDIT_TAIL_FILE_NAME.to_owned(),
        redacted_audit_tail(request.audit_records)?,
    )?;
    for cassette in request.cassettes {
        bundle.insert(
            cassette_entry_path(cassette.lane_id)?,
            redacted_cassette(cassette)?,
        )?;
    }

    // The manifest describes the files it was built over, so it is computed from
    // their real bytes and then gated with them.
    let entries = bundle
        .files
        .iter()
        .map(|(path, bytes)| BundleEntry {
            kind: entry_kind(path),
            path: path.clone(),
            sha256: oraclemcp_audit::sha256_hex(bytes),
            bytes: bytes.len() as u64,
        })
        .collect::<Vec<_>>();

    let manifest = IncidentManifest::capture(IncidentCapture {
        trigger: request.trigger,
        seed: request.seed,
        statement: request.statement,
        captured_verdict: request.captured_verdict,
        why: request.why,
        lanes: request.lanes,
        build: request.build.clone(),
        entries: &entries,
    })?;
    bundle.insert(
        MANIFEST_FILE_NAME.to_owned(),
        manifest.to_json().into_bytes(),
    )?;

    // Nothing has touched the filesystem yet. Gate every byte, then write.
    gate(&bundle.files, request.sensitive)?;
    write_bundle(dir, &bundle.files)?;
    Ok(manifest)
}

/// Re-read a bundle and prove it is the one the manifest describes: every entry
/// exists, every content hash matches, and the manifest's own id matches its
/// content. Replay (E2) starts here rather than trusting the directory.
pub fn verify_bundle(dir: &Path) -> Result<IncidentManifest, IncidentCaptureError> {
    load_verified_bundle(dir).map(|bundle| bundle.manifest)
}

struct VerifiedBundle {
    manifest: IncidentManifest,
    files: BTreeMap<String, Vec<u8>>,
}

fn load_verified_bundle(dir: &Path) -> Result<VerifiedBundle, IncidentCaptureError> {
    let manifest_path = dir.join(MANIFEST_FILE_NAME);
    let manifest_bytes = read_bounded_file(
        &manifest_path,
        MAX_INCIDENT_ENTRY_BYTES,
        "read incident manifest",
    )?;
    let json = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| IncidentCaptureError::Io("incident manifest is not UTF-8".to_owned()))?;
    let manifest = IncidentManifest::from_json(json)?;
    let mut total_bytes = manifest_bytes.len();
    let mut files = BTreeMap::new();
    for entry in &manifest.entries {
        let declared_bytes =
            usize::try_from(entry.bytes).map_err(|_| IncidentCaptureError::TooLarge)?;
        if declared_bytes > MAX_INCIDENT_ENTRY_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        total_bytes = total_bytes
            .checked_add(declared_bytes)
            .ok_or(IncidentCaptureError::TooLarge)?;
        if total_bytes > MAX_INCIDENT_BUNDLE_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        let bytes = read_bounded_file(
            &dir.join(&entry.path),
            MAX_INCIDENT_ENTRY_BYTES,
            "read incident bundle entry",
        )?;
        let digest = oraclemcp_audit::sha256_hex(&bytes);
        if digest != entry.sha256 || bytes.len() as u64 != entry.bytes {
            return Err(IncidentCaptureError::Io(
                "a bundle entry does not match the manifest".to_owned(),
            ));
        }
        if files.insert(entry.path.clone(), bytes).is_some() {
            return Err(IncidentCaptureError::Io(
                "the incident manifest names one entry more than once".to_owned(),
            ));
        }
    }
    Ok(VerifiedBundle { manifest, files })
}

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, IncidentCaptureError> {
    let file = open_nofollow_for_read(path).map_err(|error| incident_io_error(operation, error))?;
    let limit = u64::try_from(max_bytes)
        .map_err(|_| IncidentCaptureError::TooLarge)?
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| incident_io_error(operation, error))?;
    if bytes.len() > max_bytes {
        return Err(IncidentCaptureError::TooLarge);
    }
    Ok(bytes)
}

fn open_nofollow_for_read(path: &Path) -> std::io::Result<File> {
    let parent_path = bundle_parent(path)
        .ok_or_else(|| invalid_path_error("incident entry has no parent directory"))?;
    let name = safe_file_name(path)?;
    let parent = open_existing_dir_nofollow(parent_path)?;
    let before = parent.symlink_metadata(name)?;
    if before.file_type().is_symlink() || !before.is_file() || before.nlink() != 1 {
        return Err(invalid_path_error(
            "incident entry is not a private regular file",
        ));
    }

    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent.open_with(name, &options)?;
    let after = file.metadata()?;
    if !after.is_file()
        || after.nlink() != 1
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(invalid_path_error(
            "incident entry changed while it was opened",
        ));
    }
    Ok(file.into_std())
}

/// Replay a verified incident bundle under asupersync's deterministic
/// [`LabRuntimeTarget`].
///
/// Replay starts by re-checking the manifest and every entry hash, but that is
/// not enough to make a bundle safe to consume: a bundle may have been rebuilt
/// by an untrusted party with matching hashes. Each purportedly-redacted
/// statement is therefore run through Arc J's stored-skeleton postcondition
/// before the live classifier derives a fresh verdict. The manifest's
/// `captured_verdict` is never read here; it is evidence only.
pub fn replay_bundle(dir: &Path) -> Result<IncidentReplayReport, IncidentReplayError> {
    let verified = load_verified_bundle(dir)?;
    let config = TestConfig {
        rng_seed: Some(verified.manifest.seed),
        ..TestConfig::default()
    };
    let mut runtime = LabRuntimeTarget::create_runtime(config);

    // block-on-boundary: `replay_bundle` is a synchronous command entry point; it
    // drives the async bundle replay to completion on a dedicated, seeded lab
    // runtime and is never itself invoked from within another async context.
    let report =
        LabRuntimeTarget::block_on(
            &mut runtime,
            async move { replay_verified_bundle(verified) },
        );
    if !runtime.is_quiescent() {
        return Err(IncidentReplayError::RuntimeNotQuiescent);
    }
    report
}

fn replay_verified_bundle(
    verified: VerifiedBundle,
) -> Result<IncidentReplayReport, IncidentReplayError> {
    let VerifiedBundle { manifest, files } = verified;
    let classifier = Classifier::new(ClassifierConfig::served_strict());
    let mut verdicts = Vec::new();
    let mut total_frames = 0usize;

    for lane in &manifest.lanes {
        let cassette_path = cassette_entry_path(&lane.lane_id)?;
        let cassette = files
            .get(&cassette_path)
            .ok_or(IncidentCaptureError::MissingFile {
                operation: "read verified incident cassette",
            })?;
        let mut frames: Vec<RedactedCassetteFrame> = parse_bounded_json_lines(
            Cursor::new(cassette),
            MAX_INCIDENT_CASSETTE_FRAMES,
            "read verified incident cassette",
            "parse cassette frame",
        )?;
        total_frames = total_frames
            .checked_add(frames.len())
            .ok_or(IncidentCaptureError::TooLarge)?;
        if total_frames > MAX_INCIDENT_CASSETTE_FRAMES {
            return Err(IncidentCaptureError::TooLarge.into());
        }
        let mut seen_sequences = BTreeSet::new();
        for frame in &frames {
            if !seen_sequences.insert(frame.seq) {
                return Err(IncidentReplayError::AmbiguousOrdering);
            }
            if let Some(statement) = frame.statement_redacted.as_deref() {
                // Reuse, rather than duplicate, the Arc J redaction seam. Its
                // postcondition understands the generated placeholders in a
                // stored skeleton, which the raw-input redactor intentionally
                // does not treat as ordinary Oracle source text.
                validate_redacted_sql(statement)
                    .map_err(|_| IncidentReplayError::UnsafeArtifact)?;
            }
        }
        frames.sort_by_key(|frame| frame.seq);

        for frame in frames {
            let Some(statement) = frame.statement_redacted.as_deref() else {
                continue;
            };
            let decision = oraclemcp_guard::reclassify_at_replay(&classifier, statement);
            verdicts.push(IncidentReplayStep {
                lane_id: lane.lane_id.clone(),
                seq: frame.seq,
                danger: format!("{:?}", decision.danger),
                required_level: decision.required_level.map(|level| format!("{level:?}")),
                reason_class: decision
                    .reason_category
                    .map(|reason_class| format!("{reason_class:?}")),
            });
        }
    }

    let audit_tail =
        files
            .get(REDACTED_AUDIT_TAIL_FILE_NAME)
            .ok_or(IncidentCaptureError::MissingFile {
                operation: "read verified incident audit tail",
            })?;
    let audit_tail_sha256 = verified_audit_tail_sha256(audit_tail)?;
    Ok(IncidentReplayReport {
        manifest_id: manifest.id,
        seed: manifest.seed,
        replayed_steps: verdicts.len(),
        verdicts,
        audit_tail_sha256,
    })
}

fn verified_audit_tail_sha256(audit_tail: &[u8]) -> Result<String, IncidentCaptureError> {
    let _: Vec<Value> = parse_bounded_json_lines(
        Cursor::new(audit_tail),
        MAX_INCIDENT_AUDIT_RECORDS,
        "read verified incident audit tail",
        "parse verified incident audit record",
    )?;
    Ok(oraclemcp_audit::sha256_hex(audit_tail))
}

fn cassette_entry_path(lane_id: &str) -> Result<String, IncidentCaptureError> {
    let safe = !lane_id.is_empty()
        && lane_id.len() <= MAX_LANE_ID_CHARS
        && lane_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if !safe {
        return Err(IncidentManifestError::UnsafeLaneId.into());
    }
    Ok(format!("{CASSETTE_DIR_NAME}/{lane_id}.jsonl"))
}

fn entry_kind(path: &str) -> BundleEntryKind {
    match path {
        REDACTED_CONFIG_FILE_NAME => BundleEntryKind::RedactedConfig,
        REDACTED_AUDIT_TAIL_FILE_NAME => BundleEntryKind::RedactedAuditTail,
        _ => BundleEntryKind::Cassette,
    }
}

/// The last line of defence: the assembled bundle is searched for the material
/// the capture site declared, and for a handful of shapes no bundle may ever
/// contain. Case-insensitive, because `HR.EMPLOYEES` and `hr.employees` are the
/// same leak.
fn gate(
    files: &BTreeMap<String, Vec<u8>>,
    sensitive: &[String],
) -> Result<(), IncidentCaptureError> {
    let needles: Vec<String> = sensitive
        .iter()
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| token.chars().count() >= MIN_SENSITIVE_TOKEN_CHARS)
        .chain(FORBIDDEN_SHAPES.iter().map(|shape| (*shape).to_owned()))
        .collect();

    for bytes in files.values() {
        let Ok(text) = std::str::from_utf8(bytes) else {
            // A bundle file is always UTF-8 text by construction. Anything else
            // is unreviewable, so it is refused rather than shipped.
            return Err(IncidentCaptureError::WouldLeak);
        };
        let haystack = text.to_ascii_lowercase();
        if needles.iter().any(|needle| haystack.contains(needle)) {
            return Err(IncidentCaptureError::WouldLeak);
        }
    }
    Ok(())
}

fn write_bundle(dir: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), IncidentCaptureError> {
    write_bundle_inner(dir, files, None)
}

fn write_bundle_inner(
    dir: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    fail_before_entry: Option<usize>,
) -> Result<(), IncidentCaptureError> {
    let mut staging = StagedBundle::create_sibling(dir)?;
    let cassette_dir = staging
        .create_private_subdirectory(CASSETTE_DIR_NAME)
        .map_err(|error| incident_io_error("create incident cassette directory", error))?;

    for (index, (path, bytes)) in files.iter().enumerate() {
        if fail_before_entry == Some(index) {
            return Err(IncidentCaptureError::Io(
                "injected incident bundle write failure".to_owned(),
            ));
        }
        let (parent, name) = bundle_entry_location(path, staging.directory()?, &cassette_dir)
            .map_err(|error| incident_io_error("validate incident bundle entry path", error))?;
        write_private_file_at(parent, name, bytes)
            .map_err(|error| incident_io_error("create incident bundle entry", error))?;
    }

    sync_cap_directory(&cassette_dir)?;
    drop(cassette_dir);
    staging.publish()?;
    Ok(())
}

struct StagedBundle {
    parent: CapDir,
    directory: Option<CapDir>,
    staging_name: OsString,
    destination_name: OsString,
    staging_dev: u64,
    staging_ino: u64,
    published: bool,
}

impl StagedBundle {
    fn create_sibling(destination: &Path) -> Result<Self, IncidentCaptureError> {
        let parent = bundle_parent(destination).ok_or_else(|| {
            IncidentCaptureError::Io("incident bundle destination has no parent".to_owned())
        })?;
        let parent = open_trusted_bundle_parent(parent)
            .map_err(|error| incident_io_error("open incident bundle parent", error))?;
        let destination_name = safe_file_name(destination)
            .map_err(|error| incident_io_error("validate incident bundle destination", error))?
            .to_os_string();

        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).map_err(|_| {
                IncidentCaptureError::Io(
                    "generate private incident staging directory name".to_owned(),
                )
            })?;
            let nonce = u128::from_le_bytes(random);
            let staging_name = OsString::from(format!(".oraclemcp-incident-{nonce:032x}"));
            let mut builder = CapDirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match parent.create_dir_with(&staging_name, &builder) {
                Ok(()) => {
                    let before = parent.symlink_metadata(&staging_name).map_err(|error| {
                        incident_io_error("inspect private incident staging directory", error)
                    })?;
                    let directory = parent.open_dir_nofollow(&staging_name).map_err(|error| {
                        incident_io_error("open private incident staging directory", error)
                    })?;
                    let after = directory.dir_metadata().map_err(|error| {
                        incident_io_error("inspect opened incident staging directory", error)
                    })?;
                    if !before.is_dir()
                        || !after.is_dir()
                        || before.dev() != after.dev()
                        || before.ino() != after.ino()
                    {
                        return Err(IncidentCaptureError::Io(
                            "incident staging directory changed while it was opened".to_owned(),
                        ));
                    }
                    return Ok(Self {
                        parent,
                        directory: Some(directory),
                        staging_name,
                        destination_name,
                        staging_dev: after.dev(),
                        staging_ino: after.ino(),
                        published: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(incident_io_error(
                        "create private incident staging directory",
                        error,
                    ));
                }
            }
        }
        Err(IncidentCaptureError::Io(
            "could not allocate a private incident staging directory".to_owned(),
        ))
    }

    fn directory(&self) -> Result<&CapDir, IncidentCaptureError> {
        self.directory.as_ref().ok_or_else(|| {
            IncidentCaptureError::Io("incident staging directory is no longer open".to_owned())
        })
    }

    fn create_private_subdirectory(&self, name: &str) -> std::io::Result<CapDir> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| invalid_path_error("incident staging directory is closed"))?;
        let mut builder = CapDirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        directory.create_dir_with(name, &builder)?;
        let before = directory.symlink_metadata(name)?;
        let child = directory.open_dir_nofollow(name)?;
        let after = child.dir_metadata()?;
        if !before.is_dir()
            || !after.is_dir()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
        {
            return Err(invalid_path_error(
                "incident subdirectory changed while it was opened",
            ));
        }
        Ok(child)
    }

    fn publish(&mut self) -> Result<(), IncidentCaptureError> {
        let directory = self.directory.as_ref().ok_or_else(|| {
            IncidentCaptureError::Io("incident staging directory is no longer open".to_owned())
        })?;
        sync_cap_directory(directory)?;
        self.validate_staging_entry()?;
        let directory = self.directory.take().ok_or_else(|| {
            IncidentCaptureError::Io("incident staging directory is no longer open".to_owned())
        })?;
        drop(directory);
        self.validate_staging_entry()?;
        atomic_rename_noreplace_at(&self.parent, &self.staging_name, &self.destination_name)
            .map_err(|error| incident_io_error("publish incident bundle", error))?;
        self.published = true;
        sync_cap_directory(&self.parent)?;
        Ok(())
    }

    fn validate_staging_entry(&self) -> Result<(), IncidentCaptureError> {
        let reopened = self
            .parent
            .open_dir_nofollow(&self.staging_name)
            .map_err(|error| incident_io_error("reopen incident staging directory", error))?;
        let metadata = reopened.dir_metadata().map_err(|error| {
            incident_io_error("inspect reopened incident staging directory", error)
        })?;
        if !metadata.is_dir()
            || metadata.dev() != self.staging_dev
            || metadata.ino() != self.staging_ino
        {
            return Err(IncidentCaptureError::Io(
                "incident staging directory changed before publication".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Drop for StagedBundle {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let directory = self.directory.take().or_else(|| {
            let reopened = self.parent.open_dir_nofollow(&self.staging_name).ok()?;
            let metadata = reopened.dir_metadata().ok()?;
            (metadata.dev() == self.staging_dev && metadata.ino() == self.staging_ino)
                .then_some(reopened)
        });
        if directory.is_some_and(|directory| directory.remove_open_dir_all().is_err()) {
            tracing::warn!("could not remove private incident staging directory");
        }
    }
}

fn bundle_parent(path: &Path) -> Option<&Path> {
    path.parent().map(|parent| {
        if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        }
    })
}

fn safe_file_name(path: &Path) -> std::io::Result<&OsStr> {
    path.file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_path_error("incident path has no safe file name"))
}

fn capability_root(path: &Path) -> std::io::Result<CapDir> {
    let root = if path.is_absolute() {
        #[cfg(windows)]
        {
            let mut root = PathBuf::new();
            for component in path.components() {
                root.push(component.as_os_str());
                if matches!(component, Component::RootDir) {
                    break;
                }
            }
            root
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/")
        }
    } else {
        PathBuf::from(".")
    };
    CapDir::open_ambient_dir(root, ambient_authority())
}

fn open_existing_dir_nofollow(path: &Path) -> std::io::Result<CapDir> {
    let mut current = capability_root(path)?;
    for component in path.components() {
        match component {
            Component::Normal(name) => current = current.open_dir_nofollow(name)?,
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                return Err(invalid_path_error(
                    "parent traversal is forbidden in an incident path",
                ));
            }
        }
    }
    Ok(current)
}

fn open_trusted_bundle_parent(path: &Path) -> std::io::Result<CapDir> {
    let parent = open_existing_dir_nofollow(path)?;
    validate_bundle_parent_trust(&parent)?;
    Ok(parent)
}

#[cfg(unix)]
fn validate_bundle_parent_trust(parent: &CapDir) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = parent.try_clone()?.into_std_file().metadata()?;
    let owner_is_trusted =
        metadata.uid() == rustix::process::geteuid().as_raw() || metadata.uid() == 0;
    let entries_are_protected = metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0;
    if !owner_is_trusted || !entries_are_protected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "incident bundle parent is not a trusted protected directory",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_bundle_parent_trust(_parent: &CapDir) -> std::io::Result<()> {
    // The pre-existing parent is held as a no-follow capability. Windows ACLs
    // remain the authority for which principals can rename entries within it.
    Ok(())
}

fn bundle_entry_location<'a>(
    path: &'a str,
    root: &'a CapDir,
    cassettes: &'a CapDir,
) -> std::io::Result<(&'a CapDir, &'a OsStr)> {
    let mut components = Path::new(path).components();
    let first = components
        .next()
        .ok_or_else(|| invalid_path_error("empty incident entry path"))?;
    let second = components.next();
    if components.next().is_some() {
        return Err(invalid_path_error("nested incident entry path"));
    }
    match (first, second) {
        (Component::Normal(name), None) => Ok((root, name)),
        (Component::Normal(directory), Some(Component::Normal(name)))
            if directory == OsStr::new(CASSETTE_DIR_NAME) =>
        {
            Ok((cassettes, name))
        }
        _ => Err(invalid_path_error("unsafe incident entry path")),
    }
}

fn write_private_file_at(parent: &CapDir, name: &OsStr, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_CLOEXEC);
    let mut file = parent.open_with(name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid_path_error(
            "new incident entry is not a private regular file",
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn atomic_rename_noreplace_at(parent: &CapDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    let parent = parent.try_clone()?.into_std_file();
    rustix::fs::renameat_with(
        &parent,
        from,
        &parent,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(windows)]
fn atomic_rename_noreplace_at(parent: &CapDir, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    // Windows rename refuses an existing destination; unlike Unix rename it
    // does not replace it. Both names remain relative to the held parent.
    parent.rename(from, parent, to)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn atomic_rename_noreplace_at(_parent: &CapDir, _from: &OsStr, _to: &OsStr) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace directory publication is unavailable",
    ))
}

#[cfg(unix)]
fn sync_cap_directory(directory: &CapDir) -> Result<(), IncidentCaptureError> {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    directory
        .open_with(".", &options)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| incident_io_error("sync incident bundle directory", error))
}

#[cfg(not(unix))]
fn sync_cap_directory(_directory: &CapDir) -> Result<(), IncidentCaptureError> {
    // `FlushFileBuffers` on a Windows directory handle returns access denied.
    // Entry durability relies on NTFS metadata journaling; every file is still
    // flushed before the atomic directory rename.
    Ok(())
}

fn invalid_path_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

fn redacted_cassette(cassette: &Cassette<'_>) -> Result<Vec<u8>, IncidentCaptureError> {
    if cassette.frames.len() > MAX_INCIDENT_CASSETTE_FRAMES {
        return Err(IncidentCaptureError::TooLarge);
    }
    let mut lines = Vec::new();
    for frame in cassette.frames {
        if frame.tool.len() > MAX_INCIDENT_JSONL_RECORD_BYTES
            || frame
                .statement
                .is_some_and(|statement| statement.len() > MAX_INCIDENT_JSONL_RECORD_BYTES)
            || frame
                .sql_sha256
                .is_some_and(|digest| digest.len() > MAX_INCIDENT_JSONL_RECORD_BYTES)
            || frame.outcome.len() > MAX_INCIDENT_JSONL_RECORD_BYTES
        {
            return Err(IncidentCaptureError::TooLarge);
        }
        let redacted = RedactedCassetteFrame {
            seq: frame.seq,
            tool: frame.tool.to_owned(),
            statement_redacted: frame.statement.map(redact_sql).transpose()?,
            sql_sha256: frame.sql_sha256.map(str::to_owned),
            // The outcome is a label from a closed vocabulary at the call site,
            // but it is still text arriving from outside this module, so it goes
            // through the same safe-prose gate the manifest's `why` does.
            outcome: safe_why(frame.outcome)?,
        };
        append_bounded_json_line(&mut lines, &redacted, "serialize cassette")?;
    }
    Ok(lines)
}

/// Project the audit records down to the fields that are safe by construction.
///
/// This is an allowlist. Note what is NOT here: `agent_identity` and `subject`
/// (a username), `db_evidence` (database, service, instance, session user,
/// current schema, client identifier — every one a customer identifier), and
/// `sql_preview`, which on records written before schema v6 can still hold a
/// truncated **raw** SQL preview. The hashes stay, because a hash is a
/// correlation handle, not the thing it hashes.
fn redacted_audit_tail(records: &[AuditRecord]) -> Result<Vec<u8>, IncidentCaptureError> {
    if records.len() > MAX_INCIDENT_AUDIT_RECORDS {
        return Err(IncidentCaptureError::TooLarge);
    }
    let mut lines = Vec::new();
    for record in records {
        let value = json!({
            "schema_version": record.schema_version,
            "seq": record.seq,
            "timestamp": record.timestamp,
            // `sha256_hex` already carries the `sha256:` prefix.
            "subject_id_hash": oraclemcp_audit::sha256_hex(
                record.subject.legacy_agent_identity().as_bytes()
            ),
            "tool": record.tool,
            "danger_level": record.danger_level,
            "decision": record.decision,
            "outcome": record.outcome,
            "rows_affected": record.rows_affected,
            "sql_sha256": record.sql_sha256,
            "sql_normalized_sha256": record.sql_normalized_sha256,
            "observed_scn": record.observed_scn,
            "verdict_certificate_core_hash": record.verdict_certificate_core_hash,
            "proof": {
                "prev_hash": record.prev_hash,
                "entry_hash": record.entry_hash,
                "key_id": record.key_id,
                "signature": record.signature,
            },
        });
        append_bounded_json_line(&mut lines, &value, "serialize redacted audit record")?;
    }
    Ok(lines)
}

fn append_bounded_json_line<T: Serialize>(
    output: &mut Vec<u8>,
    value: &T,
    operation: &'static str,
) -> Result<(), IncidentCaptureError> {
    let line = serde_json::to_vec(value)
        .map_err(|error| IncidentCaptureError::Io(format!("{operation}: {error}")))?;
    if line.len() > MAX_INCIDENT_JSONL_RECORD_BYTES {
        return Err(IncidentCaptureError::TooLarge);
    }
    let projected = output
        .len()
        .checked_add(line.len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(IncidentCaptureError::TooLarge)?;
    if projected > MAX_INCIDENT_ENTRY_BYTES {
        return Err(IncidentCaptureError::TooLarge);
    }
    output.extend_from_slice(&line);
    output.push(b'\n');
    Ok(())
}

/// Project the configuration down to its non-secret metadata.
///
/// Also an allowlist. A profile's `connect_string`, `username`, `credential_ref`
/// and every wallet path are simply not fields a redacted config has. The
/// operator-authored `description` is free text — the one place a connect string
/// could be pasted by hand — so it passes the safe-prose gate or it is dropped.
fn redacted_config_toml(config: &OracleMcpConfig) -> Result<Vec<u8>, IncidentCaptureError> {
    let mut toml = Vec::new();
    append_bounded_text(
        &mut toml,
        "# oraclemcp incident bundle — redacted configuration.\n",
    )?;
    append_bounded_text(
        &mut toml,
        "# Non-secret profile metadata only: no connect string, no username,\n",
    )?;
    append_bounded_text(&mut toml, "# no credential reference, no wallet path.\n")?;
    append_bounded_text(
        &mut toml,
        &format!("schema_version = {}\n", config.schema_version),
    )?;

    let mut profiles: Vec<_> = config.profiles.iter().collect();
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    for profile in profiles {
        append_bounded_text(&mut toml, "\n[[profiles]]\n")?;
        append_bounded_text(
            &mut toml,
            &format!("name = {}\n", toml_string(&profile.name)),
        )?;
        append_bounded_text(
            &mut toml,
            &format!(
                "is_default = {}\n",
                config.default_profile.as_deref() == Some(profile.name.as_str())
            ),
        )?;
        append_bounded_text(
            &mut toml,
            &format!("max_level = {:?}\n", profile.max_level()),
        )?;
        append_bounded_text(&mut toml, &format!("protected = {}\n", profile.protected()))?;
        append_bounded_text(
            &mut toml,
            &format!("mcp_exposed = {}\n", profile.mcp_exposed()),
        )?;
        if let Some(max_query_cost) = profile.max_query_cost {
            append_bounded_text(&mut toml, &format!("max_query_cost = {max_query_cost}\n"))?;
        }
        if let Some(description) = profile
            .description
            .as_deref()
            .and_then(|text| safe_why(text).ok())
        {
            append_bounded_text(
                &mut toml,
                &format!("description = {}\n", toml_string(&description)),
            )?;
        }
    }
    Ok(toml)
}

fn append_bounded_text(output: &mut Vec<u8>, text: &str) -> Result<(), IncidentCaptureError> {
    let projected = output
        .len()
        .checked_add(text.len())
        .ok_or(IncidentCaptureError::TooLarge)?;
    if projected > MAX_INCIDENT_ENTRY_BYTES {
        return Err(IncidentCaptureError::TooLarge);
    }
    output.extend_from_slice(text.as_bytes());
    Ok(())
}

/// A bare TOML basic string. The value is already known safe; this only quotes it.
fn toml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// The redacted cassette frames of one lane, for replay (E2).
pub fn read_cassette(
    dir: &Path,
    lane_id: &str,
) -> Result<Vec<RedactedCassetteFrame>, IncidentCaptureError> {
    let path = dir.join(cassette_entry_path(lane_id)?);
    read_bounded_json_lines(
        &path,
        MAX_INCIDENT_CASSETTE_FRAMES,
        "read incident cassette",
        "parse cassette frame",
    )
}

/// The redacted audit records of a bundle, as JSON values (for replay's
/// hash-equality check).
pub fn read_redacted_audit_tail(dir: &Path) -> Result<Vec<Value>, IncidentCaptureError> {
    read_bounded_json_lines(
        &dir.join(REDACTED_AUDIT_TAIL_FILE_NAME),
        MAX_INCIDENT_AUDIT_RECORDS,
        "read incident audit tail",
        "parse audit record",
    )
}

fn read_bounded_json_lines<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_records: usize,
    read_operation: &'static str,
    parse_operation: &'static str,
) -> Result<Vec<T>, IncidentCaptureError> {
    let file =
        open_nofollow_for_read(path).map_err(|error| incident_io_error(read_operation, error))?;
    parse_bounded_json_lines(
        BufReader::new(file),
        max_records,
        read_operation,
        parse_operation,
    )
}

fn parse_bounded_json_lines<T: for<'de> Deserialize<'de>>(
    mut reader: impl BufRead,
    max_records: usize,
    read_operation: &'static str,
    parse_operation: &'static str,
) -> Result<Vec<T>, IncidentCaptureError> {
    let mut records = Vec::new();
    let mut total_bytes = 0usize;

    loop {
        let limit = u64::try_from(MAX_INCIDENT_JSONL_RECORD_BYTES)
            .map_err(|_| IncidentCaptureError::TooLarge)?
            .saturating_add(2);
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(limit)
            .read_until(b'\n', &mut line)
            .map_err(|error| incident_io_error(read_operation, error))?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(read)
            .ok_or(IncidentCaptureError::TooLarge)?;
        if total_bytes > MAX_INCIDENT_ENTRY_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        if line.len() > MAX_INCIDENT_JSONL_RECORD_BYTES {
            return Err(IncidentCaptureError::TooLarge);
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= max_records {
            return Err(IncidentCaptureError::TooLarge);
        }
        let record = serde_json::from_slice(&line)
            .map_err(|error| IncidentCaptureError::Io(format!("{parse_operation}: {error}")))?;
        records.push(record);
    }
    Ok(records)
}

fn incident_io_error(operation: &'static str, error: std::io::Error) -> IncidentCaptureError {
    if error.kind() == std::io::ErrorKind::NotFound {
        IncidentCaptureError::MissingFile { operation }
    } else {
        IncidentCaptureError::Io(format!("{operation}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "oraclemcp-incident-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn create_private_test_dir(path: &Path) {
        fs::create_dir(path).expect("create private incident test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("secure private incident test directory");
        }
    }

    #[test]
    fn missing_manifest_reports_typed_missing_file() {
        let dir = temporary_path("missing-manifest");
        fs::create_dir(&dir).expect("create incident test directory");

        let error = verify_bundle(&dir).expect_err("missing manifest must be typed");

        assert!(matches!(
            error,
            IncidentCaptureError::MissingFile {
                operation: "read incident manifest"
            }
        ));
        fs::remove_dir_all(&dir).expect("cleanup incident test directory");
    }

    #[test]
    fn bundle_accumulator_accepts_exact_aggregate_limit_and_rejects_max_plus_one() {
        let mut bundle = BoundedBundleFiles::default();
        for index in 0..(MAX_INCIDENT_BUNDLE_BYTES / MAX_INCIDENT_ENTRY_BYTES) {
            bundle
                .insert(
                    format!("entry-{index}"),
                    vec![b'x'; MAX_INCIDENT_ENTRY_BYTES],
                )
                .expect("exact aggregate limit is accepted");
        }
        assert_eq!(bundle.total_bytes, MAX_INCIDENT_BUNDLE_BYTES);
        assert!(matches!(
            bundle.insert("overflow".to_owned(), vec![b'x']),
            Err(IncidentCaptureError::TooLarge)
        ));

        let mut oversized_entry = BoundedBundleFiles::default();
        assert!(matches!(
            oversized_entry.insert(
                "oversized-entry".to_owned(),
                vec![b'x'; MAX_INCIDENT_ENTRY_BYTES + 1],
            ),
            Err(IncidentCaptureError::TooLarge)
        ));
    }

    #[test]
    fn bounded_json_line_reader_accepts_exact_record_limit_and_rejects_max_plus_one() {
        let root = temporary_path("jsonl-boundary");
        fs::create_dir(&root).expect("create boundary fixture directory");
        let path = root.join("records.jsonl");
        let exact = format!("\"{}\"", "a".repeat(MAX_INCIDENT_JSONL_RECORD_BYTES - 2));
        assert_eq!(exact.len(), MAX_INCIDENT_JSONL_RECORD_BYTES);
        fs::write(&path, exact).expect("write exact-boundary fixture");
        let records: Vec<Value> =
            read_bounded_json_lines(&path, 1, "read boundary fixture", "parse boundary fixture")
                .expect("exact record limit is accepted");
        assert_eq!(records.len(), 1);

        let oversized = format!("\"{}\"", "a".repeat(MAX_INCIDENT_JSONL_RECORD_BYTES - 1));
        assert_eq!(oversized.len(), MAX_INCIDENT_JSONL_RECORD_BYTES + 1);
        fs::write(&path, oversized).expect("write max-plus-one fixture");
        assert!(matches!(
            read_bounded_json_lines::<Value>(
                &path,
                1,
                "read boundary fixture",
                "parse boundary fixture",
            ),
            Err(IncidentCaptureError::TooLarge)
        ));
        fs::remove_dir_all(&root).expect("cleanup boundary fixture directory");
    }

    #[test]
    fn verified_audit_tail_rejects_max_plus_one_records_before_hashing() {
        let audit_tail = b"{}\n".repeat(MAX_INCIDENT_AUDIT_RECORDS + 1);
        assert!(matches!(
            verified_audit_tail_sha256(&audit_tail),
            Err(IncidentCaptureError::TooLarge)
        ));
    }

    #[test]
    fn cassette_reader_rejects_absolute_and_traversing_lane_ids() {
        let root = temporary_path("cassette-lane-confinement");
        fs::create_dir(&root).expect("create cassette confinement fixture");
        for lane_id in [
            "/tmp/outside",
            "../outside",
            "nested/outside",
            "nested\\outside",
        ] {
            assert!(matches!(
                read_cassette(&root, lane_id),
                Err(IncidentCaptureError::Manifest(
                    IncidentManifestError::UnsafeLaneId
                ))
            ));
        }
        fs::remove_dir_all(&root).expect("cleanup cassette confinement fixture");
    }

    #[test]
    fn max_plus_one_capture_frames_fail_before_output_creation() {
        let destination = temporary_path("frame-count-overflow");
        let config = OracleMcpConfig::default();
        let lanes = [CapturedLane {
            lane_id: "local".to_owned(),
            subject_id_hash: oraclemcp_audit::sha256_hex(b"local"),
        }];
        let frames = vec![
            CassetteFrame {
                seq: 1,
                tool: "oracle_query",
                statement: None,
                sql_sha256: None,
                outcome: "captured",
            };
            MAX_INCIDENT_CASSETTE_FRAMES + 1
        ];
        let cassettes = [Cassette {
            lane_id: "local",
            frames: &frames,
        }];
        let request = IncidentCaptureRequest {
            trigger: IncidentTrigger::Refusal,
            seed: 1,
            statement: None,
            captured_verdict: None,
            why: "bounded fixture",
            lanes: &lanes,
            build: BuildIdentity {
                server: "oraclemcp/0.10.0".to_owned(),
                classifier: "oraclemcp-guard/0.10.0;registry=1".to_owned(),
                driver: "oracledb/0.9.2".to_owned(),
            },
            audit_records: &[],
            cassettes: &cassettes,
            config: &config,
            sensitive: &[],
        };

        assert!(matches!(
            capture_bundle(&destination, &request),
            Err(IncidentCaptureError::TooLarge)
        ));
        assert!(
            !destination.exists(),
            "oversized capture created output before refusing"
        );
    }

    #[test]
    fn injected_mid_write_failure_never_exposes_a_partial_final_bundle() {
        let root = temporary_path("atomic-failure");
        create_private_test_dir(&root);
        let destination = root.join("bundle");
        let files = BTreeMap::from([
            (MANIFEST_FILE_NAME.to_owned(), b"manifest".to_vec()),
            (REDACTED_CONFIG_FILE_NAME.to_owned(), b"config".to_vec()),
        ]);

        assert!(write_bundle_inner(&destination, &files, Some(1)).is_err());
        assert!(
            !destination.exists(),
            "a failed staged write published a partial final bundle"
        );
        assert_eq!(
            fs::read_dir(&root).expect("read fixture parent").count(),
            0,
            "failed private staging directory was not cleaned up"
        );
        fs::remove_dir_all(&root).expect("cleanup atomic fixture parent");
    }

    #[test]
    fn missing_destination_parent_is_not_created_implicitly() {
        let root = temporary_path("missing-parent");
        fs::create_dir(&root).expect("create missing-parent fixture root");
        let missing_parent = root.join("not-created");
        let destination = missing_parent.join("bundle");
        let files = BTreeMap::from([(MANIFEST_FILE_NAME.to_owned(), b"manifest".to_vec())]);

        assert!(write_bundle(&destination, &files).is_err());
        assert!(
            !missing_parent.exists(),
            "incident publication must not create unflushed ancestor directories"
        );
        fs::remove_dir_all(&root).expect("cleanup missing-parent fixture root");
    }

    #[cfg(unix)]
    #[test]
    fn writable_non_sticky_destination_parent_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temporary_path("untrusted-parent");
        fs::create_dir(&root).expect("create untrusted-parent fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("make fixture parent non-sticky and writable");
        let destination = root.join("bundle");
        let files = BTreeMap::from([(MANIFEST_FILE_NAME.to_owned(), b"manifest".to_vec())]);

        assert!(write_bundle(&destination, &files).is_err());
        assert!(!destination.exists());
        fs::remove_dir_all(&root).expect("cleanup untrusted-parent fixture root");
    }

    #[test]
    fn substituted_staging_entry_is_refused_before_publication() {
        let root = temporary_path("staging-substitution");
        create_private_test_dir(&root);
        let destination = root.join("bundle");
        let mut staging =
            StagedBundle::create_sibling(&destination).expect("create staging bundle");
        let staging_path = root.join(&staging.staging_name);
        let displaced_path = root.join("displaced");
        fs::rename(&staging_path, &displaced_path).expect("displace original staging entry");
        fs::create_dir(&staging_path).expect("substitute staging directory entry");

        assert!(staging.publish().is_err());
        assert!(!destination.exists());
        drop(staging);
        fs::remove_dir_all(&root).expect("cleanup staging-substitution fixture root");
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_destination_is_never_followed_or_replaced() {
        use std::os::unix::fs::symlink;

        let root = temporary_path("symlink-destination");
        let victim = root.join("victim");
        fs::create_dir_all(&victim).expect("create symlink victim");
        let marker = victim.join("marker");
        fs::write(&marker, b"unchanged").expect("write victim marker");
        let destination = root.join("bundle");
        symlink(&victim, &destination).expect("create destination symlink");
        let files = BTreeMap::from([(MANIFEST_FILE_NAME.to_owned(), b"manifest".to_vec())]);

        assert!(write_bundle(&destination, &files).is_err());
        assert_eq!(fs::read(&marker).expect("read victim marker"), b"unchanged");
        assert!(
            !victim.join(MANIFEST_FILE_NAME).exists(),
            "bundle writer followed the destination symlink into the victim"
        );
        assert!(
            fs::symlink_metadata(&destination)
                .expect("destination symlink remains")
                .file_type()
                .is_symlink(),
            "atomic publication replaced an existing destination"
        );
        fs::remove_dir_all(&root).expect("cleanup symlink fixture parent");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_is_never_followed_while_writing() {
        use std::os::unix::fs::symlink;

        let root = temporary_path("symlink-ancestor-write");
        let victim = root.join("victim");
        fs::create_dir_all(&victim).expect("create ancestor victim");
        let alias = root.join("alias");
        symlink(&victim, &alias).expect("create ancestor symlink");
        let destination = alias.join("bundle");
        let files = BTreeMap::from([(MANIFEST_FILE_NAME.to_owned(), b"manifest".to_vec())]);

        assert!(write_bundle(&destination, &files).is_err());
        assert!(
            !victim.join("bundle").exists(),
            "bundle writer followed a symlinked ancestor"
        );
        fs::remove_dir_all(&root).expect("cleanup symlink ancestor fixture");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_is_never_followed_while_reading() {
        use std::os::unix::fs::symlink;

        let root = temporary_path("symlink-ancestor-read");
        let real = root.join("real");
        fs::create_dir_all(&real).expect("create real incident directory");
        fs::write(real.join(MANIFEST_FILE_NAME), b"manifest").expect("write incident entry");
        let alias = root.join("alias");
        symlink(&real, &alias).expect("create ancestor symlink");

        assert!(
            read_bounded_file(
                &alias.join(MANIFEST_FILE_NAME),
                MAX_INCIDENT_ENTRY_BYTES,
                "read symlink fixture",
            )
            .is_err()
        );
        fs::remove_dir_all(&root).expect("cleanup symlink ancestor fixture");
    }

    #[cfg(all(
        unix,
        not(any(
            target_vendor = "apple",
            target_os = "espidf",
            target_os = "horizon",
            target_os = "vita",
            target_os = "wasi",
            target_os = "redox"
        ))
    ))]
    #[test]
    fn special_file_incident_entry_is_rejected_before_reading() {
        let root = temporary_path("fifo-read");
        fs::create_dir(&root).expect("create fifo fixture directory");
        let fifo = root.join("entry.jsonl");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .expect("create fifo fixture");

        assert!(
            read_bounded_file(&fifo, MAX_INCIDENT_ENTRY_BYTES, "read special-file fixture",)
                .is_err()
        );
        fs::remove_dir_all(&root).expect("cleanup fifo fixture");
    }

    #[test]
    fn replay_consumes_the_exact_bytes_retained_during_verification() {
        let destination = temporary_path("verified-byte-snapshot");
        let config = OracleMcpConfig::default();
        let lanes = [CapturedLane {
            lane_id: "local".to_owned(),
            subject_id_hash: oraclemcp_audit::sha256_hex(b"local"),
        }];
        let frames = [CassetteFrame {
            seq: 1,
            tool: "oracle_query",
            statement: Some("SELECT 1 FROM dual"),
            sql_sha256: None,
            outcome: "captured",
        }];
        let cassettes = [Cassette {
            lane_id: "local",
            frames: &frames,
        }];
        let request = IncidentCaptureRequest {
            trigger: IncidentTrigger::Refusal,
            seed: 7,
            statement: Some("SELECT 1 FROM dual"),
            captured_verdict: None,
            why: "verified byte fixture",
            lanes: &lanes,
            build: BuildIdentity {
                server: "oraclemcp/0.10.0".to_owned(),
                classifier: "oraclemcp-guard/0.10.0;registry=1".to_owned(),
                driver: "oracledb/0.9.2".to_owned(),
            },
            audit_records: &[],
            cassettes: &cassettes,
            config: &config,
            sensitive: &[],
        };
        capture_bundle(&destination, &request).expect("capture verified-byte fixture");
        let verified = load_verified_bundle(&destination).expect("verify exact fixture bytes");

        fs::write(
            destination.join(CASSETTE_DIR_NAME).join("local.jsonl"),
            b"not valid json\n",
        )
        .expect("replace path after verification");

        let report = replay_verified_bundle(verified)
            .expect("replay uses retained bytes rather than reopening the path");
        assert_eq!(report.replayed_steps, 1);
        fs::remove_dir_all(&destination).expect("cleanup verified-byte fixture");
    }

    #[test]
    fn oversized_statement_is_refused_before_output_creation() {
        let destination = temporary_path("oversized-statement");
        let statement = "x".repeat(MAX_INCIDENT_ENTRY_BYTES + 1);
        let config = OracleMcpConfig::default();
        let request = IncidentCaptureRequest {
            trigger: IncidentTrigger::Refusal,
            seed: 11,
            statement: Some(&statement),
            captured_verdict: None,
            why: "bounded input fixture",
            lanes: &[],
            build: BuildIdentity {
                server: "oraclemcp/0.10.0".to_owned(),
                classifier: "oraclemcp-guard/0.10.0;registry=1".to_owned(),
                driver: "oracledb/0.9.2".to_owned(),
            },
            audit_records: &[],
            cassettes: &[],
            config: &config,
            sensitive: &[],
        };

        assert!(matches!(
            capture_bundle(&destination, &request),
            Err(IncidentCaptureError::TooLarge)
        ));
        assert!(
            !destination.exists(),
            "oversized input created output before refusing"
        );
    }
}
