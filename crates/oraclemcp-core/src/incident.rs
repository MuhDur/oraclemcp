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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use oraclemcp_audit::AuditRecord;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_guard::corpus::{CorpusRedactionError, redact_sql, safe_why};
use oraclemcp_guard::incident::{
    BuildIdentity, BundleEntry, BundleEntryKind, CASSETTE_DIR_NAME, CapturedLane, CapturedVerdict,
    IncidentCapture, IncidentManifest, IncidentManifestError, IncidentTrigger, MANIFEST_FILE_NAME,
    REDACTED_AUDIT_TAIL_FILE_NAME, REDACTED_CONFIG_FILE_NAME,
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
    /// The bundle could not be written, or a written file does not match the
    /// manifest.
    #[error("incident bundle io failed: {0}")]
    Io(String),
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

/// Assemble an incident bundle at `dir`, or refuse to write one.
///
/// The bundle is built in memory and gated before a single byte reaches disk, so
/// a capture that would leak leaves nothing behind — not even a partial
/// directory an operator might later attach to a bug report.
pub fn capture_bundle(
    dir: &Path,
    request: &IncidentCaptureRequest<'_>,
) -> Result<IncidentManifest, IncidentCaptureError> {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    files.insert(
        REDACTED_CONFIG_FILE_NAME.to_owned(),
        redacted_config_toml(request.config).into_bytes(),
    );
    files.insert(
        REDACTED_AUDIT_TAIL_FILE_NAME.to_owned(),
        redacted_audit_tail(request.audit_records).into_bytes(),
    );
    for cassette in request.cassettes {
        files.insert(
            format!("{CASSETTE_DIR_NAME}/{}.jsonl", cassette.lane_id),
            redacted_cassette(cassette)?.into_bytes(),
        );
    }

    // The manifest describes the files it was built over, so it is computed from
    // their real bytes and then gated with them.
    let entries = files
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
    files.insert(
        MANIFEST_FILE_NAME.to_owned(),
        manifest.to_json().into_bytes(),
    );

    // Nothing has touched the filesystem yet. Gate every byte, then write.
    gate(&files, request.sensitive)?;
    write_bundle(dir, &files)?;
    Ok(manifest)
}

/// Re-read a bundle and prove it is the one the manifest describes: every entry
/// exists, every content hash matches, and the manifest's own id matches its
/// content. Replay (E2) starts here rather than trusting the directory.
pub fn verify_bundle(dir: &Path) -> Result<IncidentManifest, IncidentCaptureError> {
    let manifest_path = dir.join(MANIFEST_FILE_NAME);
    let json = fs::read_to_string(&manifest_path)
        .map_err(|e| IncidentCaptureError::Io(format!("read manifest: {e}")))?;
    let manifest = IncidentManifest::from_json(&json)?;
    for entry in &manifest.entries {
        let bytes = fs::read(dir.join(&entry.path))
            .map_err(|e| IncidentCaptureError::Io(format!("read bundle entry: {e}")))?;
        let digest = oraclemcp_audit::sha256_hex(&bytes);
        if digest != entry.sha256 || bytes.len() as u64 != entry.bytes {
            return Err(IncidentCaptureError::Io(
                "a bundle entry does not match the manifest".to_owned(),
            ));
        }
    }
    Ok(manifest)
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
    fs::create_dir_all(dir.join(CASSETTE_DIR_NAME))
        .map_err(|e| IncidentCaptureError::Io(format!("create bundle dir: {e}")))?;
    for (path, bytes) in files {
        let target: PathBuf = dir.join(path);
        fs::write(&target, bytes)
            .map_err(|e| IncidentCaptureError::Io(format!("write bundle entry: {e}")))?;
    }
    Ok(())
}

fn redacted_cassette(cassette: &Cassette<'_>) -> Result<String, IncidentCaptureError> {
    let mut lines = String::new();
    for frame in cassette.frames {
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
        lines.push_str(
            &serde_json::to_string(&redacted)
                .map_err(|e| IncidentCaptureError::Io(format!("serialize cassette: {e}")))?,
        );
        lines.push('\n');
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
fn redacted_audit_tail(records: &[AuditRecord]) -> String {
    let mut lines = String::new();
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
        lines.push_str(&value.to_string());
        lines.push('\n');
    }
    lines
}

/// Project the configuration down to its non-secret metadata.
///
/// Also an allowlist. A profile's `connect_string`, `username`, `credential_ref`
/// and every wallet path are simply not fields a redacted config has. The
/// operator-authored `description` is free text — the one place a connect string
/// could be pasted by hand — so it passes the safe-prose gate or it is dropped.
fn redacted_config_toml(config: &OracleMcpConfig) -> String {
    let mut toml = String::new();
    toml.push_str("# oraclemcp incident bundle — redacted configuration.\n");
    toml.push_str("# Non-secret profile metadata only: no connect string, no username,\n");
    toml.push_str("# no credential reference, no wallet path.\n");
    toml.push_str(&format!("schema_version = {}\n", config.schema_version));

    let mut profiles: Vec<_> = config.list_profiles();
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    for profile in profiles {
        toml.push_str("\n[[profiles]]\n");
        toml.push_str(&format!("name = {}\n", toml_string(&profile.name)));
        toml.push_str(&format!("is_default = {}\n", profile.is_default));
        toml.push_str(&format!("max_level = {:?}\n", profile.max_level));
        toml.push_str(&format!("protected = {}\n", profile.protected));
        toml.push_str(&format!("mcp_exposed = {}\n", profile.mcp_exposed));
        if let Some(max_query_cost) = profile.max_query_cost {
            toml.push_str(&format!("max_query_cost = {max_query_cost}\n"));
        }
        if let Some(description) = profile
            .description
            .as_deref()
            .and_then(|text| safe_why(text).ok())
        {
            toml.push_str(&format!("description = {}\n", toml_string(&description)));
        }
    }
    toml
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
    let path = dir.join(CASSETTE_DIR_NAME).join(format!("{lane_id}.jsonl"));
    let text = fs::read_to_string(&path)
        .map_err(|e| IncidentCaptureError::Io(format!("read cassette: {e}")))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<RedactedCassetteFrame>(line)
                .map_err(|e| IncidentCaptureError::Io(format!("parse cassette frame: {e}")))
        })
        .collect()
}

/// The redacted audit records of a bundle, as JSON values (for replay's
/// hash-equality check).
pub fn read_redacted_audit_tail(dir: &Path) -> Result<Vec<Value>, IncidentCaptureError> {
    let text = fs::read_to_string(dir.join(REDACTED_AUDIT_TAIL_FILE_NAME))
        .map_err(|e| IncidentCaptureError::Io(format!("read audit tail: {e}")))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|e| IncidentCaptureError::Io(format!("parse audit record: {e}")))
        })
        .collect()
}
