//! Append-only refusal corpus writer (Arc J; bead `09x` J2).
//!
//! Corpus records are public-bound data, not a policy cache. In particular, a
//! redacted record is never executable SQL and carries no guard verdict. A
//! caller that wants to apply a suggested rewrite must present its raw SQL and
//! run `reclassify_rewrite_at_apply` again against the classifier and current
//! operating-level gate.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use oraclemcp_guard::corpus::{
    CorpusAuthenticity, CorpusRecord, CorpusRedactionError, ReasonCategory,
    classifier_proves_rewrite,
};
use oraclemcp_guard::{Classifier, suggest_parameterized_form};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

#[cfg(test)]
use oraclemcp_guard::corpus::reclassify_rewrite_at_apply;

/// A process-shared, append-only writer for redacted refusal records.
///
/// The mutex preserves one-record-per-line writes among the server's lanes. It
/// deliberately protects only the corpus file, never the classifier or the
/// dispatch decision: a corpus I/O failure cannot turn a refusal into an allow.
#[derive(Clone, Debug)]
pub(crate) struct RefusalCorpusWriter {
    path: Arc<PathBuf>,
    append_lock: Arc<Mutex<()>>,
}

/// The small, closed vocabulary of custom-tool signature failures that must be
/// visible in the unsigned B8c trail.  It deliberately carries no parser,
/// filesystem, or secret details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomToolSignatureFailure {
    Required,
    Invalid,
    UnsupportedVersion,
    VerificationKeyMissing,
}

/// A non-SQL security event in the B8c refusal/security-event trail.
///
/// This remains separate from [`CorpusRecord`]: inventing a fake SQL refusal
/// for a tampered custom-tool definition would corrupt the classifier corpus
/// and mislead an operator about what actually happened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityEventRecord {
    id: String,
    event: SecurityEventKind,
    tool: String,
    reason: CustomToolSignatureFailure,
    #[serde(default)]
    authenticity: CorpusAuthenticity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SecurityEventKind {
    CustomToolSignatureRejected,
}

impl SecurityEventRecord {
    fn custom_tool_signature_rejected(tool: &str, reason: CustomToolSignatureFailure) -> Self {
        let tool = safe_tool_name(tool)
            .unwrap_or("invalid-tool-name")
            .to_owned();
        let event = SecurityEventKind::CustomToolSignatureRejected;
        let id = oraclemcp_audit::sha256_hex(
            format!("security-event-v1|{event:?}|{tool}|{reason:?}").as_bytes(),
        );
        Self {
            id,
            event,
            tool,
            reason,
            authenticity: CorpusAuthenticity::UnsignedNotTamperEvident,
        }
    }

    fn from_jsonl_line(line: &str) -> Result<Self, CorpusRedactionError> {
        let record: Self =
            serde_json::from_str(line).map_err(|_| CorpusRedactionError::Malformed)?;
        if safe_tool_name(&record.tool).is_none() {
            return Err(CorpusRedactionError::Malformed);
        }
        let expected = oraclemcp_audit::sha256_hex(
            format!(
                "security-event-v1|{:?}|{}|{:?}",
                record.event, record.tool, record.reason
            )
            .as_bytes(),
        );
        if expected != record.id {
            return Err(CorpusRedactionError::IdMismatch);
        }
        Ok(record)
    }
}

fn safe_tool_name(name: &str) -> Option<&str> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    Some(name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TrailRecord {
    Refusal(CorpusRecord),
    SecurityEvent(SecurityEventRecord),
}

impl TrailRecord {
    fn to_jsonl_line(&self) -> String {
        match self {
            Self::Refusal(record) => record.to_jsonl_line(),
            Self::SecurityEvent(record) => {
                serde_json::to_string(record).expect("a validated security event always serializes")
            }
        }
    }

    fn from_jsonl_line(line: &str) -> Result<Self, CorpusRedactionError> {
        CorpusRecord::from_jsonl_line(line)
            .map(Self::Refusal)
            .or_else(|_| SecurityEventRecord::from_jsonl_line(line).map(Self::SecurityEvent))
    }

    fn id(&self) -> &str {
        match self {
            Self::Refusal(record) => &record.id,
            Self::SecurityEvent(record) => &record.id,
        }
    }
}

impl RefusalCorpusWriter {
    #[must_use]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            append_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Append one refused statement after independently classifying any
    /// parameterized candidate. The candidate is retained only when its own
    /// fresh verdict is not `Forbidden`; the original refusal is always
    /// recorded when redaction succeeds.
    pub(crate) fn append_refusal(
        &self,
        classifier: &Classifier,
        refused_sql: &str,
        refusal_class: ReasonCategory,
    ) -> Result<CorpusRecord, RefusalCorpusError> {
        self.append_refusal_with_candidate(
            classifier,
            refused_sql,
            refusal_class,
            suggest_parameterized_form(refused_sql).as_deref(),
        )
    }

    /// Testable lower-level seam for a candidate proposed by another rewrite
    /// mechanism. Production uses [`Self::append_refusal`]; keeping this
    /// private prevents callers from treating a stored record as approval.
    fn append_refusal_with_candidate(
        &self,
        classifier: &Classifier,
        refused_sql: &str,
        refusal_class: ReasonCategory,
        candidate: Option<&str>,
    ) -> Result<CorpusRecord, RefusalCorpusError> {
        // SEC-1: classify the raw candidate now. Do not classify the redacted
        // copy and do not persist a decision for a later request to replay.
        let suggested_rewrite =
            candidate.filter(|rewrite| classifier_proves_rewrite(classifier, rewrite));
        let record = CorpusRecord::new(
            refused_sql,
            refusal_class,
            suggested_rewrite,
            corpus_why(refusal_class),
        )?;
        self.append_record(&record)?;
        Ok(record)
    }

    /// Record a custom-tool signature rejection without pretending it was a
    /// SQL classifier refusal. The B8c trail is intentionally unsigned, but
    /// this event is durable and content-addressed so tamper evidence is never
    /// silently lost when the signed audit chain is unavailable.
    pub(crate) fn append_custom_tool_signature_rejection(
        &self,
        tool: &str,
        reason: CustomToolSignatureFailure,
    ) -> Result<(), RefusalCorpusError> {
        let event = SecurityEventRecord::custom_tool_signature_rejected(tool, reason);
        self.append_trail_record(&TrailRecord::SecurityEvent(event))
    }

    fn append_record(&self, record: &CorpusRecord) -> Result<(), RefusalCorpusError> {
        self.append_trail_record(&TrailRecord::Refusal(record.clone()))
    }

    fn append_trail_record(&self, record: &TrailRecord) -> Result<(), RefusalCorpusError> {
        let _guard = self
            .append_lock
            .lock()
            .map_err(|_| RefusalCorpusError::LockPoisoned)?;
        ensure_private_parent(&self.path)?;
        let mut file = open_private_append_file(&self.path)?;
        let mut line = record.to_jsonl_line().into_bytes();
        line.push(b'\n');
        file.write_all(&line)?;
        // The corpus is a durable state file, not a best-effort diagnostic.
        // A write failure still leaves the caller refused; it can never permit
        // dispatch of the original or suggested statement.
        file.sync_data()?;
        Ok(())
    }

    /// Export the accumulated corpus as deterministic, shippable JSONL.
    ///
    /// Every source line is re-validated before it is included, even though it
    /// was produced by this writer. The export deduplicates by redacted content
    /// hash and sorts by that hash, so the same valid state always yields the
    /// same bytes. A malformed or tampered source record aborts the export
    /// without producing a best-effort dataset.
    pub(crate) fn export_dataset(
        &self,
        destination: &Path,
    ) -> Result<CorpusExport, RefusalCorpusError> {
        if paths_resolve_to_same_file(self.path.as_ref(), destination) {
            return Err(RefusalCorpusError::ExportPathAliasesState);
        }
        let _guard = self
            .append_lock
            .lock()
            .map_err(|_| RefusalCorpusError::LockPoisoned)?;
        let mut records = read_validated_records(&self.path)?;
        records.sort_by(|left, right| left.id().cmp(right.id()));
        records.dedup_by(|left, right| left.id() == right.id());

        let mut rendered = String::new();
        for record in &records {
            rendered.push_str(&record.to_jsonl_line());
            rendered.push('\n');
        }
        write_public_export(destination, rendered.as_bytes())?;
        Ok(CorpusExport {
            record_count: records.len(),
        })
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

/// Stable metadata returned by a completed corpus export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CorpusExport {
    /// Number of unique, validated redacted records written to the dataset.
    pub(crate) record_count: usize,
}

#[derive(Debug)]
pub(crate) enum RefusalCorpusError {
    Redaction(CorpusRedactionError),
    Io(io::Error),
    LockPoisoned,
    ExportPathAliasesState,
}

impl fmt::Display for RefusalCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redaction(error) => write!(f, "refusal corpus redaction failed: {error}"),
            Self::Io(error) => write!(f, "refusal corpus I/O failed: {error}"),
            Self::LockPoisoned => f.write_str("refusal corpus append lock is poisoned"),
            Self::ExportPathAliasesState => {
                f.write_str("refusal corpus export path must differ from state path")
            }
        }
    }
}

impl Error for RefusalCorpusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Redaction(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::LockPoisoned | Self::ExportPathAliasesState => None,
        }
    }
}

impl From<CorpusRedactionError> for RefusalCorpusError {
    fn from(value: CorpusRedactionError) -> Self {
        Self::Redaction(value)
    }
}

impl From<io::Error> for RefusalCorpusError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn corpus_why(category: ReasonCategory) -> &'static str {
    match category {
        ReasonCategory::MultiStatementBatch => "the classifier requires one statement per request",
        ReasonCategory::DynamicSql => "the classifier could not prove dynamic SQL safe",
        ReasonCategory::TransactionControl => "transaction control is owned by the server",
        ReasonCategory::UnbalancedBlock => "the classifier could not parse the statement safely",
        ReasonCategory::PlSqlBlock => "the classifier could not prove the PL SQL block safe",
        ReasonCategory::RequiresHigherLevel => "the statement needs a higher operating level",
        ReasonCategory::CostBudgetExceeded => "the query cost exceeds the configured budget",
        ReasonCategory::BlockListed => "the statement matches a blocked policy",
        ReasonCategory::UnprovenSideEffect => "the classifier could not prove the statement safe",
        _ => "the classifier refused the statement",
    }
}

fn ensure_private_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(
            "refusal corpus parent is not a directory owned by this process",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o777 != 0o700 {
            permissions.set_mode(0o700);
            fs::set_permissions(parent, permissions)?;
        }
    }
    Ok(())
}

fn open_private_append_file(path: &Path) -> io::Result<File> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(io::Error::other(
            "refusal corpus path is not a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other(
            "refusal corpus path changed to a non regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        if permissions.mode() & 0o777 != 0o600 {
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }
    }
    Ok(file)
}

/// True if `a` and `b` name the same filesystem location, even through different
/// spellings (`./`, `..`, a symlink, or absolute-vs-relative). A plain `==` is
/// not enough: it would let `--out ./corpus/refusals.jsonl` alias the source
/// `corpus/refusals.jsonl` and clobber the live append-only state with the
/// public export. The destination usually does not exist yet, so an unresolved
/// path is canonicalized through its parent directory plus file name. Falls back
/// to syntactic equality only when neither side can be resolved.
fn paths_resolve_to_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    fn resolved(path: &Path) -> Option<PathBuf> {
        if let Ok(canonical) = path.canonicalize() {
            return Some(canonical);
        }
        let file_name = path.file_name()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        parent.canonicalize().ok().map(|dir| dir.join(file_name))
    }
    match (resolved(a), resolved(b)) {
        (Some(ra), Some(rb)) => ra == rb,
        _ => false,
    }
}

fn read_validated_records(path: &Path) -> Result<Vec<TrailRecord>, RefusalCorpusError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::other("refusal corpus state is not a regular file").into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }
    let state = fs::read_to_string(path)?;
    state
        .lines()
        .map(TrailRecord::from_jsonl_line)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn write_public_export(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(io::Error::other(
            "refusal corpus export parent is not a directory",
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(io::Error::other(
            "refusal corpus export path is not a regular file",
        ));
    }
    let mut staged = NamedTempFile::new_in(parent)?;
    staged.write_all(contents)?;
    staged.as_file().sync_data()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = staged.as_file().metadata()?.permissions();
        permissions.set_mode(0o644);
        staged.as_file().set_permissions(permissions)?;
    }
    staged.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oraclemcp_guard::DangerLevel;

    use super::*;

    const SECRETS: &[&str] = &[
        "hunter2",
        "alice@example.test",
        "ACME_CORP",
        "CUSTOMERS",
        "4111111111111111",
        "s3cr3t-token",
    ];

    fn writer() -> (tempfile::TempDir, RefusalCorpusWriter) {
        let dir = tempfile::tempdir().expect("temporary corpus directory");
        let writer = RefusalCorpusWriter::new(dir.path().join("corpus/refusals.jsonl"));
        (dir, writer)
    }

    fn records(writer: &RefusalCorpusWriter) -> Vec<CorpusRecord> {
        fs::read_to_string(writer.path())
            .expect("read corpus")
            .lines()
            .map(|line| CorpusRecord::from_jsonl_line(line).expect("valid redacted record"))
            .collect()
    }

    fn assert_no_secret(text: &str) {
        for secret in SECRETS {
            assert!(
                !text
                    .to_ascii_uppercase()
                    .contains(&secret.to_ascii_uppercase()),
                "secret leaked into corpus state: {secret:?} in {text:?}"
            );
        }
    }

    #[test]
    fn refused_statement_is_appended_as_a_redacted_refusal_record() {
        let (_dir, writer) = writer();
        let classifier = Classifier::default();
        let refused =
            "UPDATE acme_corp.customers SET token = 'hunter2' WHERE id = 4111111111111111";
        let raw_rewrite =
            suggest_parameterized_form(refused).expect("the bind-safe literals have a rewrite");

        let appended = writer
            .append_refusal(&classifier, refused, ReasonCategory::RequiresHigherLevel)
            .expect("a lexable refusal is appended");
        let stored = records(&writer);

        assert_eq!(stored, vec![appended]);
        assert_eq!(stored[0].refusal_class, ReasonCategory::RequiresHigherLevel);
        assert_eq!(
            reclassify_rewrite_at_apply(&classifier, &raw_rewrite).danger,
            DangerLevel::Guarded,
            "the recorded rewrite has its own fresh classifier verdict"
        );
        assert!(
            classifier_proves_rewrite(&classifier, &raw_rewrite),
            "only a classifier-proven candidate is offered or recorded"
        );
        assert!(
            stored[0].suggested_rewrite_redacted.is_some(),
            "a classifier-proven rewrite is retained as redacted evidence"
        );
        assert_no_secret(&fs::read_to_string(writer.path()).expect("read corpus"));
    }

    #[test]
    fn signature_rejection_is_a_typed_security_event_not_a_fake_sql_refusal() {
        let (_dir, writer) = writer();

        writer
            .append_custom_tool_signature_rejection(
                "report_sales",
                CustomToolSignatureFailure::Invalid,
            )
            .expect("security event is appended");

        let line = fs::read_to_string(writer.path()).expect("read B8c trail");
        let event = SecurityEventRecord::from_jsonl_line(line.trim())
            .expect("security event is validated on read");
        assert_eq!(event.event, SecurityEventKind::CustomToolSignatureRejected);
        assert_eq!(event.tool, "report_sales");
        assert_eq!(event.reason, CustomToolSignatureFailure::Invalid);
        assert_eq!(
            event.authenticity,
            CorpusAuthenticity::UnsignedNotTamperEvident,
            "the B8c floor must not masquerade as a signed audit chain"
        );
        assert!(
            CorpusRecord::from_jsonl_line(line.trim()).is_err(),
            "a custom-tool signature failure must never be rendered as invented SQL"
        );
    }

    #[test]
    fn invalid_security_event_tool_name_is_redacted_to_a_fixed_identifier() {
        let (_dir, writer) = writer();
        let malicious_name = "tool\\nsecret-token";

        writer
            .append_custom_tool_signature_rejection(
                malicious_name,
                CustomToolSignatureFailure::Required,
            )
            .expect("security event is appended without retaining an unsafe name");

        let line = fs::read_to_string(writer.path()).expect("read B8c trail");
        let event = SecurityEventRecord::from_jsonl_line(line.trim())
            .expect("security event is validated on read");
        assert_eq!(event.tool, "invalid-tool-name");
        assert!(!line.contains("secret-token"));
    }

    #[test]
    fn security_event_survives_validated_export() {
        let (dir, writer) = writer();
        writer
            .append_custom_tool_signature_rejection(
                "report_sales",
                CustomToolSignatureFailure::UnsupportedVersion,
            )
            .expect("security event is appended");
        let destination = dir.path().join("release/trail.jsonl");

        let export = writer
            .export_dataset(&destination)
            .expect("a validated security event is exportable");
        assert_eq!(export.record_count, 1);
        let line = fs::read_to_string(destination).expect("read exported trail");
        assert!(matches!(
            TrailRecord::from_jsonl_line(line.trim()),
            Ok(TrailRecord::SecurityEvent(_))
        ));
    }

    #[test]
    fn rewrite_is_reclassified_before_recording_and_unsafe_candidate_is_dropped() {
        let (_dir, writer) = writer();
        let classifier = Classifier::default();
        let unsafe_rewrite = "BEGIN EXECUTE IMMEDIATE 'DROP TABLE acme_corp.customers'; END;";

        let appended = writer
            .append_refusal_with_candidate(
                &classifier,
                "UPDATE acme_corp.customers SET status = 'closed' WHERE id = 42",
                ReasonCategory::RequiresHigherLevel,
                Some(unsafe_rewrite),
            )
            .expect("the original refusal is representable");

        assert_eq!(
            reclassify_rewrite_at_apply(&classifier, unsafe_rewrite).danger,
            DangerLevel::Forbidden,
            "the candidate is freshly classified, not trusted because it was suggested"
        );
        assert!(
            !classifier_proves_rewrite(&classifier, unsafe_rewrite),
            "unsafe SQL cannot be offered as a governed rewrite either"
        );
        assert!(
            appended.suggested_rewrite_redacted.is_none(),
            "a rewrite the classifier refuses is never persisted as a lesson"
        );
        assert!(
            records(&writer)[0].suggested_rewrite_redacted.is_none(),
            "the state file contains no unsafe candidate"
        );
    }

    #[test]
    fn stored_refusal_never_replays_a_verdict_to_widen_admission() {
        let (_dir, writer) = writer();
        let classifier = Classifier::default();
        let raw_rewrite = "UPDATE acme_corp.customers SET status = :status WHERE id = :id";
        let stored = writer
            .append_refusal_with_candidate(
                &classifier,
                "UPDATE acme_corp.customers SET status = 'closed' WHERE id = 42",
                ReasonCategory::RequiresHigherLevel,
                Some(raw_rewrite),
            )
            .expect("record a classifier-proven, level-gated rewrite");
        assert!(stored.suggested_rewrite_redacted.is_some());
        let serialized = stored.to_jsonl_line();
        assert!(
            !serialized.contains("verdict")
                && !serialized.contains("danger")
                && !serialized.contains("required_level"),
            "a corpus record stores evidence, never a reusable authorization verdict"
        );

        // The persisted form is deliberately redacted and no apply API accepts
        // it. A later raw request starts from the classifier again, under its
        // *current* (possibly tighter) policy; it cannot borrow this record's
        // earlier classification.
        let tightened = Classifier::new(
            oraclemcp_guard::ClassifierConfig::new().with_block_pattern("(?i)UPDATE"),
        );
        assert_eq!(
            reclassify_rewrite_at_apply(&tightened, raw_rewrite).danger,
            DangerLevel::Forbidden,
            "a later tightened classifier refuses a rewrite that was recordable before"
        );
        let later_raw_request = "BEGIN EXECUTE IMMEDIATE 'DROP TABLE acme_corp.customers'; END;";
        assert_eq!(
            reclassify_rewrite_at_apply(&classifier, later_raw_request).danger,
            DangerLevel::Forbidden,
            "a malicious later replacement is independently refused"
        );
        assert_eq!(
            reclassify_rewrite_at_apply(&classifier, "SELECT 1 FROM dual").danger,
            DangerLevel::Safe,
            "a different later request is admitted only after its own classification"
        );
        assert!(
            records(&writer)[0].suggested_rewrite_redacted.is_some(),
            "a stored rewrite is evidence only and does not influence the fresh verdict"
        );
    }

    #[test]
    fn writer_never_persists_secret_bind_or_customer_identifier() {
        let (_dir, writer) = writer();
        let classifier = Classifier::default();
        let refused = "BEGIN /* s3cr3t-token */ EXECUTE IMMEDIATE 'GRANT DBA TO acme_corp'; UPDATE customers SET email = :alice WHERE card = 4111111111111111; END;";

        writer
            .append_refusal(&classifier, refused, ReasonCategory::DynamicSql)
            .expect("the redactor accepts a lexable statement without preserving it");
        let persisted = fs::read_to_string(writer.path()).expect("read corpus");
        assert_no_secret(&persisted);
        assert!(
            !persisted.contains(":alice"),
            "bind names are not retained in the corpus"
        );
        assert!(
            !persisted.contains("/*"),
            "comments are not retained in the corpus"
        );
    }

    #[test]
    fn export_is_reproducible_and_contains_zero_raw_identifiers_or_binds() {
        let (dir, writer) = writer();
        let classifier = Classifier::default();
        writer
            .append_refusal(
                &classifier,
                "UPDATE acme_corp.customers SET token = :hunter2 WHERE email = 'alice@example.test'",
                ReasonCategory::RequiresHigherLevel,
            )
            .expect("first refusal is redacted into state");
        writer
            .append_refusal(
                &classifier,
                "UPDATE acme_corp.customers SET token = :s3cr3t WHERE email = 'alice@example.test'",
                ReasonCategory::RequiresHigherLevel,
            )
            .expect("equivalent refusal is redacted into state");

        let first_path = dir.path().join("release/refusal-corpus.jsonl");
        let second_path = dir.path().join("release/refusal-corpus-again.jsonl");
        let first = writer
            .export_dataset(&first_path)
            .expect("valid state exports");
        let second = writer
            .export_dataset(&second_path)
            .expect("same state exports again");
        assert_eq!(first, second);
        assert_eq!(
            first.record_count, 1,
            "redaction-level duplicates collapse to one shipped record"
        );

        let exported = fs::read_to_string(&first_path).expect("read shipped dataset");
        assert_eq!(
            exported,
            fs::read_to_string(&second_path).expect("read repeat dataset"),
            "export bytes are reproducible"
        );
        for line in exported.lines() {
            CorpusRecord::from_jsonl_line(line)
                .expect("every shipped line re-validates as a redacted corpus record");
        }
        for raw in [
            "acme_corp",
            "customers",
            "hunter2",
            "s3cr3t",
            "alice@example.test",
            ":hunter2",
            ":s3cr3t",
        ] {
            assert!(
                !exported.to_ascii_lowercase().contains(raw),
                "shipped corpus contains raw identifier, literal, or bind {raw:?}: {exported}"
            );
        }
    }

    #[test]
    fn export_refuses_tampered_state_instead_of_shipping_a_best_effort_dataset() {
        let (dir, writer) = writer();
        fs::create_dir_all(writer.path().parent().expect("state parent")).expect("state parent");
        fs::write(
            writer.path(),
            "{\"id\":\"sha256:tampered\",\"refused_sql_redacted\":\"SELECT * FROM acme_corp.customers WHERE token = 'hunter2'\",\"refusal_class\":\"DynamicSql\",\"why\":\"dynamic SQL\"}\n",
        )
        .expect("write synthetic tampered state");
        let destination = dir.path().join("release/refusal-corpus.jsonl");

        assert!(
            writer.export_dataset(&destination).is_err(),
            "an invalid state line cannot cross the public export boundary"
        );
        assert!(
            !destination.exists(),
            "the exporter must not ship a partial or best-effort dataset"
        );
    }
}
