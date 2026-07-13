//! Append-only refusal corpus writer (Arc J; bead `09x` J2).
//!
//! Corpus records are public-bound data, not a policy cache. In particular, a
//! redacted record is never executable SQL and carries no guard verdict. A
//! caller that wants to apply a suggested rewrite must present its raw SQL and
//! run [`reclassify_rewrite_at_apply`] again against the classifier and current
//! operating-level gate.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use oraclemcp_guard::corpus::{
    CorpusRecord, CorpusRedactionError, ReasonCategory, classifier_proves_rewrite,
    reclassify_rewrite_at_apply,
};
use oraclemcp_guard::{Classifier, suggest_parameterized_form};

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

    fn append_record(&self, record: &CorpusRecord) -> Result<(), RefusalCorpusError> {
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

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub(crate) enum RefusalCorpusError {
    Redaction(CorpusRedactionError),
    Io(io::Error),
    LockPoisoned,
}

impl fmt::Display for RefusalCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redaction(error) => write!(f, "refusal corpus redaction failed: {error}"),
            Self::Io(error) => write!(f, "refusal corpus I/O failed: {error}"),
            Self::LockPoisoned => f.write_str("refusal corpus append lock is poisoned"),
        }
    }
}

impl Error for RefusalCorpusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Redaction(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::LockPoisoned => None,
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
}
