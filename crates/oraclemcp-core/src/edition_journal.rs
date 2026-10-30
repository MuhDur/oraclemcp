//! Durable edition operation intents. This journal is recovery state: an
//! uncertain DDL is reconciled by observation and is never sent again.

use std::{
    collections::{BTreeMap, HashSet},
    fs,
    future::Future,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use oraclemcp_db::StatementOutcome;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    change_proposal::DatabaseIdentity,
    file_store::{FileStore, FileStoreError, ServiceOwner, StoreId},
};

const COLLECTION: &str = "edition-operations";
const JOURNAL_ID: &str = "operations";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
type ActiveKey = (PathBuf, String);
// All handles under one ServiceOwner must agree on in-flight operations. No
// filesystem mutation lock is held across an Oracle call or a catalog probe.
static ACTIVE: LazyLock<Mutex<HashSet<ActiveKey>>> = LazyLock::new(Mutex::default);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EditionOperationKind {
    Open,
    Stage,
    Promote,
    Rollback,
    Retire,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Prepared,
    Executing,
    OutcomeUnknown,
    Reconciling,
    Applied,
    Refused,
}

impl OperationState {
    fn terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Refused)
    }
    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Executing | Self::Reconciling)
                | (
                    Self::Executing,
                    Self::Applied | Self::Refused | Self::OutcomeUnknown
                )
                | (Self::OutcomeUnknown, Self::Reconciling)
                | (
                    Self::Reconciling,
                    Self::Applied | Self::Refused | Self::OutcomeUnknown | Self::Prepared
                )
        )
    }
}

/// A complete catalog observation. `None` is not a substitute for an
/// unreadable fact; probes must return an error when evidence is incomplete.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionStateSnapshot {
    pub database: DatabaseIdentity,
    pub parent_edition: String,
    pub parent_exists: bool,
    pub parent_usable: bool,
    pub default_edition: String,
    pub child_edition: String,
    pub child_exists: bool,
    pub child_usable: bool,
    pub child_parent: Option<String>,
    pub object_hashes: BTreeMap<String, String>,
}

impl EditionStateSnapshot {
    pub fn digest(&self) -> Result<String, EditionJournalError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|e| EditionJournalError::Invalid(e.to_string()))?;
        Ok(oraclemcp_audit::sha256_hex(&bytes))
    }

    fn validate(&self) -> Result<(), EditionJournalError> {
        self.database
            .validate()
            .map_err(|e| EditionJournalError::Invalid(e.to_string()))?;
        for name in [
            &self.parent_edition,
            &self.default_edition,
            &self.child_edition,
        ]
        .into_iter()
        .chain(self.child_parent.iter())
        {
            if !crate::change_proposal::normalize_edition_identifier(name.clone())
                .is_ok_and(|canonical| canonical == *name)
            {
                return Err(EditionJournalError::Invalid(
                    "noncanonical edition observation".into(),
                ));
            }
        }
        if self.child_exists != self.child_parent.is_some()
            || (!self.child_exists && (self.child_usable || !self.object_hashes.is_empty()))
            || (!self.parent_exists && self.parent_usable)
            || self.object_hashes.len() > 64
            || self.object_hashes.iter().any(|(name, hash)| {
                name.is_empty()
                    || name.len() > 256
                    || name.chars().any(char::is_control)
                    || !valid_digest(hash)
            })
        {
            return Err(EditionJournalError::Invalid(
                "incomplete edition observation".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionOperationIntent {
    pub operation_id: String,
    pub kind: EditionOperationKind,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub precondition_digest: String,
    pub expected_postcondition: EditionStateSnapshot,
    pub started_at: u64,
}

impl EditionOperationIntent {
    fn validate(&self) -> Result<(), EditionJournalError> {
        StoreId::from_safe_segment(self.operation_id.clone())?;
        StoreId::from_safe_segment(self.proposal_id.clone())?;
        if !valid_digest(&self.precondition_digest) || self.started_at == 0 {
            return Err(EditionJournalError::Invalid(
                "invalid operation precondition or timestamp".into(),
            ));
        }
        self.expected_postcondition.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionOperationRecord {
    pub sequence: u64,
    pub intent: EditionOperationIntent,
    pub state: OperationState,
    /// Monotone evidence that Executing was persisted. This says dispatch
    /// may have started, not that Oracle acknowledged an effect.
    pub dispatch_may_have_started: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ReconcileVerdict {
    Applied,
    RetryAllowed,
    OperatorReconciliationRequired {
        reason: ReconciliationReason,
        next_step: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationReason {
    PriorExecutionMayStillBeRunning,
    ObservedStateDiffers,
    ObservationUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PriorExecutionEvidence {
    /// The probe positively proved that the prior operation cannot still
    /// change Oracle state. Client cancellation or socket disposal alone
    /// does not prove Oracle session retirement.
    ProvenQuiescent,
    MayStillBeExecuting,
}

impl PriorExecutionEvidence {
    fn is_quiescent(self) -> bool {
        matches!(self, Self::ProvenQuiescent)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionStateObservation {
    pub snapshot: EditionStateSnapshot,
    pub prior_execution: PriorExecutionEvidence,
}

fn operator_reconciliation(reason: ReconciliationReason) -> ReconcileVerdict {
    ReconcileVerdict::OperatorReconciliationRequired {
        reason,
        next_step: "Confirm that the prior Oracle operation has stopped (or was never sent), then reconcile the exact DB/PDB, parent/default editions and object hashes. Do not replay uncertain DDL.".into(),
    }
}

/// Implemented by the catalog consumers. Observation must not issue DDL.
pub trait EditionStateProbe {
    fn observe(
        &self,
        intent: &EditionOperationIntent,
    ) -> Result<EditionStateObservation, EditionJournalError>;
}

#[derive(Debug, Error)]
pub enum EditionJournalError {
    #[error(transparent)]
    FileStore(#[from] FileStoreError),
    #[error("edition journal I/O failed: {0}")]
    Io(String),
    #[error("invalid edition journal: {0}")]
    Invalid(String),
    #[error("edition operation already exists; reconcile it before an explicit new attempt")]
    OperationExists,
    #[error("edition operation is currently executing or reconciling")]
    OperationActive,
    #[error("unknown edition operation")]
    UnknownOperation,
    #[error("edition operation requires reconciliation; it will not be replayed")]
    ReconciliationRequired,
    #[error("edition journal capacity reached")]
    Capacity,
    #[cfg(all(test, feature = "test-failpoints"))]
    #[error("injected journal crash")]
    InjectedCrash,
}

/// A fresh, non-cloneable dispatch capability. It cannot be reconstituted
/// from a persisted Prepared or OutcomeUnknown record after a crash.
#[derive(Debug)]
pub struct PreparedEditionOperation {
    root: PathBuf,
    intent: EditionOperationIntent,
}

struct ActiveOperation<'a> {
    key: ActiveKey,
    journal: &'a EditionOperationJournal,
}
impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        // Keep the same ACTIVE -> mutation-gate order as begin(). A cancelled
        // operation becomes durably unknown before its in-process marker is
        // released. If persistence fails, Executing remains conservatively
        // unresolved and still blocks any new operation for this PDB.
        let mut active = ACTIVE.lock();
        #[cfg(all(test, feature = "test-failpoints"))]
        let persist = !self
            .journal
            .simulating_crash
            .load(std::sync::atomic::Ordering::Acquire);
        #[cfg(not(all(test, feature = "test-failpoints")))]
        let persist = true;
        let result = if persist {
            (|| -> Result<(), EditionJournalError> {
                let _mutation = self.journal.owner.mutation_guard();
                if let Some(record) = self.journal.read_latest()?.remove(&self.key.1)
                    && matches!(
                        record.state,
                        OperationState::Executing | OperationState::Reconciling
                    )
                {
                    self.journal.append(
                        &record.intent,
                        if record.dispatch_may_have_started {
                            OperationState::OutcomeUnknown
                        } else {
                            OperationState::Prepared
                        },
                    )?;
                }
                Ok(())
            })()
        } else {
            Ok(())
        };
        active.remove(&self.key);
        drop(active);
        if let Err(error) = result {
            tracing::warn!(operation_id = %self.key.1, error = %error, "edition cancellation remains unresolved after journal persistence failure");
        }
    }
}

pub struct EditionOperationJournal {
    store: FileStore,
    owner: ServiceOwner,
    id: StoreId,
    #[cfg(all(test, feature = "test-failpoints"))]
    failpoint: Mutex<Option<CrashPoint>>,
    #[cfg(all(test, feature = "test-failpoints"))]
    simulating_crash: std::sync::atomic::AtomicBool,
}

impl EditionOperationJournal {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, EditionJournalError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("edition-operations")?;
        Self::open_with_owner(owner)
    }

    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, EditionJournalError> {
        let store = FileStore::open(owner.root())?;
        let id = StoreId::from_safe_segment(JOURNAL_ID)?;
        store.recover_jsonl(&owner, COLLECTION, &id)?;
        let journal = Self {
            store,
            owner,
            id,
            #[cfg(all(test, feature = "test-failpoints"))]
            failpoint: Mutex::new(None),
            #[cfg(all(test, feature = "test-failpoints"))]
            simulating_crash: std::sync::atomic::AtomicBool::new(false),
        };
        let active = ACTIVE.lock();
        let _mutation = journal.owner.mutation_guard();
        for record in journal.read_latest()?.values() {
            if record.state == OperationState::Executing
                && !active.contains(&(
                    journal.owner.root().to_path_buf(),
                    record.intent.operation_id.clone(),
                ))
            {
                journal.append(&record.intent, OperationState::OutcomeUnknown)?;
            }
        }
        drop(_mutation);
        drop(active);
        Ok(journal)
    }

    pub fn prepare(
        &self,
        intent: EditionOperationIntent,
    ) -> Result<PreparedEditionOperation, EditionJournalError> {
        intent.validate()?;
        let _mutation = self.owner.mutation_guard();
        let latest = self.read_latest()?;
        if latest.contains_key(&intent.operation_id) {
            return Err(EditionJournalError::OperationExists);
        }
        if latest.values().any(|record| {
            (record.intent.proposal_id == intent.proposal_id
                || record.intent.expected_postcondition.database
                    == intent.expected_postcondition.database)
                && !record.state.terminal()
        }) {
            return Err(EditionJournalError::ReconciliationRequired);
        }
        self.append(&intent, OperationState::Prepared)?;
        #[cfg(all(test, feature = "test-failpoints"))]
        self.crash_at(CrashPoint::AfterIntentPersisted)?;
        Ok(PreparedEditionOperation {
            root: self.owner.root().to_path_buf(),
            intent,
        })
    }

    /// Persist Executing before invoking the operation's future factory. Dropping this
    /// future leaves an unresolved record, including after a cancellation.
    pub async fn execute<T, F: Future<Output = (T, StatementOutcome)>>(
        &self,
        prepared: PreparedEditionOperation,
        call: impl FnOnce() -> F,
    ) -> Result<(T, OperationState), EditionJournalError> {
        if prepared.root != self.owner.root() {
            return Err(EditionJournalError::ReconciliationRequired);
        }
        let active_guard = self.begin(&prepared.intent.operation_id, |record| {
            if record.state != OperationState::Prepared || record.intent != prepared.intent {
                return Err(EditionJournalError::ReconciliationRequired);
            }
            self.append(&record.intent, OperationState::Executing)
        })?;
        let (value, outcome) = call().await;
        #[cfg(all(test, feature = "test-failpoints"))]
        self.crash_at(CrashPoint::AfterResponseReceived)?;
        let state = match outcome {
            StatementOutcome::Committed => OperationState::Applied,
            StatementOutcome::NotStarted => OperationState::Refused,
            _ => OperationState::OutcomeUnknown,
        };
        #[cfg(all(test, feature = "test-failpoints"))]
        self.crash_at(CrashPoint::BeforeFinalStatePersisted)?;
        {
            let _mutation = self.owner.mutation_guard();
            self.append(&prepared.intent, state)?;
        }
        drop(active_guard);
        Ok((value, state))
    }

    pub fn unresolved(&self) -> Result<Vec<EditionOperationRecord>, EditionJournalError> {
        let _mutation = self.owner.mutation_guard();
        Ok(self
            .read_latest()?
            .into_values()
            .filter(|record| !record.state.terminal())
            .collect())
    }

    pub fn reconcile(
        &self,
        operation_id: &str,
        probe: &dyn EditionStateProbe,
    ) -> Result<ReconcileVerdict, EditionJournalError> {
        {
            let _mutation = self.owner.mutation_guard();
            let record = self
                .read_latest()?
                .remove(operation_id)
                .ok_or(EditionJournalError::UnknownOperation)?;
            match record.state {
                OperationState::Applied => return Ok(ReconcileVerdict::Applied),
                OperationState::Refused => return Ok(ReconcileVerdict::RetryAllowed),
                _ => (),
            }
        }
        let active_guard = self.begin(operation_id, |record| {
            match record.state {
                OperationState::Prepared | OperationState::OutcomeUnknown => (),
                OperationState::Executing => {
                    self.append(&record.intent, OperationState::OutcomeUnknown)?
                }
                OperationState::Reconciling => self.append(
                    &record.intent,
                    if record.dispatch_may_have_started {
                        OperationState::OutcomeUnknown
                    } else {
                        OperationState::Prepared
                    },
                )?,
                _ => return Err(EditionJournalError::ReconciliationRequired),
            }
            self.append(&record.intent, OperationState::Reconciling)
        })?;
        let record = {
            let _mutation = self.owner.mutation_guard();
            self.read_latest()?
                .remove(operation_id)
                .ok_or(EditionJournalError::UnknownOperation)?
        };
        let intent = record.intent;
        let dispatched = record.dispatch_may_have_started;
        let verdict = match probe.observe(&intent) {
            Ok(observation) => {
                let observed = observation.snapshot;
                let precondition_matches = observed.database
                    == intent.expected_postcondition.database
                    && observed
                        .digest()
                        .is_ok_and(|hash| hash == intent.precondition_digest);
                if !dispatched && precondition_matches {
                    ReconcileVerdict::RetryAllowed
                } else if !observation.prior_execution.is_quiescent() {
                    operator_reconciliation(ReconciliationReason::PriorExecutionMayStillBeRunning)
                } else if observed == intent.expected_postcondition && observed.validate().is_ok() {
                    ReconcileVerdict::Applied
                } else if precondition_matches {
                    ReconcileVerdict::RetryAllowed
                } else {
                    operator_reconciliation(ReconciliationReason::ObservedStateDiffers)
                }
            }
            Err(_) => operator_reconciliation(ReconciliationReason::ObservationUnavailable),
        };
        let state = match &verdict {
            ReconcileVerdict::Applied => OperationState::Applied,
            ReconcileVerdict::RetryAllowed => OperationState::Refused,
            ReconcileVerdict::OperatorReconciliationRequired { .. } => {
                if dispatched {
                    OperationState::OutcomeUnknown
                } else {
                    OperationState::Prepared
                }
            }
        };
        {
            let _mutation = self.owner.mutation_guard();
            self.append(&intent, state)?;
        }
        drop(active_guard);
        Ok(verdict)
    }

    fn begin(
        &self,
        operation_id: &str,
        persist: impl FnOnce(&EditionOperationRecord) -> Result<(), EditionJournalError>,
    ) -> Result<ActiveOperation<'_>, EditionJournalError> {
        let key = (self.owner.root().to_path_buf(), operation_id.to_owned());
        let mut active = ACTIVE.lock();
        if active.contains(&key) {
            return Err(EditionJournalError::OperationActive);
        }
        let _mutation = self.owner.mutation_guard();
        let record = self
            .read_latest()?
            .remove(operation_id)
            .ok_or(EditionJournalError::UnknownOperation)?;
        persist(&record)?;
        active.insert(key.clone());
        Ok(ActiveOperation { key, journal: self })
    }

    fn path(&self) -> Result<PathBuf, EditionJournalError> {
        Ok(self.store.path_for(COLLECTION, &self.id, "jsonl")?)
    }

    fn read_latest(&self) -> Result<BTreeMap<String, EditionOperationRecord>, EditionJournalError> {
        let path = self.path()?;
        if fs::metadata(&path)
            .map_err(|e| EditionJournalError::Io(e.to_string()))?
            .len()
            > MAX_BYTES
        {
            return Err(EditionJournalError::Capacity);
        }
        let bytes = fs::read(path).map_err(|e| EditionJournalError::Io(e.to_string()))?;
        let mut latest: BTreeMap<String, EditionOperationRecord> = BTreeMap::new();
        for (index, line) in bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            let record: EditionOperationRecord = serde_json::from_slice(line)
                .map_err(|e| EditionJournalError::Invalid(e.to_string()))?;
            record.intent.validate()?;
            if record.sequence != index as u64 + 1 {
                return Err(EditionJournalError::Invalid(
                    "non-contiguous journal sequence".into(),
                ));
            }
            if let Some(previous) = latest.get(&record.intent.operation_id) {
                if previous.intent != record.intent || !previous.state.permits(record.state) {
                    return Err(EditionJournalError::Invalid(
                        "invalid operation history".into(),
                    ));
                }
            } else if record.state != OperationState::Prepared {
                return Err(EditionJournalError::Invalid(
                    "missing prepared intent".into(),
                ));
            }
            let expected_dispatch = record.state == OperationState::Executing
                || latest
                    .get(&record.intent.operation_id)
                    .is_some_and(|previous| previous.dispatch_may_have_started);
            if record.dispatch_may_have_started != expected_dispatch
                || (record.state == OperationState::Prepared && expected_dispatch)
                || (record.state == OperationState::OutcomeUnknown && !expected_dispatch)
            {
                return Err(EditionJournalError::Invalid(
                    "invalid dispatch history".into(),
                ));
            }
            latest.insert(record.intent.operation_id.clone(), record);
        }
        Ok(latest)
    }

    fn append(
        &self,
        intent: &EditionOperationIntent,
        state: OperationState,
    ) -> Result<(), EditionJournalError> {
        let latest = self.read_latest()?;
        let sequence = latest
            .values()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
            + 1;
        if let Some(previous) = latest.get(&intent.operation_id) {
            if previous.intent != *intent || !previous.state.permits(state) {
                return Err(EditionJournalError::Invalid(
                    "invalid operation transition".into(),
                ));
            }
        } else if state != OperationState::Prepared {
            return Err(EditionJournalError::UnknownOperation);
        }
        let dispatch_may_have_started = state == OperationState::Executing
            || latest
                .get(&intent.operation_id)
                .is_some_and(|previous| previous.dispatch_may_have_started);
        if (state == OperationState::Prepared && dispatch_may_have_started)
            || (state == OperationState::OutcomeUnknown && !dispatch_may_have_started)
        {
            return Err(EditionJournalError::Invalid(
                "invalid dispatch transition".into(),
            ));
        }
        let bytes = serde_json::to_vec(&EditionOperationRecord {
            sequence,
            intent: intent.clone(),
            state,
            dispatch_may_have_started,
        })
        .map_err(|e| EditionJournalError::Invalid(e.to_string()))?;
        if fs::metadata(self.path()?)
            .map_err(|e| EditionJournalError::Io(e.to_string()))?
            .len()
            + bytes.len() as u64
            + 1
            > MAX_BYTES
        {
            return Err(EditionJournalError::Capacity);
        }
        self.store
            .append_jsonl(&self.owner, COLLECTION, &self.id, &bytes)?;
        Ok(())
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(all(test, feature = "test-failpoints"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    AfterIntentPersisted,
    AfterOracleSuccess,
    AfterResponseReceived,
    BeforeFinalStatePersisted,
}

#[cfg(all(test, feature = "test-failpoints"))]
impl EditionOperationJournal {
    fn crash_at(&self, point: CrashPoint) -> Result<(), EditionJournalError> {
        if *self.failpoint.lock() == Some(point) {
            // A simulated process crash must not run the cancellation
            // persistence path: restart must recover the last durable state.
            self.simulating_crash
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(EditionJournalError::InjectedCrash);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    #[derive(Clone)]
    struct Probe {
        state: Arc<Mutex<EditionStateSnapshot>>,
        calls: Arc<AtomicUsize>,
        prior_execution: PriorExecutionEvidence,
    }
    impl EditionStateProbe for Probe {
        fn observe(
            &self,
            _: &EditionOperationIntent,
        ) -> Result<EditionStateObservation, EditionJournalError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(EditionStateObservation {
                snapshot: self.state.lock().clone(),
                prior_execution: self.prior_execution,
            })
        }
    }

    fn before() -> EditionStateSnapshot {
        EditionStateSnapshot {
            database: DatabaseIdentity {
                db_unique_name: "SYNTHETIC_DB".into(),
                dbid: "42".into(),
                container_uid: "9001".into(),
            },
            parent_edition: "ORA$BASE".into(),
            parent_exists: true,
            parent_usable: true,
            default_edition: "ORA$BASE".into(),
            child_edition: "CHILD_A".into(),
            child_exists: false,
            child_usable: false,
            child_parent: None,
            object_hashes: BTreeMap::new(),
        }
    }
    fn after() -> EditionStateSnapshot {
        EditionStateSnapshot {
            child_exists: true,
            child_usable: true,
            child_parent: Some("ORA$BASE".into()),
            ..before()
        }
    }
    fn intent() -> EditionOperationIntent {
        EditionOperationIntent {
            operation_id: "synthetic-open".into(),
            kind: EditionOperationKind::Open,
            proposal_id: "synthetic-request".into(),
            proposal_revision: 0,
            precondition_digest: before().digest().unwrap(),
            expected_postcondition: after(),
            started_at: 1,
        }
    }
    fn probe(state: EditionStateSnapshot) -> Probe {
        Probe {
            state: Arc::new(Mutex::new(state)),
            calls: Arc::new(AtomicUsize::new(0)),
            prior_execution: PriorExecutionEvidence::ProvenQuiescent,
        }
    }
    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("offline operation unexpectedly suspended"),
        }
    }

    #[test]
    fn journal_persists_executing_before_invoking_the_operation() {
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let token = journal.prepare(intent()).unwrap();
        assert_eq!(
            journal.unresolved().unwrap()[0].state,
            OperationState::Prepared
        );
        let calls = AtomicUsize::new(0);
        let result = ready(journal.execute(token, || {
            assert_eq!(
                journal.unresolved().unwrap()[0].state,
                OperationState::Executing,
                "the durable Executing record must precede the operation factory"
            );
            calls.fetch_add(1, Ordering::SeqCst);
            async { (7, StatementOutcome::Committed) }
        }))
        .unwrap();
        assert_eq!(result, (7, OperationState::Applied));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(journal.unresolved().unwrap().is_empty());
        assert!(matches!(
            journal.prepare(intent()),
            Err(EditionJournalError::OperationExists)
        ));
        let observation = probe(before());
        assert_eq!(
            journal.reconcile("synthetic-open", &observation).unwrap(),
            ReconcileVerdict::Applied
        );
        assert_eq!(
            observation.calls.load(Ordering::SeqCst),
            0,
            "terminal receipt is idempotent"
        );
    }

    #[test]
    fn outcome_unknown_never_replayed() {
        for outcome in [
            StatementOutcome::DdlOutcomeUnknown,
            StatementOutcome::CommitUnknown,
            StatementOutcome::ProtocolUnsynchronized,
        ] {
            let root = tempfile::tempdir().unwrap();
            let journal = EditionOperationJournal::open(root.path()).unwrap();
            let token = journal.prepare(intent()).unwrap();
            let calls = AtomicUsize::new(0);
            assert_eq!(
                ready(journal.execute(token, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ((), outcome)
                }))
                .unwrap()
                .1,
                OperationState::OutcomeUnknown
            );
            drop(journal);
            let journal = EditionOperationJournal::open(root.path()).unwrap();
            assert_eq!(
                journal.unresolved().unwrap()[0].state,
                OperationState::OutcomeUnknown
            );
            assert!(matches!(
                journal.prepare(intent()),
                Err(EditionJournalError::OperationExists)
            ));
            let mut new_id = intent();
            new_id.operation_id = "new-id-cannot-replay-unknown".into();
            assert!(matches!(
                journal.prepare(new_id),
                Err(EditionJournalError::ReconciliationRequired)
            ));
            let mut new_request = intent();
            new_request.operation_id = "new-request-id-cannot-replay-unknown".into();
            new_request.proposal_id = "different-request-same-pdb".into();
            assert!(matches!(
                journal.prepare(new_request),
                Err(EditionJournalError::ReconciliationRequired)
            ));
            let mut other_pdb = intent();
            other_pdb.operation_id = "independent-pdb-operation".into();
            other_pdb.proposal_id = "independent-pdb-request".into();
            other_pdb.expected_postcondition.database.container_uid = "9002".into();
            let mut other_pre = before();
            other_pre.database.container_uid = "9002".into();
            other_pdb.precondition_digest = other_pre.digest().unwrap();
            let other_token = journal
                .prepare(other_pdb)
                .expect("another PDB remains independent");
            ready(journal.execute(other_token, || {
                std::future::ready(((), StatementOutcome::Committed))
            }))
            .unwrap();
            assert_eq!(
                journal
                    .reconcile("synthetic-open", &probe(after()))
                    .unwrap(),
                ReconcileVerdict::Applied
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "recovery must never dispatch DDL"
            );
        }
    }

    #[test]
    fn journal_reconcile_requires_exact_identity_parent_default_usability_and_hashes() {
        let mut observations = Vec::new();
        let mut snapshot = after();
        snapshot.database.container_uid = "9002".into();
        observations.push(snapshot);
        let mut snapshot = after();
        snapshot.parent_edition = "OTHER_PARENT".into();
        observations.push(snapshot);
        let mut snapshot = after();
        snapshot.default_edition = "OTHER_DEFAULT".into();
        observations.push(snapshot);
        let mut snapshot = after();
        snapshot.child_usable = false;
        observations.push(snapshot);
        let mut snapshot = after();
        snapshot
            .object_hashes
            .insert("APP.PKG".into(), format!("sha256:{}", "a".repeat(64)));
        observations.push(snapshot);
        for snapshot in observations {
            let root = tempfile::tempdir().unwrap();
            let journal = EditionOperationJournal::open(root.path()).unwrap();
            let _token = journal.prepare(intent()).unwrap();
            let verdict = journal
                .reconcile("synthetic-open", &probe(snapshot))
                .unwrap();
            assert!(matches!(
                &verdict,
                ReconcileVerdict::OperatorReconciliationRequired {
                    reason: ReconciliationReason::ObservedStateDiffers,
                    ..
                }
            ));
            assert!(
                serde_json::to_value(verdict).unwrap()["next_step"]
                    .as_str()
                    .unwrap()
                    .contains("Do not replay")
            );
            assert_eq!(
                journal.unresolved().unwrap()[0].state,
                OperationState::Prepared,
                "failed observation cannot invent a dispatch that never occurred"
            );
        }
    }

    #[test]
    fn unknown_execution_requires_proven_quiescence_even_with_matching_catalog_state() {
        for snapshot in [before(), after()] {
            let root = tempfile::tempdir().unwrap();
            let journal = EditionOperationJournal::open(root.path()).unwrap();
            let token = journal.prepare(intent()).unwrap();
            ready(journal.execute(token, || {
                std::future::ready(((), StatementOutcome::DdlOutcomeUnknown))
            }))
            .unwrap();
            let mut observation = probe(snapshot.clone());
            observation.prior_execution = PriorExecutionEvidence::MayStillBeExecuting;
            let verdict = journal.reconcile("synthetic-open", &observation).unwrap();
            assert!(
                matches!(
                    &verdict,
                    ReconcileVerdict::OperatorReconciliationRequired {
                        reason: ReconciliationReason::PriorExecutionMayStillBeRunning,
                        ..
                    }
                ),
                "premature recovery: {verdict:?}"
            );
            assert!(
                serde_json::to_value(verdict).unwrap()["next_step"]
                    .as_str()
                    .unwrap()
                    .contains("Do not replay")
            );
            assert_eq!(
                journal.unresolved().unwrap()[0].state,
                OperationState::OutcomeUnknown
            );
            assert!(journal.unresolved().unwrap()[0].dispatch_may_have_started);
            observation.prior_execution = PriorExecutionEvidence::ProvenQuiescent;
            assert_eq!(
                journal.reconcile("synthetic-open", &observation).unwrap(),
                if snapshot == before() {
                    ReconcileVerdict::RetryAllowed
                } else {
                    ReconcileVerdict::Applied
                }
            );
        }
    }

    #[test]
    fn prepared_only_precondition_allows_retry_without_quiescence() {
        struct Unreadable;
        impl EditionStateProbe for Unreadable {
            fn observe(
                &self,
                _: &EditionOperationIntent,
            ) -> Result<EditionStateObservation, EditionJournalError> {
                Err(EditionJournalError::Io(
                    "synthetic catalog observation denied".into(),
                ))
            }
        }
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let _token = journal.prepare(intent()).unwrap();
        assert!(matches!(
            journal.reconcile("synthetic-open", &Unreadable).unwrap(),
            ReconcileVerdict::OperatorReconciliationRequired {
                reason: ReconciliationReason::ObservationUnavailable,
                ..
            }
        ));
        let prepared = &journal.unresolved().unwrap()[0];
        assert_eq!(prepared.state, OperationState::Prepared);
        assert!(!prepared.dispatch_may_have_started);
        let mut observation = probe(before());
        observation.prior_execution = PriorExecutionEvidence::MayStillBeExecuting;
        assert_eq!(
            journal.reconcile("synthetic-open", &observation).unwrap(),
            ReconcileVerdict::RetryAllowed
        );
    }

    #[test]
    fn journal_dispatch_history_cannot_be_reset_in_persisted_records() {
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let token = journal.prepare(intent()).unwrap();
        let mut operation =
            Box::pin(journal.execute(token, std::future::pending::<((), StatementOutcome)>));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(operation);
        let path = journal.path().unwrap();
        drop(journal);
        let text = fs::read_to_string(&path).unwrap();
        let mut forged = String::new();
        for line in text.lines() {
            let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
            record["dispatch_may_have_started"] = serde_json::Value::Bool(false);
            forged.push_str(&serde_json::to_string(&record).unwrap());
            forged.push('\n');
        }
        fs::write(path, forged).unwrap();
        assert!(matches!(
            EditionOperationJournal::open(root.path()),
            Err(EditionJournalError::Invalid(_))
        ));
    }

    #[test]
    fn journal_active_operation_cannot_be_reconciled_by_another_handle() {
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let token = journal.prepare(intent()).unwrap();
        let mut operation =
            Box::pin(journal.execute(token, std::future::pending::<((), StatementOutcome)>));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let second = EditionOperationJournal::open_with_owner(journal.owner.clone()).unwrap();
        assert_eq!(
            second.unresolved().unwrap()[0].state,
            OperationState::Executing
        );
        let observation = probe(before());
        assert!(matches!(
            second.reconcile("synthetic-open", &observation),
            Err(EditionJournalError::OperationActive)
        ));
        assert_eq!(observation.calls.load(Ordering::SeqCst), 0);
        drop(operation);
        assert_eq!(
            second.unresolved().unwrap()[0].state,
            OperationState::OutcomeUnknown,
            "ordinary cancellation records uncertainty before releasing the active marker"
        );
        assert_eq!(
            second.reconcile("synthetic-open", &observation).unwrap(),
            ReconcileVerdict::RetryAllowed
        );
        assert!(
            matches!(
                second.prepare(intent()),
                Err(EditionJournalError::OperationExists)
            ),
            "a retry needs a fresh explicit operation id"
        );
        let mut explicit_retry = intent();
        explicit_retry.operation_id = "explicit-retry-after-reconciliation".into();
        assert!(
            second.prepare(explicit_retry).is_ok(),
            "exact precondition permits a fresh explicit attempt"
        );
    }

    #[test]
    fn journal_torn_terminal_tail_recovers_unknown_without_replay() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let token = journal.prepare(intent()).unwrap();
        let mut operation =
            Box::pin(journal.execute(token, std::future::pending::<((), StatementOutcome)>));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(operation);
        let path = journal.path().unwrap();
        drop(journal);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"sequence\":3,\"state\":\"appl").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        assert_eq!(
            journal.unresolved().unwrap()[0].state,
            OperationState::OutcomeUnknown
        );
        assert_eq!(
            journal
                .reconcile("synthetic-open", &probe(after()))
                .unwrap(),
            ReconcileVerdict::Applied
        );
    }

    #[cfg(feature = "test-failpoints")]
    #[test]
    fn journal_crash_after_intent_persisted() {
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        *journal.failpoint.lock() = Some(CrashPoint::AfterIntentPersisted);
        assert!(matches!(
            journal.prepare(intent()),
            Err(EditionJournalError::InjectedCrash)
        ));
        drop(journal);
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        assert_eq!(
            journal.unresolved().unwrap()[0].state,
            OperationState::Prepared
        );
        assert_eq!(
            journal
                .reconcile("synthetic-open", &probe(before()))
                .unwrap(),
            ReconcileVerdict::RetryAllowed
        );
        assert!(journal.unresolved().unwrap().is_empty());
    }

    #[cfg(feature = "test-failpoints")]
    #[test]
    fn journal_crash_after_oracle_success() {
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let token = journal.prepare(intent()).unwrap();
        let observation = probe(before());
        let calls = AtomicUsize::new(0);
        *journal.failpoint.lock() = Some(CrashPoint::AfterOracleSuccess);
        let mut operation = Box::pin(journal.execute(token, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            *observation.state.lock() = after();
            // The effect happened, but its response has not reached execute.
            if journal.crash_at(CrashPoint::AfterOracleSuccess).is_err() {
                std::future::pending::<()>().await;
            }
            ((), StatementOutcome::Committed)
        }));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(operation);
        drop(journal);
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        assert_eq!(
            journal.unresolved().unwrap()[0].state,
            OperationState::OutcomeUnknown
        );
        assert_eq!(
            journal.reconcile("synthetic-open", &observation).unwrap(),
            ReconcileVerdict::Applied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "test-failpoints")]
    fn crash_after_response(point: CrashPoint) {
        let root = tempfile::tempdir().unwrap();
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        let token = journal.prepare(intent()).unwrap();
        let calls = AtomicUsize::new(0);
        let observation = probe(before());
        *journal.failpoint.lock() = Some(point);
        assert!(matches!(
            ready(journal.execute(token, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                *observation.state.lock() = after();
                ((), StatementOutcome::Committed)
            })),
            Err(EditionJournalError::InjectedCrash)
        ));
        drop(journal);
        let journal = EditionOperationJournal::open(root.path()).unwrap();
        assert_eq!(
            journal.unresolved().unwrap()[0].state,
            OperationState::OutcomeUnknown
        );
        assert_eq!(
            journal.reconcile("synthetic-open", &observation).unwrap(),
            ReconcileVerdict::Applied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[cfg(feature = "test-failpoints")]
    #[test]
    fn journal_crash_after_response_received() {
        crash_after_response(CrashPoint::AfterResponseReceived);
    }
    #[cfg(feature = "test-failpoints")]
    #[test]
    fn journal_crash_before_final_state_persisted() {
        crash_after_response(CrashPoint::BeforeFinalStatePersisted);
    }
}
