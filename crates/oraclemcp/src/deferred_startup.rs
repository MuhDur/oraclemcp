//! Handshake-first serve startup (#51).
//!
//! Every MCP client session launches its own `oraclemcp serve`. When a second
//! instance shares the first one's audit log (or service-state owner lock),
//! failing *before* the MCP handshake leaves the client with nothing but
//! "Connection closed". Instead the transport comes up and answers
//! `initialize` and `tools/list` from the static registry, and the tool
//! dispatcher is a [`DeferredDispatch`]: every `tools/call` first retries the
//! non-blocking locks. While one is held it returns a typed error naming the
//! holder pid. It opens no database connection and runs nothing. Once the
//! locks are free, the real, audited dispatcher is built once and every later
//! call goes to it.
//!
//! Fail-closed invariant: the deferral only moves the refusal after the
//! handshake. The real dispatcher, and with it any path that can reach Oracle,
//! exists only after the opener has acquired every audit/service lock the
//! configuration requires. No tool call runs without the audit sink its
//! profile requires.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::{Cx, Outcome};
use oraclemcp_core::admission::CapacitySnapshot;
use oraclemcp_core::edition_executor::ValidatedEditionIdent;
use oraclemcp_core::http::{
    HttpLaneBinding, HttpLaneCloseResult, HttpLaneSnapshot, HttpResultStore, HttpSessionLifecycle,
    HttpSessionStore,
};
use oraclemcp_core::{
    DispatchCloseFuture, DispatchCloseReason, DispatchContext, DispatchFuture,
    DispatchStreamStartFuture, McpSurfaceDetail, McpSurfaceFuture, ToolDispatch, ToolStreamSender,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde_json::Value;

/// How long a client should wait before retrying a locked call.
const LOCKED_RETRY_AFTER: Duration = Duration::from_secs(2);

/// A lock another oraclemcp instance holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupLock {
    /// The audit log's writer lock (`AuditError::Locked`).
    AuditLog {
        /// The contended audit log path.
        path: String,
        /// The holder's pid, when the lock file records it.
        holder_pid: Option<u32>,
    },
    /// The exclusive service-state owner lock.
    ServiceOwner {
        /// The holder's pid, when the lock file records it.
        holder_pid: Option<u32>,
    },
}

impl StartupLock {
    /// The stable machine code (also used for the startup status line).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            StartupLock::AuditLog { .. } => "ORACLEMCP_AUDIT_LOG_LOCKED",
            StartupLock::ServiceOwner { .. } => "ORACLEMCP_SERVICE_OWNER_LOCKED",
        }
    }

    fn holder(pid: Option<u32>) -> String {
        pid.map_or_else(
            || "another oraclemcp instance".to_owned(),
            |pid| format!("another oraclemcp instance (pid {pid})"),
        )
    }

    /// The operator-facing description.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            StartupLock::AuditLog { path, holder_pid } => format!(
                "audit log {path} is locked by {}",
                Self::holder(*holder_pid)
            ),
            StartupLock::ServiceOwner { holder_pid } => format!(
                "the service state is owned by {}",
                Self::holder(*holder_pid)
            ),
        }
    }

    /// The typed tool-call refusal: retryable, names the holder, and says
    /// that nothing ran.
    #[must_use]
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope::new(
            ErrorClass::Busy,
            format!(
                "{}: {}; this server has not opened a database connection and executed \
                 nothing",
                self.code(),
                self.describe()
            ),
        )
        .with_retry_after_ms(u64::try_from(LOCKED_RETRY_AFTER.as_millis()).unwrap_or(u64::MAX))
        .with_next_step(
            "retry once the other instance exits, or give this client its own state \
             directory (XDG_STATE_HOME)",
        )
    }
}

/// Why the deferred opener could not produce a dispatcher.
#[derive(Clone, Debug)]
pub enum OpenRefusal {
    /// A lock is held; the next call retries.
    Locked(StartupLock),
    /// A permanent failure; every later call returns this envelope.
    Fatal(Box<ErrorEnvelope>),
}

/// Produces the real dispatcher. Must be retry-safe on
/// [`OpenRefusal::Locked`]: take every lock *before* consuming anything
/// single-use (the connection plan) and before touching Oracle.
pub type Opener = Box<dyn FnMut() -> Result<Arc<dyn ToolDispatch>, OpenRefusal> + Send>;

struct State {
    /// Kept for the dispatcher's whole life, also after a successful open:
    /// the opener owns the locks it acquired (service-owner guard), which
    /// must be held exactly as long as the dispatcher it built.
    opener: Opener,
    open: Option<Arc<dyn ToolDispatch>>,
    failed: Option<Box<ErrorEnvelope>>,
}

/// A [`ToolDispatch`] that builds the real dispatcher on first use, once the
/// locks it needs are free. See the module docs.
pub struct DeferredDispatch {
    state: Mutex<State>,
}

impl std::fmt::Debug for DeferredDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let label = match (&state.open, &state.failed) {
            (Some(_), _) => "open",
            (None, Some(_)) => "failed",
            (None, None) => "pending",
        };
        f.debug_struct("DeferredDispatch")
            .field("state", &label)
            .finish()
    }
}

impl DeferredDispatch {
    /// A dispatcher whose real target `opener` builds on first use.
    #[must_use]
    pub fn new(opener: Opener) -> Self {
        Self {
            state: Mutex::new(State {
                opener,
                open: None,
                failed: None,
            }),
        }
    }

    /// Try `opener` once now. Uncontended, the dispatcher is open before the
    /// transport starts, exactly as an eager startup would be. A held lock
    /// defers to the first tool call and is returned for the operator's
    /// status line.
    ///
    /// # Errors
    /// A fatal refusal: the caller keeps today's pre-handshake exit.
    pub fn start(opener: Opener) -> Result<(Self, Option<StartupLock>), Box<ErrorEnvelope>> {
        let dispatch = Self::new(opener);
        let lock = {
            let mut state = dispatch.state.lock().unwrap_or_else(|e| e.into_inner());
            match (state.opener)() {
                Ok(inner) => {
                    state.open = Some(inner);
                    None
                }
                Err(OpenRefusal::Locked(lock)) => Some(lock),
                Err(OpenRefusal::Fatal(envelope)) => return Err(envelope),
            }
        };
        Ok((dispatch, lock))
    }

    /// The open dispatcher, trying the opener once if still pending.
    ///
    /// # Errors
    /// The typed lock refusal (retryable) or the permanent failure.
    pub fn resolve(&self) -> Result<Arc<dyn ToolDispatch>, ErrorEnvelope> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(inner) = &state.open {
            return Ok(Arc::clone(inner));
        }
        if let Some(envelope) = &state.failed {
            return Err((**envelope).clone());
        }
        match (state.opener)() {
            Ok(inner) => {
                state.open = Some(Arc::clone(&inner));
                Ok(inner)
            }
            Err(OpenRefusal::Locked(lock)) => Err(lock.envelope()),
            Err(OpenRefusal::Fatal(envelope)) => {
                let refusal = (*envelope).clone();
                state.failed = Some(envelope);
                Err(refusal)
            }
        }
    }

    /// The open dispatcher without attempting to open it.
    fn current(&self) -> Option<Arc<dyn ToolDispatch>> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open
            .clone()
    }
}

impl ToolDispatch for DeferredDispatch {
    fn request_timeout_ceiling(&self) -> Result<Duration, ErrorEnvelope> {
        match self.current() {
            Some(inner) => inner.request_timeout_ceiling(),
            None => Ok(oraclemcp_core::DEFAULT_REQUEST_TIMEOUT),
        }
    }

    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        match self.resolve() {
            Ok(inner) => Box::pin(async move { inner.dispatch(cx, context, name, args).await }),
            Err(envelope) => Box::pin(async move { Outcome::Err(envelope) }),
        }
    }

    fn operator_edition_flip<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        edition: &ValidatedEditionIdent,
        expected_profile: &str,
    ) -> DispatchFuture<'a> {
        match self.resolve() {
            Ok(inner) => {
                let edition = edition.clone();
                let expected_profile = expected_profile.to_owned();
                Box::pin(async move {
                    inner
                        .operator_edition_flip(cx, context, &edition, &expected_profile)
                        .await
                })
            }
            Err(envelope) => Box::pin(async move { Outcome::Err(envelope) }),
        }
    }

    fn dispatch_stream_start<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
        frames: ToolStreamSender,
    ) -> DispatchStreamStartFuture<'a> {
        match self.resolve() {
            Ok(inner) => Box::pin(async move {
                inner
                    .dispatch_stream_start(cx, context, name, args, frames)
                    .await
            }),
            Err(envelope) => Box::pin(async move { Outcome::Err(envelope) }),
        }
    }

    fn dispatch_stream<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
        frames: ToolStreamSender,
    ) -> DispatchFuture<'a> {
        match self.resolve() {
            Ok(inner) => {
                Box::pin(
                    async move { inner.dispatch_stream(cx, context, name, args, frames).await },
                )
            }
            Err(envelope) => Box::pin(async move { Outcome::Err(envelope) }),
        }
    }

    fn close<'a>(&'a self, cx: &'a Cx, reason: DispatchCloseReason) -> DispatchCloseFuture<'a> {
        match self.current() {
            Some(inner) => Box::pin(async move { inner.close(cx, reason).await }),
            None => Box::pin(async { Ok(()) }),
        }
    }

    fn mcp_surface_state<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        detail: McpSurfaceDetail,
    ) -> McpSurfaceFuture<'a> {
        // Discovery must never open the sink or the database: until the real
        // dispatcher exists, the server renders the static registry.
        match self.current() {
            Some(inner) => {
                Box::pin(async move { inner.mcp_surface_state(cx, context, detail).await })
            }
            None => Box::pin(async { Outcome::Ok(None) }),
        }
    }
}

/// The stateful HTTP transport takes its session lifecycle at startup, but
/// under #51 the stateful lane dispatcher that implements it is built by the
/// deferred opener. This forwards to it once attached. Until then there are
/// no lanes, so closes find nothing; a principal revocation floor recorded in
/// the meantime is replayed on attach, so a credential revoked while the
/// locks were held still binds the lanes built afterwards.
#[derive(Debug, Default)]
pub struct DeferredSessionLifecycle {
    state: Mutex<LifecycleState>,
}

#[derive(Debug, Default)]
struct LifecycleState {
    inner: Option<Arc<dyn HttpSessionLifecycle>>,
    pending_floors: Vec<(String, DispatchCloseReason, Option<u64>)>,
}

impl DeferredSessionLifecycle {
    /// Attach the real lifecycle and replay the floors recorded while pending.
    pub fn attach(&self, inner: Arc<dyn HttpSessionLifecycle>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for (principal_key, reason, min_generation) in state.pending_floors.drain(..) {
            inner.close_principal_sessions(&principal_key, reason, min_generation);
        }
        state.inner = Some(inner);
    }

    fn inner(&self) -> Option<Arc<dyn HttpSessionLifecycle>> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .inner
            .clone()
    }
}

impl HttpSessionLifecycle for DeferredSessionLifecycle {
    fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
        self.inner()
            .is_some_and(|inner| inner.close_session(session_id, principal_key))
    }

    fn close_session_with_reason(
        &self,
        session_id: &str,
        principal_key: &str,
        reason: DispatchCloseReason,
    ) -> bool {
        self.inner()
            .is_some_and(|inner| inner.close_session_with_reason(session_id, principal_key, reason))
    }

    fn close_all_sessions(&self) {
        if let Some(inner) = self.inner() {
            inner.close_all_sessions();
        }
    }

    fn close_principal_sessions(
        &self,
        principal_key: &str,
        reason: DispatchCloseReason,
        min_generation: Option<u64>,
    ) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.inner.clone() {
            Some(inner) => {
                drop(state);
                inner.close_principal_sessions(principal_key, reason, min_generation)
            }
            None => {
                state
                    .pending_floors
                    .push((principal_key.to_owned(), reason, min_generation));
                0
            }
        }
    }

    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        self.inner()
            .map(|inner| inner.active_lanes())
            .unwrap_or_default()
    }

    fn capacity_snapshot(&self, scope: &str, subject: &str) -> Option<CapacitySnapshot> {
        self.inner()
            .and_then(|inner| inner.capacity_snapshot(scope, subject))
    }

    fn lane_binding(&self, lane_id: &str) -> Option<HttpLaneBinding> {
        self.inner().and_then(|inner| inner.lane_binding(lane_id))
    }

    fn close_lane_with_reason(
        &self,
        lane_id: &str,
        expected_generation: u64,
        reason: DispatchCloseReason,
        session_store: Option<&HttpSessionStore>,
        result_store: Option<&HttpResultStore>,
    ) -> HttpLaneCloseResult {
        match self.inner() {
            Some(inner) => inner.close_lane_with_reason(
                lane_id,
                expected_generation,
                reason,
                session_store,
                result_store,
            ),
            None => HttpLaneCloseResult::NotFound,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asupersync::runtime::RuntimeBuilder;
    use oraclemcp_audit::{AuditError, FileAuditSink};
    use serde_json::json;

    use super::*;

    /// A stand-in for the real dispatcher: counts the calls that reach it.
    struct CountingDispatch {
        calls: Arc<AtomicUsize>,
    }

    impl ToolDispatch for CountingDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let name = name.to_owned();
            Box::pin(async move { Outcome::Ok(json!({ "ran": name })) })
        }
    }

    /// An opener shaped like the production one: it takes the audit writer
    /// lock FIRST and only then "connects" (counted) and builds the inner
    /// dispatcher, so a held lock can never lead to database work.
    fn audit_gated_opener(
        audit_path: std::path::PathBuf,
        connects: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    ) -> Opener {
        // The opener keeps the sink it opened, holding the writer lock for as
        // long as the dispatcher it built lives.
        let mut held: Vec<FileAuditSink> = Vec::new();
        Box::new(move || {
            match FileAuditSink::open(&audit_path) {
                Ok(opened) => held.push(opened),
                Err(AuditError::Locked { path, holder_pid }) => {
                    return Err(OpenRefusal::Locked(StartupLock::AuditLog {
                        path,
                        holder_pid,
                    }));
                }
                Err(other) => {
                    return Err(OpenRefusal::Fatal(Box::new(ErrorEnvelope::new(
                        ErrorClass::RuntimeStateRequired,
                        other.to_string(),
                    ))));
                }
            }
            assert_eq!(held.len(), 1, "the sink is held before any connection");
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(CountingDispatch {
                calls: Arc::clone(&calls),
            }) as Arc<dyn ToolDispatch>)
        })
    }

    fn call(dispatch: &DeferredDispatch) -> Outcome<Value, ErrorEnvelope> {
        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                dispatch
                    .dispatch(&cx, DispatchContext::default(), "oracle_query", json!({}))
                    .await
            })
    }

    fn surface_is_static(dispatch: &DeferredDispatch) -> bool {
        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                matches!(
                    dispatch
                        .mcp_surface_state(
                            &cx,
                            DispatchContext::default(),
                            McpSurfaceDetail::LevelOnly
                        )
                        .await,
                    Outcome::Ok(None)
                )
            })
    }

    fn audit_path(dir: &Path) -> std::path::PathBuf {
        dir.join("audit").join("audit.jsonl")
    }

    #[test]
    fn deferred_auditor_locked_refuses_tool_calls_without_db_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = audit_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _holder = FileAuditSink::open(&path).expect("the first instance holds the log");
        let (connects, calls) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let dispatch = DeferredDispatch::new(audit_gated_opener(
            path.clone(),
            Arc::clone(&connects),
            Arc::clone(&calls),
        ));

        for _ in 0..3 {
            let Outcome::Err(envelope) = call(&dispatch) else {
                panic!("a locked audit log must refuse the tool call");
            };
            assert_eq!(envelope.error_class, ErrorClass::Busy);
            assert!(
                envelope.message.starts_with("ORACLEMCP_AUDIT_LOG_LOCKED:"),
                "{}",
                envelope.message
            );
            assert!(
                envelope
                    .message
                    .contains(&format!("(pid {})", std::process::id())),
                "names the holder pid: {}",
                envelope.message
            );
            assert!(envelope.retry_after_ms.is_some());
        }
        assert_eq!(
            connects.load(Ordering::SeqCst),
            0,
            "no DB connection while locked"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "nothing executed while locked"
        );
        assert!(
            surface_is_static(&dispatch),
            "discovery never opens the sink"
        );
    }

    #[test]
    fn deferred_auditor_reopens_after_holder_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = audit_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let holder = FileAuditSink::open(&path).expect("the first instance holds the log");
        let (connects, calls) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let dispatch = DeferredDispatch::new(audit_gated_opener(
            path,
            Arc::clone(&connects),
            Arc::clone(&calls),
        ));
        assert!(matches!(call(&dispatch), Outcome::Err(_)));

        drop(holder); // the first instance exits
        let Outcome::Ok(value) = call(&dispatch) else {
            panic!("the next call after the holder exits must proceed");
        };
        assert_eq!(value, json!({ "ran": "oracle_query" }));
        assert!(matches!(call(&dispatch), Outcome::Ok(_)));
        assert_eq!(connects.load(Ordering::SeqCst), 1, "opened exactly once");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn deferred_fatal_open_failure_is_permanent_and_never_dispatches() {
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        let dispatch = DeferredDispatch::new(Box::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(OpenRefusal::Fatal(Box::new(ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                "ORACLEMCP_AUDIT_CHAIN_RESUME_REFUSED: synthetic",
            ))))
        }));
        for _ in 0..2 {
            assert!(matches!(call(&dispatch), Outcome::Err(_)));
        }
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "a fatal refusal is not retried"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn service_owner_lock_has_its_own_typed_code() {
        let envelope = StartupLock::ServiceOwner {
            holder_pid: Some(4242),
        }
        .envelope();
        assert!(
            envelope
                .message
                .starts_with("ORACLEMCP_SERVICE_OWNER_LOCKED:")
        );
        assert!(envelope.message.contains("(pid 4242)"));
    }

    /// Records the principal floors the real stateful lifecycle receives.
    #[derive(Debug, Default)]
    struct FloorRecorder {
        floors: Mutex<Vec<(String, Option<u64>)>>,
    }

    impl HttpSessionLifecycle for FloorRecorder {
        fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
            true
        }

        fn close_principal_sessions(
            &self,
            principal_key: &str,
            _reason: DispatchCloseReason,
            min_generation: Option<u64>,
        ) -> usize {
            self.floors
                .lock()
                .unwrap()
                .push((principal_key.to_owned(), min_generation));
            1
        }
    }

    #[test]
    fn deferred_lifecycle_replays_revocation_floors_recorded_while_locked() {
        let lifecycle = DeferredSessionLifecycle::default();
        // Pending: no lanes exist, so nothing closes; the floor is recorded.
        assert!(!lifecycle.close_session("s1", "p1"));
        assert_eq!(
            lifecycle.close_principal_sessions("p1", DispatchCloseReason::SessionDelete, Some(7)),
            0
        );
        assert!(lifecycle.active_lanes().is_empty());
        assert_eq!(
            lifecycle.close_lane_with_reason(
                "lane-1",
                1,
                DispatchCloseReason::SessionDelete,
                None,
                None
            ),
            HttpLaneCloseResult::NotFound
        );

        let recorder = Arc::new(FloorRecorder::default());
        lifecycle.attach(recorder.clone());
        assert_eq!(
            *recorder.floors.lock().unwrap(),
            vec![("p1".to_owned(), Some(7))],
            "the floor recorded while pending binds the lanes built afterwards"
        );
        // Open: calls forward.
        assert!(lifecycle.close_session("s1", "p1"));
        assert_eq!(
            lifecycle.close_principal_sessions("p2", DispatchCloseReason::SessionDelete, None),
            1
        );
        assert_eq!(recorder.floors.lock().unwrap().len(), 2);
    }
}
