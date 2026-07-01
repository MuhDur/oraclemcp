//! Thread-owned dispatch lanes for stateful Oracle work.
//!
//! N0a's production shape is deliberately a registry of **Send handles**, not a
//! registry of connections: callers hold a bounded mailbox sender and metadata,
//! while the lane thread owns the current-thread Asupersync runtime, reactor,
//! and concrete dispatcher. This matches Appendix A.1/A.8/A.10 of the 0.6.0
//! plan: non-`Send` dispatch futures are never spawned across OS threads, and
//! all stateful DB work is marshaled to the owning lane.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::channel::{
    mpsc::{self, SendError},
    oneshot,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::{CancelReason, Cx, Outcome, PanicPayload};
use oraclemcp_audit::{AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use parking_lot::Mutex;
use serde_json::Value;

use crate::admission::{AdmissionController, AdmissionPermit, DEFAULT_RETRY_AFTER_MS};
use crate::http::{HttpLaneBinding, HttpLaneSnapshot, HttpSessionLifecycle};
use crate::operator_protocol::operator_subject_id_hash;
use crate::server::{
    DispatchCloseReason, DispatchContext, DispatchFuture, DispatchOutcome, OwnedDispatchContext,
    ToolDispatch,
};

/// Default number of queued dispatch commands accepted by one lane.
pub const DEFAULT_LANE_MAILBOX_CAPACITY: usize = 64;

const STATUS_STARTING: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_QUARANTINED: u8 = 3;

/// Async factory that builds the concrete dispatcher on the lane's own runtime.
///
/// This is the N0 boundary that keeps the registry outside the Oracle session:
/// the registry owns Send lane handles, while the factory runs on the lane
/// thread and may construct reactor-affine DB/session state there.
pub type LaneDispatchFactory = dyn for<'a> Fn(
        &'a Cx,
        &'a LaneContext,
    )
        -> Pin<Box<dyn Future<Output = Result<Arc<dyn ToolDispatch>, ErrorEnvelope>> + 'a>>
    + Send
    + Sync
    + 'static;

/// The identity and immutable metadata for one stateful HTTP lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneContext {
    lane_id: String,
    mcp_session_id: String,
    principal_key: String,
    generation: u64,
}

impl LaneContext {
    /// Build a lane context from transport-resolved, server-derived values.
    #[must_use]
    pub fn new(
        lane_id: impl Into<String>,
        mcp_session_id: impl Into<String>,
        principal_key: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self {
            lane_id: lane_id.into(),
            mcp_session_id: mcp_session_id.into(),
            principal_key: principal_key.into(),
            generation,
        }
    }

    fn process_shared(lane_id: impl Into<String>) -> Self {
        Self::new(lane_id, "process", "process", 1)
    }

    /// Stable, non-secret lane id used in diagnostics.
    #[must_use]
    pub fn lane_id(&self) -> &str {
        &self.lane_id
    }

    /// MCP Streamable HTTP session id bound to this lane.
    #[must_use]
    pub fn mcp_session_id(&self) -> &str {
        &self.mcp_session_id
    }

    /// Server-derived, redacted principal key bound to this lane.
    #[must_use]
    pub fn principal_key(&self) -> &str {
        &self.principal_key
    }

    /// Monotonic lane generation. Later N3/C-4 work binds grants to this value.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LaneKey {
    mcp_session_id: String,
    principal_key: String,
}

impl LaneKey {
    fn new(mcp_session_id: &str, principal_key: &str) -> Self {
        Self {
            mcp_session_id: mcp_session_id.to_owned(),
            principal_key: principal_key.to_owned(),
        }
    }
}

/// Coarse lifecycle state of a lane handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneRuntimeStatus {
    Starting,
    Running,
    Stopped,
    Quarantined,
}

impl LaneRuntimeStatus {
    fn from_raw(raw: u8) -> Self {
        match raw {
            STATUS_RUNNING => Self::Running,
            STATUS_STOPPED => Self::Stopped,
            STATUS_QUARANTINED => Self::Quarantined,
            _ => Self::Starting,
        }
    }

    /// Stable lower-case label for operator diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Quarantined => "quarantined",
        }
    }
}

enum LaneCommand {
    Dispatch {
        context: OwnedDispatchContext,
        name: String,
        args: Value,
        reply: oneshot::Sender<DispatchOutcome>,
    },
    Close {
        reason: DispatchCloseReason,
    },
}

struct LaneRuntimeInner {
    name: String,
    generation: AtomicU64,
    status: Arc<AtomicU8>,
    sender: Mutex<Option<mpsc::Sender<LaneCommand>>>,
    join: Mutex<Option<JoinHandle<()>>>,
    _capacity_permit: Option<AdmissionPermit>,
}

impl Drop for LaneRuntimeInner {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.lock().take() {
            let _ = enqueue_close(&sender, DispatchCloseReason::RuntimeDrop);
        }
        if let Some(handle) = self.join.lock().take()
            && handle.thread().id() != thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

/// Sendable handle to one stateful dispatch lane.
///
/// The handle intentionally contains no connection or dispatcher state directly.
/// It is the capability a transport/registry may hold: bounded mailbox,
/// generation, lifecycle status, and the owned lane thread. Later N0/N3 work can
/// attach subject/session/grant metadata to this handle without letting HTTP
/// reach into the DB state.
#[derive(Clone)]
pub struct LaneRuntime {
    inner: Arc<LaneRuntimeInner>,
}

impl LaneRuntime {
    /// Spawn one dedicated OS-thread lane around a concrete dispatcher.
    #[must_use]
    pub fn spawn(
        name: impl Into<String>,
        dispatcher: Arc<dyn ToolDispatch>,
        mailbox_capacity: usize,
    ) -> Self {
        Self::spawn_with_panic_auditor(name, dispatcher, mailbox_capacity, None)
    }

    /// Spawn one dedicated OS-thread lane with a durable panic audit sink.
    #[must_use]
    pub fn spawn_with_panic_auditor(
        name: impl Into<String>,
        dispatcher: Arc<dyn ToolDispatch>,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        let lane_name = name.into();
        let shared_dispatcher = Arc::clone(&dispatcher);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
            let dispatcher = Arc::clone(&shared_dispatcher);
            Box::pin(async move { Ok(dispatcher) })
        });
        Self::spawn_with_dispatch_factory(
            lane_name.clone(),
            LaneContext::process_shared(lane_name),
            factory,
            mailbox_capacity,
            panic_auditor,
        )
    }

    /// Spawn one dedicated OS-thread lane that constructs its dispatcher on the
    /// lane runtime before handling the first command.
    #[must_use]
    pub fn spawn_with_dispatch_factory(
        name: impl Into<String>,
        lane_context: LaneContext,
        factory: Arc<LaneDispatchFactory>,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        Self::spawn_with_dispatch_factory_and_capacity(
            name,
            lane_context,
            factory,
            mailbox_capacity,
            panic_auditor,
            None,
        )
    }

    /// Spawn a lane while holding an admission permit for the lane lifetime.
    #[must_use]
    pub fn spawn_with_dispatch_factory_and_capacity(
        name: impl Into<String>,
        lane_context: LaneContext,
        factory: Arc<LaneDispatchFactory>,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
        capacity_permit: Option<AdmissionPermit>,
    ) -> Self {
        let name = name.into();
        let capacity = mailbox_capacity.max(1);
        let (sender, receiver) = mpsc::channel::<LaneCommand>(capacity);
        let status = Arc::new(AtomicU8::new(STATUS_STARTING));
        let thread_status = Arc::clone(&status);
        let thread_name = format!("oraclemcp-lane-{name}");
        let lane_name = name.clone();
        let join = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                run_lane_thread_with_factory(
                    lane_name,
                    lane_context,
                    receiver,
                    factory,
                    thread_status,
                    panic_auditor,
                );
            })
            .expect("dedicated Oracle MCP lane thread spawns");

        Self {
            inner: Arc::new(LaneRuntimeInner {
                name,
                generation: AtomicU64::new(1),
                status,
                sender: Mutex::new(Some(sender)),
                join: Mutex::new(Some(join)),
                _capacity_permit: capacity_permit,
            }),
        }
    }

    /// Spawn a lane using the release-train default mailbox capacity.
    #[must_use]
    pub fn spawn_default(name: impl Into<String>, dispatcher: Arc<dyn ToolDispatch>) -> Self {
        Self::spawn(name, dispatcher, DEFAULT_LANE_MAILBOX_CAPACITY)
    }

    /// Spawn a default-capacity lane with durable panic auditing.
    #[must_use]
    pub fn spawn_default_with_panic_auditor(
        name: impl Into<String>,
        dispatcher: Arc<dyn ToolDispatch>,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        Self::spawn_with_panic_auditor(
            name,
            dispatcher,
            DEFAULT_LANE_MAILBOX_CAPACITY,
            panic_auditor,
        )
    }

    /// The stable lane name used in diagnostics and future registry leases.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Current lane generation. N0a only publishes the primitive; C-4 wires
    /// profile/level changes to monotonic increments and grant invalidation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    /// Advance the lane generation after a profile, connection, or operating
    /// level transition. Grants bind to this value, so a stale grant minted
    /// before the transition cannot be consumed after it.
    pub fn bump_generation(&self) -> u64 {
        self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Current lifecycle status.
    #[must_use]
    pub fn status(&self) -> LaneRuntimeStatus {
        LaneRuntimeStatus::from_raw(self.inner.status.load(Ordering::Acquire))
    }

    fn sender(&self) -> Result<mpsc::Sender<LaneCommand>, ErrorEnvelope> {
        if self.status() == LaneRuntimeStatus::Quarantined {
            return Err(ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!("dispatch lane {} is quarantined after panic", self.name()),
            ));
        }
        let guard = self.inner.sender.lock();
        guard.as_ref().cloned().ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!("dispatch lane {} is stopped", self.name()),
            )
        })
    }

    /// Stop accepting new commands for this lane and join its thread once the
    /// current bounded mailbox drains. This is the N5 Streamable HTTP DELETE
    /// hook; full dirty-session rollback is owned by the lane dispatcher/lease
    /// layer, while this handle tears down the transport-facing lane resource.
    pub fn close(&self) {
        self.close_with_reason(DispatchCloseReason::SessionDelete);
    }

    /// Stop accepting new commands and ask the lane-owned dispatcher to clean
    /// up with the supplied lifecycle reason before the lane exits.
    pub fn close_with_reason(&self, reason: DispatchCloseReason) {
        let sender = self.inner.sender.lock().take();
        if let Some(sender) = sender {
            let _ = enqueue_close(&sender, reason);
        }
        if let Some(handle) = self.inner.join.lock().take()
            && handle.thread().id() != thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

impl ToolDispatch for LaneRuntime {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "dispatch lane send cancelled before admission",
                ));
            }
            let sender = match self.sender() {
                Ok(sender) => sender,
                Err(_) if self.status() == LaneRuntimeStatus::Quarantined => {
                    return Outcome::Panicked(lane_panic_payload(self.name()));
                }
                Err(err) => return Outcome::Err(err),
            };
            let (reply_tx, mut reply_rx) = oneshot::channel();
            let lane_generation = self.generation();
            let context = context.with_lane_identity(self.name(), lane_generation);
            let command = LaneCommand::Dispatch {
                context: context.to_owned_context(),
                name: name.to_owned(),
                args,
                reply: reply_tx,
            };
            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(error) => return lane_send_error_outcome(self.name(), error, cx),
            };
            if let Err(error) = permit.try_send(command) {
                return lane_send_error_outcome(self.name(), error, cx);
            }
            match reply_rx.recv(cx).await {
                Ok(outcome) => outcome,
                Err(oneshot::RecvError::Cancelled) => Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "dispatch lane receive cancelled before reply",
                )),
                Err(oneshot::RecvError::Closed) => {
                    Outcome::Panicked(lane_panic_payload(self.name()))
                }
                Err(_) => Outcome::Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    format!("dispatch lane {} stopped before replying", self.name()),
                )),
            }
        })
    }
}

/// Guard for stateful HTTP lane dispatch.
///
/// N0 makes the MCP session id part of the lane identity. Until the full
/// per-session lane registry lands, this wrapper is the fail-closed boundary:
/// stateful served dispatch cannot accidentally fall through to shared
/// dispatcher state unless HTTP resolved a session-bound [`DispatchContext`].
pub struct StatefulLaneDispatch {
    factory: Arc<LaneDispatchFactory>,
    panic_auditor: Option<Arc<Auditor>>,
    admission: Option<Arc<AdmissionController>>,
    mailbox_capacity: usize,
    next_lane_id: AtomicU64,
    lanes: Mutex<HashMap<LaneKey, LaneRuntime>>,
}

impl fmt::Debug for StatefulLaneDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulLaneDispatch")
            .field("mailbox_capacity", &self.mailbox_capacity)
            .field("admission", &self.admission.is_some())
            .field("lane_count", &self.lanes.lock().len())
            .finish_non_exhaustive()
    }
}

impl StatefulLaneDispatch {
    #[must_use]
    pub fn new(inner: Arc<dyn ToolDispatch>) -> Self {
        let shared = Arc::clone(&inner);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
            let inner = Arc::clone(&shared);
            Box::pin(async move { Ok(inner) })
        });
        Self::with_dispatch_factory(factory, None)
    }

    /// Build a stateful lane registry whose concrete dispatchers are created on
    /// each lane's own runtime.
    #[must_use]
    pub fn with_dispatch_factory(
        factory: Arc<LaneDispatchFactory>,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        Self {
            factory,
            panic_auditor,
            admission: None,
            mailbox_capacity: DEFAULT_LANE_MAILBOX_CAPACITY,
            next_lane_id: AtomicU64::new(1),
            lanes: Mutex::new(HashMap::new()),
        }
    }

    /// Install capacity admission for new lane allocation.
    #[must_use]
    pub fn with_admission_controller(mut self, admission: Arc<AdmissionController>) -> Self {
        self.admission = Some(admission);
        self
    }

    fn resolve_lane(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
    ) -> Result<LaneRuntime, ErrorEnvelope> {
        let session_id = context.http_session_id().ok_or_else(lease_required)?;
        let principal_key = context.principal_key().unwrap_or("anonymous-http");
        let key = LaneKey::new(session_id, principal_key);
        if let Some(lane) = self.lanes.lock().get(&key).cloned() {
            return Ok(lane);
        }

        let mut lanes = self.lanes.lock();
        if let Some(lane) = lanes.get(&key).cloned() {
            return Ok(lane);
        }
        let capacity_permit = self
            .admission
            .as_ref()
            .map(|admission| admission.try_admit_capacity(cx, principal_key, "stateful_lane"))
            .transpose()?;
        let lane_number = self.next_lane_id.fetch_add(1, Ordering::SeqCst);
        let lane_id = format!("http-lane-{lane_number}");
        let lane_context = LaneContext::new(
            lane_id.clone(),
            key.mcp_session_id.clone(),
            key.principal_key.clone(),
            1,
        );
        let lane = LaneRuntime::spawn_with_dispatch_factory_and_capacity(
            lane_id,
            lane_context,
            Arc::clone(&self.factory),
            self.mailbox_capacity,
            self.panic_auditor.clone(),
            capacity_permit,
        );
        lanes.insert(key, lane.clone());
        Ok(lane)
    }

    /// Close and forget the lane bound to one MCP session/principal pair.
    ///
    /// Returns `true` when a lane existed. New requests for the same pair must
    /// initialize a fresh MCP session because the HTTP session store is removed
    /// by the caller before this is invoked.
    pub fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
        let lane = self
            .lanes
            .lock()
            .remove(&LaneKey::new(session_id, principal_key));
        if let Some(lane) = lane {
            lane.close();
            true
        } else {
            false
        }
    }

    /// Close every registered lane and return how many were present.
    pub fn close_all_sessions(&self) -> usize {
        let lanes: Vec<LaneRuntime> = self.lanes.lock().drain().map(|(_, lane)| lane).collect();
        let count = lanes.len();
        for lane in lanes {
            lane.close_with_reason(DispatchCloseReason::ServerShutdown);
        }
        count
    }

    #[cfg(test)]
    fn lane_count(&self) -> usize {
        self.lanes.lock().len()
    }
}

impl HttpSessionLifecycle for StatefulLaneDispatch {
    fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
        StatefulLaneDispatch::close_session(self, session_id, principal_key)
    }

    fn close_session_with_reason(
        &self,
        session_id: &str,
        principal_key: &str,
        reason: DispatchCloseReason,
    ) -> bool {
        let lane = self
            .lanes
            .lock()
            .remove(&LaneKey::new(session_id, principal_key));
        if let Some(lane) = lane {
            lane.close_with_reason(reason);
            true
        } else {
            false
        }
    }

    fn close_all_sessions(&self) {
        let _ = StatefulLaneDispatch::close_all_sessions(self);
    }

    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        self.lanes
            .lock()
            .iter()
            .map(|(key, lane)| HttpLaneSnapshot {
                lane_id: lane.name().to_owned(),
                generation: lane.generation(),
                status: lane.status().as_str(),
                subject_id_hash: operator_subject_id_hash(&key.principal_key),
            })
            .collect()
    }

    fn lane_binding(&self, lane_id: &str) -> Option<HttpLaneBinding> {
        self.lanes.lock().iter().find_map(|(key, lane)| {
            (lane.name() == lane_id).then(|| HttpLaneBinding {
                lane_id: lane.name().to_owned(),
                mcp_session_id: key.mcp_session_id.clone(),
                principal_key: key.principal_key.clone(),
                generation: lane.generation(),
            })
        })
    }
}

impl ToolDispatch for StatefulLaneDispatch {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let lane = self.resolve_lane(cx, context)?;
            lane.dispatch(cx, context, name, args).await
        })
    }
}

fn lease_required() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::LeaseRequired,
        "stateful HTTP dispatch requires an MCP-session-bound lane context",
    )
    .with_next_step("initialize the Streamable HTTP session before calling tools")
}

fn lane_send_error<T>(name: &str, error: SendError<T>) -> ErrorEnvelope {
    match error {
        SendError::Full(_) => ErrorEnvelope::new(
            ErrorClass::Busy,
            format!("dispatch lane {name} mailbox is full"),
        )
        .with_retry_after_ms(DEFAULT_RETRY_AFTER_MS)
        .with_next_step("Retry after retry_after_ms, or open/use another lane when available."),
        SendError::Disconnected(_) => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            format!("dispatch lane {name} is unavailable"),
        ),
        SendError::Cancelled(_) => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            format!("dispatch lane {name} send was cancelled before admission"),
        ),
    }
}

fn lane_send_error_outcome<T>(name: &str, error: SendError<T>, cx: &Cx) -> DispatchOutcome {
    match error {
        SendError::Cancelled(_) => Outcome::Cancelled(cancel_reason_from_cx(
            cx,
            "dispatch lane send cancelled before admission",
        )),
        other => Outcome::Err(lane_send_error(name, other)),
    }
}

fn cancel_reason_from_cx(cx: &Cx, fallback: &'static str) -> CancelReason {
    cx.cancel_reason()
        .unwrap_or_else(|| CancelReason::user(fallback))
}

fn lane_panic_payload(name: &str) -> PanicPayload {
    PanicPayload::new(format!("dispatch lane {name} panicked before replying"))
}

fn enqueue_close(
    sender: &mpsc::Sender<LaneCommand>,
    reason: DispatchCloseReason,
) -> Result<(), SendError<LaneCommand>> {
    let command = LaneCommand::Close { reason };
    match sender.try_send(command) {
        Ok(()) => Ok(()),
        Err(SendError::Full(command)) => block_on_lane_bridge(async {
            let Some(cx) = Cx::current() else {
                return Err(SendError::Cancelled(command));
            };
            sender.send(&cx, command).await
        }),
        Err(err) => Err(err),
    }
}

fn run_lane_thread_with_factory(
    name: String,
    lane_context: LaneContext,
    receiver: mpsc::Receiver<LaneCommand>,
    factory: Arc<LaneDispatchFactory>,
    status: Arc<AtomicU8>,
    panic_auditor: Option<Arc<Auditor>>,
) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("Asupersync native reactor builds for lane dispatch");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("Asupersync current-thread runtime builds for lane dispatch");
        status.store(STATUS_RUNNING, Ordering::Release);
        // block-on-boundary: sanctioned lane runtime on a dedicated OS thread.
        runtime.block_on(run_lane_loop_with_factory(receiver, lane_context, factory));
    }));
    match outcome {
        Ok(()) => status.store(STATUS_STOPPED, Ordering::Release),
        Err(_) => {
            audit_lane_panic(&name, panic_auditor.as_deref());
            tracing::error!(
                lane = %name,
                audit_event = "lane_panic_unknown_discarded",
                outcome = "unknown_discarded",
                "oraclemcp lane panicked; quarantined lane and discarded unknown in-flight DB state"
            );
            status.store(STATUS_QUARANTINED, Ordering::Release);
        }
    }
}

fn audit_lane_panic(name: &str, auditor: Option<&Auditor>) {
    let Some(auditor) = auditor else {
        return;
    };
    let draft = AuditEntryDraft {
        subject: AuditSubject::new("lane", name),
        db_evidence: None,
        cancel: None,
        tool: "lane_runtime".to_owned(),
        sql: "LANE_PANIC_UNKNOWN_DISCARDED".to_owned(),
        danger_level: "UNKNOWN".to_owned(),
        decision: AuditDecision::Blocked,
        rows_affected: None,
        outcome: AuditOutcome::UnknownDiscarded,
    };
    if let Err(err) = auditor.append(&draft, audit_timestamp(), true) {
        tracing::error!(
            lane = %name,
            error = %err,
            "failed to append durable lane panic audit record"
        );
    }
}

fn audit_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

// SAFETY: This is the sanctioned N0a block_on boundary. It is entered only by
// `run_lane_thread_with_factory`, where `Runtime::block_on` is the outermost
// operation on a dedicated OS thread. The concrete dispatcher and its Oracle
// connection are constructed inside that thread; callers interact through
// bounded `mpsc` commands and oneshot replies carrying owned, Send values.
async fn run_lane_loop_with_factory(
    mut receiver: mpsc::Receiver<LaneCommand>,
    lane_context: LaneContext,
    factory: Arc<LaneDispatchFactory>,
) {
    let Some(cx) = Cx::current() else {
        return;
    };
    let mut dispatcher: Option<Arc<dyn ToolDispatch>> = None;

    while let Ok(command) = receiver.recv(&cx).await {
        match command {
            LaneCommand::Dispatch {
                context,
                name,
                args,
                reply,
            } => {
                if dispatcher.is_none() {
                    match factory(&cx, &lane_context).await {
                        Ok(created) => dispatcher = Some(created),
                        Err(err) => {
                            let _ = reply.send_blocking(Outcome::Err(err));
                            continue;
                        }
                    }
                }
                let borrowed_context = context.as_dispatch_context();
                let result = dispatcher
                    .as_ref()
                    .expect("dispatcher initialized above")
                    .dispatch(&cx, borrowed_context, name.as_str(), args)
                    .await;
                let _ = reply.send_blocking(result);
            }
            LaneCommand::Close { reason } => {
                if let Some(dispatcher) = dispatcher.as_ref()
                    && let Err(err) = dispatcher.close(&cx, reason).await
                {
                    tracing::warn!(
                        lane = %lane_context.lane_id(),
                        close_reason = reason.as_str(),
                        error_class = ?err.error_class,
                        error = %err.message,
                        "stateful lane dispatcher cleanup returned an error"
                    );
                }
                break;
            }
        }
    }
}

/// Synchronous bridge for native blocking transports and tests. This creates no
/// shared dispatcher runtime; it only installs a request `Cx` so the caller can
/// send work to a lane and await the owned reply.
pub fn block_on_lane_bridge<F>(future: F) -> F::Output
where
    F: Future,
{
    let reactor = asupersync::runtime::reactor::create_reactor()
        .expect("Asupersync native reactor builds for lane bridge");
    RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("Asupersync current-thread runtime builds for lane bridge")
        // block-on-boundary: synchronous transport/test bridge into a lane future.
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc as std_mpsc;
    use std::time::{Duration, Instant};

    use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};
    use serde_json::json;

    use super::*;

    struct SharedAuditSink(Arc<MemoryAuditSink>);

    impl AuditSink for SharedAuditSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    struct BlockingDispatch {
        entered: std_mpsc::Sender<thread::ThreadId>,
        release: Mutex<std_mpsc::Receiver<()>>,
    }

    impl ToolDispatch for BlockingDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                let lane_thread = thread::current().id();
                self.entered
                    .send(lane_thread)
                    .expect("test coordinator waits for lane entry");
                self.release
                    .lock()
                    .recv()
                    .expect("test coordinator releases blocked lane");
                Outcome::Ok(json!({ "lane_thread": format!("{lane_thread:?}") }))
            })
        }
    }

    struct EchoThreadDispatch;

    impl ToolDispatch for EchoThreadDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                let lane_thread = thread::current().id();
                Outcome::Ok(json!({ "lane_thread": format!("{lane_thread:?}") }))
            })
        }
    }

    struct CloseRecordingDispatch {
        close_reasons: Arc<Mutex<Vec<DispatchCloseReason>>>,
    }

    impl ToolDispatch for CloseRecordingDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                let lane_thread = thread::current().id();
                Outcome::Ok(json!({ "lane_thread": format!("{lane_thread:?}") }))
            })
        }

        fn close<'a>(
            &'a self,
            _cx: &'a Cx,
            reason: DispatchCloseReason,
        ) -> crate::server::DispatchCloseFuture<'a> {
            Box::pin(async move {
                self.close_reasons.lock().push(reason);
                Ok(())
            })
        }
    }

    struct NotifyDispatch {
        entered: std_mpsc::Sender<()>,
    }

    impl ToolDispatch for NotifyDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                self.entered
                    .send(())
                    .expect("test observes unexpected lane entry");
                Outcome::Ok(json!({ "entered": true }))
            })
        }
    }

    struct ContextEchoDispatch;

    impl ToolDispatch for ContextEchoDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                let lane_thread = thread::current().id();
                Outcome::Ok(json!({
                    "lane_thread": format!("{lane_thread:?}"),
                    "session_id": context.http_session_id(),
                    "principal_key": context.principal_key(),
                }))
            })
        }
    }

    struct PanicDispatch;

    impl ToolDispatch for PanicDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move { panic!("intentional lane panic for CX-I7") })
        }
    }

    fn wait_for_quarantine(lane: &LaneRuntime) {
        for _ in 0..50 {
            if lane.status() == LaneRuntimeStatus::Quarantined {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("lane did not enter Quarantined status");
    }

    fn queued_lane_commands(lane: &LaneRuntime) -> usize {
        lane.inner
            .sender
            .lock()
            .as_ref()
            .map(|sender| sender.telemetry_snapshot(1).queued_messages)
            .unwrap_or(0)
    }

    fn wait_for_queued_lane_command(lane: &LaneRuntime) {
        for _ in 0..50 {
            if queued_lane_commands(lane) == 1 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("lane mailbox did not fill");
    }

    #[test]
    fn blocked_lane_does_not_block_another_lane() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let blocked = LaneRuntime::spawn(
            "blocked-test",
            Arc::new(BlockingDispatch {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            4,
        );
        let fast = LaneRuntime::spawn("fast-test", Arc::new(EchoThreadDispatch), 4);

        let blocked_call = {
            let blocked = blocked.clone();
            thread::spawn(move || {
                block_on_lane_bridge(async move {
                    let cx = Cx::current().expect("bridge installs Cx");
                    blocked
                        .dispatch(&cx, DispatchContext::default(), "block", Value::Null)
                        .await
                        .expect("blocked lane eventually replies")
                })
            })
        };

        let blocked_thread = entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("blocked lane reached dispatch body");
        let fast_result = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            fast.dispatch(&cx, DispatchContext::default(), "fast", Value::Null)
                .await
                .expect("independent lane replies while another lane is blocked")
        });

        let fast_thread = fast_result
            .get("lane_thread")
            .and_then(Value::as_str)
            .expect("fast lane reports thread id")
            .to_owned();
        assert_ne!(fast_thread, format!("{blocked_thread:?}"));

        release_tx.send(()).expect("release blocked lane");
        let blocked_result = blocked_call.join().expect("blocked caller joined");
        assert_eq!(
            blocked_result
                .get("lane_thread")
                .and_then(Value::as_str)
                .expect("blocked lane reports thread id"),
            format!("{blocked_thread:?}")
        );
    }

    #[test]
    fn full_lane_mailbox_returns_busy_without_waiting() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "backpressure-test",
            Arc::new(BlockingDispatch {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            1,
        );

        let first_call = {
            let lane = lane.clone();
            thread::spawn(move || {
                block_on_lane_bridge(async move {
                    let cx = Cx::current().expect("bridge installs Cx");
                    lane.dispatch(&cx, DispatchContext::default(), "first", Value::Null)
                        .await
                        .expect("first blocked call eventually replies")
                })
            })
        };
        let _first_thread = entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first call reached the lane");

        let second_call = {
            let lane = lane.clone();
            thread::spawn(move || {
                block_on_lane_bridge(async move {
                    let cx = Cx::current().expect("bridge installs Cx");
                    lane.dispatch(&cx, DispatchContext::default(), "second", Value::Null)
                        .await
                        .expect("queued second call eventually replies")
                })
            })
        };
        wait_for_queued_lane_command(&lane);

        let err = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            lane.dispatch(&cx, DispatchContext::default(), "third", Value::Null)
                .await
                .expect_err("full mailbox returns structured backpressure")
        });
        assert_eq!(err.error_class, ErrorClass::Busy);
        assert_eq!(err.retry_after_ms, Some(DEFAULT_RETRY_AFTER_MS));
        assert!(
            err.message.contains("mailbox is full"),
            "lane saturation error is specific enough to translate to HTTP 429: {err:?}"
        );
        assert_eq!(
            queued_lane_commands(&lane),
            1,
            "rejected dispatch must not enqueue an extra command"
        );

        release_tx.send(()).expect("release first call");
        let _second_thread = entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second queued call reached the lane");
        release_tx.send(()).expect("release second call");
        first_call.join().expect("first caller joined");
        second_call.join().expect("second caller joined");
    }

    #[test]
    fn idle_lane_mailbox_wakes_for_cross_thread_close() {
        let close_reasons = Arc::new(Mutex::new(Vec::new()));
        let lane = LaneRuntime::spawn(
            "idle-close-wake",
            Arc::new(CloseRecordingDispatch {
                close_reasons: Arc::clone(&close_reasons),
            }),
            4,
        );

        let initialized = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            lane.dispatch(&cx, DispatchContext::default(), "init", Value::Null)
                .await
                .expect("lane initializes and replies")
        });
        assert!(initialized.get("lane_thread").is_some());

        let lane_for_close = lane.clone();
        let (closed_tx, closed_rx) = std_mpsc::channel();
        thread::spawn(move || {
            let started = Instant::now();
            lane_for_close.close_with_reason(DispatchCloseReason::ServerShutdown);
            closed_tx
                .send(started.elapsed())
                .expect("test waits for close completion");
        });

        let elapsed = closed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("cross-thread close wakes the idle lane mailbox");
        assert!(
            elapsed < Duration::from_secs(5),
            "idle lane close should not wait for an external timeout"
        );
        assert_eq!(lane.status(), LaneRuntimeStatus::Stopped);
        assert_eq!(
            close_reasons.lock().as_slice(),
            &[DispatchCloseReason::ServerShutdown]
        );
    }

    #[test]
    fn cancelled_lane_dispatch_never_enqueues_command() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "cancel-before-admit-test",
            Arc::new(NotifyDispatch {
                entered: entered_tx,
            }),
            1,
        );

        let outcome = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            cx.set_cancel_requested(true);
            lane.dispatch(&cx, DispatchContext::default(), "cancelled", Value::Null)
                .await
        });

        assert!(
            matches!(outcome, Outcome::Cancelled(_)),
            "pre-cancelled request is preserved as Outcome::Cancelled"
        );
        assert!(
            entered_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "cancelled caller must not enqueue work onto the lane"
        );
    }

    #[test]
    fn stateful_lane_dispatch_requires_session_bound_context() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let guarded = StatefulLaneDispatch::new(Arc::new(NotifyDispatch {
            entered: entered_tx,
        }));

        let err = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            guarded
                .dispatch(&cx, DispatchContext::default(), "stateful", Value::Null)
                .await
                .expect_err("stateful dispatch without session id is refused")
        });
        assert_eq!(err.error_class, ErrorClass::LeaseRequired);
        assert_eq!(
            guarded.lane_count(),
            0,
            "missing session id must not allocate a lane"
        );
        assert!(
            entered_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "missing session id must fail before entering the lane dispatcher"
        );

        let result = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            guarded
                .dispatch(
                    &cx,
                    DispatchContext::default().with_http_session_id("session-1"),
                    "stateful",
                    Value::Null,
                )
                .await
                .expect("session-bound context reaches inner dispatcher")
        });
        assert_eq!(result, json!({ "entered": true }));
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("session-bound call entered the inner dispatcher");
        assert_eq!(guarded.lane_count(), 1);
    }

    #[test]
    fn stateful_lane_dispatch_keys_lanes_by_session_and_principal() {
        fn call(registry: &StatefulLaneDispatch, session: &str, principal: &str) -> Value {
            block_on_lane_bridge(async {
                let cx = Cx::current().expect("bridge installs Cx");
                registry
                    .dispatch(
                        &cx,
                        DispatchContext::default()
                            .with_http_session_id(session)
                            .with_principal_key(principal),
                        "stateful",
                        Value::Null,
                    )
                    .await
                    .expect("stateful registry dispatch succeeds")
            })
        }

        let registry = StatefulLaneDispatch::new(Arc::new(ContextEchoDispatch));

        let a1 = call(&registry, "session-a", "principal-a");
        let a2 = call(&registry, "session-a", "principal-a");
        let b = call(&registry, "session-b", "principal-a");
        let c = call(&registry, "session-a", "principal-b");

        let thread = |value: &Value| {
            value
                .get("lane_thread")
                .and_then(Value::as_str)
                .expect("lane thread recorded")
                .to_owned()
        };
        assert_eq!(thread(&a1), thread(&a2), "same key reuses its lane");
        assert_ne!(thread(&a1), thread(&b), "different session gets a lane");
        assert_ne!(thread(&a1), thread(&c), "different principal gets a lane");
        assert_eq!(registry.lane_count(), 3);
    }

    #[test]
    fn stateful_lane_capacity_refuses_before_factory_opens_connection() {
        let factory_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_runs = Arc::clone(&factory_runs);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
            counted_runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok(Arc::new(EchoThreadDispatch) as Arc<dyn ToolDispatch>) })
        });
        let registry = StatefulLaneDispatch::with_dispatch_factory(factory, None)
            .with_admission_controller(Arc::new(AdmissionController::with_reserved(2, 10, 1, 0)));

        let first = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            registry
                .dispatch(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("session-a")
                        .with_principal_key("principal-a"),
                    "stateful",
                    Value::Null,
                )
                .await
                .expect("first lane admits")
        });
        assert!(first.get("lane_thread").is_some());
        assert_eq!(factory_runs.load(std::sync::atomic::Ordering::SeqCst), 1);

        let err = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            registry
                .dispatch(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("session-b")
                        .with_principal_key("principal-b"),
                    "stateful",
                    Value::Null,
                )
                .await
                .expect_err("regular stateful lane capacity is exhausted")
        });
        assert_eq!(err.error_class, ErrorClass::AtCapacity);
        assert_eq!(err.retry_after_ms, Some(DEFAULT_RETRY_AFTER_MS));
        assert!(
            err.message.contains("\"operator_reserved\":1"),
            "capacity snapshot should report reserved operator slot: {err:?}"
        );
        assert!(
            !err.message.contains("principal-b"),
            "capacity snapshot must not echo raw principal keys"
        );
        assert_eq!(
            factory_runs.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "capacity rejection must happen before the lane factory can open a connection"
        );
        assert_eq!(registry.lane_count(), 1);
    }

    #[test]
    fn stateful_lane_close_session_releases_capacity_for_new_lane() {
        let factory_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_runs = Arc::clone(&factory_runs);
        let close_reasons = Arc::new(Mutex::new(Vec::new()));
        let recorded_reasons = Arc::clone(&close_reasons);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
            counted_runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let close_reasons = Arc::clone(&recorded_reasons);
            Box::pin(async move {
                Ok(Arc::new(CloseRecordingDispatch { close_reasons }) as Arc<dyn ToolDispatch>)
            })
        });
        let admission = Arc::new(AdmissionController::with_reserved(2, 10, 1, 0));
        let registry = StatefulLaneDispatch::with_dispatch_factory(factory, None)
            .with_admission_controller(Arc::clone(&admission));

        let first = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            registry
                .dispatch(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("session-a")
                        .with_principal_key("principal-a"),
                    "stateful",
                    Value::Null,
                )
                .await
                .expect("first lane admits")
        });
        assert!(first.get("lane_thread").is_some());
        assert_eq!(registry.lane_count(), 1);
        assert_eq!(admission.available_global(), 0);

        assert!(
            registry.close_session("session-a", "principal-a"),
            "existing lane should close"
        );
        assert_eq!(
            close_reasons.lock().as_slice(),
            &[DispatchCloseReason::SessionDelete]
        );
        assert_eq!(registry.lane_count(), 0);
        assert_eq!(
            admission.available_global(),
            admission.regular_global_cap(),
            "closing the session drops the lane's capacity permit"
        );

        let second = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            registry
                .dispatch(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("session-b")
                        .with_principal_key("principal-b"),
                    "stateful",
                    Value::Null,
                )
                .await
                .expect("capacity is available for a fresh lane after close")
        });
        assert!(second.get("lane_thread").is_some());
        assert_eq!(registry.lane_count(), 1);
        assert_eq!(factory_runs.load(std::sync::atomic::Ordering::SeqCst), 2);

        assert_eq!(registry.close_all_sessions(), 1);
        assert_eq!(
            close_reasons.lock().as_slice(),
            &[
                DispatchCloseReason::SessionDelete,
                DispatchCloseReason::ServerShutdown,
            ]
        );
        assert_eq!(registry.lane_count(), 0);
        assert_eq!(admission.available_global(), admission.regular_global_cap());
    }

    #[test]
    fn lane_generation_is_monotonic_and_observable() {
        let lane = LaneRuntime::spawn("generation-test", Arc::new(EchoThreadDispatch), 4);

        assert_eq!(lane.generation(), 1);
        assert_eq!(lane.bump_generation(), 2);
        assert_eq!(lane.generation(), 2);
        assert_eq!(lane.bump_generation(), 3);
        assert_eq!(lane.generation(), 3);
    }

    #[test]
    fn lane_panic_is_quarantined_audited_and_sibling_lane_survives() {
        let memory_sink = Arc::new(MemoryAuditSink::new());
        let auditor = Arc::new(Auditor::new(
            Box::new(SharedAuditSink(Arc::clone(&memory_sink))),
            SigningKey::new("test-key", b"test-secret-for-lane-panic".to_vec()),
        ));
        let panicking = LaneRuntime::spawn_default_with_panic_auditor(
            "panic-test",
            Arc::new(PanicDispatch),
            Some(auditor),
        );
        let sibling = LaneRuntime::spawn("panic-sibling", Arc::new(EchoThreadDispatch), 4);

        let outcome = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            panicking
                .dispatch(&cx, DispatchContext::default(), "panic", Value::Null)
                .await
        });
        assert!(
            matches!(outcome, Outcome::Panicked(_)),
            "panicked lane returns Outcome::Panicked to caller"
        );
        wait_for_quarantine(&panicking);

        let records = memory_sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(memory_sink.flush_count(), 1);
        assert_eq!(records[0].agent_identity, "lane:panic-test");
        assert_eq!(records[0].subject, AuditSubject::new("lane", "panic-test"));
        assert_eq!(records[0].tool, "lane_runtime");
        assert_eq!(records[0].sql_preview, "LANE_PANIC_UNKNOWN_DISCARDED");
        assert_eq!(records[0].outcome, AuditOutcome::UnknownDiscarded);

        let sibling_result = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            sibling
                .dispatch(&cx, DispatchContext::default(), "sibling", Value::Null)
                .await
                .expect("sibling lane keeps serving after another lane panics")
        });
        assert!(
            sibling_result
                .get("lane_thread")
                .and_then(Value::as_str)
                .is_some(),
            "sibling lane returned its thread id"
        );

        let quarantined_outcome = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            panicking
                .dispatch(&cx, DispatchContext::default(), "again", Value::Null)
                .await
        });
        assert!(
            matches!(quarantined_outcome, Outcome::Panicked(_)),
            "quarantined lane refuses later dispatch as Outcome::Panicked"
        );
    }
}
