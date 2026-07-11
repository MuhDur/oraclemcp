//! Thread-owned dispatch lanes for stateful Oracle work.
//!
//! N0a's production shape is deliberately a registry of **Send handles**, not a
//! registry of connections: callers hold a bounded mailbox sender and metadata,
//! while the lane thread owns the current-thread Asupersync runtime, reactor,
//! and concrete dispatcher. This matches Appendix A.1/A.8/A.10 of the 0.6.0
//! plan: non-`Send` dispatch futures are never spawned across OS threads, and
//! all stateful DB work is marshaled to the owning lane.

#[cfg(debug_assertions)]
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::channel::{
    mpsc::{self, SendError},
    oneshot,
};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::sync::OnceCell;
use asupersync::{Budget, CancelReason, Cx, Outcome, PanicPayload, Time};
use oraclemcp_audit::{AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use parking_lot::{Condvar, Mutex};
use serde_json::Value;

use crate::admission::{
    AdmissionController, AdmissionPermit, CapacitySnapshot, DEFAULT_FAIR_ADMISSION_WAIT_MS,
    DEFAULT_RETRY_AFTER_MS,
};
use crate::capability::narrow_to_lane;
use crate::http::{HttpLaneBinding, HttpLaneSnapshot, HttpSessionLifecycle};
use crate::operator_protocol::operator_subject_id_hash;
use crate::request_budget::{DEFAULT_REQUEST_POLL_QUOTA, DEFAULT_REQUEST_TIMEOUT, RequestBudget};
use crate::server::{
    DispatchCloseReason, DispatchContext, DispatchFuture, DispatchOutcome, DispatchReplyReceiver,
    DispatchStreamStartFuture, McpSurfaceDetail, McpSurfaceFuture, McpSurfaceOutcome,
    OwnedDispatchContext, TerminalReplyWaitError, ToolDispatch, ToolStreamSender,
    recv_terminal_after_cancel,
};

/// Default number of queued dispatch commands accepted by one lane.
pub const DEFAULT_LANE_MAILBOX_CAPACITY: usize = 64;

const MAX_TOOL_TIMEOUT_SECONDS: u64 = 3_600;

const STATUS_STARTING: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_QUARANTINED: u8 = 3;

// DL-4 canonical lock rank for the served lane path:
// Config watch snapshot/read -> lifecycle generation -> lane registry -> lane handle/status ->
// lease state -> grants -> audit-chain writer -> metadata cache.
//
// The high-risk AB-BA edge is Registry -> Lane mailbox. The registry may copy
// or insert `LaneRuntime` handles, but it must not dispatch, surface-state, or
// close a lane while the registry guard is held. The debug rank below makes
// that edge executable in tests.
#[cfg(debug_assertions)]
thread_local! {
    static LANE_REGISTRY_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

#[cfg(debug_assertions)]
fn enter_lane_registry_lock() {
    LANE_REGISTRY_LOCK_DEPTH.with(|depth| depth.set(depth.get() + 1));
}

#[cfg(debug_assertions)]
fn exit_lane_registry_lock() {
    LANE_REGISTRY_LOCK_DEPTH.with(|depth| {
        let current = depth.get();
        debug_assert!(current > 0, "lane registry lock depth underflow");
        depth.set(current.saturating_sub(1));
    });
}

#[cfg(debug_assertions)]
fn lane_registry_lock_held() -> bool {
    LANE_REGISTRY_LOCK_DEPTH.with(|depth| depth.get() > 0)
}

#[cfg(debug_assertions)]
fn assert_no_lane_registry_lock(operation: &str) {
    debug_assert!(
        !lane_registry_lock_held(),
        "{operation} while holding the lane registry lock violates DL-4"
    );
}

#[cfg(not(debug_assertions))]
fn assert_no_lane_registry_lock(_operation: &str) {}

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

/// A generation-bound lazy dispatcher factory plus the exact whole-request
/// ceiling from the same policy snapshot.
pub struct PreparedLaneDispatch {
    factory: Arc<LaneDispatchFactory>,
    request_timeout: Duration,
}

impl PreparedLaneDispatch {
    /// Bind a lazy factory to the request timeout from the same immutable
    /// profile generation it will open.
    #[must_use]
    pub fn new(factory: Arc<LaneDispatchFactory>, request_timeout: Duration) -> Self {
        Self {
            factory,
            request_timeout,
        }
    }

    /// Consume the atomic preparation into its factory and matching timeout.
    #[must_use]
    pub fn into_parts(self) -> (Arc<LaneDispatchFactory>, Duration) {
        (self.factory, self.request_timeout)
    }
}

/// Prepares one new stateful lane outside the lane-registry lock. Production
/// builders atomically reserve the profile generation and return its timeout
/// together with a factory that consumes that exact reservation.
pub type LaneDispatchFactoryBuilder =
    dyn Fn(&LaneContext) -> Result<PreparedLaneDispatch, ErrorEnvelope> + Send + Sync + 'static;

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
        caller: Arc<LaneCallerSignal>,
        enqueued_at: Instant,
        context: OwnedDispatchContext,
        name: String,
        args: Value,
        reply: oneshot::Sender<DispatchOutcome>,
    },
    DispatchStream {
        caller: Arc<LaneCallerSignal>,
        enqueued_at: Instant,
        context: OwnedDispatchContext,
        name: String,
        args: Value,
        frames: ToolStreamSender,
        reply: oneshot::Sender<DispatchOutcome>,
    },
    SurfaceState {
        caller: Arc<LaneCallerSignal>,
        enqueued_at: Instant,
        context: OwnedDispatchContext,
        detail: McpSurfaceDetail,
        reply: oneshot::Sender<McpSurfaceOutcome>,
    },
}

/// Cross-task cancellation edge for one lane command.
///
/// A caller Cx must never become the lane dispatch Cx: the lane always creates
/// a fresh owner-local Cx for factory and database effects. This bridge retains
/// one cheap Cx clone solely as a read-only cancellation witness; Asupersync's
/// Cx contract explicitly makes cancellation visible across clones. That lets
/// a still-queued command observe cancellation even when the caller task was
/// woken but has not yet been scheduled to publish the same reason below.
struct LaneCallerSignal {
    source_cx: Cx,
    cancelled: AtomicBool,
    reason: Mutex<Option<CancelReason>>,
    lane_waker: Mutex<Option<Waker>>,
    budget: LaneCallerBudget,
}

/// Caller budget expressed without an absolute runtime-local timestamp.
///
/// `Time` is process-shared in production but virtual/runtime-local in labs.
/// Carrying the raw caller deadline into another runtime would therefore be a
/// clock-domain bug. Store remaining time at admission and rebase it onto the
/// lane clock after subtracting mailbox wait.
#[derive(Clone, Copy)]
struct LaneCallerBudget {
    deadline_after_admission: Option<std::time::Duration>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
}

impl LaneCallerBudget {
    fn capture(cx: &Cx) -> Self {
        let budget = cx.budget();
        Self {
            deadline_after_admission: budget
                .deadline
                .map(|deadline| std::time::Duration::from_nanos(deadline.duration_since(cx.now()))),
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }

    fn rebase(self, lane_now: Time, queue_wait: std::time::Duration) -> Budget {
        Budget {
            deadline: self
                .deadline_after_admission
                .map(|remaining| lane_now + remaining.saturating_sub(queue_wait)),
            poll_quota: self.poll_quota,
            cost_quota: self.cost_quota,
            priority: self.priority,
        }
    }
}

fn tool_request_timeout_ceiling(profile_ceiling: Duration, args: &Value) -> Duration {
    args.get("timeout_seconds")
        .and_then(Value::as_u64)
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Duration::from_secs(seconds.min(MAX_TOOL_TIMEOUT_SECONDS)))
        .map_or(profile_ceiling, |tool_ceiling| {
            profile_ceiling.min(tool_ceiling)
        })
}

impl LaneCallerSignal {
    fn new(cx: &Cx) -> Self {
        Self {
            source_cx: cx.clone(),
            cancelled: AtomicBool::new(false),
            reason: Mutex::new(None),
            lane_waker: Mutex::new(None),
            budget: LaneCallerBudget::capture(cx),
        }
    }

    fn budget_for_lane(&self, lane_now: Time, queue_wait: std::time::Duration) -> Budget {
        self.budget.rebase(lane_now, queue_wait)
    }

    fn cancel(&self, reason: CancelReason) {
        if !self.cancelled.load(Ordering::Acquire) {
            let mut stored = self.reason.lock();
            if stored.is_none() {
                *stored = Some(reason);
            }
            self.cancelled.store(true, Ordering::Release);
        }
        if let Some(waker) = self.lane_waker.lock().take() {
            waker.wake();
        }
    }

    fn reason(&self) -> Option<CancelReason> {
        if !self.cancelled.load(Ordering::Acquire) && self.source_cx.is_cancel_requested() {
            let reason = self.source_cx.cancel_reason().unwrap_or_else(|| {
                CancelReason::user("dispatch caller cancellation requested before lane execution")
            });
            self.cancel(reason);
        }
        if self.cancelled.load(Ordering::Acquire) {
            self.reason.lock().clone()
        } else {
            None
        }
    }

    fn register_lane_waker(&self, waker: &Waker) {
        if self.cancelled.load(Ordering::Acquire) {
            waker.wake_by_ref();
            return;
        }
        let mut slot = self.lane_waker.lock();
        if !slot
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
        drop(slot);
        if self.cancelled.load(Ordering::Acquire)
            && let Some(waker) = self.lane_waker.lock().take()
        {
            waker.wake();
        }
    }
}

struct LaneCallerGuard {
    signal: Arc<LaneCallerSignal>,
    armed: bool,
}

impl LaneCallerGuard {
    fn new(signal: Arc<LaneCallerSignal>) -> Self {
        Self {
            signal,
            armed: true,
        }
    }

    fn complete(mut self) {
        self.armed = false;
    }

    fn signal_cancel(&self, reason: CancelReason) {
        self.signal.cancel(reason);
    }
}

impl Drop for LaneCallerGuard {
    fn drop(&mut self) {
        if self.armed {
            self.signal.cancel(CancelReason::user(
                "dispatch caller dropped before lane reply",
            ));
        }
    }
}

struct LaneCloseState {
    requested: AtomicBool,
    reason: Mutex<Option<DispatchCloseReason>>,
}

impl LaneCloseState {
    fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            reason: Mutex::new(None),
        }
    }

    fn request(&self, reason: DispatchCloseReason) {
        if self.requested.load(Ordering::Acquire) {
            return;
        }
        let mut guard = self.reason.lock();
        if guard.is_none() {
            *guard = Some(reason);
            self.requested.store(true, Ordering::Release);
        }
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn requested_reason(&self) -> Option<DispatchCloseReason> {
        if self.requested.load(Ordering::Acquire) {
            Some(
                self.reason
                    .lock()
                    .unwrap_or(DispatchCloseReason::RuntimeDrop),
            )
        } else {
            None
        }
    }
}

struct LaneRuntimeInner {
    name: String,
    generation: AtomicU64,
    status: Arc<AtomicU8>,
    close_state: Arc<LaneCloseState>,
    sender: Mutex<Option<mpsc::Sender<LaneCommand>>>,
    join: Mutex<Option<JoinHandle<()>>>,
    panic_auditor: Option<Arc<Auditor>>,
    _capacity_permit: Option<AdmissionPermit>,
}

impl LaneRuntimeInner {
    fn request_close(&self, reason: DispatchCloseReason) -> Option<mpsc::Sender<LaneCommand>> {
        self.close_state.request(reason);
        self.sender.lock().take()
    }
}

impl Drop for LaneRuntimeInner {
    fn drop(&mut self) {
        assert_no_lane_registry_lock("dropping a dispatch lane handle");
        if let Some(sender) = self.request_close(DispatchCloseReason::RuntimeDrop) {
            sender.wake_receiver();
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
            DEFAULT_REQUEST_TIMEOUT,
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
        factory_request_timeout: Duration,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        Self::spawn_with_dispatch_factory_and_capacity(
            name,
            lane_context,
            factory,
            factory_request_timeout,
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
        factory_request_timeout: Duration,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
        capacity_permit: Option<AdmissionPermit>,
    ) -> Self {
        Self::spawn_with_factory_policy(
            name,
            lane_context,
            factory,
            factory_request_timeout,
            mailbox_capacity,
            panic_auditor,
            capacity_permit,
            false,
        )
    }

    /// Spawn a lane from one atomic, generation-bound preparation.
    ///
    /// Unlike a reusable raw factory, a prepared factory is consumed by its
    /// first initialization attempt. If that attempt fails the lane stops so a
    /// registry can rebuild it from a fresh policy generation.
    #[must_use]
    pub fn spawn_prepared_dispatch(
        name: impl Into<String>,
        lane_context: LaneContext,
        prepared: PreparedLaneDispatch,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        Self::spawn_prepared_dispatch_with_capacity(
            name,
            lane_context,
            prepared,
            mailbox_capacity,
            panic_auditor,
            None,
        )
    }

    fn spawn_prepared_dispatch_with_capacity(
        name: impl Into<String>,
        lane_context: LaneContext,
        prepared: PreparedLaneDispatch,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
        capacity_permit: Option<AdmissionPermit>,
    ) -> Self {
        Self::spawn_with_factory_policy(
            name,
            lane_context,
            prepared.factory,
            prepared.request_timeout,
            mailbox_capacity,
            panic_auditor,
            capacity_permit,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_with_factory_policy(
        name: impl Into<String>,
        lane_context: LaneContext,
        factory: Arc<LaneDispatchFactory>,
        factory_request_timeout: Duration,
        mailbox_capacity: usize,
        panic_auditor: Option<Arc<Auditor>>,
        capacity_permit: Option<AdmissionPermit>,
        factory_error_is_terminal: bool,
    ) -> Self {
        let name = name.into();
        let capacity = mailbox_capacity.max(1);
        let (sender, receiver) = mpsc::channel::<LaneCommand>(capacity);
        let status = Arc::new(AtomicU8::new(STATUS_STARTING));
        let thread_status = Arc::clone(&status);
        let close_state = Arc::new(LaneCloseState::new());
        let thread_close_state = Arc::clone(&close_state);
        let thread_name = format!("oraclemcp-lane-{name}");
        let thread_auditor = panic_auditor.clone();
        let thread_config = LaneThreadConfig {
            name: name.clone(),
            lane_context,
            factory,
            factory_request_timeout,
            factory_error_is_terminal,
            status: thread_status,
            close_state: thread_close_state,
            panic_auditor: thread_auditor,
        };
        let join = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                run_lane_thread_with_factory(receiver, thread_config);
            })
            .expect("dedicated Oracle MCP lane thread spawns");

        Self {
            inner: Arc::new(LaneRuntimeInner {
                name,
                generation: AtomicU64::new(1),
                status,
                close_state,
                sender: Mutex::new(Some(sender)),
                join: Mutex::new(Some(join)),
                panic_auditor,
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

    /// Whether the lane can still accept a new command.
    ///
    /// A lane may briefly remain `Running` while its owning thread drains a
    /// terminal close request, so lifecycle status alone is not sufficient for
    /// registries deciding whether to reuse the handle.
    #[must_use]
    pub fn accepts_commands(&self) -> bool {
        matches!(
            self.status(),
            LaneRuntimeStatus::Starting | LaneRuntimeStatus::Running
        ) && !self.inner.close_state.is_requested()
    }

    fn sender(&self) -> Result<mpsc::Sender<LaneCommand>, ErrorEnvelope> {
        if self.status() == LaneRuntimeStatus::Quarantined {
            return Err(ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!("dispatch lane {} is quarantined after panic", self.name()),
            ));
        }
        if self.inner.close_state.is_requested() {
            return Err(lane_stopped_before_reply(self.name()));
        }
        let guard = self.inner.sender.lock();
        guard.as_ref().cloned().ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!("dispatch lane {} is stopped", self.name()),
            )
        })
    }

    /// Stop accepting new commands for this lane and join its thread once any
    /// active dispatcher call returns. Queued commands are not run after close is
    /// requested. This is the N5 Streamable HTTP DELETE hook; full dirty-session
    /// rollback is owned by the lane dispatcher/lease layer, while this handle
    /// tears down the transport-facing lane resource.
    pub fn close(&self) {
        self.close_with_reason(DispatchCloseReason::SessionDelete);
    }

    /// Stop accepting new commands and ask the lane-owned dispatcher to clean
    /// up with the supplied lifecycle reason before the lane exits.
    pub fn close_with_reason(&self, reason: DispatchCloseReason) {
        assert_no_lane_registry_lock("closing a dispatch lane");
        if let Some(sender) = self.inner.request_close(reason) {
            sender.wake_receiver();
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
            assert_no_lane_registry_lock("sending a dispatch command to a lane");
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
            let caller = Arc::new(LaneCallerSignal::new(cx));
            let command = LaneCommand::Dispatch {
                caller: Arc::clone(&caller),
                enqueued_at: Instant::now(),
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
            let caller_guard = LaneCallerGuard::new(caller);
            match recv_lane_reply(cx, &mut reply_rx).await {
                Ok(outcome) => {
                    caller_guard.complete();
                    outcome
                }
                Err(oneshot::RecvError::Cancelled) => {
                    let reason =
                        cancel_reason_from_cx(cx, "dispatch lane receive cancelled before reply");
                    caller_guard.signal_cancel(reason.clone());
                    match recv_terminal_after_cancel(cx, &mut reply_rx).await {
                        Ok(outcome) => {
                            caller_guard.complete();
                            outcome
                        }
                        Err(TerminalReplyWaitError::Closed) => {
                            caller_guard.complete();
                            if self.inner.close_state.is_requested() {
                                Outcome::Err(lane_stopped_before_reply(self.name()))
                            } else {
                                Outcome::Panicked(lane_panic_payload(self.name()))
                            }
                        }
                        Err(TerminalReplyWaitError::Expired) => {
                            caller_guard.complete();
                            terminal_reply_wait_expired_outcome(
                                self.name(),
                                &self.inner.close_state,
                                self.inner.panic_auditor.as_deref(),
                                reason,
                            )
                        }
                    }
                }
                Err(oneshot::RecvError::Closed) => {
                    caller_guard.complete();
                    if self.inner.close_state.is_requested() {
                        Outcome::Err(lane_stopped_before_reply(self.name()))
                    } else {
                        Outcome::Panicked(lane_panic_payload(self.name()))
                    }
                }
                Err(_) => {
                    caller_guard.complete();
                    Outcome::Err(ErrorEnvelope::new(
                        ErrorClass::RuntimeStateRequired,
                        format!("dispatch lane {} stopped before replying", self.name()),
                    ))
                }
            }
        })
    }

    fn dispatch_stream_start<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
        frames: ToolStreamSender,
    ) -> DispatchStreamStartFuture<'a> {
        Box::pin(async move {
            assert_no_lane_registry_lock("sending a streaming dispatch command to a lane");
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "streaming dispatch lane send cancelled before admission",
                ));
            }
            let sender = match self.sender() {
                Ok(sender) => sender,
                Err(_) if self.status() == LaneRuntimeStatus::Quarantined => {
                    return Outcome::Panicked(lane_panic_payload(self.name()));
                }
                Err(err) => return Outcome::Err(err),
            };
            let (reply_tx, reply_rx) = oneshot::channel();
            let lane_generation = self.generation();
            let context = context.with_lane_identity(self.name(), lane_generation);
            let caller = Arc::new(LaneCallerSignal::new(cx));
            let command = LaneCommand::DispatchStream {
                caller: Arc::clone(&caller),
                enqueued_at: Instant::now(),
                context: context.to_owned_context(),
                name: name.to_owned(),
                args,
                frames,
                reply: reply_tx,
            };
            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(error) => return lane_stream_start_error_outcome(self.name(), error, cx),
            };
            if let Err(error) = permit.try_send(command) {
                return lane_stream_start_error_outcome(self.name(), error, cx);
            }
            let cancel_caller = Arc::clone(&caller);
            let expiry_close_state = Arc::clone(&self.inner.close_state);
            let expiry_auditor = self.inner.panic_auditor.clone();
            let expiry_lane_name = self.name().to_owned();
            Outcome::Ok(DispatchReplyReceiver::with_cancel_hooks(
                reply_rx,
                Arc::new(move |reason| cancel_caller.cancel(reason)),
                Arc::new(move |reason| {
                    terminal_reply_wait_expired_outcome(
                        &expiry_lane_name,
                        &expiry_close_state,
                        expiry_auditor.as_deref(),
                        reason,
                    )
                }),
            ))
        })
    }

    fn mcp_surface_state<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        detail: McpSurfaceDetail,
    ) -> McpSurfaceFuture<'a> {
        Box::pin(async move {
            assert_no_lane_registry_lock("sending an MCP surface-state command to a lane");
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "dispatch lane surface-state send cancelled before admission",
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
            let caller = Arc::new(LaneCallerSignal::new(cx));
            let command = LaneCommand::SurfaceState {
                caller: Arc::clone(&caller),
                enqueued_at: Instant::now(),
                context: context.to_owned_context(),
                detail,
                reply: reply_tx,
            };
            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(error) => return lane_send_error_surface_outcome(self.name(), error, cx),
            };
            if let Err(error) = permit.try_send(command) {
                return lane_send_error_surface_outcome(self.name(), error, cx);
            }
            let caller_guard = LaneCallerGuard::new(caller);
            match recv_lane_reply(cx, &mut reply_rx).await {
                Ok(outcome) => {
                    caller_guard.complete();
                    outcome
                }
                Err(oneshot::RecvError::Cancelled) => {
                    let reason = cancel_reason_from_cx(
                        cx,
                        "dispatch lane surface-state receive cancelled before reply",
                    );
                    caller_guard.signal_cancel(reason.clone());
                    match recv_terminal_after_cancel(cx, &mut reply_rx).await {
                        Ok(outcome) => {
                            caller_guard.complete();
                            outcome
                        }
                        Err(TerminalReplyWaitError::Closed) => {
                            caller_guard.complete();
                            if self.inner.close_state.is_requested() {
                                Outcome::Err(lane_stopped_before_reply(self.name()))
                            } else {
                                Outcome::Panicked(lane_panic_payload(self.name()))
                            }
                        }
                        Err(TerminalReplyWaitError::Expired) => {
                            caller_guard.complete();
                            terminal_reply_wait_expired_outcome(
                                self.name(),
                                &self.inner.close_state,
                                self.inner.panic_auditor.as_deref(),
                                reason,
                            )
                        }
                    }
                }
                Err(oneshot::RecvError::Closed) => {
                    caller_guard.complete();
                    if self.inner.close_state.is_requested() {
                        Outcome::Err(lane_stopped_before_reply(self.name()))
                    } else {
                        Outcome::Panicked(lane_panic_payload(self.name()))
                    }
                }
                Err(_) => {
                    caller_guard.complete();
                    Outcome::Err(ErrorEnvelope::new(
                        ErrorClass::RuntimeStateRequired,
                        format!("dispatch lane {} stopped before replying", self.name()),
                    ))
                }
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
    factory_builder: Arc<LaneDispatchFactoryBuilder>,
    panic_auditor: Option<Arc<Auditor>>,
    admission: Option<Arc<AdmissionController>>,
    mailbox_capacity: usize,
    next_lane_id: AtomicU64,
    lanes: Mutex<HashMap<LaneKey, LaneRuntime>>,
    lifecycle: Mutex<LaneLifecycleState>,
    creation_changed: Condvar,
}

struct LaneLifecycleState {
    creating_lanes: HashSet<LaneKey>,
    key_tokens: HashMap<LaneKey, Weak<LaneCloseState>>,
    principal_tokens: HashMap<String, Weak<LaneCloseState>>,
    global_token: Arc<LaneCloseState>,
}

impl LaneLifecycleState {
    fn new() -> Self {
        Self {
            creating_lanes: HashSet::new(),
            key_tokens: HashMap::new(),
            principal_tokens: HashMap::new(),
            global_token: Arc::new(LaneCloseState::new()),
        }
    }

    fn key_token(&mut self, key: &LaneKey) -> Arc<LaneCloseState> {
        if let Some(token) = self.key_tokens.get(key).and_then(Weak::upgrade)
            && !token.is_requested()
        {
            return token;
        }
        let token = Arc::new(LaneCloseState::new());
        self.key_tokens.insert(key.clone(), Arc::downgrade(&token));
        token
    }

    fn principal_token(&mut self, principal_key: &str) -> Arc<LaneCloseState> {
        if let Some(token) = self
            .principal_tokens
            .get(principal_key)
            .and_then(Weak::upgrade)
            && !token.is_requested()
        {
            return token;
        }
        let token = Arc::new(LaneCloseState::new());
        self.principal_tokens
            .insert(principal_key.to_owned(), Arc::downgrade(&token));
        token
    }
}

/// Strong generation tokens held by one lane-resolution attempt.
///
/// Lifecycle closure removes and invalidates the current weak token for its
/// scope. Requests already inside resolution retain the invalidated generation,
/// while a later, valid HTTP reinitialization receives a fresh generation. The
/// weak registry entries are removed by the final ticket, so abandoned session
/// ids cannot accumulate as lifecycle tombstones.
struct LaneResolutionTicket<'a> {
    lifecycle: &'a Mutex<LaneLifecycleState>,
    key: LaneKey,
    key_token: Arc<LaneCloseState>,
    principal_token: Arc<LaneCloseState>,
    global_token: Arc<LaneCloseState>,
}

impl LaneResolutionTicket<'_> {
    fn remains_current(&self, state: &LaneLifecycleState) -> bool {
        let key_is_current = state
            .key_tokens
            .get(&self.key)
            .and_then(Weak::upgrade)
            .is_some_and(|token| Arc::ptr_eq(&token, &self.key_token));
        let principal_is_current = state
            .principal_tokens
            .get(&self.key.principal_key)
            .and_then(Weak::upgrade)
            .is_some_and(|token| Arc::ptr_eq(&token, &self.principal_token));
        key_is_current
            && principal_is_current
            && Arc::ptr_eq(&state.global_token, &self.global_token)
            && self.closed_reason().is_none()
    }

    fn closed_reason(&self) -> Option<DispatchCloseReason> {
        self.key_token
            .requested_reason()
            .or_else(|| self.principal_token.requested_reason())
            .or_else(|| self.global_token.requested_reason())
    }
}

impl Drop for LaneResolutionTicket<'_> {
    fn drop(&mut self) {
        let mut state = self.lifecycle.lock();
        if Arc::strong_count(&self.key_token) == 1
            && state
                .key_tokens
                .get(&self.key)
                .and_then(Weak::upgrade)
                .is_some_and(|token| Arc::ptr_eq(&token, &self.key_token))
        {
            state.key_tokens.remove(&self.key);
        }
        if Arc::strong_count(&self.principal_token) == 1
            && state
                .principal_tokens
                .get(&self.key.principal_key)
                .and_then(Weak::upgrade)
                .is_some_and(|token| Arc::ptr_eq(&token, &self.principal_token))
        {
            state.principal_tokens.remove(&self.key.principal_key);
        }
    }
}

struct LaneCreationGuard<'a> {
    key: Option<LaneKey>,
    lifecycle: &'a Mutex<LaneLifecycleState>,
    creation_changed: &'a Condvar,
}

impl Drop for LaneCreationGuard<'_> {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        self.lifecycle.lock().creating_lanes.remove(&key);
        self.creation_changed.notify_all();
    }
}

enum LaneCreationTurn<'a> {
    Existing(LaneRuntime),
    Create(LaneCreationGuard<'a>),
}

struct LaneRegistryGuard<'a> {
    inner: parking_lot::MutexGuard<'a, HashMap<LaneKey, LaneRuntime>>,
}

impl Drop for LaneRegistryGuard<'_> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        exit_lane_registry_lock();
    }
}

impl Deref for LaneRegistryGuard<'_> {
    type Target = HashMap<LaneKey, LaneRuntime>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for LaneRegistryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl fmt::Debug for StatefulLaneDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lane_count = self.lock_lanes().len();
        f.debug_struct("StatefulLaneDispatch")
            .field("mailbox_capacity", &self.mailbox_capacity)
            .field("admission", &self.admission.is_some())
            .field("lane_count", &lane_count)
            .finish_non_exhaustive()
    }
}

impl StatefulLaneDispatch {
    #[must_use]
    pub fn new(inner: Arc<dyn ToolDispatch>) -> Self {
        let shared = Arc::clone(&inner);
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            let shared = Arc::clone(&shared);
            let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
                let inner = Arc::clone(&shared);
                Box::pin(async move { Ok(inner) })
            });
            Ok(PreparedLaneDispatch::new(factory, DEFAULT_REQUEST_TIMEOUT))
        });
        Self::with_dispatch_factory_builder(factory_builder, None)
    }

    /// Build a stateful lane registry whose concrete dispatchers are created on
    /// each lane's own runtime.
    #[must_use]
    pub fn with_dispatch_factory_builder(
        factory_builder: Arc<LaneDispatchFactoryBuilder>,
        panic_auditor: Option<Arc<Auditor>>,
    ) -> Self {
        Self {
            factory_builder,
            panic_auditor,
            admission: None,
            mailbox_capacity: DEFAULT_LANE_MAILBOX_CAPACITY,
            next_lane_id: AtomicU64::new(1),
            lanes: Mutex::new(HashMap::new()),
            lifecycle: Mutex::new(LaneLifecycleState::new()),
            creation_changed: Condvar::new(),
        }
    }

    /// Install capacity admission for new lane allocation.
    #[must_use]
    pub fn with_admission_controller(mut self, admission: Arc<AdmissionController>) -> Self {
        self.admission = Some(admission);
        self
    }

    fn lock_lanes(&self) -> LaneRegistryGuard<'_> {
        let inner = self.lanes.lock();
        #[cfg(debug_assertions)]
        enter_lane_registry_lock();
        LaneRegistryGuard { inner }
    }

    fn reusable_lane(&self, key: &LaneKey) -> Option<LaneRuntime> {
        let (lane, stale) = {
            let mut lanes = self.lock_lanes();
            match lanes.get(key).cloned() {
                Some(lane) if lane.accepts_commands() => (Some(lane), None),
                Some(_) => (None, lanes.remove(key)),
                None => (None, None),
            }
        };
        // Dropping a stale lane can release its generation-bound factory. Do
        // that only after the registry lock is gone (Config -> Registry order).
        drop(stale);
        lane
    }

    fn begin_lane_resolution(&self, key: LaneKey) -> LaneResolutionTicket<'_> {
        let mut state = self.lifecycle.lock();
        let key_token = state.key_token(&key);
        let principal_token = state.principal_token(&key.principal_key);
        let global_token = Arc::clone(&state.global_token);
        drop(state);
        LaneResolutionTicket {
            lifecycle: &self.lifecycle,
            key,
            key_token,
            principal_token,
            global_token,
        }
    }

    fn acquire_creation_turn<'a>(
        &'a self,
        cx: &Cx,
        key: &LaneKey,
        ticket: &LaneResolutionTicket<'_>,
    ) -> Result<LaneCreationTurn<'a>, ErrorEnvelope> {
        let wait_deadline = Instant::now()
            .checked_add(Duration::from_millis(DEFAULT_FAIR_ADMISSION_WAIT_MS))
            .unwrap_or_else(Instant::now);
        loop {
            cx.checkpoint()
                .map_err(|_| lane_resolution_cancelled_error())?;
            if let Some(reason) = ticket.closed_reason() {
                return Err(lane_lifecycle_closed_error(reason));
            }
            if let Some(lane) = self.reusable_lane(key) {
                return Ok(LaneCreationTurn::Existing(lane));
            }
            let mut lifecycle = self.lifecycle.lock();
            if !ticket.remains_current(&lifecycle) {
                let reason = ticket
                    .closed_reason()
                    .unwrap_or(DispatchCloseReason::RuntimeDrop);
                return Err(lane_lifecycle_closed_error(reason));
            }
            if lifecycle.creating_lanes.insert(key.clone()) {
                drop(lifecycle);
                let guard = LaneCreationGuard {
                    key: Some(key.clone()),
                    lifecycle: &self.lifecycle,
                    creation_changed: &self.creation_changed,
                };
                // Close the Registry-miss -> marker-acquire race with a
                // concurrent owner that inserted just before releasing its
                // marker.
                if let Some(lane) = self.reusable_lane(key) {
                    drop(guard);
                    return Ok(LaneCreationTurn::Existing(lane));
                }
                return Ok(LaneCreationTurn::Create(guard));
            }
            let Some(remaining) = wait_deadline.checked_duration_since(Instant::now()) else {
                return Err(ErrorEnvelope::new(
                    ErrorClass::Busy,
                    "timed out waiting for concurrent construction of the same stateful lane",
                )
                .with_retry_after_ms(DEFAULT_RETRY_AFTER_MS));
            };
            self.creation_changed
                .wait_for(&mut lifecycle, remaining.min(Duration::from_millis(5)));
            drop(lifecycle);
        }
    }

    fn resolve_lane(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
    ) -> Result<LaneRuntime, ErrorEnvelope> {
        cx.checkpoint()
            .map_err(|_| lane_resolution_cancelled_error())?;
        let session_id = context.http_session_id().ok_or_else(lease_required)?;
        let principal_key = context.principal_key().unwrap_or("anonymous-http");
        let key = LaneKey::new(session_id, principal_key);
        let lifecycle_ticket = self.begin_lane_resolution(key.clone());
        if let Some(lane) = self.reusable_lane(&key) {
            return Ok(lane);
        }
        let _creation_guard = match self.acquire_creation_turn(cx, &key, &lifecycle_ticket)? {
            LaneCreationTurn::Existing(lane) => return Ok(lane),
            LaneCreationTurn::Create(guard) => guard,
        };

        let capacity_permit = if let Some(admission) = self.admission.as_ref() {
            match admission.try_admit(cx, principal_key) {
                Ok(permit) => Some(permit),
                Err(_) => match admission.admit_capacity_with_fair_wait(
                    cx,
                    principal_key,
                    "stateful_lane",
                ) {
                    Ok(permit) => Some(permit),
                    Err(error) => {
                        if cx.checkpoint().is_err() {
                            return Err(lane_resolution_cancelled_error());
                        }
                        // Another request for the same key can consume the last
                        // permit while constructing the one lane both callers
                        // should share. Reuse that concurrent winner before
                        // surfacing a false capacity refusal.
                        if let Some(lane) = self.reusable_lane(&key) {
                            return Ok(lane);
                        }
                        return Err(error);
                    }
                },
            }
        } else {
            None
        };
        let lane_number = self.next_lane_id.fetch_add(1, Ordering::SeqCst);
        let lane_id = format!("http-lane-{lane_number}");
        let lane_context = LaneContext::new(
            lane_id.clone(),
            key.mcp_session_id.clone(),
            key.principal_key.clone(),
            1,
        );
        // Config/profile generation preparation happens before the lane
        // registry lock. This both preserves the canonical Config -> Registry
        // order and binds factory + timeout to one atomic generation lease.
        let prepared = (self.factory_builder)(&lane_context)?;
        if cx.checkpoint().is_err() {
            drop(prepared);
            drop(capacity_permit);
            return Err(lane_resolution_cancelled_error());
        }
        if let Some(reason) = lifecycle_ticket.closed_reason() {
            drop(prepared);
            drop(capacity_permit);
            return Err(lane_lifecycle_closed_error(reason));
        }

        // Spawn the inert candidate outside both lifecycle and registry locks.
        // Its dispatcher factory remains lazy until the first command, so a
        // lifecycle invalidation can still discard it without touching Oracle.
        let candidate = self.spawn_lane_candidate(lane_id, lane_context, prepared, capacity_permit);

        // SAFETY: lifecycle closure takes these locks in the same
        // Lifecycle -> Registry order. Holding the lifecycle lock from final
        // generation validation through insertion makes the close/insert race
        // linearizable; no closure can return and then observe a late insert.
        let lifecycle = self.lifecycle.lock();
        if !lifecycle_ticket.remains_current(&lifecycle) {
            let reason = lifecycle_ticket
                .closed_reason()
                .unwrap_or(DispatchCloseReason::RuntimeDrop);
            drop(lifecycle);
            candidate.close_with_reason(reason);
            return Err(lane_lifecycle_closed_error(reason));
        }
        let mut lanes = self.lock_lanes();
        if let Some(lane) = lanes
            .get(&key)
            .filter(|lane| lane.accepts_commands())
            .cloned()
        {
            drop(lanes);
            drop(lifecycle);
            candidate.close_with_reason(DispatchCloseReason::RuntimeDrop);
            return Ok(lane);
        }
        let stale = lanes.remove(&key);
        lanes.insert(key, candidate.clone());
        drop(lanes);
        drop(lifecycle);
        drop(stale);
        Ok(candidate)
    }

    fn spawn_lane_candidate(
        &self,
        lane_id: String,
        lane_context: LaneContext,
        prepared: PreparedLaneDispatch,
        capacity_permit: Option<AdmissionPermit>,
    ) -> LaneRuntime {
        LaneRuntime::spawn_prepared_dispatch_with_capacity(
            lane_id,
            lane_context,
            prepared,
            self.mailbox_capacity,
            self.panic_auditor.clone(),
            capacity_permit,
        )
    }

    /// Close and forget the lane bound to one MCP session/principal pair.
    ///
    /// Returns `true` when a lane existed. New requests for the same pair must
    /// initialize a fresh MCP session because the HTTP session store is removed
    /// by the caller before this is invoked.
    pub fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
        self.close_session_with_lifecycle_reason(
            session_id,
            principal_key,
            DispatchCloseReason::SessionDelete,
        )
    }

    fn close_session_with_lifecycle_reason(
        &self,
        session_id: &str,
        principal_key: &str,
        reason: DispatchCloseReason,
    ) -> bool {
        let key = LaneKey::new(session_id, principal_key);
        let (lane, cancelled_creation) = {
            let mut lifecycle = self.lifecycle.lock();
            let token = lifecycle
                .key_tokens
                .remove(&key)
                .and_then(|token| token.upgrade());
            let cancelled_creation = token.is_some();
            if let Some(token) = token {
                token.request(reason);
            }
            let lane = self.lock_lanes().remove(&key);
            (lane, cancelled_creation)
        };
        self.creation_changed.notify_all();
        if let Some(lane) = lane {
            lane.close_with_reason(reason);
            true
        } else {
            cancelled_creation
        }
    }

    /// Close every registered lane and return how many were present.
    pub fn close_all_sessions(&self) -> usize {
        let (lanes, count) = {
            let mut lifecycle = self.lifecycle.lock();
            let invalidated =
                std::mem::replace(&mut lifecycle.global_token, Arc::new(LaneCloseState::new()));
            invalidated.request(DispatchCloseReason::ServerShutdown);
            let creating = lifecycle.creating_lanes.clone();
            let mut registered = self.lock_lanes();
            let count = registered
                .keys()
                .chain(creating.iter())
                .collect::<HashSet<_>>()
                .len();
            let lanes = registered
                .drain()
                .map(|(_, lane)| lane)
                .collect::<Vec<LaneRuntime>>();
            (lanes, count)
        };
        self.creation_changed.notify_all();
        for lane in lanes {
            lane.close_with_reason(DispatchCloseReason::ServerShutdown);
        }
        count
    }

    #[cfg(test)]
    fn lane_count(&self) -> usize {
        self.lock_lanes().len()
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
        self.close_session_with_lifecycle_reason(session_id, principal_key, reason)
    }

    fn close_all_sessions(&self) {
        let _ = StatefulLaneDispatch::close_all_sessions(self);
    }

    fn close_principal_sessions(&self, principal_key: &str, reason: DispatchCloseReason) -> usize {
        let (lanes, count) = {
            let mut lifecycle = self.lifecycle.lock();
            if let Some(token) = lifecycle
                .principal_tokens
                .remove(principal_key)
                .and_then(|token| token.upgrade())
            {
                token.request(reason);
            }
            let creating = lifecycle
                .creating_lanes
                .iter()
                .filter(|key| key.principal_key == principal_key)
                .cloned()
                .collect::<HashSet<_>>();
            let mut registered = self.lock_lanes();
            let keys = registered
                .keys()
                .filter(|key| key.principal_key == principal_key)
                .cloned()
                .collect::<Vec<_>>();
            let count = keys
                .iter()
                .chain(creating.iter())
                .collect::<HashSet<_>>()
                .len();
            let lanes = keys
                .into_iter()
                .filter_map(|key| registered.remove(&key))
                .collect::<Vec<_>>();
            (lanes, count)
        };
        self.creation_changed.notify_all();
        for lane in lanes {
            lane.close_with_reason(reason);
        }
        count
    }

    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        self.lock_lanes()
            .iter()
            .map(|(key, lane)| HttpLaneSnapshot {
                lane_id: lane.name().to_owned(),
                generation: lane.generation(),
                status: lane.status().as_str(),
                subject_id_hash: operator_subject_id_hash(&key.principal_key),
            })
            .collect()
    }

    fn capacity_snapshot(&self, scope: &str, subject: &str) -> Option<CapacitySnapshot> {
        self.admission
            .as_ref()
            .map(|admission| admission.snapshot(scope, subject))
    }

    fn lane_binding(&self, lane_id: &str) -> Option<HttpLaneBinding> {
        self.lock_lanes().iter().find_map(|(key, lane)| {
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
            let context = context.with_request_started_at(Instant::now());
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "stateful lane resolution cancelled before admission",
                ));
            }
            let lane = self.resolve_lane(cx, context)?;
            lane.dispatch(cx, context, name, args).await
        })
    }

    fn dispatch_stream_start<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
        frames: ToolStreamSender,
    ) -> DispatchStreamStartFuture<'a> {
        Box::pin(async move {
            let context = context.with_request_started_at(Instant::now());
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "stateful streaming lane resolution cancelled before admission",
                ));
            }
            let lane = self.resolve_lane(cx, context)?;
            lane.dispatch_stream_start(cx, context, name, args, frames)
                .await
        })
    }

    fn mcp_surface_state<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        detail: McpSurfaceDetail,
    ) -> McpSurfaceFuture<'a> {
        Box::pin(async move {
            let context = context.with_request_started_at(Instant::now());
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(cancel_reason_from_cx(
                    cx,
                    "stateful surface resolution cancelled before admission",
                ));
            }
            let lane = self.resolve_lane(cx, context)?;
            lane.mcp_surface_state(cx, context, detail).await
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

fn lane_resolution_cancelled_error() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::Timeout,
        "stateful lane resolution was cancelled or exhausted its caller budget",
    )
    .with_next_step("retry only if the original operation was safe to retry")
}

fn lane_lifecycle_closed_error(reason: DispatchCloseReason) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RuntimeStateRequired,
        format!(
            "stateful lane creation was invalidated by {} lifecycle closure",
            reason.as_str()
        ),
    )
    .with_next_step("initialize a fresh MCP session after the lifecycle transition before retrying")
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

fn lane_stream_start_error_outcome<T>(
    name: &str,
    error: SendError<T>,
    cx: &Cx,
) -> Outcome<DispatchReplyReceiver, ErrorEnvelope> {
    match error {
        SendError::Cancelled(_) => Outcome::Cancelled(cancel_reason_from_cx(
            cx,
            "streaming dispatch lane send cancelled before admission",
        )),
        other => Outcome::Err(lane_send_error(name, other)),
    }
}

fn lane_send_error_surface_outcome<T>(
    name: &str,
    error: SendError<T>,
    cx: &Cx,
) -> McpSurfaceOutcome {
    match error {
        SendError::Cancelled(_) => Outcome::Cancelled(cancel_reason_from_cx(
            cx,
            "dispatch lane surface-state send cancelled before admission",
        )),
        other => Outcome::Err(lane_send_error(name, other)),
    }
}

fn cancel_reason_from_cx(cx: &Cx, fallback: &'static str) -> CancelReason {
    cx.cancel_reason()
        .unwrap_or_else(|| CancelReason::user(fallback))
}

async fn recv_lane_reply<T>(
    cx: &Cx,
    reply: &mut oneshot::Receiver<T>,
) -> Result<T, oneshot::RecvError> {
    let mut receive = std::pin::pin!(reply.recv(cx));
    // `oneshot::recv` observes cancellation when polled but its value waker is
    // not registered with an externally supplied caller Cx. An uninitialized
    // OnceCell wait is the public Asupersync cancellation sentinel: it installs
    // the Cx cancellation waker, closes the cancel/register race with a second
    // checkpoint, and unregisters cleanly when this wait completes.
    let cancel_sentinel = OnceCell::<()>::new();
    let mut cancelled = std::pin::pin!(cancel_sentinel.wait(cx));
    std::future::poll_fn(|task_cx| {
        // A ready lane reply may carry the only safe terminal classification
        // for a commit/DDL/elevation. Preserve it even when caller cancellation
        // became visible in the same scheduling turn; returning a generic
        // cancellation here would invite an unsafe retry after a real effect.
        match receive.as_mut().poll(task_cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match cancelled.as_mut().poll(task_cx) {
                Poll::Ready(_) => Poll::Ready(Err(oneshot::RecvError::Cancelled)),
                Poll::Pending => Poll::Pending,
            },
        }
    })
    .await
}

fn lane_panic_payload(name: &str) -> PanicPayload {
    PanicPayload::new(format!("dispatch lane {name} panicked before replying"))
}

fn lane_stopped_before_reply(name: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::RuntimeStateRequired,
        format!("dispatch lane {name} stopped before replying"),
    )
}

struct LaneThreadConfig {
    name: String,
    lane_context: LaneContext,
    factory: Arc<LaneDispatchFactory>,
    factory_request_timeout: Duration,
    factory_error_is_terminal: bool,
    status: Arc<AtomicU8>,
    close_state: Arc<LaneCloseState>,
    panic_auditor: Option<Arc<Auditor>>,
}

fn run_lane_thread_with_factory(receiver: mpsc::Receiver<LaneCommand>, config: LaneThreadConfig) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("Asupersync native reactor builds for lane dispatch");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("Asupersync current-thread runtime builds for lane dispatch");
        config.status.store(STATUS_RUNNING, Ordering::Release);
        run_lane_loop_with_factory(&runtime, receiver, &config);
    }));
    match outcome {
        Ok(()) => config.status.store(STATUS_STOPPED, Ordering::Release),
        Err(_) => {
            audit_lane_panic(&config.name, config.panic_auditor.as_deref());
            tracing::error!(
                lane = %config.name,
                audit_event = "lane_panic_unknown_discarded",
                outcome = "unknown_discarded",
                "oraclemcp lane panicked; quarantined lane and discarded unknown in-flight DB state"
            );
            config.status.store(STATUS_QUARANTINED, Ordering::Release);
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

fn audit_lane_finalization_timeout(name: &str, auditor: Option<&Auditor>) -> bool {
    let Some(auditor) = auditor else {
        return true;
    };
    let draft = AuditEntryDraft {
        subject: AuditSubject::new("lane", name),
        db_evidence: None,
        cancel: None,
        tool: "lane_runtime".to_owned(),
        sql: "LANE_FINALIZATION_TIMEOUT_UNKNOWN_DISCARDED".to_owned(),
        danger_level: "UNKNOWN".to_owned(),
        decision: AuditDecision::Blocked,
        rows_affected: None,
        outcome: AuditOutcome::UnknownDiscarded,
    };
    match auditor.append(&draft, audit_timestamp(), true) {
        Ok(_) => true,
        Err(error) => {
            tracing::error!(
                lane = %name,
                error = %error,
                "failed to append durable lane finalization-timeout audit record"
            );
            false
        }
    }
}

fn audit_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

// SAFETY: These are the sanctioned N0a block_on boundaries. They are entered
// only by `run_lane_thread_with_factory` on its dedicated OS thread. Mailbox
// receive, each command, and close each get a fresh lane-runtime Cx; the
// concrete dispatcher and Oracle connection remain owned by this thread.
// Callers interact only through bounded commands and owned reply values.
fn run_lane_loop_with_factory(
    runtime: &Runtime,
    mut receiver: mpsc::Receiver<LaneCommand>,
    config: &LaneThreadConfig,
) {
    let mut dispatcher: Option<Arc<dyn ToolDispatch>> = None;
    let lane_context = &config.lane_context;
    let close_state = &config.close_state;
    let panic_auditor = config.panic_auditor.as_deref();

    loop {
        if let Some(reason) = close_state.requested_reason() {
            close_lane_dispatcher_on_runtime(runtime, dispatcher.as_deref(), lane_context, reason);
            break;
        }

        // block-on-boundary: one fresh lane-runtime Cx owns this mailbox wait.
        let command = runtime.block_on(async {
            let cx = Cx::current().expect("lane runtime installs a mailbox Cx");
            // A9: the lane shell needs TIME+IO only. Dispatcher/DB calls below
            // keep the full, lane-owned Cx as the object-safe IO exception.
            let lane_cx = narrow_to_lane(&cx);
            if lane_cx.checkpoint().is_err() {
                return None;
            }
            receiver.recv(&lane_cx).await.ok()
        });
        let Some(command) = command else {
            if let Some(reason) = close_state.requested_reason() {
                close_lane_dispatcher_on_runtime(
                    runtime,
                    dispatcher.as_deref(),
                    lane_context,
                    reason,
                );
            }
            break;
        };

        if let Some(reason) = close_state.requested_reason() {
            close_lane_dispatcher_on_runtime(runtime, dispatcher.as_deref(), lane_context, reason);
            break;
        }

        match command {
            LaneCommand::Dispatch {
                caller,
                enqueued_at,
                context,
                name,
                args,
                reply,
            } => {
                // block-on-boundary: each command gets a fresh lane-owned Cx.
                runtime.block_on(async {
                    let cx = Cx::current().expect("lane runtime installs a command Cx");
                    let context = lane_command_context(&cx, &caller, enqueued_at, &context);
                    let request_budget = context
                        .as_dispatch_context()
                        .request_budget()
                        .cloned()
                        .expect("lane command installs a shared request budget");
                    let factory_budget = request_budget.tighten_timeout(
                        tool_request_timeout_ceiling(config.factory_request_timeout, &args),
                    );
                    if let Some(reason) = caller.reason() {
                        let _ = reply.send_blocking(Outcome::Cancelled(reason));
                        return;
                    }
                    if dispatcher.is_none() {
                        match run_with_caller_signal(
                            &cx,
                            &caller,
                            &factory_budget,
                            (config.factory)(&cx, lane_context),
                        )
                        .await
                        {
                            Ok(Ok(created)) => dispatcher = Some(created),
                            Ok(Err(err)) => {
                                // Prepared factories are generation-bound and
                                // one-shot. Stop this lane so the owning
                                // registry rebuilds it from a fresh generation
                                // on the next request instead of reusing a
                                // consumed factory forever.
                                if config.factory_error_is_terminal {
                                    close_state.request(DispatchCloseReason::RuntimeDrop);
                                }
                                let _ = reply.send_blocking(Outcome::Err(err));
                                return;
                            }
                            Err(error) => {
                                let outcome = request_run_error_outcome(
                                    error,
                                    close_state,
                                    lane_context,
                                    panic_auditor,
                                );
                                let _ = reply.send_blocking(outcome);
                                return;
                            }
                        }
                        if let Some(reason) = caller.reason().or_else(|| cx.cancel_reason()) {
                            close_state.request(DispatchCloseReason::OperatorCancel);
                            let _ = reply.send_blocking(Outcome::Cancelled(reason));
                            return;
                        }
                    }
                    let dispatcher = dispatcher.as_ref().expect("dispatcher initialized above");
                    let profile_timeout = match dispatcher.request_timeout_ceiling() {
                        Ok(timeout) => timeout,
                        Err(error) => {
                            let _ = reply.send_blocking(Outcome::Err(error));
                            return;
                        }
                    };
                    let dispatch_budget = request_budget
                        .tighten_timeout(tool_request_timeout_ceiling(profile_timeout, &args));
                    let borrowed_context = context
                        .as_dispatch_context()
                        .with_request_budget(&dispatch_budget);
                    let result = match run_with_caller_signal(
                        &cx,
                        &caller,
                        &dispatch_budget,
                        dispatcher.dispatch(&cx, borrowed_context, name.as_str(), args),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => request_run_error_outcome(
                            error,
                            close_state,
                            lane_context,
                            panic_auditor,
                        ),
                    };
                    let _ = reply.send_blocking(result);
                });
            }
            LaneCommand::DispatchStream {
                caller,
                enqueued_at,
                context,
                name,
                args,
                frames,
                reply,
            } => {
                runtime.block_on(async {
                    let cx = Cx::current().expect("lane runtime installs a stream command Cx");
                    let context = lane_command_context(&cx, &caller, enqueued_at, &context);
                    let request_budget = context
                        .as_dispatch_context()
                        .request_budget()
                        .cloned()
                        .expect("lane stream command installs a shared request budget");
                    let factory_budget = request_budget.tighten_timeout(
                        tool_request_timeout_ceiling(config.factory_request_timeout, &args),
                    );
                    if let Some(reason) = caller.reason() {
                        let _ = reply.send_blocking(Outcome::Cancelled(reason));
                        return;
                    }
                    if dispatcher.is_none() {
                        match run_with_caller_signal(
                            &cx,
                            &caller,
                            &factory_budget,
                            (config.factory)(&cx, lane_context),
                        )
                        .await
                        {
                            Ok(Ok(created)) => dispatcher = Some(created),
                            Ok(Err(err)) => {
                                if config.factory_error_is_terminal {
                                    close_state.request(DispatchCloseReason::RuntimeDrop);
                                }
                                let _ = reply.send_blocking(Outcome::Err(err));
                                return;
                            }
                            Err(error) => {
                                let outcome = request_run_error_outcome(
                                    error,
                                    close_state,
                                    lane_context,
                                    panic_auditor,
                                );
                                let _ = reply.send_blocking(outcome);
                                return;
                            }
                        }
                        if let Some(reason) = caller.reason().or_else(|| cx.cancel_reason()) {
                            close_state.request(DispatchCloseReason::OperatorCancel);
                            let _ = reply.send_blocking(Outcome::Cancelled(reason));
                            return;
                        }
                    }
                    let dispatcher = dispatcher.as_ref().expect("dispatcher initialized above");
                    let profile_timeout = match dispatcher.request_timeout_ceiling() {
                        Ok(timeout) => timeout,
                        Err(error) => {
                            let _ = reply.send_blocking(Outcome::Err(error));
                            return;
                        }
                    };
                    let dispatch_budget = request_budget
                        .tighten_timeout(tool_request_timeout_ceiling(profile_timeout, &args));
                    let borrowed_context = context
                        .as_dispatch_context()
                        .with_request_budget(&dispatch_budget);
                    let result = match run_with_caller_signal(
                        &cx,
                        &caller,
                        &dispatch_budget,
                        dispatcher.dispatch_stream(
                            &cx,
                            borrowed_context,
                            name.as_str(),
                            args,
                            frames,
                        ),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => request_run_error_outcome(
                            error,
                            close_state,
                            lane_context,
                            panic_auditor,
                        ),
                    };
                    let _ = reply.send_blocking(result);
                });
            }
            LaneCommand::SurfaceState {
                caller,
                enqueued_at,
                context,
                detail,
                reply,
            } => {
                runtime.block_on(async {
                    let cx = Cx::current().expect("lane runtime installs a surface command Cx");
                    let context = lane_command_context(&cx, &caller, enqueued_at, &context);
                    let request_budget = context
                        .as_dispatch_context()
                        .request_budget()
                        .cloned()
                        .expect("lane surface command installs a shared request budget");
                    let factory_budget =
                        request_budget.tighten_timeout(config.factory_request_timeout);
                    if let Some(reason) = caller.reason() {
                        let _ = reply.send_blocking(Outcome::Cancelled(reason));
                        return;
                    }
                    if dispatcher.is_none() {
                        match run_with_caller_signal(
                            &cx,
                            &caller,
                            &factory_budget,
                            (config.factory)(&cx, lane_context),
                        )
                        .await
                        {
                            Ok(Ok(created)) => dispatcher = Some(created),
                            Ok(Err(err)) => {
                                if config.factory_error_is_terminal {
                                    close_state.request(DispatchCloseReason::RuntimeDrop);
                                }
                                let _ = reply.send_blocking(Outcome::Err(err));
                                return;
                            }
                            Err(error) => {
                                let outcome = request_run_error_outcome(
                                    error,
                                    close_state,
                                    lane_context,
                                    panic_auditor,
                                );
                                let _ = reply.send_blocking(outcome);
                                return;
                            }
                        }
                        if let Some(reason) = caller.reason().or_else(|| cx.cancel_reason()) {
                            close_state.request(DispatchCloseReason::OperatorCancel);
                            let _ = reply.send_blocking(Outcome::Cancelled(reason));
                            return;
                        }
                    }
                    let dispatcher = dispatcher.as_ref().expect("dispatcher initialized above");
                    let profile_timeout = match dispatcher.request_timeout_ceiling() {
                        Ok(timeout) => timeout,
                        Err(error) => {
                            let _ = reply.send_blocking(Outcome::Err(error));
                            return;
                        }
                    };
                    let dispatch_budget = request_budget.tighten_timeout(profile_timeout);
                    let borrowed_context = context
                        .as_dispatch_context()
                        .with_request_budget(&dispatch_budget);
                    let result = match run_with_caller_signal(
                        &cx,
                        &caller,
                        &dispatch_budget,
                        dispatcher.mcp_surface_state(&cx, borrowed_context, detail),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => request_run_error_outcome(
                            error,
                            close_state,
                            lane_context,
                            panic_auditor,
                        ),
                    };
                    let _ = reply.send_blocking(result);
                });
            }
        }
    }
}

fn lane_command_context(
    cx: &Cx,
    caller: &LaneCallerSignal,
    enqueued_at: Instant,
    context: &OwnedDispatchContext,
) -> OwnedDispatchContext {
    let queue_wait = enqueued_at.elapsed();
    let total_wait = context
        .as_dispatch_context()
        .request_started_at()
        .map_or(queue_wait, |started_at| started_at.elapsed());
    let lane_now = cx.now();
    let elapsed_nanos = total_wait.as_nanos().min(u128::from(u64::MAX)) as u64;
    let admitted_at = lane_now.saturating_sub_nanos(elapsed_nanos);
    let caller_budget = caller.budget_for_lane(lane_now, queue_wait);
    // One shared application budget spans lazy dispatcher construction and
    // the eventual tool call. Admission carries the caller's deadline and the
    // service quota, but deliberately does not pre-apply the 30-second default:
    // the concrete dispatcher owns the active profile timeout and must be able
    // to select a configured ceiling above 30 seconds. Lane-owned factory and
    // surface work apply the default explicitly at their call sites below.
    let request_budget = RequestBudget::from_budget_at(
        admitted_at,
        Budget::new().with_poll_quota(DEFAULT_REQUEST_POLL_QUOTA),
    )
    .meet(caller_budget);
    context
        .as_dispatch_context()
        .with_admitted_at(admitted_at)
        .with_caller_budget(caller_budget)
        .with_request_budget(&request_budget)
        .to_owned_context()
}

async fn run_with_request_budget<F>(
    lane_cx: &Cx,
    budget: &RequestBudget,
    caller: Option<&LaneCallerSignal>,
    future: F,
) -> Result<F::Output, RequestRunError>
where
    F: Future,
{
    run_with_request_budget_and_finalization_budget(
        lane_cx,
        budget,
        caller,
        future,
        RequestBudget::fresh_cleanup,
    )
    .await
}

async fn run_with_request_budget_and_finalization_budget<F, B>(
    lane_cx: &Cx,
    budget: &RequestBudget,
    caller: Option<&LaneCallerSignal>,
    future: F,
    make_finalization_budget: B,
) -> Result<F::Output, RequestRunError>
where
    F: Future,
    B: FnOnce(Time) -> RequestBudget,
{
    let mut future = std::pin::pin!(future);
    let mut future_was_polled = false;
    let initial = {
        let driven = std::future::poll_fn(|task_cx| {
            if let Some(caller) = caller {
                caller.register_lane_waker(task_cx.waker());
                // Close the check/register race: cancellation after the first
                // check either appears here or wakes the registered lane waker.
                if let Some(reason) = caller.reason() {
                    if lane_cx.cancel_reason().is_none() {
                        lane_cx.set_cancel_reason(reason.clone());
                    }
                    return Poll::Ready(Err(reason));
                }
            }
            // Asupersync 0.3.5 does not decrement nonzero Cx poll/cost fields.
            // Charge the shared application quota explicitly on every poll.
            // Interruption ends only the normal phase; the same pinned future
            // is retained below for bounded terminal finalization.
            if budget.enforce(lane_cx).is_err() {
                let reason = lane_cx
                    .cancel_reason()
                    .unwrap_or_else(CancelReason::timeout);
                if lane_cx.cancel_reason().is_none() {
                    lane_cx.set_cancel_reason(reason.clone());
                }
                return Poll::Ready(Err(reason));
            }
            future_was_polled = true;
            match future.as_mut().poll(task_cx) {
                Poll::Ready(output) => Poll::Ready(Ok(output)),
                Poll::Pending => Poll::Pending,
            }
        });

        match budget.deadline() {
            Some(deadline) => match asupersync::time::timeout_at(deadline, driven).await {
                Ok(result) => result,
                Err(_) => Err(CancelReason::timeout()),
            },
            None => driven.await,
        }
    };

    let reason = match initial {
        Ok(output) => return Ok(output),
        Err(reason) => reason,
    };
    if lane_cx.cancel_reason().is_none() {
        lane_cx.set_cancel_reason(reason.clone());
    }

    if !future_was_polled {
        return Err(RequestRunError::InterruptedBeforeStart { reason });
    }

    // Dropping the future at the request deadline can strand a commit/DDL
    // between its database effect and terminal audit/intent record. Give the
    // already-cancelled future one fresh, short finalization window. It cannot
    // start another request-budgeted wire operation, but its masked rollback,
    // driver drain, durable terminal record, and response classification can
    // complete. Close cleanup itself already owns a fresh budget and must not
    // recursively gain another window.
    if caller.is_none() {
        return Err(RequestRunError::FinalizationTimeout { reason });
    }
    let finalization_budget = make_finalization_budget(lane_cx.now());
    let finalize = std::future::poll_fn(|task_cx| {
        if finalization_budget.enforce_at(lane_cx.now()).is_err() {
            return Poll::Ready(None);
        }
        match future.as_mut().poll(task_cx) {
            Poll::Ready(output) => Poll::Ready(Some(output)),
            Poll::Pending => Poll::Pending,
        }
    });
    match finalization_budget.deadline() {
        Some(deadline) => match asupersync::time::timeout_at(deadline, finalize).await {
            Ok(Some(output)) => Ok(output),
            Ok(None) | Err(_) => Err(RequestRunError::FinalizationTimeout { reason }),
        },
        None => finalize
            .await
            .ok_or(RequestRunError::FinalizationTimeout { reason }),
    }
}

#[derive(Debug)]
enum RequestRunError {
    InterruptedBeforeStart { reason: CancelReason },
    FinalizationTimeout { reason: CancelReason },
}

fn request_run_error_outcome<T>(
    error: RequestRunError,
    close_state: &LaneCloseState,
    lane_context: &LaneContext,
    auditor: Option<&Auditor>,
) -> Outcome<T, ErrorEnvelope> {
    match error {
        RequestRunError::InterruptedBeforeStart { reason } => Outcome::Cancelled(reason),
        RequestRunError::FinalizationTimeout { reason } => {
            close_state.request(DispatchCloseReason::RequestFinalizationTimeout);
            // The outward reply must never outrun the durable unknown-outcome
            // record. Dispatcher-specific lifecycle cleanup runs afterward and
            // may add richer evidence, but this generic record covers factory
            // timeouts where no dispatcher exists yet.
            let audit_succeeded = audit_lane_finalization_timeout(lane_context.lane_id(), auditor);
            finalization_timeout_outcome(reason, !audit_succeeded)
        }
    }
}

fn terminal_reply_wait_expired_outcome<T>(
    lane_name: &str,
    close_state: &LaneCloseState,
    auditor: Option<&Auditor>,
    reason: CancelReason,
) -> Outcome<T, ErrorEnvelope> {
    close_state.request(DispatchCloseReason::RequestFinalizationTimeout);
    let audit_succeeded = audit_lane_finalization_timeout(lane_name, auditor);
    finalization_timeout_outcome(reason, !audit_succeeded)
}

fn finalization_timeout_outcome<T>(
    reason: CancelReason,
    audit_failed: bool,
) -> Outcome<T, ErrorEnvelope> {
    let mut envelope = ErrorEnvelope::new(
        ErrorClass::RuntimeStateRequired,
        format!(
            "request cancellation could not safely finalize the active Oracle operation: {reason}"
        ),
    )
    .with_next_step("the stateful lane was discarded and must not be reused")
    .with_next_step(
        "do not retry non-idempotent work until its audit and write-intent outcome is verified",
    );
    if audit_failed {
        envelope = envelope.with_next_step(
            "the durable lane audit append also failed; verify database and audit storage manually",
        );
    }
    Outcome::Err(envelope)
}

async fn run_with_caller_signal<F>(
    lane_cx: &Cx,
    caller: &LaneCallerSignal,
    budget: &RequestBudget,
    future: F,
) -> Result<F::Output, RequestRunError>
where
    F: Future,
{
    run_with_request_budget(lane_cx, budget, Some(caller), future).await
}

fn close_lane_dispatcher_on_runtime(
    runtime: &Runtime,
    dispatcher: Option<&dyn ToolDispatch>,
    lane_context: &LaneContext,
    reason: DispatchCloseReason,
) {
    // block-on-boundary: cleanup receives a fresh lane-owned Cx independent of
    // any cancelled/expired request command.
    runtime.block_on(async {
        let cx = Cx::current().expect("lane runtime installs a cleanup Cx");
        let cleanup_budget = RequestBudget::fresh_cleanup(cx.now());
        if run_with_request_budget(
            &cx,
            &cleanup_budget,
            None,
            close_lane_dispatcher(dispatcher, &cx, lane_context, reason),
        )
        .await
        .is_err()
        {
            tracing::warn!(
                lane = %lane_context.lane_id(),
                close_reason = reason.as_str(),
                "stateful lane dispatcher cleanup exceeded its fresh bounded budget; lane state will be discarded"
            );
        }
    });
}

async fn close_lane_dispatcher(
    dispatcher: Option<&dyn ToolDispatch>,
    cx: &Cx,
    lane_context: &LaneContext,
    reason: DispatchCloseReason,
) {
    if let Some(dispatcher) = dispatcher
        && let Err(err) = dispatcher.close(cx, reason).await
    {
        tracing::warn!(
            lane = %lane_context.lane_id(),
            close_reason = reason.as_str(),
            error_class = ?err.error_class,
            error = %err.message,
            "stateful lane dispatcher cleanup returned an error"
        );
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

    use asupersync::Budget;
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

    struct BlockingCloseRecordingDispatch {
        entered: std_mpsc::Sender<thread::ThreadId>,
        release: Mutex<std_mpsc::Receiver<()>>,
        close_reasons: Arc<Mutex<Vec<DispatchCloseReason>>>,
    }

    impl ToolDispatch for BlockingCloseRecordingDispatch {
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

    #[derive(Debug)]
    struct CallerContextRecord {
        task_id: String,
        explicit_deadline: Option<Time>,
        ambient_deadline: Option<Time>,
        admitted_at: Option<Time>,
        caller_budget: Option<Budget>,
    }

    struct CallerContextDispatch {
        records: std_mpsc::Sender<CallerContextRecord>,
    }

    impl ToolDispatch for CallerContextDispatch {
        fn dispatch<'a>(
            &'a self,
            cx: &'a Cx,
            context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                self.records
                    .send(CallerContextRecord {
                        task_id: format!("{:?}", cx.task_id()),
                        explicit_deadline: cx.budget().deadline,
                        ambient_deadline: Cx::current()
                            .and_then(|ambient| ambient.budget().deadline),
                        admitted_at: context.admitted_at(),
                        caller_budget: context.caller_budget(),
                    })
                    .expect("test waits for caller context record");
                Outcome::Ok(json!({ "entered": true }))
            })
        }
    }

    struct QueueTimingDispatch {
        first_entered: std_mpsc::Sender<()>,
        release_first: Mutex<std_mpsc::Receiver<()>>,
        queue_timing: std_mpsc::Sender<(u64, u64)>,
    }

    impl ToolDispatch for QueueTimingDispatch {
        fn dispatch<'a>(
            &'a self,
            cx: &'a Cx,
            context: DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                if name == "first" {
                    self.first_entered
                        .send(())
                        .expect("test coordinator waits for first lane command");
                    self.release_first
                        .lock()
                        .recv()
                        .expect("test coordinator releases first lane command");
                } else {
                    let admitted_at = context
                        .admitted_at()
                        .expect("lane stamps each admitted command");
                    let lane_now = cx.now();
                    let deadline_remaining = context
                        .caller_budget()
                        .and_then(|budget| budget.deadline)
                        .expect("queued test caller has a deadline")
                        .duration_since(lane_now);
                    self.queue_timing
                        .send((lane_now.duration_since(admitted_at), deadline_remaining))
                        .expect("test coordinator waits for queue duration");
                }
                Outcome::Ok(json!({ "name": name }))
            })
        }
    }

    struct MidFlightCancellationDispatch {
        entered: std_mpsc::Sender<()>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
        observed_cancel: std_mpsc::Sender<bool>,
    }

    struct LateTerminalCancellationDispatch {
        entered: std_mpsc::Sender<()>,
        finalized: std_mpsc::Sender<()>,
    }

    impl ToolDispatch for LateTerminalCancellationDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            if name == "healthy-after-terminal" {
                return Box::pin(async { Outcome::Ok(json!({ "healthy": true })) });
            }
            let mut started = false;
            Box::pin(std::future::poll_fn(move |_task_cx| {
                if !started {
                    started = true;
                    self.entered
                        .send(())
                        .expect("test waits for late-terminal dispatcher entry");
                    return Poll::Pending;
                }
                self.finalized
                    .send(())
                    .expect("test waits for late terminal classification");
                Poll::Ready(Outcome::Ok(json!({
                    "committed": true,
                    "audited": true
                })))
            }))
        }
    }

    struct AdmissionTimingDispatch {
        observed: std_mpsc::Sender<u64>,
    }

    struct LifecycleRaceDispatch {
        executions: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ToolDispatch for LifecycleRaceDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Outcome::Ok(json!({ "executed": true })) })
        }
    }

    struct LifecycleRaceHarness {
        registry: Arc<StatefulLaneDispatch>,
        builder_entered: Arc<std::sync::Barrier>,
        release_builder: Arc<std::sync::Barrier>,
        admission: Arc<AdmissionController>,
        builder_runs: Arc<std::sync::atomic::AtomicUsize>,
        factory_runs: Arc<std::sync::atomic::AtomicUsize>,
        dispatch_runs: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl LifecycleRaceHarness {
        fn new() -> Self {
            let builder_entered = Arc::new(std::sync::Barrier::new(2));
            let release_builder = Arc::new(std::sync::Barrier::new(2));
            let builder_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let factory_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let dispatch_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let entered = Arc::clone(&builder_entered);
            let release = Arc::clone(&release_builder);
            let counted_builders = Arc::clone(&builder_runs);
            let counted_factories = Arc::clone(&factory_runs);
            let counted_dispatches = Arc::clone(&dispatch_runs);
            let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
                let attempt = counted_builders.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    entered.wait();
                    release.wait();
                }
                let factory_runs = Arc::clone(&counted_factories);
                let dispatch_runs = Arc::clone(&counted_dispatches);
                let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
                    factory_runs.fetch_add(1, Ordering::SeqCst);
                    let dispatcher: Arc<dyn ToolDispatch> = Arc::new(LifecycleRaceDispatch {
                        executions: Arc::clone(&dispatch_runs),
                    });
                    Box::pin(async move { Ok(dispatcher) })
                });
                Ok(PreparedLaneDispatch::new(factory, DEFAULT_REQUEST_TIMEOUT))
            });
            let admission = Arc::new(AdmissionController::with_reserved(2, 10, 1, 0));
            let registry = Arc::new(
                StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None)
                    .with_admission_controller(Arc::clone(&admission)),
            );
            Self {
                registry,
                builder_entered,
                release_builder,
                admission,
                builder_runs,
                factory_runs,
                dispatch_runs,
            }
        }

        fn spawn_dispatch(
            &self,
            session_id: &str,
            principal_key: &str,
        ) -> JoinHandle<DispatchOutcome> {
            let registry = Arc::clone(&self.registry);
            let session_id = session_id.to_owned();
            let principal_key = principal_key.to_owned();
            thread::spawn(move || {
                block_on_lane_bridge(async {
                    let cx = Cx::current().expect("bridge installs Cx");
                    registry
                        .dispatch(
                            &cx,
                            DispatchContext::default()
                                .with_http_session_id(&session_id)
                                .with_principal_key(&principal_key),
                            "lifecycle-race",
                            Value::Null,
                        )
                        .await
                })
            })
        }

        fn assert_invalidated(
            &self,
            caller: JoinHandle<DispatchOutcome>,
            reason: DispatchCloseReason,
        ) {
            self.release_builder.wait();
            let outcome = caller.join().expect("lane resolution caller joined");
            let Outcome::Err(error) = outcome else {
                panic!("lifecycle-closed resolution must fail: {outcome:?}");
            };
            assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
            assert!(error.message.contains(reason.as_str()), "{error:?}");
            assert_eq!(self.registry.lane_count(), 0);
            assert_eq!(self.builder_runs.load(Ordering::SeqCst), 1);
            assert_eq!(self.factory_runs.load(Ordering::SeqCst), 0);
            assert_eq!(self.dispatch_runs.load(Ordering::SeqCst), 0);
            assert_eq!(
                self.admission.available_global(),
                self.admission.regular_global_cap(),
                "invalidated creation must release its capacity permit",
            );
        }
    }

    struct NeverFinalizesDispatch {
        entered: std_mpsc::Sender<()>,
    }

    impl ToolDispatch for NeverFinalizesDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            let mut started = false;
            Box::pin(std::future::poll_fn(move |task_cx| {
                if !started {
                    started = true;
                    self.entered
                        .send(())
                        .expect("test waits for uncooperative operation start");
                    return Poll::Pending;
                }
                task_cx.waker().wake_by_ref();
                Poll::Pending
            }))
        }
    }

    impl ToolDispatch for AdmissionTimingDispatch {
        fn dispatch<'a>(
            &'a self,
            cx: &'a Cx,
            context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                let admitted_at = context
                    .admitted_at()
                    .expect("stateful wrapper carries its pre-resolution start");
                self.observed
                    .send(cx.now().duration_since(admitted_at))
                    .expect("test waits for admission timing");
                Outcome::Ok(json!({ "timed": true }))
            })
        }
    }

    impl ToolDispatch for MidFlightCancellationDispatch {
        fn dispatch<'a>(
            &'a self,
            cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async move {
                if name != "cancel-midflight" {
                    return match cx.checkpoint() {
                        Ok(()) => Outcome::Ok(json!({ "healthy": true })),
                        Err(_) => Outcome::Cancelled(cancel_reason_from_cx(
                            cx,
                            "fresh lane command unexpectedly cancelled",
                        )),
                    };
                }
                self.entered
                    .send(())
                    .expect("test waits for dispatcher entry");
                let mut release = self
                    .release
                    .lock()
                    .take()
                    .expect("one cancellation probe per dispatcher");
                let _ = release.recv(cx).await;
                let cancelled = cx.checkpoint().is_err();
                self.observed_cancel
                    .send(cancelled)
                    .expect("test waits for dispatcher cancellation observation");
                if cancelled {
                    Outcome::Cancelled(cancel_reason_from_cx(
                        cx,
                        "caller cancelled during lane execution",
                    ))
                } else {
                    Outcome::Ok(json!({ "cancelled": false }))
                }
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

    fn wait_for_close_requested(lane: &LaneRuntime) {
        for _ in 0..50 {
            if lane.inner.close_state.is_requested() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("lane close request was not published");
    }

    fn testing_cx_with_timeout(timeout: Duration) -> Cx {
        let clock = Cx::for_testing();
        Cx::for_testing_with_budget(
            Budget::new()
                .with_timeout(clock.now(), timeout)
                .with_poll_quota(10_000),
        )
    }

    #[test]
    fn ready_terminal_reply_wins_simultaneous_caller_cancellation() {
        let received = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs a caller Cx");
            let (reply_tx, mut reply_rx) = oneshot::channel();
            reply_tx
                .send_blocking("terminal-outcome")
                .expect("lane terminal reply is buffered");
            cx.set_cancel_requested(true);

            recv_lane_reply(&cx, &mut reply_rx).await
        });

        assert_eq!(
            received.expect("a ready terminal result outranks simultaneous cancellation"),
            "terminal-outcome"
        );
    }

    #[test]
    fn lane_admission_does_not_preclamp_longer_profile_timeout() {
        let caller_cx = testing_cx_with_timeout(Duration::from_secs(60));
        let lane_cx = Cx::for_testing();
        let caller = LaneCallerSignal::new(&caller_cx);
        let context = lane_command_context(
            &lane_cx,
            &caller,
            Instant::now(),
            &OwnedDispatchContext::default(),
        );
        let admitted_at = context
            .as_dispatch_context()
            .admitted_at()
            .expect("lane stamps request admission");
        let root = context
            .as_dispatch_context()
            .request_budget()
            .expect("lane installs a shared root budget")
            .clone();

        let root_deadline = root.deadline().expect("caller deadline reaches the lane");
        assert!(
            root_deadline.duration_since(admitted_at) >= 59_000_000_000,
            "lane admission preserves the approximately 60s caller ceiling instead of pre-clamping every profile to 30s"
        );
        let factory = root.tighten_timeout(Duration::from_secs(60));
        assert_eq!(
            factory.deadline(),
            Some(root_deadline),
            "a resolved 60s profile also governs lazy factory work without a hidden 30s clamp"
        );

        let quota_before_factory = root.budget().poll_quota;
        factory
            .enforce_at(admitted_at)
            .expect("factory consumes one shared checkpoint");
        let profile = root.tighten_timeout(Duration::from_secs(60));
        assert_eq!(
            profile.deadline(),
            Some(root_deadline),
            "a 60s active profile remains selectable up to the caller's slightly earlier captured deadline"
        );
        assert_eq!(
            profile.budget().poll_quota,
            quota_before_factory - 1,
            "factory and tool budgets must consume the same shared request quota"
        );
    }

    #[test]
    fn per_tool_timeout_tightens_profile_ceiling_before_factory_or_dispatch() {
        let args = serde_json::json!({ "timeout_seconds": 7 });
        assert_eq!(
            tool_request_timeout_ceiling(Duration::from_secs(60), &args),
            Duration::from_secs(7),
        );
        assert_eq!(
            tool_request_timeout_ceiling(Duration::from_secs(3), &args),
            Duration::from_secs(3),
            "a tool override cannot widen the active profile ceiling",
        );
        assert_eq!(
            tool_request_timeout_ceiling(
                Duration::from_secs(60),
                &serde_json::json!({ "timeout_seconds": 99_999 }),
            ),
            Duration::from_secs(60),
            "a clamped tool override still cannot widen the active profile ceiling",
        );
    }

    #[test]
    fn interrupted_request_retains_same_future_through_terminal_completion() {
        let (terminal, poll_count) = block_on_lane_bridge(async {
            let lane_cx = Cx::current().expect("bridge installs a lane Cx");
            let caller = Arc::new(LaneCallerSignal::new(&lane_cx));
            let request_budget =
                RequestBudget::from_call_timeout(lane_cx.now(), Some(Duration::from_secs(1)));
            let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let future_polls = Arc::clone(&polls);
            let interrupt = Arc::clone(&caller);

            let terminal = match run_with_caller_signal(
                &lane_cx,
                &caller,
                &request_budget,
                std::future::poll_fn(move |_task_cx| {
                    if future_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                        interrupt.cancel(CancelReason::user(
                            "test interruption after the operation started",
                        ));
                        Poll::Pending
                    } else {
                        Poll::Ready("durable-terminal-outcome")
                    }
                }),
            )
            .await
            {
                Ok(terminal) => terminal,
                Err(_) => {
                    panic!("the retained future must complete inside its finalization window")
                }
            };

            (terminal, polls.load(Ordering::SeqCst))
        });

        assert_eq!(terminal, "durable-terminal-outcome");
        assert_eq!(
            poll_count, 2,
            "the operation is polled once before interruption and the same future once more to finalize"
        );
    }

    #[test]
    fn interruption_before_first_poll_never_starts_the_future() {
        let cancelled_polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancelled_observer = Arc::clone(&cancelled_polls);
        let cancelled = block_on_lane_bridge(async {
            let lane_cx = Cx::current().expect("bridge installs a lane Cx");
            let caller = Arc::new(LaneCallerSignal::new(&lane_cx));
            caller.cancel(CancelReason::user("cancelled before operation start"));
            let request_budget =
                RequestBudget::from_call_timeout(lane_cx.now(), Some(Duration::from_secs(1)));
            run_with_caller_signal(
                &lane_cx,
                &caller,
                &request_budget,
                std::future::poll_fn(move |_task_cx| {
                    cancelled_observer.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(())
                }),
            )
            .await
        });
        assert!(matches!(
            cancelled,
            Err(RequestRunError::InterruptedBeforeStart { .. })
        ));
        assert_eq!(cancelled_polls.load(Ordering::SeqCst), 0);

        let exhausted_polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let exhausted_observer = Arc::clone(&exhausted_polls);
        let exhausted = block_on_lane_bridge(async {
            let lane_cx = Cx::current().expect("bridge installs a lane Cx");
            let caller = Arc::new(LaneCallerSignal::new(&lane_cx));
            let request_budget =
                RequestBudget::from_budget_at(lane_cx.now(), Budget::new().with_poll_quota(0));
            run_with_caller_signal(
                &lane_cx,
                &caller,
                &request_budget,
                std::future::poll_fn(move |_task_cx| {
                    exhausted_observer.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(())
                }),
            )
            .await
        });
        assert!(matches!(
            exhausted,
            Err(RequestRunError::InterruptedBeforeStart { .. })
        ));
        assert_eq!(exhausted_polls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn factory_budget_exhaustion_does_not_poison_next_lane_command() {
        let factory_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_factory_polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_runs = Arc::clone(&factory_runs);
        let counted_polls = Arc::clone(&first_factory_polls);
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |cx, _lane_context| {
            let attempt = counted_runs.fetch_add(1, Ordering::SeqCst);
            let counted_polls = Arc::clone(&counted_polls);
            Box::pin(async move {
                if attempt == 0 {
                    return std::future::poll_fn(move |task_cx| {
                        counted_polls.fetch_add(1, Ordering::SeqCst);
                        if cx.checkpoint().is_err() {
                            Poll::Ready(Err(ErrorEnvelope::new(
                                ErrorClass::RuntimeStateRequired,
                                "factory observed request-budget cancellation",
                            )))
                        } else {
                            task_cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                }
                Ok(Arc::new(EchoThreadDispatch) as Arc<dyn ToolDispatch>)
            })
        });
        let lane = LaneRuntime::spawn_with_dispatch_factory(
            "factory-budget-recovery",
            LaneContext::process_shared("factory-budget-recovery"),
            factory,
            DEFAULT_REQUEST_TIMEOUT,
            4,
            None,
        );
        let constrained_cx = Cx::for_testing_with_budget(Budget::new().with_poll_quota(4));

        let first = block_on_lane_bridge(async {
            lane.dispatch(
                &constrained_cx,
                DispatchContext::default(),
                "first",
                Value::Null,
            )
            .await
        });
        match first {
            Outcome::Err(error) => assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired),
            other => panic!("the exhausted factory request must terminate explicitly: {other:?}"),
        }
        assert!(
            first_factory_polls.load(Ordering::SeqCst) >= 2,
            "the first factory must start before its shared request budget interrupts it"
        );

        let second = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs an independent caller Cx");
            lane.dispatch(&cx, DispatchContext::default(), "second", Value::Null)
                .await
        });
        assert!(
            matches!(second, Outcome::Ok(_)),
            "a fresh command must receive a fresh lane Cx after factory interruption: {second:?}"
        );
        assert_eq!(factory_runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn uncooperative_finalizer_is_runtime_state_required_and_requests_unknown_lane_close() {
        let (outcome, requested_reason, close_reasons) = block_on_lane_bridge(async {
            let lane_cx = Cx::current().expect("bridge installs a lane Cx");
            let caller = Arc::new(LaneCallerSignal::new(&lane_cx));
            let request_budget =
                RequestBudget::from_call_timeout(lane_cx.now(), Some(Duration::from_secs(1)));
            let cancel_after_start = Arc::clone(&caller);

            let timeout = run_with_request_budget_and_finalization_budget(
                &lane_cx,
                &request_budget,
                Some(&caller),
                std::future::poll_fn(move |task_cx| {
                    cancel_after_start
                        .cancel(CancelReason::user("test caller disconnected after start"));
                    task_cx.waker().wake_by_ref();
                    Poll::<()>::Pending
                }),
                |now| RequestBudget::from_call_timeout(now, Some(Duration::from_millis(10))),
            )
            .await
            .expect_err("an uncooperative finalizer must hit its independent hard bound");

            let close_state = LaneCloseState::new();
            close_state.request(DispatchCloseReason::RequestFinalizationTimeout);
            let close_reasons = Arc::new(Mutex::new(Vec::new()));
            let dispatcher = CloseRecordingDispatch {
                close_reasons: Arc::clone(&close_reasons),
            };
            close_lane_dispatcher(
                Some(&dispatcher),
                &lane_cx,
                &LaneContext::process_shared("finalization-timeout-test"),
                DispatchCloseReason::RequestFinalizationTimeout,
            )
            .await;

            let RequestRunError::FinalizationTimeout { reason } = timeout else {
                panic!("the already-started operation must enter bounded finalization")
            };
            (
                finalization_timeout_outcome::<Value>(reason, false),
                close_state.requested_reason(),
                close_reasons.lock().clone(),
            )
        });

        match outcome {
            Outcome::Err(error) => {
                assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
                assert!(
                    error.message.contains("could not safely finalize"),
                    "terminal error must explain that outcome classification is unavailable: {error:?}"
                );
                assert!(
                    error
                        .next_steps
                        .iter()
                        .any(|step| step.contains("do not retry non-idempotent work")),
                    "unsafe automatic retries must be explicitly refused: {error:?}"
                );
            }
            other => panic!("uncooperative finalization must fail closed, got {other:?}"),
        }
        assert_eq!(
            requested_reason,
            Some(DispatchCloseReason::RequestFinalizationTimeout)
        );
        assert_eq!(
            close_reasons,
            vec![DispatchCloseReason::RequestFinalizationTimeout],
            "the concrete dispatcher receives the reason that forces unknown/discarded handling"
        );
    }

    #[test]
    fn terminal_finalization_charges_its_fresh_poll_quota() {
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_polls = Arc::clone(&polls);
        let started = Instant::now();
        let result = block_on_lane_bridge(async {
            let lane_cx = Cx::current().expect("bridge installs a lane Cx");
            let caller = Arc::new(LaneCallerSignal::new(&lane_cx));
            let request_budget =
                RequestBudget::from_call_timeout(lane_cx.now(), Some(Duration::from_secs(1)));
            let cancel_after_start = Arc::clone(&caller);

            run_with_request_budget_and_finalization_budget(
                &lane_cx,
                &request_budget,
                Some(&caller),
                std::future::poll_fn(move |task_cx| {
                    if observed_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                        cancel_after_start.cancel(CancelReason::user(
                            "test caller disconnected after operation start",
                        ));
                    }
                    task_cx.waker().wake_by_ref();
                    Poll::Pending::<()>
                }),
                |now| {
                    RequestBudget::from_budget_at(
                        now,
                        Budget::new()
                            .with_timeout(now, Duration::from_secs(1))
                            .with_poll_quota(1),
                    )
                },
            )
            .await
        });

        assert!(result.is_err(), "spent finalization quota is a hard stop");
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "one initial poll starts the operation and the one-unit fresh quota permits exactly one finalization poll",
        );
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "quota exhaustion must stop a self-waking finalizer before its one-second wall deadline",
        );
    }

    #[test]
    fn finalization_timeout_audit_is_flushed_before_caller_receives_error() {
        let memory_sink = Arc::new(MemoryAuditSink::new());
        let auditor = Arc::new(Auditor::new(
            Box::new(SharedAuditSink(Arc::clone(&memory_sink))),
            SigningKey::new("test-key", b"test-secret-for-finalization-timeout".to_vec())
                .expect("valid test key"),
        ));
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn_default_with_panic_auditor(
            "finalization-audit-order",
            Arc::new(NeverFinalizesDispatch {
                entered: entered_tx,
            }),
            Some(auditor),
        );
        let caller_cx = Cx::for_testing();
        let thread_cx = caller_cx.clone();
        let thread_lane = lane.clone();
        let call = thread::spawn(move || {
            block_on_lane_bridge(async move {
                thread_lane
                    .dispatch(
                        &thread_cx,
                        DispatchContext::default(),
                        "never-finalizes",
                        Value::Null,
                    )
                    .await
            })
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("operation starts before cancellation");
        caller_cx.set_cancel_requested(true);
        call.thread().unpark();
        match call.join().expect("caller receives terminal error") {
            Outcome::Err(error) => {
                assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
                assert!(error.message.contains("could not safely finalize"));
            }
            other => panic!("hard finalization failure must be explicit: {other:?}"),
        }

        let records = memory_sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(memory_sink.flush_count(), 1);
        assert_eq!(records[0].agent_identity, "lane:finalization-audit-order");
        assert_eq!(
            records[0].sql_preview,
            "<sql text redacted; see sql_sha256>",
        );
        assert_eq!(
            records[0].sql_sha256,
            oraclemcp_audit::sha256_hex(b"LANE_FINALIZATION_TIMEOUT_UNKNOWN_DISCARDED")
        );
        assert_eq!(records[0].outcome, AuditOutcome::UnknownDiscarded);
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
    fn close_requested_with_full_mailbox_preempts_queued_work() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let close_reasons = Arc::new(Mutex::new(Vec::new()));
        let lane = LaneRuntime::spawn(
            "full-mailbox-close",
            Arc::new(BlockingCloseRecordingDispatch {
                entered: entered_tx,
                release: Mutex::new(release_rx),
                close_reasons: Arc::clone(&close_reasons),
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
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first call reached the lane");

        let second_call = {
            let lane = lane.clone();
            thread::spawn(move || {
                block_on_lane_bridge(async move {
                    let cx = Cx::current().expect("bridge installs Cx");
                    lane.dispatch(&cx, DispatchContext::default(), "second", Value::Null)
                        .await
                })
            })
        };
        wait_for_queued_lane_command(&lane);

        let lane_for_close = lane.clone();
        let (closed_tx, closed_rx) = std_mpsc::channel();
        thread::spawn(move || {
            lane_for_close.close_with_reason(DispatchCloseReason::ServerShutdown);
            closed_tx.send(()).expect("test waits for close completion");
        });
        wait_for_close_requested(&lane);

        release_tx.send(()).expect("release first call");
        first_call.join().expect("first caller joined");

        let second_entry = entered_rx.recv_timeout(Duration::from_millis(100));
        if second_entry.is_ok() {
            let _ = release_tx.send(());
        }
        assert!(
            second_entry.is_err(),
            "queued work must not enter the dispatcher after close is requested"
        );

        closed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("close completes after active dispatch returns");
        assert_eq!(lane.status(), LaneRuntimeStatus::Stopped);
        assert_eq!(
            close_reasons.lock().as_slice(),
            &[DispatchCloseReason::ServerShutdown]
        );

        match second_call.join().expect("second caller joined") {
            Outcome::Err(err) => assert_eq!(err.error_class, ErrorClass::RuntimeStateRequired),
            other => panic!("queued call should fail as stopped, got {other:?}"),
        }
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
    fn lane_mints_fresh_task_local_context_for_each_command() {
        let (records_tx, records_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "caller-budget-isolation",
            Arc::new(CallerContextDispatch {
                records: records_tx,
            }),
            4,
        );
        let first_cx = testing_cx_with_timeout(Duration::from_secs(5));
        let second_cx = testing_cx_with_timeout(Duration::from_secs(30));
        let first_deadline = first_cx.budget().deadline;
        let second_deadline = second_cx.budget().deadline;
        assert_ne!(first_deadline, second_deadline);

        let first = block_on_lane_bridge(async {
            lane.dispatch(&first_cx, DispatchContext::default(), "first", Value::Null)
                .await
        });
        let second = block_on_lane_bridge(async {
            lane.dispatch(
                &second_cx,
                DispatchContext::default(),
                "second",
                Value::Null,
            )
            .await
        });
        assert!(matches!(first, Outcome::Ok(_)));
        assert!(matches!(second, Outcome::Ok(_)));

        let first_record = records_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first command records its caller context");
        let second_record = records_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second command records its caller context");
        assert_ne!(
            first_record.task_id, second_record.task_id,
            "consecutive lane commands must not share task identity or cancellation state"
        );
        assert_eq!(first_record.explicit_deadline, None);
        assert_eq!(second_record.explicit_deadline, None);
        assert_eq!(first_record.ambient_deadline, None);
        assert_eq!(second_record.ambient_deadline, None);
        let first_admitted_at = first_record.admitted_at.expect("first lane admission time");
        let second_admitted_at = second_record
            .admitted_at
            .expect("second lane admission time");
        let first_budget = first_record
            .caller_budget
            .expect("first caller budget reaches lane execution");
        let second_budget = second_record
            .caller_budget
            .expect("second caller budget reaches lane execution");
        assert_eq!(first_budget.poll_quota, 10_000);
        assert_eq!(second_budget.poll_quota, 10_000);
        assert!(
            first_budget
                .deadline
                .expect("first caller deadline")
                .duration_since(first_admitted_at)
                >= 4_000_000_000
        );
        assert!(
            second_budget
                .deadline
                .expect("second caller deadline")
                .duration_since(second_admitted_at)
                >= 29_000_000_000
        );
    }

    #[test]
    fn caller_cancellation_during_lane_execution_reaches_dispatcher() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (_release_tx, release_rx) = oneshot::channel();
        let (observed_tx, observed_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "caller-midflight-cancel",
            Arc::new(MidFlightCancellationDispatch {
                entered: entered_tx,
                release: Mutex::new(Some(release_rx)),
                observed_cancel: observed_tx,
            }),
            4,
        );
        let caller_cx = Cx::for_testing();
        let thread_cx = caller_cx.clone();
        let thread_lane = lane.clone();
        let call = thread::spawn(move || {
            block_on_lane_bridge(async move {
                thread_lane
                    .dispatch(
                        &thread_cx,
                        DispatchContext::default(),
                        "cancel-midflight",
                        Value::Null,
                    )
                    .await
            })
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("caller command entered the dispatcher");
        caller_cx.set_cancel_requested(true);
        // `block_on_lane_bridge` polls its root future directly rather than as
        // a scheduler-owned task, so its synthetic test Cx has no scheduler
        // cancellation wake edge. Unpark once to model the wake a real runtime
        // task receives when its region is cancelled.
        call.thread().unpark();
        assert!(
            observed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("dispatcher reports whether it observed cancellation"),
            "lane dispatcher must receive the caller's cancellation through the task-local bridge"
        );
        assert!(matches!(
            call.join().expect("caller thread joined"),
            Outcome::Cancelled(_)
        ));

        let healthy = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs a fresh caller Cx");
            lane.dispatch(
                &cx,
                DispatchContext::default(),
                "healthy-after-cancel",
                Value::Null,
            )
            .await
        });
        assert!(
            matches!(healthy, Outcome::Ok(_)),
            "one command's cancellation must not poison the next lane command: {healthy:?}"
        );
    }

    #[test]
    fn caller_cancellation_waits_for_late_terminal_classification() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (finalized_tx, finalized_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "late-terminal-cancel",
            Arc::new(LateTerminalCancellationDispatch {
                entered: entered_tx,
                finalized: finalized_tx,
            }),
            4,
        );
        let caller_cx = Cx::for_testing();
        let thread_cx = caller_cx.clone();
        let thread_lane = lane.clone();
        let call = thread::spawn(move || {
            block_on_lane_bridge(async move {
                thread_lane
                    .dispatch(
                        &thread_cx,
                        DispatchContext::default(),
                        "late-terminal",
                        Value::Null,
                    )
                    .await
            })
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("operation starts before caller cancellation");
        caller_cx.set_cancel_requested(true);
        call.thread().unpark();
        finalized_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the retained future reaches its terminal classification");
        assert_eq!(
            call.join().expect("late-terminal caller joined"),
            Outcome::Ok(json!({ "committed": true, "audited": true })),
            "the authoritative terminal result must replace generic caller cancellation",
        );

        let healthy = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs a fresh caller Cx");
            lane.dispatch(
                &cx,
                DispatchContext::default(),
                "healthy-after-terminal",
                Value::Null,
            )
            .await
        });
        assert_eq!(healthy, Outcome::Ok(json!({ "healthy": true })));
    }

    #[test]
    fn streaming_receive_cancellation_waits_for_late_terminal_classification() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (finalized_tx, finalized_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "late-stream-terminal-cancel",
            Arc::new(LateTerminalCancellationDispatch {
                entered: entered_tx,
                finalized: finalized_tx,
            }),
            4,
        );
        let (frames_tx, _frames_rx) = mpsc::channel(1);
        let reply = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs stream admission Cx");
            lane.dispatch_stream_start(
                &cx,
                DispatchContext::default(),
                "late-terminal-stream",
                Value::Null,
                frames_tx,
            )
            .await
            .expect("stream command admitted")
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stream operation starts before receive cancellation");

        let receive_cx = Cx::for_testing();
        let thread_cx = receive_cx.clone();
        let receive = thread::spawn(move || {
            let mut reply = reply;
            block_on_lane_bridge(async move { reply.recv(&thread_cx).await })
        });
        receive_cx.set_cancel_requested(true);
        receive.thread().unpark();
        finalized_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stream future reaches its terminal classification");
        assert_eq!(
            receive.join().expect("stream receiver joined"),
            Ok(Outcome::Ok(json!({ "committed": true, "audited": true }))),
        );
    }

    #[test]
    fn dropping_stream_reply_receiver_cancels_lane_execution() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (_release_tx, release_rx) = oneshot::channel();
        let (observed_tx, observed_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "stream-receiver-drop-cancel",
            Arc::new(MidFlightCancellationDispatch {
                entered: entered_tx,
                release: Mutex::new(Some(release_rx)),
                observed_cancel: observed_tx,
            }),
            4,
        );
        let (frames_tx, _frames_rx) = mpsc::channel(1);
        let reply_rx = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs stream caller Cx");
            lane.dispatch_stream_start(
                &cx,
                DispatchContext::default(),
                "cancel-midflight",
                Value::Null,
                frames_tx,
            )
            .await
            .expect("stream command admitted")
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stream command entered dispatcher");
        drop(reply_rx);
        assert!(
            observed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("dispatcher observes stream receiver drop"),
            "dropping the final-result receiver must cancel orphaned stream work"
        );
    }

    #[test]
    fn pending_lane_reply_is_woken_by_external_caller_cancellation() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Wake};

        struct CountingWaker(AtomicUsize);

        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = Cx::for_testing();
        let (_reply_tx, mut reply_rx) = oneshot::channel::<()>();
        let wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task_cx = Context::from_waker(&waker);
        let mut receive = std::pin::pin!(recv_lane_reply(&cx, &mut reply_rx));

        assert!(matches!(receive.as_mut().poll(&mut task_cx), Poll::Pending));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        cx.set_cancel_requested(true);
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "external caller cancellation must wake the pending lane reply"
        );
        assert!(matches!(
            receive.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(oneshot::RecvError::Cancelled))
        ));
    }

    #[test]
    fn queued_lane_observes_source_cancellation_before_caller_is_repolled() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "source-cancel-before-repoll",
            Arc::new(BlockingDispatch {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            1,
        );

        let first_lane = lane.clone();
        let first = thread::spawn(move || {
            block_on_lane_bridge(async move {
                let cx = Cx::current().expect("bridge installs Cx");
                first_lane
                    .dispatch(&cx, DispatchContext::default(), "first", Value::Null)
                    .await
            })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first command blocks the lane");

        let queued_cx = Cx::for_testing();
        let mut queued = std::pin::pin!(lane.dispatch(
            &queued_cx,
            DispatchContext::default(),
            "queued",
            Value::Null,
        ));
        let waker = Waker::noop();
        let mut task_cx = std::task::Context::from_waker(waker);
        assert!(matches!(queued.as_mut().poll(&mut task_cx), Poll::Pending));
        wait_for_queued_lane_command(&lane);

        // Do not poll the caller future again yet. The lane must observe the
        // shared source-Cx cancellation witness itself before dispatch entry.
        queued_cx.set_cancel_requested(true);
        release_tx.send(()).expect("release first command");
        assert!(matches!(
            first.join().expect("first caller joined"),
            Outcome::Ok(_)
        ));

        let unexpected_entry = entered_rx.recv_timeout(Duration::from_millis(250));
        if unexpected_entry.is_ok() {
            let _ = release_tx.send(());
        }
        let queued_outcome = (0..50)
            .find_map(|_| match queued.as_mut().poll(&mut task_cx) {
                Poll::Ready(outcome) => Some(outcome),
                Poll::Pending => {
                    thread::sleep(Duration::from_millis(10));
                    None
                }
            })
            .expect("cancelled queued caller reaches its authoritative terminal reply");
        assert!(matches!(queued_outcome, Outcome::Cancelled(_)));
        assert!(
            unexpected_entry.is_err(),
            "source-cancelled queued command must not enter the dispatcher"
        );
    }

    #[test]
    fn caller_cancellation_while_queued_prevents_dispatcher_entry() {
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "caller-queue-cancel",
            Arc::new(BlockingDispatch {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            1,
        );

        let first_lane = lane.clone();
        let first = thread::spawn(move || {
            block_on_lane_bridge(async move {
                let cx = Cx::current().expect("bridge installs Cx");
                first_lane
                    .dispatch(&cx, DispatchContext::default(), "first", Value::Null)
                    .await
            })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first command blocks the lane");

        let queued_cx = Cx::for_testing();
        let queued_thread_cx = queued_cx.clone();
        let queued_lane = lane.clone();
        let queued = thread::spawn(move || {
            block_on_lane_bridge(async move {
                queued_lane
                    .dispatch(
                        &queued_thread_cx,
                        DispatchContext::default(),
                        "queued",
                        Value::Null,
                    )
                    .await
            })
        });
        wait_for_queued_lane_command(&lane);
        queued_cx.set_cancel_requested(true);
        queued.thread().unpark();
        // The caller now waits for the lane's authoritative acknowledgement
        // instead of dropping the reply channel on generic cancellation.
        release_tx.send(()).expect("release first command");
        assert!(matches!(
            queued.join().expect("queued caller joined"),
            Outcome::Cancelled(_)
        ));

        assert!(matches!(
            first.join().expect("first caller joined"),
            Outcome::Ok(_)
        ));

        let unexpected_entry = entered_rx.recv_timeout(Duration::from_millis(250));
        if unexpected_entry.is_ok() {
            let _ = release_tx.send(());
        }
        assert!(
            unexpected_entry.is_err(),
            "caller-cancelled queued command must fail before entering the dispatcher"
        );
    }

    #[test]
    fn lane_admission_timestamp_includes_mailbox_wait() {
        let (first_entered_tx, first_entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let (queue_wait_tx, queue_wait_rx) = std_mpsc::channel();
        let lane = LaneRuntime::spawn(
            "mailbox-wait-budget",
            Arc::new(QueueTimingDispatch {
                first_entered: first_entered_tx,
                release_first: Mutex::new(release_rx),
                queue_timing: queue_wait_tx,
            }),
            1,
        );

        let first_lane = lane.clone();
        let first = thread::spawn(move || {
            block_on_lane_bridge(async move {
                let cx = Cx::current().expect("bridge installs first caller Cx");
                first_lane
                    .dispatch(&cx, DispatchContext::default(), "first", Value::Null)
                    .await
            })
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first command blocks the lane");

        let queued_lane = lane.clone();
        let queued_cx = testing_cx_with_timeout(Duration::from_millis(250));
        let queued = thread::spawn(move || {
            block_on_lane_bridge(async move {
                queued_lane
                    .dispatch(
                        &queued_cx,
                        DispatchContext::default(),
                        "queued",
                        Value::Null,
                    )
                    .await
            })
        });
        wait_for_queued_lane_command(&lane);
        std::thread::sleep(Duration::from_millis(100));
        release_tx.send(()).expect("release first command");

        assert!(matches!(
            first.join().expect("first caller joined"),
            Outcome::Ok(_)
        ));
        assert!(matches!(
            queued.join().expect("queued caller joined"),
            Outcome::Ok(_)
        ));
        let (queue_wait_nanos, deadline_remaining_nanos) = queue_wait_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("queued command reports lane-relative admission age");
        assert!(
            queue_wait_nanos >= 75_000_000,
            "mailbox wait must consume the request window; observed only {queue_wait_nanos}ns"
        );
        assert!(
            deadline_remaining_nanos <= 175_000_000,
            "rebased caller deadline must lose mailbox time; {deadline_remaining_nanos}ns remained"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(
        expected = "closing a dispatch lane while holding the lane registry lock violates DL-4"
    )]
    fn registry_lane_lock_order_ab_ba_unconstructible() {
        let registry = StatefulLaneDispatch::new(Arc::new(EchoThreadDispatch));
        let lane = LaneRuntime::spawn("lock-order-test", Arc::new(EchoThreadDispatch), 4);
        let _registry_guard = registry.lock_lanes();

        lane.close_with_reason(DispatchCloseReason::ServerShutdown);
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
    fn pre_cancelled_stateful_request_allocates_no_lane_or_capacity() {
        let builder_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_runs = Arc::clone(&builder_runs);
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            counted_runs.fetch_add(1, Ordering::SeqCst);
            let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
                Box::pin(async { Ok(Arc::new(EchoThreadDispatch) as Arc<dyn ToolDispatch>) })
            });
            Ok(PreparedLaneDispatch::new(factory, DEFAULT_REQUEST_TIMEOUT))
        });
        let admission = Arc::new(AdmissionController::with_reserved(2, 10, 1, 0));
        let registry = StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None)
            .with_admission_controller(Arc::clone(&admission));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let outcome = block_on_lane_bridge(async {
            registry
                .dispatch(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("cancelled-session")
                        .with_principal_key("cancelled-principal"),
                    "cancelled",
                    Value::Null,
                )
                .await
        });

        assert!(matches!(outcome, Outcome::Cancelled(_)));
        assert_eq!(registry.lane_count(), 0);
        assert_eq!(builder_runs.load(Ordering::SeqCst), 0);
        assert_eq!(admission.available_global(), admission.regular_global_cap(),);
    }

    #[test]
    fn session_delete_invalidates_inflight_lane_creation_before_execution() {
        let harness = LifecycleRaceHarness::new();
        let caller = harness.spawn_dispatch("deleted-session", "session-principal");
        harness.builder_entered.wait();

        assert!(
            harness
                .registry
                .close_session("deleted-session", "session-principal"),
            "an in-flight creation is a live lifecycle resource",
        );
        harness.assert_invalidated(caller, DispatchCloseReason::SessionDelete);
    }

    #[test]
    fn principal_revocation_invalidates_inflight_lane_creation_before_execution() {
        let harness = LifecycleRaceHarness::new();
        let caller = harness.spawn_dispatch("revoked-session", "revoked-principal");
        harness.builder_entered.wait();

        assert_eq!(
            HttpSessionLifecycle::close_principal_sessions(
                harness.registry.as_ref(),
                "revoked-principal",
                DispatchCloseReason::SessionDelete,
            ),
            1,
            "the principal close reports its in-flight lane creation",
        );
        harness.assert_invalidated(caller, DispatchCloseReason::SessionDelete);
    }

    #[test]
    fn shutdown_invalidates_inflight_lane_creation_before_execution() {
        let harness = LifecycleRaceHarness::new();
        let caller = harness.spawn_dispatch("shutdown-session", "shutdown-principal");
        harness.builder_entered.wait();

        assert_eq!(
            harness.registry.close_all_sessions(),
            1,
            "shutdown reports its in-flight lane creation",
        );
        harness.assert_invalidated(caller, DispatchCloseReason::ServerShutdown);
    }

    #[test]
    fn lifecycle_close_allows_exactly_one_fresh_same_key_reinitialization() {
        let harness = LifecycleRaceHarness::new();
        let stale = harness.spawn_dispatch("reinitialized-session", "rotated-principal");
        harness.builder_entered.wait();
        assert_eq!(
            HttpSessionLifecycle::close_principal_sessions(
                harness.registry.as_ref(),
                "rotated-principal",
                DispatchCloseReason::SessionDelete,
            ),
            1,
        );
        harness.assert_invalidated(stale, DispatchCloseReason::SessionDelete);

        let start_fresh = Arc::new(std::sync::Barrier::new(3));
        let mut fresh_callers = Vec::new();
        for _ in 0..2 {
            let start_fresh = Arc::clone(&start_fresh);
            let registry = Arc::clone(&harness.registry);
            fresh_callers.push(thread::spawn(move || {
                start_fresh.wait();
                block_on_lane_bridge(async {
                    let cx = Cx::current().expect("bridge installs Cx");
                    registry
                        .dispatch(
                            &cx,
                            DispatchContext::default()
                                .with_http_session_id("reinitialized-session")
                                .with_principal_key("rotated-principal"),
                            "fresh-generation",
                            Value::Null,
                        )
                        .await
                })
            }));
        }
        start_fresh.wait();
        for caller in fresh_callers {
            assert!(matches!(
                caller.join().expect("fresh caller joined"),
                Outcome::Ok(_)
            ));
        }

        assert_eq!(harness.registry.lane_count(), 1);
        assert_eq!(
            harness.builder_runs.load(Ordering::SeqCst),
            2,
            "one invalid generation plus exactly one fresh generation",
        );
        assert_eq!(harness.factory_runs.load(Ordering::SeqCst), 1);
        assert_eq!(harness.dispatch_runs.load(Ordering::SeqCst), 2);
        assert!(
            harness
                .registry
                .close_session("reinitialized-session", "rotated-principal")
        );
    }

    #[test]
    fn stateful_factory_preparation_consumes_the_total_request_window() {
        let (observed_tx, observed_rx) = std_mpsc::channel();
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            std::thread::sleep(Duration::from_millis(40));
            let observed = observed_tx.clone();
            let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
                let dispatch: Arc<dyn ToolDispatch> = Arc::new(AdmissionTimingDispatch {
                    observed: observed.clone(),
                });
                Box::pin(async move { Ok(dispatch) })
            });
            Ok(PreparedLaneDispatch::new(factory, DEFAULT_REQUEST_TIMEOUT))
        });
        let registry = StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None);

        let outcome = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            registry
                .dispatch(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("timed-session")
                        .with_principal_key("timed-principal"),
                    "timed",
                    Value::Null,
                )
                .await
        });
        assert!(matches!(outcome, Outcome::Ok(_)));
        assert!(
            observed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("dispatcher reports total pre-lane elapsed time")
                >= 30_000_000,
            "synchronous capacity/profile preparation must consume the profile timeout",
        );
    }

    #[test]
    fn failed_prepared_factory_is_rebuilt_on_the_next_stateful_request() {
        let builder_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_runs = Arc::clone(&builder_runs);
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            let attempt = counted_runs.fetch_add(1, Ordering::SeqCst);
            let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
                Box::pin(async move {
                    if attempt == 0 {
                        Err(ErrorEnvelope::new(
                            ErrorClass::ConnectionFailed,
                            "transient first lane initialization failure",
                        ))
                    } else {
                        Ok(Arc::new(EchoThreadDispatch) as Arc<dyn ToolDispatch>)
                    }
                })
            });
            Ok(PreparedLaneDispatch::new(factory, DEFAULT_REQUEST_TIMEOUT))
        });
        let registry = StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None);
        let call = || {
            block_on_lane_bridge(async {
                let cx = Cx::current().expect("bridge installs Cx");
                registry
                    .dispatch(
                        &cx,
                        DispatchContext::default()
                            .with_http_session_id("retry-session")
                            .with_principal_key("retry-principal"),
                        "retry",
                        Value::Null,
                    )
                    .await
            })
        };

        assert!(matches!(call(), Outcome::Err(_)));
        assert!(matches!(call(), Outcome::Ok(_)));
        assert_eq!(builder_runs.load(Ordering::SeqCst), 2);
        assert_eq!(registry.lane_count(), 1);
    }

    #[test]
    fn concurrent_first_calls_for_same_key_share_one_capacity_permit() {
        let builder_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted_runs = Arc::clone(&builder_runs);
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            counted_runs.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(5));
            let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
                Box::pin(async { Ok(Arc::new(EchoThreadDispatch) as Arc<dyn ToolDispatch>) })
            });
            Ok(PreparedLaneDispatch::new(factory, DEFAULT_REQUEST_TIMEOUT))
        });
        let admission = Arc::new(AdmissionController::with_reserved(2, 10, 1, 0));
        let registry = Arc::new(
            StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None)
                .with_admission_controller(Arc::clone(&admission)),
        );
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut callers = Vec::new();
        for _ in 0..2 {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            callers.push(thread::spawn(move || {
                barrier.wait();
                block_on_lane_bridge(async {
                    let cx = Cx::current().expect("bridge installs Cx");
                    registry
                        .dispatch(
                            &cx,
                            DispatchContext::default()
                                .with_http_session_id("shared-session")
                                .with_principal_key("shared-principal"),
                            "shared",
                            Value::Null,
                        )
                        .await
                })
            }));
        }
        barrier.wait();
        for caller in callers {
            assert!(matches!(
                caller.join().expect("caller joined"),
                Outcome::Ok(_)
            ));
        }
        assert_eq!(builder_runs.load(Ordering::SeqCst), 1);
        assert_eq!(registry.lane_count(), 1);
        assert_eq!(admission.available_global(), 0);
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
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            Ok(PreparedLaneDispatch::new(
                Arc::clone(&factory),
                DEFAULT_REQUEST_TIMEOUT,
            ))
        });
        let registry = StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None)
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
        let factory_builder: Arc<LaneDispatchFactoryBuilder> = Arc::new(move |_lane_context| {
            Ok(PreparedLaneDispatch::new(
                Arc::clone(&factory),
                DEFAULT_REQUEST_TIMEOUT,
            ))
        });
        let registry = StatefulLaneDispatch::with_dispatch_factory_builder(factory_builder, None)
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
    fn outstanding_stream_receiver_does_not_pin_closed_lane_capacity() {
        let admission = Arc::new(AdmissionController::with_reserved(2, 10, 1, 0));
        let registry = StatefulLaneDispatch::new(Arc::new(EchoThreadDispatch))
            .with_admission_controller(Arc::clone(&admission));
        let (frames_tx, _frames_rx) = mpsc::channel(1);
        let reply = block_on_lane_bridge(async {
            let cx = Cx::current().expect("bridge installs Cx");
            registry
                .dispatch_stream_start(
                    &cx,
                    DispatchContext::default()
                        .with_http_session_id("stream-session")
                        .with_principal_key("stream-principal"),
                    "stream",
                    Value::Null,
                    frames_tx,
                )
                .await
                .expect("stream command admitted")
        });
        assert_eq!(admission.available_global(), 0);

        assert!(registry.close_session("stream-session", "stream-principal"));
        assert_eq!(
            admission.available_global(),
            admission.regular_global_cap(),
            "receiver safety hooks must not retain the lane capacity permit",
        );
        drop(reply);
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
            SigningKey::new("test-key", b"test-secret-for-lane-panic-12345".to_vec())
                .expect("valid test key"),
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
        assert_eq!(
            records[0].sql_preview,
            "<sql text redacted; see sql_sha256>"
        );
        assert_eq!(
            records[0].sql_sha256,
            oraclemcp_audit::sha256_hex(b"LANE_PANIC_UNKNOWN_DISCARDED")
        );
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
