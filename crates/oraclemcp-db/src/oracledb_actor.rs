//! Cx-aware bridge to the synchronous official Oracle driver.
//!
//! This module deliberately contains no SQL/type/error mapping yet. It proves
//! the ownership and cancellation contract that the later `oracledb` adapter
//! will use: one dedicated OS thread owns the synchronous connection, callers
//! use a bounded Cx-aware mailbox and oneshot reply, and a deadline,
//! cancellation, dropped reply, or actor failure makes that physical session
//! permanently unavailable for reuse.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use std::{panic::AssertUnwindSafe, panic::catch_unwind};

use asupersync::Cx;
use asupersync::channel::{mpsc, oneshot};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::{OwnedSemaphorePermit, Semaphore};
use asupersync::types::Time;

use crate::DbError;
use crate::error::QuarantineOutcome;

const ACTOR_ACTIVE: u8 = 0;
const ACTOR_QUARANTINED: u8 = 1;
const ACTOR_CLOSED: u8 = 2;
const ACTOR_MAILBOX_CAPACITY: usize = 1;
/// The process-wide maximum number of native official-driver handshakes that
/// may be unable to observe cancellation. A permit is held only until a
/// successful connect is published, or a failed/cancelled actor actually
/// retires; healthy established sessions do not consume this capacity.
const OFFICIAL_CONNECT_GUARD_CAPACITY: usize = 2;
/// The longest time a caller may wait to start an official-driver connect.
/// The caller's own remaining deadline can only make this shorter.
const OFFICIAL_CONNECT_GUARD_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(250);
/// A caller which has received an actor reply must promptly confirm the
/// post-completion checkpoint before that physical session is reusable. When
/// the request carried no absolute deadline, this finite grace is the actor's
/// liveness fuse: a live-but-never-polled caller cannot retain a session or
/// actor thread indefinitely.
const ACTOR_COMPLETION_ACK_GRACE: Duration = Duration::from_millis(250);

/// Process-wide, Cx-aware bulkhead for uninterruptible initial official-driver
/// TCP/TLS connection work.
///
/// The pinned official driver can block before a connection object exists, so
/// an actor cancellation cannot interrupt that native call. The returned slot
/// is deliberately owned by the actor resource rather than the awaiting
/// caller: cancellation may abandon the reply, but it must not make another
/// stalled native connect possible until this actor has retired.
pub(crate) struct OfficialConnectGuard {
    semaphore: Arc<Semaphore>,
    acquire_timeout: Duration,
}

/// One owned official-connect bulkhead slot.
///
/// Dropping this value releases exactly one capacity unit. It is moved into
/// the actor resource and therefore cannot be released by a caller timeout.
pub(crate) struct OfficialConnectSlot {
    _permit: OwnedSemaphorePermit,
}

impl OfficialConnectGuard {
    /// Returns the singleton process-wide connect guard.
    #[must_use]
    pub(crate) fn shared() -> &'static Self {
        static GUARD: OnceLock<OfficialConnectGuard> = OnceLock::new();
        GUARD.get_or_init(|| Self {
            semaphore: Arc::new(Semaphore::new(OFFICIAL_CONNECT_GUARD_CAPACITY)),
            acquire_timeout: OFFICIAL_CONNECT_GUARD_ACQUIRE_TIMEOUT,
        })
    }

    /// Acquires a slot without extending the caller's deadline.
    ///
    /// Asupersync's owned semaphore acquisition is cancellation-safe. The
    /// explicit race supplies the hard bulkhead boundary even when the caller
    /// has no deadline; when it does, the shorter remaining duration wins.
    pub(crate) async fn acquire(&self, cx: &Cx) -> Result<OfficialConnectSlot, DbError> {
        checkpoint(cx, "official Oracle connect guard before admission")?;
        let timeout = self.acquire_timeout(cx)?;
        let semaphore = Arc::clone(&self.semaphore);
        let acquire_cx = cx.clone();
        let acquire =
            Box::pin(async move { OwnedSemaphorePermit::acquire(semaphore, &acquire_cx, 1).await });

        match cx.race_timeout(timeout, vec![acquire]).await {
            Ok(Ok(permit)) => Ok(OfficialConnectSlot { _permit: permit }),
            Ok(Err(_)) => {
                checkpoint(cx, "official Oracle connect guard acquisition")?;
                Err(DbError::Connect(
                    "official Oracle connect guard is unavailable".to_owned(),
                ))
            }
            Err(_) => {
                checkpoint(cx, "official Oracle connect guard acquisition")?;
                Err(DbError::Connect(
                    "official Oracle connect guard capacity exhausted".to_owned(),
                ))
            }
        }
    }

    fn acquire_timeout(&self, cx: &Cx) -> Result<Duration, DbError> {
        let Some(deadline) = cx.budget().deadline else {
            return Ok(self.acquire_timeout);
        };
        let now = cx.now();
        if now >= deadline {
            return Err(DbError::Cancelled(
                "official Oracle connect guard caller deadline exceeded".to_owned(),
            ));
        }
        let remaining = Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos()));
        Ok(self.acquire_timeout.min(remaining))
    }

    #[cfg(test)]
    pub(crate) fn for_test(capacity: usize, acquire_timeout: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            acquire_timeout,
        }
    }

    #[cfg(test)]
    pub(crate) fn available_for_test(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Fresh operation budget sampled by the actor immediately before the
/// synchronous call begins.
///
/// A caller-side duration is only an upper cap: it may have become stale while
/// its command waited in the bounded mailbox. The executor must tighten that
/// cap with the remaining timeout before handing work to a blocking driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ActorAdmission {
    remaining_timeout: Option<Duration>,
}

impl ActorAdmission {
    /// The remaining duration until the copied absolute deadline, sampled on
    /// the actor thread immediately before execution.
    #[must_use]
    pub(crate) const fn remaining_timeout(self) -> Option<Duration> {
        self.remaining_timeout
    }
}

/// A bounded actor which owns one synchronous physical Oracle connection.
///
/// The resource is constructed inside the dedicated OS thread and never
/// crosses the mailbox. This lets the future adapter keep
/// `oracledb::Connection` thread-confined even though callers use the async,
/// `Cx`-first [`crate::OracleConnection`] seam.
pub(crate) struct BlockingConnectionActor<Request, Reply> {
    mailbox: mpsc::Sender<ActorCommand<Request, Reply>>,
    state: Arc<ActorState>,
    #[cfg(test)]
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl<Request, Reply> BlockingConnectionActor<Request, Reply>
where
    Request: Send + 'static,
    Reply: Send + 'static,
{
    /// Starts a dedicated owner thread for one physical connection resource.
    ///
    /// `Resource` need not be `Send`: it is created and used entirely inside
    /// the actor thread. Requests and replies are owned values because they
    /// cross the Cx-aware mailbox boundary.
    pub(crate) fn spawn<Resource, Factory, Execute>(
        factory: Factory,
        execute: Execute,
    ) -> Result<Self, DbError>
    where
        Resource: 'static,
        Factory: FnOnce() -> Resource + Send + 'static,
        Execute: FnMut(&mut Resource, Request, ActorAdmission) -> Result<Reply, DbError>
            + Send
            + 'static,
    {
        Self::spawn_with_thread(factory, execute, |actor_thread| {
            thread::Builder::new()
                .name("oraclemcp-oracledb-actor".to_owned())
                .spawn(actor_thread)
        })
    }

    /// Starts an actor with an injectable native-thread launcher.
    ///
    /// The injection point confines an OS thread/PID exhaustion regression to
    /// this boundary. On launcher failure, every locally constructed channel,
    /// state cell, closure, and the unstarted actor task are dropped before an
    /// actor handle can escape to a caller.
    fn spawn_with_thread<Resource, Factory, Execute, Spawn>(
        factory: Factory,
        execute: Execute,
        spawn_thread: Spawn,
    ) -> Result<Self, DbError>
    where
        Resource: 'static,
        Factory: FnOnce() -> Resource + Send + 'static,
        Execute: FnMut(&mut Resource, Request, ActorAdmission) -> Result<Reply, DbError>
            + Send
            + 'static,
        Spawn:
            FnOnce(Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<thread::JoinHandle<()>>,
    {
        let (mailbox, receiver) = mpsc::channel(ACTOR_MAILBOX_CAPACITY);
        let state = Arc::new(ActorState::default());
        let actor_state = Arc::clone(&state);
        let join = spawn_thread(Box::new(move || {
            run_actor_thread(receiver, actor_state, factory, execute);
        }))
        .map_err(|_| DbError::Connect("official Oracle actor thread could not start".to_owned()))?;

        #[cfg(not(test))]
        let _ = join;

        Ok(Self {
            mailbox,
            state,
            #[cfg(test)]
            join: Mutex::new(Some(join)),
        })
    }

    /// Runs one synchronous operation through the actor.
    ///
    /// The absolute deadline is copied from `Cx` rather than moving `Cx` to
    /// the actor. The bridge checks it before and after a blocking operation;
    /// the future adapter additionally maps it to the driver's call timeout.
    #[cfg(test)]
    pub(crate) async fn call(&self, cx: &Cx, request: Request) -> Result<Reply, DbError> {
        self.call_with_deadline(cx, cx.budget().deadline, request)
            .await
    }

    /// Runs one operation with an explicit absolute deadline supplied by the
    /// connection layer. This is the earlier of a per-request limit and the
    /// caller's Cx deadline when both exist.
    pub(crate) async fn call_with_deadline(
        &self,
        cx: &Cx,
        deadline: Option<Time>,
        request: Request,
    ) -> Result<Reply, DbError> {
        self.call_inner(cx, deadline, request, true, false).await
    }

    /// Terminal counterpart to the explicit-deadline call.
    pub(crate) async fn call_terminal_with_deadline(
        &self,
        cx: &Cx,
        deadline: Option<Time>,
        request: Request,
    ) -> Result<Reply, DbError> {
        self.call_inner(cx, deadline, request, false, false).await
    }

    /// Runs an explicit terminal cleanup operation, then retires the actor.
    ///
    /// The reply is sent before the owner thread exits, but the physical
    /// resource is never available to a later mailbox command. This is for a
    /// consuming connection close; commit is terminal to a transaction but
    /// deliberately keeps its session actor alive.
    pub(crate) async fn call_disposing_with_deadline(
        &self,
        cx: &Cx,
        deadline: Option<Time>,
        request: Request,
    ) -> Result<Reply, DbError> {
        self.call_inner(cx, deadline, request, true, true).await
    }

    async fn call_inner(
        &self,
        cx: &Cx,
        deadline: Option<Time>,
        request: Request,
        checkpoint_after_completion: bool,
        dispose_after_reply: bool,
    ) -> Result<Reply, DbError> {
        self.state.require_active()?;
        checkpoint(cx, "official Oracle actor call before admission")?;

        let (reply_tx, mut reply_rx) = oneshot::channel();
        // The actor must not dequeue a later operation merely because it has
        // handed this reply to the runtime. The caller still has to perform
        // its post-completion Cx checkpoint; this acknowledgement closes that
        // completion/admission race without moving Cx onto the actor thread.
        let (completion_tx, completion_ack) = oneshot::channel();
        self.mailbox
            .send(
                cx,
                ActorCommand::Call {
                    request,
                    deadline,
                    reply: reply_tx,
                    completion_ack,
                    dispose_after_reply,
                },
            )
            .await
            .map_err(|error| self.send_error(error))?;

        let reply = if let Some(deadline) = deadline {
            let now = cx.now();
            let remaining =
                Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos()));
            let receive_cx = cx.clone();
            match cx
                .race_timeout(
                    remaining,
                    vec![Box::pin(async move { reply_rx.recv(&receive_cx).await })],
                )
                .await
            {
                Ok(reply) => reply,
                Err(_) => {
                    let deadline_elapsed = cx.now() >= deadline;
                    let reason = if deadline_elapsed {
                        "official Oracle actor caller deadline elapsed while the operation was in flight"
                    } else {
                        "official Oracle actor caller cancelled while the operation was in flight"
                    };
                    self.state.quarantine(reason);
                    let message = if deadline_elapsed {
                        "official Oracle actor request deadline exceeded"
                    } else {
                        "official Oracle actor caller cancelled"
                    };
                    return Err(DbError::Cancelled(message.to_owned()));
                }
            }
        } else {
            reply_rx.recv(cx).await
        };

        match reply {
            Ok(ActorReply::Completed(result)) => {
                if checkpoint_after_completion
                    && let Err(error) =
                        checkpoint(cx, "official Oracle actor call after completion")
                {
                    self.state.quarantine(
                        "caller cancelled after an official Oracle actor operation completed",
                    );
                    let _ = completion_tx.send_blocking(ActorCompletionAck::Quarantine);
                    return Err(error);
                }
                let _ = completion_tx.send_blocking(ActorCompletionAck::Continue);
                result
            }
            Ok(ActorReply::DeadlineExceeded) => {
                self.state.quarantine(
                    "official Oracle actor reached the request deadline; session state is uncertain",
                );
                Err(DbError::Cancelled(
                    "official Oracle actor request deadline exceeded".to_owned(),
                ))
            }
            Err(oneshot::RecvError::Cancelled) => {
                self.state.quarantine(
                    "caller cancelled while an official Oracle actor operation was in flight",
                );
                Err(DbError::Cancelled(
                    "official Oracle actor reply wait cancelled".to_owned(),
                ))
            }
            Err(oneshot::RecvError::Closed) => {
                self.state.quarantine(
                    "official Oracle actor stopped before replying; session state is uncertain",
                );
                Err(self.state.quarantined_error())
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                self.state.quarantine(
                    "official Oracle actor reply was polled after completion; session state is uncertain",
                );
                Err(self.state.quarantined_error())
            }
        }
    }

    /// Permanently discards the resource without waiting for mailbox capacity.
    ///
    /// `Drop` cannot await a `Cx`-aware send. Marking the state first makes
    /// every concurrent/future caller fail closed; the best-effort typed wakeup
    /// then releases an idle actor. If another command already occupies the
    /// one-slot mailbox, that command observes the quarantined state and exits
    /// the owner loop instead.
    pub(crate) fn discard_nonblocking(&self, reason: &str) {
        self.state.quarantine(reason);
        let _ = self.mailbox.try_send(ActorCommand::Discard);
        self.mailbox.wake_receiver();
    }

    /// Returns whether the physical session has been permanently removed from
    /// reuse because its outcome was uncertain.
    #[cfg(test)]
    pub(crate) fn is_quarantined_for_test(&self) -> bool {
        self.state.is_quarantined()
    }

    #[cfg(test)]
    pub(crate) fn is_closed_for_test(&self) -> bool {
        self.state.is_closed()
    }

    /// Joins an already-stopped actor thread.
    #[cfg(test)]
    pub(crate) fn join_for_test(&self) {
        if let Some(join) = self
            .join
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            join.join()
                .expect("official Oracle actor thread must not panic");
        }
    }

    fn send_error<T>(&self, error: mpsc::SendError<T>) -> DbError {
        match error {
            mpsc::SendError::Cancelled(_) => DbError::Cancelled(
                "official Oracle actor admission cancelled before execution".to_owned(),
            ),
            mpsc::SendError::Disconnected(_) | mpsc::SendError::Full(_) => {
                self.state.quarantine(
                    "official Oracle actor mailbox became unavailable; session state is uncertain",
                );
                self.state.quarantined_error()
            }
        }
    }
}

enum ActorCommand<Request, Reply> {
    Call {
        request: Request,
        deadline: Option<Time>,
        reply: oneshot::Sender<ActorReply<Reply>>,
        completion_ack: oneshot::Receiver<ActorCompletionAck>,
        dispose_after_reply: bool,
    },
    Discard,
}

/// Caller disposition after it has observed an operation's reply.
///
/// The actor waits for this one-shot acknowledgement before admitting another
/// command, so a cancellation at the caller-side post-completion checkpoint
/// makes the physical session unavailable before it can execute again.
enum ActorCompletionAck {
    Continue,
    Quarantine,
}

enum ActorReply<Reply> {
    Completed(Result<Reply, DbError>),
    DeadlineExceeded,
}

#[derive(Default)]
struct ActorState {
    status: AtomicU8,
    quarantine_reason: Mutex<Option<String>>,
}

impl ActorState {
    fn require_active(&self) -> Result<(), DbError> {
        if self.status.load(Ordering::Acquire) == ACTOR_ACTIVE {
            Ok(())
        } else {
            Err(self.quarantined_error())
        }
    }

    fn quarantine(&self, reason: &str) {
        if self
            .status
            .compare_exchange(
                ACTOR_ACTIVE,
                ACTOR_QUARANTINED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            *self
                .quarantine_reason
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason.to_owned());
        }
    }

    fn close(&self) {
        let _ = self.status.compare_exchange(
            ACTOR_ACTIVE,
            ACTOR_CLOSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    #[cfg(test)]
    fn is_quarantined(&self) -> bool {
        self.status.load(Ordering::Acquire) == ACTOR_QUARANTINED
    }

    #[cfg(test)]
    fn is_closed(&self) -> bool {
        self.status.load(Ordering::Acquire) == ACTOR_CLOSED
    }

    fn quarantined_error(&self) -> DbError {
        let reason = self
            .quarantine_reason
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| "official Oracle actor is no longer available".to_owned());
        DbError::Quarantined {
            outcome: QuarantineOutcome::UnknownDiscarded,
            message: reason,
        }
    }
}

fn run_actor_thread<Resource, Request, Reply, Factory, Execute>(
    receiver: mpsc::Receiver<ActorCommand<Request, Reply>>,
    state: Arc<ActorState>,
    factory: Factory,
    execute: Execute,
) where
    Resource: 'static,
    Request: Send + 'static,
    Reply: Send + 'static,
    Factory: FnOnce() -> Resource + Send + 'static,
    Execute:
        FnMut(&mut Resource, Request, ActorAdmission) -> Result<Reply, DbError> + Send + 'static,
{
    let result = catch_unwind(AssertUnwindSafe(|| {
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("native reactor must build for the official Oracle actor");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("current-thread runtime must build for the official Oracle actor");
        // block-on-boundary: this is the one dedicated native actor thread, not a
        // caller-side DB round-trip. The actor owns the synchronous resource and
        // drives its Cx-aware channels for its whole lifetime.
        runtime.block_on(run_actor_loop(
            receiver,
            Arc::clone(&state),
            factory,
            execute,
        ));
    }));
    if result.is_err() {
        state.quarantine("official Oracle actor panicked; session discarded");
    }
    state.close();
}

async fn run_actor_loop<Resource, Request, Reply, Factory, Execute>(
    mut receiver: mpsc::Receiver<ActorCommand<Request, Reply>>,
    state: Arc<ActorState>,
    factory: Factory,
    mut execute: Execute,
) where
    Resource: 'static,
    Request: Send + 'static,
    Reply: Send + 'static,
    Factory: FnOnce() -> Resource + Send + 'static,
    Execute:
        FnMut(&mut Resource, Request, ActorAdmission) -> Result<Reply, DbError> + Send + 'static,
{
    let cx = Cx::current().expect("actor runtime installs a current Cx");
    let mut resource = factory();

    while let Ok(command) = receiver.recv(&cx).await {
        let ActorCommand::Call {
            request,
            deadline,
            reply,
            completion_ack,
            dispose_after_reply,
        } = command
        else {
            state.quarantine("official Oracle actor discarded an abandoned stream");
            break;
        };

        if state.status.load(Ordering::Acquire) != ACTOR_ACTIVE {
            let _ = reply.send_blocking(ActorReply::DeadlineExceeded);
            break;
        }
        let admission = match deadline {
            Some(deadline) => {
                let now = cx.now();
                if now >= deadline {
                    state.quarantine(
                        "official Oracle actor received an operation after its absolute deadline",
                    );
                    let _ = reply.send_blocking(ActorReply::DeadlineExceeded);
                    break;
                }
                ActorAdmission {
                    remaining_timeout: Some(Duration::from_nanos(
                        deadline.as_nanos().saturating_sub(now.as_nanos()),
                    )),
                }
            }
            None => ActorAdmission {
                remaining_timeout: None,
            },
        };

        let result = execute(&mut resource, request, admission);
        let result_left_session_uncertain = result
            .as_ref()
            .err()
            .is_some_and(DbError::is_uncertain_session_state);
        if deadline.is_some_and(|deadline| cx.now() >= deadline) {
            state.quarantine(
                "official Oracle actor completed after its absolute deadline; session state is uncertain",
            );
            let _ = reply.send_blocking(ActorReply::DeadlineExceeded);
            break;
        }
        if reply.send_blocking(ActorReply::Completed(result)).is_err() {
            if !dispose_after_reply {
                state.quarantine(
                    "official Oracle actor reply receiver was dropped; session state is uncertain",
                );
            }
            break;
        }
        let acknowledgement = completion_ack_wait(&cx, deadline, completion_ack).await;
        if !matches!(acknowledgement, Ok(ActorCompletionAck::Continue)) {
            state.quarantine(
                "caller did not confirm an official Oracle actor completion before the acknowledgement boundary; session state is uncertain",
            );
            break;
        }
        if dispose_after_reply {
            state.close();
        }
        if result_left_session_uncertain {
            state.quarantine(
                "official Oracle actor operation left the physical session state uncertain",
            );
            break;
        }
        if dispose_after_reply {
            break;
        }
    }

    state.close();
}

/// Wait for the caller's post-completion disposition without allowing a live
/// but stalled caller task to retain the thread-owned session indefinitely.
///
/// The actor uses the request's copied absolute deadline when one exists. A
/// deadline that elapsed while the reply was in flight is fail-closed before
/// polling the acknowledgement. Requests without a deadline receive only the
/// fixed, documented grace above. `race_timeout` drops the waiter on expiry,
/// which drops the receiver and lets the caller's retained sender observe that
/// the actor has retired rather than permitting another command.
async fn completion_ack_wait(
    cx: &Cx,
    deadline: Option<Time>,
    mut completion_ack: oneshot::Receiver<ActorCompletionAck>,
) -> Result<ActorCompletionAck, ()> {
    let now = cx.now();
    let timeout = match deadline {
        Some(deadline) if now >= deadline => return Err(()),
        Some(deadline) => Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos())),
        None => ACTOR_COMPLETION_ACK_GRACE,
    };
    let acknowledge_cx = cx.clone();
    let acknowledgement = Box::pin(async move { completion_ack.recv(&acknowledge_cx).await });
    match cx.race_timeout(timeout, vec![acknowledgement]).await {
        Ok(Ok(ActorCompletionAck::Continue))
            if deadline.is_none_or(|deadline| cx.now() < deadline) =>
        {
            Ok(ActorCompletionAck::Continue)
        }
        Ok(Ok(ActorCompletionAck::Quarantine)) => Ok(ActorCompletionAck::Quarantine),
        Ok(Err(_)) | Err(_) | Ok(Ok(ActorCompletionAck::Continue)) => Err(()),
    }
}

fn checkpoint(cx: &Cx, phase: &str) -> Result<(), DbError> {
    cx.checkpoint()
        .map_err(|error| DbError::Cancelled(format!("{phase}: {error}")))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    fn block_on_actor<T>(future: impl std::future::Future<Output = T>) -> T {
        let reactor = asupersync::runtime::reactor::create_reactor()
            .expect("native reactor must build for actor test");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("current-thread runtime must build for actor test");
        runtime.block_on(future)
    }

    struct NonSendConnection {
        owner_thread: thread::ThreadId,
        value: u64,
        _not_send: Rc<RefCell<()>>,
    }

    impl NonSendConnection {
        fn new() -> Self {
            Self {
                owner_thread: thread::current().id(),
                value: 0,
                _not_send: Rc::new(RefCell::new(())),
            }
        }
    }

    #[test]
    fn actor_keeps_non_send_connection_on_its_dedicated_thread() {
        let actor =
            BlockingConnectionActor::spawn(NonSendConnection::new, |connection, amount, _| {
                assert_eq!(thread::current().id(), connection.owner_thread);
                connection.value += amount;
                Ok((connection.owner_thread, connection.value))
            })
            .expect("actor thread starts for ownership test");
        let caller_thread = thread::current().id();

        let (owner_thread, value) = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            actor.call(&cx, 7).await
        })
        .expect("actor call completes through the Cx-aware bridge");

        assert_ne!(owner_thread, caller_thread);
        assert_eq!(value, 7);
        drop(actor);
    }

    #[test]
    fn expired_absolute_deadline_quarantines_before_the_blocking_operation() {
        let executions = Arc::new(AtomicUsize::new(0));
        let executions_for_actor = Arc::clone(&executions);
        let actor = BlockingConnectionActor::spawn(
            || (),
            move |_, (), _| {
                executions_for_actor.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("actor thread starts for deadline test");
        let result = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            actor.call_with_deadline(&cx, Some(Time::ZERO), ()).await
        });

        assert!(matches!(result, Err(DbError::Cancelled(_))));
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert!(actor.is_quarantined_for_test());
        actor.join_for_test();
    }

    #[test]
    fn disposing_call_drops_resource_stops_actor_and_refuses_reuse() {
        struct Resource(Arc<AtomicUsize>);

        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let resource_dropped = Arc::clone(&dropped);
        let actor = BlockingConnectionActor::spawn(
            move || Resource(resource_dropped),
            |_, (), _| -> Result<(), DbError> { Ok(()) },
        )
        .expect("actor thread starts for terminal-disposal test");

        let result = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            actor.call_disposing_with_deadline(&cx, None, ()).await
        });

        assert!(matches!(result, Ok(())));
        actor.join_for_test();
        assert!(actor.is_closed_for_test());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(matches!(
            block_on_actor(async {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                actor.call(&cx, ()).await
            }),
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));
    }

    #[test]
    fn blocking_call_panic_quarantines_stops_actor_and_refuses_reuse() {
        struct Resource(Arc<AtomicUsize>);

        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let resource_dropped = Arc::clone(&dropped);
        let actor = BlockingConnectionActor::spawn(
            move || Resource(resource_dropped),
            |_, (), _| -> Result<(), DbError> {
                panic!("test-only blocking driver panic");
            },
        )
        .expect("actor thread starts for panic quarantine test");

        let result = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            actor.call(&cx, ()).await
        });

        assert!(matches!(
            result,
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));
        actor.join_for_test();
        assert!(actor.is_quarantined_for_test());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(matches!(
            block_on_actor(async {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                actor.call(&cx, ()).await
            }),
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));
    }

    #[test]
    fn queued_command_receives_only_its_remaining_deadline_budget() {
        #[derive(Clone, Copy)]
        enum Request {
            Block,
            Timed,
        }

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (budget_tx, budget_rx) = mpsc::channel();
        let actor = BlockingConnectionActor::spawn(
            || (),
            move |_, request, admission| {
                match request {
                    Request::Block => {
                        entered_tx.send(()).expect("actor reports operation start");
                        release_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("test releases the blocking operation");
                    }
                    Request::Timed => budget_tx
                        .send(admission.remaining_timeout())
                        .expect("actor reports the freshly sampled budget"),
                }
                Ok(())
            },
        )
        .expect("actor thread starts for deadline-admission test");

        let (first_result, timed_result) = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            let (first_reply, mut first_wait) = oneshot::channel();
            let (first_completion, first_completion_ack) = oneshot::channel();
            let first_send = actor
                .mailbox
                .send(
                    &cx,
                    ActorCommand::Call {
                        request: Request::Block,
                        deadline: None,
                        reply: first_reply,
                        completion_ack: first_completion_ack,
                        dispose_after_reply: false,
                    },
                )
                .await;
            assert!(first_send.is_ok(), "first command enters the actor mailbox");
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("first command begins blocking in the actor");

            let initial_budget = Duration::from_millis(500);
            let (timed_reply, mut timed_wait) = oneshot::channel();
            let (timed_completion, timed_completion_ack) = oneshot::channel();
            let timed_send = actor
                .mailbox
                .send(
                    &cx,
                    ActorCommand::Call {
                        request: Request::Timed,
                        deadline: Some(cx.now() + initial_budget),
                        reply: timed_reply,
                        completion_ack: timed_completion_ack,
                        dispose_after_reply: false,
                    },
                )
                .await;
            assert!(
                timed_send.is_ok(),
                "timed command queues behind the blocking command"
            );

            thread::sleep(Duration::from_millis(50));
            release_tx
                .send(())
                .expect("test releases the first command");
            let first_result = first_wait.recv(&cx).await;
            assert!(matches!(
                first_completion.send_blocking(ActorCompletionAck::Continue),
                Ok(())
            ));
            let timed_result = timed_wait.recv(&cx).await;
            assert!(matches!(
                timed_completion.send_blocking(ActorCompletionAck::Continue),
                Ok(())
            ));
            (first_result, timed_result)
        });

        assert!(matches!(first_result, Ok(ActorReply::Completed(Ok(())))));
        assert!(matches!(timed_result, Ok(ActorReply::Completed(Ok(())))));
        let observed = budget_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("actor reports the timed command budget")
            .expect("timed command has an absolute deadline");
        assert!(
            observed < Duration::from_millis(450),
            "actor must subtract mailbox time from a caller-side budget; observed {observed:?}"
        );
        drop(actor);
    }

    #[test]
    fn caller_cancellation_drops_reply_and_quarantines_actor() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let actor = BlockingConnectionActor::spawn(
            || (),
            move |_, (), _| {
                entered_tx.send(()).expect("actor reports operation start");
                release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test releases the blocking operation");
                Ok(())
            },
        )
        .expect("actor thread starts for cancellation test");
        let call = block_on_actor(async {
            let caller_cx = Cx::current().expect("test runtime installs a current Cx");
            let thread_cx = caller_cx.clone();
            let thread_actor = &actor;
            thread::scope(|scope| {
                let call = scope.spawn(|| block_on_actor(thread_actor.call(&thread_cx, ())));
                entered_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("actor operation starts before cancellation");
                caller_cx.set_cancel_requested(true);
                call.thread().unpark();
                let result = call.join().expect("caller thread joins");
                release_tx
                    .send(())
                    .expect("release blocked actor operation");
                result
            })
        });

        assert!(matches!(call, Err(DbError::Cancelled(_))));
        assert!(actor.is_quarantined_for_test());
        actor.join_for_test();
        assert!(matches!(
            block_on_actor(async {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                actor.call(&cx, ()).await
            }),
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));
    }

    #[test]
    fn cancelled_completed_reply_never_admits_a_queued_second_caller() {
        #[derive(Clone, Copy)]
        enum Request {
            First,
            Second,
        }

        let first_executions = Arc::new(AtomicUsize::new(0));
        let second_executions = Arc::new(AtomicUsize::new(0));
        let first_for_actor = Arc::clone(&first_executions);
        let second_for_actor = Arc::clone(&second_executions);
        let actor = Arc::new(
            BlockingConnectionActor::spawn(
                || (),
                move |_, request, _| {
                    match request {
                        Request::First => {
                            first_for_actor.fetch_add(1, Ordering::SeqCst);
                        }
                        Request::Second => {
                            second_for_actor.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Ok(())
                },
            )
            .expect("actor thread starts for completion/admission race test"),
        );
        let (first_completion, second_completion, mut second_wait) = block_on_actor({
            let actor = Arc::clone(&actor);
            async move {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                let (first_reply, mut first_wait) = oneshot::channel();
                let (first_completion, first_completion_ack) = oneshot::channel();
                let first_send = actor
                    .mailbox
                    .send(
                        &cx,
                        ActorCommand::Call {
                            request: Request::First,
                            deadline: None,
                            reply: first_reply,
                            completion_ack: first_completion_ack,
                            dispose_after_reply: false,
                        },
                    )
                    .await;
                assert!(first_send.is_ok(), "first caller enters the actor");
                assert!(matches!(
                    first_wait.recv(&cx).await,
                    Ok(ActorReply::Completed(Ok(())))
                ));

                let (second_reply, second_wait) = oneshot::channel();
                let (second_completion, second_completion_ack) = oneshot::channel();
                let second_send = actor
                    .mailbox
                    .send(
                        &cx,
                        ActorCommand::Call {
                            request: Request::Second,
                            deadline: None,
                            reply: second_reply,
                            completion_ack: second_completion_ack,
                            dispose_after_reply: false,
                        },
                    )
                    .await;
                assert!(
                    second_send.is_ok(),
                    "second caller queues while the first completion waits for acknowledgement"
                );

                cx.set_cancel_requested(true);
                assert!(checkpoint(&cx, "test first caller after-completion checkpoint").is_err());
                actor.state.quarantine(
                    "test caller cancellation after an official actor operation completed",
                );
                (first_completion, second_completion, second_wait)
            }
        });

        assert!(matches!(
            first_completion.send_blocking(ActorCompletionAck::Quarantine),
            Ok(())
        ));
        actor.join_for_test();
        assert_eq!(first_executions.load(Ordering::SeqCst), 1);
        assert_eq!(
            second_executions.load(Ordering::SeqCst),
            0,
            "the queued second caller cannot execute before the cancelled first caller closes completion admission"
        );
        assert!(actor.is_quarantined_for_test());

        let second_result: Result<(), DbError> = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            match second_wait.recv(&cx).await {
                Err(oneshot::RecvError::Closed) => Err(actor.state.quarantined_error()),
                _ => panic!("queued second caller must receive actor closure"),
            }
        });
        assert!(matches!(
            second_result,
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));

        drop(second_completion);
    }

    #[test]
    fn withheld_live_completion_ack_quarantines_and_retires_actor_within_grace() {
        #[derive(Clone, Copy)]
        enum Request {
            First,
            Second,
        }

        struct Resource(mpsc::Sender<()>);

        impl Drop for Resource {
            fn drop(&mut self) {
                self.0
                    .send(())
                    .expect("actor resource reports its bounded retirement");
            }
        }

        let (retired_tx, retired_rx) = mpsc::channel();
        let first_executions = Arc::new(AtomicUsize::new(0));
        let second_executions = Arc::new(AtomicUsize::new(0));
        let first_for_actor = Arc::clone(&first_executions);
        let second_for_actor = Arc::clone(&second_executions);
        let actor = Arc::new(
            BlockingConnectionActor::spawn(
                move || Resource(retired_tx),
                move |_, request, _| {
                    match request {
                        Request::First => {
                            first_for_actor.fetch_add(1, Ordering::SeqCst);
                        }
                        Request::Second => {
                            second_for_actor.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Ok(())
                },
            )
            .expect("actor thread starts for bounded acknowledgement test"),
        );

        let (first_completion, mut second_wait) = block_on_actor({
            let actor = Arc::clone(&actor);
            async move {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                let (first_reply, mut first_wait) = oneshot::channel();
                let (first_completion, first_completion_ack) = oneshot::channel();
                let first_send = actor
                    .mailbox
                    .send(
                        &cx,
                        ActorCommand::Call {
                            request: Request::First,
                            deadline: None,
                            reply: first_reply,
                            completion_ack: first_completion_ack,
                            dispose_after_reply: false,
                        },
                    )
                    .await;
                assert!(first_send.is_ok(), "first caller enters the actor");
                assert!(matches!(
                    first_wait.recv(&cx).await,
                    Ok(ActorReply::Completed(Ok(())))
                ));

                let (second_reply, second_wait) = oneshot::channel();
                let (_second_completion, second_completion_ack) = oneshot::channel();
                let second_send = actor
                    .mailbox
                    .send(
                        &cx,
                        ActorCommand::Call {
                            request: Request::Second,
                            deadline: None,
                            reply: second_reply,
                            completion_ack: second_completion_ack,
                            dispose_after_reply: false,
                        },
                    )
                    .await;
                assert!(
                    second_send.is_ok(),
                    "second caller queues behind the withheld live acknowledgement"
                );
                (first_completion, second_wait)
            }
        });

        retired_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("a live-but-withheld acknowledgement must not retain the actor indefinitely");
        actor.join_for_test();
        assert!(actor.is_quarantined_for_test());
        assert_eq!(first_executions.load(Ordering::SeqCst), 1);
        assert_eq!(
            second_executions.load(Ordering::SeqCst),
            0,
            "a queued command cannot execute after its predecessor misses acknowledgement grace"
        );
        let second_result: Result<(), DbError> = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            match second_wait.recv(&cx).await {
                Err(oneshot::RecvError::Closed) => Err(actor.state.quarantined_error()),
                _ => panic!("queued second caller must receive actor closure"),
            }
        });
        assert!(matches!(
            second_result,
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                ..
            })
        ));

        drop(first_completion);
    }

    #[test]
    fn bounded_connect_guard_caps_stalled_actors_and_recovers_every_slot() {
        struct StalledConnect {
            _slot: OfficialConnectSlot,
        }

        let guard = Arc::new(OfficialConnectGuard::for_test(2, Duration::from_millis(25)));
        let first_slot = block_on_actor({
            let guard = Arc::clone(&guard);
            async move {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                guard
                    .acquire(&cx)
                    .await
                    .expect("first stalled connect receives a guard slot")
            }
        });
        let second_slot = block_on_actor({
            let guard = Arc::clone(&guard);
            async move {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                guard
                    .acquire(&cx)
                    .await
                    .expect("second stalled connect receives a guard slot")
            }
        });

        let (started_tx, started_rx) = mpsc::channel();
        let first_started_tx = started_tx.clone();
        let (first_release_tx, first_release_rx) = mpsc::channel();
        let (second_release_tx, second_release_rx) = mpsc::channel();
        let first_actor = Arc::new(
            BlockingConnectionActor::spawn(
                move || StalledConnect { _slot: first_slot },
                move |_, (), _| {
                    first_started_tx
                        .send(())
                        .expect("first simulated native connect starts");
                    first_release_rx
                        .recv_timeout(Duration::from_secs(1))
                        .expect("first simulated native connect is released");
                    Ok(())
                },
            )
            .expect("first guarded actor thread starts"),
        );
        let second_actor = Arc::new(
            BlockingConnectionActor::spawn(
                move || StalledConnect { _slot: second_slot },
                move |_, (), _| {
                    started_tx
                        .send(())
                        .expect("second simulated native connect starts");
                    second_release_rx
                        .recv_timeout(Duration::from_secs(1))
                        .expect("second simulated native connect is released");
                    Ok(())
                },
            )
            .expect("second guarded actor thread starts"),
        );

        let (first_call, second_call) = thread::scope(|scope| {
            let first_actor_for_call = Arc::clone(&first_actor);
            let first_call = scope.spawn(move || {
                block_on_actor(async move {
                    let cx = Cx::current().expect("test runtime installs a current Cx");
                    first_actor_for_call.call(&cx, ()).await
                })
            });
            let second_actor_for_call = Arc::clone(&second_actor);
            let second_call = scope.spawn(move || {
                block_on_actor(async move {
                    let cx = Cx::current().expect("test runtime installs a current Cx");
                    second_actor_for_call.call(&cx, ()).await
                })
            });

            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("first simulated native connect blocks");
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("second simulated native connect blocks");
            assert_eq!(guard.available_for_test(), 0);

            let saturated = block_on_actor({
                let guard = Arc::clone(&guard);
                async move {
                    let cx = Cx::current().expect("test runtime installs a current Cx");
                    guard.acquire(&cx).await
                }
            });
            assert!(
                matches!(saturated, Err(DbError::Connect(message)) if message == "official Oracle connect guard capacity exhausted")
            );
            assert_eq!(
                guard.available_for_test(),
                0,
                "a saturated guard cannot admit an unbounded third native connect"
            );

            first_release_tx
                .send(())
                .expect("release first simulated native connect");
            second_release_tx
                .send(())
                .expect("release second simulated native connect");
            (
                first_call.join().expect("first guarded caller joins"),
                second_call.join().expect("second guarded caller joins"),
            )
        });

        assert!(first_call.is_ok());
        assert!(second_call.is_ok());
        first_actor.discard_nonblocking("test retires first guarded actor");
        second_actor.discard_nonblocking("test retires second guarded actor");
        first_actor.join_for_test();
        second_actor.join_for_test();
        assert_eq!(
            guard.available_for_test(),
            2,
            "retiring stalled actors returns the guard to its exact baseline"
        );
    }

    #[test]
    fn uncertain_operation_error_quarantines_and_discards_the_actor() {
        let actor = BlockingConnectionActor::spawn(
            || (),
            |_, (), _| -> Result<(), DbError> {
                Err(DbError::Cancelled(
                    "driver timeout leaves the session state uncertain".to_owned(),
                ))
            },
        )
        .expect("actor thread starts for uncertainty test");

        let result = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            actor.call(&cx, ()).await
        });

        assert!(matches!(result, Err(DbError::Cancelled(_))));
        assert!(actor.is_quarantined_for_test());
        actor.join_for_test();
    }

    #[test]
    fn actor_spawn_failure_is_redacted_and_never_starts_a_resource() {
        struct UnstartedTaskDrop(Arc<AtomicUsize>);

        impl Drop for UnstartedTaskDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let factory_runs = Arc::new(AtomicUsize::new(0));
        let factory_runs_for_actor = Arc::clone(&factory_runs);
        let unstarted_task_drops = Arc::new(AtomicUsize::new(0));
        let task_drop_guard = UnstartedTaskDrop(Arc::clone(&unstarted_task_drops));
        let result = BlockingConnectionActor::spawn_with_thread(
            move || {
                let _task_drop_guard = task_drop_guard;
                factory_runs_for_actor.fetch_add(1, Ordering::SeqCst);
            },
            |_, (), _| -> Result<(), DbError> { Ok(()) },
            |_actor_thread| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "host thread limit exhausted: /operator-only/path",
                ))
            },
        );

        let error = match result {
            Ok(_) => panic!("failed launcher must not publish an actor handle"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            DbError::Connect(ref message) if message == "official Oracle actor thread could not start"
        ));
        assert_eq!(
            factory_runs.load(Ordering::SeqCst),
            0,
            "an unstarted actor task must not create the physical resource"
        );
        assert_eq!(
            unstarted_task_drops.load(Ordering::SeqCst),
            1,
            "the failed launcher must drop the unstarted actor task rather than leak its mailbox"
        );
    }

    #[test]
    fn actor_spawn_failure_returns_the_reserved_connect_guard_slot() {
        struct GuardedUnstartedResource {
            _slot: OfficialConnectSlot,
        }

        let guard = Arc::new(OfficialConnectGuard::for_test(1, Duration::from_millis(25)));
        let slot = block_on_actor({
            let guard = Arc::clone(&guard);
            async move {
                let cx = Cx::current().expect("test runtime installs a current Cx");
                guard
                    .acquire(&cx)
                    .await
                    .expect("unstarted actor reserves the only guard slot")
            }
        });
        assert_eq!(guard.available_for_test(), 0);

        let result = BlockingConnectionActor::spawn_with_thread(
            move || GuardedUnstartedResource { _slot: slot },
            |_, (), _| -> Result<(), DbError> { Ok(()) },
            |_actor_thread| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "test-only native thread exhaustion",
                ))
            },
        );

        assert!(matches!(result, Err(DbError::Connect(_))));
        assert_eq!(
            guard.available_for_test(),
            1,
            "a failed actor spawn drops its unstarted guarded factory rather than stranding capacity"
        );
    }
}
