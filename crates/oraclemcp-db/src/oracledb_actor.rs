//! Cx-aware bridge to the synchronous official Oracle driver.
//!
//! This module deliberately contains no SQL/type/error mapping yet. It proves
//! the ownership and cancellation contract that the later `oracledb` adapter
//! will use: one dedicated OS thread owns the synchronous connection, callers
//! use a bounded Cx-aware mailbox and oneshot reply, and a deadline,
//! cancellation, dropped reply, or actor failure makes that physical session
//! permanently unavailable for reuse.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::{panic::AssertUnwindSafe, panic::catch_unwind};

use asupersync::Cx;
use asupersync::channel::{mpsc, oneshot};
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::Time;

use crate::DbError;
use crate::error::QuarantineOutcome;

const ACTOR_ACTIVE: u8 = 0;
const ACTOR_QUARANTINED: u8 = 1;
const ACTOR_CLOSED: u8 = 2;
const ACTOR_MAILBOX_CAPACITY: usize = 1;

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
    pub(crate) fn spawn<Resource, Factory, Execute>(factory: Factory, execute: Execute) -> Self
    where
        Resource: 'static,
        Factory: FnOnce() -> Resource + Send + 'static,
        Execute: FnMut(&mut Resource, Request, ActorAdmission) -> Result<Reply, DbError>
            + Send
            + 'static,
    {
        let (mailbox, receiver) = mpsc::channel(ACTOR_MAILBOX_CAPACITY);
        let state = Arc::new(ActorState::default());
        let actor_state = Arc::clone(&state);
        let join = thread::Builder::new()
            .name("oraclemcp-oracledb-actor".to_owned())
            .spawn(move || run_actor_thread(receiver, actor_state, factory, execute))
            .expect("dedicated official Oracle actor thread must spawn");

        #[cfg(not(test))]
        let _ = join;

        Self {
            mailbox,
            state,
            #[cfg(test)]
            join: Mutex::new(Some(join)),
        }
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
        self.mailbox
            .send(
                cx,
                ActorCommand::Call {
                    request,
                    deadline,
                    reply: reply_tx,
                    dispose_after_reply,
                },
            )
            .await
            .map_err(|error| self.send_error(error))?;

        match reply_rx.recv(cx).await {
            Ok(ActorReply::Completed(result)) => {
                if checkpoint_after_completion
                    && let Err(error) =
                        checkpoint(cx, "official Oracle actor call after completion")
                {
                    self.state.quarantine(
                        "caller cancelled after an official Oracle actor operation completed",
                    );
                    return Err(error);
                }
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
        dispose_after_reply: bool,
    },
    Discard,
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
        if dispose_after_reply {
            state.close();
        }
        if reply.send_blocking(ActorReply::Completed(result)).is_err() {
            if !dispose_after_reply {
                state.quarantine(
                    "official Oracle actor reply receiver was dropped; session state is uncertain",
                );
            }
            break;
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
            });
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
        );
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
        );

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
        );

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
        );

        let (first_result, timed_result) = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            let (first_reply, mut first_wait) = oneshot::channel();
            let first_send = actor
                .mailbox
                .send(
                    &cx,
                    ActorCommand::Call {
                        request: Request::Block,
                        deadline: None,
                        reply: first_reply,
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
            let timed_send = actor
                .mailbox
                .send(
                    &cx,
                    ActorCommand::Call {
                        request: Request::Timed,
                        deadline: Some(cx.now() + initial_budget),
                        reply: timed_reply,
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
            let timed_result = timed_wait.recv(&cx).await;
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
        );
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
    fn uncertain_operation_error_quarantines_and_discards_the_actor() {
        let actor = BlockingConnectionActor::spawn(
            || (),
            |_, (), _| -> Result<(), DbError> {
                Err(DbError::Cancelled(
                    "driver timeout leaves the session state uncertain".to_owned(),
                ))
            },
        );

        let result = block_on_actor(async {
            let cx = Cx::current().expect("test runtime installs a current Cx");
            actor.call(&cx, ()).await
        });

        assert!(matches!(result, Err(DbError::Cancelled(_))));
        assert!(actor.is_quarantined_for_test());
        actor.join_for_test();
    }
}
