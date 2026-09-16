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

/// A bounded actor which owns one synchronous physical Oracle connection.
///
/// The resource is constructed inside the dedicated OS thread and never
/// crosses the mailbox. This lets the future adapter keep
/// `oracledb::Connection` thread-confined even though callers use the async,
/// `Cx`-first [`crate::OracleConnection`] seam.
pub(crate) struct BlockingConnectionActor<Request, Reply> {
    mailbox: mpsc::Sender<ActorCommand<Request, Reply>>,
    state: Arc<ActorState>,
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
        Execute: FnMut(&mut Resource, Request) -> Result<Reply, DbError> + Send + 'static,
    {
        let (mailbox, receiver) = mpsc::channel(ACTOR_MAILBOX_CAPACITY);
        let state = Arc::new(ActorState::default());
        let actor_state = Arc::clone(&state);
        let join = thread::Builder::new()
            .name("oraclemcp-oracledb-actor".to_owned())
            .spawn(move || run_actor_thread(receiver, actor_state, factory, execute))
            .expect("dedicated official Oracle actor thread must spawn");

        Self {
            mailbox,
            state,
            join: Mutex::new(Some(join)),
        }
    }

    /// Runs one synchronous operation through the actor.
    ///
    /// The absolute deadline is copied from `Cx` rather than moving `Cx` to
    /// the actor. The bridge checks it before and after a blocking operation;
    /// the future adapter additionally maps it to the driver's call timeout.
    pub(crate) async fn call(&self, cx: &Cx, request: Request) -> Result<Reply, DbError> {
        self.call_with_deadline(cx, cx.budget().deadline, request)
            .await
    }

    async fn call_with_deadline(
        &self,
        cx: &Cx,
        deadline: Option<Time>,
        request: Request,
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
                },
            )
            .await
            .map_err(|error| self.send_error(error))?;

        match reply_rx.recv(cx).await {
            Ok(ActorReply::Completed(result)) => {
                if let Err(error) = checkpoint(cx, "official Oracle actor call after completion") {
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

    /// Returns whether the physical session has been permanently removed from
    /// reuse because its outcome was uncertain.
    #[cfg(test)]
    fn is_quarantined(&self) -> bool {
        self.state.is_quarantined()
    }

    /// Joins an already-stopped actor thread.
    ///
    /// Normal adapter teardown will send a typed close command in the next
    /// increment. This skeleton only needs to prove that a quarantined actor
    /// cannot remain reusable after its owner thread finishes.
    #[cfg(test)]
    fn join(&self) {
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
    },
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

    fn is_quarantined(&self) -> bool {
        self.status.load(Ordering::Acquire) == ACTOR_QUARANTINED
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
    Execute: FnMut(&mut Resource, Request) -> Result<Reply, DbError> + Send + 'static,
{
    let reactor = asupersync::runtime::reactor::create_reactor()
        .expect("native reactor must build for the official Oracle actor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("current-thread runtime must build for the official Oracle actor");
    // block-on-boundary: this is the one dedicated native actor thread, not a
    // caller-side DB round-trip. The actor owns the synchronous resource and
    // drives its Cx-aware channels for its whole lifetime.
    runtime.block_on(run_actor_loop(receiver, state, factory, execute));
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
    Execute: FnMut(&mut Resource, Request) -> Result<Reply, DbError> + Send + 'static,
{
    let cx = Cx::current().expect("actor runtime installs a current Cx");
    let mut resource = factory();

    while let Ok(command) = receiver.recv(&cx).await {
        let ActorCommand::Call {
            request,
            deadline,
            reply,
        } = command;

        if state.status.load(Ordering::Acquire) != ACTOR_ACTIVE {
            let _ = reply.send_blocking(ActorReply::DeadlineExceeded);
            break;
        }
        if deadline.is_some_and(|deadline| cx.now() >= deadline) {
            state.quarantine(
                "official Oracle actor received an operation after its absolute deadline",
            );
            let _ = reply.send_blocking(ActorReply::DeadlineExceeded);
            break;
        }

        let result = execute(&mut resource, request);
        if deadline.is_some_and(|deadline| cx.now() >= deadline) {
            state.quarantine(
                "official Oracle actor completed after its absolute deadline; session state is uncertain",
            );
            let _ = reply.send_blocking(ActorReply::DeadlineExceeded);
            break;
        }
        if reply.send_blocking(ActorReply::Completed(result)).is_err() {
            state.quarantine(
                "official Oracle actor reply receiver was dropped; session state is uncertain",
            );
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
        let actor = BlockingConnectionActor::spawn(NonSendConnection::new, |connection, amount| {
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
            move |_, ()| {
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
        assert!(actor.is_quarantined());
        actor.join();
    }

    #[test]
    fn caller_cancellation_drops_reply_and_quarantines_actor() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let actor = BlockingConnectionActor::spawn(
            || (),
            move |_, ()| {
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
        assert!(actor.is_quarantined());
        actor.join();
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
}
