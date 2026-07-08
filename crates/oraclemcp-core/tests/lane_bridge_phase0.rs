#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;
use std::thread;
use std::time::Instant;

use asupersync::channel::{mpsc, oneshot};
use asupersync::runtime::RuntimeBuilder;
use asupersync::Cx;
use serde_json::json;

const DEDICATED_OPS: u64 = 64;

#[derive(Debug)]
enum LaneCommand {
    Increment {
        amount: u64,
        reply: oneshot::Sender<LaneReply>,
    },
    Stop {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Clone, Copy, Debug)]
struct LaneReply {
    owner_thread: thread::ThreadId,
    value: u64,
}

#[derive(Clone, Copy, Debug)]
struct LaneStats {
    owner_thread: thread::ThreadId,
    processed: u64,
    final_value: u64,
    elapsed_ns: u128,
}

struct FakeNonSendOracleConn {
    owner_thread: thread::ThreadId,
    value: u64,
    _thread_local_marker: Rc<()>,
}

impl FakeNonSendOracleConn {
    fn new() -> Self {
        Self {
            owner_thread: thread::current().id(),
            value: 0,
            _thread_local_marker: Rc::new(()),
        }
    }

    fn increment(&mut self, amount: u64) -> LaneReply {
        assert_eq!(
            thread::current().id(),
            self.owner_thread,
            "non-Send connection was polled outside its owner thread"
        );
        self.value += amount;
        LaneReply {
            owner_thread: self.owner_thread,
            value: self.value,
        }
    }
}

struct DedicatedLane {
    commands: mpsc::Sender<LaneCommand>,
    join: thread::JoinHandle<LaneStats>,
}

fn spawn_dedicated_lane() -> DedicatedLane {
    let (commands, receiver) = mpsc::channel::<LaneCommand>(16);
    let join = thread::Builder::new()
        .name("oraclemcp-dl1-lane-prototype".to_string())
        .spawn(move || {
            let reactor = asupersync::runtime::reactor::create_reactor()
                .expect("native reactor builds for lane prototype");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("current-thread lane runtime builds");
            runtime.block_on(run_lane_loop(receiver))
        })
        .expect("spawn dedicated lane thread");

    DedicatedLane { commands, join }
}

// SAFETY: This lane loop is entered only by `spawn_dedicated_lane`, where
// `Runtime::block_on` is the outermost operation on a dedicated OS thread. The
// `Rc<RefCell<_>>` connection is created inside that thread, never crosses the
// mailbox boundary, and is driven only by this loop. Callers interact through
// bounded `mpsc` commands plus oneshot replies; they never call `block_on` on a
// transport/runtime worker to reach the non-Send resource.
async fn run_lane_loop(mut receiver: mpsc::Receiver<LaneCommand>) -> LaneStats {
    let cx = Cx::current().expect("block_on installs a current Cx");
    let conn = Rc::new(RefCell::new(FakeNonSendOracleConn::new()));
    let owner_thread = conn.borrow().owner_thread;
    let started = Instant::now();
    let mut processed = 0_u64;
    let mut final_value = 0_u64;

    while let Ok(command) = receiver.recv(&cx).await {
        match command {
            LaneCommand::Increment { amount, reply } => {
                let lane_reply = conn.borrow_mut().increment(amount);
                final_value = lane_reply.value;
                processed += 1;
                reply
                    .send_blocking(lane_reply)
                    .expect("coordinator waits for increment reply");
            }
            LaneCommand::Stop { reply } => {
                reply
                    .send_blocking(())
                    .expect("coordinator waits for stop reply");
                break;
            }
        }
    }

    LaneStats {
        owner_thread,
        processed,
        final_value,
        elapsed_ns: started.elapsed().as_nanos(),
    }
}

#[test]
fn dedicated_thread_block_on_lane_keeps_non_send_connection_thread_local() {
    let dedicated = spawn_dedicated_lane();
    let coordinator_reactor = asupersync::runtime::reactor::create_reactor()
        .expect("native reactor builds for coordinator prototype");
    let coordinator_runtime = RuntimeBuilder::current_thread()
        .with_reactor(coordinator_reactor)
        .build()
        .expect("coordinator runtime builds");
    let main_thread = thread::current().id();
    let commands = dedicated.commands.clone();
    let started = Instant::now();

    let last_reply = coordinator_runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let mut last_reply = None;

        for amount in 1..=DEDICATED_OPS {
            let (reply_tx, mut reply_rx) = oneshot::channel();
            commands
                .send(
                    &cx,
                    LaneCommand::Increment {
                        amount,
                        reply: reply_tx,
                    },
                )
                .await
                .expect("dedicated lane accepts increment command");
            let reply = reply_rx
                .recv(&cx)
                .await
                .expect("dedicated lane returns increment reply");

            assert_eq!(reply.value, amount * (amount + 1) / 2);
            if let Some(previous) = last_reply {
                assert_eq!(
                    previous, reply.owner_thread,
                    "all non-Send operations stay on one owner thread"
                );
            }
            last_reply = Some(reply.owner_thread);
        }

        let (stop_tx, mut stop_rx) = oneshot::channel();
        commands
            .send(&cx, LaneCommand::Stop { reply: stop_tx })
            .await
            .expect("dedicated lane accepts stop command");
        stop_rx
            .recv(&cx)
            .await
            .expect("dedicated lane confirms stop");

        last_reply.expect("prototype sent at least one operation")
    });

    let stats = dedicated.join.join().expect("dedicated lane thread joined");
    assert_ne!(
        last_reply, main_thread,
        "non-Send connection owner must not be the caller thread"
    );
    assert_eq!(stats.owner_thread, last_reply);
    assert_eq!(stats.processed, DEDICATED_OPS);
    assert_eq!(stats.final_value, DEDICATED_OPS * (DEDICATED_OPS + 1) / 2);
    assert!(stats.elapsed_ns > 0);

    println!(
        "{}",
        json!({
            "event": "dl1_lane_bridge_measurement",
            "candidate": "dedicated_os_thread_current_thread_runtime",
            "ops": DEDICATED_OPS,
            "lane_elapsed_ns": stats.elapsed_ns,
            "coordinator_elapsed_ns": started.elapsed().as_nanos(),
            "lane_owner_thread": format!("{:?}", stats.owner_thread),
            "caller_thread": format!("{:?}", main_thread),
            "verdict": "accepted_for_n0a"
        })
    );
}

// (Removed) `spawn_local_bridge_requires_private_scheduler_context_from_consumer_code`:
// this WP-N phase-0 probe called `Scope::spawn_local(...)` and asserted consumer
// code gets `Err(SpawnError::LocalSchedulerUnavailable)` — i.e. cannot install
// asupersync's private local-scheduler TLS. As of asupersync 0.3.5 `Scope::spawn_local`
// is REMOVED entirely, so that invariant is now a COMPILE-TIME guarantee (there is no
// method to call) — strictly stronger than the old runtime-error check. The runtime
// probe is therefore obsolete; the dedicated-OS-thread current-thread-runtime lane
// (validated by `spawn_dedicated_lane` / the N0a candidate above) remains the WP-N
// bridge. `SpawnError` is no longer imported.
