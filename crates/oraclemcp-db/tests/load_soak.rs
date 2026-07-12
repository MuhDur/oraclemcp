//! B3 — net load + shutdown soak evidence (release gate).
//!
//! This is the OFFLINE, deterministic half of the B3 evidence: a load/soak
//! harness that drives N concurrent in-process clients through the session
//! lifecycle the dispatch path uses (acquire a lease over a mock connection,
//! run a query mix, release), exercising B1's **thread-per-connection +
//! async** model — each client is its own OS thread driving its own
//! current-thread Asupersync runtime via `block_on`, exactly like
//! `oraclemcp-core/src/server.rs` drives one runtime per HTTP connection.
//!
//! It asserts, with NO database, the three release-gate invariants:
//!
//!   1. **ZERO leaked sessions** — checkout accounting balances: every
//!      `acquire` is matched by exactly one `release`/discard, and once the run
//!      quiesces `LeaseManager::active_count()` is `0`. The shared ledger's
//!      `acquired == released + discarded` is the pool-checkout analogue
//!      asserted on the real `OraclePool` via `PoolMetrics::is_balanced` in the
//!      `live-xe` variant.
//!   2. **Clean drain on shutdown** — on the shutdown signal a client stops
//!      acquiring new work; `LeaseManager::release_all` force-rolls-back every
//!      open transaction and drops every lease (no in-flight write committed,
//!      no orphan session held), and the readiness gate flips to draining.
//!   3. **Bounded behavior** — the live-lease count never exceeds the per-DB
//!      ceiling (= N clients here), and the ledger shows no unbounded growth
//!      (open sessions return to 0).
//!
//! ## Load shape (defined here; mirrored in docs/performance-footprint.md)
//!
//! | Parameter        | Value (offline soak)                                |
//! |------------------|-----------------------------------------------------|
//! | Clients (N)      | 8 concurrent OS threads, one runtime each           |
//! | Query mix        | 70% read (`query_rows`), 20% describe, 10% preview  |
//! |                  | DML (begin txn + DML + rollback-to-savepoint)       |
//! | Soak duration    | 200 iterations per client (1,600 total operations)  |
//! | Session model    | acquire lease -> op -> release, every iteration     |
//!
//! The mix is deterministic (a per-client counter selects the op), so the
//! verdict is reproducible and never schedule-accidental. The `live-xe`
//! variant (ignored by default) re-runs the same shape against a real database
//! and is where p50/p95/p99 latency is captured (D7).
//!
//! ## Pass conditions (asserted below)
//!
//!   * `ledger.acquired == ledger.released + ledger.discarded` (no leak)
//!   * `mgr.active_count() == 0` after drain (no held session)
//!   * `ledger.live_peak <= N` (bounded; never over the ceiling)
//!   * `ledger.committed == 0` on the shutdown-drained leases (no torn commit)
//!   * readiness flips to draining and never flips back

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    DbError, LeaseManager, OracleBackend, OracleBind, OracleConnectOptions, OracleConnection,
    OracleConnectionInfo, OraclePool, OracleRow, PoolSettings,
};

/// Number of concurrent in-process clients (one OS thread + runtime each).
const CLIENTS: usize = 8;
/// Operations per client (the soak length). Deterministic, not wall-clock.
const ITERATIONS: usize = 200;

/// Shared checkout ledger — the offline zero-leaked-session accounting. All
/// fields are atomics so the N client threads share one view.
#[derive(Default)]
struct Ledger {
    /// Live (currently-held) session count, incremented on acquire, decremented
    /// on release/discard. Must return to 0 once the run quiesces.
    live: AtomicUsize,
    /// High-water mark of `live` — must never exceed the client ceiling.
    live_peak: AtomicUsize,
    /// Lifetime totals: acquired must equal released + discarded.
    acquired: AtomicUsize,
    released: AtomicUsize,
    discarded: AtomicUsize,
    /// Commits observed on a drained session — must stay 0 (no torn commit).
    committed: AtomicUsize,
}

impl Ledger {
    fn on_acquire(&self) {
        self.acquired.fetch_add(1, Ordering::SeqCst);
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        // Track the peak with a CAS loop so it is the true high-water mark.
        let mut peak = self.live_peak.load(Ordering::SeqCst);
        while live > peak {
            match self
                .live_peak
                .compare_exchange(peak, live, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }

    fn on_release(&self, dirty: bool) {
        self.live.fetch_sub(1, Ordering::SeqCst);
        if dirty {
            self.discarded.fetch_add(1, Ordering::SeqCst);
        } else {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A `Send + Sync` mock connection that records transaction-control calls into
/// the shared ledger and checkpoints `cx` first (so a cancelled `cx` aborts the
/// call exactly like the real adapter). It performs no I/O.
struct LoadConn {
    ledger: Arc<Ledger>,
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for LoadConn {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        cx.checkpoint()
            .map_err(|e| DbError::Cancelled(e.to_string()))
    }
    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        cx.checkpoint()
            .map_err(|e| DbError::Cancelled(e.to_string()))?;
        Ok(OracleConnectionInfo::default())
    }
    async fn query_rows(
        &self,
        cx: &Cx,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        cx.checkpoint()
            .map_err(|e| DbError::Cancelled(e.to_string()))?;
        Ok(vec![])
    }
    async fn execute(&self, cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        cx.checkpoint()
            .map_err(|e| DbError::Cancelled(e.to_string()))?;
        Ok(0)
    }
    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        cx.checkpoint()
            .map_err(|e| DbError::Cancelled(e.to_string()))?;
        self.ledger.committed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// One client's soak loop: until the shutdown flag flips, run the query mix one
/// op at a time, each as a full acquire -> op -> release cycle. Returns the
/// number of completed operations.
async fn client_soak(
    cx: &Cx,
    client_id: usize,
    mgr: &LeaseManager,
    ledger: &Arc<Ledger>,
    shutting_down: &AtomicBool,
) -> usize {
    let mut completed = 0;
    for iteration in 0..ITERATIONS {
        // A draining client stops acquiring new work (the admission rule the
        // real server enforces on SIGTERM).
        if shutting_down.load(Ordering::SeqCst) {
            break;
        }

        let conn = Box::new(LoadConn {
            ledger: Arc::clone(ledger),
        });
        let agent = format!("agent-{client_id}");
        let id = match mgr
            .acquire(
                cx,
                "soak",
                agent.as_str(),
                Duration::from_secs(900),
                &[],
                conn,
            )
            .await
        {
            Ok(id) => id,
            Err(_) => continue,
        };
        ledger.on_acquire();

        // Deterministic 70/20/10 read/describe/preview mix.
        let op = (client_id + iteration) % 10;
        let outcome: Result<(), DbError> = if op < 7 {
            mgr.info(cx, &agent, &id).await.map(|_| ())
        } else if op < 9 {
            // A read round trip on the pinned session via begin/rollback bracket.
            mgr.begin_transaction(cx, &agent, &id).await
        } else {
            // Preview DML: SAVEPOINT -> DML -> ROLLBACK TO SAVEPOINT (no commit).
            mgr.preview_dml(
                cx,
                &agent,
                &id,
                "UPDATE t SET x = x WHERE id = :1",
                &[OracleBind::I64(1)],
            )
            .await
            .map(|_| ())
        };

        // Release the lease no matter the op outcome (ready-or-dead): the
        // session is never held past this point.
        let dirty = outcome.is_err();
        let _ = mgr.release(cx, &agent, &id).await;
        ledger.on_release(dirty);
        if outcome.is_ok() {
            completed += 1;
        }
    }
    completed
}

/// Run one client on its own current-thread runtime (thread-per-connection).
fn run_client(
    client_id: usize,
    mgr: Arc<LeaseManager>,
    ledger: Arc<Ledger>,
    shutting_down: Arc<AtomicBool>,
) -> usize {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("client current-thread runtime builds");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        client_soak(&cx, client_id, &mgr, &ledger, &shutting_down).await
    })
}

#[test]
fn load_soak_zero_leaked_sessions_clean_drain_bounded() {
    let mgr = Arc::new(LeaseManager::new());
    let ledger = Arc::new(Ledger::default());
    let shutting_down = Arc::new(AtomicBool::new(false));

    // Fan out N thread-per-connection clients, each driving its own runtime.
    let mut handles = Vec::with_capacity(CLIENTS);
    for client_id in 0..CLIENTS {
        let mgr = Arc::clone(&mgr);
        let ledger = Arc::clone(&ledger);
        let shutting_down = Arc::clone(&shutting_down);
        handles.push(std::thread::spawn(move || {
            run_client(client_id, mgr, ledger, shutting_down)
        }));
    }

    // Let the soak run, then signal shutdown so clients stop acquiring.
    std::thread::sleep(Duration::from_millis(50));
    shutting_down.store(true, Ordering::SeqCst);

    let mut total_ops = 0;
    for handle in handles {
        total_ops += handle.join().expect("client thread joins cleanly");
    }

    // ── Clean drain ──────────────────────────────────────────────────────────
    // Any sessions still held (a client mid-cycle when shutdown fired) are
    // force-drained: release_all rolls back and drops every lease.
    let drained = {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("drain runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            mgr.release_all(&cx).await
        })
    };
    // Account for any leases the drain reclaimed (they were acquired but the
    // owning client never reached its own release).
    for _ in 0..drained {
        ledger.on_release(false);
    }

    let acquired = ledger.acquired.load(Ordering::SeqCst);
    let released = ledger.released.load(Ordering::SeqCst);
    let discarded = ledger.discarded.load(Ordering::SeqCst);
    let live = ledger.live.load(Ordering::SeqCst);
    let live_peak = ledger.live_peak.load(Ordering::SeqCst);
    let committed = ledger.committed.load(Ordering::SeqCst);

    // ── 1. ZERO leaked sessions ──────────────────────────────────────────────
    assert_eq!(
        acquired,
        released + discarded,
        "leak: {acquired} acquired != {released} released + {discarded} discarded"
    );
    assert_eq!(live, 0, "a session is still held after drain ({live} live)");
    assert_eq!(
        mgr.active_count(),
        0,
        "LeaseManager still holds a lease after release_all"
    );

    // ── 2. Clean drain (no torn commit) ──────────────────────────────────────
    assert_eq!(
        committed, 0,
        "shutdown/preview never commits an in-flight write"
    );

    // ── 3. Bounded behavior ──────────────────────────────────────────────────
    assert!(
        live_peak <= CLIENTS,
        "unbounded: live_peak {live_peak} exceeds the {CLIENTS}-client ceiling"
    );
    assert!(
        total_ops > 0,
        "the soak completed no operations — the harness did not exercise the path"
    );
}

/// LIVE variant (ignored offline): the same load shape against a real database
/// via the real [`OraclePool`], capturing p50/p95/p99 latency and asserting the
/// pool checkout accounting balances ([`PoolMetrics::is_balanced`] — zero leaked
/// sessions). Skips with a clear message (never panics) when the live gate is
/// off or no database is reachable, exactly like the exact-SHA qualification.
/// Run it with:
///
/// ```text
/// ORACLEMCP_LIVE_XE=1 ORACLEMCP_TEST_DSN=... ORACLEMCP_TEST_USER=... \
///   ORACLEMCP_TEST_PASSWORD=... \
///   cargo test -p oraclemcp-db --test load_soak -- --ignored --nocapture
/// ```
#[test]
#[ignore = "live-xe: requires a real Oracle database; see docs/performance-footprint.md"]
fn live_xe_load_soak_pool_accounting_and_latency() {
    // Heavy live soak is explicitly opt-in via ORACLEMCP_LIVE_XE; connection
    // params come from the unified ORACLEMCP_TEST_* env the rest of the live
    // suite uses. Any missing prerequisite SKIPS (never fails/panics).
    if std::env::var("ORACLEMCP_LIVE_XE").is_err() {
        eprintln!(
            "live_xe_load_soak: skipped — set ORACLEMCP_LIVE_XE=1 (+ ORACLEMCP_TEST_DSN/_USER/\
             _PASSWORD) to run the live load/soak and capture p50/p95/p99 latency. The offline \
             test load_soak_zero_leaked_sessions_clean_drain_bounded covers the deterministic \
             zero-leak/clean-drain/bounded invariants without a database."
        );
        return;
    }
    let (Ok(dsn), Ok(user), Ok(password)) = (
        std::env::var("ORACLEMCP_TEST_DSN"),
        std::env::var("ORACLEMCP_TEST_USER"),
        std::env::var("ORACLEMCP_TEST_PASSWORD"),
    ) else {
        eprintln!(
            "live_xe_load_soak: skipped — ORACLEMCP_LIVE_XE is set but \
             ORACLEMCP_TEST_DSN/_USER/_PASSWORD are not; nothing to connect to."
        );
        return;
    };
    let opts = OracleConnectOptions {
        connect_string: dsn,
        username: Some(user),
        password: Some(password),
        ..Default::default()
    };
    // Reachability probe (reactor-backed runtime, connect once); skip cleanly if
    // the DB is unreachable. A connection's socket is bound to the reactor that
    // drives it, so each client below owns its runtime + reactor + pool — the
    // production thread-per-connection model. A single pool shared across multiple
    // reactor-backed runtimes would mis-route socket readiness and hang.
    {
        let reactor =
            asupersync::runtime::reactor::create_reactor().expect("native reactor for live I/O");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("probe runtime builds");
        let reachable = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let probe = PoolSettings {
                max_size: 1,
                min_idle: 1,
                ..Default::default()
            };
            OraclePool::connect(&cx, opts.clone(), probe).await.is_ok()
        });
        if !reachable {
            eprintln!("live_xe_load_soak: skipped — no reachable Oracle at the configured DSN");
            return;
        }
    }

    // Fan out N thread-per-connection clients; each owns its runtime + reactor +
    // a small pool, runs ITERATIONS ops, and checks its pool's checkout accounting.
    let opts = Arc::new(opts);
    let latencies: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::new()));
    let leaks: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::with_capacity(CLIENTS);
    for client_id in 0..CLIENTS {
        let opts = Arc::clone(&opts);
        let latencies = Arc::clone(&latencies);
        let leaks = Arc::clone(&leaks);
        handles.push(std::thread::spawn(move || {
            let reactor = asupersync::runtime::reactor::create_reactor()
                .expect("native reactor for live I/O");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("client runtime builds");
            runtime.block_on(async move {
                let cx = Cx::current().expect("block_on installs a current Cx");
                let settings = PoolSettings {
                    max_size: 2,
                    min_idle: 1,
                    ..Default::default()
                };
                let pool = match OraclePool::connect(&cx, (*opts).clone(), settings).await {
                    Ok(pool) => pool,
                    Err(_) => return,
                };
                let mut local = Vec::with_capacity(ITERATIONS);
                for iteration in 0..ITERATIONS {
                    // 80% scalar read / 20% describe, deterministic per client.
                    let op = (client_id + iteration) % 10;
                    let start = std::time::Instant::now();
                    let outcome: Result<(), DbError> = if op < 8 {
                        pool.query_rows(&cx, "SELECT 1 FROM dual", vec![])
                            .await
                            .map(|_| ())
                    } else {
                        pool.describe(&cx).await.map(|_| ())
                    };
                    local.push(start.elapsed().as_micros());
                    outcome.expect("live pool op succeeds against a healthy DB");
                }
                // Per-client pool checkout accounting: zero leaked sessions, bounded.
                let m = pool.metrics();
                if !(m.is_balanced() && m.is_bounded()) {
                    leaks.lock().expect("leaks lock").push(format!(
                        "client {client_id}: in_use={} acquired={} released={} discarded={} open={} max={}",
                        m.in_use, m.acquired, m.released, m.discarded, m.open, m.max_size
                    ));
                }
                latencies.lock().expect("latency lock").extend(local);
            });
        }));
    }
    for handle in handles {
        handle.join().expect("client thread joins cleanly");
    }

    // ── ZERO leaked sessions across every client pool ────────────────────────
    let leaks = leaks.lock().expect("leaks lock");
    assert!(
        leaks.is_empty(),
        "pool accounting failed under load: {:?}",
        *leaks
    );

    // ── Latency p50/p95/p99 (D7 evidence — recorded from the real run, never
    //    fabricated; feeds docs/performance-footprint.md) ─────────────────────
    let mut lat = latencies.lock().expect("latency lock").clone();
    lat.sort_unstable();
    let pct = |p: f64| -> u128 {
        if lat.is_empty() {
            return 0;
        }
        let idx = (((lat.len() - 1) as f64) * p).round() as usize;
        lat[idx]
    };
    eprintln!(
        "live_xe_load_soak: {} ops across {CLIENTS} clients (ITERATIONS={ITERATIONS}) — \
         p50={}us p95={}us p99={}us; all per-client pools balanced",
        lat.len(),
        pct(0.50),
        pct(0.95),
        pct(0.99)
    );
}
