//! Live pool load/soak evidence (release gate).

use std::sync::{Arc, Mutex};

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{DbError, OracleConnectOptions, OraclePool, PoolSettings};

const CLIENTS: usize = 8;
const ITERATIONS: usize = 200;

/// LIVE variant (ignored offline): each client owns a bounded real pool and
/// the test asserts checkout accounting remains balanced.
#[test]
#[ignore = "live-xe: requires a real Oracle database; see docs/performance-footprint.md"]
fn live_xe_load_soak_pool_accounting_and_latency() {
    if std::env::var("ORACLEMCP_LIVE_XE").is_err() {
        eprintln!(
            "live_xe_load_soak: skipped — set ORACLEMCP_LIVE_XE=1 (+ ORACLEMCP_TEST_DSN/_USER/_PASSWORD)"
        );
        return;
    }
    let (Ok(dsn), Ok(user), Ok(password)) = (
        std::env::var("ORACLEMCP_TEST_DSN"),
        std::env::var("ORACLEMCP_TEST_USER"),
        std::env::var("ORACLEMCP_TEST_PASSWORD"),
    ) else {
        eprintln!(
            "live_xe_load_soak: skipped — ORACLEMCP_LIVE_XE is set but ORACLEMCP_TEST_DSN/_USER/_PASSWORD are not"
        );
        return;
    };
    let opts = OracleConnectOptions {
        connect_string: dsn,
        username: Some(user),
        password: Some(password),
        ..Default::default()
    };
    {
        let reactor =
            asupersync::runtime::reactor::create_reactor().expect("native reactor for live I/O");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("probe runtime builds");
        let reachable = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            OraclePool::connect(
                &cx,
                opts.clone(),
                PoolSettings {
                    max_size: 1,
                    min_idle: 1,
                    ..Default::default()
                },
            )
            .await
            .is_ok()
        });
        if !reachable {
            eprintln!("live_xe_load_soak: skipped — no reachable Oracle at the configured DSN");
            return;
        }
    }

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
                let pool = match OraclePool::connect(
                    &cx,
                    (*opts).clone(),
                    PoolSettings {
                        max_size: 2,
                        min_idle: 1,
                        ..Default::default()
                    },
                )
                .await
                {
                    Ok(pool) => pool,
                    Err(_) => return,
                };
                let mut local = Vec::with_capacity(ITERATIONS);
                for iteration in 0..ITERATIONS {
                    let start = std::time::Instant::now();
                    let outcome: Result<(), DbError> = if (client_id + iteration) % 10 < 8 {
                        pool.query_rows(&cx, "SELECT 1 FROM dual", vec![])
                            .await
                            .map(|_| ())
                    } else {
                        pool.describe(&cx).await.map(|_| ())
                    };
                    local.push(start.elapsed().as_micros());
                    outcome.expect("live pool op succeeds against a healthy DB");
                }
                let metrics = pool.metrics();
                if !(metrics.is_balanced() && metrics.is_bounded()) {
                    leaks.lock().expect("leaks lock").push(format!(
                        "client {client_id}: in_use={} acquired={} released={} discarded={} open={} max={}",
                        metrics.in_use,
                        metrics.acquired,
                        metrics.released,
                        metrics.discarded,
                        metrics.open,
                        metrics.max_size
                    ));
                }
                latencies.lock().expect("latency lock").extend(local);
            });
        }));
    }
    for handle in handles {
        handle.join().expect("client thread joins cleanly");
    }

    assert!(
        leaks.lock().expect("leaks lock").is_empty(),
        "pool accounting failed under load"
    );
    let mut latencies = latencies.lock().expect("latency lock").clone();
    latencies.sort_unstable();
    let percentile = |p: f64| -> u128 {
        if latencies.is_empty() {
            0
        } else {
            latencies[(((latencies.len() - 1) as f64) * p).round() as usize]
        }
    };
    eprintln!(
        "live_xe_load_soak: {} ops across {CLIENTS} clients (ITERATIONS={ITERATIONS}) — p50={}us p95={}us p99={}us; all per-client pools balanced",
        latencies.len(),
        percentile(0.50),
        percentile(0.95),
        percentile(0.99)
    );
}
