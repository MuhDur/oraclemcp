# C1/C2 Deadlock And Concurrency Audit

Scope: `deadlock-finder-and-fixer` pass for bead `oraclemcp-8fc.5`.

Static scan focus:

- `std::sync` locks and nested lock ordering.
- `block_on` bridges after the asupersync migration.
- Native HTTP worker lifecycle.
- Plugin subprocess pipe handling.
- Oracle pool, lease, and connection state.
- Dispatcher state serialization around the single live connection.

## Fixed Findings

### F1: Pool mutex held across Oracle liveness probe

Class: Class 1 / lock-held-across-blocking-I/O, with Class 3 resource-starvation
symptoms.

Before:

- `OraclePool::try_checkout` and `try_checkout_cx` popped an idle connection and
  called `manager.is_valid*()` while still holding the pool-state mutex.
- A dead TCP session or stalled Oracle ping could hold the pool mutex while
  other workers tried to check in healthy connections or check out new ones.

Concrete interleaving:

1. T1 enters checkout, locks `PoolState`, pops stale idle connection.
2. T1 calls Oracle ping while still holding `PoolState`.
3. T2 finishes real work and calls checkin, but blocks on `PoolState`.
4. T3 attempts checkout and also blocks on `PoolState`.
5. If the stale ping hangs until driver/network timeout, the whole pool appears
   wedged behind one validation call.

Fix:

- `take_checkout_slot()` now only pops an idle connection or reserves a new
  connection slot while holding `PoolState`.
- Idle validation and new physical connection setup run outside the pool mutex.
- Failed validation/setup decrements `open_count` through a short
  `forget_open_connection()` critical section.

Evidence:

- `crates/oraclemcp-db/src/pool.rs:280`
- `crates/oraclemcp-db/src/pool.rs:301`
- `crates/oraclemcp-db/src/pool.rs:322`

### F2: Native HTTP workers had no per-connection I/O deadline

Class: Class 7 / external-client resource race, with slowloris-style worker
pinning.

Before:

- `serve_http_until` spawns one worker per accepted connection.
- Request size is bounded, but a client that connects and never finishes
  headers/body can block that worker indefinitely in `read()`.

Fix:

- `handle_connection` now installs 30-second read and write timeouts on each
  accepted `TcpStream` before parsing the request.
- Timed-out abandoned clients now end the worker instead of accumulating stuck
  threads forever.

Evidence:

- `crates/oraclemcp-core/src/http.rs:904`
- `crates/oraclemcp-core/src/http.rs:924`

## Clean Findings

### Lease manager

Verdict: no AB-BA deadlock found.

`LeaseManager` has two lock layers: the lease map and the individual lease
mutex. The map lookup clones the `Arc` and releases the map lock before normal
lease operations. Expiry paths drop the lease lock before calling `remove`.
`release_all` drains the map before locking each lease. `reap_expired` does
lock map then lease while checking deadlines, but no audited path locks lease
then map without first dropping the lease.

Evidence:

- `crates/oraclemcp-db/src/lease.rs:187`
- `crates/oraclemcp-db/src/lease.rs:197`
- `crates/oraclemcp-db/src/lease.rs:215`
- `crates/oraclemcp-db/src/lease.rs:394`
- `crates/oraclemcp-db/src/lease.rs:424`

### Thin connection wrapper

Verdict: no lock-order cycle found.

`RustOracleConnection` has an inner Oracle connection mutex and a separate
call-timeout mutex. Query/execute paths read the timeout first, then lock the
inner connection. `set_call_timeout` only locks the timeout mutex, so there is
no reverse inner-then-timeout order.

### Dispatcher

Verdict: intentional serialization, no reentrant cycle found.

`OracleDispatcher` serializes the live connection behind one state mutex.
`oracle_switch_profile` opens/describes the replacement connection and loads
profile custom tools before taking the state lock. The remaining tool arms hold
the lock while using the live connection, which is intentional serialization
rather than a lock-order deadlock. The downside is bounded throughput, not
cycle risk.

Evidence:

- `crates/oraclemcp/src/dispatch/mod.rs:3023`
- `crates/oraclemcp/src/dispatch/mod.rs:3062`

### Plugin subprocess runner

Verdict: pipe deadlock deliberately avoided.

The subprocess plugin runner writes stdin on one thread and drains stdout/stderr
on separate threads. On timeout it kills and reaps the child, then deliberately
does not join reader threads because a grandchild may have inherited pipe write
ends. This avoids the synchronous-pipe deadlock and timeout-overrun hazard.

Evidence:

- `crates/oraclemcp-core/src/plugin.rs:176`
- `crates/oraclemcp-core/src/plugin.rs:190`
- `crates/oraclemcp-core/src/plugin.rs:209`

### Asupersync block-on bridges

Verdict: no lock-held-across-async wait found in production code.

The static scan found `block_on` in the server-owned synchronous transport
bridge and in tests. The bridge runs tool dispatch through the server-owned
asupersync runtime; no `std::sync::Mutex` guard was found crossing an `.await`
point in production code.

## Verification

```bash
cargo fmt --all -- --check
cargo test -p oraclemcp-db pool::tests
cargo test -p oraclemcp-core http::tests::serve_http_until_stops_accepting_and_drains_worker
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER='system' \
ORACLEMCP_TEST_PASSWORD='<from plsql-intelligence-xe env>' \
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_pool_thin_roundtrip -- --exact --nocapture
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER='system' \
ORACLEMCP_TEST_PASSWORD='<from plsql-intelligence-xe env>' \
cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture
```

Results:

- Formatting passed.
- Pool unit tests passed.
- Native HTTP shutdown/drain test passed.
- Full clippy gate passed with `-D warnings`.
- Full workspace test suite passed.
- `cargo deny check` passed; it still reports the existing unmatched
  allowance/advisory warnings from `deny.toml`.
- Live Oracle 23ai pool roundtrip passed.
- Full live Oracle 23ai suite passed: 9 passed, 1 ignored profiling helper;
  DBMS_OUTPUT capture reported the expected explicit thin-driver unsupported
  skip.
