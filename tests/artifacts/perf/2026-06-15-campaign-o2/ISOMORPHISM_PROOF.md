# O2 Isomorphism Proof

Change: replace `inner.close_cursor(cursor_id)` with
`inner.release_cursor(cursor_id)` after `collect_all_rows` consumes a query
result.

Behavior contract:

- Returned rows are unchanged; conversion still happens through
  `rows_to_oracle_rows`.
- Pagination/fetch behavior is unchanged; all remaining rows are still fetched
  before the cursor is released.
- The SQL guard, bind handling, serialization rules, and read-only posture are
  untouched.
- The thin driver decides whether a released cursor belongs in the statement
  cache or should be queued for close. This matches the driver's public
  lifecycle split between reusable cached cursors and copied cursors.

Proof commands:

```bash
cargo fmt --all -- --check
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER='system' \
ORACLEMCP_TEST_PASSWORD='<from plsql-intelligence-xe env>' \
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_connect_ping_query_bind_describe -- --exact --nocapture
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER='system' \
ORACLEMCP_TEST_PASSWORD='<from plsql-intelligence-xe env>' \
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_perf_phase_split_connect_ping_query_describe -- --ignored --exact --nocapture
```

Proof results:

- `cargo fmt --all -- --check`: passed after formatting.
- `live_connect_ping_query_bind_describe`: passed against Oracle 23ai
  `23.26.1.0.0`, including the new query-after-describe regression.
- `live_perf_phase_split_connect_ping_query_describe`: passed and emitted
  `raw/live-phase-split.csv` with 300 measured phase rows.
- Full `live_oracle` file against Oracle 23ai: passed with 9 tests, 0 failures,
  1 ignored profiling helper; DBMS_OUTPUT capture reported the expected thin
  driver unsupported skip.
- Secret scan confirmed the Docker Oracle password value is not present in O2
  artifacts.

The failed pre-fix symptom was `ORA-01001` on a reused session after
`describe()`. The fix keeps the cursor lifecycle inside the thin driver's
statement-cache contract instead of queuing reusable cursor ids for close.
