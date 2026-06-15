# R2 Isomorphism Proof

Target: simplify `RustOracleConnection::describe()` by extracting
`query_first_row`.

Before:

- Each best-effort metadata query repeated:
  `query_rows(sql, &[]).ok().and_then(|rows| rows.into_iter().next())`.
- The version query used `rows.first()` and then discarded the rest.

After:

- `query_first_row(sql)` centralizes the same best-effort query behavior.
- All `describe()` metadata probes still ignore individual query failures and
  keep filling whatever metadata is available.
- SQL strings, bind lists, field mapping, and `with_read_only_status()` are
  unchanged.

Risk controls:

- No tool registry, dispatch, SQL guard, serialization, or transport code was
  touched.
- The helper is private to `RustOracleConnection`.
- The live query-after-describe regression from O2 still covers the connection
  metadata path against Oracle 23ai.

Proof commands:

```bash
cargo fmt --all -- --check
cargo test -p oraclemcp-db connection::tests::driver_error_redaction_removes_connect_material
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER='system' \
ORACLEMCP_TEST_PASSWORD='<from plsql-intelligence-xe env>' \
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_connect_ping_query_bind_describe -- --exact --nocapture
```

Proof results:

- Formatting check passed after rustfmt.
- Focused unit test passed.
- Live Oracle 23ai regression passed against version `23.26.1.0.0`.

Net effect:

- Removes duplicated best-effort row extraction logic from `describe()`.
- No behavior change intended or observed.
