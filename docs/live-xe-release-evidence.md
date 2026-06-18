# Live XE Release Evidence

Date: 2026-06-18

Purpose: release evidence for `oraclemcp-epic-release-v7t.2`.

## Target

- Local Oracle Free container, exposed on loopback port 1521.
- PDB service: `FREEPDB1`.
- Synthetic test account: `ORACLEMCP_TEST`.
- Oracle version reported by the harness: `23.26.1.0.0`.
- Database role/open mode reported by the harness: `PRIMARY` / `READ WRITE`.

No real customer hostnames, schemas, credentials, wallet paths, or tokens are
recorded here.

## Command

```sh
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER='ORACLEMCP_TEST' \
ORACLEMCP_TEST_PASSWORD='<redacted synthetic local test password>' \
ORACLEMCP_TEST_EDITION='ORA$BASE' \
cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture
```

The command was run with the session's isolated `CARGO_TARGET_DIR` and serialized
through the `/tmp/oraclemcp-cargo-build.lock` build lock.

## Result

```text
test result: ok. 20 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.08s
```

Covered live paths included:

- username/password thin connect, ping, query, binds, and describe;
- session identity round trip;
- edition selection during authentication via `ORA$BASE`;
- invalid edition failure at connect time;
- SDU override connection;
- NUMBER string fidelity and ISO date/timestamp serialization;
- CLOB/BLOB locator materialization under caps;
- cursor expression and implicit result-set serialization;
- DBMS_OUTPUT capture through thin output binds;
- lease lifecycle, savepoint preview rollback, pagination, local pool round trip,
  and cancellation recovery.

## Expected Skips

The following checks were skipped because their optional local prerequisites were
not configured for this release proof:

- app-context namespace round trip: `ORACLEMCP_TEST_APP_CONTEXT` not set;
- DRCP routing: `ORACLEMCP_TEST_DRCP=1` not set;
- proxy auth: `ORACLEMCP_TEST_PROXY_USER` / target schema not set;
- wallet username/password: `ORACLEMCP_TEST_WALLET_LOCATION` not set;
- tier-1 intelligence fixture: `DEMO.PKG_AUTONOMOUS` fixture not present.

The profiling helper test remained ignored by design:
`live_perf_phase_split_connect_ping_query_describe`.
