# DOC1 README And Comment Freshness

Scope: `readme-writing` + `de-slopify` pass for bead `oraclemcp-8fc.6`.

## Changes

- `README.md`: added the required `About Contributions` policy section before
  the license section. The existing README already documented the thin-native
  driver, nightly pin, safe-by-default guard, transports, profiles, safety
  model, architecture, limitations around unsupported thin-driver auth/features,
  and license, so this pass did not rewrite it wholesale.
- `AGENTS.md`: replaced stale ODPI-C/Instant Client runtime guidance with the
  current pure-Rust thin-driver contract, and removed em-dash prose in reviewed
  lines.
- `crates/oraclemcp-db/src/connection.rs`: replaced W4/W6b migration-era module
  text with the current synchronous thin-driver/asupersync API contract.
- `crates/oraclemcp-auth/src/http_guard.rs`: removed stale rmcp/axum transport
  wording and described the native/embedding transport contract.
- `crates/oraclemcp-auth/src/oauth_rs.rs`: removed stale axum transport wording
  around asymmetric token verification.
- `crates/oraclemcp-db/src/doctor.rs`: clarified that `thick_mode_enabled` is
  always false for this thin-native binary.

## De-Slopify Scan

Commands:

```bash
rg -n "W4|W6b|ODPI-C adapter|needs Oracle Instant Client|rmcp|axum|Here's why|It's not|At its core|Let's dive" README.md AGENTS.md crates --glob '*.rs' --glob '*.md'
rg -n "—" README.md AGENTS.md crates/oraclemcp-db/src/connection.rs crates/oraclemcp-auth/src/http_guard.rs crates/oraclemcp-auth/src/oauth_rs.rs crates/oraclemcp-db/src/doctor.rs crates/oraclemcp-db/src/pool.rs
```

Results:

- No stale transport/runtime migration references found in the reviewed public
  docs and comments.
- No em-dashes found in the reviewed README/AGENTS/comment paths.
