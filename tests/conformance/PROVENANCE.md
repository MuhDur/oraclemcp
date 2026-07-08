# Committed generated-artifact provenance register

Every generated artifact committed to this repository — golden fixtures,
operator/UI fixtures, JSON Schemas, generated TypeScript, synthetic Oracle
wallets, and synthetic `tnsnames.ora` fixtures — has an entry below recording
**how it was made** (generator tool + regeneration command) and **where its
source of truth lives**. This kills the "regenerated six months later, why is it
different?" failure mode: a reviewer can always reproduce or diff any artifact.

This register is distinct in scope from the two focused provenance docs it
cross-references:

- `tests/golden/PROVENANCE.md` — golden-artifact discipline (the `Scrubber`,
  `assert_golden`, and the per-suite `UPDATE_GOLDENS=1` rebless commands).
- `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` — the exact
  OpenSSL/orapki commands, OpenSSL version, subject, and passwords for the
  synthetic wallet bytes.

`scripts/provenance_check.sh` enforces this file: it enumerates every committed
(and every untracked, non-ignored) artifact under the in-scope roots and FAILS
if any lacks a verbatim entry here. All committed inputs are **synthetic** — no
real hostnames, OCIDs, customer identifiers, secrets, or PII.

## In-scope roots

`tests/golden/`, `tests/fixtures/`, `crates/*/tests/fixtures/`, `schemas/`, and
`ui/generated/`. Out of scope: `tests/artifacts/perf/` (one-time performance
campaign evidence, each campaign self-describing via its own
`fingerprint.json`), and `*.md` / `*.rs` / `*.actual` support files.

## No committed cassettes

This repository records no HTTP/DB cassettes: live-database coverage runs
against a real env-gated Oracle (`ORACLEMCP_TEST_*`), never a recorded replay.
If a cassette is ever committed, it MUST gain an entry here (generator tool +
exact command + git-ref) and the check will fail until it does.

## Artifact register

| Artifact | Origin | Regenerate / source of truth |
| --- | --- | --- |
| `crates/oraclemcp-core/tests/fixtures/wallet/good_sso/cwallet.sso` | Synthetic Oracle wallet (lab-only; CN=oracle-test.invalid) | OpenSSL 3.5.5 legacy chain / orapki SSO copied from the oracledb driver fixture — see `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` |
| `crates/oraclemcp-core/tests/fixtures/wallet/undecryptable_without_sso/ewallet.pem` | Synthetic Oracle wallet (lab-only; CN=oracle-test.invalid) | OpenSSL 3.5.5 legacy chain / orapki SSO copied from the oracledb driver fixture — see `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` |
| `crates/oraclemcp-core/tests/fixtures/wallet/undecryptable_with_sso/cwallet.sso` | Synthetic Oracle wallet (lab-only; CN=oracle-test.invalid) | OpenSSL 3.5.5 legacy chain / orapki SSO copied from the oracledb driver fixture — see `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` |
| `crates/oraclemcp-core/tests/fixtures/wallet/undecryptable_with_sso/ewallet.pem` | Synthetic Oracle wallet (lab-only; CN=oracle-test.invalid) | OpenSSL 3.5.5 legacy chain / orapki SSO copied from the oracledb driver fixture — see `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` |
| `crates/oraclemcp-core/tests/fixtures/wallet/expired_cert/ewallet.pem` | Synthetic cert-only Oracle wallet (lab-only; CN=oracle-test.invalid), explicitly EXPIRED validity (2020-01-01 .. 2020-02-01 UTC) for the K1 cert-expiry WARN | OpenSSL 3.5.5 `req -x509 -not_before 20200101000000Z -not_after 20200201000000Z` (cert only, no key) — see `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` |
| `schemas/operator.schema.json` | Generated from the Rust operator v1 protocol (`crates/oraclemcp-core/src/operator_protocol.rs`) | `bash scripts/generate_operator_schema.sh` (UPDATE_OPERATOR_SCHEMA=1 …generated_operator_schema_artifacts_match) |
| `schemas/oracle-cell-structured.schema.json` | Authored source-of-truth JSON Schema for `OracleCell::structured` (contract version pinned to `ORACLE_CELL_STRUCTURED_CONTRACT_VERSION`) | Hand-authored; validated by `crates/oraclemcp-db/tests/structured_schema_golden.rs` |
| `tests/fixtures/tns/cycle/cycle_b.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/cycle/tnsnames.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/malformed/tnsnames.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/tnsnames_include.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/tnsnames.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/ui/operator-v1/active-lanes.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/audit-tail-unavailable.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/change-proposals.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/client-credentials.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/event-snapshot.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/gated-action.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/health.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/route-index.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/schema-diff.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/source-history.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/golden/demo/roundtrip.json` | Golden: round-trip scrubber demo (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_scrubber_framework` |
| `tests/golden/doctor/connectivity_failure_secret_redaction.json` | Golden: doctor secret-redaction transcript (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test doctor_secret_golden` |
| `tests/golden/http/host_origin_guards.json` | Golden: frozen HTTP/OAuth wire behavior (synthetic; session ids scrubbed) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/http/protected_resource_metadata.json` | Golden: frozen HTTP/OAuth wire behavior (synthetic; session ids scrubbed) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/http/served_auth_scope_session_matrix.json` | Golden: frozen HTTP/OAuth wire behavior (synthetic; session ids scrubbed) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/http/stateful_streamable_session.json` | Golden: frozen HTTP/OAuth wire behavior (synthetic; session ids scrubbed) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/http/stateless_initialize_json_response.json` | Golden: frozen HTTP/OAuth wire behavior (synthetic; session ids scrubbed) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/http/unauthorized_www_authenticate.json` | Golden: frozen HTTP/OAuth wire behavior (synthetic; session ids scrubbed) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/oracle-cell-structured/array-json-vector-tstz.json` | Golden: `oraclemcp-db` structured-cell serializer output (synthetic, no DB data) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-db --test structured_schema_golden` |
| `tests/golden/oracle-cell-structured/generic-unsupported.json` | Golden: `oraclemcp-db` structured-cell serializer output (synthetic, no DB data) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-db --test structured_schema_golden` |
| `tests/golden/oracle-cell-structured/object-unsupported.json` | Golden: `oraclemcp-db` structured-cell serializer output (synthetic, no DB data) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-db --test structured_schema_golden` |
| `tests/golden/oracle-cell-structured/oson-scalars.json` | Golden: `oraclemcp-db` structured-cell serializer output (synthetic, no DB data) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-db --test structured_schema_golden` |
| `tests/golden/stdio/completion_complete.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/init_token_failures.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/main_tool_transcript.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/progress_and_list_changed.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/query_export_resource_and_resource_link.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/query_opaque_cursor_pagination.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/resource_subscribe_and_updated.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/search_objects_detail_levels.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `tests/golden/stdio/structured_error_envelope.json` | Golden: frozen stdio MCP wire behavior (synthetic) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior` — see `tests/golden/PROVENANCE.md` |
| `ui/generated/operator-v1.ts` | Generated TypeScript types from the Rust operator v1 protocol | `bash scripts/generate_operator_schema.sh` (UPDATE_OPERATOR_SCHEMA=1 …generated_operator_schema_artifacts_match) |

