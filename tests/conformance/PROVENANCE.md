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
real hostnames, OCIDs, customer identifiers, secrets, or PII, with the single
exception of the vendored MIT sample schemas below, which are third-party
upstream source rather than fixtures we authored.

### Vendored trees record provenance as data, not prose

A third-party tree vendored with a `vendored-sample-schemas/v1` `MANIFEST.json`
is exempt from needing one row per file, because the manifest already records
strictly more than a row could: upstream repository, tag, commit, license,
retrieval date, and a **git-blob-sha1 for every file**. Transcribing those into
this table would create a second register with nothing keeping the two in
agreement — and the transcription carries no hashes, so it would be weaker than
the thing it duplicates and the first drift would be silent.

The exemption is not free. `provenance_check.sh` re-hashes every file the
manifest lists and fails if any byte has moved, so vendored upstream code gains
tamper-detection that no prose row has ever provided. A file sitting inside a
vendored tree that the manifest does **not** list is not covered and still needs
its own row here — that is how something gets quietly added to a vendored
directory. The manifest itself is registered below, so this table keeps pointing
at the source of truth.

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
| `crates/oraclemcp-core/tests/fixtures/mtls/c3_client.der` | Synthetic mTLS client leaf certificate, DER (lab-only; `CN=c3-fixture-mtls-client, O=oraclemcp-test-fixtures`), self-signed. SHA-256 `e054ab20728e767d8345c46ff53c4f33453094af5688cdff64b45922c01aef01`. The C3 wire-contract fixture asserts hand-written operator fingerprint spellings against the runtime `mtls:sha256:<hex>` principal key. **Private key deliberately discarded** — the fixture carries identity through the authorization path and never completes a handshake, so no key material is committed | `openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out c3_client.pem -days 36500 -nodes -subj "/CN=c3-fixture-mtls-client/O=oraclemcp-test-fixtures"` then `openssl x509 -in c3_client.pem -outform DER -out c3_client.der`. Do NOT regenerate casually: the committed hex literal in `crates/oraclemcp-core/tests/c3_mtls_literal_fingerprints.rs` is externally transcribed on purpose, and `c3_committed_certificate_hashes_to_the_literal_hex` fails if the two drift. Inspect with `openssl x509 -inform DER -in <path> -noout -text` |
| `crates/oraclemcp-verifier/tests/fixtures/test-attestation-v1.golden.jsonl` | Golden: byte-stable `test-attestation/v1` signed document (synthetic key `test-attestation-key`, synthetic outcomes; pins the wire format for the browser re-verifier) | `UPDATE_GOLDENS=1 cargo test -p oraclemcp-verifier --test test_attestation` — see ADR-0012 |
| `schemas/operator.schema.json` | Generated from the Rust operator v1 protocol (`crates/oraclemcp-core/src/operator_protocol.rs`) | `bash scripts/generate_operator_schema.sh` (UPDATE_OPERATOR_SCHEMA=1 …generated_operator_schema_artifacts_match) |
| `schemas/oracle-cell-structured.schema.json` | Authored source-of-truth JSON Schema for `OracleCell::structured` (contract version pinned to `ORACLE_CELL_STRUCTURED_CONTRACT_VERSION`) | Hand-authored; validated by `crates/oraclemcp-db/tests/structured_schema_golden.rs` |
| `schemas/evidence/required-proof-v1.schema.json` | Cross-repo evidence-contract-v1 schema, byte-identical to the rust-oracledb canonical artifact | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-evidence-controls-f1cl.1` |
| `schemas/evidence/release-candidate-proof-v1.schema.json` | Cross-repo evidence-contract-v1 schema, byte-identical to the rust-oracledb canonical artifact | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-evidence-controls-f1cl.1` |
| `schemas/evidence/mutation-result-v1.schema.json` | Cross-repo evidence-contract-v1 schema, byte-identical to the rust-oracledb canonical artifact | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-evidence-controls-f1cl.1` |
| `schemas/evidence/bead-close-evidence-v1.schema.json` | Cross-repo evidence-contract-v1 schema, byte-identical to the rust-oracledb canonical artifact | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-evidence-controls-f1cl.1` |
| `schemas/evidence/fixtures/manifest.json` | Cross-repo evidence-contract-v1 fixture manifest; the server adds its two documented server-only negative cases to the mirrored baseline | `python3 scripts/validate_evidence.py --check-fixtures` |
| `schemas/evidence/fixtures/valid/required-proof-pass.json`<br>`schemas/evidence/fixtures/valid/required-proof-fail.json`<br>`schemas/evidence/fixtures/valid/release-candidate-proof.json`<br>`schemas/evidence/fixtures/valid/mutation-result.json`<br>`schemas/evidence/fixtures/valid/bead-close-evidence.json` | Mirrored valid cross-repo evidence-contract-v1 fixtures | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-evidence-controls-f1cl.1` |
| `schemas/evidence/fixtures/invalid/malformed-sha.json`<br>`schemas/evidence/fixtures/invalid/skipped-as-pass.json`<br>`schemas/evidence/fixtures/invalid/null-end-time.json`<br>`schemas/evidence/fixtures/invalid/arithmetic-mismatch.json`<br>`schemas/evidence/fixtures/invalid/wrong-artifact-sha.json`<br>`schemas/evidence/fixtures/invalid/required-ci-not-green.json`<br>`schemas/evidence/fixtures/invalid/tag-version-mismatch.json`<br>`schemas/evidence/fixtures/invalid/stale-command-sha.json`<br>`schemas/evidence/fixtures/invalid/tree-dirty.json`<br>`schemas/evidence/fixtures/invalid/shard-incomplete.json`<br>`schemas/evidence/fixtures/invalid/unwitnessed-kill.json`<br>`schemas/evidence/fixtures/invalid/scoped-test-marks-ready.json`<br>`schemas/evidence/fixtures/invalid/live-claim-without-artifact.json`<br>`schemas/evidence/fixtures/invalid/defect-without-bead.json` | Mirrored invalid cross-repo evidence-contract-v1 fixtures; each is structurally valid and must fail for the exact declared semantic rule and path | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-evidence-controls-f1cl.1` |
| `schemas/evidence/fixtures/invalid/server-required-local-proof-parent-sha.json` | Server-only negative fixture: a release candidate cannot inherit `oraclemcp` required-local evidence from its parent SHA | `python3 scripts/validate_evidence.py --check-fixtures` |
| `schemas/evidence/fixtures/invalid/server-adb-live-claim-without-artifact.json` | Server-only negative fixture: an OCI/ADB live claim without an artifact is refused | `python3 scripts/validate_evidence.py --check-fixtures` |
| `schemas/evidence/required-proof-v2.schema.json`<br>`schemas/evidence/release-candidate-proof-v2.schema.json` | Cross-repo evidence-contract-v2 schemas, byte-identical to the rust-oracledb canonical artifacts | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-sy6k` |
| `schemas/evidence/fixtures/valid/release-candidate-proof-v2.json` | Mirrored valid cross-repo evidence-contract-v2 fixture | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-sy6k` |
| `schemas/evidence/fixtures/invalid/duplicate-kill-mutant.json`<br>`schemas/evidence/fixtures/invalid/duplicate-survivor-mutant.json`<br>`schemas/evidence/fixtures/invalid/fail-zero-exit-code.json`<br>`schemas/evidence/fixtures/invalid/missing-required-command.json`<br>`schemas/evidence/fixtures/invalid/missing-survivor-taxonomy.json`<br>`schemas/evidence/fixtures/invalid/mutation-null-end-time.json`<br>`schemas/evidence/fixtures/invalid/nan-rate.json`<br>`schemas/evidence/fixtures/invalid/null-exit-code.json`<br>`schemas/evidence/fixtures/invalid/overlapping-mutant.json`<br>`schemas/evidence/fixtures/invalid/pass-nonzero-exit-code.json` | Mirrored invalid cross-repo evidence-contract-v2 fixtures; each is structurally valid and must fail for the exact declared semantic rule and path | `python3 scripts/validate_evidence.py --check-fixtures`; canonical source is `rust-oracledb` bead `rust-oracledb-sy6k` |
| `tests/fixtures/tns/cycle/cycle_b.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/cycle/tnsnames.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/malformed/tnsnames.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/tnsnames_include.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/tns/tnsnames.ora` | Synthetic hand-authored `tnsnames.ora` fixture (no real hosts/OCIDs) | Hand-authored for the TNS parser tests (`crates/oraclemcp-config`); no generator |
| `tests/fixtures/rig/refusal_corpus_baseline.jsonl` | Hand-authored refusal-corpus baseline (synthetic case IDs, synthetic `sql_sha256` placeholders; no real SQL or customer data). The R4 refusal gate (`scripts/rig/refusal_corpus_gate.py`) diffs a live `oraclemcp refusal-corpus export` against this baseline and fails on any category or allowed-status drift | Hand-authored; regenerate the *candidate* with `oraclemcp --json refusal-corpus export --out /tmp/candidate.jsonl`, then diff: `python3 scripts/rig/refusal_corpus_gate.py --baseline tests/fixtures/rig/refusal_corpus_baseline.jsonl --candidate /tmp/candidate.jsonl` |
| `tests/fixtures/rig/refusal_corpus_seeded_flip.jsonl` | Deliberately-mutated copy of the baseline (two records have flipped `allowed`/`category` values) used to prove the R4 gate detects drift — the gate must FAIL when this file is the candidate | Hand-authored mutation of the baseline; never used as a live baseline |
| `tests/fixtures/ui/operator-v1/active-lanes.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/audit-tail-unavailable.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/change-proposals.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
| `tests/fixtures/ui/operator-v1/ci-lanes.json` | Operator v1 UI fixture, authored to the Rust operator schema | `bash scripts/ui_fixtures_validate_against_rust_schema.sh` validates against the Rust schema source of truth |
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
| `tests/fixtures/coverage_ratchet/changed-line.diff` | Hand-authored D2 self-test fixture: a synthetic changed-line diff the coverage ratchet must accept/reject deterministically | Hand-edit alongside `scripts/coverage_ratchet.sh` self-test; synthetic, no generator |
| `tests/fixtures/coverage_ratchet/changed-line-covered.lcov` | Hand-authored D2 self-test fixture: lcov marking the synthetic changed lines covered (must PASS the ratchet) | Hand-edit alongside `scripts/coverage_ratchet.sh` self-test; synthetic, no generator |
| `tests/fixtures/coverage_ratchet/changed-line-lowered.lcov` | Hand-authored D2 self-test fixture: lcov leaving a changed line uncovered (must FAIL the ratchet) | Hand-edit alongside `scripts/coverage_ratchet.sh` self-test; synthetic, no generator |
| `tests/fixtures/coverage_ratchet/mutation-floor-valid.md.in` | Hand-authored D2 self-test fixture: a valid per-crate mutation-floor report the gate must accept | Hand-edit alongside `scripts/mutation_safety_gate.sh check-floor-report` self-test; synthetic |
| `tests/fixtures/coverage_ratchet/mutation-floor-low-guard.md.in` | Hand-authored D2 self-test fixture: guard kill-rate below floor (must FAIL the gate) | Hand-edit alongside `scripts/mutation_safety_gate.sh check-floor-report` self-test; synthetic |
| `tests/fixtures/coverage_ratchet/mutation-floor-low-audit.md.in` | Hand-authored D2 self-test fixture: audit kill-rate below floor (must FAIL the gate) | Hand-edit alongside `scripts/mutation_safety_gate.sh check-floor-report` self-test; synthetic |
| `tests/fixtures/coverage_ratchet/mutation-floor-low-db.md.in` | Hand-authored D2 self-test fixture: db kill-rate below floor (must FAIL the gate) | Hand-edit alongside `scripts/mutation_safety_gate.sh check-floor-report` self-test; synthetic |
| `crates/oraclemcp-core/tests/fixtures/wallet/legacy_3des_p12/ewallet.p12` | Synthetic Oracle wallet (lab-only; `CN=oracle-test.invalid`), sealed with **legacy** PKCS#12 `pbeWithSHA1And3-KeyTripleDES-CBC` (OID `1.2.840.113549.1.12.1.3`) so the P-U4 doctor probe is proven against the shape still common in the field, not only modern PBES2. Cert + key only, no `cwallet.sso`, so the p12 is unambiguously primary. Fixture password `oracle-test-wallet-16` | OpenSSL 3.5.5 `pkcs12 -export -legacy -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1` over a self-signed 2048-bit key — full command, subject, and the "both bags must say TripleDES" verification in `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` § `legacy_3des_p12/`. PKCS#12 output is not byte-deterministic, so these bytes are committed once and asserted by decryption (`doctor_wallet_posture.rs::legacy_3des_p12_decrypts_through_the_server_wallet_path`), never by hash |
| `tests/fixtures/sample_schemas/governance/governance_overlay.sql` | Hand-authored D9 rig governance layer, entirely ours. The MIT sample schemas ship realistic shape but no governance surface at all — no VPD/RLS, no proxy authentication, no logoff auditing — which is exactly what the guard, lease, and audit paths need to run against. Layered on top so the vendored SQL is never edited in place. **Synthetic only**: every identifier is invented, nothing is derived from a real or field-test environment | Hand-edit alongside the rig L2 scenarios; no generator. Rationale and the never-edit-vendored-SQL rule in `tests/fixtures/sample_schemas/PROVENANCE.md` |
| `tests/fixtures/sample_schemas/upstream/MANIFEST.json` | Vendoring record for the MIT `oracle-samples/db-sample-schemas` tree (tag `v23.3`, commit `e3325a83e56c516815844025418a96ecaf219751`, MIT, `LICENSE.txt` retained), carrying a git-blob-sha1 for every vendored file. This is the source of truth for the 19 files it covers, which is why they carry no rows of their own | Hand-maintained at re-vendor time. `scripts/provenance_check.sh` re-hashes every listed file against it on each run, so an edit to vendored upstream source fails the gate |
