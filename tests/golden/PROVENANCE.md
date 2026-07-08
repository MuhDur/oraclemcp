# Golden Behavior Fixtures

These fixtures freeze current client-visible behavior for bead
`oraclemcp-w1-golden-behavior-harness-y8p` before the stdio and HTTP transport
rewrites.

Generated with the repository-pinned Rust toolchain from this checkout:

```bash
UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior
UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior
UPDATE_GOLDENS=1 cargo test -p oraclemcp-db --test structured_schema_golden
```

Review rule: fixture changes are protocol behavior changes. Do not regenerate
and accept them without reading the diff. Dynamic Streamable HTTP session IDs
are scrubbed to `[SESSION_ID]`; the remaining values are expected to be stable.

`oracle-cell-structured/*.json` fixtures freeze the synthetic
`OracleCell::structured` payload examples covered by
`schemas/oracle-cell-structured.schema.json`. They were generated from the
repository-pinned `oraclemcp-db` serializer and contain no database data. The
schema's `x-oraclemcp-contract-version` must match
`ORACLE_CELL_STRUCTURED_CONTRACT_VERSION`.

All inputs are synthetic. The stdio init token strings, OAuth metadata, JWT
verifier key, database user/schema names, SQL text, hostnames, and Oracle error
messages in these fixtures are test-only values and are not real secrets or PII.

## Golden-artifact discipline (bead D6.3d)

`support.rs` is the shared harness every golden test includes via
`#[path = "../../../tests/golden/support.rs"] mod golden_support;`. It provides:

- **`Scrubber`** — a reusable canonicalizer (`Scrubber::standard()` +
  `.with_custom(pattern, replacement)`) that masks non-deterministic /
  secret-shaped dynamic values to stable placeholders (`[TIMESTAMP]`, `[UUID]`,
  `[DURATION]`, `[SCN]`, `[PATH]`, `[ADDR]`) before comparison, so a golden can
  never itself leak a secret or flake. The redaction subset (`[PATH]`/`[ADDR]`)
  is wired into every `assert_golden` surface; the broader canonicalizers are
  applied only to clean surfaces (they would over-scrub the deterministic
  fixture values — server/DB versions, JSON-schema bounds, synthetic timestamps —
  that the transcripts intentionally freeze).
- **`assert_golden` / `check_golden`** — on a mismatch they write a
  `<name>.actual` sidecar (gitignored) next to the golden and panic/return a
  unified diff plus the `UPDATE_GOLDENS=1` re-approval hint.

`demo/roundtrip.json` is the round-trip demo golden
(`crates/oraclemcp/tests/golden_scrubber_framework.rs`): generate → scrub →
assert → an intentional semantic change fails with a unified diff → re-approve.

The capabilities / serverInfo surface is snapshot-tested with **insta** in that
same file, with the shared `Scrubber` wired in as insta filters (the crate
version is masked to `[VERSION]` so the snapshot survives every release bump).

Regenerate (never in CI):

```bash
UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior --test doctor_secret_golden
UPDATE_GOLDENS=1 cargo test -p oraclemcp      --test golden_behavior
UPDATE_GOLDENS=1 cargo test -p oraclemcp-db   --test structured_schema_golden
UPDATE_GOLDENS=1 cargo test -p oraclemcp      --test golden_scrubber_framework   # demo golden
INSTA_UPDATE=always cargo test -p oraclemcp   --test golden_scrubber_framework   # insta snapshot
```
