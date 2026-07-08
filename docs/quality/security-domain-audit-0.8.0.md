# Security-Domain Audit: 0.8.0 Pre-Tag Surface

D6.8 audit date: 2026-07-08.

Scope: focused security review of the new or always-shipping 0.8.0 attack
surface called out by the release gate: server IAM `token_exec`, HTTP
`allow_remote`, dashboard guarded operator routes, and shipped K.2 additions.
K6 cassette support-capture is noted out-of-surface because it is an `oracledb`
driver bead and this repository records no committed HTTP/DB cassettes.

## Summary

- **Total findings:** 0
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Release gate:** pass. There are zero unresolved Critical or High findings.

## Findings

No security findings were identified in this focused audit.

## Audited Surfaces

| Surface | Verdict | Evidence |
| --- | --- | --- |
| IAM `token_exec` | Pass | Config selection is mutually exclusive and fails closed on ambiguity (`crates/oraclemcp-core/src/iam_token.rs:170`). The command is spawned as an argv array with no shell, closed stdin, piped stdout/stderr, 5s timeout, and 64 KiB stdout cap (`crates/oraclemcp-core/src/iam_token.rs:299`). Output must be non-empty UTF-8 in the JWT/base64url charset and non-zero exits fail before stdout is trusted (`crates/oraclemcp-core/src/iam_token.rs:391`). The TCPS gate runs before token resolution, so a non-TCPS profile cannot even spawn `token_exec` (`crates/oraclemcp-core/src/iam_token.rs:473`). Tests cover non-TCPS no-spawn, ambiguity, token-free debug/errors, and exec fuzz cases (`crates/oraclemcp-core/src/iam_token.rs:1049`, `crates/oraclemcp-core/src/iam_token.rs:1121`). |
| HTTP `allow_remote` | Pass | `allow_remote` defaults false (`crates/oraclemcp-config/src/lib.rs:277`) and `ORACLEMCP_HTTP_ALLOW_REMOTE` is ignored by config load so it remains a runtime serve-time override only (`crates/oraclemcp-config/src/lib.rs:43`). Serve-time validation still requires OAuth/mTLS/client credentials or explicit `--allow-no-auth`, and non-loopback binding requires a second opt-in (`crates/oraclemcp/src/main.rs:2685`, `crates/oraclemcp/src/main.rs:3017`). Unit tests cover loopback allow, remote refusal, remote opt-in, and auth-refusal precedence (`crates/oraclemcp/src/main_tests.rs:256`). |
| Dashboard guarded operator routes | Pass | Pairing tickets are short-lived one-time local files with 0600 mode and hashed secrets on disk (`crates/oraclemcp-core/src/dashboard_auth.rs:340`). The session cookie is `HttpOnly` and `SameSite=Strict`; action tickets are route-scoped hashes bound to session id, CSRF token, method, and path (`crates/oraclemcp-core/src/dashboard_auth.rs:431`). Browser POSTs require same-origin headers, the dashboard session cookie, CSRF header, and the route-scoped action ticket before normal operator authority is evaluated (`crates/oraclemcp-core/src/http/mod.rs:1915`). Operator routes also require operator authority and an appendable audit chain before dispatch (`crates/oraclemcp-core/src/http/mod.rs:1722`, `crates/oraclemcp-core/src/http/mod.rs:2138`). Browser DDL/Admin apply is release-gated before MCP dispatch (`crates/oraclemcp-core/src/http/mod.rs:4690`). Tests cover single-use pairing, strict cookie/session view, CSRF/cross-origin rejection, uniform auth errors, and dashboard DDL apply blocked before dispatch (`crates/oraclemcp-core/src/dashboard_auth.rs:518`, `crates/oraclemcp-core/src/http/tests.rs:2237`, `crates/oraclemcp-core/src/http/tests.rs:2723`, `crates/oraclemcp-core/src/http/tests.rs:2938`, `crates/oraclemcp-core/src/http/tests.rs:5694`). |
| K6 cassette support-capture | Out-of-surface | The D6.8-required K6 audit item did not ship in this repository. The local bead is still `in_progress` and marked `repo: oracledb`; this checkout also states that it records no HTTP/DB cassettes and requires provenance if one is ever committed (`tests/conformance/PROVENANCE.md:31`). |
| K8 StructuredReason coach | Pass | `StructuredReason` and `ReasonCategory` are additive optional fields on `ErrorEnvelope` and omit empty fields from the wire form (`crates/oraclemcp-error/src/lib.rs:106`, `crates/oraclemcp-error/src/lib.rs:228`). The dispatcher builds the structured reason after the existing guard decision and only attaches guidance/rewrites; it never changes the guard decision, error class, or execution path (`crates/oraclemcp/src/dispatch/mod.rs:1386`). Rewrite hints are observational and restricted to safe literal positions (`crates/oraclemcp-guard/src/rewrite.rs:1`). Tests cover round-trip serialization and representative refusal classes with/without minimal rewrites (`crates/oraclemcp-error/src/lib.rs:597`, `crates/oraclemcp/src/dispatch/tests.rs:4862`). |
| K9 structured `as_of` flashback read | Pass | `as_of` is a structured argument separate from SQL, with exactly one of `scn` or `timestamp` required before classification or I/O (`crates/oraclemcp/src/dispatch/args.rs:59`, `crates/oraclemcp/src/dispatch/mod.rs:774`). The base SQL is classified unchanged and must pass the read-only gate before any flashback work (`crates/oraclemcp/src/dispatch/mod.rs:5656`). SCN/timestamp values are bound into fixed `DBMS_FLASHBACK.ENABLE_*` templates and never interpolated into SQL (`crates/oraclemcp-db/src/query.rs:125`). The flashback window is bracketed with rollback, defensive disable, enable, read, disable, and rollback; disable is surfaced as an error if the read succeeded but teardown failed (`crates/oraclemcp-db/src/query.rs:184`). The driver override skips adapter pre-checkpoints for cleanup so cancellation cannot strand a session in flashback mode (`crates/oraclemcp-db/src/connection.rs:653`, `crates/oraclemcp-db/src/connection.rs:4376`). Tests prove classifier input identity, non-read refusal before DB I/O, invalid `as_of` refusal, happy-path wrapper dispatch, non-interpolated binds, and teardown on read failure (`crates/oraclemcp/src/dispatch/tests.rs:2915`, `crates/oraclemcp-db/src/query.rs:619`, `crates/oraclemcp-db/src/query.rs:848`). |

## Notes

- Raw Oracle flashback SQL remains handled by the classifier's existing
  fail-closed behavior; K9 does not teach the prover to accept handwritten
  `AS OF` SQL.
- K10 streaming was reviewed as adjacent surface because it intersects K9:
  streaming is delivery-only and is mutually exclusive with `export` and
  `as_of` (`crates/oraclemcp/src/dispatch/mod.rs:6474`,
  `crates/oraclemcp/src/dispatch/tests.rs:5997`).
- Dependency and secret gates are still run by the release preflight; this
  report is the focused code-level security audit for D6.8.
