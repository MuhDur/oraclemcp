# Security-Domain Audit: 0.8.0 Pre-Tag Surface

D6.8 audit date: 2026-07-08.

Scope: security-domain review of all accumulated `oraclemcp` server changes
since the 0.7.x release line that affect authority, transport, credentials,
observability, or operator workflows. This includes the original D6.8
always-shipping surface (`token_exec`, HTTP `allow_remote`, dashboard guarded
routes, shipped K.2 additions) plus the near-final 0.8.0 server surface:
guard/classifier, audit chain, IAM, wallet/doctor, streaming, `as_of`, and
`oracle_explain_plan`.

The `SEC-1`..`SEC-7` names below are audit lenses for this report. `SEC-1` is
also an explicit in-code/release-plan label; the remaining lenses map to the
same threat model controls and release-gate tests.

## Summary

- **Total findings:** 0
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Code fixes required by this audit:** none
- **Release gate:** pass. There are zero unresolved Critical or High findings.

## Findings

No security findings were identified in this audit. No tighten-only code fix was
needed for D6.8.

## SEC Audit Lenses

| Lens | Verdict | Evidence |
| --- | --- | --- |
| SEC-1 live authority is re-derived at apply/recovery time | Pass | Stored execute grants and proposal verdicts are not authorization inputs. Dispatch SEC-1 tests assert stale grants are invalidated on lowering (`crates/oraclemcp/src/dispatch/tests.rs:6020`, `crates/oraclemcp/src/dispatch/tests.rs:6247`), and a stale grant is refused even when the live level would otherwise allow the SQL (`crates/oraclemcp/src/dispatch/tests.rs:6312`). Passive TTL expiry is explicitly handled by live re-classify/re-gate rather than grant invalidation (`crates/oraclemcp/src/dispatch/tests.rs:6375`). Dashboard Change Proposal apply re-classifies the current templates and ignores stored verdicts (`crates/oraclemcp-core/src/http/tests.rs:2309`, `crates/oraclemcp-core/src/http/tests.rs:2369`). The previously discovered unwired helper risk is closed by bead `oraclemcp-release-073-iec3.2.34`. |
| SEC-2 raw SQL cannot bypass the fail-closed guard | Pass | The threat model anchors the fail-closed classifier and operating ladder (`docs/threat-model.md:9`, `docs/threat-model.md:55`). Raw caller SQL for `oracle_query` and the inner SQL of `oracle_explain_plan` is always classified by `ensure_read_only` before Oracle I/O (`crates/oraclemcp/src/dispatch/mod.rs:1353`). `oracle_query` parses once, computes the classifier gate before execution, and reuses that verdict on the read path (`crates/oraclemcp/src/dispatch/mod.rs:5656`, `crates/oraclemcp/src/dispatch/mod.rs:6460`). |
| SEC-3 operating levels, profile ceilings, protected profiles, and OAuth scopes are monotone-down | Pass | OAuth read scope blocks write tools even when the session is elevated (`crates/oraclemcp/src/dispatch/tests.rs:3516`), scoped previews do not persistently lower or mutate the underlying session (`crates/oraclemcp/src/dispatch/tests.rs:3550`), admin scope cannot exceed the profile max level (`crates/oraclemcp/src/dispatch/tests.rs:3581`), and protected profiles remain read-only even with admin scope (`crates/oraclemcp/src/dispatch/tests.rs:3604`). |
| SEC-4 privileged execution is audit-first and tamper-evident | Pass | Current schema-v6 audit records store SQL hashes plus a fixed redaction marker, never SQL text, bind values, or secrets, with server-derived subjects and DB evidence fields (`crates/oraclemcp-audit/src/record.rs`). Historical v1-v5 records remain byte-for-byte verifiable and are handled as restricted legacy evidence. The head anchor detects tail truncation with a domain-separated keyed MAC and never writes anchor-ahead of durable records (`crates/oraclemcp-audit/src/anchor.rs:1`, `crates/oraclemcp-audit/src/anchor.rs:113`). Privileged dispatch tests show caller-supplied identity cannot spoof audit subject/evidence (`crates/oraclemcp/src/dispatch/tests.rs:5041`), escalation and compile/patch actions are signed/audited (`crates/oraclemcp/src/dispatch/tests.rs:5110`, `crates/oraclemcp/src/dispatch/tests.rs:5144`, `crates/oraclemcp/src/dispatch/tests.rs:5191`), and audit write failure refuses DB execution (`crates/oraclemcp/src/dispatch/tests.rs:5238`). |
| SEC-5 HTTP/operator/dashboard boundaries are explicit and no-leak | Pass | `allow_remote` defaults false and env config cannot silently enable it during config load (`crates/oraclemcp-config/src/lib.rs:43`, `crates/oraclemcp-config/src/lib.rs:277`). Serve-time startup still requires OAuth, mTLS, client credentials, or explicit local no-auth, and non-loopback binding requires a second opt-in (`crates/oraclemcp/src/main.rs:2685`, `crates/oraclemcp/src/main.rs:3017`). The surface inventory asserts authn/gating for MCP, operator, dashboard, config apply, readiness, and metrics, and checks unauthenticated observability for DB/secret leaks (`crates/oraclemcp-core/src/http/tests.rs:3862`, `crates/oraclemcp-core/src/http/tests.rs:4017`). Browser dashboard pairing and POSTs require one-time pairing, strict cookie/session view, same-origin/CSRF/action-ticket gates, and DDL apply is release-gated before MCP dispatch (`crates/oraclemcp-core/src/http/tests.rs:2237`, `crates/oraclemcp-core/src/http/tests.rs:2724`, `crates/oraclemcp-core/src/http/tests.rs:2938`). |
| SEC-6 secrets, wallet paths, IAM tokens, and cassettes do not leak | Pass | IAM token source selection is mutually exclusive and fail-closed (`crates/oraclemcp-core/src/iam_token.rs:160`); `token_exec` is spawned as argv with no shell, closed stdin, drained/capped pipes, timeout, no stdout trust on non-zero exit, and no output-byte logging (`crates/oraclemcp-core/src/iam_token.rs:299`, `crates/oraclemcp-core/src/iam_token.rs:391`). TCPS is checked before resolving/spawning any token source (`crates/oraclemcp-core/src/iam_token.rs:473`). Doctor tests prove wallet paths, passwords, connect strings, usernames, and IAM tokens are redacted while preserving actionable failure classes (`crates/oraclemcp-core/src/doctor.rs:3004`, `crates/oraclemcp-core/src/doctor.rs:3017`, `crates/oraclemcp-core/src/doctor.rs:3085`, `crates/oraclemcp-core/src/doctor.rs:3102`, `crates/oraclemcp-core/src/doctor.rs:3302`). K6 cassette support-capture did not ship in this repository; the bead is repo-oracledb/in-progress and this checkout records no committed HTTP/DB cassettes (`tests/conformance/PROVENANCE.md:31`). |
| SEC-7 observational and diagnostic features do not widen authority | Pass | K8 `StructuredReason` is built after the guard decision and only adds explanation/rewrite guidance (`crates/oraclemcp/src/dispatch/mod.rs:1386`). K9 `as_of` is structured outside SQL, validates one-of before classification/I/O, runs the base SQL unchanged through the guard, binds SCN/timestamp into fixed `DBMS_FLASHBACK` calls, and tears the flashback window down even on read failure (`crates/oraclemcp/src/dispatch/mod.rs:5656`, `crates/oraclemcp-db/src/query.rs:125`, `crates/oraclemcp-db/src/query.rs:184`, `crates/oraclemcp-db/src/query.rs:619`, `crates/oraclemcp-db/src/query.rs:849`). K10 streaming runs only after the same read-only gate, is delivery-only, and is mutually exclusive with `export` and `as_of` (`crates/oraclemcp/src/dispatch/mod.rs:6474`, `crates/oraclemcp/src/dispatch/tests.rs:5877`, `crates/oraclemcp/src/dispatch/tests.rs:5978`, `crates/oraclemcp/src/dispatch/tests.rs:5997`). `oracle_explain_plan` gates the inner SQL as read-only, then separately requires explicit PLAN_TABLE write opt-in, READ_WRITE level, and non-standby (`crates/oraclemcp/src/dispatch/mod.rs:1471`, `crates/oraclemcp/src/dispatch/mod.rs:6376`, `crates/oraclemcp-db/src/intelligence.rs:1196`, `crates/oraclemcp/src/dispatch/tests.rs:4653`). |

## Audited Surfaces

| Surface | Verdict | Evidence |
| --- | --- | --- |
| IAM `token_exec` | Pass | Mutually exclusive source selection, no-shell argv execution, capped/drained pipes, timeout, strict stdout validation, TCPS-before-spawn, and token-free debug/error behavior are covered by implementation and tests (`crates/oraclemcp-core/src/iam_token.rs:160`, `crates/oraclemcp-core/src/iam_token.rs:299`, `crates/oraclemcp-core/src/iam_token.rs:473`, `crates/oraclemcp-core/src/iam_token.rs:1016`, `crates/oraclemcp-core/src/iam_token.rs:1050`). |
| Wallet/TCPS/doctor | Pass | The local TCPS e2e harness proves profile wallet plus IAM token reaches a synthetic TCPS terminator without leaking token or wallet path in connect errors (`crates/oraclemcp-core/tests/oci_tcps_e2e.rs:227`). Doctor reports supported wallet modes truthfully and redacts wallet paths/passwords/tokens in structured diagnostics (`crates/oraclemcp-core/src/doctor.rs:3004`, `crates/oraclemcp-core/src/doctor.rs:3302`, `crates/oraclemcp-core/src/doctor.rs:4113`). |
| HTTP `allow_remote` | Pass | Default false, config env ignored, serve-time auth guard still mandatory, and non-loopback bind needs explicit opt-in (`crates/oraclemcp-config/src/lib.rs:43`, `crates/oraclemcp-config/src/lib.rs:277`, `crates/oraclemcp/src/main.rs:2685`, `crates/oraclemcp/src/main.rs:3017`). |
| Dashboard guarded operator routes | Pass | Pairing/session/cookie/action-ticket/CSRF controls and route-level release gates keep the browser surface on the same guarded MCP path (`crates/oraclemcp-core/src/http/tests.rs:2237`, `crates/oraclemcp-core/src/http/tests.rs:2309`, `crates/oraclemcp-core/src/http/tests.rs:2724`, `crates/oraclemcp-core/src/http/tests.rs:2938`). |
| Guard/classifier and generated reads | Pass | `oracle_query` and `oracle_explain_plan` route caller SQL through `ensure_read_only`; generated dictionary reads/custom tools are still classified/backstopped per the threat model (`crates/oraclemcp/src/dispatch/mod.rs:1353`, `docs/threat-model.md:105`, `crates/oraclemcp/src/dispatch/tests.rs:5589`). |
| Audit chain | Pass | Privileged action audit is signed, hash-chained, anchor-backed, and fail-closed before DB execution on write failure (`crates/oraclemcp-audit/src/record.rs:1`, `crates/oraclemcp-audit/src/anchor.rs:1`, `crates/oraclemcp/src/dispatch/tests.rs:5238`). |
| K6 cassette support-capture | Out-of-surface | The D6.8-required K6 audit item did not ship in this repository. The local bead is still `in_progress` and marked `repo-oracledb`; this checkout records no HTTP/DB cassettes and requires provenance if one is ever committed (`tests/conformance/PROVENANCE.md:31`). |
| K8 StructuredReason coach | Pass | Additive error metadata only; no guard decision or execution path mutation (`crates/oraclemcp/src/dispatch/mod.rs:1386`, `crates/oraclemcp-error/src/lib.rs:106`, `crates/oraclemcp-error/src/lib.rs:228`, `crates/oraclemcp/src/dispatch/tests.rs:4862`). |
| K9 structured `as_of` flashback read | Pass | Structured argument, unchanged base SQL classification, bound flashback target, and guaranteed teardown (`crates/oraclemcp/src/dispatch/mod.rs:5656`, `crates/oraclemcp-db/src/query.rs:125`, `crates/oraclemcp-db/src/query.rs:184`, `crates/oraclemcp-db/src/query.rs:619`, `crates/oraclemcp-db/src/query.rs:848`). |
| K10 streaming query delivery | Pass | Same guard, same cursor contract, byte-identical chunks, and no combination with export/flashback (`crates/oraclemcp/src/dispatch/mod.rs:6474`, `crates/oraclemcp/src/dispatch/tests.rs:5877`, `crates/oraclemcp/src/dispatch/tests.rs:5943`, `crates/oraclemcp/src/dispatch/tests.rs:5997`). |
| `oracle_explain_plan` | Pass | Inner SQL is read-only-gated first; PLAN_TABLE diagnostic write requires explicit opt-in, READ_WRITE, and non-standby (`crates/oraclemcp/src/dispatch/mod.rs:1471`, `crates/oraclemcp/src/dispatch/mod.rs:6376`, `crates/oraclemcp-db/src/intelligence.rs:1196`, `crates/oraclemcp/src/dispatch/tests.rs:4653`). |

## Residual Notes

- Raw Oracle flashback SQL remains handled by the classifier's existing
  fail-closed behavior; K9 does not teach the prover to accept handwritten
  `AS OF` SQL.
- `oracle_explain_plan` is intentionally not represented as read-only-only:
  it is a diagnostic write and reports that fact in its structured response.
- Dependency, provenance, and secret gates remain part of release preflight; this
  report is the code-level D6.8 security-domain audit.
