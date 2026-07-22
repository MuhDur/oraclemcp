## [HIGH] SEC-6 close evidence binds the wrong source commit
- Where: tests/artifacts/evidence/closes/oraclemcp-yxg1u.json:21
- Claim checked: SEC-6 close evidence for uniform OAuth rejection must bind to the commit containing the OAuth auth-oracle fix.
- Method: `git show --stat --name-status 3719ed8d dc092cdc` and `sed -n '1,120p' tests/artifacts/evidence/closes/oraclemcp-yxg1u.json`.
- Verdict: CONFIRMED DEFECT - evidence source `3719ed8d` is the synthetic TCPS lane; the OAuth implementation is `dc092cdc`.

## [MEDIUM] C6 classifier close evidence binds a later metadata commit
- Where: tests/artifacts/evidence/closes/oraclemcp-eng-program-bp8ia.4.6.4.json:21
- Claim checked: C6 classifier split evidence should bind to the classifier split that preserves fail-closed behavior.
- Method: `git show --stat --name-status 984de104 b233fff0` and `nl -ba tests/artifacts/evidence/closes/oraclemcp-eng-program-bp8ia.4.6.4.json | sed -n '1,140p'`.
- Verdict: CONFIRMED DEFECT - `source.sha` is `984de104`, while the classifier split is `b233fff0`; the evidence prose names the real implementation SHA, so the proof boundary is honest but the machine-readable source is wrong.

## [MEDIUM] Multiple closes use tracker/evidence SHAs as source commits
- Where: b514ee3c, 56994f4a, a6e5cea5, 332c2c65
- Claim checked: Close evidence should bind to a commit that contains the claimed implementation or proof.
- Method: `git show --stat --name-status b514ee3c 56994f4a a6e5cea5 332c2c65 5e1aca16 ae3aed82 b5736dce fb7c093e 4e6a95ea d6aafc64` and sampled JSON under `tests/artifacts/evidence/closes/`.
- Verdict: CONFIRMED DEFECT - B12c/jjtrc, B14b, P2-8/20cw3, and D10 evidence files use tracker/evidence/bookkeeping commits as `source.sha`; sampled live/proof claims were otherwise bounded honestly.

## [LOW] Historical plan docs retain stale lease/session references
- Where: docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md; docs/plan/PLAN_ASUPERSYNC_THIN_NATIVE.md
- Claim checked: B14b removed the dead lease subsystem and no reachable core resource surface remains.
- Method: `test ! -e crates/oraclemcp-db/src/lease.rs`, `test ! -e crates/oraclemcp-core/src/session_tool.rs`, exact-name `rg` for lease/session resource strings, `cargo test -p oraclemcp-core --lib resources -- --nocapture`, and `cargo test -p oraclemcp-core --test mcp_conformance resources -- --nocapture`.
- Verdict: CONFIRMED DEFECT - runtime reachability is clean, but historical planning text still mentions deleted lease/session files.

## [LOW] Core test helpers triggered clippy type-complexity warnings
- Where: 3934cde6
- Claim checked: The core lane should remain clippy-clean after the TCPS/IAM test helper work.
- Method: `cargo clippy -p oraclemcp-core --all-targets -- -D warnings`.
- Verdict: CONFIRMED DEFECT - fixed in `3934cde6` with local test-helper type aliases; rerun passed.

## [LOW] Full workspace formatting was blocked by unrelated dirty dispatch work
- Where: crates/oraclemcp/src/dispatch/mod.rs; crates/oraclemcp/src/dispatch/orient.rs
- Claim checked: Whole-workspace formatting status after the core review fix.
- Method: `cargo fmt --all -- --check` and `git status --short`.
- Verdict: UNPROVEN - full formatting could not be credited to this lane because unrelated live dispatch/orient work was dirty; core-scoped formatting and clippy checks passed.

## [CLEAN] Doctor redaction survived the doctor split
- Where: b0833a8c; ed55693e
- Claim checked: Doctor output must omit connect strings, usernames, credential_ref values, passwords, proxy identities, wallet passwords, IAM tokens, wallet paths, and server DNs.
- Method: `cargo test -p oraclemcp-core doctor::tests::auth_capability_matrix_is_thin_and_redaction_safe -- --exact`, `cargo test -p oraclemcp-core redacts`, and `cargo test -p oraclemcp-core --test doctor_secret_golden`.
- Verdict: CLEAN - targeted doctor redaction tests passed.

## [CLEAN] Custom-tool skip-and-warn does not silently admit security failures
- Where: 5e1aca16; ae3aed82
- Claim checked: Malformed/config-quality custom tools skip and warn, while over-ceiling, forbidden, and tampered-signature tools refuse startup.
- Method: `cargo test -p oraclemcp custom_tool_loader_ -- --nocapture`, `cargo test -p oraclemcp-core skipped_custom_tools -- --nocapture`, and `cargo test -p oraclemcp-core custom_tools -- --nocapture`.
- Verdict: CLEAN - scoped loader tests passed; security-critical custom-tool failures remain refusals.

## [CLEAN] Deleted lease subsystem is not reachable at runtime
- Where: b5736dce; fb7c093e
- Claim checked: B14b deletion removed the dead lease/session subsystem from the served core surface.
- Method: `test ! -e crates/oraclemcp-db/src/lease.rs`, `test ! -e crates/oraclemcp-core/src/session_tool.rs`, exact-name `rg` over runtime resource strings, `cargo test -p oraclemcp-core --lib resources -- --nocapture`, and `cargo test -p oraclemcp-core --test mcp_conformance resources -- --nocapture`.
- Verdict: CLEAN - no served core lease/session resource surface was found.

## [CLEAN] E3 evidence binds to the implementation test commit
- Where: tests/artifacts/evidence/closes/oraclemcp-091-e3-audit-chain-e2e-69bbf.json:17
- Claim checked: E3 close evidence should bind to the commit containing the adversarial audit-chain test suite.
- Method: `git show --stat --name-status e0f319d0 6f1da17c a3fbc7c1 d0263cb2 -- tests/artifacts/evidence/closes/oraclemcp-091-e3-audit-chain-e2e-69bbf.json crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs` and `br show oraclemcp-091-e3-audit-chain-e2e-69bbf --json`.
- Verdict: CLEAN - source `e0f319d0` actually modifies `crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs`; close/evidence commits only update evidence metadata.

## [CLEAN] Audit chain detects record tampering and HMAC recompute forgery
- Where: crates/oraclemcp-audit/src/verify.rs; crates/oraclemcp-audit/src/record.rs
- Claim checked: Hash-chained HMAC-SHA256 JSONL must detect in-place tamper and recompute-from-genesis forgery without the key.
- Method: `cargo test -p oraclemcp-audit recompute -- --nocapture`, `cargo test -p oraclemcp-audit hmac -- --nocapture`, and a generated temp-log probe where `oraclemcp audit verify` exited 2 after editing record 2.
- Verdict: CLEAN - recompute/HMAC tests passed and the binary verifier rejected the edited record with `entry_hash does not match the record content`.

## [CLEAN] Audit verify fails on a truncated tail when the anchor survives
- Where: crates/oraclemcp/src/main.rs:5672; crates/oraclemcp-audit/src/anchor.rs:373
- Claim checked: `oraclemcp audit verify` must fail closed on a truncated audit JSONL tail against its `.anchor` sidecar.
- Method: Generated a 3-record signed temp JSONL with `.anchor`, copied the original anchor beside a 2-line truncated JSONL, then ran `ORACLEMCP_AUDIT_KEY=0123456789abcdef0123456789abcdef cargo run -q -p oraclemcp -- --json audit verify <file>` for both files.
- Verdict: CLEAN - intact log exited 0 with `anchor.status=match`; truncated copy exited 2 with `truncated=true`.

## [CLEAN] SEC-3 audit-write failure is fail-closed
- Where: crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs; crates/oraclemcp-audit/src/sink.rs; crates/oraclemcp/src/dispatch/mod.rs:9067
- Claim checked: Audit write/open failure must stop execution or quarantine instead of allowing unaudited privileged work.
- Method: `cargo test -p oraclemcp-audit --test e3_audit_chain_e2e -- --nocapture`, `cargo test -p oraclemcp-audit anchor -- --nocapture`, `cargo test -p oraclemcp ddl_mutators_resolve_uncertain_evidence_as_aborted_before_execute -- --nocapture`, `cargo test -p oraclemcp cancelled_audit_evidence_preflight_quarantines_before_execute -- --nocapture`, and `cargo test -p oraclemcp commit_in_doubt_remains_primary_when_terminal_audit_also_fails -- --nocapture`.
- Verdict: CLEAN - tests passed; pending audit append is before execution, and terminal audit failure preserves uncertain DB outcome.

## [CLEAN] Unsigned refusal trail does not masquerade as signed audit
- Where: crates/oraclemcp/src/refusal_corpus.rs:50
- Claim checked: The unsigned refusal/security-event corpus must stay distinct from the signed HMAC audit tier.
- Method: `cargo test -p oraclemcp refusal_corpus -- --nocapture`, `cargo test -p oraclemcp signature_rejection -- --nocapture`, and `ORACLEMCP_AUDIT_KEY=0123456789abcdef0123456789abcdef cargo run -q -p oraclemcp -- --json audit verify tests/fixtures/rig/refusal_corpus_baseline.jsonl`.
- Verdict: CLEAN - refusal corpus tests passed; feeding the corpus to `audit verify` exited 2 as malformed audit JSONL rather than verifying as signed audit.
