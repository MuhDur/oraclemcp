# Round 1 Review Summary

Source files read:

- `docs/review/round1-p2.md`
- `docs/review/round1-p3.md`
- `docs/review/round1-p5.md`
- `docs/review/round1-p9.md` (present but untracked when summarized)

## Counts

Counts are per review block, not per unique underlying defect. The stale
lease/session plan-doc finding appears in both p2 and p5 and is counted twice
here because it was recorded twice.

| Total | CLEAN | CONFIRMED DEFECT | UNPROVEN |
| ---: | ---: | ---: | ---: |
| 69 | 48 | 17 | 4 |

Breakdown:

| File | Total | CLEAN | CONFIRMED DEFECT | UNPROVEN |
| --- | ---: | ---: | ---: | ---: |
| `round1-p2.md` | 20 | 16 | 3 | 1 |
| `round1-p3.md` | 16 | 13 | 2 | 1 |
| `round1-p5.md` | 31 | 19 | 10 | 2 |
| `round1-p9.md` | 2 | 0 | 2 | 0 |

`round1-p9.md` did not use the exact `CONFIRMED DEFECT` phrase in the
`Verdict` line, but both blocks identify proven defect states: one custom-tool
contract gap and one set of active stale A1a test witnesses.

## Confirmed Defects

### HIGH

- **Write-capable custom tools load and advertise on writable profiles, then
  fail closed at invocation.**
  - Source: `round1-p9.md`, `HEAD 0a51dcb9`,
    `crates/oraclemcp-core/src/custom_tools.rs:413`.
  - State: **open**. Tracker has
    `oraclemcp-custom-tool-write-loader-contract-vq69v` open, unassigned, P0;
    the bead description labels it critical. The review did not find a direct
    unguarded Oracle write: invocation refuses before `execute`, `commit`, or
    `rollback`. The defect is the loader/advertised contract, not a write
    bypass.

- **A1a semantic-read tightening invalidated active stdio/golden witnesses.**
  - Source: `round1-p9.md`; A1a implementation `fa93e169`; current inspected
    witnesses remain in `crates/oraclemcp/tests/golden_behavior.rs` and
    `crates/oraclemcp/tests/e2e_stdio.rs`.
  - State: **partly fixed, partly open**. Dispatch and preview-DML witness
    repairs landed in `cd90a3e3` and `4cf4e200`; `oraclemcp-8ul1t` is closed.
    Four active golden/e2e witnesses remain listed in p9: main tool transcript,
    opaque cursor pagination, export/resource-link, and advertised
    `oracle_query` output schema. No specific open tracker owner was found.

- **Preview-DML sandbox proof was stale under the fail-closed catalog gate.**
  - Source: `round1-p3.md`,
    `crates/oraclemcp/src/dispatch/tests.rs:14715`.
  - State: **fixed** by `cd90a3e3` and folded into the A1a witness-repair
    theme; p9 records the focused preview-DML filter passing at clean HEAD.

- **Non-cursor implicit result values serialize as ordinary placeholder
  strings.**
  - Source: `round1-p3.md`,
    `crates/oraclemcp-db/src/connection.rs:4183`.
  - State: **open**. Current source still contains the
    `<unsupported implicit resultset value ...>` `VARCHAR2` placeholder. No
    specific open tracker owner was found.

- **SEC-6 close evidence binds the wrong source commit.**
  - Source: `round1-p5.md`,
    `tests/artifacts/evidence/closes/oraclemcp-yxg1u.json:21`.
  - State: **open**. Current evidence still records source `3719ed8d` while the
    OAuth implementation commit named by the review is `dc092cdc`. No specific
    open tracker owner was found.

- **Doctor RLS/VPD check renders the session user.**
  - Source: `round1-p5.md`,
    `crates/oraclemcp-core/src/doctor.rs:2356`.
  - State: **open**. Current source still has a test asserting
    `session_user=ORACLEMCP_D3_SIGHTED` appears in doctor detail. No specific
    open tracker owner was found.

### MEDIUM

- **PowerShell installer auto-consented to discovery under `-Yes`.**
  - Source: `round1-p2.md`, `install.ps1:727`.
  - State: **fixed** in `0a51dcb9` by requiring interactive install before the
    PowerShell installer offers discovery.

- **C6 classifier close evidence bound a later metadata commit.**
  - Source: `round1-p5.md`,
    `tests/artifacts/evidence/closes/oraclemcp-eng-program-bp8ia.4.6.4.json:21`.
  - State: **fixed** in `1fed082f`; follow-up evidence `50a8f72d` closed
    `oraclemcp-ug2e1`. Current evidence source is the real split commit
    `b233fff0`.

- **Multiple closes used tracker/evidence SHAs as source commits.**
  - Source: `round1-p5.md`; sampled commits `b514ee3c`, `56994f4a`,
    `a6e5cea5`, `332c2c65`.
  - State: **mixed / aggregate open**. The classifier case above was repaired,
    but p5 separately records B12c/jjtrc, B14b, P2-8/20cw3, and D10 evidence
    source-binding debt. No single open owner was found.

- **Semantic-search `RuntimeStateRequired` proof was masked by an earlier guard
  refusal.**
  - Source: `round1-p5.md`,
    `crates/oraclemcp/src/dispatch/tests.rs:374`.
  - State: **fixed** by the dispatch semantic fixture repair; p9 records the
    focused filter passing at clean HEAD after `4cf4e200` / `40ff4354`.

- **Broad offline registry route proof was broken by an unproven helper query.**
  - Source: `round1-p5.md`,
    `crates/oraclemcp/src/dispatch/tests.rs:2107`.
  - State: **fixed** by `4cf4e200`; p9 records the registry and alias filters
    passing at clean HEAD.

- **Agent-facing capabilities text still says pre-0.9.1.**
  - Source: `round1-p5.md`,
    `crates/oraclemcp-core/src/server.rs:2646` plus generated goldens.
  - State: **open**. Current source and goldens still contain
    `pre-0.9.1 descriptor report`; release-surface checks did not catch it.

- **Engineering-program release target still points at 0.9.1.**
  - Source: `round1-p5.md`, `scripts/eng_program_manifest_build.py:88`,
    `engineering-program-manifest.json:9`,
    `scripts/plan_bead_graph_lint.py:17`.
  - State: **open**. Current generator, manifest, and lint defaults still
    mention `0.9.1`. The broad train bead
    `oraclemcp-091-train-root-jp5k9` is open and unassigned, but no specific
    defect bead was found for this residue.

### LOW

- **Discovery writer anti-rot contract was stale after session-teardown
  fields.**
  - Source: `round1-p2.md`,
    `crates/oraclemcp-config/src/discovery/contract.rs:403`.
  - State: **fixed** in `0a51dcb9`; p2 records `cargo test -p
    oraclemcp-config discovery` passing with 39 tests.

- **Historical plan docs retain stale lease/session file references.**
  - Source: `round1-p2.md` and `round1-p5.md`; `docs/plan/*`.
  - State: **open in committed history / corrected only in dirty working tree**.
    Runtime reachability is clean, but current uncommitted `docs/plan` edits mark
    these references as former/deleted-by-B14b. The same plan paths already carry
    unrelated staged doc moves and normalization hunks, so this summary does not
    claim a landed fix.

- **Core test helpers triggered clippy type-complexity warnings.**
  - Source: `round1-p5.md`, commit `3934cde6`.
  - State: **fixed** in `3934cde6` with local test-helper type aliases; p5
    records the rerun of `cargo clippy -p oraclemcp-core --all-targets -- -D
    warnings` passing.

## Clean Coverage

### C6 Splits And Routing

- Dispatch alias routing still reaches the same fail-closed semantic-read
  refusal; no routing drift was proven.
- The classifier grammar split preserved checked fail-closed classifier behavior.
- Dispatch terminal-effect helper extraction preserved checkpoint, undo, and
  cancellability behavior.
- Doctor redaction tests survived the doctor split.
- The deleted lease/session subsystem is not reachable from the served runtime
  resource surface.

### Installer And Onboarding

- Unix installer syntax/offline smoke held: SHA-256 required, no surprise
  prompts/scans/service start in the scoped smoke, and service mutation remains
  explicit.
- `oraclemcp setup --discover` consent, no-secret disk writes, READ_ONLY caps,
  and idempotent merge behavior held under targeted tests.

### HTTP, Auth, Dashboard, And Transport

- `--listen` refuses to start without client credentials, OAuth, mTLS, or
  explicit `--allow-no-auth`.
- Non-loopback binds require explicit remote opt-in.
- CA-verified mTLS client certificates are not application identities until the
  leaf fingerprint is registered.
- Registered mTLS leaf fingerprints become the principal key.
- Rejected OAuth bearers return a generic `invalid_token` challenge with no
  `error_description`.
- Remote plaintext does not receive privileged browser cookies.
- Auth and dashboard error envelopes avoid credential-oracle detail in sampled
  paths.

### Config And Profile Layering

- `base` inherits unset fields only; it is reuse, not a safety ceiling.
- `mcp_exposed = false` behaves as a visibility opt-out for list, switch, and
  fleet search, while operator CLI profile JSON still sees metadata.
- Protected profiles reject literal credential references.

### Resources And Prompts

- `resources/list`, `resources/templates/list`, and `prompts/list` expose only
  the intended browsable resource/template/playbook surface.
- Resource template reads route through guarded dispatch with transport
  authorization context; `8d8c8228` added a regression test for this.

### Write Path, Grants, And Lifecycle

- Write path requires preview grant before commit or non-transactional effect.
- DML rolls back unless `commit=true`.
- Query-shaped `NEXTVAL` is refused instead of executed without fetch proof.
- DDL requires `commit=true` plus confirmation.
- Failed commit remains `commit_in_doubt` and is not repaired by rollback.
- Unresolved durable write intent fails writable startup closed.
- Grants are process-local and single-use.
- Failed or cancelled pooled calls are dirty-discarded.
- Commit-in-doubt stays primary and quarantines.

### Serialization And Value Fidelity

- Oracle `NUMBER` stays a string by default and floats only by explicit opt-in.
- Structured ARRAY/JSON/VECTOR decode remains capped; `deep_decode` only widens
  to capped limits.
- Nested REF CURSOR materialization uses separate row, cell, byte, and depth
  caps.
- Structured unsupported markers carry typed provenance on normal value paths.

### Audit, Errors, And Redaction

- E3 close evidence binds to the implementation test commit.
- Audit chain verification detects record tampering and HMAC recompute forgery.
- Audit verify fails on a truncated tail when the anchor survives.
- SEC-3 audit-write failure is fail-closed.
- Unsigned refusal trail does not masquerade as signed audit.
- Doctor connectivity/auth secret redaction held in sampled paths.
- `oracle_connection_info` redacts identity/topology by default and degrades in
  band with structured recovery.
- `oracle_list_profiles` omits profile secrets and topology.
- MCP tool errors remain structured `ErrorEnvelope`s.
- Guard refusals stop before Oracle with typed classes and next steps.
- Error-adjacent sampled paths preserved redaction.

### Release And Publishing

- The release surface has one normal tag-driven publishing pipeline.
- The m4kua guard covers both manual auxiliary workflows, `docker.yml` and
  `publish-mcp.yml`.
- Release metadata mismatch fails closed in the direct surface check and
  preflight wrapper.

### Custom Tools

- Malformed/config-quality custom tools skip and warn, while over-ceiling,
  forbidden, and tampered-signature custom tools refuse startup.

## Unproven Items

- **Profile completion hidden-profile behavior lacks a direct regression**
  (`round1-p2.md`). Code inspection shows completion routes through filtered
  `oracle_list_profiles`, but no executable test was found that drives
  `completion/complete` for a hidden profile.

- **Preview-DML late cancellation after DML is not pinned by a passing focused
  test** (`round1-p3.md`). Adjacent rollback-preview cancellation proof passed
  and the source appears to clean up through `ROLLBACK TO SAVEPOINT`, but no
  passing test injects cancellation after `oracle_preview_dml`'s DML execute.

- **Full workspace formatting was not proven** (`round1-p5.md`). The lane could
  not credit whole-workspace `cargo fmt --all -- --check` because unrelated
  dirty dispatch/orient work was present; scoped core formatting and clippy were
  clean.

- **Full `release_preflight.sh` clean run was not proven** (`round1-p5.md`). A
  bounded 120-second run progressed through early lints and then timed out; the
  reviewer did not wait again.

## Patterns

- **A1a did the right fail-closed thing, and exposed stale tests.** The VPD /
  virtual-column gate tightening did not appear as a guard weakness; it caused
  many offline witnesses to stop proving their intended downstream properties
  because their mock catalog could not prove reads safe. Several were repaired
  (`cd90a3e3`, `4cf4e200`, `40ff4354`), but p9 still lists four active golden /
  stdio witnesses. The fix pattern is to model positive catalog proof or choose
  modeled plain-table witnesses, not weaken A1a.

- **Evidence honesty is a recurring defect class.** Multiple closes bound
  `source.sha` to a later tracker/evidence/bookkeeping commit instead of the
  implementation/proof commit. The C6 classifier case was corrected, but SEC-6
  and several sampled evidence files remain suspect. This is not a runtime
  safety bypass, but it directly weakens close reproducibility.

- **Most runtime fail-closed auth and transport checks held.** HTTP startup
  auth, remote bind opt-in, mTLS identity registration, uniform OAuth bearer
  rejection, remote plaintext cookie suppression, and guarded resource-template
  reads all came back clean under scoped tests.

- **The 0.10.0 train rename is incomplete outside the obvious release surfaces.**
  `Cargo.toml` was intentionally untouched, and the primary release-surface
  checks pass, but agent-facing capability text, generated goldens, and
  engineering-program manifest defaults still contain `0.9.1`.

- **Doc rot is separate from runtime reachability.** The deleted lease/session
  subsystem is not reachable at runtime, but historical plan text still points
  at deleted files unless the current dirty `docs/plan` corrections are landed
  cleanly.
