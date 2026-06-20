# Severity policy and exact-SHA release qualification

This is the **certifying gate** for an `oraclemcp` release (bead
`oraclemcp-040-epic-wp-d-1il.12` / D9; plan §8 items 8 and 11). It defines the
severity classes for findings against this project, the **release qualification
rule** built on them, and the **exact-SHA qualification** that binds the whole
§8 Definition of Done to one frozen commit.

It is the gate that signs off the entire release: the standard CI gates in
[`release-checklist.md`](release-checklist.md) prove the build is *green*; this
policy decides whether the body of findings (security audit D5, the multi-pass
bug-hunt, conformance, live-XE) is *acceptable to ship*, and records the
certification against an exact, immutable SHA.

`oraclemcp` is **governed and least-privilege**: a fail-closed SQL classifier in
front of an explicit operating-level ladder `READ_ONLY < READ_WRITE < DDL <
ADMIN`, read-only by default and escalation-capable only through a
TTL-bounded, per-profile-capped confirmation step-up, with privileged actions
written to a hash-chained, HMAC-signed audit log. The severity lens below is
framed around *that* model: what would break the classifier's promise, forge or
lose the audit evidence, escalate privilege, or take the server down.

---

## 1. Severity classes

Severity is assigned through a **security / data-integrity / availability**
lens, not by component. A finding takes the **highest** class any of its
realistic consequences reaches. When two reviewers disagree, the finding takes
the higher class until argued down with evidence (fail-closed triage — the
mirror of the classifier's own "cannot prove safe ⇒ dangerous" rule).

### P0 — Critical (the core guarantees are broken)

A defect that voids one of the load-bearing invariants this project exists to
hold. P0 examples:

- **Classifier bypass:** a statement the current operating level forbids reaches
  Oracle (e.g. a write/DDL/admin statement executes at `READ_ONLY`, or a
  protected/standby profile is mutated). This is the headline guarantee.
- **Operating-ceiling escape:** any path that elevates a session above the
  profile's `max_level`, or makes an OAuth scope *raise* (rather than only
  lower) the effective ceiling.
- **Audit forgery / silent loss:** a privileged action that produces no audit
  record, or a tampered/forged record that `oraclemcp audit verify` accepts
  (broken hash chain or MAC that still verifies).
- **Data loss / corruption:** the server causes unintended writes, deletes, or
  schema changes, or returns wrong data as if correct (e.g. NUMBER fidelity
  silently lost, a transaction committed that should have rolled back).
- **Authentication bypass on the HTTP transport:** the listener serves `/mcp`
  without the required OAuth bearer (outside an explicit `--allow-no-auth` dev
  opt-in), or binds non-loopback without the remote opt-in.
- **Credential / secret disclosure:** connect strings, passwords, wallet paths,
  tokens, or audit keys leak into logs, tool output, or error envelopes.

### P1 — High (a real defect, but not a direct invariant break)

- **Privilege-escalation defect** that is gated by a non-default misconfiguration
  or a narrow precondition (would be P0 if reachable by default).
- **Crash / panic / hang** reachable from a tool call or connection path
  (denial of service of the server), including a deadlock or unbounded resource
  growth under normal load.
- **Session/lease or connection leak**, savepoint/rollback defect, or pool
  exhaustion that degrades the server over time.
- **Redaction gap** in a surface that is *documented as* redaction-safe (e.g.
  `doctor`, audit-verify output) that exposes non-secret-but-sensitive
  topology, short of a full secret disclosure (which is P0).
- **Drain/shutdown defect:** `SIGTERM` does not roll back in-flight work, revoke
  leases, or flush the audit/telemetry exporters cleanly.

### P2 — Medium (correctness or usability, no safety/availability breach)

- A classifier **false positive** (refuses a statement that is in fact permitted
  at the current level) — annoying, but fail-*closed*, so not P1.
- Wrong-but-not-dangerous output: a mis-shaped tool result, an off-by-one in
  pagination, a non-load-bearing serialization quirk.
- Confusing or missing error envelope, doc/runbook inaccuracy that could
  mislead an operator, or a metadata/version-alignment slip.
- Missing or weak test coverage on a non-invariant path.

### P3 — Low (cosmetic / polish)

- Wording, formatting, log-message phrasing, or a purely cosmetic CLI/JSON
  nit with no behavioral consequence.

> **Honesty note.** Severity is about *consequence*, not blame or effort. A
> one-line fix can be P0; a large refactor can be P3. Do not down-rank a finding
> because it is inconvenient to fix before the tag — that is what the P2
> signed-exception path (below) is for, and P0/P1 have no exception path.

---

## 2. Release qualification rule

A release qualifies only when **all** of the following hold on the frozen RC
(see §3 for "frozen RC"):

1. **No open P0.** Zero, no exceptions, no sign-off path. A single open P0 voids
   the release.
2. **No open P1.** Same: every P1 is fixed before the tag. There is no
   "ship-with-known-P1" path.
3. **Every P2 is fixed _or_ explicitly signed off.** A P2 may ship *only* with a
   recorded, named exception (see §2.1). An *untriaged* finding is not a P2 —
   it blocks the tag until it is triaged into a class.
4. **No untriaged findings.** Every finding from the D5 security audit, the
   multi-pass bug-hunt, conformance, and live-XE is assigned a class. "We
   haven't looked at that one yet" is a blocker.
5. **Two consecutive clean fresh-eyes bug-hunt passes** (see §2.2): the last two
   passes both found **zero new in-scope findings**.
6. **The standard CI gates are green on the RC SHA** — the full table in
   [`release-checklist.md`](release-checklist.md). This policy sits *on top of*
   that checklist; it does not replace it.

### 2.1 P2 signed-exception format

A P2 ships only with an exception recorded in the RC evidence bundle (§3.2):

```
P2 exception
Finding: <id / one-line summary>
Why deferred: <why it is acceptable to ship; blast radius; workaround>
Tracking: <bead id for the follow-up fix>
Signed-off-by: <release owner> on <RC SHA>
```

A P2 with no such block is treated as **open** and blocks the tag. P0 and P1
have **no** exception block — they are fixed or the release does not happen.

### 2.2 The fresh-eyes bug-hunt and the 2-consecutive-pass rule

The bug-hunt is an adversarial audit-fix-rescan loop over the in-scope surface
(classifier and operating-level ladder, audit chain, connect/exec path, HTTP
auth/network posture, redaction, drain/shutdown). A **pass** is one full sweep:

- **In-scope finding:** anything that lands at P0–P2 against the surface above.
  P3 cosmetics do not reset the counter.
- **"Fresh eyes":** the pass is performed against the current frozen artifact by
  a reviewer (or agent) **not anchored to the previous pass's conclusions** —
  re-derive findings from the code, do not re-confirm the last report.
- **Consecutive:** the two clean passes must be the **last two** passes with no
  in-scope finding in between. If pass *N* finds and fixes a P1, the counter
  resets: you need two *more* clean passes after the fix, because the fix is new
  code that has itself never been hunted clean.

Convergence is "two consecutive passes, zero new in-scope findings." One clean
pass is necessary but not sufficient — a single clean pass can be luck; two
consecutive clean passes after the last change is the evidence of convergence.

> Scheduled / CI bug-hunt runs on moving commits are **discovery**, not
> qualification (§3). They surface findings to triage; they never *count* toward
> the two consecutive passes, because they do not run on the frozen RC.

---

## 3. Exact-SHA qualification

The §8 DoD is certified **against one exact commit SHA** — the frozen
release-candidate. The certification is a **manual** qualification run on that
SHA, and it is **void the instant any byte changes**.

### 3.1 The rule

1. **Freeze the RC.** Choose the commit to tag. Record its **full 40-char SHA**.
   Do not amend, rebase, or push more commits to the release branch after this
   point.
2. **Qualify on that SHA.** Run the qualification (the §2 rule: severity policy
   met, two consecutive clean fresh-eyes passes, CI green on *this* SHA, audit
   verify on the produced ledger, conformance/live-XE evidence). This is a
   deliberate, manual run by the release owner — not "whatever CI happened to be
   green last."
3. **Any change ⇒ new RC.** If a single byte changes after the qualifying run —
   a fix, a doc tweak, a rebase, a re-tag onto a different commit — the
   qualification is **void**. You start a fresh RC at the new SHA and re-run the
   two-consecutive-pass rule from scratch (the new code has never been hunted
   clean on that SHA).
4. **The tag points at the qualified SHA.** The pushed `vX.Y.Z` tag must resolve
   to the exact frozen SHA the qualification certified. `release_preflight.sh`
   and the `release-metadata` gate confirm the tag/version alignment; this
   policy adds that the tag's *commit* is the certified one.

Why exact-SHA: scheduled and CI runs slide across many commits and are
**discovery** (find things to triage). The release claim is about *one*
artifact. Binding the certification to a single immutable SHA is what makes the
"§8 DoD is met" statement falsifiable — anyone can check out that SHA and re-run
the gates.

### 3.2 RC qualification sign-off block (commit into the release evidence)

Record this against the frozen RC (in `CHANGELOG.md` / the release notes /
`docs/`), alongside the standard-gate sign-off block in
[`release-checklist.md`](release-checklist.md):

```
Release: vX.Y.Z
Frozen RC commit (full SHA): <40-char SHA>          # qualification is void if this changes
Pinned toolchain: nightly-2026-05-11
CI run (standard gates, this SHA): <URL>

Severity policy (D9) — met on the frozen RC:
- [ ] No open P0
- [ ] No open P1
- [ ] Every P2 fixed OR signed-exception recorded (§2.1)
- [ ] No untriaged findings (D5 audit + bug-hunt + conformance + live-XE all classed)
- [ ] >=2 consecutive fresh-eyes bug-hunt passes, zero new in-scope findings
      Pass N-1: <ref>  (clean)
      Pass N:   <ref>  (clean)
- [ ] Audit verify passes on the produced ledger; tamper detected
- [ ] Supply-chain artifacts produced + verifiable (operations.md §6)

P2 exceptions (if any): <list, or "none">

Certified-by: <release owner> against SHA <40-char SHA>
```

The qualification certifies §8 items 1–12 **as a set, against this SHA**. It is
the last gate before the tag.

---

## 4. Scope of a finding ("in-scope")

The bug-hunt and audit are scoped to the surfaces where a defect breaks a stated
guarantee:

- the **SQL classifier** and the operating-level ladder (the central control);
- the **audit chain** (record production, hash-chaining, MAC, `audit verify`);
- the **connect / exec path** through the driver-adapter seam;
- the **HTTP transport** auth, host/origin allowlists, and remote-bind guard;
- **redaction** of secrets and topology in logs, tool output, and `doctor`;
- **drain / shutdown** correctness (rollback, lease revocation, exporter flush).

Out-of-scope findings (third-party upstream behavior, advisor features that are
deliberately OUT per [ADR-0005](adr/0005-awr-diagnostics-license-gating.md),
cosmetic-only items) are recorded but do not gate the tag and do not reset the
two-consecutive-pass counter.

---

See also:
[`release-checklist.md`](release-checklist.md) for the standard CI gates and the
release-day procedure (D4 / `release-gre.1`),
[`operations.md` §6](operations.md#6-verifying-release-artifacts-sbom-provenance-signatures)
for the supply-chain verification commands (D3),
[`hardening.md`](hardening.md) for the security-controls checklist, and the §8
Definition of Done in `PLAN_0_4_0_PRODUCTION_HARDENING.md` (items 8 and 11) that
this policy certifies.
