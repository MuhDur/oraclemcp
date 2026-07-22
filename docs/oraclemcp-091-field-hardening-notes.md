# oraclemcp-091 Field-Hardening Release and Migration Notes

These notes cover the train currently tracked as
`oraclemcp-091-train-root-jp5k9`:
`0.9.1/0.9.0 field-hardening train (PLAN_0_9_1 v8)`.

Version label is not final. The tracker still names the server side `0.9.1`,
while the changelog already records a planned rename to `0.10.0` because of
breaking public API changes. Do not tag, publish, or announce these notes with a
version string until the operator resolves bead `788nn`.

## Operator Actions

Do these before rolling the train into an environment that already runs
`oraclemcp`.

1. Review catalog privileges for guarded read profiles.
   The catalog resolver now fails closed when it cannot prove VPD/RLS policy or
   virtual-column visibility. A database principal that cannot see the needed
   catalog rows may now receive an explicit refusal where older builds could
   silently treat an empty catalog result as absence. Grant the least catalog
   visibility needed for the protected schemas, or treat the refusal as the
   intended safe outcome.

2. Re-test profiles that depend on RLS/VPD-protected schemas.
   Query results and doctor output now surface RLS/VPD visibility observations,
   but those observations are not an absence proof. Update automation that
   previously interpreted hidden or empty policy catalog results as a normal
   no-policy state.

3. Preflight Flashback grants.
   Flashback read paths now probe `DBMS_FLASHBACK` capability before changing
   session state. If a profile uses `as_of` reads, verify that the database
   principal has the needed capability. A clean pre-change refusal does not
   quarantine the session; a failure while tearing down a changed flashback
   window still quarantines and must be investigated as session uncertainty.

4. Check dashboard reverse proxies and browser automation.
   Dashboard pairing and operator actions are fetch-first and strict-origin.
   Pairing codes are accepted only from the form POST body, never from query
   strings or fragments. `/dashboard/pair?ticket=...` is refused before ticket
   exchange and does not consume the ticket. Tickets are single-use and expire
   after 60 seconds. Keep same-origin `Host` and `Origin` behavior intact, and
   do not strip dashboard cookies, CSRF headers, or route-scoped action-ticket
   headers from `/operator/v1` browser POSTs.

5. Update dashboard clients that parse 403s.
   Dashboard-facing 403 responses are now structured `ErrorEnvelope` JSON.
   They remain deliberately uniform for authentication failures. Clients should
   handle the envelope class and generic next step, not infer or display a
   hidden refusal reason.

6. Update OAuth rejection monitoring.
   Rejected bearer responses stay public and uniform as `invalid_token` without
   an `error_description`. The detailed rejection category is for the operator
   audit trail, not for clients. Alerting that parsed public rejection text for
   reason-specific buckets should move to audit records.

7. Re-run privileged-action previews after policy or profile changes.
   Recovery and apply paths reclassify at apply time. Stored previews, grant records, and recovery state are evidence, not durable authorization. If a policy, profile, operating level, or SQL text changed after preview, run the preview and confirmation flow again.

8. Adjust first-call capability discovery if pinned to the old full shape.
   `oracle_capabilities` now defaults to a compact discovery response. Agents
   should use the compact result as the first call. Clients that intentionally
   require the pre-train full response must request the full detail level.

9. Plan for explicit session close on shutdown paths.
   The database connection trait now requires explicit logical close handling,
   and server shutdown, profile lifecycle, and pool lifecycle drive close
   rather than relying on drop. Operators with shutdown hooks or sidecar health
   checks should allow close to run before killing the process.

10. Review IAM token-source configuration.
    IAM token profiles now wire a refreshable driver `TokenSource` instead of
    embedding a one-shot token. `doctor` reports the configured source kind and
    whether source invocation was observed by the caller; it does not claim a
    live refresh unless that observation exists. Ensure `token_exec`,
    `token_env`, or `token_file` sources are configured as intended and that
    token commands do not log secrets.

11. Re-read wallet and TCPS assumptions.
    The wallet truth table now matches the default thin-driver support:
    password-protected `ewallet.pem`, standalone `ewallet.p12`, and auto-login
    `cwallet.sso` are supported modes. The train also follows the driver-side
    system-root plus wallet-CA trust behavior planned for this release line; do
    not assume a wallet-only trust store unless the final driver release notes
    state such a knob exists.

## Security and Correctness Changes

### Catalog gates fail closed

A1a closes the fail-open in VPD/RLS and virtual-column catalog gates. Empty
catalog probes no longer certify safety unless the resolver can prove the
catalog view was visible enough to answer the question. This is a security fix
with operator-visible blast radius: previously admitted reads may now refuse
when the server cannot prove the database metadata it depends on.

A1e builds on that by surfacing RLS/VPD visibility observations in doctor and
successful `oracle_query` results. It does not weaken the gate and does not
turn an empty `ALL_POLICIES` result into an absence proof.

### Flashback refusal and quarantine semantics

A3a adds a `DBMS_FLASHBACK` capability preflight before rollback, defensive
disable, enable, or caller reads can change session state. A3b preserves the
intended asymmetry: a clean pre-change refusal is safe and does not quarantine;
a teardown failure after session state may have changed remains uncertain and
does quarantine.

### Pool validation and session recycle

A4a validates idle pooled sessions before checkout and discards failed final
pooled calls instead of returning them to the idle pool. A4e adds an audited
session-recycle path for recoverable pinned-session uncertainty while keeping
nonrecoverable uncertainty fail-closed.

### Dashboard browser flow

C4 and A5 make the live browser lane prove both sides of the dashboard flow: a
browser pairs and then performs an authenticated dashboard action POST. A5 keeps
the pairing contract strict while changing browser actions to same-origin JSON
fetches. The A5 security review is recorded in
[`dashboard-origin-threat-model-addendum.md`](dashboard-origin-threat-model-addendum.md).

PU3 makes dashboard 403 responses structured without making them explanatory
about authentication refusal causes. This keeps the SEC-6 anti-oracle posture
for dashboard failures.

### Explicit session close

B7c makes logical close explicit in the database connection trait and routes
server shutdown, active profile lifecycle, and pool lifecycle through it. The
server no longer relies on Rust drop timing as the primary session teardown
mechanism.

### IAM token sources and doctor observation

B16a wires IAM token profiles to a refreshable driver token source. B16b makes
doctor report source kind and observation truthfully: configured token source
and observed invocation are separate facts.

### Uniform OAuth rejection

SEC-6 keeps public bearer rejection uniform. Public HTTP responses do not reveal
whether the token failed because of format, signature, audience, issuer,
expiration, or another verifier category. Operators get the typed category only
through audit.

### SEC-1 recovery reclassification

SEC-1 recovery coverage now proves persisted recovery and apply paths
reclassify before action. Stored authorization-shaped data is never trusted as
permission to execute at apply time.

### Bounded orientation responses

B11 caps the orientation trio and related metadata surfaces. `oracle_orient`,
`oracle_capabilities`, `get_schema`, compile errors, constraints, PL/Scope
arrays, and fixed DDL prefixes now use bounded projections, page caps,
continuation metadata, or explicit loss markers rather than assuming discovery
responses are naturally small.

### Wallet truth table

P-U5 corrects the documentation for wallet modes. `cwallet.sso` is first-class
auto-login support, not diagnostic-only.

## Release Evidence To Attach At RC

These notes are migration guidance, not release qualification evidence. At RC
time, attach the exact frozen-SHA CI run and the operator-run live gates named
in [`release-checklist.md`](release-checklist.md). If the version label remains
ambiguous, stop before tag creation and resolve `788nn` first.
