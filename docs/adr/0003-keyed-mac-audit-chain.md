# ADR 0003 — Keyed-MAC (HMAC-SHA256) signed audit chain wired into served dispatch

## Status

Accepted (0.4.0; bead A8). A8 audit-wiring was a **blocking release gate** for
0.4.0.

## Context

Earlier releases recorded privileged actions in a hash-chained log. A bare hash
chain is *tamper-evident only against accidental corruption*: anyone who can
rewrite the file can also recompute the chain, so it does not detect a
deliberate, knowledgeable forgery. For a server that can escalate up to `ADMIN`,
the audit trail needs to resist a writer who controls the file but not the key.

## Decision

Sign the audit chain with a **keyed MAC (HMAC-SHA256)** and wire the auditor
into the **served dispatch path** so every privileged action is recorded as it
happens, out-of-band of the Oracle session, fsync-before-execute. The signing
key comes from config/env (`[audit].key_ref` secret-ref) and carries a rotatable
`key_id`. The `oraclemcp audit verify <file>` CLI re-walks the file, recomputes
every hash link, and re-checks the keyed MAC, exiting non-zero on a broken link
or a recompute-without-key forgery. Treating A8 as a blocking release gate
ensures dispatch cannot ship un-audited.

## Consequences

- The audit trail is now genuinely **tamper-evident**: an attacker who rewrites
  the log but lacks the key cannot produce a chain that `audit verify` accepts.
- "Audited / tamper-evident" became an honest, defensible claim for 0.4.0
  (before A8 it was not, and the honesty gate rejected any such over-claim).
- Operators must manage an audit signing key: protect it, rotate it via
  `key_id`, and keep prior `key_id`s available so historical records still
  verify.
- fsync-before-execute adds latency to privileged actions, accepted as the cost
  of durability before the side effect.

## Review trigger

Revisit if **HMAC-SHA256 is deprecated** for integrity use in the project's
threat model, if a regulatory requirement demands asymmetric signatures
(non-repudiation across trust domains, where a shared MAC key is insufficient),
or if dispatch grows a privileged path that bypasses the auditor — the last of
which must fail the release gate, not pass review.
