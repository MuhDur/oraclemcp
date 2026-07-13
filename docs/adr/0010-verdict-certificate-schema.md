# ADR 0010 — Verdict-certificate schema and classifier rule registry

## Status

Accepted for the Arc B1.0 design spike. B1.1 implements this contract inside
the classify-and-audit path; it is not an additional execution path.

## Context

The fail-closed classifier already decides a statement's danger tier and
required operating level, while the audit chain records the governed action.
Arc B needs a portable, redacted proof of that exact decision. A certificate
must be attributable to the bytes that were classified and to the exact,
MAC-authenticated audit record, without exposing SQL, bind values, or schema
identifiers.

The currently explicit R-numbered classifier rule is R15: a `SELECT` that
calls a user-defined routine can be `Safe` only when every such call is
`ProvenReadOnly`. `Unknown` is not evidence of purity.

## Decision

### Certificate grammar

The serialized form has exactly these fields:

```text
VerdictCertificate = {
  stmt_digest: "sha256:<lowercase-hex>",
  level: "READ_ONLY" | "READ_WRITE" | "DDL" | "ADMIN" | null,
  verdict: "SAFE" | "GUARDED" | "DESTRUCTIVE" | "FORBIDDEN",
  derivation: [DerivationStep, ...],
  classifier_version: "oraclemcp-guard@<semver>/rules-v1",
  observed_scn: null | "<unsigned decimal SCN>",
  bound_audit_hash: "sha256:<lowercase-hex>"
}

DerivationStep = {
  rule_id: "R<positive decimal>",
  construct: "<registered non-secret construct label>"
}
```

`stmt_digest` is the existing exact-byte `sql_digest` / audit `sql_sha256`:
SHA-256 over the precise UTF-8 bytes supplied to `Classifier::classify`, with
the `sha256:` prefix and lowercase hexadecimal encoding. It is never a
whitespace- or case-normalized fingerprint. A verifier supplies those bytes
out of band and compares their digest; the certificate never carries the SQL.

`level` is the classifier's required `OperatingLevel`, and is `null` exactly
when `verdict` is `FORBIDDEN`. `verdict` is the classifier's `DangerLevel`, not
the post-step-up execution outcome. `observed_scn` is the Oracle-observed SCN
when a query has one; it is an ASCII decimal string to avoid JSON number
precision loss and is `null` when no SCN was observed. `classifier_version`
names both the guard build and the immutable registry generation so a verifier
can select the ruleset it must replay.

`derivation` is ordered in classifier evaluation order. A producer must fail
closed rather than emit a certificate with a missing, invented, or unknown
rule id. This includes decisions currently implemented by a branch that has no
R-numbered entry: B1.1 must first add that entry to this registry and its
classifier test before it can certify that branch.

### Rule-id registry (generation 1)

Rule ids are immutable: an id is never repurposed, deleted, or given a broader
meaning. A future rule appends one row and the guard test must keep this table
equal to the explicit R-numbered labels in `classifier.rs`. The complete
registry at this spike is:

| Rule id | Classifier fact | Allowed `construct` labels |
| --- | --- | --- |
| `R15` | A query containing user-defined routine calls is `Safe` only when every consulted routine is `ProvenReadOnly`; `Unknown` and `ProvenSideEffecting` prevent that admission. | `routine_calls:absent`, `routine_purity:all_proven_read_only`, `routine_purity:unproven_present` |
| `R16` | The certificate is constructed from the final `GuardDecision` returned by the exact public `Classifier::classify` call that gates the statement. It observes that decision and never admits or lowers a statement. | `final_verdict:SAFE`, `final_verdict:GUARDED`, `final_verdict:DESTRUCTIVE`, `final_verdict:FORBIDDEN` |

The labels are an allowlist, not free-form diagnostic text. In particular,
they must not contain a routine name, identifier, SQL fragment, literal, bind
value, connection value, or parser rendering. Repeated routine facts may be
collapsed into the aggregate labels above; a certificate does not need to
expose the number or identity of routines. Arc-M redaction remains mandatory
before a certificate crosses the host boundary.

### Exact audit binding without a hash cycle

`bound_audit_hash` binds the final certificate to `AuditRecord::entry_hash`,
which is already covered by the audit chain and its HMAC signature. It is not
itself part of the hash-covered certificate payload; otherwise the certificate
hash and `entry_hash` would form an unsatisfiable cycle.

The binding protocol for B1.1 is:

1. The same `Classifier::classify` call that gates the statement creates the
   six-field certificate core (every field above except `bound_audit_hash`).
   It serializes that core with RFC 8785 JSON Canonicalization Scheme and
   computes `certificate_core_hash` as `sha256:` over the UTF-8 bytes of
   `"oraclemcp:verdict-certificate-core:v1\\n" || JCS(core)`.
2. The certificate-aware audit append API accepts
   `verdict_certificate_core_hash` alongside the generic `AuditEntryDraft` and
   persists it on `AuditRecord`; the audit canonical-entry function covers that
   field. Keeping the specialized proof input out of the generic draft prevents
   unrelated audit producers from inventing certificate evidence. The record is
   appended and fsynced before the proof-carrying result is released, producing
   its signed `entry_hash`.
3. Only after that succeeds does the response projection set
   `bound_audit_hash = entry_hash`. The response-only bound field is not stored
   inside the audit's hash-covered certificate core; the stored core hash is
   what binds every other certificate field to that record.
4. Audit append or fsync failure refuses the statement and produces no bound
   certificate. A certificate never authorizes execution; it witnesses the
   already-enforced classifier decision.

An external verifier receives the certificate, the matching audit record and
chain evidence, and the SQL bytes from an authorized source. It must: verify
the audit chain and record HMAC; require
`record.entry_hash == certificate.bound_audit_hash`; recompute
`stmt_digest` and compare it with both the certificate and
`record.sql_sha256`; recompute the domain-separated certificate-core hash and
match `record.verdict_certificate_core_hash`; validate every derivation step
against this versioned registry; and re-run the selected classifier ruleset on
the supplied SQL. Any absent record, unknown rule/version/construct, digest
mismatch, audit verification failure, or replay mismatch is a failed proof.

## Consequences

- B1.1 can make audit persistence a fail-closed prerequisite while avoiding a
  self-referential hash design.
- The certificate has no raw SQL or bind material. Its exact SQL digest is a
  correlation handle, so certificate distribution still follows the existing
  authorization and redaction boundary.
- The registry starts deliberately small and honest. Adding derivations for
  classifier branches without a registered rule is prohibited until their
  semantics and non-secret construct vocabulary are reviewed.

## Review trigger

Revisit this decision if the audit record gains a signed external identity in
place of its keyed MAC, if the certificate must support a non-JSON canonical
encoding, or if a new classifier rule needs a construct vocabulary that cannot
be safely redacted.
