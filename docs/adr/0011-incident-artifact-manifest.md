# ADR 0011 — Incident-artifact manifest and bundle layout

## Status

Accepted for the Arc E0 design spike. E1–E4 implement capture and replay against
this contract; they do not re-open it.

## Context

Arc E gives an operator a way to capture what happened around a refusal, a
failure, a panic, a quarantine or a capacity rejection, and to replay it
deterministically. That capture runs at exactly the moment the interesting bytes
in the process are the ones we must never persist: the customer's SQL, their bind
values, their connect string, their wallet path, their schema and table names.

An incident bundle is therefore a security surface first and a debugging aid
second. Two further constraints shape it. A verdict recorded in a bundle is an
artifact an operator can edit, so it can never be an input to an authorization
decision (SEC-1). And a bundle that is not reproducible cannot be compared,
deduplicated, or trusted to be the thing it claims to be.

## Decision

### Bundle layout

```text
<bundle>/
  manifest.json              — the manifest defined below
  cassettes/<lane-id>.jsonl  — the K6 recorded interactions, one file per lane
  config.redacted.toml       — the profile config, secrets left as references
  audit-tail.redacted.jsonl  — the redacted audit records around the incident
```

`manifest.json` is the root. It names the other three by bundle-relative path and
SHA-256 content hash, so the bundle is self-describing and tamper-evident without
the manifest having to parse them. `om incident replay <bundle>` runs the
cassettes under `LabRuntimeTarget` with the manifest's `seed`.

### Manifest grammar

```text
IncidentManifest = {
  schema_version: 1,
  id: "sha256:<lowercase-hex>",          // content hash over every other field
  trigger: "REFUSAL" | "FAILURE" | "PANIC" | "QUARANTINE" | "CAPACITY_REJECTION",
  seed: <u64>,                           // the seed the recorded run used
  statement_redacted: null | "<redacted skeleton>",
  captured_verdict: null | CapturedVerdict,
  why: "<safe prose, ≤200 chars>",
  lanes: [CapturedLane, ...],            // canonically ordered by lane_id
  build: BuildIdentity,
  entries: [BundleEntry, ...],           // canonically ordered by (kind, path)
}

CapturedVerdict = {
  danger: "SAFE" | "GUARDED" | "DESTRUCTIVE" | "FORBIDDEN",
  required_level: null | "READ_ONLY" | "READ_WRITE" | "DDL" | "ADMIN",
  reason_class: null | <ReasonCategory>,
}

CapturedLane = {
  lane_id: "<bare identifier, ≤64 chars>",
  subject_id_hash: "sha256:<64 hex>" | "subject-sha256:<64 hex>",
}

BuildIdentity = { server: Version, classifier: Version, driver: Version }

BundleEntry = {
  kind: "cassette" | "redacted_config" | "redacted_audit_tail",
  path: "cassettes/<lane-id>.jsonl" | "config.redacted.toml" | "audit-tail.redacted.jsonl",
  sha256: "sha256:<64 hex>",
  bytes: <u64>,
}
```

The struct is `#[serde(deny_unknown_fields)]`: a field the schema does not know
is a refused manifest, not an ignored one. An unknown field is how a payload
gets smuggled into a file everybody assumes is safe to attach to a bug report.

### It cannot become an exfiltration channel

Every free-text field is reduced through the **same redaction seam the Arc J
corpus already proved** (`corpus::redact_sql`, `corpus::validate_redacted_sql`,
`corpus::safe_why`) — deliberately not a second implementation, because a second
redactor is a second thing to get wrong, and the two will drift. `statement` is
stored only as its redacted skeleton: literals become `'?'`, numbers `?`, binds
`:?`, comments are removed, and any identifier that is not an Oracle-shipped name
is replaced. The result is re-lexed to prove nothing survived. A statement the
redactor cannot lex produces **no manifest at all** — an incident that cannot be
captured safely is not captured.

Every structured field is an allowlist rather than a denylist:

| Field | Rule | What it keeps out |
| --- | --- | --- |
| `lane_id` | bare identifier, `[A-Za-z0-9_-]{1,64}` | usernames, paths, connect strings |
| `subject_id_hash` | `sha256:<64 hex>` (optionally `subject-` prefixed) | the raw subject (a username) |
| `build.*` | `package/<digit…>` with optional `;key=value` | `/etc/oracle/wallet/cwallet.sso`, `host:1521/orcl`, TNS descriptors, and `system/hunter2` — a credential pair is `name/name`, which is why the version part must start with a digit |
| `entries[].path` | matched against the three fixed bundle names | `..`, absolute paths, drive letters, `tnsnames.ora`, any wallet path |
| `entries[].sha256` | `sha256:<64 hex>` | free text in a hash field |
| `why` | the corpus safe-prose alphabet, ≤200 chars | a password pasted into the note |

The error vocabulary (`IncidentManifestError`) is closed and carries **no
payload**: an error that quoted the offending text would leak the very secret the
manifest was refused for, into whatever log or bug report the error lands in.

### A captured verdict is evidence, never authorization (SEC-1)

`CapturedVerdict` records what the guard decided so an operator can see it. It is
inert: nothing converts a manifest into a `GuardDecision`, there is no
`Into<GuardDecision>`, and no code path reads it back as a decision. Replay must
call `incident::reclassify_at_replay(&classifier, statement)`, which runs the
live classifier every time. A bundle that claims `SAFE` for a `DROP TABLE`
re-classifies as destructive at replay; the stored verdict changes nothing. This
is pinned by a test, not by convention.

### The same incident yields the same artifact

The manifest carries **no wall clock and no random id**. Lanes are ordered by
`lane_id` and entries by `(kind, path)` at capture, so the order the capture site
happened to walk its lanes cannot change the bytes. `id` is a domain-separated
SHA-256 over every other field, so capturing the same incident twice produces a
byte-identical `manifest.json`.

`id` is also the tamper check. `IncidentManifest::from_json` re-validates every
field against the same postconditions a fresh capture must satisfy and recomputes
the id. A manifest edited on disk to put the customer's SQL back into the
skeleton field is refused by the redaction postcondition before the id is even
considered; an edit the validators cannot see — a byte count changed so a swapped
file passes as the captured one — is caught by the id.

## Consequences

- Capture is fail-closed: an incident that cannot be represented safely is simply
  not collected. That is a deliberate loss of debuggability in exchange for the
  guarantee that a bundle is always safe to attach to a bug report.
- The bundle is only as redacted as its *other three files*. This manifest binds
  them by hash but does not parse them; `config.redacted.toml` and
  `audit-tail.redacted.jsonl` must pass their own redaction seams (Arc M / the
  audit tail's existing projection), and the cassettes must be recorded redacted.
  E1–E4 own that, and it is the single biggest way this design can still fail.
- `seed` is a `u64` the capture site supplies. It is the one field that is not
  shape-constrained, because a replay seed has no shape. It is a number, not a
  string, so it cannot carry text — but a capture site that derived a "seed" from
  secret material would still be leaking 8 bytes, and must not.

## Review trigger

Revisit if a bundle needs to carry a file kind this layout does not have, if
replay needs a field the manifest does not record, or if the corpus redaction
seam changes its postcondition — this schema depends on that seam being the only
way text enters an artifact.
