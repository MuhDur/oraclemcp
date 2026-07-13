# ADR 0008: Result Masking Policy And Per-Profile Tokenization

## Status

Accepted for the Arc M.0 design spike.

## Context

`oraclemcp` already redacts secrets, credentials, profile output, and telemetry
attributes. That seam protects operator material, not query result data. A
read-only query can still return sensitive business values to an agent context,
so egress needs its own fail-closed control.

Arc M adds a server-side result transformer. Oracle-native controls such as
VPD, RLS, or `DBMS_REDACT` can be added later as a separate licensed tier, but
they do not replace the server seam: the MCP server is the last point that can
enforce a uniform policy over every result payload before serialization.

## Decision

The masking policy is profile-scoped and evaluated after a statement has passed
the read guard but before rows leave the server.

Policy records are TOML objects under the profile:

```toml
[[profiles.prod.masking.rules]]
column_match = { schema = "HR", table = "EMPLOYEES", column = "EMAIL" }
action = "tokenize"
tag = "pii.email"

[[profiles.prod.masking.rules]]
column_match = { tag = "sensitive" }
action = "mask"

[profiles.prod.masking]
mask_unknown_default = true
salt_ref = "profile:prod:masking:v1"
```

`column_match` has these fields:

- `schema` — optional Oracle owner, normalized with the same identifier rules as
  the catalog resolver.
- `table` — optional object name.
- `column` — exact result-column/catalog-column name. It is mutually exclusive
  with `tag`.
- `tag` — operator-defined sensitivity label from the catalog/tagging layer.

`action` is one of:

- `mask` — replace a non-null value with a fixed marker that carries no length
  or distribution signal: `"<masked>"`.
- `tokenize` — replace a non-null value with a deterministic per-profile token.
- `null` — replace a non-null value with JSON null. This is explicit; missing
  policy never means pass-through.

Rules are first-match by declaration order. A profile that enables masking must
define `mask_unknown_default = true` unless it also defines a complete catalog
tagging source. Unknown, unlisted, or sensitive-tagged columns are masked, not
passed through. This is the egress analogue of fail-closed admission.

Null database values remain null for all actions. Masking only transforms data
that exists; it does not invent a value.

## Token Function

Tokenization is deterministic inside one profile and unlinkable across profiles.
The profile salt is the HMAC key; the message is domain-separated and type-aware:

```text
token = "tok_v1_" || base64url_no_pad(HMAC-SHA256(
  key = profile_salt_bytes,
  msg = "oraclemcp-mask-token:v1" || 0x00 || type_tag || 0x00 || canonical_plaintext_bytes
)[0..16])
```

`type_tag` is the serializer's canonical Oracle type family (`VARCHAR2`,
`NUMBER`, `DATE`, `TIMESTAMP`, and so on). `canonical_plaintext_bytes` are the
same canonical value bytes the result serializer would have emitted before
masking. This keeps `NUMBER` and date/time tokenization stable across NLS
settings.

The 16-byte truncation yields a 128-bit token body. That is enough for
non-secret, deterministic joins while keeping tokens compact. The token is not
reversible without the per-profile salt.

Test vector:

- `profile_salt_bytes` hex:
  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- `type_tag`: `VARCHAR2`
- `canonical_plaintext_bytes`: `alice@example.com`
- full HMAC-SHA256 hex:
  `7344b4310a62eba054ac0c07646657a09d8e43a9c0dd6c756516b1fe815b17df`
- emitted token: `tok_v1_c0S0MQpi66BUrAwHZGZXoA`

## Salt Storage And Rotation

Salts are stored in server state files, not in Oracle. The state record is
profile-scoped:

```json
{
  "kind": "oraclemcp.masking_salt.v1",
  "profile": "prod",
  "salt_id": "profile:prod:masking:v1",
  "created_at": "2026-07-13T00:00:00Z",
  "salt_b64": "<32 random bytes, base64url-no-pad>",
  "status": "active"
}
```

Rotation creates a new `salt_id` and marks the previous salt as `retired`.
Existing audit records and exported result artifacts keep the salt id used for
their masking decision; the raw salt is never written into audit records. New
queries use the active salt. A profile without an active salt cannot tokenize;
it must fail closed at policy load or downgrade affected rules to `mask` only
if the operator configured that fallback explicitly.

## Consequences

The result transformer can only remove or transform data after a read has
already been admitted. It does not loosen SQL admission and it cannot expose a
value that was not present in the original row.

Deterministic tokens support agent joins within one profile. They intentionally
do not support joins across profiles or salt generations.

Format-preserving tokenization is deferred. If added, it must be a separate
action because preserving length, character class, or numeric shape leaks more
distribution information than the default `tok_v1_...` token.

The mask decision must be auditable in later beads: policy version, matched
rule id, action, salt id for tokenized values, and masked column identities
should feed the Arc B proof/certificate path without exposing plaintext.

## Review Trigger

Revisit this ADR if result masking moves into a database-native-only tier, if
tokenization must be joinable across profiles, or if a future threat model
requires stronger privacy against frequency analysis than deterministic
per-profile tokens can provide.
