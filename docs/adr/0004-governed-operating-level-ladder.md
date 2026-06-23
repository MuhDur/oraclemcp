# ADR 0004 — Governed operating-level ladder with confirmation-gated escalation

## Status

Accepted (0.4.0). Supersedes the earlier "read-only-only" framing.

## Context

The first framing of the server was "read-only". That is too narrow: real agent
workflows need guarded DDL, compiles, source patches, and occasional DML — but
under controls, not by flipping a flag. A binary read/write switch is the wrong
model because it has no notion of *how much more* privilege a given action needs,
and no per-deployment ceiling.

## Decision

Adopt an explicit operating-level ladder
`READ_ONLY < READ_WRITE < DDL < ADMIN`. A fail-closed classifier derives the
*minimum* level each raw statement needs and admits it only when the active
session already permits that level; anything it cannot prove safe for the active
level is refused before reaching Oracle. The server is **read-only by default**
but **escalation-capable**, governed by:

- a per-profile `max_level` ceiling (immutable for that profile) and a
  `default_level` starting level;
- a **preview → confirmation-token** step-up for elevation, creating a
  **TTL-bounded** window (default 900s, max 3600s);
- DML rolling back by default; commits and DDL/Admin requiring the preview
  confirmation token;
- `protected` profiles pinned at `READ_ONLY` with an immutable ceiling;
- OAuth scopes that can only **lower** the effective level, never raise it above
  `max_level`.

This is **not** read-only-only and not a blanket safety guarantee — it is
governed and least-privilege, with escalation possible only within configured
bounds.

## Consequences

- One model covers reads, guarded writes, DDL, compiles, and admin work without
  a flag that silently widens capability.
- Operators control blast radius per profile via `max_level`; the lowest useful
  ceiling is the safest configuration.
- Documentation and public positioning must use governed/least-privilege
  language; the honesty gate (`scripts/oraclemcp_honesty_grep.sh`) enforces this
  and rejects the over-claiming framing it forbids.
- More moving parts than a boolean switch (levels, tokens, TTL windows), which
  is the cost of provable, bounded escalation.

## Review trigger

Revisit if a fifth distinct operating level is genuinely needed (the four-rung
ladder no longer expresses real workflows), if step-up friction proves to block
legitimate work often enough to warrant a different gate, or if any path is
found that escalates **without** passing the classifier and the per-profile
ceiling — the last is a defect to fix, not a decision to re-litigate.
