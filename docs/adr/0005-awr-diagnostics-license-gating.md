# ADR 0005 — AWR / Diagnostics-Pack license gating (never invoke a paid pack unlicensed)

## Status

Accepted (0.4.0; bead family C1–C10).

## Context

The DBA suite (`oracle_db_health`, `oracle_top_queries`) wants the richest data
source available. The best top-SQL data comes from AWR/ASH, which are part of
the Oracle **Diagnostics Pack** — a *separately licensed* option. Querying
`DBA_HIST_*` / `V$ACTIVE_SESSION_HISTORY` on a database that is not licensed for
the pack is a license violation, even though the views are technically readable.
An MCP server that silently reaches for AWR would expose operators to that risk.

## Decision

License-gate the diagnostics path. The DBA tools detect entitlement by reading
`control_management_pack_access` (a `DIAGNOSTIC` entitlement) and **degrade**:

1. **Licensed** (`control_management_pack_access` includes `DIAGNOSTIC`): use
   AWR/ASH.
2. **Not licensed**: fall back to **Statspack** if available.
3. **Neither**: return a **structured "unavailable / license required"** error —
   never invoke the paid pack regardless.

This sits alongside the suite's general privilege degradation (`DBA_*` → `ALL_*`
→ skip), so a least-privilege account also degrades cleanly. The whole suite is
read-only.

## Consequences

- oraclemcp never invokes a paid Oracle pack on an unlicensed database — an
  honesty and compliance property, not just a feature flag.
- On unlicensed databases the tools still return useful output (Statspack) or a
  clear, structured reason, rather than failing opaquely or over-reaching.
- We must track the correct entitlement signal; if Oracle changes how pack
  access is reported, the detection must follow.
- A pure performance *advisor* (recommendations from licensed pack data) stays
  **out of scope** for this reason — the licensing surface is not worth the
  compliance risk in an agent-facing tool.

## Review trigger

Revisit if Oracle changes the entitlement signal (`control_management_pack_access`
semantics change, or a new authoritative source appears), if a future Oracle
edition bundles AWR/ASH without separate licensing, or if a license-clean data
source for advisor-grade recommendations becomes available — only then reconsider
the advisor scope decision.
