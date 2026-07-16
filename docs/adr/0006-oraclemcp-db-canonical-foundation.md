# ADR 0006 — Superseded: planned `plsql-mcp` convergence onto `oraclemcp-db`

## Status

Superseded (0.9.0): the standalone `plsql-mcp` server is deprecated. The
optional `plsql-intelligence` feature remains supported and embeds the offline
PL/SQL engine directly in `oraclemcp`.

## Context

This ADR recorded a proposed convergence for a standalone `plsql-mcp` server.
That server is deprecated. `oraclemcp` still supports offline PL/SQL analysis
through its optional `plsql-intelligence` feature; this historical record does
not retire that feature, its engine crates, or its offline tools and Workbench
surface.

## Decision

No active convergence is required. The engine-free core remains a one-way
boundary: it imports **no** PL/SQL analysis engine, while the optional feature
embeds the offline engine above that boundary.

## Consequences

- The engine-free core stays independent of the optional offline analysis
  engine.
- The `plsql-intelligence` feature, engine crates, offline tools, and Workbench
  remain supported within `oraclemcp`.
- Future work must not present the deprecated standalone `plsql-mcp` server as
  a live downstream consumer.

## Review trigger

This ADR is historical. Revisit only if a new standalone server is explicitly
proposed; preserve the engine-free boundary regardless.
