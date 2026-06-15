# R3 Simplification Convergence

Scope: final `simplify-and-refactor-code-isomorphically` pass for bead
`oraclemcp-8fc.3`.

Landed simplification:

- R2 extracted the repeated `describe()` best-effort first-row query pattern
  into a private helper.

Remaining candidates and disposition:

| Candidate | Why not in simplification loop |
| --- | --- |
| Split `dispatch/mod.rs` by tool family | This is a file-boundary/module extraction, not a local simplification. It belongs to de-monolithization with explicit import/API isomorphism proof. |
| Generate or table-drive registry schemas | Public MCP schema output is agent-facing and large. It needs schema golden artifacts and a dedicated design, not a local refactor. |
| Refactor dispatch JSON response builders | The code is repetitive but each branch encodes a tool-specific response shape. Risk is too high without per-tool golden comparison. |
| Simplify SQL classifier internals | The classifier is the fail-closed safety invariant and is not a current hotspot. |
| Simplify HTTP transport loops | Concurrency/deadlock audit should run before reshaping transport control flow. |

Stop condition:

- One safe simplification landed.
- A second pass found no remaining local candidate with low enough risk for
  behavior-preserving refactor inside this skill loop.
- Larger changes are intentionally handed to the de-monolith and deadlock passes
  where their risks are directly evaluated.
