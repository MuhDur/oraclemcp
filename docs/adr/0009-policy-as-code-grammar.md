# ADR 0009: Policy-As-Code Grammar And Monotone Decisions

## Status

Accepted for the Arc N.0 design spike (`oraclemcp-epic-09x-alien-6sj8.5.1`).

## Context

The guard classifies an input statement before the operating-level gate can
admit it.  Profiles and the caller's current level can restrict that result,
but there is no per-principal, operator-authored SQL restriction layer.

This is deliberately separate from two existing mechanisms:

- `OperatorAuthorityPolicy` (D17, `oraclemcp-core/src/admin_auth.rs`) answers
  only whether a server-derived local/OAuth/mTLS subject may administer the
  HTTP operator API.  It has no SQL match fields, no statement evaluator, and
  no rewrite path.  D17 is an identity/configuration pattern, not a partial
  Arc N implementation.
- `SchemaPolicySet` (`oraclemcp-guard/src/policy.rs`) is the older schema gate.
  Its `PolicyDecision::Allow` is not an Arc N decision and must not be reused
  for the new policy boundary.  In particular, it has no principal selector,
  no policy version, and cannot represent a SQL narrowing certificate.

Arc N must sit after base classification and must not become a second SQL
classifier.  The invariant is that a policy may remove an admitted operation
or make its requirements stricter, but may never make a refused operation
admissible.

## Decision

### Scope and configuration shape

Arc N is a small declarative TOML rule list, not an embedded policy language.
It is profile-scoped, versioned, and loaded with `deny_unknown_fields`.  The
following is the version-one wire shape; N.1 owns its Rust config types and
loader.

```toml
[profiles.production.sql_policy]
version = 1

[[profiles.production.sql_policy.rules]]
id = "deny-payroll-read"
match = { schema = "HR", object = "PAYROLL", verb = "select" }
effect = { kind = "deny" }

[[profiles.production.sql_policy.rules]]
id = "billing-writes-need-admin"
match = { schema = "BILLING", object = "INVOICES", verb = "update", principal = "oauth:acct-42" }
effect = { kind = "require_level", level = "ADMIN" }

[[profiles.production.sql_policy.rules]]
id = "tenant-42-sees-only-tenant-42"
match = { schema = "APP", object = "ORDERS", verb = "select", principal = "oauth:acct-42" }
effect = { kind = "require_predicate", sql_fragment = "tenant_id = 42 AND archived_at IS NULL" }
```

`version` is mandatory and version `1` is the only accepted value.  An absent
`sql_policy` means that Arc N contributes its identity narrowing; it does not
mean a policy grants access.  Every rule has a non-empty, unique `id` used in
audit/certificates.  Rule order is preserved for audit and predicate rendering,
not for allow/else precedence.

`match` is required.  Its fields are all optional and are conjunctive:

| Field | Meaning | Version-one matching rule |
| --- | --- | --- |
| `schema` | Oracle owner | One normalized identifier; unquoted values use Oracle's uppercase normalization and quoted values retain Oracle quote semantics. No dots, globs, or regexes. |
| `object` | Object within `schema` | One normalized identifier under the same rules. A rule with `object` must also name `schema`. |
| `verb` | Classified top-level operation | One of `select`, `insert`, `update`, `delete`, `merge`, `ddl`, `admin`, `plsql`, or `alter_session`. It comes from the base classification context, never a user-supplied label. |
| `principal` | Authenticated requester | Exact server-derived stable principal key, such as `oauth:acct-42` or `mtls:sha256-...`. It is never taken from a tool argument. |

An empty `match = {}` is a global tightening rule and is valid.  Matching is
based on canonical semantic context, including resolved synonym targets, not a
regex over SQL text.  A schema/object selector has three states: proven match,
proven non-match, or unresolved.  An unresolved selector is a denial, rather
than a silent non-match, whenever a rule could apply.  This prevents a synonym,
quoted name, or incomplete catalog result from bypassing a scoped restriction.

### Effects and the return type

The TOML tagged-union spelling maps to the conceptual grammar required by the
plan:

```text
Rule              := { id, match: Match, effect: Deny | RequireLevel(L) | RequirePredicate(P) }
Match             := { schema?, object?, verb?, principal? }
Deny              := { kind = "deny" }
RequireLevel(L)   := { kind = "require_level", level = OperatingLevel }
RequirePredicate(P) := { kind = "require_predicate", sql_fragment = Predicate }
```

`OperatingLevel` is exactly the existing `READ_ONLY < READ_WRITE < DDL <
ADMIN` ladder.  `RequireLevel(L)` adds a lower bound; it never replaces the
base required level.  A lower or equal configured level may be a no-op for an
already-more-dangerous base statement, but cannot lower the final requirement.

The evaluator's public result must have this shape (names are illustrative):

```rust
enum PolicyTightening {
    Deny(PolicyDenial),
    Narrow(PolicyNarrowing),
}
```

There is intentionally no `Allow` variant.  No matching rules produce
`Narrow(PolicyNarrowing::identity())`; that identity says only that this layer
added no restriction, never that the operation is authorized.  A policy type
with `Allow`, `Permit`, `Override`, a danger/level reduction, or a classifier
configuration mutation is a load-time rejection, not an alternate spelling.

All matching rules compose, rather than first-match-wins:

- any matching `Deny` returns `Deny`;
- matching `RequireLevel` rules take the maximum requested level;
- matching `RequirePredicate` rules are conjoined with `AND` in declaration
  order; and
- a predicate targeting a different relation from another matching predicate
  is denied rather than guessed at.

This aggregation makes adding a rule monotonically at least as restrictive as
the prior policy set.

### Predicate vocabulary

`RequirePredicate` is an Oracle SQL boolean fragment, not a general execution
escape hatch.  Version one accepts only a conjunction of row-filter atoms:

```text
Predicate    := Atom ("AND" Atom)*
Atom         := Column Compare Value
             | Column "IS" ["NOT"] "NULL"
Column       := [Identifier "."] Identifier
Compare      := "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "LIKE"
Value        := NumericLiteral | StringLiteral | "NULL"
```

The fragment may not contain comments, a semicolon, `OR`, subqueries,
`SELECT`/`WITH`, functions, package calls, identifiers in value position,
binds, or any DML, DDL, DCL, PL/SQL, or session-control token.  Configuration
values are intentionally literals in v1: allowing a request-controlled bind
would let the requester choose the supposed restriction.  A later version may
add a separate, server-derived claim-binding design; it must not silently make
request values policy inputs.

`RequirePredicate` must name exactly one `schema` and `object` and a `verb` of
`select`, `update`, or `delete`.  It is applied only when the parsed base
statement has exactly that one resolved target relation and a structural
location to add a `WHERE` condition.  It is otherwise denied.  In particular,
joins, CTEs, `MERGE`, `INSERT`, PL/SQL, unresolved names, and aliases that do
not resolve to the matched target are not predicate-rewritable in v1.  The
restriction is intentional: it keeps a policy predicate from adding another
data source or an unreviewed callable.

### Composition and SQL rewrite

The execution path is normative:

1. Classify the original SQL with the existing fail-closed classifier.  A base
   refusal remains refused and does not invoke a policy rewrite.
2. Build the policy match context only from the classified/semantic statement
   and the server-derived principal.  Evaluate to `Deny` or `Narrow`.
3. For `Deny`, stop.  For a `Narrow` with predicates, parse the original SQL
   and add one parenthesized conjunction to its AST `WHERE` condition; string
   concatenation is forbidden.  Failure to parse or place the predicate is a
   denial.
4. Re-classify the rendered candidate with the same classifier configuration.
   A forbidden candidate is denied.  The final required level is the maximum
   of the original classification, the candidate classification, and every
   `RequireLevel` floor.  The ordinary session/profile level gate, protected
   cap, confirmation flow, and rollback-by-default DML behaviour run unchanged.

Formally, the authorization condition is
`final = base_classification AND policy_tightening AND candidate_classification`.
The original base result is retained in the maximum even if a candidate would
otherwise classify at a lower level.  Thus neither a rewrite nor a policy level
can downgrade a requirement.  Reclassification is mandatory even though the
predicate vocabulary is deliberately narrow; it is the SEC-1 recovery check
against an implementation/parser discrepancy.

The audit/certificate record must retain the policy version, profile, ordered
matched rule ids, original SQL hash and classification summary, any rendered
candidate hash, candidate classification summary, and final denial or level
floor.  It must never write a secret or raw SQL literal merely to explain a
match.

### Load-time rejection

N.1 must reject the whole profile configuration, with an actionable
diagnostic, for unknown fields, unknown versions/effects/verbs/levels, duplicate
rule ids, malformed identifiers, wildcard/regex selectors, an `object` without
`schema`, and any predicate outside the vocabulary above.  It must also reject
a `RequirePredicate` that lacks an exact schema/object/select-or-update-or-
delete match.  Invalid regexes in the older `SchemaPolicyRaw` are not precedent
for dropping Arc N rules: this layer never silently removes a restriction.

## Normative conformance cases

The following cases are the test corpus that N.1--N.4 must implement.  They
are part of this grammar contract, not illustrative prose.

| Case | Required result |
| --- | --- |
| Base classifier refuses `DROP TABLE APP.ORDERS`; a matching `RequireLevel(READ_ONLY)` exists | Refused; policy cannot turn it into a read. |
| Two matching `RequireLevel` rules request `READ_WRITE` and `ADMIN` | `Narrow` has an `ADMIN` floor. |
| A matching deny follows a matching predicate | `Deny`; there is no declaration-order escape. |
| A policy requires `tenant_id = 42` for `APP.ORDERS` select | Candidate has `AND (tenant_id = 42)`, is reclassified, and retains at least the original level. |
| Predicate is `tenant_id = 42 OR 1 = 1`, `EXISTS (SELECT ...)`, `pkg.f() = 1`, `:tenant_id`, or includes `;`/a comment | Configuration load fails. |
| A rule targets `HR.PAYROLL`, but a synonym/canonical target cannot be resolved | Denied as an unresolved policy match; it is not treated as a miss. |
| TOML uses `effect = { kind = "allow" }`, an unknown field, or a duplicate id | Configuration load fails. |
| A rewritable policy candidate is refused by the classifier | Refused before execution, even though the original base SQL was admitted. |

N.2 must unit-test the `Deny | Narrow` representation and all-rule
aggregation; N.3 must test AST placement and mandatory reclassification; N.4
must property-test that no policy configuration admits a base-refused statement
or lowers its required operating level.  These tests belong with the guard and
config implementations, not with this design-only spike.

## Consequences

The first Arc N implementation is intentionally less expressive than an
arbitrary SQL policy engine.  It can deny a principal/object/verb combination,
raise its required operating level, or add a static conjunctive row filter.
It cannot grant authority, replace the classifier, inject executable SQL, or
make a request-controlled value a policy input.

This gives N.1--N.4 a stable, testable boundary.  Future expression richness
requires a versioned grammar decision and the same proof that the new form is
strictly tightening.

## Review trigger

Revisit this ADR before accepting any policy-controlled bind, claim-derived
value, function, subquery, `OR` expression, multi-relation rewrite, or a new
effect kind.  Each trigger requires a new versioned grammar and an executable
proof that the added form cannot admit a base-refused statement or lower its
required operating level.
