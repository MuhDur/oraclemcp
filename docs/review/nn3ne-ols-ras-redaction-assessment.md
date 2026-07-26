# nn3ne — extend the read-purity proof to OLS / RAS / Data Redaction catalogs?

**Bead:** `oraclemcp-nn3ne` (P3, assess-then-act).
**Verdict: DEFER.** This is *not* a bounded, testable mirror of the existing
`ALL_POLICIES` proof; the naive mirror would convert a targeted fail-closed
refusal into wholesale over-refusal on the common database, and doing it
correctly needs catalog-visibility semantics we cannot resolve or test without
provisioning OLS / RAS / Data-Redaction–configured databases. The operator has
pre-approved deferral for this case. No existing path is weakened — this bead
lands as assessment only, no code change.

## What the existing proof does and *why it is sound*

`resolved_relations_read_purity`
(`crates/oraclemcp-db/src/catalog_resolver.rs:461-517`) proves a plain table
fetch cannot invoke user-controlled code. After ruling out non-tables, db-links,
and virtual columns, it establishes the trustworthiness of its "no VPD policy"
answer with a **catalog-visibility proof**:

- `prove_policy_catalog_readable` (`:1594-1600`) runs
  `SELECT policy_name FROM all_policies WHERE ROWNUM <= 1`.
- Determinant is **Ok-vs-error, not row count**: a successful read (even zero
  rows) *proves visibility*; an error propagates via `?` to a fail-closed
  refusal (see the C8-A test, `:2670`).

This is sound **only because of three properties that are specific to
`ALL_POLICIES`:**

1. **Always present.** VPD (`DBMS_RLS`) is a core, always-installed feature, so
   `ALL_POLICIES` exists on *every* database. An error therefore means "this
   principal is blind", never "this feature is not installed".
2. **PUBLIC-granted.** `ALL_POLICIES` is readable by ordinary principals, so a
   successful read is the *expected* case and an error is the rare, suspicious
   one worth refusing on.
3. **Scoped to the caller.** `ALL_POLICIES` lists policies on objects the
   current user can access, so a successful empty read is positive proof of
   *absence*, not merely of visibility.

## Why OLS / RAS / Data Redaction break every one of those properties

Source: local Oracle reference
`~/.claude/skills/oracle/SECURITY-OPTIONS-REFERENCE.md` (Oracle Label Security
is an installed, administered option under `LBACSYS` / `SA_SYSDBA`), plus the
routing note that VPD lives in core `DBMS_RLS`.

| Catalog | Feature | "Always present"? | PUBLIC-readable? |
|---|---|---|---|
| `ALL_POLICIES` (VPD) | core `DBMS_RLS` | **yes** | **yes** |
| `ALL_SA_POLICIES` (OLS) | Oracle Label Security **option** (`LBACSYS`) | **no** — absent unless OLS installed | no — LBACSYS-owned / catalog-role |
| `REDACTION_POLICIES` (Data Redaction) | Advanced Security **option** | **no** on editions without it | no — restricted / `EXEMPT REDACTION POLICY` territory |
| `DBA_XS_*` / `XS$*` (Real Application Security) | RAS **option** | **no** unless RAS configured | no — DBA-level |

Consequences of copying the `ALL_POLICIES` "error ⇒ blind ⇒ refuse" rule onto
these views:

- On the **majority** of real databases OLS/RAS/Redaction are **not
  installed**, so `SELECT ... FROM all_sa_policies` returns **ORA-00942 (table
  or view does not exist)**. The mirror would then refuse **every** read-only
  proof on those databases. That is not a security tightening — it is a
  fail-closed denial-of-service against the normal case.
- Even where the option *is* installed, an ordinary MCP principal typically
  lacks the catalog role / EXEMPT privilege, so the probe errors and again
  refuses everything.
- The correct behavior would have to **distinguish "feature not installed ⇒ no
  such policies ⇒ safe to proceed" from "feature installed but I am blind ⇒
  uncertain ⇒ refuse".** But to a low-privileged principal both surface as
  **ORA-00942**, which is genuinely ambiguous (missing object vs. no
  visibility). There is no clean, always-present, PUBLIC-granted equivalent view
  (there is no `ALL_REDACTION_POLICIES`, `ALL_SA_POLICIES` requires OLS, RAS is
  DBA-only) on which the simple Ok-vs-error determinant is sound. This is the
  "uncertain catalog visibility semantics" the bead flags.

## Testing cost

The existing proof is unit-testable with a mock `OracleConnection` because the
determinant is Ok-vs-error on one always-present view. A correct OLS/RAS/
Redaction proof would need live coverage across four states per feature —
installed+policy, installed+no-policy, installed+blind-principal, and
not-installed — which requires provisioning OLS (`LBACSYS`/`SA_SYSDBA`), RAS,
and Advanced Security Data Redaction. None of these are configured in the
current live-test matrix (18c/21c/23ai XE/Free do not ship them enabled), so the
"injected-failure vs. proven-absence" distinction that makes the addition safe
cannot actually be exercised. Heavy, uncertain testing — the DEFER criterion.

## Is a real hole being left open?

No open security hole; at most a defense-in-depth gap, and a contained one:

- The read-purity proof's stated concern is **user-controlled code invoked on a
  plain fetch** — precisely what a **VPD SELECT policy function** or a **virtual
  column expression** does, which is why those two are the checks that exist.
- OLS filters rows by label comparison; Data Redaction masks column output
  (largely built-in FULL/PARTIAL/REGEXP/RANDOM types); RAS enforces ACLs. These
  change *which rows/values* a `SELECT` returns but the statement remains
  `READ_ONLY`, and they do not inject arbitrary user PL/SQL into the ordinary
  fetch path the way a VPD policy function does. Extending the proof to them is
  belt-and-suspenders, not the closing of an open door.
- The guard remains fail-closed by construction: anything not *proven*
  `ProvenReadOnly` stays `Unknown` and is gated by the classifier at the active
  operating level. Deferring adds no new admit path.

## If revisited later (design sketch, not this bead)

The only sound shape is a **three-valued** probe per feature, gated on an
explicit install/visibility check, never the `ALL_POLICIES` binary mirror:

1. Detect installation independently (e.g. a bounded existence check that maps
   "object absent" to *feature-not-installed ⇒ no policies of this class* and a
   privilege error on an *existing* view to *blind ⇒ refuse*), and only then
2. run the per-object policy probe.

That requires an install-vs-blind oracle we do not have offline, and the live
provisioning above to validate it. Track as a separate, larger bead when an
OLS/RAS/Redaction-configured test database is available — not a P3 quick win.
