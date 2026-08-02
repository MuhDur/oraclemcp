# nn3ne — extend the read-purity proof to OLS / RAS / Data Redaction catalogs?

**Bead:** `oraclemcp-nn3ne` (P3, boundary assessment).
**Verdict: the existing boundary is intentional.** The read-purity proof
answers whether a plain fetch can invoke user-controlled side effects. VPD
policy functions and virtual-column expressions are therefore in scope. Oracle
Label Security (OLS), Real Application Security (RAS), and Data Redaction are
declarative row/column enforcement applied by Oracle; reproducing their policy
catalogs is outside this side-effect proof. This bead records that contract and
does not add a new driver or admission path.

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

## Why OLS / RAS / Data Redaction are not mirror checks

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

## Evidence and non-goals

The existing proof has focused offline evidence in
`crates/oraclemcp-db/src/catalog_resolver.rs`:

- `relation_purity_requires_plain_policy_free_non_virtual_tables` proves an
  enabled VPD policy or virtual column cannot earn `ProvenReadOnly`.
- `c8_a_sighted_principal_on_a_clean_table_still_proves_read_only` proves a
  readable, successfully empty `ALL_POLICIES` result remains the ordinary
  VPD-free allow case.
- `c8_a_catalog_blind_principal_must_not_yield_a_read_only_proof` proves a
  catalog error propagates fail-closed instead of masquerading as absence.

Those tests define the read-purity boundary without pretending to prove the
presence or absence of OLS, RAS, or Data Redaction policies. A separate feature
that inventories those controls would require live coverage across installed,
not-installed, policy-present, policy-absent, and catalog-blind states. That is
not an acceptance condition for classifying a statement's side-effect level.

## Is a real hole being left open?

No gap is left in the read-purity proof's stated contract:

- The read-purity proof's stated concern is **user-controlled code invoked on a
  plain fetch** — precisely what a **VPD SELECT policy function** or a **virtual
  column expression** does, which is why those two are the checks that exist.
- OLS filters rows by label comparison; Data Redaction masks column output
  (largely built-in FULL/PARTIAL/REGEXP/RANDOM types); RAS enforces ACLs. These
  change *which rows/values* a `SELECT` returns but the statement remains
  `READ_ONLY`, and they do not inject arbitrary user PL/SQL into the ordinary
  fetch path the way a VPD policy function does. Extending the proof to them is
  belt-and-suspenders, not the closing of an open door.
- Oracle continues to apply OLS, RAS, and Data Redaction to the connected
  principal regardless of this proof. The server does not bypass or attempt to
  reimplement those controls.

## If policy inventory is added later

The only sound shape is a **three-valued** probe per feature, gated on an
explicit install/visibility check, never the `ALL_POLICIES` binary mirror:

1. Detect installation independently (e.g. a bounded existence check that maps
   "object absent" to *feature-not-installed ⇒ no policies of this class* and a
   privilege error on an *existing* view to *blind ⇒ refuse*), and only then
2. run the per-object policy probe.

That requires an install-vs-blind oracle plus live option-specific fixtures. It
would be a policy-observability feature, not a prerequisite for this
side-effect-purity decision.
