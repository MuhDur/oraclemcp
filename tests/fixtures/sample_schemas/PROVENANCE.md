# Vendored sample schemas — provenance and governance (D9, rig L2)

## What is vendored

`upstream/` holds the SQL of Oracle's own **db-sample-schemas** — the HR
(`human_resources`), CO (`customer_orders`) and SH (`sales_history`) schemas —
copied verbatim, plus the upstream `LICENSE.txt`, `README.md` and `SECURITY.md`.

| | |
|---|---|
| Repository | <https://github.com/oracle-samples/db-sample-schemas> |
| Tag | `v23.3` |
| Commit | `e3325a83e56c516815844025418a96ecaf219751` |
| Retrieved | 2026-07-21 (UTC) |
| Licence | MIT — full text at `upstream/LICENSE.txt`, © 2023 Oracle and/or its affiliates |
| Files | 19, listed with their hashes in `upstream/MANIFEST.json` |

## How the licence was verified

Not by a badge or by the phrase "sample data". The GitHub API reports
`spdx_id: MIT`, **and** the vendored `LICENSE.txt` was read: it is the standard
MIT grant ("Permission is hereby granted, free of charge… THE SOFTWARE IS
PROVIDED \"AS IS\"") with an Oracle copyright line and no additional
restriction, field-of-use rider, or attribution clause beyond MIT's own
"above copyright notice … included in all copies".

MIT requires the copyright and permission notice to travel with the copies, so
`LICENSE.txt` is vendored alongside the SQL and
`scripts/rig/verify_sample_schemas.sh` refuses if it ever goes missing.

## How the bytes were verified

Every vendored file was hashed with `git hash-object` and compared against the
blob SHA GitHub reports for that path **at the pinned commit**. All 19 matched.
`upstream/MANIFEST.json` records those hashes, so the check is repeatable:

```bash
bash scripts/rig/verify_sample_schemas.sh
```

## What is deliberately NOT vendored

The five SH CSV data files — `sales.csv` (72 MB), `customers.csv` (12 MB),
`costs.csv`, `supplementary_demographics.csv`, `times.csv`, `promotions.csv`
— about **88 MB**, against roughly 1.5 MB for everything vendored here. They are
bulk row data, not structure, and carrying them would dominate the repository
and the release size budget.

Consequence, stated plainly so nobody is surprised: **`sh_populate.sql` loads no
rows without them, so SH arrives structure-only** (tables, views, constraints —
enough for a catalog/tool-surface sweep, not enough for a data-volume lane). HR
and CO are complete, data included, because their data is inline SQL.

If a data-volume lane is ever needed, fetch them at the same pinned commit
rather than from `main`:

```bash
SHA=e3325a83e56c516815844025418a96ecaf219751
for f in sales customers costs supplementary_demographics times promotions; do
  curl -sSfO "https://raw.githubusercontent.com/oracle-samples/db-sample-schemas/$SHA/sales_history/$f.csv"
done
```

Do not commit them.

## Confidentiality

These schemas are public sample data published by Oracle. **No file here is
derived from a real or field-test environment**, and none may ever be. The
governance overlay layered on top (`../governance/`) is synthetic and written
by us, using the repository's existing fictional identifiers.

This is not a preference. Customer or field identifiers must never enter a
committed artifact, so "I'll just load a trimmed copy of a real schema to make
the lane realistic" is out of scope permanently, not merely discouraged.

## Governance

### How these stay current

They do not drift on their own, and that is deliberate. The pin is what makes a
rig run reproducible: the same commit yields the same DDL, so a lane failure is
about our code rather than about which day the schemas were fetched.

Upgrading is an explicit act, never automatic:

1. Re-fetch every file in `MANIFEST.json` at the **new** tag.
2. Regenerate `MANIFEST.json` (hashes are `git hash-object` of each file).
3. Update the table at the top of this file — tag, commit, retrieval date.
4. Re-read the upstream `LICENSE.txt`. A relicence is exactly the kind of change
   a version bump hides; do not assume it is still MIT because it was.
5. Run `bash scripts/rig/verify_sample_schemas.sh` and its `--selftest`.
6. Re-run the D9 load against `free23` (and `xe21` where compatible) before
   relying on it — upstream DDL can gain syntax an older generation refuses.

There is no scheduled upgrade. Upgrade when a lane needs something a newer
release provides, and say so in the commit.

### Who may add to this tree, and how

Anyone may propose an addition; nothing lands without all five of:

1. **A licence verified from the upstream licence text**, not a repository badge
   or a README sentence. MIT, Apache-2.0, BSD or UPL are acceptable; anything
   with a field-of-use restriction is not.
2. **The licence text vendored** alongside the files it covers.
3. **A pinned commit** — a tag alone is not enough, since tags move.
4. **`MANIFEST.json` regenerated** so the new files are hash-pinned.
5. **Provenance recorded here**: what, from where, at what revision, retrieved
   when, and why the rig needs it.

This is enforced, not advisory: `verify_sample_schemas.sh` refuses any file in
`upstream/` that the manifest does not list. A schema dropped in without going
through the steps above fails the gate rather than quietly inheriting the
vendored directory's implied "this was checked" status — which is the failure
mode this section exists to prevent.

### What must never be added

- Anything derived from a real or field-test environment (see Confidentiality).
- Anything whose licence forbids redistribution or restricts field of use.
- Bulk data that would blow the size budget — link and fetch on demand instead,
  as the SH CSVs do above.
