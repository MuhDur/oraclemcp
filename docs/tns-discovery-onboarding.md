# TNS discovery and consent-gated onboarding — design spec (anchor)

This is the single shared design contract for the *TNS-onboarding* feature: the
`oraclemcp setup --discover` / init flow that finds a host's `tnsnames.ora`
files, maps each net-service to a **governed, least-privilege** connection
profile (read-only by default, capped at `READ_ONLY`), and writes a
self-documenting `profiles.toml` — only ever after explicit consent and never
clobbering an existing config.

It exists so no implementer of a downstream bead needs the originating
conversation. The mapping tables, the search order, the consent matrix, the
idempotency/backup rules, and the canonical test fixture are all fixed here and
cited by exact anchor.

The machine-readable half of this contract lives beside the config structs it
governs, in [`crates/oraclemcp-config/src/discovery/`](../crates/oraclemcp-config/src/discovery/mod.rs)
(`FieldDisposition`, `CONNECTION_PROFILE_FIELD_DISPOSITIONS`,
`TOP_LEVEL_FIELD_DISPOSITIONS`). A schema-drift test there asserts the tables
below enumerate **every** serde field of `ConnectionProfile` and
`OracleMcpConfig`, so this document and the code cannot silently diverge.

Nothing here weakens the [`AGENTS.md`](../AGENTS.md) safety invariant: every
synthesized profile is capped at `READ_ONLY` (both `max_level` and
`default_level` set explicitly), credentials are only ever emitted as
placeholder secret-refs (never a literal), and the fail-closed classifier and
the operating-level ladder are untouched.

---

## A. Search order for `tnsnames.ora` candidate directories

Oracle Net resolves `tnsnames.ora` from `TNS_ADMIN`, then
`ORACLE_HOME/network/admin`, then platform defaults. Discovery looks **wider**
than today's doctor (which only reads `TNS_ADMIN`,
`crates/oraclemcp/src/main.rs:4752`) and than the wrapper script (which defaults
`ORACLE_NET_HOME` to `~/.config/oraclemcp/network`,
`crates/oraclemcp/src/robot_docs.rs:26`).

Candidate directories, in **precedence order** (first-match-wins for choosing the
authoritative file, but *scan-all-for-report* so the operator sees every place a
`tnsnames.ora` was — or was not — found):

| # | Candidate | Source |
|---|-----------|--------|
| 1 | `$TNS_ADMIN` | env; the canonical Oracle Net override |
| 2 | `$ORACLE_HOME/network/admin` | env; the classic client/server layout |
| 3 | `~/.config/oraclemcp/network` | the wrapper default (`ORACLE_NET_HOME`, `robot_docs.rs:26`) |
| 4 | `~` (home directory) | a common ad-hoc location |
| 5 | `/etc` | a common system-wide location (Unix) |
| 6 | Common Instant Client dirs | platform-guarded (see below) |
| 7 | Current working directory | last resort; where the operator ran the command |

**Rules**

- **Canonicalize + de-duplicate.** Each candidate is canonicalized
  (`std::fs::canonicalize`); a symlinked or repeated directory is scanned once.
  A candidate that does not canonicalize (missing) is still reported, keyed by
  its *displayed* (non-canonical) path so it appears in the report exactly once.
- **Degrade gracefully.** A missing directory is reported with `exists = false`;
  a permission error is reported `skipped` **with a note** — never a hard
  failure. Discovery of one bad candidate never aborts the scan.
- **Pure `std` only.** `std::env` + `std::fs`, no driver calls, so the resolver
  is trivially unit-testable and cross-platform. Platform-specific defaults are
  guarded behind `cfg`.
- **Instant Client defaults (candidate 6)** are best-effort, platform-guarded
  hints and never a hard dependency:
  - Unix: `/usr/lib/oracle/*/client64/lib/network/admin`,
    `/opt/oracle/instantclient*/network/admin`, `/usr/local/oracle/network/admin`.
  - macOS: `~/Downloads/instantclient*/network/admin`, `/opt/oracle/instantclient*/network/admin`.
  - Windows: `%ORACLE_HOME%\network\admin` (already covered by #2) and
    `C:\oracle\instantclient*\network\admin`.
- **No `HOME` / no `ORACLE_HOME`** must never panic: an unset variable simply
  drops that candidate.

The report is an ordered, de-duplicated list of `(display_path, canonical_path?,
status, note?)`, where `status ∈ {exists, missing, skipped}`. The first `exists`
directory that actually yields net-services is the authoritative source; the
rest stay in the report for operator legibility.

---

## B. Net-service → profile mapping rules

Each discovered net-service (a `tnsnames.ora` alias, or an EZConnect string)
maps to at most one [`ConnectionProfile`]
(`crates/oraclemcp-config/src/profile.rs:457`–`profile.rs:550`). The synthesis
is deliberately conservative:

- **`name`** — the alias, lower-cased and sanitized to `[a-z0-9_]` (Oracle Net
  upper-cases aliases; profile names are stable lower-snake identifiers). On a
  collision the synth appends a numeric suffix. Never empty.
- **`connect_string`** — the alias itself when the host has a resolvable
  `tnsnames.ora` on `TNS_ADMIN` (so the profile stays a thin reference), or a
  normalized EZConnect (`host:port/service`) synthesized from the descriptor
  hints when no shared `tnsnames.ora` will be present at runtime. The
  parse-adapter hints (host/port/service/protocol) drive this choice; the raw
  descriptor is used only for the human report.
- **`credential_ref`** — always a **placeholder** `env:` secret-ref
  (`env:ORACLE_<NAME>_PASSWORD` by convention), never a literal. A literal
  credential is never synthesized or written.
- **`username`** — set **only** when a least-privilege convention is known for
  the target; otherwise left commented for the operator to fill in.
- **`max_level` / `default_level`** — both set **explicitly** to `READ_ONLY`, so
  the safety ceiling is legible in the written file and never relies on a
  struct default.
- **`protected`** — left unset (commented) by default; discovery never marks a
  profile `protected` on the operator's behalf (that is an operator decision
  that also pins the ceiling immutable).
- **`mcp_exposed`** — left unset (commented); the struct default is *exposed*
  (opt-out), and discovery does not silently hide or expose a profile — the
  commented one-liner tells the operator how to opt a target out.

The full disposition of every field is in §C.

---

## C. Annotated writer contract (every field fixed)

The writer renders a **bootable minimum** (the keys required for a valid,
safe profile) plus a **self-documenting commented menu** (every remaining
optional key present but commented, each with a one-line help string using its
**exact serde name**, so uncommenting yields a valid key).

**Hard constraint — `deny_unknown_fields`.** Both `OracleMcpConfig`
(`crates/oraclemcp-config/src/lib.rs:83`) and `ConnectionProfile`
(`profile.rs:457`) are `#[serde(deny_unknown_fields)]`. Therefore **every
uncommented key the writer emits MUST be a real serde field**, and **no unknown
key may ever appear** — commented or not, a typo'd key becomes a load error the
moment the operator uncomments it. The output MUST round-trip through
`OracleMcpConfig::from_toml_str` (config-ops re-parses it at
`crates/oraclemcp-core/src/config_ops.rs:280`).

Help strings are reconciled **in meaning** with `oraclemcp.example.toml` (the
worked example may *set* some of these for illustration; the discovery writer
*comments* them — reconciliation is on the help wording, not on set/unset
disposition).

### C.1 Top-level `OracleMcpConfig` fields (6 serde fields)

| serde field | disposition | one-line help |
|-------------|-------------|---------------|
| `schema_version` | **SET** | `= 2`. Config schema version this build understands; a higher value is rejected. |
| `default_profile` | **SET** (when unambiguous) | Profile used when the launcher passes no `serve --profile <name>`; set to the sole/obvious synthesized profile. |
| `monitor_profile` | **COMMENTED** | Optional least-privilege profile for fleet-wide DB observability (`v$session`, evidence); unset degrades to self-lane/local telemetry. |
| `http` | **POINTER** | Native Streamable HTTP transport is off by default (stdio-only); see `oraclemcp.example.toml` `[http]` for the full surface. |
| `audit` | **POINTER** | Out-of-band hash-chained audit log; see `oraclemcp.example.toml` `[audit]`. **Safety note:** `[audit].key_ref` MUST be configured before any profile raises `max_level` above `READ_ONLY`, or the server fails closed at startup. |
| `profiles` | **STRUCTURAL** | The `[[profiles]]` array; the writer renders one profile block (per §C.2) for each synthesized net-service. Not a scalar key. |

The `[http]` and `[audit]` surfaces are **not** reproduced field-by-field — that
would duplicate `oraclemcp.example.toml`, which the docs bead forbids. The
writer emits a short commented pointer to the example plus the one `[audit]`
safety note above.

### C.2 Per-profile `ConnectionProfile` fields (29 serde fields)

Disposition legend: **SET** = written uncommented with a value; **SET?** = set
only when known, else commented; **COMMENTED** = present but commented with a
one-line help string using the exact serde name.

| serde field | disposition | one-line help |
|-------------|-------------|---------------|
| `name` | **SET** | Stable identifier the agent connects by; unique, `[a-z0-9_]`. |
| `description` | **SET** | Friendly description shown in `list_profiles`; seeded from the net-service alias. |
| `connect_string` | **SET** | Oracle Net connect identifier: the `tnsnames.ora` alias, or a normalized EZConnect (`host:port/service`). |
| `credential_ref` | **SET** | Placeholder secret-ref for the DB password (`env:ORACLE_<NAME>_PASSWORD`); use `env:`/`file:`/`keyring:` — never a literal. |
| `max_level` | **SET** | `= "READ_ONLY"`. Per-target operating-level ceiling; the immutable cap escalation can never exceed. |
| `default_level` | **SET** | `= "READ_ONLY"`. Level a fresh session starts at; must not exceed `max_level`. |
| `username` | **SET?** | Oracle username; set only when a least-privilege convention is known, else commented (none for wallet / OS-auth / OCI-IAM). |
| `login_script` | **COMMENTED** | Path to an allowlisted `ALTER SESSION …` login script run on lease acquire. |
| `login_statements` | **COMMENTED** | Inline allowlist-validated `ALTER SESSION SET …` statements run on lease acquire. |
| `trusted_session_statements` | **COMMENTED** | Trusted local session setup, authored by the profile owner, never accepted from agent tool calls. |
| `call_timeout_seconds` | **COMMENTED** | Per-round-trip Oracle call timeout, in seconds (default 30 when omitted). |
| `max_query_cost` | **COMMENTED** | Per-query cooperative cost ceiling for `oracle_query`; per-call overrides may only lower it. |
| `connect_timeout_seconds` | **COMMENTED** | Oracle Net transport connect timeout, in seconds (default: the thin driver's 20s). |
| `inactivity_timeout_seconds` | **COMMENTED** | Per-read inactivity deadline on an established session, in seconds (unset = unbounded reads). |
| `keepalive_minutes` | **COMMENTED** | Oracle `EXPIRE_TIME` dead-connection-detection probe interval, in minutes. |
| `sdu` | **COMMENTED** | Session Data Unit request size for the thin driver (512..=65535 bytes; negotiated when unset). |
| `protected` | **COMMENTED** | Production profile: pins the ceiling immutable; requires `max_level = "READ_ONLY"` and rejects `literal:` secret refs. |
| `require_signed_tools` | **COMMENTED** | Require HMAC signatures for operator-defined custom tools on this profile (implied by `protected`). |
| `read_only_standby` | **COMMENTED** | Mark target as a read-only Active Data Guard standby: forces `READ_ONLY` regardless of `max_level`. |
| `mcp_exposed` | **COMMENTED** | Per-profile MCP exposure; default is exposed (opt-out), set `false` to hide this profile from the agent surface. |
| `dashboard_ddl_workbench` | **COMMENTED** | Browser dashboard DDL/Admin apply opt-in; never raises `max_level` or bypasses preview/confirm/rollback/audit. |
| `session_identity` | **COMMENTED** | `[profiles.session_identity]` end-to-end Oracle session identity (program/machine/module/action/client_identifier/…). |
| `pool` | **COMMENTED** | `[profiles.pool]` local client-side connection pool for stateless catalog/metadata reads. |
| `oci` | **COMMENTED** | `[profiles.oci]` OCI / Autonomous DB fields (wallet_location, wallet_password_ref, DN matching, SNI, IAM token). |
| `drcp` | **COMMENTED** | `[profiles.drcp]` Database Resident Connection Pooling server routing (`pooled`, `connection_class`, `purity`). |
| `proxy_auth` | **COMMENTED** | `[profiles.proxy_auth]` thin proxy authentication (`proxy_user`, `target_schema`). |
| `app_context` | **COMMENTED** | `[[profiles.app_context]]` driver-level application-context triples applied at logon (redacted from diagnostics). |
| `masking` | **COMMENTED** | `[profiles.masking]` result egress masking policy; `mask_unknown_default` must stay true unless complete catalog tagging is configured. |
| `base` | **COMMENTED** | Name of a profile to inherit unset fields from (shallow-merge). |

---

## D. Consent matrix

Discovery **never scans without consent** and **never prompts a non-interactive
caller**. The exit taxonomy is the shared CLI one
(`crates/oraclemcp/src/robot_docs.rs:52`, `cli_exit_codes_json`): a refusal to
proceed is a **usage/safety block → exit code 2**
(`usage_config_or_safety_block`).

| Caller | Consent path | Behavior |
|--------|-------------|----------|
| **Human TTY** | interactive prompt | Discovery lists candidate dirs + net-services found, then prompts before writing. Declining exits `0` (no-op, nothing written). |
| **Agent (TTY or not)** | explicit `--discover` / `--yes` flag | With the flag, proceeds non-interactively; without it on a non-TTY, refuses (exit `2`). |
| **CI / non-TTY** | explicit flag required | No prompt is ever shown; without `--discover`/`--yes` the command refuses to scan/write and exits `2`. |

- The doctor contract already states this posture: on a non-TTY
  *"no interactive prompts are used; destructive host changes require flags
  instead"* (`robot_docs.rs:132`). Discovery honors it.
- **Exact non-TTY refusal (stderr, exit 2):**
  `refusing to scan for tnsnames.ora without consent: re-run on an interactive terminal, or pass --discover to consent explicitly (non-interactive).`
- **Exact success line (stderr, exit 0):**
  `discovered <N> net-service(s) across <M> candidate director(y|ies); wrote <K> read-only profile(s) to <path>.`
- **Exact human prompt (TTY):**
  `Write <K> read-only profile(s) to <path>? [y/N]:` — any answer other than
  `y`/`yes` (case-insensitive) is a decline (exit 0, nothing written).

---

## E. Idempotency and backup contract

Discovery is **add-only and never clobbers**.

- **Existing-config detection.** If the target already exists, its current bytes
  are parsed through `OracleMcpConfig::from_toml_str`; the pre-existing profiles
  are preserved verbatim.
- **Add-only merge.** Only net-services whose synthesized `name` is **not**
  already a profile are appended. A name that already exists is reported as
  *skipped (already configured)* and never overwritten or edited.
- **Verify-before-mutate + timestamped backup.** Writes go through config-ops:
  `backup_path_for` (`config_ops.rs:655`) makes a timestamped
  `<file>.backup.<ts>` copy, and the apply path re-hashes the current bytes and
  refuses on drift (`ConfigOpsError::CurrentChanged`, `config_ops.rs:311` and
  `config_ops.rs:423`) so a concurrent edit is never silently lost.
- **Secrets never on disk.** The writer emits only placeholder secret-refs; no
  discovered or resolved secret is ever written. The parse adapter likewise
  never surfaces a raw password (redacted `Debug`), so a descriptor that happens
  to embed one cannot leak into the report or the written file.

---

## F. Canonical test fixture tree

There is **one** shared synthetic fixture tree so the discovery test beads never
diverge. It is **created by the parse-adapter bead (`.3`)** under a committed
`tests/fixtures/tns/` path co-located with the adapter tests; the edge-case
(`.16`), unit (`.17`), and e2e (`.18`) beads **reuse** it, adding the extra
variants (malformed, permission-denied) as siblings in the same tree. No bead
creates a divergent copy.

### F.1 Tree

```
tests/fixtures/tns/
  tnsnames.ora            # primary (bead .3): multiple aliases, one TCPS+wallet,
                          #   one EZConnect-style, one duplicate alias, one IFILE
  tnsnames_include.ora    # IFILE target of the primary (bead .3)
  cycle/
    tnsnames.ora          # (bead .3) IFILEs cycle_b.ora
    cycle_b.ora           # (bead .3) IFILEs back to cycle/tnsnames.ora → cycle
  malformed/
    tnsnames.ora          # (bead .16) partly-broken; parser recovers what it can
  noperm/                 # (bead .16) directory chmod 000 to simulate permission-denied
```

### F.2 Primary `tnsnames.ora` — enumerated expected values

The primary file defines four effective aliases (Oracle Net upper-cases them;
last-definition-wins collapses the duplicate). Reading
`TnsnamesReader::read("tests/fixtures/tns")` yields, in **first-seen order**:

| # | `service_name` (upper) | protocol | host | port | service | wallet_location |
|---|------------------------|----------|------|------|---------|-----------------|
| 1 | `PRIMARY_TCPS` | `TCPS` | `tcps.example.com` | `2484` | `PRIMARY.example.com` | `/etc/oracle/wallet/primary` |
| 2 | `EZ_PLAIN` | *(none)* | `ez.example.com` | `1521` | `EZSERVICE` | *(none)* |
| 3 | `DUP_ALIAS` | `TCP` | `new.example.com` | `1522` | `NEW.example.com` | *(none)* |
| 4 | `INCLUDED_ONE` | `TCP` | `inc.example.com` | `1521` | `INCLUDED.example.com` | *(none)* |

- `service_names().len() == 4`.
- `DUP_ALIAS` is defined **twice** in the primary file (first `old.example.com` /
  `OLD.example.com`, then, after the `IFILE` line, `new.example.com` /
  `NEW.example.com`); **last definition wins**, and the first-seen position
  (slot 3) is preserved.
- `INCLUDED_ONE` comes from `tnsnames_include.ora` via the primary's `IFILE`
  line, proving IFILE follow.
- **Hint rules for these fixed values:** `protocol` is populated only when
  explicit — a `(PROTOCOL=…)` inside a descriptor, or a `scheme://` on an
  easy-connect string. Plain EZConnect (`EZ_PLAIN`) has no scheme, so its
  `protocol` hint is `None`. `wallet_location` is sourced from a descriptor's
  `MY_WALLET_DIRECTORY` / `WALLET_LOCATION`, or an easy-connect
  `?wallet_location=…`.

### F.3 Error / edge fixtures

- `cycle/`: reading `TnsnamesReader::read("tests/fixtures/tns/cycle")` returns a
  **structured error** (`ProtocolError::InvalidConnectDescriptor`, an IFILE
  cycle), never a panic. The adapter surfaces it as a typed error.
- A **missing** `tnsnames.ora` in a directory yields an **empty result plus a
  note** (not an error) — the adapter pre-checks existence.
- `malformed/` (bead `.16`) and `noperm/` (bead `.16`) exercise partial-parse
  recovery and permission-denied skip-with-note, respectively.

---

## Review checklist (embedded)

- [x] Every `ConnectionProfile` serde field (`profile.rs:457`–`550`) appears in
      §C.2 with a disposition and a one-line help string using its exact serde
      name (25 fields).
- [x] Every top-level `OracleMcpConfig` serde field (`lib.rs:83`) appears in §C.1
      with a disposition and one-line help (6 fields).
- [x] The `deny_unknown_fields` constraint is stated (§C) — every uncommented
      key is a real serde field; no unknown key ever appears.
- [x] The candidate search dirs and their precedence are enumerated (§A), with
      canonical-path de-dup and permission-denied = skip-with-note.
- [x] The consent matrix (§D) states human-TTY / agent / CI / non-TTY behavior,
      the exact non-TTY refusal and success wording, and exit code 2.
- [x] The merge / ask / backup rules are stated (§E), citing `backup_path_for`
      and `CurrentChanged`.
- [x] The canonical fixture tree (§F) is defined with exact expected
      `service_name`s and hint extractions.
- [x] Nothing here weakens the `AGENTS.md` safety invariant: every synthesized
      profile is `READ_ONLY`-capped (both levels set explicitly), credentials are
      placeholder-only, and the classifier/ladder are untouched.
