# Backup & Restore

oraclemcp is **files-first**: all durable server state lives in a single state
directory as atomically-written files (no database). Backing it up is therefore
an ordinary directory copy, and restoring is a directory replace plus an
integrity check. This document describes exactly what to back up, how, and what
is safe to lose.

## Where state lives

`FileStore::default_state_dir()` resolves the state root as:

1. `$XDG_STATE_HOME/oraclemcp/` if `XDG_STATE_HOME` is set, else
2. `$HOME/.local/state/oraclemcp/`.

(If neither `XDG_STATE_HOME` nor `HOME` is set, the server refuses to start
rather than guess — a fail-closed default.)

Under that root, state is organized into collections, each a directory of
atomically-written files (`write_atomic` = write-temp + fsync + rename, so a
concurrent copy never sees a torn file):

| Collection | Contents | Lose it? |
|---|---|---|
| `audit/` | `audit.jsonl` (append-only SHA-256 hash-chain) + `audit.jsonl.anchor` (keyed-MAC tamper-detection anchor) | **No** — tamper-evidence record |
| `change-proposals/`, `proposals/` | pending/applied Change Proposals (the PR-for-PL/SQL board) | **No** — change history |
| `snapshots/`, `source-snapshots/`, `source-history/` | pre-change DDL/source snapshots used for review + revert-drafts | **No** — revert basis |
| `client-credentials/`, `clients/` | per-client HTTP credential records | **No** — clients must re-enroll otherwise |
| `metrics/` | append-only metric history we write ourselves | Yes — regenerable; losing it loses history only, not correctness |
| `state/` | assorted small runtime state | Prefer keep |

## What is NOT in the state directory

- **Oracle / OCI secrets.** Connection secrets are never persisted by oraclemcp.
  The config holds *references* (`env:NAME`, `file:/path`, or a system keyring
  ref) resolved at use-time by `SecretResolver`; the secret value is never
  written to state, rendered, or logged. Back up the underlying secret material
  (keyring entries, referenced files, your secret manager) **out of band** — it
  is not part of an oraclemcp state backup by design.
- **Tokens.** IAM/OAuth tokens are ephemeral: fetched per-connection via the
  configured `TokenSource` and never persisted. There is no token state to back
  up or restore.
- **Streams.** Result streams are per-session and in-memory; nothing to back up.
- **The config file.** The config lives at its own path (see
  `docs/configuration.md`). Every config-ops write already takes an automatic
  backup (backup → atomic replace → strict revalidate → rollback-on-failure),
  but for a full backup, copy the config file alongside the state directory.

## Backing up

Cold (recommended — guaranteed consistent):

```bash
# 1. stop the oraclemcp service
# 2. copy the state root and the config file
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/oraclemcp"
tar czf oraclemcp-backup-$(date +%Y%m%d).tgz -C "$(dirname "$STATE")" oraclemcp
cp /path/to/oraclemcp.toml oraclemcp-config-backup.toml   # your config path
```

Hot (acceptable): because every file is written atomically and the audit log is
strictly append-only, a copy taken while the service runs is
self-consistent per file. A proposal being applied at the instant of the copy
may or may not be included, but no file is ever torn. Prefer cold backups when
you can stop the service.

Do **not** capture secret values into the backup archive — the state directory
contains none, and you should keep secret material in its own protected store.

## Restoring

```bash
# 1. stop the service
# 2. move the current state aside (do NOT delete until verified)
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/oraclemcp"
mv "$STATE" "$STATE.pre-restore" 2>/dev/null || true
# 3. extract the backup into place
tar xzf oraclemcp-backup-YYYYMMDD.tgz -C "$(dirname "$STATE")"
# 4. restore the config file, ensure the referenced secrets still resolve
# 5. start the service — it verifies the audit chain + anchor on load
```

On start, the audit subsystem verifies the hash-chain (`audit.jsonl`) against
its anchor (`audit.jsonl.anchor`): a chain that does not verify, or a
present-but-unreadable anchor, is treated as **tamper-suspect** and surfaced
(an anchor merely *behind* the chain head is an explainable, non-tamper state).
`doctor` reports the audit-chain status; treat any verification failure as a
restore that must be investigated, not overwritten.

## Migration & compatibility

State layout changes are additive and versioned; upgrades are doctor-assisted.
Keep the `.pre-restore` copy until a restored instance passes `doctor` and its
audit chain verifies.
