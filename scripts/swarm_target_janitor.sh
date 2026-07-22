#!/usr/bin/env bash
# swarm_target_janitor.sh — reclaim disk from dead agents' scratch CARGO_TARGET_DIRs.
#
# A multi-agent swarm that points CARGO_TARGET_DIR at a per-run subdirectory
# leaves one full build tree behind per agent per bead. The 2026-07 campaign
# accumulated 133 such trees in the checkout (338GB) and another 380GB under
# /var/tmp before anyone noticed. This sweeps the dead ones from both.
#
# It only ever removes directories that are ALL of:
#   * under <repo>/target/, or an oraclemcp-owned name under /var/tmp
#   * not a canonical cargo output dir (debug, release, doc, package, tmp, ...)
#   * idle for at least $IDLE_MIN minutes (guards against a live build)
#
# Usage:
#   scripts/swarm_target_janitor.sh            # report only (default)
#   scripts/swarm_target_janitor.sh --apply    # actually remove
#   scripts/swarm_target_janitor.sh --apply --idle-min 30
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$REPO_ROOT/target"
IDLE_MIN=45
APPLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --idle-min) IDLE_MIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

is_protected() {
  case "$1" in
    debug|release|doc|docs|package|tmp|CACHEDIR.TAG|.rustc_info.json|.fingerprint) return 0 ;;
    *) return 1 ;;
  esac
}

before_avail=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
swept=0
reclaimed_kb=0
skipped_live=0

sweep_entry() {
  local entry="$1" label="$2"
  [[ -d "$entry" ]] || return 0

  # Idle guard: a live build writes into its tree continuously, so an idle
  # tree is a finished one. This is what makes the sweep safe to automate.
  if [[ -n "$(find "$entry" -newermt "-${IDLE_MIN} minutes" -print -quit 2>/dev/null)" ]]; then
    echo "  SKIP (active <${IDLE_MIN}m)  $label"
    skipped_live=$((skipped_live + 1))
    return 0
  fi

  local size_kb size_h
  size_kb=$(du -sk "$entry" 2>/dev/null | cut -f1 || echo 0)
  size_h=$(du -sh "$entry" 2>/dev/null | cut -f1 || echo '?')

  if [[ "$APPLY" -eq 1 ]]; then
    rm -rf -- "$entry"
    echo "  REMOVED  ${size_h}	$label"
  else
    echo "  WOULD REMOVE  ${size_h}	$label"
  fi
  swept=$((swept + 1))
  reclaimed_kb=$((reclaimed_kb + size_kb))
}

shopt -s nullglob

if [[ -d "$TARGET_DIR" ]]; then
  for entry in "$TARGET_DIR"/*; do
    name="$(basename "$entry")"
    [[ -d "$entry" ]] || continue
    is_protected "$name" && continue
    sweep_entry "$entry" "$name"
  done
fi

# Agents also place per-run CARGO_TARGET_DIRs OUTSIDE the checkout. Match ONLY
# oraclemcp-owned names: /var/tmp is shared with the rest of the machine.
for entry in /var/tmp/oraclemcp-* /var/tmp/omcp-* /var/tmp/cargo-mutants-oraclemcp-*; do
  sweep_entry "$entry" "/var/tmp/$(basename "$entry")"
done

reclaimed_gb=$((reclaimed_kb / 1024 / 1024))
after_avail=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')

echo "---"
if [[ "$APPLY" -eq 1 ]]; then
  echo "janitor: removed $swept scratch target dir(s), ~${reclaimed_gb}GB; skipped $skipped_live active"
  echo "janitor: disk avail ${before_avail}G -> ${after_avail}G"
else
  echo "janitor: $swept scratch target dir(s) reclaimable, ~${reclaimed_gb}GB; skipped $skipped_live active (dry run — pass --apply)"
fi
