#!/usr/bin/env bash
# swarm_orchestrator_tick.sh — one cheap observation pass for the swarm orchestrator.
#
# Prints a compact, machine-skimmable status block so the orchestrator can decide
# interventions without burning context on raw tool output. Read-only except for
# the disk janitor, which only sweeps dead agents' scratch target dirs.
#
# Usage: scripts/swarm_orchestrator_tick.sh [--session NAME] [--stall-hours N] [--disk-pct N]
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="oraclemcp--swarm"
STALL_HOURS=2
DISK_PCT=85
TMUX_BIN="${TMUX_BIN:-/usr/bin/tmux}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --session) SESSION="$2"; shift 2 ;;
    --stall-hours) STALL_HOURS="$2"; shift 2 ;;
    --disk-pct) DISK_PCT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

cd "$REPO_ROOT" || exit 1
echo "===== TICK $(date -u '+%Y-%m-%dT%H:%M:%SZ') session=$SESSION ====="

# --- 1. Pane liveness -------------------------------------------------------
# pane_current_command is the only signal that catches an agent that silently
# exited back to zsh; the robot feed cannot see that. Note a moving spinner is
# NOT evidence of work — cross-check with commits and `ntm --robot-is-working`.
echo "--- PANES ---"
"$TMUX_BIN" list-panes -t "$SESSION" -F '#{pane_index}|#{pane_current_command}|#{pane_title}' 2>/dev/null |
while IFS='|' read -r idx cmd title; do
  [[ "$idx" == "1" ]] && continue   # user pane
  tail_txt="$("$TMUX_BIN" capture-pane -p -t "${SESSION}.${idx}" -S -6 2>/dev/null | tr -d '\r' | grep -v '^[[:space:]]*$' | tail -2 | tr '\n' ' ' | cut -c1-110)"
  flag=""
  [[ "$cmd" == "zsh" || "$cmd" == "bash" ]] && flag="  <<< DEAD-AGENT(shell)"
  printf '  p%-2s %-8s %-26s %s%s\n' "$idx" "$cmd" "${title:0:26}" "$tail_txt" "$flag"
done

# --- 2. Real output: commits ------------------------------------------------
echo "--- COMMITS (60m) ---"
n_commits=$(git log --since='60 minutes ago' --oneline 2>/dev/null | wc -l)
git log --since='60 minutes ago' --format='  %h %an %s' 2>/dev/null | head -12
echo "  total=$n_commits"

# --- 3. Bead graph ----------------------------------------------------------
echo "--- BEADS ---"
n_ready=$(br ready --json 2>/dev/null | jq '(if type=="array" then . else .issues end)|length' 2>/dev/null || echo '?')
n_prog=$(br list --status in_progress --json 2>/dev/null | jq '.issues|length' 2>/dev/null || echo '?')
n_open=$(br list --status open --json 2>/dev/null | jq '.issues|length' 2>/dev/null || echo '?')
echo "  ready=$n_ready in_progress=$n_prog open(page)=$n_open"
br stats 2>/dev/null | grep -E 'Open:|Blocked:|Ready to Work:|Deferred:' | sed 's/^/  /'

# --- 4. Stalled claims ------------------------------------------------------
# A bead in_progress with no update for hours is usually an abandoned claim.
# AGENTS.md forbids `br update --status open`; release-claim is the only path.
echo "--- STALLED CLAIMS (>${STALL_HOURS}h idle) ---"
cutoff=$(date -u -d "-${STALL_HOURS} hours" '+%s' 2>/dev/null)
br list --status in_progress --json 2>/dev/null |
  jq -r --argjson cutoff "${cutoff:-0}" '
    .issues[]
    | select((.updated_at // "1970-01-01T00:00:00Z") | sub("\\.[0-9]+";"") | fromdateiso8601 < $cutoff)
    | "  STALLED \(.id)  last_update=\(.updated_at[0:19])  \(.title[0:60])"
  ' 2>/dev/null || echo "  (none / parse skipped)"
echo "  release with: scripts/bead_tracker_guard.sh release-claim <id>"
# The cutoff measures TRACKER silence, not abandonment. A bead whose agent is
# running a long induction (E5's failure_recovery_e2e rig idles the tracker for
# hours while genuinely working) trips it every tick. Releasing then yanks the
# bead out from under a live agent. Cross-check before acting.
if [[ -n "${cutoff:-}" ]]; then
  live_rig="$(pgrep -af 'scripts/rig/|target/e2e/' 2>/dev/null | head -3 | cut -c1-88)"
  [[ -n "$live_rig" ]] && {
    echo "  NOTE: live rig/e2e processes exist — a STALLED line above may be a working agent:"
    echo "$live_rig" | sed 's/^/    /'
  }
  echo "  VERIFY FIRST: pane tail shows '• Working' + pgrep shows a live child => do NOT release."
fi

# --- 5. Disk + build lease --------------------------------------------------
echo "--- RESOURCES ---"
used_pct=$(df --output=pcent / | tail -1 | tr -dc '0-9')
avail=$(df -h --output=avail / | tail -1 | tr -d ' ')
tgt=$(du -sh "$REPO_ROOT/target" 2>/dev/null | cut -f1)
echo "  disk_used=${used_pct}% avail=${avail} target/=${tgt}"
# target/ is not the only pool: the rig's Tier-B container lane grows Docker
# images/containers, which the target janitor cannot see and must never prune
# blindly (a live rig container would be destroyed).
if command -v docker >/dev/null 2>&1; then
  docker system df 2>/dev/null |
    awk 'NR>1 {printf "  docker %-14s total=%-5s active=%-5s size=%-9s reclaimable=%s\n", $1, $2, $3, $4, $5}' |
    head -4
fi
bash "$REPO_ROOT/scripts/build_lease.sh" --status 2>/dev/null | sed 's/^/  lease: /' | head -3

# Per-run CARGO_TARGET_DIRs are sanctioned by AGENTS.md, so the answer to their
# growth is continuous reaping, not a ban. Sweep every tick with a wide idle
# gate; tighten only under real disk pressure.
if [[ "${used_pct:-0}" -ge "$DISK_PCT" ]]; then
  echo "  disk >= ${DISK_PCT}% — aggressive sweep (idle gate 30m)"
  bash "$REPO_ROOT/scripts/swarm_target_janitor.sh" --apply --idle-min 30 2>/dev/null | tail -2 | sed 's/^/  /'
else
  bash "$REPO_ROOT/scripts/swarm_target_janitor.sh" --apply --idle-min 45 2>/dev/null | tail -2 | sed 's/^/  /'
fi

echo "===== END TICK ====="
