#!/usr/bin/env bash
# D6.4 — mutation-testing gate on the safety-critical crates.
# (bead oraclemcp-release-073-iec3.4.4 / plan §D6.4.)
#
# Runs `cargo-mutants` over the two safety-core crates — the fail-closed
# statement classifier / purity prover (`oraclemcp-guard`) and the append-only
# audit hash-chain (`oraclemcp-audit`) — computes the per-crate kill-rate, and
# enforces a floor (default 90%). This is THE proof the safety tests are not
# placebo: a surviving mutant is a classification (or a chain check) the tests
# do not pin.
#
# Deliberately slow (the classifier is ~134 KB, ~400 mutants). Runs NIGHTLY and
# in the D3.2 local pre-tag gate, NOT on every PR. The cheap, fast tag gate is
# `check-report` below: it parses the committed report the nightly run refreshes.
#
# Subcommands:
#   run           run cargo-mutants on the safety crates, print per-crate
#                 kill-rate, write a machine summary, and (unless --advisory)
#                 exit non-zero if any crate is below the threshold.
#   check-report  cheap: parse the committed report (docs/quality/mutation-safety.md)
#                 and assert the recorded per-crate kill-rate meets the floor.
#                 Called by scripts/release_preflight.sh so the tag is gated by
#                 the committed proof without re-running the slow mutation pass.
#
# ─────────────────────────────────────────────────────────────────────────────
# CORRECTNESS TRAP (do not "optimize" away): cargo-mutants MUST isolate a
# separate target directory PER parallel job. Do NOT export a shared
# CARGO_TARGET_DIR when running under `-j > 1` — a shared target races
# incremental-compilation artifacts across concurrent mutant builds and yields
# FALSE survivors (mutants get tested against a stale/unmutated test binary).
# This script therefore UNSETS CARGO_TARGET_DIR and passes --copy-target=false
# so every build dir owns its own target. (`./target` in this repo is huge, so
# copy-target=true is also not an option.)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CRATES=(oraclemcp-guard oraclemcp-audit)
THRESHOLD="${MUTATION_THRESHOLD:-90}"
# Default to one mutant build at a time. The cgroup cap protects the host, but
# the 2026-07-08 guard baseline showed `-j4` can OOM-kill the cargo-mutants
# controller before it writes a complete outcome set. Operators can still opt in
# to higher concurrency with MUTATION_JOBS/--jobs on larger runners.
JOBS="${MUTATION_JOBS:-1}"
TIMEOUT="${MUTATION_TIMEOUT:-120}"
# Hard cgroup memory cap on the whole mutation pass. A pathological mutant (e.g. a
# mutated loop/size bound inducing an unbounded allocation) MUST NOT OOM the host:
# on 2026-07-08 an uncapped guard test binary hit ~40GB RSS and triggered a GLOBAL
# OOM that killed unrelated processes. This scope OOM-kills the runaway INSIDE the
# cap instead (cargo-mutants grades a killed mutant as caught). Override w/ MUTATION_MEMMAX.
MEMMAX="${MUTATION_MEMMAX:-24G}"
OUTPUT_BASE="${MUTATION_OUTPUT:-$ROOT/target/mutants}"
REPORT="${MUTATION_REPORT:-$ROOT/docs/quality/mutation-safety.md}"
ADVISORY=0

# Memory-cap wrapper (transient user scope). Falls back to no cap with a loud
# warning if the user systemd instance is unavailable (then -j + timeout only).
MEMCAP=()
if systemd-run --user --scope -q -p MemoryMax=64M -p MemorySwapMax=0 -- true 2>/dev/null; then
  MEMCAP=(systemd-run --user --scope -q -p "MemoryMax=$MEMMAX" -p MemorySwapMax=0 --)
else
  echo "mutation-gate: WARNING — no systemd --user cgroup cap available; running UNCAPPED (-j=$JOBS, timeout only)" >&2
fi

die() { echo "mutation-gate: $*" >&2; exit 1; }

# Kill-rate policy: killed = caught + timeout (a timeout means the mutant was
# detected — it broke or hung the tests). unviable (won't compile) is excluded
# from the denominator. rate = 100 * killed / (caught + missed + timeout).
kill_rate() { # <caught> <missed> <timeout>
  awk -v c="$1" -v m="$2" -v t="$3" 'BEGIN{
    v=c+m+t; if(v==0){print "0.0"; exit} printf "%.1f", 100*(c+t)/v
  }'
}

cmd_run() {
  command -v cargo-mutants >/dev/null 2>&1 || die "cargo-mutants not installed (cargo install cargo-mutants)"
  mkdir -p "$OUTPUT_BASE"
  local overall_ok=1
  local summary="$OUTPUT_BASE/summary.txt"
  : >"$summary"
  for crate in "${CRATES[@]}"; do
    local out="$OUTPUT_BASE/$crate"
    echo "mutation-gate: running cargo-mutants on $crate (j=$JOBS timeout=${TIMEOUT}s) ..." >&2
    # NB: env -u CARGO_TARGET_DIR — see the correctness trap above.
    "${MEMCAP[@]}" env -u CARGO_TARGET_DIR cargo mutants -p "$crate" \
      -j "$JOBS" --copy-target=false --timeout "$TIMEOUT" \
      --output "$out" >"$out.log" 2>&1 || true   # non-zero exit == survivors; we grade below
    local oc="$out/mutants.out/outcomes.json"
    [ -f "$oc" ] || die "$crate: no outcomes.json produced (see $out.log)"
    local caught missed timeout unviable
    caught="$(jq -r '.caught'  "$oc")"
    missed="$(jq -r '.missed'  "$oc")"
    timeout="$(jq -r '.timeout' "$oc")"
    unviable="$(jq -r '.unviable' "$oc")"
    local rate; rate="$(kill_rate "$caught" "$missed" "$timeout")"
    printf '%s kill=%s%% caught=%s missed=%s timeout=%s unviable=%s\n' \
      "$crate" "$rate" "$caught" "$missed" "$timeout" "$unviable" | tee -a "$summary"
    if awk -v r="$rate" -v t="$THRESHOLD" 'BEGIN{exit !(r+0 < t+0)}'; then
      echo "mutation-gate: $crate kill-rate ${rate}% is BELOW the ${THRESHOLD}% floor" >&2
      overall_ok=0
    fi
  done
  echo "mutation-gate: summary written to $summary" >&2
  if [ "$overall_ok" -ne 1 ] && [ "$ADVISORY" -ne 1 ]; then
    die "one or more safety crates are below the ${THRESHOLD}% kill-rate floor"
  fi
  [ "$overall_ok" -eq 1 ] || echo "mutation-gate: ADVISORY mode — below floor but not failing" >&2
}

# Parse the machine-readable marker the report carries, e.g.:
#   <!-- MUTATION-GATE guard=93.5 audit=91.2 threshold=90 status=enforcing -->
cmd_check_report() {
  [ -f "$REPORT" ] || die "committed mutation report missing: $REPORT"
  local marker
  marker="$(grep -oE '<!-- MUTATION-GATE [^>]*-->' "$REPORT" | tail -1)" \
    || die "report $REPORT has no MUTATION-GATE marker"
  local guard audit thresh status
  guard="$(sed -E 's/.*guard=([0-9.]+).*/\1/'  <<<"$marker")"
  audit="$(sed -E 's/.*audit=([0-9.]+).*/\1/'  <<<"$marker")"
  thresh="$(sed -E 's/.*threshold=([0-9.]+).*/\1/' <<<"$marker")"
  status="$(sed -E 's/.*status=([a-z]+).*/\1/'  <<<"$marker")"
  echo "mutation-gate: report marker guard=${guard}% audit=${audit}% threshold=${thresh}% status=${status}"
  # 'advisory' status is allowed to gate softly while the suite is still being
  # brought up to the floor; 'enforcing' hard-gates the tag.
  if [ "$status" = "enforcing" ]; then
    for pair in "guard:$guard" "audit:$audit"; do
      local name="${pair%%:*}" val="${pair##*:}"
      awk -v r="$val" -v t="$thresh" 'BEGIN{exit !(r+0 < t+0)}' \
        && die "$name kill-rate ${val}% is below the enforcing floor ${thresh}%"
    done
    echo "mutation-gate: OK — both safety crates meet the enforcing ${thresh}% floor"
  else
    echo "mutation-gate: report is ADVISORY (status=$status); tag not hard-gated yet"
  fi
}

sub="${1:-run}"; shift || true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --advisory) ADVISORY=1 ;;
    --threshold) THRESHOLD="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --output) OUTPUT_BASE="$2"; shift ;;
    --report) REPORT="$2"; shift ;;
    --crate) CRATES=("$2"); shift ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

case "$sub" in
  run) cmd_run ;;
  check-report) cmd_check_report ;;
  *) die "unknown subcommand '$sub' (expected: run | check-report)" ;;
esac
