#!/usr/bin/env bash
# Tier-C release runner (bead .9.2). Runs the W4 suite on each rig lane in
# sequence against the checked-out SHA and writes
#   target/e2e/tier_c/<sha>/summary.json
#   {sha, tree_dirty, lanes: [{lane, version, cases_total, cases_failed, verdict}]}
# for the release proof (T5.5). Lanes run one at a time (memory discipline);
# each is brought up by scripts/rig/oracle_l1.sh first. The Always-Free ADB
# lane belongs to the W9 harness (T9.1) and is recorded as delegated.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail() {
  echo "tier-c: $*" >&2
  exit 1
}

usage() {
  echo "Usage: scripts/rig/tier_c.sh --sha <sha> [--lane xe18|xe21|free23]... [--dry-run]"
}

sha=''
dry_run=0
lanes=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --sha)
      [ "$#" -ge 2 ] || fail "--sha requires a value"
      sha="$2"
      shift 2
      ;;
    --lane)
      [ "$#" -ge 2 ] || fail "--lane requires a value"
      case "$2" in xe18 | xe21 | free23) lanes+=("$2") ;; *) fail "unknown lane: $2" ;; esac
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[ -n "$sha" ] || { usage >&2; exit 2; }
[ "${#lanes[@]}" -gt 0 ] || lanes=(xe18 xe21 free23)

# Results are only meaningful for the tree they ran on: --sha must name HEAD.
head="$(git rev-parse HEAD)"
resolved="$(git rev-parse --verify --quiet "$sha^{commit}" || true)"
[ "$resolved" = "$head" ] || fail "--sha $sha is not the checked-out HEAD ($head); check out the release candidate first"
tree_dirty=false
[ -z "$(git status --porcelain --untracked-files=no)" ] || tree_dirty=true

out_dir="$ROOT/target/e2e/tier_c/$head"
mkdir -p "$out_dir"
rows="$out_dir/lanes.jsonl"
: >"$rows"

for lane in "${lanes[@]}"; do
  echo "tier-c: lane=$lane up"
  if [ "$dry_run" = 1 ]; then
    printf '{"lane":"%s","version":null,"cases_total":0,"cases_failed":0,"verdict":"dry_run"}\n' "$lane" >>"$rows"
    continue
  fi
  up_ok=1
  bash "$ROOT/scripts/rig/oracle_l1.sh" up --lane "$lane" --log >"$out_dir/$lane.up.log" 2>&1 || up_ok=0
  w4_ok=0
  if [ "$up_ok" = 1 ]; then
    echo "tier-c: lane=$lane W4"
    w4_ok=1
    ORACLEMCP_LIVE_XE=1 bash "$ROOT/scripts/e2e/w4.sh" --lane "$lane" --log \
      >"$out_dir/$lane.w4.log" 2>&1 || w4_ok=0
  fi
  python3 - "$ROOT/target/e2e/w4/$lane/results.json" "$lane" "$head" "$up_ok" "$w4_ok" >>"$rows" <<'PY'
import json, sys
path, lane, head, up_ok, w4_ok = sys.argv[1:]
row = {"lane": lane, "version": None, "cases_total": 0, "cases_failed": 0, "verdict": "fail"}
if up_ok != "1":
    row["reason"] = "lane_up_failed"
else:
    try:
        results = json.load(open(path))
    except (OSError, ValueError):
        results = None
    if results is None or results.get("checkout_sha") != head:
        row["reason"] = "no_w4_results_for_this_sha"
    else:
        cases = results.get("cases", [])
        row["cases_total"] = len(cases)
        row["cases_failed"] = sum(1 for case in cases if case.get("verdict") != "pass")
        versions = [c for c in results.get("capabilities", []) if c.startswith("version:")]
        row["version"] = versions[0].split(":", 1)[1] if versions else None
        passed = w4_ok == "1" and row["cases_total"] > 0 and row["cases_failed"] == 0
        row["verdict"] = "pass" if passed else "fail"
        if not passed and w4_ok != "1":
            row["reason"] = "w4_run_failed"
print(json.dumps(row, sort_keys=True))
PY
done

python3 - "$rows" "$out_dir/summary.json" "$head" "$tree_dirty" <<'PY'
import json, sys
rows_path, summary_path, head, dirty = sys.argv[1:]
lanes = [json.loads(line) for line in open(rows_path) if line.strip()]
lanes.append({"lane": "adb", "verdict": "delegated", "reason": "Always-Free ADB runs in the W9 harness (T9.1)"})
summary = {"sha": head, "tree_dirty": dirty == "true", "lanes": lanes}
with open(summary_path, "w") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
print(json.dumps(summary, sort_keys=True))
PY
echo "tier-c: wrote $out_dir/summary.json"
