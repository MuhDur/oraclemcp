#!/usr/bin/env bash
# Tier-C release runner (bead .9.2). Runs the W4 suite on each rig lane in
# sequence against the checked-out SHA and writes
#   target/e2e/tier_c/<sha>/summary.json
#   {sha, tree_dirty, lanes: [{lane, version, cases_total, cases_failed, verdict}]}
# for the release proof (T5.5). Lanes run one at a time (memory discipline);
# each is brought up by scripts/rig/oracle_l1.sh first. The Always-Free ADB
# lane belongs to the W9 harness (T9.1) and is recorded as delegated.
#
# --check <summary.json> --sha <sha> is the fail-closed consumer used by
# scripts/local_release_gate.sh and the release rehearsal: it passes only a
# clean-tree summary for that exact SHA where XE 18, XE 21 and FREE 23ai each
# passed with at least one case and the client proofs passed. --selftest
# proves each way a summary can fall short is refused.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail() {
  echo "tier-c: $*" >&2
  exit 1
}

usage() {
  echo "Usage: scripts/rig/tier_c.sh --sha <sha> [--lane xe18|xe21|free23]... [--dry-run]"
  echo "       scripts/rig/tier_c.sh --check <summary.json> --sha <sha>"
  echo "       scripts/rig/tier_c.sh --selftest"
}

check_summary() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, sha = sys.argv[1:]
try:
    summary = json.load(open(path))
except (OSError, ValueError) as exc:
    sys.exit(f"tier-c check: unreadable summary {path}: {exc}")
problems = []
if summary.get("sha") != sha:
    problems.append(f"summary is for {summary.get('sha')!r}, not {sha}")
if summary.get("tree_dirty") is not False:
    problems.append("summary was produced on a dirty tree")
lanes = {row.get("lane"): row for row in summary.get("lanes", [])}
for lane in ("xe18", "xe21", "free23"):
    row = lanes.get(lane)
    if row is None:
        problems.append(f"lane {lane} is missing")
    elif row.get("verdict") != "pass" or not row.get("cases_total") or row.get("cases_failed") != 0:
        problems.append(f"lane {lane} did not pass: {row.get('verdict')} {row.get('reason', '')}".rstrip())
if (summary.get("clients") or {}).get("verdict") != "pass":
    problems.append("client snippet proofs did not pass")
if problems:
    sys.exit("tier-c check: FAIL: " + "; ".join(problems))
print(f"tier-c check: pass ({path})")
PY
}

selftest() {
  local dir sha
  dir="$ROOT/target/e2e/tier_c/selftest"
  mkdir -p "$dir"
  sha="$(printf '%040d' 7)"
  python3 - "$dir" "$sha" <<'PY'
import copy, json, sys
from pathlib import Path
dir, sha = Path(sys.argv[1]), sys.argv[2]
good = {"sha": sha, "tree_dirty": False, "clients": {"verdict": "pass", "clients": []},
        "lanes": [{"lane": lane, "version": None, "cases_total": 3, "cases_failed": 0, "verdict": "pass"}
                  for lane in ("xe18", "xe21", "free23")]
        + [{"lane": "adb", "verdict": "delegated"}]}
def variant(name, mutate):
    value = copy.deepcopy(good)
    mutate(value)
    (dir / f"{name}.json").write_text(json.dumps(value))
variant("good", lambda v: None)
variant("missing_lane", lambda v: v["lanes"].pop(1))
variant("failed_lane", lambda v: v["lanes"][2].update(verdict="fail", cases_failed=1))
variant("dry_run_lane", lambda v: v["lanes"][0].update(verdict="dry_run", cases_total=0))
variant("empty_lane", lambda v: v["lanes"][0].update(cases_total=0))
variant("other_sha", lambda v: v.update(sha="f" * 40))
variant("dirty_tree", lambda v: v.update(tree_dirty=True))
variant("client_fail", lambda v: v["clients"].update(verdict="fail"))
(dir / "truncated.json").write_text(json.dumps(good)[:-20])
PY
  check_summary "$dir/good.json" "$sha" >/dev/null || fail "selftest: a passing summary was refused"
  local name
  for name in missing_lane failed_lane dry_run_lane empty_lane other_sha dirty_tree client_fail truncated absent; do
    if check_summary "$dir/$name.json" "$sha" >/dev/null 2>&1; then
      fail "selftest: accepted $name"
    fi
  done
  echo "tier-c selftest: pass (good summary accepted; 9 short summaries refused)"
}

sha=''
dry_run=0
check=''
lanes=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check)
      [ "$#" -ge 2 ] || fail "--check requires a summary path"
      check="$2"
      shift 2
      ;;
    --selftest)
      selftest
      exit 0
      ;;
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
if [ -n "$check" ]; then
  check_summary "$check" "$sha"
  exit 0
fi
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

client_binary="${CARGO_TARGET_DIR:-$ROOT/target}/release/oraclemcp"
client_summary="$out_dir/clients.json"
client_exit=0
echo "tier-c: real MCP client snippet proofs"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/rig/client_snippets.py" \
  --binary "$client_binary" --summary-file "$client_summary" || client_exit=$?

python3 - "$rows" "$out_dir/summary.json" "$head" "$tree_dirty" "$client_summary" "$client_exit" <<'PY'
import json, sys
rows_path, summary_path, head, dirty, client_summary_path, client_exit = sys.argv[1:]
lanes = [json.loads(line) for line in open(rows_path) if line.strip()]
lanes.append({"lane": "adb", "verdict": "delegated", "reason": "Always-Free ADB runs in the W9 harness (T9.1)"})
try:
    clients = json.load(open(client_summary_path))
except (OSError, ValueError):
    clients = {"clients": [], "verdict": "fail", "reason": "client_proof_runner_failed_without_summary"}
else:
    records = clients.get("clients", [])
    clients["verdict"] = "fail" if client_exit != "0" or any(row.get("status") == "fail" for row in records) else "pass"
summary = {"sha": head, "tree_dirty": dirty == "true", "lanes": lanes, "clients": clients}
with open(summary_path, "w") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
print(json.dumps(summary, sort_keys=True))
PY
echo "tier-c: wrote $out_dir/summary.json"
