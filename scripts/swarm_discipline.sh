#!/usr/bin/env bash
# Swarm discipline mechanisms — AGENTS.md constitution rules 13-17.
#
# Five agents share one checkout. Each subcommand here answers, from git or from
# an exit status, a question that a 2026-07-21 incident showed an agent answering
# from a buffer, a guess, or a hope:
#
#   foreign-edit       rule 13  is this file broken, or is another agent mid-edit?
#   evidence-source    rule 14  what is the honest source block for this evidence?
#   verified-push      rule 15  did the gate actually pass?
#   bounded-run        rule 16  how long may this turn block?
#   unbounded-wait-lint rule 16 do committed scripts contain a wait that cannot end?
#   struct-atomicity   rule 17  does this change add a field without its initializers?
#
# Exit codes: 0 satisfied · 64 usage/environment · 65 refused (rule violated)
# · 124 bounded-run deadline reached.
set -euo pipefail

SELF="${BASH_SOURCE[0]}"
ROOT="$(cd "$(dirname "$SELF")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

usage() {
  cat <<'EOF'
Usage:
  scripts/swarm_discipline.sh foreign-edit PATH...
  scripts/swarm_discipline.sh evidence-source [--kind close|proof] [--scope PATH]...
  scripts/swarm_discipline.sh evidence-source [--kind close|proof] --from EVIDENCE.json
  scripts/swarm_discipline.sh verified-push --gate-cmd CMD [-- GIT_PUSH_ARG...]
  scripts/swarm_discipline.sh gate-verdict
  scripts/swarm_discipline.sh bounded-run [--timeout SECONDS] -- CMD...
  scripts/swarm_discipline.sh unbounded-wait-lint [PATH...]
  scripts/swarm_discipline.sh struct-atomicity [--staged | --commit REF]
  scripts/swarm_discipline.sh --selftest

foreign-edit (rule 13)
  Reports, per path, whether the worktree copy differs from HEAD. A differing
  path is another agent mid-edit until proven otherwise: judge it at HEAD
  (git show HEAD:PATH) before calling it a defect. Exit 65 if any path differs.

evidence-source (rule 14)
  Prints the evidence "source" object {sha, tree_clean, branch} derived from git
  instead of asserted by hand. --kind close scopes tree_clean to the bead's
  in-scope paths (what the close auditor checks) and reports other agents' dirty
  paths as a note; --kind proof requires the whole tree to be clean, because a
  reproducibility proof describes code at a commit. Refuses rather than emit
  tree_clean:false.

verified-push (rule 15)
  Runs the named gate, records its verdict, and pushes only on exit 0. HEAD must
  not move while the gate runs. A failed gate never reaches git push.

bounded-run / unbounded-wait-lint (rule 16)
  bounded-run imposes a hard deadline and reports a timeout as a result.
  unbounded-wait-lint refuses committed shell that waits without a deadline.

struct-atomicity (rule 17)
  For each struct field a change adds, lists struct-literal and struct-pattern
  sites the same change does not touch and that do not use `..`. Those sites
  stop compiling the moment the field lands, so they belong in this commit.
EOF
}

die() {
  printf 'swarm-discipline: %s\n' "$*" >&2
  exit 64
}

refuse() {
  printf 'swarm-discipline: REFUSED: %s\n' "$*" >&2
  exit 65
}

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || die "not inside a git repository"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# --------------------------------------------------------------------------
# rule 13 — a modified file that is not yours is another agent mid-edit
# --------------------------------------------------------------------------

foreign_edit() {
  local repo head path status dirty=0
  (( $# )) || die "foreign-edit requires at least one path"
  repo="$(repo_root)"
  head="$(git -C "$repo" rev-parse HEAD)"
  for path in "$@"; do
    status="$(git -C "$repo" status --porcelain=v1 --untracked-files=all -- "$path")"
    if [[ -z "$status" ]]; then
      printf 'AT-HEAD        %s (identical to %s)\n' "$path" "${head:0:12}"
      continue
    fi
    dirty=1
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      case "$line" in
        '??'*) printf 'UNTRACKED      %s — exists only in this worktree\n' "${line:3}" ;;
        *)     printf 'FOREIGN-EDIT   %s [%s] — differs from HEAD\n' "${line:3}" "${line:0:2}" ;;
      esac
    done <<<"$status"
  done
  if (( dirty )); then
    cat >&2 <<EOF
swarm-discipline: REFUSED: the paths above differ from HEAD ${head:0:12}.
In a shared checkout an uncommitted file is another agent mid-edit unless it is
yours. Judge the committed truth before filing a defect:
  git show HEAD:<path>
  git log --oneline -3 -- <path>
Do not report a build blocker from a mid-edit buffer, and do not go idle on one.
EOF
    exit 65
  fi
}

# --------------------------------------------------------------------------
# rule 14 — evidence comes from a tree verified clean of other agents' work
# --------------------------------------------------------------------------

evidence_source() {
  local repo kind=close from="" head branch scope_status all_status
  local -a scopes=()
  while (( $# )); do
    case "$1" in
      --kind)
        (( $# >= 2 )) || die "--kind requires close or proof"
        kind="$2"
        shift 2
        ;;
      --scope)
        (( $# >= 2 )) || die "--scope requires a path"
        scopes+=("$2")
        shift 2
        ;;
      --from)
        (( $# >= 2 )) || die "--from requires an evidence file"
        from="$2"
        shift 2
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  case "$kind" in
    close|proof) ;;
    *) die "--kind must be close or proof" ;;
  esac
  repo="$(repo_root)"
  if [[ -n "$from" ]]; then
    (( ${#scopes[@]} == 0 )) || die "--from and --scope are mutually exclusive"
    while IFS= read -r line; do
      [[ -n "$line" ]] && scopes+=("$line")
    done < <("$PYTHON_BIN" -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    doc = json.load(handle)
for entry in doc["scope"]["in_scope"]:
    print(entry)
' "$from")
  fi
  head="$(git -C "$repo" rev-parse HEAD)"
  branch="$(git -C "$repo" rev-parse --abbrev-ref HEAD)"
  all_status="$(git -C "$repo" status --porcelain=v1 --untracked-files=all)"

  if [[ "$kind" == proof || ${#scopes[@]} -eq 0 ]]; then
    scope_status="$all_status"
  else
    scope_status="$(git -C "$repo" status --porcelain=v1 --untracked-files=all -- "${scopes[@]}")"
  fi

  if [[ -n "$scope_status" ]]; then
    printf '%s\n' "$scope_status" >&2
    if [[ "$kind" == proof ]]; then
      refuse "a reproducibility proof needs a clean tree; the paths above exist at no commit.
Generate it from a dedicated clean worktree at HEAD instead:
  git worktree add ../$(basename "$repo")-proof-$$ $head"
    fi
    refuse "commit your in-scope work before generating close evidence; the paths above are claimed but uncommitted"
  fi

  if [[ -n "$all_status" ]]; then
    printf 'swarm-discipline: note: %s path(s) dirty outside this scope (other agents mid-edit); excluded from tree_clean by design\n' \
      "$(printf '%s\n' "$all_status" | wc -l | tr -d ' ')" >&2
  fi

  "$PYTHON_BIN" -c '
import json, sys
print(json.dumps({"sha": sys.argv[1], "tree_clean": True, "branch": sys.argv[2]}))
' "$head" "$branch"
}

# --------------------------------------------------------------------------
# rule 15 — read the gate verdict; never infer a pass from a successful push
# --------------------------------------------------------------------------

verdict_path() {
  local repo common
  repo="$1"
  common="$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)"
  printf '%s/oraclemcp-gate-verdict.json\n' "$common"
}

write_verdict() {
  "$PYTHON_BIN" -c '
import json, sys
path, sha, gate, status, code, started, finished = sys.argv[1:8]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "sha": sha,
            "gate_cmd": gate,
            "status": status,
            "exit_code": int(code),
            "started_at": started,
            "finished_at": finished,
        },
        handle,
        indent=2,
    )
    handle.write("\n")
' "$@"
}

gate_verdict() {
  local repo path
  repo="$(repo_root)"
  path="$(verdict_path "$repo")"
  [[ -f "$path" ]] || die "no gate verdict recorded yet at $path"
  cat "$path"
}

verified_push() {
  local repo gate="${ORACLEMCP_GATE_CMD:-}" path head after started finished code=0
  local -a push_args=()
  while (( $# )); do
    case "$1" in
      --gate-cmd)
        (( $# >= 2 )) || die "--gate-cmd requires a command"
        gate="$2"
        shift 2
        ;;
      --)
        shift
        push_args=("$@")
        break
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -n "$gate" ]] \
    || die "--gate-cmd (or ORACLEMCP_GATE_CMD) is required: name the gate whose verdict authorizes this push"
  repo="$(repo_root)"
  path="$(verdict_path "$repo")"
  head="$(git -C "$repo" rev-parse HEAD)"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'swarm-discipline: running gate at %s: %s\n' "${head:0:12}" "$gate" >&2
  set +e
  ( cd "$repo" && eval "$gate" )
  code=$?
  set -e
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  after="$(git -C "$repo" rev-parse HEAD)"

  if (( code != 0 )); then
    write_verdict "$path" "$head" "$gate" fail "$code" "$started" "$finished"
    cat "$path" >&2
    refuse "gate exited $code; nothing was pushed. Fix the gate, do not re-read the push output for reassurance."
  fi
  if [[ "$after" != "$head" ]]; then
    write_verdict "$path" "$head" "$gate" stale "$code" "$started" "$finished"
    refuse "HEAD moved from ${head:0:12} to ${after:0:12} while the gate ran; that verdict does not describe what you are about to push"
  fi
  write_verdict "$path" "$head" "$gate" pass "$code" "$started" "$finished"
  printf 'swarm-discipline: gate passed at %s; pushing\n' "${head:0:12}" >&2
  git -C "$repo" push "${push_args[@]}"
}

# --------------------------------------------------------------------------
# rule 16 — never block a turn on an unbounded wait
# --------------------------------------------------------------------------

BOUNDED_RUN_MAX_SECONDS="${ORACLEMCP_BOUNDED_RUN_MAX_SECONDS:-1800}"

bounded_run() {
  local seconds=300 code=0
  while (( $# )); do
    case "$1" in
      --timeout)
        (( $# >= 2 )) || die "--timeout requires a positive integer of seconds"
        seconds="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  case "$seconds" in
    ''|*[!0-9]*|0) die "--timeout must be a positive integer of seconds; there is no unbounded mode" ;;
  esac
  (( seconds <= BOUNDED_RUN_MAX_SECONDS )) \
    || die "--timeout $seconds exceeds the ${BOUNDED_RUN_MAX_SECONDS}s ceiling; check once, report, and move on"
  (( $# )) || die "bounded-run requires -- CMD..."
  require_command timeout
  set +e
  timeout --signal=TERM --kill-after=10s "$seconds" "$@"
  code=$?
  set -e
  if (( code == 124 || code == 137 )); then
    printf 'swarm-discipline: BOUNDED-RUN TIMEOUT after %ss: %s\n' "$seconds" "$*" >&2
    printf 'swarm-discipline: report the timeout as the result of this turn; do not wait again.\n' >&2
    return 124
  fi
  return "$code"
}

unbounded_wait_lint() {
  local -a targets=("$@")
  if (( ${#targets[@]} == 0 )); then
    while IFS= read -r path; do
      targets+=("$path")
    done < <(git -C "$ROOT" ls-files 'scripts/*.sh' 'scripts/**/*.sh' '*.sh')
  fi
  "$PYTHON_BIN" - "$ROOT" "${targets[@]}" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
paths = sys.argv[2:]

FOLLOW = re.compile(r"\btail\s+(-[a-zA-Z]*f|--follow)\b")
LOOP = re.compile(r"^\s*while\s+(true|:)\s*;?\s*do\b")
# A loop is bounded when its body can decide to stop: a deadline, an explicit
# timeout, or a bounded attempt counter.
BOUND = re.compile(r"deadline|timeout|SECONDS|attempt|tries|retries|max_|remaining")

findings = []
for name in paths:
    path = root / name if not Path(name).is_absolute() else Path(name)
    if not path.is_file():
        continue
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue
        if FOLLOW.search(line) and "timeout" not in line:
            findings.append(
                (name, index, "tail --follow never returns; wrap it in a deadline or read a snapshot")
            )
        if LOOP.search(line):
            depth = 0
            bounded = False
            for body in lines[index - 1 :]:
                depth += len(re.findall(r"\bdo\b", body)) - len(re.findall(r"\bdone\b", body))
                if BOUND.search(body):
                    bounded = True
                if depth <= 0 and body is not lines[index - 1]:
                    break
            if not bounded:
                findings.append(
                    (name, index, "infinite loop with no deadline, timeout, or bounded attempt counter")
                )

for name, index, detail in findings:
    print(f"{name}:{index}: {detail}", file=sys.stderr)
if findings:
    print(
        f"swarm-discipline: REFUSED: {len(findings)} unbounded wait(s) in committed shell",
        file=sys.stderr,
    )
    raise SystemExit(65)
print(f"swarm-discipline: no unbounded waits in {len(paths)} shell file(s)")
PY
}

# --------------------------------------------------------------------------
# rule 17 — a struct field and its initializers are one commit
# --------------------------------------------------------------------------

struct_atomicity() {
  local repo mode=staged ref=""
  while (( $# )); do
    case "$1" in
      --staged)
        mode=staged
        shift
        ;;
      --commit)
        (( $# >= 2 )) || die "--commit requires a ref"
        mode=commit
        ref="$2"
        shift 2
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  repo="$(repo_root)"
  [[ "$mode" == staged ]] && ref=""
  "$PYTHON_BIN" - "$repo" "$mode" "$ref" <<'PY'
import re
import subprocess
import sys

repo, mode, ref = sys.argv[1], sys.argv[2], sys.argv[3]


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", repo, *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


if mode == "staged":
    diff = git("diff", "--cached", "-U0")
    revision = ""  # the index
else:
    diff = git("show", "-U0", "--format=", ref)
    revision = ref

FIELD = re.compile(r"^\+\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][A-Za-z0-9_]*)\s*:\s*\S.*,\s*$")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
ITEM = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")

touched: set[str] = set()
added: list[tuple[str, int, str]] = []
current = ""
line_number = 0
for line in diff.splitlines():
    if line.startswith("+++ b/"):
        current = line[6:]
        touched.add(current)
        continue
    if line.startswith("--- a/"):
        touched.add(line[6:])
        continue
    hunk = HUNK.match(line)
    if hunk:
        line_number = int(hunk.group(1))
        continue
    if not line.startswith("+") or line.startswith("+++"):
        continue
    if current.endswith(".rs"):
        match = FIELD.match(line)
        if match:
            added.append((current, line_number, match.group(1)))
    line_number += 1


def file_at(path: str) -> list[str]:
    spec = f"{revision}:{path}" if revision else f":{path}"
    try:
        return git("show", spec).splitlines()
    except subprocess.CalledProcessError:
        return []


def enclosing_struct(lines: list[str], target: int) -> str | None:
    """Name of the struct whose body contains 1-based line `target`, if any."""
    stack: list[tuple[str | None, int]] = []
    depth = 0
    pending: str | None = None
    for index, line in enumerate(lines, start=1):
        code = line.split("//", 1)[0]
        item = ITEM.match(code)
        if item:
            pending = item.group(1)
        for char in code:
            if char == "{":
                depth += 1
                stack.append((pending, depth))
                pending = None
            elif char == "}":
                if stack:
                    stack.pop()
                depth = max(0, depth - 1)
        if index == target:
            for name, _ in reversed(stack):
                if name:
                    return name
            return None
    return None


def literal_sites(name: str) -> list[tuple[str, int]]:
    try:
        out = git("grep", "-n", "-E", rf"\b{name}\s*\{{", "--", "*.rs")
    except subprocess.CalledProcessError:
        return []
    sites = []
    for row in out.splitlines():
        path, number, _ = row.split(":", 2)
        sites.append((path, int(number)))
    return sites


def block_uses_rest(lines: list[str], start: int) -> bool:
    """True when the braced block opening at 1-based `start` uses `..`."""
    depth = 0
    for line in lines[start - 1 :]:
        code = line.split("//", 1)[0]
        if depth > 0 and re.search(r"\.\.\s*(\w|\)|\}|$)", code):
            return True
        if depth == 0 and re.search(r"\{.*\.\..*\}", code):
            return True
        depth += code.count("{") - code.count("}")
        if depth <= 0 and "{" in code:
            return False
    return False


violations: list[str] = []
for path, number, field in added:
    lines = file_at(path)
    if not lines:
        continue
    struct = enclosing_struct(lines, number)
    if struct is None:
        continue
    for site_path, site_line in literal_sites(struct):
        if site_path in touched:
            continue
        site_lines = file_at(site_path) or []
        if not site_lines:
            continue
        text = site_lines[site_line - 1] if site_line <= len(site_lines) else ""
        if ITEM.match(text.split("//", 1)[0]):
            continue
        if block_uses_rest(site_lines, site_line):
            continue
        violations.append(
            f"{site_path}:{site_line}: {struct} used without `..` but "
            f"{path} adds field `{field}` in a change that does not touch it"
        )

for violation in sorted(set(violations)):
    print(violation, file=sys.stderr)
if violations:
    print(
        "swarm-discipline: REFUSED: a struct field and its initializers are ONE "
        "logical change, landed in ONE commit by ONE agent",
        file=sys.stderr,
    )
    raise SystemExit(65)
print(f"swarm-discipline: {len(added)} added struct field(s); no orphaned initializer sites")
PY
}

# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

selftest() {
  local work status
  require_command git
  require_command timeout
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN

  git -C "$work" init -q
  git -C "$work" config user.email selftest@example.invalid
  git -C "$work" config user.name selftest
  mkdir -p "$work/crates/demo/src"
  cat >"$work/crates/demo/src/lib.rs" <<'RS'
pub struct Ctx {
    pub a: u8,
}

pub fn make() -> Ctx {
    Ctx { a: 1 }
}
RS
  cat >"$work/crates/demo/src/other.rs" <<'RS'
use crate::Ctx;

pub fn also() -> Ctx {
    Ctx { a: 2 }
}
RS
  git -C "$work" add -A
  git -C "$work" commit -qm initial

  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" foreign-edit crates/demo/src/lib.rs >/dev/null )
  printf 'PASS selftest: an unmodified path reports AT-HEAD\n'

  printf '// mid-edit\n' >>"$work/crates/demo/src/lib.rs"
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" foreign-edit crates/demo/src/lib.rs >/dev/null 2>&1 ) || status=$?
  (( status == 65 )) || die "selftest: a mid-edit path was not reported as foreign (exit $status)"
  printf 'PASS selftest: a mid-edit path is refused as foreign, not a defect\n'

  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" evidence-source --kind proof >/dev/null 2>&1 ) || status=$?
  (( status == 65 )) || die "selftest: a dirty tree produced proof evidence (exit $status)"
  printf 'PASS selftest: a dirty tree cannot produce proof evidence\n'

  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" evidence-source \
      --kind close --scope crates/demo/src/other.rs >/dev/null 2>&1 ) || status=$?
  (( status == 0 )) || die "selftest: a clean scope was refused close evidence (exit $status)"
  printf 'PASS selftest: close evidence is scoped, and foreign dirt is a note\n'

  git -C "$work" checkout -q -- crates/demo/src/lib.rs

  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" verified-push \
      --gate-cmd 'echo "!!! GATE FAILED" >&2; exit 1' >/dev/null 2>&1 ) || status=$?
  (( status == 65 )) || die "selftest: a failed gate did not refuse the push (exit $status)"
  printf 'PASS selftest: a failed gate refuses the push\n'
  status="$(git -C "$work" rev-parse --path-format=absolute --git-common-dir)"
  grep -q '"status": "fail"' "$status/oraclemcp-gate-verdict.json" \
    || die "selftest: the failing verdict was not recorded"
  printf 'PASS selftest: the verdict is recorded where it can be read\n'

  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" bounded-run --timeout 1 -- sleep 30 ) \
    >/dev/null 2>&1 || status=$?
  (( status == 124 )) || die "selftest: an over-deadline command did not time out (exit $status)"
  printf 'PASS selftest: a wait past its deadline returns instead of blocking\n'

  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" bounded-run -- true ) >/dev/null 2>&1 || status=$?
  (( status == 0 )) || die "selftest: a fast command was disturbed by the deadline (exit $status)"
  printf 'PASS selftest: a command inside its deadline is untouched\n'

  mkdir -p "$work/waits"
  cat >"$work/waits/unbounded.sh" <<'SH'
#!/usr/bin/env bash
tail -f /var/log/build.log
SH
  status=0
  bash "$SELF" unbounded-wait-lint "$work/waits/unbounded.sh" >/dev/null 2>&1 || status=$?
  (( status == 65 )) || die "selftest: tail --follow was not linted (exit $status)"
  printf 'PASS selftest: an unbounded wait in committed shell is refused\n'

  status=0
  bash "$SELF" unbounded-wait-lint "$ROOT/scripts/build_lease.sh" >/dev/null 2>&1 || status=$?
  (( status == 0 )) || die "selftest: a deadline-bounded loop was falsely linted (exit $status)"
  printf 'PASS selftest: a deadline-bounded loop passes the lint\n'

  "$PYTHON_BIN" - "$work/crates/demo/src/lib.rs" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text.replace("    pub a: u8,\n", "    pub a: u8,\n    pub b: u8,\n"))
PY
  git -C "$work" add crates/demo/src/lib.rs
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged ) >/dev/null 2>&1 \
    || status=$?
  (( status == 65 )) || die "selftest: a split struct-field change was accepted (exit $status)"
  printf 'PASS selftest: a field added without its far initializer is refused\n'

  "$PYTHON_BIN" - "$work/crates/demo/src/other.rs" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text.replace("Ctx { a: 2 }", "Ctx { a: 2, b: 2 }"))
PY
  git -C "$work" add crates/demo/src/other.rs
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged ) >/dev/null 2>&1 \
    || status=$?
  (( status == 0 )) || die "selftest: one complete logical change was refused (exit $status)"
  printf 'PASS selftest: field plus every initializer in one change is accepted\n'
}

command_name="${1:-}"
case "$command_name" in
  foreign-edit) foreign_edit "${@:2}" ;;
  evidence-source)
    require_command "$PYTHON_BIN"
    evidence_source "${@:2}"
    ;;
  verified-push)
    require_command "$PYTHON_BIN"
    verified_push "${@:2}"
    ;;
  gate-verdict) gate_verdict ;;
  bounded-run) bounded_run "${@:2}" ;;
  unbounded-wait-lint)
    require_command "$PYTHON_BIN"
    unbounded_wait_lint "${@:2}"
    ;;
  struct-atomicity)
    require_command "$PYTHON_BIN"
    struct_atomicity "${@:2}"
    ;;
  --selftest) selftest ;;
  -h|--help) usage ;;
  *)
    usage >&2
    exit 64
    ;;
esac
