#!/usr/bin/env bash
# Swarm discipline mechanisms — AGENTS.md constitution rules 13-18.
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
#   stale-delete-check rule 18  is this commit deleting files that still exist?
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
  scripts/swarm_discipline.sh stale-delete-check [--staged | --commit REF]
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

stale-delete-check (rule 18)
  Refuses a change that deletes a path still present in the worktree. Such a
  deletion is a stale index snapshot committed over another agent's landed
  work, not a delete anyone asked for.
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

# Print "<sha>\t<status>" from a verdict file, or "\t" when the file is absent
# or unreadable. Callers compare the fields themselves so an unreadable verdict
# can never masquerade as a matching pass.
read_verdict_sha_status() {
  "$PYTHON_BIN" -c '
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        record = json.load(handle)
    print("{}\t{}".format(record.get("sha", ""), record.get("status", "")))
except (OSError, ValueError):
    print("\t")
' "$1"
}

gate_verdict() {
  local repo path head line recorded status
  repo="$(repo_root)"
  path="$(verdict_path "$repo")"
  head="$(git -C "$repo" rev-parse HEAD)"
  # ABSENT IS A REFUSAL THAT NAMES THE CANDIDATE. "no verdict recorded yet"
  # hides which commit went ungated; an agent reading it cannot tell whether
  # HEAD was gated or some other commit was. Name the candidate explicitly.
  if [[ ! -f "$path" ]]; then
    refuse "no verdict recorded for ${head:0:12}; run the gate (verified-push --gate-cmd ...) at HEAD before reading a verdict"
  fi
  line="$(read_verdict_sha_status "$path")"
  recorded="${line%%$'\t'*}"
  status="${line#*$'\t'}"
  # A STALE VERDICT IS WORSE THAN NO VERDICT. An absent one blocks safely: the
  # reader knows nothing was gated. One that describes a DIFFERENT commit looks
  # present, reads "pass", and is how someone pushes on evidence that was never
  # about the code in front of them. This bit us: the tool printed a verdict for
  # an unrelated SHA while HEAD had never been gated at all. Report it as "no
  # verdict recorded for <candidate>" — because that is the truth — and name the
  # record SHA too, so the reader can see which commit was actually gated.
  if [[ "$recorded" != "$head" ]]; then
    local shown="${recorded:-<unreadable>}"
    refuse "no verdict recorded for ${head:0:12}; a verdict describing ${shown:0:12} exists but it does not gate what you are about to push — re-run the gate at HEAD"
  fi
  # A VERDICT AT HEAD THAT IS NOT A PASS IS A FAILURE. A gate that printed a
  # failure is a failure regardless of how a later push went; surfacing a
  # matching fail/stale record as exit 0 would let an agent read "verdict
  # present" and push on a gate that never passed.
  if [[ "$status" != "pass" ]]; then
    refuse "the gate verdict at ${head:0:12} is '${status:-<unreadable>}', not pass; a gate that printed a failure is a failure — fix the gate, do not push"
  fi
  cat "$path"
}

verified_push() {
  local repo gate="${SWARM_GATE_CMD:-${ORACLEMCP_GATE_CMD:-}}" path head after started finished code=0
  # THE GATE RUNNER MUST NOT LEAK ITS OWN CONFIGURATION INTO THE GATE.
  # oraclemcp's config loader claims the ENTIRE `ORACLEMCP_*` environment
  # namespace and refuses to start on an unrecognised key, so a gate that runs
  # `cargo test` inherits ORACLEMCP_GATE_CMD and every test that spawns the
  # binary dies with:
  #   unknown field: found `gate_cmd` ... for key "GATE_CMD"
  # That produced 9 phantom failures in `--test cli` and refused a push whose
  # HEAD was in fact clean (27/27 pass without the variable). The variable is
  # read above and removed here, so the gate subprocess never sees it.
  # SWARM_GATE_CMD is the non-colliding spelling; ORACLEMCP_GATE_CMD still works.
  unset ORACLEMCP_GATE_CMD SWARM_GATE_CMD
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
    || die "--gate-cmd (or SWARM_GATE_CMD) is required: name the gate whose verdict authorizes this push"
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
  # BELT-AND-BRACES: re-read the verdict we just wrote and refuse the push
  # unless the recorded SHA exactly equals the candidate HEAD and the status is
  # pass. The push is authorized by the recorded verdict, never by the exit code
  # we observed a moment ago — so a verdict that is absent, for another SHA, or
  # not a pass must stop the push here even if something raced the write.
  local final_line final_sha final_status
  final_line="$(read_verdict_sha_status "$path")"
  final_sha="${final_line%%$'\t'*}"
  final_status="${final_line#*$'\t'}"
  if [[ "$final_sha" != "$head" || "$final_status" != "pass" ]]; then
    refuse "the recorded verdict (sha=${final_sha:-<none>} status=${final_status:-<none>}) does not authorize a push of ${head:0:12} with status=pass; nothing was pushed"
  fi
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
# A lint that cannot describe its own subject is useless: this file, and any
# fixture or message that must name the idiom, marks the line explicitly.
ALLOW = "swarm-discipline: allow-unbounded"
# swarm-discipline: allow-unbounded (the message must name the idiom)
FOLLOW_MESSAGE = "tail --follow never returns; wrap it in a deadline or read a snapshot"
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
        previous = lines[index - 2] if index >= 2 else ""
        if ALLOW in line or ALLOW in previous:
            continue
        if FOLLOW.search(line) and "timeout" not in line:
            # swarm-discipline: allow-unbounded (the message must name the idiom)
            findings.append((name, index, FOLLOW_MESSAGE))
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
import posixpath
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


# `Name {` that opens something other than a struct literal or pattern: a
# return type (`-> Name {`), an impl/trait/for header or an item definition.
NOT_LITERAL = re.compile(
    r"(?:->|\b(?:impl|for|struct|enum|union|trait|mod|dyn|type)(?:\s*<[^>]*>)?)\s*$"
)
PATH_QUALIFIER = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*$")


def literal_uses(code: str, name: str) -> list[str]:
    """Qualifiers of every `name {` on this line that is a struct literal/pattern.

    An empty qualifier is an unqualified `name {`; `a::b::` is the qualifier of
    `a::b::name {`. A `name {` introduced by `->`, `impl`, `struct`, ... opens a
    body, not a literal, and is not listed.
    """
    qualifiers: list[str] = []
    for match in re.finditer(rf"\b{name}\s*\{{", code):
        prefix = code[: match.start()]
        qmatch = PATH_QUALIFIER.search(prefix)
        qualifier = qmatch.group(0) if qmatch else ""
        rest = prefix[: len(prefix) - len(qualifier)].rstrip()
        if not NOT_LITERAL.search(rest):
            qualifiers.append(qualifier.rstrip(":"))
    return qualifiers


# --------------------------------------------------------------------------
# Module / import resolution (oraclemcp-it7iq): a bare `Name {` is not proof
# that a site refers to the changed struct — two modules may define the same
# private name. A site counts only when the name resolves to the changed
# struct's defining module. Resolution is deliberately conservative: when it is
# ambiguous the site counts, so a genuinely orphaned initializer is refused.
# --------------------------------------------------------------------------

# A module is (crate-root file, path parts), so two crates with `mod pb` never
# collide on the bare module name.
MOD_DECL = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)
USE_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(.+?);\s*$")
DEF_DECL = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:struct|enum|union|trait|type)\s+([A-Za-z_][A-Za-z0-9_]*)"
)

_FILE_CACHE: dict[str, list[str]] = {}
_SCAN_CACHE: dict[str, dict] = {}


def file_at_cached(path: str) -> list[str]:
    if path not in _FILE_CACHE:
        _FILE_CACHE[path] = file_at(path)
    return _FILE_CACHE[path]


def list_rs() -> list[str]:
    if revision:
        out = git("ls-tree", "-r", "--name-only", revision)
    else:
        out = git("ls-files", "--cached")
    return [path for path in out.splitlines() if path.endswith(".rs")]


ALL_RS = list_rs()
_RS_SET = set(ALL_RS)


def crate_root_of(path: str) -> tuple[str, str] | None:
    """The (root file, root directory) of the crate owning `path`, if any."""
    directory = posixpath.dirname(path)
    while True:
        for candidate in ("lib.rs", "main.rs"):
            root = f"{directory}/{candidate}" if directory else candidate
            if root in _RS_SET:
                return root, directory
        parent = posixpath.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def file_module(path: str) -> tuple[str, tuple[str, ...]] | None:
    """Canonical module id for a .rs file, or None outside a known crate."""
    found = crate_root_of(path)
    if found is None:
        return None
    root, root_dir = found
    if path == root:
        return (root, ())
    rel = posixpath.relpath(path, root_dir) if root_dir else path
    if rel.endswith("/mod.rs"):
        rel = rel[: -len("/mod.rs")]
    elif rel == "mod.rs":
        rel = ""
    elif rel.endswith(".rs"):
        rel = rel[:-3]
    return (root, tuple(part for part in rel.split("/") if part))


def _split_use_items(text: str) -> list[str]:
    items: list[str] = []
    depth = 0
    current = ""
    for char in text:
        if char in "{(":
            depth += 1
        elif char in ")}":
            depth -= 1
        if char == "," and depth == 0:
            items.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        items.append(current)
    return [item.strip() for item in items if item.strip()]


def _parse_use_tree(
    text: str, prefix: list[str]
) -> list[tuple[str | None, list[str], bool]]:
    """Expand one use tree into (binding, path segments, is_glob) rows."""
    text = text.strip()
    if not text:
        return []
    brace = text.find("{")
    if brace != -1:
        head = text[:brace].rstrip().rstrip(":")
        base = prefix + [part for part in head.split("::") if part]
        inner = text[brace + 1 :]
        depth = 1
        end = len(inner)
        for index, char in enumerate(inner):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        rows: list[tuple[str | None, list[str], bool]] = []
        for item in _split_use_items(inner[:end]):
            rows.extend(_parse_use_tree(item, base))
        return rows
    if text.endswith("*"):
        head = text[:-1].rstrip().rstrip(":")
        base = prefix + [part for part in head.split("::") if part]
        return [(None, base, True)]
    if " as " in text:
        path, alias = text.split(" as ", 1)
        segments = prefix + [part for part in path.strip().split("::") if part]
        return [(alias.strip(), segments, False)]
    segments = prefix + [part for part in text.split("::") if part]
    if segments and segments[-1] == "self":
        segments = segments[:-1]
        return [(segments[-1] if segments else None, segments, False)]
    return [(segments[-1] if segments else None, segments, False)]


def scan_file(path: str) -> dict:
    if path in _SCAN_CACHE:
        return _SCAN_CACHE[path]
    lines = file_at_cached(path)
    module = file_module(path)
    inline_stack: list[tuple[str, ...]] = [()] * (len(lines) + 1)
    defs: dict[tuple[str, tuple[str, ...]], set[str]] = {}
    imports: dict[tuple[str, tuple[str, ...]], list] = {}
    stack: list[tuple[bool, str | None]] = []
    for index, raw in enumerate(lines, 1):
        code = raw.split("//", 1)[0]
        inline_stack[index] = tuple(name for is_mod, name in stack if is_mod)
        if module is not None and all(is_mod for is_mod, _ in stack):
            mid = (module[0], module[1] + inline_stack[index])
            item = DEF_DECL.match(code)
            if item:
                defs.setdefault(mid, set()).add(item.group(1))
            use = USE_DECL.match(code)
            if use:
                for binding, segments, is_glob in _parse_use_tree(use.group(1), []):
                    imports.setdefault(mid, []).append((binding, segments, is_glob))
        pending = MOD_DECL.match(code)
        pending_name = pending.group(1) if pending else None
        for char in code:
            if char == "{":
                if pending_name is not None:
                    stack.append((True, pending_name))
                    pending_name = None
                else:
                    stack.append((False, None))
            elif char == "}":
                if stack:
                    stack.pop()
    result = {
        "module": module,
        "inline_stack": inline_stack,
        "defs": defs,
        "imports": imports,
    }
    _SCAN_CACHE[path] = result
    return result


MODULE_DEFS: dict[tuple[str, tuple[str, ...]], set[str]] = {}
MODULE_IMPORTS: dict[tuple[str, tuple[str, ...]], list] = {}
INLINE_MODULES: set[tuple[str, tuple[str, ...]]] = set()
for _path in ALL_RS:
    _scan = scan_file(_path)
    _module = _scan["module"]
    for _mid, _names in _scan["defs"].items():
        MODULE_DEFS.setdefault(_mid, set()).update(_names)
    for _mid, _rows in _scan["imports"].items():
        MODULE_IMPORTS.setdefault(_mid, []).extend(_rows)
    if _module is not None:
        for _stack in _scan["inline_stack"]:
            for _depth in range(1, len(_stack) + 1):
                INLINE_MODULES.add((_module[0], _module[1] + _stack[:_depth]))


def module_of_line(path: str, line: int) -> tuple[str, tuple[str, ...]] | None:
    scan = scan_file(path)
    module = scan["module"]
    if module is None:
        return None
    stack = scan["inline_stack"]
    if not 1 <= line < len(stack):
        return None
    return (module[0], module[1] + stack[line])


def _module_layout(base: tuple[str, tuple[str, ...]]) -> tuple[str, str] | None:
    root, parts = base
    root_dir = posixpath.dirname(root)
    if not parts:
        return root, root_dir
    rel = posixpath.join(root_dir, *parts) if root_dir else posixpath.join(*parts)
    as_mod = f"{rel}/mod.rs"
    as_file = f"{rel}.rs"
    has_mod = as_mod in _RS_SET
    has_file = as_file in _RS_SET
    if has_mod and has_file:
        return None
    if has_mod or has_file:
        return (as_mod if has_mod else as_file), rel
    return None


def module_descend(
    base: tuple[str, tuple[str, ...]], segment: str
) -> tuple[str, tuple[str, ...]] | None:
    layout = _module_layout(base)
    if layout is None:
        return None
    _, child_dir = layout
    child_mod = f"{child_dir}/{segment}/mod.rs"
    child_file = f"{child_dir}/{segment}.rs"
    has_mod = child_mod in _RS_SET
    has_file = child_file in _RS_SET
    if has_mod and has_file:
        return None
    child = (base[0], base[1] + (segment,))
    if has_mod or has_file:
        return child
    if child in INLINE_MODULES:
        return child
    return None


def resolve_module_segments(
    segments: list[str], base: tuple[str, tuple[str, ...]]
) -> tuple[str, tuple[str, ...]] | None:
    root, parts = base
    index = 0
    current = base
    if segments and segments[0] == "crate":
        current = (root, ())
        index = 1
    elif segments and segments[0] == "self":
        index = 1
    elif segments and segments[0] == "super":
        count = 0
        while index < len(segments) and segments[index] == "super":
            count += 1
            index += 1
        if count > len(parts):
            return None
        current = (root, parts[: len(parts) - count])
    for segment in segments[index:]:
        current = module_descend(current, segment)
        if current is None:
            return None
    return current


def import_resolution(
    module: tuple[str, tuple[str, ...]], name: str
) -> tuple[str, tuple[str, tuple[str, ...]] | None, str | None]:
    for binding, segments, is_glob in MODULE_IMPORTS.get(module, []):
        if is_glob or binding != name or not segments:
            continue
        item = segments[-1]
        target = resolve_module_segments(segments[:-1], module)
        if target is None:
            return ("unresolved", None, None)
        if item in MODULE_DEFS.get(target, ()):
            # The target module really defines this item: same name + module is
            # the changed struct, anything else is provably a different type.
            return ("type", target, item)
        # Not a definition in the target (a re-export, a module, or a name we
        # did not see): cannot be resolved => fail closed.
        return ("unresolved", None, None)
    return ("none", None, None)


def site_may_be_def(
    site_path: str,
    site_line: int,
    name: str,
    qualifier: str,
    def_module: tuple[str, tuple[str, ...]],
    def_name: str,
) -> bool:
    """True when the site could refer to the changed struct (keep refusing)."""
    module = module_of_line(site_path, site_line)
    if module is None:
        return True  # cannot place the site => fail closed
    if qualifier:
        segments = [part for part in qualifier.split("::") if part]
        target = resolve_module_segments(segments, module)
        if target is None:
            return True  # ambiguous qualified path => fail closed
        if name in MODULE_DEFS.get(target, ()):
            return target == def_module and name == def_name
        return True
    if name in MODULE_DEFS.get(module, ()):
        # A local item shadows every import; it is the changed struct only when
        # it lives in the changed struct's defining module.
        return module == def_module and name == def_name
    kind, target, base_name = import_resolution(module, name)
    if kind == "type":
        return target == def_module and base_name == def_name
    return True  # none, glob, or unresolved => fail closed


def literal_sites(name: str) -> list[tuple[str, int, list[str]]]:
    # Read the SAME source the added field came from: the index for
    # --staged, the revision for --commit. A worktree grep would mix in
    # other agents' unstaged edits and shift line numbers against file_at.
    # `git grep` takes --cached before the pattern and a revision after it.
    args = ["grep", "-n", "-E"]
    if not revision:
        args.append("--cached")
    args += ["-e", rf"\b{name}\s*\{{"]
    if revision:
        args.append(revision)
    result = subprocess.run(
        ["git", "-C", repo, *args, "--", "*.rs"], capture_output=True, text=True
    )
    # Exit 1 is "no matches". Anything else is a failed search, and a failed
    # search must refuse, never read as "no initializer sites" (fail closed).
    if result.returncode == 1:
        return []
    if result.returncode != 0:
        print(f"swarm-discipline: git grep failed: {result.stderr.strip()}", file=sys.stderr)
        raise SystemExit(65)
    out = result.stdout
    sites = []
    for row in out.splitlines():
        if revision:
            row = row[len(revision) + 1 :]
        path, number, text = row.split(":", 2)
        qualifiers = literal_uses(text.split("//", 1)[0], name)
        if not qualifiers:
            continue
        sites.append((path, int(number), qualifiers))
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
    lines = file_at_cached(path)
    if not lines:
        continue
    struct = enclosing_struct(lines, number)
    if struct is None:
        continue
    def_module = module_of_line(path, number)
    for site_path, site_line, qualifiers in literal_sites(struct):
        if site_path in touched:
            continue
        site_lines = file_at_cached(site_path)
        if not site_lines:
            continue
        text = site_lines[site_line - 1] if site_line <= len(site_lines) else ""
        if ITEM.match(text.split("//", 1)[0]):
            continue
        if block_uses_rest(site_lines, site_line):
            continue
        if def_module is not None and not any(
            site_may_be_def(site_path, site_line, struct, qualifier, def_module, struct)
            for qualifier in qualifiers
        ):
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
# rule 18 — commit explicit paths; a delete of a live file is a stale index
# --------------------------------------------------------------------------

stale_delete_check() {
  local repo mode=staged ref="" path violations=0
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
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    if [[ -e "$repo/$path" ]]; then
      printf 'STALE-DELETE   %s — deleted by this change, still present in the worktree\n' "$path"
      violations=$((violations + 1))
    fi
  done < <(
    if [[ "$mode" == staged ]]; then
      git -C "$repo" diff --cached --name-only --diff-filter=D
    else
      git -C "$repo" show --name-only --diff-filter=D --format= "$ref"
    fi
  )
  if (( violations )); then
    cat >&2 <<'EOF'
swarm-discipline: REFUSED: this change deletes paths that still exist on disk.
That is a stale index snapshot committed over someone's landed work, not a
delete. Commit explicit paths and check what actually landed:
  git commit -m '...' -- <path>...
  git show --stat HEAD
EOF
    exit 65
  fi
  printf 'swarm-discipline: no deletion of a path that still exists\n'
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
  # swarm-discipline: allow-unbounded (fixture text the lint must still refuse)
  printf '#!/usr/bin/env bash\ntail -f /var/log/build.log\n' >"$work/waits/unbounded.sh"
  status=0
  bash "$SELF" unbounded-wait-lint "$work/waits/unbounded.sh" >/dev/null 2>&1 || status=$?
  # swarm-discipline: allow-unbounded (the assertion must name the idiom)
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

  git -C "$work" commit -qm "field and initializer together"
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" stale-delete-check --commit HEAD ) \
    >/dev/null 2>&1 || status=$?
  (( status == 0 )) || die "selftest: an ordinary commit was called a stale delete (exit $status)"
  printf 'PASS selftest: a change that deletes nothing passes the stale-delete check\n'

  # Rule 17 precision: `-> Ctx {`, `impl Ctx {` and friends open a body, not
  # a struct literal, so they are never orphaned initializers. A real literal
  # left behind still is, and --staged judges the index, not the worktree.
  cat >"$work/crates/demo/src/sig.rs" <<'RS'
use crate::Ctx;

impl Ctx {
    pub fn fresh() -> Ctx {
        crate::make()
    }
}

pub fn via() -> crate::Ctx {
    Ctx::fresh()
}
RS
  cat >"$work/crates/demo/src/lit.rs" <<'RS'
use crate::Ctx;

pub fn lit() -> Ctx {
    Ctx { a: 4, b: 4 }
}
RS
  git -C "$work" add crates/demo/src/sig.rs crates/demo/src/lit.rs
  git -C "$work" commit -qm "signature-only and literal users of Ctx"
  "$PYTHON_BIN" - "$work/crates/demo/src" <<'PY'
import sys
root = sys.argv[1]
for name, old, new in (
    ("lib.rs", "    pub b: u8,\n", "    pub b: u8,\n    pub c: u8,\n"),
    ("other.rs", "Ctx { a: 2, b: 2 }", "Ctx { a: 2, b: 2, c: 2 }"),
):
    path = f"{root}/{name}"
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    assert old in text, (name, old)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(old, new))
PY
  git -C "$work" add crates/demo/src/lib.rs crates/demo/src/other.rs
  local report
  status=0
  report="$( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged 2>&1 )" \
    || status=$?
  (( status == 65 )) || die "selftest: a real struct literal left behind was accepted (exit $status)"
  [[ "$report" == *"lit.rs:4"* ]] || die "selftest: the orphaned literal in lit.rs was not reported: $report"
  [[ "$report" != *"sig.rs"* ]] || die "selftest: a signature/impl header was reported as a literal: $report"
  printf 'PASS selftest: a real literal left behind is refused; signatures are not literals\n'

  printf 'use crate::Ctx;\n\npub fn lit() -> Ctx {\n    Ctx { a: 4, b: 4, c: 4 }\n}\n' \
    >"$work/crates/demo/src/lit.rs"
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged ) >/dev/null 2>&1 \
    || status=$?
  (( status == 65 )) || die "selftest: an unstaged worktree fix satisfied --staged (exit $status)"
  printf 'PASS selftest: --staged judges the index, not unstaged worktree edits\n'

  git -C "$work" add crates/demo/src/lit.rs
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged ) >/dev/null 2>&1 \
    || status=$?
  (( status == 0 )) || die "selftest: signature/impl users of a struct were refused (exit $status)"
  git -C "$work" commit -qm "field c with every initializer"
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --commit HEAD ) >/dev/null 2>&1 \
    || status=$?
  (( status == 0 )) || die "selftest: --commit refused a complete change with signature users (exit $status)"
  printf 'PASS selftest: a complete change passes with -> Type { and impl Type { users untouched\n'

  # A stale index: the path is staged as deleted while it still exists on disk,
  # which is how one pane committed another pane's landed evidence away.
  git -C "$work" rm -q --cached crates/demo/src/other.rs
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" stale-delete-check --staged ) \
    >/dev/null 2>&1 || status=$?
  (( status == 65 )) || die "selftest: a delete of a live file was accepted (exit $status)"
  printf 'PASS selftest: deleting a path that still exists is refused\n'

  # The gate runner must not leak its own configuration into the gate it runs.
  # oraclemcp's config loader owns the whole ORACLEMCP_* namespace and refuses to
  # start on an unknown key, so a leaked ORACLEMCP_GATE_CMD makes every test that
  # spawns the binary fail: 9 phantom failures in --test cli against a HEAD that
  # passes 27/27 without it.
  #
  # The gate below RECORDS what it can see and then FAILS, so verified-push
  # refuses and never reaches its push. An earlier version of this case set only
  # SWARM_GATE_CMD and asked the gate whether ORACLEMCP_GATE_CMD was set -- it
  # read "unset" whether or not the runner leaked, and passed against a
  # deliberately re-broken runner. The variable must actually be SET for the
  # question to mean anything.
  # RUN IT INSIDE THE THROWAWAY REPO. verified-push writes its verdict to the
  # git common dir of whatever repository it runs in, so invoking it here in the
  # REAL checkout made the selftest overwrite this repository's gate verdict with
  # a fabricated failing one for HEAD — a verdict that misrepresents, which is
  # the exact thing the stale-verdict check below exists to prevent. A test must
  # not forge the evidence its own subject is judged by.
  local observed="$work/gate-env-observed"
  ( cd "$work" \
      && ORACLEMCP_GATE_CMD="printf %s \"\${ORACLEMCP_GATE_CMD-ABSENT}\" >'$observed'; false" \
         bash "$ROOT/scripts/swarm_discipline.sh" verified-push -- origin HEAD ) >/dev/null 2>&1 || true
  [[ -f "$observed" ]] || die "selftest: the gate never ran, so its environment proves nothing"
  [[ "$(cat "$observed")" == "ABSENT" ]] \
    || die "selftest: the gate saw ORACLEMCP_GATE_CMD=$(cat "$observed"); the runner leaks its own config into the gate"
  printf 'PASS selftest: the gate subprocess cannot see the runner own config variable\n'

  # A STALE VERDICT MUST NOT READ AS A VERDICT. An absent one blocks safely --
  # the reader knows nothing was gated. One naming a DIFFERENT commit looks
  # present and says "pass", which is how a push happens on evidence that was
  # never about the code being pushed. Both directions are checked, because a
  # gate_verdict that refused everything would be equally useless.
  local verdict_repo verdict_file verdict_head
  verdict_repo="$work"
  verdict_file="$(git -C "$verdict_repo" rev-parse --path-format=absolute --git-common-dir)/oraclemcp-gate-verdict.json"
  verdict_head="$(git -C "$verdict_repo" rev-parse HEAD)"

  # ABSENT: no verdict file at all must be refused and must name the candidate
  # SHA, not print a generic "no verdict yet" that hides which commit went
  # ungated.
  rm -f "$verdict_file"
  local absent_out=""
  status=0
  absent_out="$(cd "$verdict_repo" && bash "$ROOT/scripts/swarm_discipline.sh" gate-verdict 2>&1)" || status=$?
  (( status == 65 )) || die "selftest: an ABSENT verdict was accepted (exit $status); nothing was gated, so nothing may read as a verdict"
  [[ "$absent_out" == *"no verdict recorded for ${verdict_head:0:12}"* ]] \
    || die "selftest: the absent-verdict refusal did not name the candidate SHA: $absent_out"
  printf 'PASS selftest: an absent verdict is refused and names the candidate SHA\n'

  write_verdict "$verdict_file" "$verdict_head" 'true' pass 0 't0' 't1'
  status=0
  ( cd "$verdict_repo" && bash "$ROOT/scripts/swarm_discipline.sh" gate-verdict ) >/dev/null 2>&1 || status=$?
  (( status == 0 )) || die "selftest: a verdict recorded AT HEAD was refused (exit $status)"
  printf 'PASS selftest: a verdict whose sha is HEAD is accepted\n'

  # MATCHING-FAIL: a verdict at HEAD that is a failure must be refused. A gate
  # that printed a failure is a failure regardless of how a later push went;
  # surfacing it as exit 0 would let an agent push on a gate that never passed.
  write_verdict "$verdict_file" "$verdict_head" 'false' fail 1 't0' 't1'
  local fail_out=""
  status=0
  fail_out="$(cd "$verdict_repo" && bash "$ROOT/scripts/swarm_discipline.sh" gate-verdict 2>&1)" || status=$?
  (( status == 65 )) || die "selftest: a matching FAIL verdict was accepted (exit $status); a gate that printed a failure is a failure"
  [[ "$fail_out" == *"not pass"* ]] \
    || die "selftest: the matching-fail refusal did not say the verdict is not pass: $fail_out"
  printf 'PASS selftest: a matching verdict that is a failure is refused\n'

  # STALE/MISMATCHED: a verdict for a different SHA must be refused, reported as
  # "no verdict recorded for <candidate>", and name BOTH the candidate and the
  # record SHA so the reader sees which commit was actually gated.
  local other_sha
  other_sha="$(printf '0%.0s' {1..40})"
  write_verdict "$verdict_file" "$other_sha" 'true' pass 0 't0' 't1'
  local stale_out=""
  status=0
  stale_out="$(cd "$verdict_repo" && bash "$ROOT/scripts/swarm_discipline.sh" gate-verdict 2>&1)" || status=$?
  (( status == 65 )) || die "selftest: a verdict for a DIFFERENT sha was accepted (exit $status); a stale verdict must never read as a verdict"
  [[ "$stale_out" == *"no verdict recorded for ${verdict_head:0:12}"* ]] \
    || die "selftest: the stale-verdict refusal did not name the candidate SHA: $stale_out"
  [[ "$stale_out" == *"${other_sha:0:12}"* ]] \
    || die "selftest: the stale-verdict refusal did not name the record SHA: $stale_out"
  printf 'PASS selftest: a verdict describing another commit is refused and names both SHAs\n'

  # Rule 17 precision: same-named structs in different modules (oraclemcp-it7iq).
  # Bare-name matching treated every `Ctx { .. }` as the changed `Ctx`, so adding
  # a field to one module's private `Ctx` flagged another module's unrelated
  # private `Ctx` as an orphaned initializer. The check now resolves the changed
  # struct to its defining module and only counts sites that resolve to it.
  git -C "$work" add -A
  git -C "$work" commit -qm "checkpoint before same-named struct fixtures"
  printf '\nmod pa;\nmod pb;\nmod pc;\nmod pd;\n' >>"$work/crates/demo/src/lib.rs"
  cat >"$work/crates/demo/src/pa.rs" <<'RS'
struct Ctx {
    a: u8,
}

fn pa_make() -> Ctx {
    Ctx { a: 1 }
}
RS
  cat >"$work/crates/demo/src/pb.rs" <<'RS'
struct Ctx {
    a: u8,
}

fn pb_make() -> Ctx {
    Ctx { a: 2 }
}
RS
  cat >"$work/crates/demo/src/pc.rs" <<'RS'
pub(crate) struct Ctx {
    a: u8,
}

fn pc_make() -> Ctx {
    Ctx { a: 3 }
}
RS
  cat >"$work/crates/demo/src/pd.rs" <<'RS'
use crate::pc::Ctx;

fn pd_make() -> Ctx {
    Ctx { a: 4 }
}
RS
  git -C "$work" add crates/demo/src/lib.rs crates/demo/src/pa.rs \
    crates/demo/src/pb.rs crates/demo/src/pc.rs crates/demo/src/pd.rs
  git -C "$work" commit -qm "two same-named private structs and one imported"

  # Positive: add `b` to pb's private Ctx and update pb's own literal. pa's
  # untouched literal is a DIFFERENT private Ctx and must not be flagged.
  "$PYTHON_BIN" - "$work/crates/demo/src/pb.rs" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
assert "struct Ctx {\n    a: u8,\n}" in text, text
text = text.replace("struct Ctx {\n    a: u8,\n}", "struct Ctx {\n    a: u8,\n    b: u8,\n}")
assert "Ctx { a: 2 }" in text, text
text = text.replace("Ctx { a: 2 }", "Ctx { a: 2, b: 2 }")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
  git -C "$work" add crates/demo/src/pb.rs
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged ) >/dev/null 2>&1 \
    || status=$?
  (( status == 0 )) || die "selftest: a field in one same-named private struct flagged another module's literals (exit $status)"
  printf 'PASS selftest: a same-named private struct in another module is not an orphaned initializer\n'

  git -C "$work" commit -qm "field b in pb::Ctx"

  # Negative: add `c` to pc's pub(crate) Ctx, update pc's own literal, but leave
  # pd's imported literal of the CHANGED struct un-updated. It must still refuse,
  # and it must not name the unrelated private pa/pb literals.
  "$PYTHON_BIN" - "$work/crates/demo/src/pc.rs" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
assert "struct Ctx {\n    a: u8,\n}" in text, text
text = text.replace("struct Ctx {\n    a: u8,\n}", "struct Ctx {\n    a: u8,\n    c: u8,\n}")
assert "Ctx { a: 3 }" in text, text
text = text.replace("Ctx { a: 3 }", "Ctx { a: 3, c: 3 }")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
  git -C "$work" add crates/demo/src/pc.rs
  status=0
  report="$( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged 2>&1 )" \
    || status=$?
  (( status == 65 )) || die "selftest: an un-updated imported literal of the changed struct was accepted (exit $status)"
  [[ "$report" == *"pd.rs:4"* ]] || die "selftest: the imported orphan in pd.rs was not reported: $report"
  [[ "$report" != *"pa.rs"* && "$report" != *"pb.rs"* ]] \
    || die "selftest: an unrelated same-named private struct was reported: $report"
  printf 'PASS selftest: an un-updated literal of the changed struct is still refused; unrelated same-named ones are not\n'

  "$PYTHON_BIN" - "$work/crates/demo/src/pd.rs" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
assert "Ctx { a: 4 }" in text, text
text = text.replace("Ctx { a: 4 }", "Ctx { a: 4, c: 4 }")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
  git -C "$work" add crates/demo/src/pd.rs
  status=0
  ( cd "$work" && bash "$ROOT/scripts/swarm_discipline.sh" struct-atomicity --staged ) >/dev/null 2>&1 \
    || status=$?
  (( status == 0 )) || die "selftest: a complete cross-module change was refused (exit $status)"
  printf 'PASS selftest: a qualified/imported initializer of the changed struct is still counted\n'
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
  stale-delete-check) stale_delete_check "${@:2}" ;;
  --selftest) selftest ;;
  -h|--help) usage ;;
  *)
    usage >&2
    exit 64
    ;;
esac
