#!/usr/bin/env python3
"""Read-only audit of bead close evidence.

READ-ONLY, and that is a design constraint, not a disclaimer: this command never
writes a bead, never closes or reopens anything, and never touches a file. An
auditor that can change the thing it audits is not an auditor. `--template` is
the one exception and it only prints to stdout.

What it audits
--------------
Closes that carry a bead-close-evidence/v1 document under
tests/artifacts/evidence/closes/<bead-id>.json get the full check: the document
must satisfy the contract, its proof references must exist on disk, and every
SHA it cites must be a real commit in this repository.

Pre-charter closes that carry no document are reported as UNEVIDENCED. They are
not failures: retroactively failing hundreds of closes would only teach people to
ignore the audit. Post-charter closes require evidence, and a CI floor makes the
legacy evidence count a one-way ratchet.

Two tiers, kept apart on purpose
--------------------------------
  hard      Structural, exit non-zero. Every check is decidable: a document
            either satisfies the schema or does not; a SHA either resolves or
            does not.
  advisory  Historical topology and free-text heuristics that cannot be made
            reliable. Post-charter bindings and an explicit false-close comment
            are deterministic controls and therefore remain hard findings.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
CLOSES_DIR = ROOT / "tests" / "artifacts" / "evidence" / "closes"
LOCAL_REPOSITORY = "oraclemcp"
TRACKER_JSONL = ROOT / ".beads" / "issues.jsonl"
PAGE_SIZE = 200
UTC = timezone.utc

# The tracker charter was adopted at this UTC instant. Historical closes remain
# visible in the coverage denominator, while closes at or after the epoch must
# satisfy the landed-evidence controls below. This is deliberately an instant,
# not a local date, so agents in different time zones select the same records.
HARDENING_EPOCH_TEXT = "2026-07-18T20:00:00Z"
HARDENING_EPOCH = datetime(2026, 7, 18, 20, 0, tzinfo=UTC)

_spec = importlib.util.spec_from_file_location(
    "validate_evidence", ROOT / "scripts" / "validate_evidence.py"
)
_ve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ve)

# A bare 7-40 hex run. Deliberately loose; every hit is treated as advisory only.
_SHA_RE = re.compile(r"\b([0-9a-f]{7,40})\b")

# Claims that assert behaviour against something real and external. If a close
# says one of these, the reader is entitled to an artifact.
_LIVE_CLAIM_RE = re.compile(
    r"\b(live|end-to-end|e2e|23ai|21c|18c|against the (database|server)|"
    r"real (database|server))\b",
    re.I,
)
_SELF_SKIPPING_RE = re.compile(
    r"self[- ]skipp|#\[ignore\]|ignored test|skips? when (?:the )?(?:database|server)",
    re.I,
)
_FALSE_CLOSE_DISCOVERY_RE = re.compile(
    r"(?:prior|original|previous) close (?:is|was) false|false[- ]close|"
    r"close claim (?:is|was) (?:false|incorrect)|incorrectly closed",
    re.I,
)
_FALSE_CLOSE_NEGATION_RE = re.compile(r"\bno false[- ]closes?\b|correctly closed", re.I)
_FALSE_CLOSE_CORRECTION_RE = re.compile(
    r"false[- ]close corrected|(?:claim|close) (?:retracted|corrected|superseded)|"
    r"not (?:live[- ]|end[- ]to[- ]end )?verified|previous claim was incorrect",
    re.I,
)
_BEAD_TRAILER_RE = re.compile(r"^Bead:\s*(\S+)\s*$", re.M)
_RUST_TEST_TRACE_RE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.rs)"
    r"(?:::(?P<test>[A-Za-z_][A-Za-z0-9_]*))?"
)


class AuditInputError(RuntimeError):
    """The tracker could not be enumerated without guessing."""


class Finding:
    def __init__(self, tier: str, bead: str, code: str, message: str) -> None:
        self.tier = tier
        self.bead = bead
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"[{self.tier}] {self.bead}: {self.code} — {self.message}"


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False
    )


def _commit_exists(sha: str) -> bool:
    return _git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def _is_ancestor_of_head(sha: str) -> bool:
    return _git("merge-base", "--is-ancestor", sha, "HEAD").returncode == 0


def _commit_message(sha: str) -> str:
    return _git("show", "-s", "--format=%B", sha).stdout


def _default_br_runner(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, check=False, cwd=ROOT
    )


def _validated_issue_list(value: object, source: str) -> list[dict]:
    if not isinstance(value, list):
        raise AuditInputError(f"{source}: expected an issues array")
    issues: list[dict] = []
    for index, issue in enumerate(value):
        if not isinstance(issue, dict):
            raise AuditInputError(f"{source}: issue {index} is not an object")
        bead_id = issue.get("id")
        if not isinstance(bead_id, str) or not bead_id.strip():
            raise AuditInputError(
                f"{source}: issue {index} has no non-empty string id"
            )
        issues.append(issue)
    return issues


def _validated_bulk_ids(payload: object, source: str) -> list[str]:
    """Validate a complete `br --json` capture before any bulk mutation."""
    if not isinstance(payload, dict):
        raise AuditInputError(f"{source}: expected the paginated br object shape")
    issues = _validated_issue_list(payload.get("issues"), source)
    has_more = payload.get("has_more")
    total = payload.get("total")
    if has_more is not False:
        raise AuditInputError(
            f"{source}: capture is incomplete (has_more must be false; use --limit 0)"
        )
    if not isinstance(total, int) or total != len(issues):
        raise AuditInputError(
            f"{source}: total {total!r} does not match {len(issues)} captured issues"
        )
    ids = [issue["id"] for issue in issues]
    if len(set(ids)) != len(ids):
        raise AuditInputError(f"{source}: duplicate issue IDs in bulk capture")
    return ids


def validate_id_capture(path_text: str) -> int:
    source = "stdin" if path_text == "-" else path_text
    try:
        raw = sys.stdin.read() if path_text == "-" else Path(path_text).read_text()
        payload = json.loads(raw)
        ids = _validated_bulk_ids(payload, source)
    except (OSError, json.JSONDecodeError, AuditInputError) as exc:
        print(f"audit: invalid bulk ID capture: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"count": len(ids), "ids": ids}, separators=(",", ":")))
    return 0


def _br_all_beads(
    runner: Callable[[list[str]], subprocess.CompletedProcess] = _default_br_runner,
) -> list[dict]:
    """Enumerate every status, validating JSON IDs and exhausting pagination."""
    issues: list[dict] = []
    seen: set[str] = set()
    offset = 0
    expected_total: int | None = None

    while True:
        args = [
            "br",
            "list",
            "--all",
            "--deferred",
            "--json",
            "--limit",
            str(PAGE_SIZE),
            "--offset",
            str(offset),
        ]
        out = runner(args)
        if out.returncode != 0:
            raise AuditInputError(f"br list failed: {out.stderr.strip()}")
        try:
            payload = json.loads(out.stdout)
        except json.JSONDecodeError as exc:
            raise AuditInputError(f"br list emitted malformed JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AuditInputError("br list must emit the paginated object shape")

        page = _validated_issue_list(payload.get("issues"), f"br offset {offset}")
        total = payload.get("total")
        has_more = payload.get("has_more")
        page_offset = payload.get("offset")
        if not isinstance(total, int) or total < 0:
            raise AuditInputError(f"br offset {offset}: invalid total")
        if not isinstance(has_more, bool):
            raise AuditInputError(f"br offset {offset}: invalid has_more")
        if page_offset != offset:
            raise AuditInputError(
                f"br offset {offset}: response reports offset {page_offset!r}"
            )
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise AuditInputError(
                f"br total changed during pagination: {expected_total} -> {total}"
            )

        for issue in page:
            bead_id = issue["id"]
            if bead_id in seen:
                raise AuditInputError(
                    f"br pagination returned duplicate issue id {bead_id!r}"
                )
            seen.add(bead_id)
            issues.append(issue)

        if not has_more:
            break
        if not page:
            raise AuditInputError("br pagination reports has_more with an empty page")
        offset += len(page)

    if expected_total != len(issues):
        raise AuditInputError(
            f"br pagination captured {len(issues)} ids, expected {expected_total}"
        )
    return issues


def _jsonl_all_beads(path: Path) -> list[dict]:
    """Read the checked-in tracker snapshot for CI hosts that do not install br."""
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise AuditInputError(f"cannot read tracker JSONL {path}: {exc}") from exc

    issues: list[dict] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditInputError(
                f"{path}:{line_number}: malformed JSON: {exc}"
            ) from exc
        issue = _validated_issue_list([value], f"{path}:{line_number}")[0]
        if issue["id"] in seen:
            raise AuditInputError(
                f"{path}:{line_number}: duplicate issue id {issue['id']!r}"
            )
        seen.add(issue["id"])
        issues.append(issue)
    return issues


def _all_beads(tracker_jsonl: Path | None = None) -> list[dict]:
    if tracker_jsonl is not None:
        resolved = tracker_jsonl if tracker_jsonl.is_absolute() else ROOT / tracker_jsonl
        return _jsonl_all_beads(resolved)
    if not shutil.which("br"):
        return _jsonl_all_beads(TRACKER_JSONL)

    issues = _br_all_beads()
    # `br list` intentionally omits comments and full dependency records. Merge
    # those read-only fields from the checked-in snapshot when it is available;
    # status and close reason always remain the live database values.
    if TRACKER_JSONL.exists():
        snapshot = {issue["id"]: issue for issue in _jsonl_all_beads(TRACKER_JSONL)}
        live_ids = {issue["id"] for issue in issues}
        snapshot_ids = set(snapshot)
        stale = [
            issue["id"]
            for issue in issues
            if issue["id"] in snapshot
            and issue.get("updated_at") != snapshot[issue["id"]].get("updated_at")
        ]
        if live_ids != snapshot_ids or stale:
            raise AuditInputError(
                "live br state and .beads/issues.jsonl differ; run "
                "`br sync --flush-only` before auditing "
                f"(live_only={len(live_ids - snapshot_ids)}, "
                f"snapshot_only={len(snapshot_ids - live_ids)}, stale={len(stale)})"
            )
        for issue in issues:
            stored = snapshot.get(issue["id"], {})
            for key in ("comments", "dependencies", "parent"):
                if key not in issue and key in stored:
                    issue[key] = stored[key]
    return issues


def _parse_utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuditInputError(f"{field}: expected an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditInputError(f"{field}: invalid RFC3339 timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AuditInputError(f"{field}: timestamp must use explicit UTC")
    return parsed.astimezone(UTC)


def _is_hardened_close(bead: dict) -> bool:
    if bead.get("status") != "closed":
        return False
    if _is_historical_false_close_correction(bead):
        return False
    try:
        closed_at = _parse_utc_timestamp(
            bead.get("closed_at"), f"{bead['id']}.closed_at"
        )
    except AuditInputError:
        return False
    return closed_at >= HARDENING_EPOCH


def _is_post_charter_issue(bead: dict) -> bool:
    try:
        created_at = _parse_utc_timestamp(
            bead.get("created_at"), f"{bead['id']}.created_at"
        )
    except AuditInputError:
        return False
    return created_at >= HARDENING_EPOCH


def _reason_of(bead: dict) -> str:
    for key in ("close_reason", "reason", "resolution"):
        if bead.get(key):
            return str(bead[key])
    return ""


def _false_close_discoveries(bead: dict) -> list[str]:
    return [
        str(comment.get("text", ""))
        for comment in (bead.get("comments") or [])
        if isinstance(comment, dict)
        and _FALSE_CLOSE_DISCOVERY_RE.search(str(comment.get("text", "")))
        and not _FALSE_CLOSE_NEGATION_RE.search(str(comment.get("text", "")))
    ]


def _is_historical_false_close_correction(bead: dict) -> bool:
    """A tracker-only correction is not a new delivery requiring source paths."""
    try:
        created_at = _parse_utc_timestamp(
            bead.get("created_at"), f"{bead['id']}.created_at"
        )
    except AuditInputError:
        return False
    reason = _reason_of(bead)
    return (
        created_at < HARDENING_EPOCH
        and bool(_false_close_discoveries(bead))
        and bool(_FALSE_CLOSE_CORRECTION_RE.search(reason))
        and bool(_SHA_RE.search(reason))
        and bool(re.search(r"\brun\s+[0-9]+\b", reason, re.I))
    )


def _timestamp_findings(bead: dict) -> list:
    findings: list = []
    for field in ("created_at", "updated_at"):
        if bead.get(field) is None:
            continue
        try:
            _parse_utc_timestamp(bead[field], f"{bead['id']}.{field}")
        except AuditInputError as exc:
            findings.append(
                Finding("hard", bead["id"], "TRACKER_TIMESTAMP_NOT_UTC", str(exc))
            )
    if bead.get("status") == "closed":
        try:
            _parse_utc_timestamp(bead.get("closed_at"), f"{bead['id']}.closed_at")
        except AuditInputError as exc:
            findings.append(
                Finding("hard", bead["id"], "TRACKER_TIMESTAMP_NOT_UTC", str(exc))
            )
    return findings


def _false_close_findings(bead: dict) -> list:
    """Require the original close claim to acknowledge a discovered false-close."""
    discoveries = _false_close_discoveries(bead)
    if not discoveries:
        return []
    reason = _reason_of(bead)
    if _FALSE_CLOSE_CORRECTION_RE.search(reason):
        return []
    return [
        Finding(
            "hard",
            bead["id"],
            "ORIGINAL_FALSE_CLOSE_UNCORRECTED",
            "a tracker comment establishes that this close was false, but the "
            "original close_reason still makes the uncorrected claim",
        )
    ]


def _dependency_parts(dependency: dict) -> tuple[str | None, str | None]:
    target = dependency.get("depends_on_id") or dependency.get("id")
    kind = dependency.get("type") or dependency.get("dependency_type")
    return (
        target if isinstance(target, str) else None,
        kind if isinstance(kind, str) else None,
    )


def _umbrella_findings(beads: list[dict]) -> list:
    """Catch umbrella/leaf topology that hides or re-blocks unfinished leaves."""
    by_id = {bead["id"]: bead for bead in beads}
    children: dict[str, list[dict]] = {}
    findings: list = []
    terminal = {"closed", "tombstone"}

    for bead in beads:
        for dependency in bead.get("dependencies") or []:
            if not isinstance(dependency, dict):
                continue
            target, kind = _dependency_parts(dependency)
            if target is None:
                continue
            if kind == "parent-child":
                children.setdefault(target, []).append(bead)
            elif (
                bead.get("issue_type") != "epic"
                and target in by_id
                and by_id[target].get("issue_type") == "epic"
                and by_id[target].get("status") not in terminal
                and bead.get("status") not in terminal
            ):
                findings.append(
                    Finding(
                        "hard"
                        if _is_post_charter_issue(bead)
                        or _is_hardened_close(by_id[target])
                        else "advisory",
                        bead["id"],
                        "LEAF_BLOCKED_BY_UMBRELLA",
                        f"leaf has ordinary {kind or 'unknown'} dependency on umbrella {target}; "
                        "use parent-child topology and put real prerequisites on leaves",
                    )
                )

    for parent_id, leaves in children.items():
        parent = by_id.get(parent_id)
        if parent is None or parent.get("status") not in terminal:
            continue
        unfinished = sorted(
            leaf["id"] for leaf in leaves if leaf.get("status") not in terminal
        )
        if unfinished:
            findings.append(
                Finding(
                    "hard" if _is_hardened_close(parent) else "advisory",
                    parent_id,
                    "UMBRELLA_CLOSED_WITH_OPEN_LEAVES",
                    f"umbrella is terminal while leaves remain non-terminal: "
                    f"{', '.join(unfinished[:8])}",
                )
            )
    return findings


def _scan_reason(bead: dict) -> list:
    """Advisory heuristics over a free-text close reason.

    Never hard. A close reason legitimately cites SHAs this repository does not
    contain -- upstream python-oracledb commits, for one (etib.2 cites
    6cfd00aa642e, an upstream reference that will never resolve here). Failing on
    an unresolvable SHA would flag correct closes, so this reports and moves on.
    """
    findings: list = []
    bead_id = bead["id"]
    reason = _reason_of(bead)
    if not reason:
        return findings

    shas = [s for s in _SHA_RE.findall(reason) if not s.isdigit()]
    unresolvable = [s for s in shas if not _commit_exists(s)]
    if unresolvable:
        findings.append(
            Finding(
                "advisory",
                bead_id,
                "CITED_SHA_UNRESOLVABLE",
                f"close cites {', '.join(unresolvable)}, which do not resolve to a "
                "commit here (may be an upstream reference, or may be fabricated)",
            )
        )

    if _LIVE_CLAIM_RE.search(reason) and not shas:
        findings.append(
            Finding(
                "advisory",
                bead_id,
                "LIVE_CLAIM_WITHOUT_REFERENCE",
                "close makes a live/end-to-end claim but cites no commit or artifact",
            )
        )
    return findings


def _scope_pathspecs(doc: dict) -> list[str]:
    pathspecs: list[str] = []
    for item in doc["scope"]["in_scope"]:
        if not item.startswith("path:"):
            continue
        pathspec = item.removeprefix("path:").strip()
        if pathspec:
            pathspecs.append(pathspec)
    return pathspecs


def _safe_repo_pathspec(pathspec: str) -> bool:
    path = Path(pathspec)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and not pathspec.startswith(":")
        and "\x00" not in pathspec
    )


def _pathspec_is_clean(pathspec: str) -> bool:
    result = _git(
        "status", "--porcelain=v1", "--untracked-files=all", "--", pathspec
    )
    return result.returncode == 0 and not result.stdout.strip()


def _pathspec_is_landed(source_sha: str, pathspec: str) -> bool:
    result = _git("ls-tree", "-r", "--name-only", source_sha, "--", pathspec)
    return result.returncode == 0 and bool(result.stdout.strip())


def _reason_binds_sha(reason: str, sha: str) -> bool:
    return any(sha.startswith(token) for token in _SHA_RE.findall(reason))


def _has_bead_trailer(message: str, bead_id: str) -> bool:
    return bead_id in _BEAD_TRAILER_RE.findall(message)


def _live_run_ids(doc: dict) -> list[str]:
    run_id = doc["live_evidence"].get("run_id")
    return [run_id] if isinstance(run_id, str) and run_id.strip() else []


def _ignored_test_traces(doc: dict) -> list[str]:
    ignored: list[str] = []
    for entry in doc["integration_evidence"]["entry_points"]:
        trace = entry["trace"]
        for match in _RUST_TEST_TRACE_RE.finditer(trace):
            path_text = match.group("path")
            test_name = match.group("test")
            if test_name is None or not _safe_repo_pathspec(path_text):
                continue
            try:
                lines = (ROOT / path_text).read_text().splitlines()
            except OSError:
                continue
            function_re = re.compile(rf"\bfn\s+{re.escape(test_name)}\b")
            for index, line in enumerate(lines):
                if not function_re.search(line):
                    continue
                attributes = "\n".join(lines[max(0, index - 12) : index])
                if re.search(r"#\s*\[\s*ignore\b", attributes):
                    ignored.append(f"{path_text}::{test_name}")
                break
    return sorted(set(ignored))


def _live_claim_findings(bead_id: str, reason: str, doc: dict) -> list:
    findings: list = []
    live_claim = bool(_LIVE_CLAIM_RE.search(reason)) or doc["live_evidence"][
        "claimed"
    ]
    run_ids = _live_run_ids(doc)
    if live_claim and not doc["live_evidence"]["claimed"]:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_CLAIM_NOT_DECLARED",
                "close_reason makes a live/e2e claim but live_evidence.claimed is false",
            )
        )
    if doc["live_evidence"]["claimed"]:
        live_evidence = doc["live_evidence"]
        if not live_evidence.get("run_id") or not live_evidence.get("lane"):
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "LIVE_ARTIFACT_WITHOUT_SCHEDULED_RUN",
                    "live_evidence must bind its artifacts to both lane and run_id",
                )
            )
    proof_text = "\n".join(
        [reason, doc["scope"]["summary"]]
        + [entry["trace"] for entry in doc["integration_evidence"]["entry_points"]]
    )
    ignored_traces = _ignored_test_traces(doc)
    if (_SELF_SKIPPING_RE.search(proof_text) or ignored_traces) and not run_ids:
        detail = f" ({', '.join(ignored_traces)})" if ignored_traces else ""
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SELF_SKIPPING_TEST_IS_SOLE_PROOF",
                "ignored/self-skipping live test is cited without a scheduled-lane "
                f"run_id and artifact{detail}",
            )
        )
    return findings


def _hardened_document_findings(bead: dict, doc: dict) -> list:
    """Post-charter controls: landed source, clean scope, trailer and live proof."""
    findings: list = []
    bead_id = bead["id"]
    source_sha = doc["source"]["sha"]
    reason = _reason_of(bead)

    if not _is_ancestor_of_head(source_sha):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SOURCE_NOT_LANDED",
                f"source commit {source_sha} is not an ancestor of HEAD",
            )
        )
    if not _reason_binds_sha(reason, source_sha):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "CLOSE_REASON_NOT_BOUND_TO_COMMIT",
                "close_reason must record the evidence source commit (full SHA or "
                "an unambiguous 7+ character prefix)",
            )
        )
    if not _has_bead_trailer(_commit_message(source_sha), bead_id):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "BEAD_TRAILER_ABSENT",
                f"source commit {source_sha} lacks exact trailer 'Bead: {bead_id}'",
            )
        )

    pathspecs = _scope_pathspecs(doc)
    if not pathspecs:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SCOPE_PATHS_ABSENT",
                "post-charter evidence must include at least one in_scope entry "
                "of the form 'path:<repository-relative pathspec>'",
            )
        )
    for pathspec in pathspecs:
        if not _safe_repo_pathspec(pathspec):
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "UNSAFE_SCOPE_PATH",
                    f"scope pathspec {pathspec!r} is absolute, magic, or escapes the repo",
                )
            )
            continue
        if not _pathspec_is_landed(source_sha, pathspec):
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "SCOPE_PATH_NOT_LANDED",
                    f"scope pathspec {pathspec!r} matches no path in source.sha",
                )
            )
        if not _pathspec_is_clean(pathspec):
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "SCOPE_PATH_DIRTY",
                    f"scope pathspec {pathspec!r} has uncommitted changes at HEAD",
                )
            )

    findings.extend(_live_claim_findings(bead_id, reason, doc))
    return findings


def _audit_document_payload(
    bead_id: str, doc: dict, bead: dict | None = None
) -> list:
    """Hard checks on one parsed bead-close-evidence/v1 document."""
    findings: list = []

    for f in _ve.validate_doc(doc):
        findings.append(
            Finding("hard", bead_id, f.code, f"{f.path or '/'}: {f.message}")
        )
    if findings:
        # The contract rejected it; deeper checks would index into a document
        # that is not the shape they assume.
        return findings

    if doc["repo"] != LOCAL_REPOSITORY:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "E_REPO_MISMATCH",
                f"close evidence declares repo {doc['repo']!r}, expected {LOCAL_REPOSITORY!r}",
            )
        )

    if doc["bead_id"] != bead_id:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "BEAD_ID_MISMATCH",
                f"file is named {bead_id}.json but declares {doc['bead_id']!r}",
            )
        )

    source_exists = _commit_exists(doc["source"]["sha"])
    if not source_exists:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SOURCE_SHA_ABSENT",
                f"{doc['source']['sha']} is not a commit in this repository",
            )
        )

    if source_exists and not _is_ancestor_of_head(doc["source"]["sha"]):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SOURCE_SHA_NOT_AT_HEAD",
                f"{doc['source']['sha']} exists but is not landed in HEAD ancestry",
            )
        )

    try:
        _parse_utc_timestamp(doc["generated_at"], f"{bead_id}.generated_at")
    except AuditInputError as exc:
        findings.append(Finding("hard", bead_id, "E_TIMESTAMP_NOT_UTC", str(exc)))

    for proof in doc["proofs"]:
        if not (ROOT / proof["path"]).exists():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "PROOF_ARTIFACT_ABSENT",
                    f"{proof['schema']} references {proof['path']}, which is not on disk",
                )
            )

    for artifact in doc["live_evidence"]["artifacts"]:
        if not (ROOT / artifact["path"]).exists():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "LIVE_ARTIFACT_ABSENT",
                    f"live claim references {artifact['path']}, which is not on disk",
                )
            )

    if bead is not None and _is_hardened_close(bead) and source_exists:
        findings.extend(_hardened_document_findings(bead, doc))

    return findings


def _audit_document(path: Path, bead: dict | None = None) -> list:
    """Load and hard-check one bead-close-evidence/v1 document."""
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [Finding("hard", path.stem, "MALFORMED_JSON", str(exc))]
    return _audit_document_payload(path.stem, doc, bead)


def self_test() -> int:
    """Exercise paging, ID capture, UTC, false-close and commit binding logic."""
    failures: list[str] = []

    pages = {
        0: {
            "issues": [{"id": "a"}, {"id": "b"}],
            "total": 3,
            "limit": PAGE_SIZE,
            "offset": 0,
            "has_more": True,
        },
        2: {
            "issues": [{"id": "c"}],
            "total": 3,
            "limit": PAGE_SIZE,
            "offset": 2,
            "has_more": False,
        },
    }
    calls: list[list[str]] = []

    def page_runner(args: list[str]) -> subprocess.CompletedProcess:
        calls.append(args)
        offset = int(args[args.index("--offset") + 1])
        return subprocess.CompletedProcess(args, 0, json.dumps(pages[offset]), "")

    captured = _br_all_beads(page_runner)
    if [issue["id"] for issue in captured] != ["a", "b", "c"]:
        failures.append("pagination did not capture all IDs in order")
    if not all("--all" in call and "--deferred" in call for call in calls):
        failures.append("pagination did not request explicit all-status results")

    duplicate = {
        "issues": [{"id": "a"}, {"id": "a"}],
        "total": 2,
        "limit": PAGE_SIZE,
        "offset": 0,
        "has_more": False,
    }
    try:
        _br_all_beads(
            lambda args: subprocess.CompletedProcess(
                args, 0, json.dumps(duplicate), ""
            )
        )
    except AuditInputError:
        pass
    else:
        failures.append("duplicate JSON ID capture was accepted")
    complete_capture = {
        "issues": [{"id": "a"}, {"id": "b"}],
        "total": 2,
        "has_more": False,
    }
    if _validated_bulk_ids(complete_capture, "self-test") != ["a", "b"]:
        failures.append("complete bulk ID capture was not preserved exactly")
    complete_capture["has_more"] = True
    try:
        _validated_bulk_ids(complete_capture, "self-test")
    except AuditInputError:
        pass
    else:
        failures.append("incomplete bulk ID capture was accepted")

    for invalid in ("2026-07-18T20:00:00", "2026-07-18T22:00:00+02:00"):
        try:
            _parse_utc_timestamp(invalid, "self-test")
        except AuditInputError:
            pass
        else:
            failures.append(f"non-UTC timestamp {invalid!r} was accepted")

    false_bead = {
        "id": "tracker-false-close",
        "close_reason": "Verified end-to-end.",
        "comments": [{"text": "The prior close is false; live proof failed."}],
    }
    if not _false_close_findings(false_bead):
        failures.append("original false-close was not detected")
    false_bead["close_reason"] = "Previous claim was incorrect; not live verified."
    if _false_close_findings(false_bead):
        failures.append("corrected original close_reason was rejected")
    false_bead["close_reason"] = "Release completed."
    false_bead["comments"] = [{"text": "Audit found no false-closes."}]
    if _false_close_findings(false_bead):
        failures.append("negated false-close text produced a finding")

    if not _has_bead_trailer("Subject\n\nBead: tracker-1\n", "tracker-1"):
        failures.append("exact Bead trailer was not recognized")
    if _has_bead_trailer("Subject (tracker-1)\n", "tracker-1"):
        failures.append("subject mention was accepted as a Bead trailer")
    sample_sha = "0123456789abcdef0123456789abcdef01234567"
    if not _reason_binds_sha("landed in 0123456", sample_sha):
        failures.append("close_reason SHA prefix was not bound to source commit")
    if _reason_binds_sha("landed in fedcba9", sample_sha):
        failures.append("unrelated close_reason SHA was bound to source commit")
    if _safe_repo_pathspec("../outside") or _safe_repo_pathspec("/absolute"):
        failures.append("escaping scope pathspec was accepted")

    parent = {
        "id": "tracker-epic",
        "issue_type": "epic",
        "status": "closed",
        "created_at": HARDENING_EPOCH_TEXT,
        "closed_at": HARDENING_EPOCH_TEXT,
    }
    leaf = {
        "id": "tracker-leaf",
        "issue_type": "task",
        "status": "open",
        "created_at": HARDENING_EPOCH_TEXT,
        "dependencies": [
            {"depends_on_id": "tracker-epic", "type": "parent-child"}
        ],
    }
    umbrella_codes = {finding.code for finding in _umbrella_findings([parent, leaf])}
    if "UMBRELLA_CLOSED_WITH_OPEN_LEAVES" not in umbrella_codes:
        failures.append("closed umbrella with open leaf was not detected")

    fixture = (
        ROOT
        / "schemas"
        / "evidence"
        / "fixtures"
        / "valid"
        / "bead-close-evidence.json"
    )
    foreign_doc = json.loads(fixture.read_text())
    run_doc = json.loads(json.dumps(foreign_doc))
    run_doc["live_evidence"].update(
        {"lane": "scheduled-oracle-matrix", "run_id": "gh-29638451182"}
    )
    if _ve.validate_doc(run_doc):
        failures.append("scheduled lane/run_id extension failed schema validation")
    run_doc["live_evidence"]["run_id"] = "bad id with spaces"
    if not _ve.validate_doc(run_doc):
        failures.append("malformed scheduled run_id passed schema validation")
    live_doc = json.loads(json.dumps(foreign_doc))
    live_doc["integration_evidence"]["entry_points"][0]["trace"] = (
        "crates/oraclemcp-db/tests/multi_lane_live_xe.rs::"
        "live_xe_two_configured_lanes_keep_session_isolation"
    )
    live_codes = {
        finding.code
        for finding in _live_claim_findings(
            "live-self-test", "Verified live database behavior", live_doc
        )
    }
    if not {"LIVE_CLAIM_NOT_DECLARED", "SELF_SKIPPING_TEST_IS_SOLE_PROOF"}.issubset(
        live_codes
    ):
        failures.append("self-skipping live claim was not rejected")
    live_doc["live_evidence"].update(
        {"claimed": True, "lane": "scheduled-oracle-matrix", "run_id": "gh-1"}
    )
    if _live_claim_findings(
        "live-self-test", "Verified live database behavior", live_doc
    ):
        failures.append("scheduled live run did not supersede self-skipping sole proof")
    findings = _audit_document_payload("foreign-close", foreign_doc)
    if not any(f.code == "E_REPO_MISMATCH" for f in findings):
        failures.append("foreign close evidence was accepted")

    if failures:
        for failure in failures:
            print(f"audit: self-test failed: {failure}", file=sys.stderr)
        return 1
    print("audit: self-test passed")
    return 0


TEMPLATE = {
    "schema": "bead-close-evidence/v1",
    "repo": "oraclemcp",
    "generated_at": "REPLACE-WITH-RFC3339-UTC",
    "bead_id": "REPLACE",
    "scope": {
        "summary": "What this close covers, in one sentence.",
        "in_scope": ["path:repository/relative/path actually delivered"],
        "out_of_scope": ["what a reader might assume was done but was not"],
    },
    "source": {"sha": "REPLACE-WITH-40-HEX", "tree_clean": True, "branch": "main"},
    "proofs": [],
    "integration_evidence": {
        "entry_points": [
            {
                "name": "the command or route that reaches this change",
                "kind": "cli",
                "trace": "the test or artifact tracing it to a result",
            }
        ]
    },
    "live_evidence": {"claimed": False, "artifacts": []},
    "limitations": ["State them. Empty means you assert there are none."],
    "known_defects": [],
    "follow_ups": [],
    "readiness": {"claim": "not-ready", "basis": "scoped-test"},
}


def template(bead_id: str) -> int:
    doc = json.loads(json.dumps(TEMPLATE))
    doc["bead_id"] = bead_id
    head = _git("rev-parse", "HEAD").stdout.strip()
    if head:
        doc["source"]["sha"] = head
    doc["source"]["tree_clean"] = not _git("status", "--porcelain").stdout.strip()
    print(json.dumps(doc, indent=2))
    print(
        f"\n# Write to tests/artifacts/evidence/closes/{bead_id}.json, then:\n"
        f"#   scripts/check_bead_close_evidence.sh",
        file=sys.stderr,
    )
    return 0


def audit(
    strict: bool,
    minimum_evidence: int,
    exact_evidence_floor: int | None,
    tracker_jsonl: Path | None,
) -> int:
    beads = _all_beads(tracker_jsonl)
    documents = sorted(CLOSES_DIR.glob("*.json")) if CLOSES_DIR.exists() else []
    evidenced = {p.stem for p in documents}
    by_id = {bead["id"]: bead for bead in beads}
    closed = [bead for bead in beads if bead.get("status") == "closed"]

    findings: list = []
    valid_evidence: set[str] = set()
    for bead in beads:
        findings.extend(_timestamp_findings(bead))
        if bead.get("status") == "closed":
            findings.extend(_false_close_findings(bead))
    findings.extend(_umbrella_findings(beads))

    for path in documents:
        document_findings = _audit_document(path, by_id.get(path.stem))
        findings.extend(document_findings)
        if not any(f.tier == "hard" for f in document_findings):
            valid_evidence.add(path.stem)
    for bead in closed:
        findings.extend(_scan_reason(bead))
        if _is_hardened_close(bead) and bead["id"] not in evidenced:
            findings.append(
                Finding(
                    "hard",
                    bead["id"],
                    "POST_CHARTER_CLOSE_UNEVIDENCED",
                    f"close at or after {HARDENING_EPOCH_TEXT} requires a landed "
                    "bead-close-evidence document",
                )
            )

    closed_ids = {b["id"] for b in closed}
    orphans = sorted(evidenced - closed_ids)
    unevidenced = len(closed_ids - evidenced)
    covered = len(valid_evidence & closed_ids)
    floor = exact_evidence_floor if exact_evidence_floor is not None else minimum_evidence
    if covered < floor:
        findings.append(
            Finding(
                "hard",
                "coverage-ratchet",
                "EVIDENCE_COVERAGE_REGRESSED",
                f"{covered} valid evidenced closes is below floor {floor}",
            )
        )
    elif exact_evidence_floor is not None and covered > exact_evidence_floor:
        findings.append(
            Finding(
                "hard",
                "coverage-ratchet",
                "EVIDENCE_COVERAGE_FLOOR_STALE",
                f"{covered} valid evidenced closes exceeds recorded floor "
                f"{exact_evidence_floor}; raise the CI floor in the same change",
            )
        )

    hard = [f for f in findings if f.tier == "hard"]
    advisory = [f for f in findings if f.tier == "advisory"]

    if hard:
        print("HARD findings (these fail the audit):")
        for f in hard:
            print(f"  {f}")
        print()
    if advisory:
        print(f"Advisory findings ({len(advisory)}, never gating):")
        for f in advisory[:20]:
            print(f"  {f}")
        if len(advisory) > 20:
            print(f"  ... and {len(advisory) - 20} more")
        print()
    if orphans:
        print("Close evidence for beads that are not closed:")
        for bead_id in orphans:
            print(f"  [advisory] {bead_id}: evidence exists but the bead is not closed")
        print()

    print(
        f"audit: {len(beads)} all-status beads, {len(closed_ids)} closed, "
        f"{len(evidenced & closed_ids)} with close evidence ({covered} valid), "
        f"{unevidenced} unevidenced (pre-contract closes are not failures before "
        f"{HARDENING_EPOCH_TEXT}); {len(hard)} hard, "
        f"{len(advisory)} advisory findings"
    )

    if hard:
        return 1
    if strict and unevidenced:
        print(
            f"audit: --strict, and {unevidenced} closed beads carry no evidence",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only audit of bead close evidence.")
    parser.add_argument("--template", metavar="BEAD_ID", help="print a close-evidence skeleton")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic tracker-control tests without reading or writing beads",
    )
    parser.add_argument(
        "--minimum-evidence",
        type=int,
        default=0,
        metavar="COUNT",
        help="fail if fewer than COUNT closed beads have valid evidence",
    )
    parser.add_argument(
        "--exact-evidence-floor",
        type=int,
        metavar="COUNT",
        help="CI ratchet: fail below COUNT and also fail above it until the "
        "checked-in floor is raised",
    )
    parser.add_argument(
        "--tracker-jsonl",
        type=Path,
        metavar="PATH",
        help="enumerate the checked-in all-status JSONL snapshot (CI fallback); "
        "otherwise paginate br to exhaustion",
    )
    parser.add_argument(
        "--validate-id-capture",
        metavar="PATH",
        help="validate a complete `br list --json --limit 0` capture and emit "
        "a machine-readable ID array; use - for stdin",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail when any closed bead has no evidence (not the default: "
        "this repo predates the contract)",
    )
    args = parser.parse_args()

    if args.template:
        return template(args.template)
    if args.self_test:
        return self_test()
    if args.validate_id_capture:
        return validate_id_capture(args.validate_id_capture)
    if args.minimum_evidence < 0:
        parser.error("--minimum-evidence must be non-negative")
    if args.exact_evidence_floor is not None and args.exact_evidence_floor < 0:
        parser.error("--exact-evidence-floor must be non-negative")
    try:
        return audit(
            args.strict,
            args.minimum_evidence,
            args.exact_evidence_floor,
            args.tracker_jsonl,
        )
    except AuditInputError as exc:
        print(f"audit: input error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
