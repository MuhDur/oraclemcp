#!/usr/bin/env python3
"""Read-only audit and pre-close gate for bead evidence.

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

Closes before the enforcement epoch that carry no document are reported as
UNEVIDENCED. Closes at or after the epoch fail without landed evidence and a
machine-readable close-reason binding. The epoch preserves an honest legacy
baseline without leaving new closes advisory forever.

Two tiers, kept apart on purpose
--------------------------------
  hard      Structural, exit non-zero. Every check is decidable: a document
            either satisfies the schema or does not; a SHA either resolves or
            does not.
  advisory  Heuristics over free-text close reasons, reported and never gating.
            Text scanning cannot be made reliable -- see the note on upstream
            SHAs in _scan_reason -- and an audit that cries wolf gets muted,
            which is worse than one that stays quiet.
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
CLOSES_DIR = ROOT / "tests" / "artifacts" / "evidence" / "closes"
LOCAL_REPOSITORY = "oraclemcp"
TRACKER_POLICY = ROOT / ".beads" / "policy.yaml"
# The first implementation of E5/T1-T4. Historical closes remain coverage debt;
# closes at or after this UTC instant are subject to the hard gate.
ENFORCEMENT_EPOCH_TEXT = "2026-07-20T07:36:00Z"
ENFORCEMENT_EPOCH = datetime.fromisoformat(ENFORCEMENT_EPOCH_TEXT.replace("Z", "+00:00"))

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

_CLOSE_BINDING_RE = re.compile(
    r"\[closing=(?P<closing>[0-9a-f]{40}) "
    r"source=(?P<source>[0-9a-f]{40}) "
    r"evidence=(?P<evidence>[^\]\s]+)\]"
)

_SELF_SKIP_RE = re.compile(r"#\s*\[\s*ignore\s*\]|self[- ]skip(?:ping)?", re.I)

_NATIVE_CLOSE_REASON_REGEX = (
    r"\[closing=[0-9a-f]{40} source=[0-9a-f]{40} "
    r"evidence=tests/artifacts/evidence/closes/[A-Za-z0-9._-]+\.json\]$"
)


class Finding:
    def __init__(self, tier: str, bead: str, code: str, message: str) -> None:
        self.tier = tier
        self.bead = bead
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"[{self.tier}] {self.bead}: {self.code} — {self.message}"


def _tracker_policy_errors(document: object) -> list[str]:
    """Pin the fail-closed native `br close` policy consumed by br itself."""
    if not isinstance(document, dict):
        return ["policy document must be an object"]
    errors: list[str] = []
    if set(document) != {"allow_bypass", "close_policy"}:
        errors.append("policy keys must be exactly allow_bypass and close_policy")
    if document.get("allow_bypass") is not False:
        errors.append("allow_bypass must be false")
    close_policy = document.get("close_policy")
    if not isinstance(close_policy, dict):
        return errors + ["close_policy must be an object"]
    if set(close_policy) != {"require_close_reason"}:
        errors.append("close_policy keys must be exactly require_close_reason")
    reason = close_policy.get("require_close_reason")
    if not isinstance(reason, dict):
        return errors + ["close_policy.require_close_reason must be an object"]
    if set(reason) != {"enabled", "min_length", "regex"}:
        errors.append(
            "close_policy.require_close_reason keys must be exactly enabled, "
            "min_length, and regex"
        )
    if reason.get("enabled") is not True:
        errors.append("close_policy.require_close_reason.enabled must be true")
    if reason.get("min_length") != 0:
        errors.append("close_policy.require_close_reason.min_length must be 0")
    if reason.get("regex") != _NATIVE_CLOSE_REASON_REGEX:
        errors.append("close_policy.require_close_reason.regex drifted")
    return errors


def _check_tracker_policy() -> int:
    try:
        document = json.loads(TRACKER_POLICY.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"audit: native tracker policy is unavailable or invalid: {exc}",
            file=sys.stderr,
        )
        return 1
    errors = _tracker_policy_errors(document)
    for error in errors:
        print(f"audit: native tracker policy invalid: {error}", file=sys.stderr)
    return int(bool(errors))


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False
    )


def _commit_exists(sha: str) -> bool:
    return _git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def _repo_relative_path(value: str) -> Path | None:
    """Return a safe repository-relative path, retaining git glob syntax."""
    if not value or "\n" in value or "\r" in value or value.startswith(('/', ':')):
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        return None
    return Path(*pure.parts)


def _file_at_commit(sha: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{sha}:{path}"],
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def _is_ancestor(older: str, newer: str) -> bool:
    return _git("merge-base", "--is-ancestor", older, newer).returncode == 0


def _issue_shape_errors(issue: dict) -> list[str]:
    errors: list[str] = []
    priority = issue.get("priority")
    if priority is not None and (
        isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 4
    ):
        errors.append(
            f"priority must be an integer from 0 through 4, got {priority!r}"
        )
    compaction_level = issue.get("compaction_level")
    if compaction_level is not None and (
        isinstance(compaction_level, bool)
        or not isinstance(compaction_level, int)
        or compaction_level < 0
    ):
        errors.append(
            "compaction_level must be a non-negative integer, got "
            f"{compaction_level!r}"
        )
    return errors


def _closed_beads(issues_jsonl: Path) -> list[dict]:
    """Read the exported snapshot directly; auditing never opens tracker state."""
    if not issues_jsonl.exists():
        print(f"audit: issues JSONL not found: {issues_jsonl}", file=sys.stderr)
        raise SystemExit(2)

    issues: dict[str, dict] = {}
    invalid_shape = False
    for line_number, raw in enumerate(issues_jsonl.read_text().splitlines(), 1):
        if not raw.strip():
            continue
        try:
            issue = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(
                f"audit: malformed issues JSONL at {issues_jsonl}:{line_number}: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(2) from exc
        if not isinstance(issue, dict) or not isinstance(issue.get("id"), str):
            print(
                f"audit: invalid issue record at {issues_jsonl}:{line_number}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        shape_errors = _issue_shape_errors(issue)
        for shape_error in shape_errors:
            print(
                f"audit: invalid tracker record at {issues_jsonl}:{line_number}: "
                f"{shape_error}",
                file=sys.stderr,
            )
            invalid_shape = True
        issues[issue["id"]] = issue
    if invalid_shape:
        raise SystemExit(2)
    return [issue for issue in issues.values() if issue.get("status") == "closed"]


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _requires_evidence(bead: dict) -> bool:
    closed_at = _parse_utc(bead.get("closed_at"))
    return closed_at is not None and closed_at >= ENFORCEMENT_EPOCH


def _reason_of(bead: dict) -> str:
    for key in ("close_reason", "reason", "resolution"):
        if bead.get(key):
            return str(bead[key])
    return ""


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


def _audit_document_payload(bead_id: str, doc: dict) -> list:
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

    if not _commit_exists(doc["source"]["sha"]):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SOURCE_SHA_ABSENT",
                f"{doc['source']['sha']} is not a commit in this repository",
            )
        )

    for proof in doc["proofs"]:
        proof_path = _repo_relative_path(proof["path"])
        if proof_path is None:
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "PROOF_PATH_OUTSIDE_REPO",
                    f"{proof['schema']} references unsafe path {proof['path']!r}",
                )
            )
        elif not (ROOT / proof_path).is_file():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "PROOF_ARTIFACT_ABSENT",
                    f"{proof['schema']} references {proof['path']}, which is not on disk",
                )
            )

    for artifact in doc["live_evidence"]["artifacts"]:
        artifact_path = _repo_relative_path(artifact["path"])
        if artifact_path is None:
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "LIVE_ARTIFACT_PATH_OUTSIDE_REPO",
                    f"live claim references unsafe path {artifact['path']!r}",
                )
            )
        elif not (ROOT / artifact_path).is_file():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "LIVE_ARTIFACT_ABSENT",
                    f"live claim references {artifact['path']}, which is not on disk",
                )
            )

    return findings


def _audit_document(path: Path) -> list:
    """Load and hard-check one bead-close-evidence/v1 document."""
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [Finding("hard", path.stem, "MALFORMED_JSON", str(exc))]
    return _audit_document_payload(path.stem, doc)


def _artifact_field(payload: dict, *names: str) -> object:
    for container in (payload, payload.get("metadata")):
        if not isinstance(container, dict):
            continue
        for name in names:
            if name in container:
                return container[name]
    return None


def _scheduled_lane_artifact_findings(
    bead_id: str, artifact: dict, source_sha: str, closing_sha: str
) -> list[Finding]:
    """Verify that live proof is a committed, exact-SHA scheduled-lane record."""
    path = artifact["path"]
    relative = _repo_relative_path(path)
    if relative is None or not (ROOT / relative).is_file():
        return []  # The base document audit emits the precise path finding.

    findings: list[Finding] = []
    committed = _file_at_commit(closing_sha, relative.as_posix())
    if committed is None:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_ARTIFACT_NOT_LANDED",
                f"{path} is absent from closing commit {closing_sha}",
            )
        )
    elif (ROOT / relative).read_bytes() != committed:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_ARTIFACT_CHANGED_AFTER_CLOSE",
                f"{path} differs from its bytes at closing commit {closing_sha}",
            )
        )

    try:
        payload = json.loads((ROOT / relative).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_ARTIFACT_NOT_JSON",
                f"{path} cannot supply scheduled-lane metadata: {exc}",
            )
        )
        return findings
    if not isinstance(payload, dict):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_ARTIFACT_NOT_OBJECT",
                f"{path} must contain a JSON object",
            )
        )
        return findings

    run_id = _artifact_field(payload, "run_id", "workflow_run_id")
    if isinstance(run_id, bool) or not isinstance(run_id, (str, int)) or not str(run_id).strip():
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_RUN_ID_MISSING",
                f"{path} has no non-empty run_id/workflow_run_id",
            )
        )
    lane = _artifact_field(payload, "lane", "lane_name", "job")
    if not isinstance(lane, str) or not lane.strip():
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_LANE_MISSING",
                f"{path} has no non-empty lane/lane_name/job",
            )
        )
    artifact_sha = _artifact_field(
        payload, "source_sha", "commit_sha", "head_sha", "sha"
    )
    if artifact_sha != source_sha:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "LIVE_ARTIFACT_SOURCE_MISMATCH",
                f"{path} records {artifact_sha!r}, expected source SHA {source_sha}",
            )
        )
    return findings


def _scope_findings(
    bead_id: str,
    doc: dict,
    closing_sha: str,
    *,
    require_worktree_clean: bool,
) -> list[Finding]:
    source_sha = doc["source"]["sha"]
    findings: list[Finding] = []
    scopes = doc["scope"]["in_scope"]

    safe_scopes: list[str] = []
    for scope in scopes:
        if _repo_relative_path(scope) is None:
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "SCOPE_PATH_INVALID",
                    f"scope.in_scope entry is not a safe repository pathspec: {scope!r}",
                )
            )
        else:
            safe_scopes.append(scope)
    if findings:
        return findings

    tree = _git("ls-tree", "-r", "--name-only", source_sha)
    tree_paths = tree.stdout.splitlines() if tree.returncode == 0 else []
    for scope in safe_scopes:
        if not _scope_resolves(scope, tree_paths):
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "SCOPE_PATH_UNRESOLVED",
                    f"scope.in_scope pathspec does not resolve at source.sha: {scope!r}",
                )
            )

    changed = _git("diff", "--quiet", source_sha, closing_sha, "--", *safe_scopes)
    if changed.returncode == 1:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SCOPE_CHANGED_AFTER_SOURCE",
                f"in-scope paths changed between source {source_sha} and closing {closing_sha}",
            )
        )
    elif changed.returncode != 0:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SCOPE_DIFF_FAILED",
                changed.stderr.strip() or "git diff could not verify in-scope paths",
            )
        )

    if require_worktree_clean:
        dirty = _git(
            "status", "--porcelain=v1", "--untracked-files=all", "--", *safe_scopes
        )
        if dirty.returncode != 0:
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "SCOPE_STATUS_FAILED",
                    dirty.stderr.strip() or "git status could not verify in-scope paths",
                )
            )
        elif dirty.stdout.strip():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "SCOPE_DIRTY_AT_CLOSE",
                    "in-scope paths have uncommitted changes:\n" + dirty.stdout.rstrip(),
                )
            )
    return findings


def _self_skipping_findings(bead_id: str, doc: dict) -> list[Finding]:
    traces = [
        entry["trace"] for entry in doc["integration_evidence"]["entry_points"]
    ]
    if (
        traces
        and any(_SELF_SKIP_RE.search(trace) for trace in traces)
        and not doc["proofs"]
        and not doc["live_evidence"]["artifacts"]
    ):
        return [
            Finding(
                "hard",
                bead_id,
                "SELF_SKIPPING_SOLE_PROOF",
                "a #[ignore]/self-skipping test is the only cited proof",
            )
        ]
    return []


def _scope_resolves(scope: str, tree_paths: list[str]) -> bool:
    has_magic = any(character in scope for character in "*?[")
    return any(
        fnmatch.fnmatchcase(path, scope)
        if has_magic
        else path == scope or path.startswith(scope.rstrip("/") + "/")
        for path in tree_paths
    )


def _landed_evidence_findings(
    bead_id: str,
    doc: dict,
    evidence_path: Path,
    closing_sha: str,
    *,
    require_worktree_clean: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    source_sha = doc["source"]["sha"]
    relative = evidence_path.relative_to(ROOT).as_posix()

    if not _commit_exists(closing_sha):
        return [
            Finding(
                "hard",
                bead_id,
                "CLOSING_SHA_ABSENT",
                f"{closing_sha} is not a commit in this repository",
            )
        ]
    if not _is_ancestor(source_sha, closing_sha):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SOURCE_NOT_ANCESTOR",
                f"source {source_sha} is not an ancestor of closing commit {closing_sha}",
            )
        )
    if not _is_ancestor(closing_sha, _git("rev-parse", "HEAD").stdout.strip()):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "CLOSING_SHA_NOT_ANCESTOR",
                f"closing commit {closing_sha} is not an ancestor of HEAD",
            )
        )

    committed_evidence = _file_at_commit(closing_sha, relative)
    if committed_evidence is None:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "CLOSE_EVIDENCE_NOT_LANDED",
                f"{relative} is absent from closing commit {closing_sha}",
            )
        )
    elif evidence_path.read_bytes() != committed_evidence:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "CLOSE_EVIDENCE_CHANGED_AFTER_CLOSE",
                f"{relative} differs from its bytes at closing commit {closing_sha}",
            )
        )

    for proof in doc["proofs"]:
        proof_relative = _repo_relative_path(proof["path"])
        if proof_relative is None or not (ROOT / proof_relative).is_file():
            continue  # The base document audit emits the precise path finding.
        committed_proof = _file_at_commit(closing_sha, proof_relative.as_posix())
        if committed_proof is None:
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "PROOF_ARTIFACT_NOT_LANDED",
                    f"{proof['path']} is absent from closing commit {closing_sha}",
                )
            )
        elif (ROOT / proof_relative).read_bytes() != committed_proof:
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "PROOF_ARTIFACT_CHANGED_AFTER_CLOSE",
                    f"{proof['path']} differs from its bytes at closing commit {closing_sha}",
                )
            )

    findings.extend(
        _scope_findings(
            bead_id,
            doc,
            closing_sha,
            require_worktree_clean=require_worktree_clean,
        )
    )
    findings.extend(_self_skipping_findings(bead_id, doc))
    if doc["live_evidence"]["claimed"]:
        for artifact in doc["live_evidence"]["artifacts"]:
            findings.extend(
                _scheduled_lane_artifact_findings(
                    bead_id, artifact, source_sha, closing_sha
                )
            )
    return findings


def _close_binding_findings(bead: dict, evidence_path: Path, doc: dict) -> list[Finding]:
    bead_id = bead["id"]
    reason = _reason_of(bead)
    binding = _CLOSE_BINDING_RE.search(reason)
    if binding is None:
        return [
            Finding(
                "hard",
                bead_id,
                "CLOSE_REASON_UNBOUND",
                "post-enforcement close_reason lacks [closing=... source=... evidence=...]",
            )
        ]

    findings: list[Finding] = []
    expected_path = evidence_path.relative_to(ROOT).as_posix()
    if binding["source"] != doc["source"]["sha"]:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "CLOSE_REASON_SOURCE_MISMATCH",
                f"reason binds {binding['source']}, evidence binds {doc['source']['sha']}",
            )
        )
    if binding["evidence"] != expected_path:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "CLOSE_REASON_EVIDENCE_MISMATCH",
                f"reason binds {binding['evidence']!r}, expected {expected_path!r}",
            )
        )
    findings.extend(
        _landed_evidence_findings(
            bead_id,
            doc,
            evidence_path,
            binding["closing"],
            require_worktree_clean=False,
        )
    )
    return findings


def pre_close(bead_id: str, evidence_argument: str) -> int:
    expected = CLOSES_DIR / f"{bead_id}.json"
    candidate = Path(evidence_argument)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    try:
        evidence_path = candidate.resolve(strict=True)
    except OSError as exc:
        print(f"pre-close: evidence path is unavailable: {exc}", file=sys.stderr)
        return 1
    if evidence_path != expected.resolve():
        print(
            "pre-close: evidence must be the canonical original-bead path "
            f"{expected.relative_to(ROOT)}",
            file=sys.stderr,
        )
        return 1

    findings = _audit_document(evidence_path)
    if not findings:
        doc = json.loads(evidence_path.read_text())
        closing_sha = _git("rev-parse", "HEAD").stdout.strip()
        findings.extend(
            _landed_evidence_findings(
                bead_id,
                doc,
                evidence_path,
                closing_sha,
                require_worktree_clean=True,
            )
        )

    if findings:
        print("PRE-CLOSE HARD findings:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(
        f"pre-close: PASS {bead_id}; evidence landed at HEAD and in-scope paths clean"
    )
    return 0


def self_test() -> int:
    """Pin E5 decisions without creating, deleting, or mutating an artifact."""
    fixture = ROOT / "schemas" / "evidence" / "fixtures" / "valid" / "bead-close-evidence.json"
    foreign_doc = json.loads(fixture.read_text())
    findings = _audit_document_payload("foreign-close", foreign_doc)
    if not any(f.code == "E_REPO_MISMATCH" for f in findings):
        print("audit: self-test failed: foreign close evidence was accepted", file=sys.stderr)
        return 1
    before = {"closed_at": "2026-07-20T07:35:59Z"}
    at = {"closed_at": ENFORCEMENT_EPOCH_TEXT}
    if _requires_evidence(before) or not _requires_evidence(at):
        print("audit: self-test failed: enforcement epoch boundary drifted", file=sys.stderr)
        return 1
    if not any(
        "priority" in error for error in _issue_shape_errors({"priority": "2"})
    ):
        print("audit: self-test failed: string priority was accepted", file=sys.stderr)
        return 1
    if not any(
        "compaction_level" in error
        for error in _issue_shape_errors({"compaction_level": "0"})
    ):
        print(
            "audit: self-test failed: string compaction_level was accepted",
            file=sys.stderr,
        )
        return 1
    binding = _CLOSE_BINDING_RE.search(
        "done [closing=" + "a" * 40 + " source=" + "b" * 40
        + " evidence=tests/artifacts/evidence/closes/x.json]"
    )
    if binding is None or binding["closing"] != "a" * 40:
        print("audit: self-test failed: close binding was not parsed", file=sys.stderr)
        return 1
    raw_close = {
        "id": "raw-close",
        "closed_at": ENFORCEMENT_EPOCH_TEXT,
        "close_reason": "done without the guarded binding",
    }
    raw_close_findings = _close_binding_findings(raw_close, fixture, foreign_doc)
    if not any(f.code == "CLOSE_REASON_UNBOUND" for f in raw_close_findings):
        print("audit: self-test failed: raw br close bypass was accepted", file=sys.stderr)
        return 1
    permissive_policy = {
        "allow_bypass": True,
        "close_policy": {"require_close_reason": {"enabled": False, "regex": None}},
    }
    if not _tracker_policy_errors(permissive_policy):
        print(
            "audit: self-test failed: permissive native close policy was accepted",
            file=sys.stderr,
        )
        return 1
    self_skip_doc = json.loads(json.dumps(foreign_doc))
    self_skip_doc["proofs"] = []
    self_skip_doc["live_evidence"] = {"claimed": False, "artifacts": []}
    self_skip_doc["integration_evidence"]["entry_points"][0]["trace"] = (
        "#[ignore] self-skipping test"
    )
    if not _self_skipping_findings("x", self_skip_doc):
        print("audit: self-test failed: self-skipping sole proof was accepted", file=sys.stderr)
        return 1
    paths = [
        "schemas/evidence/bead-close-evidence-v1.schema.json",
        "scripts/audit_bead_closes.py",
    ]
    if not _scope_resolves("schemas/evidence/*.schema.json", paths):
        print("audit: self-test failed: scope glob did not resolve", file=sys.stderr)
        return 1
    if not _scope_resolves("scripts", paths):
        print("audit: self-test failed: scope directory did not resolve", file=sys.stderr)
        return 1
    return 0


TEMPLATE = {
    "schema": "bead-close-evidence/v1",
    "repo": "oraclemcp",
    "generated_at": "REPLACE-WITH-RFC3339-UTC",
    "bead_id": "REPLACE",
    "scope": {
        "summary": "What this close covers, in one sentence.",
        "in_scope": ["path or behaviour actually delivered"],
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


def audit(strict: bool, issues_jsonl: Path) -> int:
    beads = _closed_beads(issues_jsonl)
    documents = sorted(CLOSES_DIR.glob("*.json")) if CLOSES_DIR.exists() else []
    evidenced = {p.stem for p in documents}

    findings: list = []
    for path in documents:
        findings.extend(_audit_document(path))
    documents_by_bead: dict[str, tuple[Path, dict]] = {}
    for path in documents:
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            documents_by_bead[path.stem] = (path, payload)

    required_missing = 0
    for bead in beads:
        findings.extend(_scan_reason(bead))
        if not _requires_evidence(bead):
            continue
        item = documents_by_bead.get(bead["id"])
        if item is None:
            required_missing += 1
            findings.append(
                Finding(
                    "hard",
                    bead["id"],
                    "CLOSE_EVIDENCE_MISSING",
                    f"close at {bead.get('closed_at')} is on/after enforcement epoch "
                    f"{ENFORCEMENT_EPOCH_TEXT}",
                )
            )
            continue
        path, doc = item
        if not _audit_document_payload(bead["id"], doc):
            findings.extend(_close_binding_findings(bead, path, doc))

    hard = [f for f in findings if f.tier == "hard"]
    advisory = [f for f in findings if f.tier == "advisory"]

    closed_ids = {b["id"] for b in beads}
    orphans = sorted(evidenced - closed_ids)
    unevidenced = len(closed_ids - evidenced)
    legacy_unevidenced = unevidenced - required_missing

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
        f"audit: {len(closed_ids)} closed beads, {len(evidenced & closed_ids)} with "
        f"close evidence, {legacy_unevidenced} legacy unevidenced, "
        f"{required_missing} required evidence missing; {len(hard)} hard, "
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
        help="exercise enforcement boundaries without tracker or filesystem mutation",
    )
    parser.add_argument(
        "--pre-close",
        metavar="BEAD_ID",
        help="hard-check one landed evidence document before tracker mutation",
    )
    parser.add_argument(
        "--evidence",
        metavar="PATH",
        help="canonical evidence path used with --pre-close",
    )
    parser.add_argument(
        "--issues-jsonl",
        type=Path,
        default=ROOT / ".beads" / "issues.jsonl",
        help="read-only tracker snapshot (default: .beads/issues.jsonl)",
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
    if bool(args.pre_close) != bool(args.evidence):
        parser.error("--pre-close and --evidence must be supplied together")
    if _check_tracker_policy() != 0:
        return 1
    self_test_result = self_test()
    if args.self_test:
        if self_test_result == 0:
            print("audit: self-test PASS")
        return self_test_result
    if self_test_result != 0:
        return 1
    if args.pre_close:
        return pre_close(args.pre_close, args.evidence)
    return audit(args.strict, args.issues_jsonl)


if __name__ == "__main__":
    sys.exit(main())
