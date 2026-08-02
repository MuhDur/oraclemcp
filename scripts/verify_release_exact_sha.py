#!/usr/bin/env python3
"""Fail-closed, non-mutating candidate release proof generator."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_VALIDATOR = ROOT / "scripts" / "validate_evidence.py"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_API_ORIGIN = "https://api.github.com"
OFFICIAL_REPOSITORY = "MuhDur/oraclemcp"
CI_WORKFLOW_FILE = "ci.yml"
MAIN_BRANCH = "main"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_required_local import (  # noqa: E402
    ContractError as RequiredGraphError,
    effective_plan,
    validate_command_coverage,
)
from scripts.ci_taxonomy import (  # noqa: E402
    DEFAULT_WORKFLOW_DIR,
    load_workflows,
    taxonomy_document,
)


def run(*argv: str) -> str:
    return subprocess.check_output(argv, cwd=ROOT, text=True).strip()


def require_file(path: Path, error_code: str) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise SystemExit(f"{error_code}: {path}")


@dataclass(frozen=True)
class ReleaseIdentity:
    repository: str
    source_ref: str
    workflow_name: str
    source_sha: str
    certificate_identity: str
    oidc_issuer: str


def release_identity(tag: str, sha: str) -> ReleaseIdentity:
    repository = os.environ.get(
        "ORACLEMCP_RELEASE_REPOSITORY",
        os.environ.get("GITHUB_REPOSITORY", OFFICIAL_REPOSITORY),
    )
    if repository != OFFICIAL_REPOSITORY:
        raise SystemExit(
            f"E_RELEASE_REPOSITORY: exact repository must be {OFFICIAL_REPOSITORY}"
        )
    source_ref = f"refs/tags/{tag}"
    workflow_name = os.environ.get("ORACLEMCP_RELEASE_WORKFLOW_NAME", "Release")
    if not workflow_name:
        raise SystemExit("E_RELEASE_WORKFLOW_NAME: workflow name is empty")
    expected_identity = (
        f"https://github.com/{repository}/.github/workflows/release.yml@{source_ref}"
    )
    certificate_identity = os.environ.get(
        "EXPECTED_CERTIFICATE_IDENTITY", expected_identity
    )
    if certificate_identity != expected_identity:
        raise SystemExit(
            "E_CERTIFICATE_IDENTITY: expected release.yml identity for candidate tag"
        )
    oidc_issuer = os.environ.get(
        "EXPECTED_OIDC_ISSUER", "https://token.actions.githubusercontent.com"
    )
    if not oidc_issuer:
        raise SystemExit("E_OIDC_ISSUER: issuer is empty")
    return ReleaseIdentity(
        repository=repository,
        source_ref=source_ref,
        workflow_name=workflow_name,
        source_sha=sha,
        certificate_identity=certificate_identity,
        oidc_issuer=oidc_issuer,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def github_api_json(path: str) -> object:
    """Fetch one GitHub REST response from the fixed HTTPS API origin."""

    if not path.startswith("/repos/") or "://" in path:
        raise SystemExit("E_REQUIRED_CI_FETCH: invalid GitHub API path")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "oraclemcp-exact-sha-verifier",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{GITHUB_API_ORIGIN}{path}", headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.netloc != "api.github.com":
                raise SystemExit("E_REQUIRED_CI_FETCH: GitHub API redirected off origin")
            raw = response.read(16 * 1024 * 1024 + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise SystemExit(f"E_REQUIRED_CI_FETCH: GitHub API request failed: {error}") from error
    if len(raw) > 16 * 1024 * 1024:
        raise SystemExit("E_REQUIRED_CI_FETCH: GitHub API response exceeds 16 MiB")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit("E_REQUIRED_CI_FETCH: GitHub API returned invalid JSON") from error


def github_collection(path: str, key: str) -> list[dict[str, object]]:
    """Fetch every page of a GitHub collection with a stable total count."""

    records: list[dict[str, object]] = []
    total: int | None = None
    separator = "&" if "?" in path else "?"
    for page in range(1, 101):
        document = github_api_json(f"{path}{separator}per_page=100&page={page}")
        if not isinstance(document, dict):
            raise SystemExit("E_REQUIRED_CI_FETCH: collection response is not an object")
        observed_total = document.get("total_count")
        batch = document.get(key)
        if (
            isinstance(observed_total, bool)
            or not isinstance(observed_total, int)
            or observed_total < 0
            or not isinstance(batch, list)
            or any(not isinstance(item, dict) for item in batch)
        ):
            raise SystemExit("E_REQUIRED_CI_FETCH: malformed GitHub collection response")
        if total is None:
            total = observed_total
        elif total != observed_total:
            raise SystemExit("E_REQUIRED_CI_FETCH: GitHub collection changed while paging")
        records.extend(batch)
        if len(records) >= total:
            if len(records) != total:
                raise SystemExit("E_REQUIRED_CI_FETCH: GitHub collection count mismatch")
            return records
        if not batch:
            raise SystemExit("E_REQUIRED_CI_FETCH: truncated GitHub collection")
    raise SystemExit("E_REQUIRED_CI_FETCH: GitHub collection exceeds 10,000 records")


def ci_policy_jobs() -> list[dict[str, object]]:
    """Derive Required/advisory job identities from workflow policy, not evidence."""

    try:
        taxonomy = taxonomy_document(load_workflows(DEFAULT_WORKFLOW_DIR))
    except (OSError, ValueError) as error:
        raise SystemExit(f"E_REQUIRED_CI_POLICY: {error}") from error
    jobs = [
        job
        for job in taxonomy["jobs"]
        if job["tier"] in {"required", "advisory"}
    ]
    required = [job for job in jobs if job["tier"] == "required"]
    if not required:
        raise SystemExit("E_REQUIRED_CI_NO_REQUIRED: CI policy has no Required jobs")
    identities = [(job["workflow_file"], job["check_name"]) for job in jobs]
    if len(identities) != len(set(identities)):
        raise SystemExit("E_REQUIRED_CI_POLICY: duplicate workflow/check identity")
    return jobs


def validate_actions_run(
    run_document: object,
    *,
    run_id: int,
    candidate_sha: str,
    identity: ReleaseIdentity,
    workflow_file: str,
    workflow_name: str,
) -> int:
    if not isinstance(run_document, dict):
        raise SystemExit("E_REQUIRED_CI_PROVENANCE: Actions run is not an object")
    repository = run_document.get("repository")
    if (
        run_document.get("id") != run_id
        or not isinstance(repository, dict)
        or repository.get("full_name") != identity.repository
        or run_document.get("path") != f".github/workflows/{workflow_file}"
        or run_document.get("name") != workflow_name
        or run_document.get("event") != "push"
        or run_document.get("head_branch") != MAIN_BRANCH
    ):
        raise SystemExit("E_REQUIRED_CI_PROVENANCE: Actions run identity is not trusted")
    if run_document.get("head_sha") != candidate_sha:
        raise SystemExit("E_REQUIRED_CI_SHA_MISMATCH: Actions run SHA differs from candidate")
    if (
        run_document.get("status") != "completed"
        or run_document.get("conclusion") != "success"
    ):
        raise SystemExit("E_REQUIRED_CI_NOT_GREEN: Actions run is not completed/success")
    attempt = run_document.get("run_attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise SystemExit("E_REQUIRED_CI_PROVENANCE: invalid Actions run attempt")
    return attempt


def _github_actions_run_id(details_url: object, repository: str) -> int:
    if not isinstance(details_url, str):
        raise SystemExit("E_REQUIRED_CI_PROVENANCE: check-run details URL is missing")
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repository)}/actions/runs/([1-9][0-9]*)/job/[1-9][0-9]*",
        details_url,
    )
    if match is None:
        raise SystemExit("E_REQUIRED_CI_PROVENANCE: check-run URL is not a GitHub Actions job")
    return int(match.group(1))


def authenticated_required_ci(
    run_id: int, candidate_sha: str, identity: ReleaseIdentity
) -> tuple[str, list[dict[str, object]], list[dict[str, str]]]:
    """Authenticate the selected CI run and every repository Required check."""

    repository = identity.repository
    run_path = f"/repos/{repository}/actions/runs/{run_id}"
    run_document = github_api_json(run_path)
    attempt = validate_actions_run(
        run_document,
        run_id=run_id,
        candidate_sha=candidate_sha,
        identity=identity,
        workflow_file=CI_WORKFLOW_FILE,
        workflow_name="CI",
    )
    run_references = [
        {
            "kind": "github-actions-run",
            "path": (
                f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}"
            ),
            "sha": candidate_sha,
        }
    ]
    policy = ci_policy_jobs()
    ci_policy = {
        str(job["check_name"]): job
        for job in policy
        if job["workflow_file"] == CI_WORKFLOW_FILE
    }
    if not ci_policy:
        raise SystemExit("E_REQUIRED_CI_POLICY: ci.yml has no classified jobs")

    attempt_jobs = github_collection(
        f"{run_path}/attempts/{attempt}/jobs", "jobs"
    )
    observed_ci: dict[str, dict[str, object]] = {}
    observed_ids: set[int] = set()
    for job in attempt_jobs:
        job_id = job.get("id")
        name = job.get("name")
        if (
            isinstance(job_id, bool)
            or not isinstance(job_id, int)
            or not isinstance(name, str)
            or job.get("run_id") != run_id
            or job.get("head_sha") != candidate_sha
        ):
            raise SystemExit("E_REQUIRED_CI_PROVENANCE: malformed CI job provenance")
        if job_id in observed_ids or name in observed_ci:
            raise SystemExit("E_REQUIRED_CI_PROVENANCE: duplicate CI job identity")
        observed_ids.add(job_id)
        observed_ci[name] = job

    unknown = sorted(set(observed_ci) - set(ci_policy))
    missing = sorted(set(ci_policy) - set(observed_ci))
    if unknown:
        raise SystemExit(
            "E_REQUIRED_CI_POLICY: unclassified CI jobs: " + ", ".join(unknown)
        )
    if missing:
        raise SystemExit(
            "E_REQUIRED_CI_MISSING_JOB: terminal CI omitted " + ", ".join(missing)
        )

    evidence: list[dict[str, object]] = []
    for name, policy_job in sorted(ci_policy.items()):
        job = observed_ci[name]
        tier = str(policy_job["tier"])
        if job.get("status") != "completed":
            raise SystemExit(f"E_REQUIRED_CI_NOT_GREEN: {name} is not completed")
        if tier == "required" and job.get("conclusion") != "success":
            raise SystemExit(f"E_REQUIRED_CI_NOT_GREEN: Required job {name} is not success")
        evidence.append(
            {
                "name": name,
                "tier": tier,
                "status": job.get("status"),
                "conclusion": job.get("conclusion"),
            }
        )

    external_required = [
        job
        for job in policy
        if job["tier"] == "required" and job["workflow_file"] != CI_WORKFLOW_FILE
    ]
    if external_required:
        check_runs = github_collection(
            f"/repos/{repository}/commits/{candidate_sha}/check-runs?filter=latest",
            "check_runs",
        )
        by_name: dict[str, list[dict[str, object]]] = {}
        for check in check_runs:
            name = check.get("name")
            if isinstance(name, str):
                by_name.setdefault(name, []).append(check)
        run_cache: dict[int, object] = {run_id: run_document}
        for policy_job in external_required:
            name = str(policy_job["check_name"])
            candidates = by_name.get(name, [])
            if len(candidates) != 1:
                raise SystemExit(
                    f"E_REQUIRED_CI_MISSING_JOB: expected one authenticated {name!r} check"
                )
            check = candidates[0]
            app = check.get("app")
            if (
                check.get("head_sha") != candidate_sha
                or not isinstance(app, dict)
                or app.get("slug") != "github-actions"
            ):
                raise SystemExit(
                    f"E_REQUIRED_CI_PROVENANCE: {name!r} is not a GitHub Actions "
                    "check for the candidate"
                )
            if check.get("status") != "completed" or check.get("conclusion") != "success":
                raise SystemExit(f"E_REQUIRED_CI_NOT_GREEN: Required job {name} is not success")
            external_run_id = _github_actions_run_id(check.get("details_url"), repository)
            if external_run_id not in run_cache:
                run_cache[external_run_id] = github_api_json(
                    f"/repos/{repository}/actions/runs/{external_run_id}"
                )
            external_attempt = validate_actions_run(
                run_cache[external_run_id],
                run_id=external_run_id,
                candidate_sha=candidate_sha,
                identity=identity,
                workflow_file=str(policy_job["workflow_file"]),
                workflow_name=str(policy_job["workflow"]),
            )
            run_references.append(
                {
                    "kind": "github-actions-run",
                    "path": (
                        f"https://github.com/{repository}/actions/runs/"
                        f"{external_run_id}/attempts/{external_attempt}"
                    ),
                    "sha": candidate_sha,
                }
            )
            evidence.append(
                {
                    "name": name,
                    "tier": "required",
                    "status": "completed",
                    "conclusion": "success",
                }
            )

    unique_references = {reference["path"]: reference for reference in run_references}
    return (
        candidate_sha,
        sorted(evidence, key=lambda job: str(job["name"])),
        [unique_references[path] for path in sorted(unique_references)],
    )


def run_cosign(cosign_bin: str, argv: list[str], error_code: str) -> str:
    try:
        result = subprocess.run(
            [cosign_bin, *argv],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise SystemExit(f"{error_code}: cannot execute {cosign_bin}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        if len(detail) > 500:
            detail = f"{detail[:500]}..."
        raise SystemExit(
            f"{error_code}: {detail or f'cosign exited {result.returncode}'}"
        )
    return result.stdout.strip()


def require_cosign_v3(cosign_bin: str) -> None:
    raw = run_cosign(cosign_bin, ["version", "--json"], "E_COSIGN_VERSION")
    try:
        version = json.loads(raw)["gitVersion"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise SystemExit("E_COSIGN_VERSION: invalid cosign version JSON") from error
    if not re.fullmatch(r"v?3(?:\.[0-9]+){1,2}(?:[-+].*)?", version):
        raise SystemExit(f"E_COSIGN_VERSION: cosign v3 required, found {version!r}")


def artifact_evidence(
    path_text: str,
    sha: str,
    identity: ReleaseIdentity,
    cosign_bin: str,
) -> dict[str, str]:
    path = Path(path_text)
    if not path.name.endswith((".tar.gz", ".zip", ".cdx.json")):
        raise SystemExit(f"E_ARTIFACT_KIND: unsupported release payload: {path}")
    require_file(path, "E_ARTIFACT_MISSING")
    signature = Path(f"{path}.sigstore.json")
    attestation = Path(f"{path}.attestation.sigstore.json")
    require_file(signature, "E_SIGNATURE_BUNDLE_MISSING")
    require_file(attestation, "E_ATTESTATION_BUNDLE_MISSING")

    certificate_claims = [
        "--certificate-identity",
        identity.certificate_identity,
        "--certificate-oidc-issuer",
        identity.oidc_issuer,
        "--certificate-github-workflow-repository",
        identity.repository,
        "--certificate-github-workflow-ref",
        identity.source_ref,
        "--certificate-github-workflow-name",
        identity.workflow_name,
        "--certificate-github-workflow-sha",
        identity.source_sha,
    ]
    run_cosign(
        cosign_bin,
        ["verify-blob", "--bundle", str(signature), *certificate_claims, str(path)],
        "E_SIGNATURE_VERIFICATION_FAILED",
    )
    run_cosign(
        cosign_bin,
        [
            "verify-blob-attestation",
            "--bundle",
            str(attestation),
            "--type",
            "slsaprovenance1",
            "--check-claims=true",
            *certificate_claims,
            str(path),
        ],
        "E_ATTESTATION_VERIFICATION_FAILED",
    )
    return {"kind": "release-artifact", "path": str(path), "sha": sha}


def candidate_version(tag: str, root: Path = ROOT) -> str:
    version = tag[1:]
    try:
        workspace = tomllib.loads((root / "Cargo.toml").read_text())
        server = tomllib.loads((root / "crates/oraclemcp/Cargo.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"E_MANIFEST_INVALID: {error}") from error

    declared = [server.get("package", {}).get("version")]
    workspace_version = workspace.get("workspace", {}).get("package", {}).get("version")
    if workspace_version is not None:
        declared.append(workspace_version)
    if any(item != version for item in declared):
        found = ", ".join(repr(item) for item in declared)
        raise SystemExit(
            f"E_TAG_VERSION_MISMATCH: {tag} does not match declared version(s) {found}"
        )
    return version


def default_required_proof(sha: str) -> Path:
    return ROOT / "target/release-evidence/required" / f"required-proof-{sha}.json"


def default_output(sha: str) -> Path:
    return ROOT / "target/release-evidence/release-candidate" / (
        f"release-candidate-proof-{sha}.json"
    )


def resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def evidence_label(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return f"external/{path.name}"


def validate_evidence_file(path: Path, error_code: str) -> None:
    result = subprocess.run(
        [sys.executable, str(EVIDENCE_VALIDATOR), str(path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"{error_code}: {detail}")


def validate_required_proof(proof: dict[str, object], candidate_sha: str) -> None:
    if proof.get("schema") != "required-proof/v2":
        raise SystemExit("E_REQUIRED_PROOF_INVALID: required-proof/v2 is required")
    source = proof.get("source")
    if not isinstance(source, dict) or source.get("sha") != candidate_sha:
        raise SystemExit("E_REQUIRED_PROOF_INVALID: proof SHA does not match candidate")
    if proof.get("verdict") != "pass":
        raise SystemExit("E_REQUIRED_PROOF_INVALID: Required graph is not green")
    commands = proof.get("commands")
    if not isinstance(commands, list):
        raise SystemExit("E_REQUIRED_PROOF_INVALID: commands are missing")
    try:
        validate_command_coverage(commands, effective_plan())
    except RequiredGraphError as error:
        raise SystemExit(
            f"E_REQUIRED_PROOF_GRAPH_MISMATCH: {error}"
        ) from error


def write_validated_proof(output: Path, payload: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_name(f".{output.name}.pending")
    pending.write_text(json.dumps(payload, indent=2) + "\n")
    validate_evidence_file(pending, "E_EVIDENCE_SCHEMA_INVALID")
    pending.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--required-proof", type=Path)
    parser.add_argument("--ci-run-id", type=int)
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    tag = args.tag
    sha = args.sha
    if not SHA_RE.fullmatch(sha):
        parser.error("--sha must be a full lowercase SHA")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag):
        parser.error("invalid candidate tag")
    if run("git", "rev-parse", "HEAD") != sha:
        raise SystemExit("E_SHA_MISMATCH: HEAD is not --sha")
    if run("git", "status", "--porcelain"):
        raise SystemExit("E_TREE_DIRTY: clean tree required")
    version = candidate_version(tag)
    proof = (
        resolve_path(args.required_proof)
        if args.required_proof
        else default_required_proof(sha)
    )
    if not proof.exists():
        raise SystemExit("E_REQUIRED_PROOF_MISSING: required-proof artifact not found")
    validate_evidence_file(proof, "E_REQUIRED_PROOF_INVALID")
    doc = json.loads(proof.read_text())
    validate_required_proof(doc, sha)
    if args.ci_run_id is None or args.ci_run_id < 1:
        raise SystemExit("E_REQUIRED_CI_MISSING: provide a positive --ci-run-id")
    identity = release_identity(tag, sha)
    ci_sha, jobs, ci_run_references = authenticated_required_ci(
        args.ci_run_id, sha, identity
    )
    if not args.artifact:
        raise SystemExit("E_ARTIFACT_MISSING: provide --artifact")
    cosign_bin = os.environ.get("ORACLEMCP_COSIGN_BIN", "cosign")
    require_cosign_v3(cosign_bin)
    artifacts = [
        artifact_evidence(path, sha, identity, cosign_bin) for path in args.artifact
    ]
    artifacts.extend(ci_run_references)
    output = resolve_path(args.output) if args.output else default_output(sha)
    payload = {
        "schema": "release-candidate-proof/v2",
        "repo": "oraclemcp",
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "candidate": {"tag": tag, "version": version},
        "source": {"sha": sha, "tree_clean": True},
        "required_proof": {
            "schema": "required-proof/v2",
            "path": evidence_label(proof),
            "sha": sha,
        },
        "required_ci": {"sha": ci_sha, "jobs": jobs},
        "artifacts": artifacts,
        "verdict": "pass",
    }
    write_validated_proof(output, payload)
    print(f"release-candidate-proof: wrote {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"command failed: {error}") from error
