#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set +e
"$ROOT/scripts/verify_release_exact_sha.sh" --tag v0.9.0 --sha 0000000000000000000000000000000000000000 --ci-run-id 1 --artifact /nope >/tmp/release-proof-test.out 2>&1
status=$?
set -e
test "$status" -ne 0
grep -q 'E_SHA_MISMATCH' /tmp/release-proof-test.out

work="$ROOT/target/verify-release-exact-sha-test/$$"
mkdir -p "$work"
payload="$work/oraclemcp-test.tar.gz"
signature="$payload.sigstore.json"
attestation="$payload.attestation.sigstore.json"
fake_cosign="$work/cosign"
cosign_log="$work/cosign.log"
printf 'payload\n' >"$payload"

python3 - "$fake_cosign" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(r'''#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
log = Path(os.environ["FAKE_COSIGN_LOG"])
with log.open("a") as handle:
    handle.write(json.dumps(args) + "\n")

if args == ["version", "--json"]:
    print(json.dumps({"gitVersion": os.environ.get("FAKE_COSIGN_VERSION", "v3.1.2")}))
    raise SystemExit(0)

if not args or args[0] not in {"verify-blob", "verify-blob-attestation"}:
    raise SystemExit("unexpected command")

def value(flag):
    if args.count(flag) != 1:
        raise SystemExit(f"expected exactly one {flag}")
    index = args.index(flag)
    if index + 1 >= len(args):
        raise SystemExit(f"missing value for {flag}")
    return args[index + 1]

expected = {
    "--certificate-identity": os.environ["FAKE_EXPECTED_IDENTITY"],
    "--certificate-oidc-issuer": os.environ["FAKE_EXPECTED_ISSUER"],
    "--certificate-github-workflow-repository": os.environ["FAKE_EXPECTED_REPOSITORY"],
    "--certificate-github-workflow-ref": os.environ["FAKE_EXPECTED_REF"],
    "--certificate-github-workflow-name": os.environ["FAKE_EXPECTED_WORKFLOW"],
    "--certificate-github-workflow-sha": os.environ["FAKE_EXPECTED_SHA"],
}
for flag, wanted in expected.items():
    if value(flag) != wanted:
        raise SystemExit(f"wrong {flag}")

command = args[0]
if command == "verify-blob-attestation":
    if value("--type") != "slsaprovenance1" or "--check-claims=true" not in args:
        raise SystemExit("attestation claims are not bound to the payload")
    marker = "attestation"
else:
    if "--type" in args or "--check-claims=true" in args:
        raise SystemExit("signature command received attestation-only flags")
    marker = "signature"

payload = Path(args[-1])
digest = hashlib.sha256(payload.read_bytes()).hexdigest()
bundle = Path(value("--bundle"))
if bundle.read_text().strip() != f"{marker}:{digest}":
    raise SystemExit(f"invalid {marker} bundle")
''')
PY
chmod +x "$fake_cosign"

write_bundles() {
  digest="$(sha256sum "$payload" | awk '{print $1}')"
  printf 'signature:%s\n' "$digest" >"$signature"
  printf 'attestation:%s\n' "$digest" >"$attestation"
}

tag="v0.10.0"
printf -v sha '%040x' "$$"
repository="MuhDur/oraclemcp"
release_ref="refs/tags/$tag"
identity="https://github.com/$repository/.github/workflows/release.yml@$release_ref"
issuer="https://token.actions.githubusercontent.com"
workflow="Release"
write_bundles
: >"$cosign_log"

export ORACLEMCP_COSIGN_BIN="$fake_cosign"
export ORACLEMCP_RELEASE_REPOSITORY="$repository"
export ORACLEMCP_RELEASE_WORKFLOW_NAME="$workflow"
export EXPECTED_CERTIFICATE_IDENTITY="$identity"
export EXPECTED_OIDC_ISSUER="$issuer"
export FAKE_COSIGN_LOG="$cosign_log"
export FAKE_EXPECTED_REPOSITORY="$repository"
export FAKE_EXPECTED_REF="$release_ref"
export FAKE_EXPECTED_WORKFLOW="$workflow"
export FAKE_EXPECTED_SHA="$sha"
export FAKE_EXPECTED_IDENTITY="$identity"
export FAKE_EXPECTED_ISSUER="$issuer"

PYTHONPATH="$ROOT" python3 - "$payload" "$sha" "$tag" <<'PY'
import os
import sys
from scripts.verify_release_exact_sha import (
    artifact_evidence,
    release_identity,
    require_cosign_v3,
)

payload, sha, tag = sys.argv[1:]
cosign = os.environ["ORACLEMCP_COSIGN_BIN"]
require_cosign_v3(cosign)
record = artifact_evidence(payload, sha, release_identity(tag, sha), cosign)
assert record == {"kind": "release-artifact", "path": payload, "sha": sha}

official = os.environ["ORACLEMCP_RELEASE_REPOSITORY"]
os.environ["ORACLEMCP_RELEASE_REPOSITORY"] = "attacker/fork"
try:
    release_identity(tag, sha)
except SystemExit as error:
    assert "E_RELEASE_REPOSITORY" in str(error), error
else:
    raise AssertionError("attacker-controlled release repository was accepted")
finally:
    os.environ["ORACLEMCP_RELEASE_REPOSITORY"] = official
PY
test "$(wc -l <"$cosign_log" | tr -d '[:space:]')" = 3

printf 'arbitrary text\n' >"$signature"
set +e
PYTHONPATH="$ROOT" python3 - "$payload" "$sha" "$tag" >"$work/arbitrary-signature.out" 2>&1 <<'PY'
import os
import sys
from scripts.verify_release_exact_sha import artifact_evidence, release_identity
artifact_evidence(
    sys.argv[1],
    sys.argv[2],
    release_identity(sys.argv[3], sys.argv[2]),
    os.environ["ORACLEMCP_COSIGN_BIN"],
)
PY
status=$?
set -e
test "$status" -ne 0
grep -q 'E_SIGNATURE_VERIFICATION_FAILED' "$work/arbitrary-signature.out"

write_bundles
printf 'payload-tampered\n' >"$payload"
set +e
PYTHONPATH="$ROOT" python3 - "$payload" "$sha" "$tag" >"$work/tampered-payload.out" 2>&1 <<'PY'
import os
import sys
from scripts.verify_release_exact_sha import artifact_evidence, release_identity
artifact_evidence(
    sys.argv[1],
    sys.argv[2],
    release_identity(sys.argv[3], sys.argv[2]),
    os.environ["ORACLEMCP_COSIGN_BIN"],
)
PY
status=$?
set -e
test "$status" -ne 0
grep -q 'E_SIGNATURE_VERIFICATION_FAILED' "$work/tampered-payload.out"

printf 'payload\n' >"$payload"
write_bundles
printf 'arbitrary text\n' >"$attestation"
set +e
PYTHONPATH="$ROOT" python3 - "$payload" "$sha" "$tag" >"$work/arbitrary-attestation.out" 2>&1 <<'PY'
import os
import sys
from scripts.verify_release_exact_sha import artifact_evidence, release_identity
artifact_evidence(
    sys.argv[1],
    sys.argv[2],
    release_identity(sys.argv[3], sys.argv[2]),
    os.environ["ORACLEMCP_COSIGN_BIN"],
)
PY
status=$?
set -e
test "$status" -ne 0
grep -q 'E_ATTESTATION_VERIFICATION_FAILED' "$work/arbitrary-attestation.out"

write_bundles
: >"$signature"
set +e
PYTHONPATH="$ROOT" python3 - "$payload" "$sha" "$tag" >"$work/missing-signature.out" 2>&1 <<'PY'
import os
import sys
from scripts.verify_release_exact_sha import artifact_evidence, release_identity
artifact_evidence(
    sys.argv[1],
    sys.argv[2],
    release_identity(sys.argv[3], sys.argv[2]),
    os.environ["ORACLEMCP_COSIGN_BIN"],
)
PY
status=$?
set -e
test "$status" -ne 0
grep -q 'E_SIGNATURE_BUNDLE_MISSING' "$work/missing-signature.out"

write_bundles
: >"$attestation"
set +e
PYTHONPATH="$ROOT" python3 - "$payload" "$sha" "$tag" >"$work/missing-attestation.out" 2>&1 <<'PY'
import os
import sys
from scripts.verify_release_exact_sha import artifact_evidence, release_identity
artifact_evidence(
    sys.argv[1],
    sys.argv[2],
    release_identity(sys.argv[3], sys.argv[2]),
    os.environ["ORACLEMCP_COSIGN_BIN"],
)
PY
status=$?
set -e
test "$status" -ne 0
grep -q 'E_ATTESTATION_BUNDLE_MISSING' "$work/missing-attestation.out"

proof="$work/release-candidate-proof.json"
required_proof="$ROOT/target/release-evidence/required/required-proof-$sha.json"
malformed_required_proof="$work/required-proof-malformed.json"
fabricated_required_proof="$work/required-proof-fabricated.json"
write_bundles
PYTHONPATH="$ROOT" python3 - \
  "$required_proof" "$malformed_required_proof" "$fabricated_required_proof" "$sha" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from scripts.verify_required_local import (
    command_graph_commitment,
    effective_plan,
    expected_command_records,
)

(
    required_proof,
    malformed_required_proof,
    fabricated_required_proof,
    sha,
) = sys.argv[1:]

plan = effective_plan()
commands = []
for identifier, expected in expected_command_records(plan).items():
    record = {
        "id": identifier,
        "tier": expected["tier"],
        "argv": expected["argv"],
        "sha": sha,
        "outcome": "pass" if expected["tier"] == "required" else "skip",
        "exit_code": 0 if expected["tier"] == "required" else None,
        "started_at": "2026-08-02T00:00:00Z",
        "ended_at": "2026-08-02T00:00:01Z" if expected["tier"] == "required" else None,
    }
    if expected["tier"] == "advisory":
        record["skip_reason"] = "not-run-by-required-local"
    commands.append(record)

valid = {
    "schema": "required-proof/v2",
    "repo": "oraclemcp",
    "generated_at": "2026-08-02T00:00:00Z",
    "source": {"sha": sha, "tree_clean": True},
    "tool_versions": {"rustc": "test-toolchain"},
    "resource_budget": {
        "isolated_target_dir": "/tmp/exact-sha-test-target",
        "memory_max_bytes": 1073741824,
        "pid_task_max": 64,
    },
    "command_graph": command_graph_commitment(plan),
    "commands": commands,
    "verdict": "pass",
}
Path(required_proof).parent.mkdir(parents=True, exist_ok=True)
Path(required_proof).write_text(json.dumps(valid) + "\n")
Path(malformed_required_proof).write_text(json.dumps({
    "schema": "required-proof/v2",
    "source": {"sha": sha},
    "verdict": "pass",
}) + "\n")

fabricated_ids = ["fabricated"]
fabricated = {
    **valid,
    "command_graph": {
        "command_ids": fabricated_ids,
        "sha256": hashlib.sha256(
            json.dumps(fabricated_ids, separators=(",", ":")).encode()
        ).hexdigest(),
    },
    "commands": [{
        "id": "fabricated",
        "tier": "required",
        "argv": ["true"],
        "sha": sha,
        "outcome": "pass",
        "exit_code": 0,
        "started_at": "2026-08-02T00:00:00Z",
        "ended_at": "2026-08-02T00:00:01Z",
    }],
    "verdict": "pass",
}
Path(fabricated_required_proof).write_text(json.dumps(fabricated) + "\n")
PY
git check-ignore -q "$required_proof"
PYTHONPATH="$ROOT" python3 - \
  "$proof" "$payload" "$required_proof" "$malformed_required_proof" "$fabricated_required_proof" \
  "$sha" "$tag" "$work" <<'PY'
import json
import copy
import contextlib
import io
import os
import sys
from pathlib import Path
import scripts.verify_release_exact_sha as verifier

(
    output,
    artifact,
    required_proof,
    malformed_required_proof,
    fabricated_required_proof,
    sha,
    tag,
    work,
) = sys.argv[1:]

def observed_git(*argv):
    if argv == ("git", "rev-parse", "HEAD"):
        return sha
    if argv == ("git", "status", "--porcelain"):
        return ""
    raise AssertionError(f"unexpected command: {argv}")

verifier.run = observed_git

repository = os.environ["ORACLEMCP_RELEASE_REPOSITORY"]
selected_run_id = 1001
policy = verifier.ci_policy_jobs()
ci_policy = [job for job in policy if job["workflow_file"] == verifier.CI_WORKFLOW_FILE]
external_policy = [
    job
    for job in policy
    if job["tier"] == "required" and job["workflow_file"] != verifier.CI_WORKFLOW_FILE
]
required_names = [job["check_name"] for job in ci_policy if job["tier"] == "required"]
advisory_names = [job["check_name"] for job in ci_policy if job["tier"] == "advisory"]
assert required_names and advisory_names and external_policy

def run_document(run_id, workflow_file, workflow_name, *, head_sha=sha, conclusion="success"):
    return {
        "id": run_id,
        "run_attempt": 1,
        "name": workflow_name,
        "path": f".github/workflows/{workflow_file}",
        "event": "push",
        "head_branch": "main",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "repository": {"full_name": repository},
    }

def install_api(*, run_sha=sha, run_path=".github/workflows/ci.yml", failed_job=None,
                relabel_job=None, missing_job=None, external_failure=False):
    selected = run_document(selected_run_id, "ci.yml", "CI", head_sha=run_sha)
    selected["path"] = run_path
    jobs = []
    for index, policy_job in enumerate(ci_policy, start=1):
        name = policy_job["check_name"]
        if name == missing_job:
            continue
        observed_name = relabel_job[1] if relabel_job and name == relabel_job[0] else name
        jobs.append({
            "id": 2000 + index,
            "run_id": selected_run_id,
            "head_sha": sha,
            "name": observed_name,
            "status": "completed",
            "conclusion": "failure" if name == failed_job else "success",
        })

    checks = []
    external_runs = {}
    for index, policy_job in enumerate(external_policy, start=1):
        external_run_id = 3000 + index
        check_name = policy_job["check_name"]
        failed = external_failure and index == 1
        checks.append({
            "id": 4000 + index,
            "name": check_name,
            "head_sha": sha,
            "status": "completed",
            "conclusion": "failure" if failed else "success",
            "details_url": (
                f"https://github.com/{repository}/actions/runs/"
                f"{external_run_id}/job/{5000 + index}"
            ),
            "app": {"slug": "github-actions"},
        })
        external_runs[external_run_id] = run_document(
            external_run_id,
            policy_job["workflow_file"],
            policy_job["workflow"],
        )

    def api(path):
        if path == f"/repos/{repository}/actions/runs/{selected_run_id}":
            return copy.deepcopy(selected)
        if path == (
            f"/repos/{repository}/actions/runs/{selected_run_id}/attempts/1/"
            "jobs?per_page=100&page=1"
        ):
            return {"total_count": len(jobs), "jobs": copy.deepcopy(jobs)}
        if path.startswith(f"/repos/{repository}/commits/{sha}/check-runs?"):
            return {"total_count": len(checks), "check_runs": copy.deepcopy(checks)}
        for external_run_id, document in external_runs.items():
            if path == f"/repos/{repository}/actions/runs/{external_run_id}":
                return copy.deepcopy(document)
        raise AssertionError(f"unexpected GitHub API path: {path}")

    verifier.github_api_json = api

def arguments(proof_path, output_path):
    argv = [
        "verify_release_exact_sha.py",
        "--tag", tag,
        "--sha", sha,
        "--ci-run-id", str(selected_run_id),
        "--artifact", artifact,
        "--output", output_path,
    ]
    if proof_path is not None:
        argv.extend(["--required-proof", proof_path])
    return argv

from scripts.verify_required_local import default_output as producer_default_output
assert verifier.default_required_proof(sha) == producer_default_output(sha)
assert verifier.default_required_proof(sha) == Path(required_proof)

install_api()
sys.argv = arguments(None, output)
assert verifier.main() == 0
generated = json.loads(Path(output).read_text())
assert generated["schema"] == "release-candidate-proof/v2"
assert generated["candidate"] == {"tag": tag, "version": tag[1:]}
assert generated["required_proof"]["schema"] == "required-proof/v2"
assert set(generated["artifacts"][0]) == {"kind", "path", "sha"}
run_references = [
    artifact
    for artifact in generated["artifacts"]
    if artifact["kind"] == "github-actions-run"
]
assert run_references
assert all(f"/actions/runs/" in artifact["path"] for artifact in run_references)
assert {job["name"] for job in generated["required_ci"]["jobs"]} >= set(required_names)
assert all(
    job["conclusion"] == "success"
    for job in generated["required_ci"]["jobs"]
    if job["tier"] == "required"
)

proof_mutations = (
    (
        malformed_required_proof,
        "E_REQUIRED_PROOF_INVALID",
        str(Path(work) / "malformed-required-output.json"),
    ),
    (
        fabricated_required_proof,
        "E_REQUIRED_PROOF_GRAPH_MISMATCH",
        str(Path(work) / "fabricated-required-output.json"),
    ),
)
for proof_path, expected, output_path in proof_mutations:
    install_api()
    sys.argv = arguments(proof_path, output_path)
    try:
        verifier.main()
    except SystemExit as error:
        assert expected in str(error), error
    else:
        raise AssertionError(f"accepted mutation expected to fail with {expected}")
    assert not Path(output_path).exists()

ci_mutations = (
    (
        {"run_sha": "b" * 40},
        "E_REQUIRED_CI_SHA_MISMATCH",
        "cross-commit-output.json",
    ),
    (
        {"run_path": ".github/workflows/release.yml"},
        "E_REQUIRED_CI_PROVENANCE",
        "wrong-workflow-output.json",
    ),
    (
        {"failed_job": required_names[0]},
        "E_REQUIRED_CI_NOT_GREEN",
        "failed-required-output.json",
    ),
    (
        {"missing_job": required_names[0]},
        "E_REQUIRED_CI_MISSING_JOB",
        "missing-required-output.json",
    ),
    (
        {"relabel_job": (required_names[0], advisory_names[0])},
        "E_REQUIRED_CI_PROVENANCE",
        "relabeled-failure-output.json",
    ),
    (
        {"external_failure": True},
        "E_REQUIRED_CI_NOT_GREEN",
        "external-required-output.json",
    ),
)
for mutation, expected, filename in ci_mutations:
    output_path = str(Path(work) / filename)
    install_api(**mutation)
    sys.argv = arguments(required_proof, output_path)
    try:
        verifier.main()
    except SystemExit as error:
        assert expected in str(error), error
    else:
        raise AssertionError(f"accepted CI mutation expected to fail with {expected}")
    assert not Path(output_path).exists()

# A matching-SHA local JSON object is no longer an input channel at all.
forged = str(Path(work) / "forged-ci.json")
Path(forged).write_text(json.dumps({
    "sha": sha,
    "jobs": [{
        "name": required_names[0],
        "tier": "required",
        "status": "completed",
        "conclusion": "success",
    }],
}) + "\n")
sys.argv = arguments(required_proof, str(Path(work) / "forged-output.json")) + [
    "--ci-json", forged,
]
try:
    with contextlib.redirect_stderr(io.StringIO()):
        verifier.main()
except SystemExit as error:
    assert error.code == 2, error
else:
    raise AssertionError("caller-authored --ci-json was still accepted")
PY
python3 "$ROOT/scripts/validate_evidence.py" "$proof" >"$work/proof-validation.out"
grep -q '^OK' "$work/proof-validation.out"

unknown="$work/release-candidate-proof-unknown-field.json"
python3 - "$proof" "$unknown" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text())
document["artifacts"][0]["sha256"] = "sha256:" + "0" * 64
Path(sys.argv[2]).write_text(json.dumps(document) + "\n")
PY
set +e
python3 "$ROOT/scripts/validate_evidence.py" "$unknown" >"$work/unknown-field.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -q 'E_SCHEMA at /artifacts/0' "$work/unknown-field.out"

PYTHONPATH="$ROOT" python3 - "$work/versions" <<'PY'
import sys
from pathlib import Path
from scripts.verify_release_exact_sha import candidate_version

base = Path(sys.argv[1])

def manifests(name, server_version, workspace_version=None):
    root = base / name
    (root / "crates/oraclemcp").mkdir(parents=True, exist_ok=True)
    workspace_package = ""
    if workspace_version is not None:
        workspace_package = f'\n[workspace.package]\nversion = "{workspace_version}"\n'
    (root / "Cargo.toml").write_text(f'[workspace]\nmembers = []\n{workspace_package}')
    (root / "crates/oraclemcp/Cargo.toml").write_text(
        f'[package]\nname = "oraclemcp"\nversion = "{server_version}"\n'
    )
    return root

stable = manifests("stable", "1.2.3")
prerelease = manifests("prerelease", "1.2.3-rc.1")
workspace_mismatch = manifests("workspace-mismatch", "1.2.3-rc.1", "1.2.3")
assert candidate_version("v1.2.3", stable) == "1.2.3"
assert candidate_version("v1.2.3-rc.1", prerelease) == "1.2.3-rc.1"

for tag, root in (
    ("v1.2.3", prerelease),
    ("v1.2.3-rc.1", stable),
    ("v1.2.3-rc.1", workspace_mismatch),
):
    try:
        candidate_version(tag, root)
    except SystemExit as error:
        assert "E_TAG_VERSION_MISMATCH" in str(error)
    else:
        raise AssertionError(f"accepted mismatched {tag} in {root}")
PY

set +e
FAKE_COSIGN_VERSION=v2.4.1 PYTHONPATH="$ROOT" python3 - >"$work/cosign-v2.out" 2>&1 <<'PY'
import os
from scripts.verify_release_exact_sha import require_cosign_v3
require_cosign_v3(os.environ["ORACLEMCP_COSIGN_BIN"])
PY
status=$?
set -e
test "$status" -ne 0
grep -q 'E_COSIGN_VERSION: cosign v3 required' "$work/cosign-v2.out"

echo 'verify-release-exact-sha: authenticated CI, v2 graph, cosign v3 bundles, and version contracts OK'
