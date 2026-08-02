#!/usr/bin/env bash
# Hermetic contracts for CI fixture pins and the release-container build context.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:---static}"

fail() {
  echo "container-supply-chain-contract-test: $*" >&2
  exit 1
}

case "$MODE" in
  --static | --context) ;;
  *) fail "usage: $0 [--static|--context]" ;;
esac

python3 - "$ROOT" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
operations = (root / "docs/operations.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")

PSSA_VERSION = "1.25.0"
PYTHON_ORACLEDB_VERSION = "4.0.2"
ORACLE_SERVICE = (
    "gvenzl/oracle-free:23-slim@sha256:"
    "fbbd3023d5abc33e36d3814816e6fd740e8efabeaa70cf470ddeab5874a3f6f8"
)
ORACLELINUX = (
    "oraclelinux:9@sha256:"
    "fe2c9e975c93c1b8c00712e5ad40e0127c0f1982c2d76031f1e09e5307e32aeb"
)
DOCKERFILE_FRONTEND = (
    "# syntax=docker/dockerfile:1@sha256:"
    "87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89"
)
RUSTUP_SHA = {
    "x86_64-unknown-linux-gnu": "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c",
    "aarch64-unknown-linux-gnu": "e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def service_images(workflow: str) -> list[str]:
    images: list[str] = []
    lines = workflow.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)services:\s*(?:#.*)?$", lines[index])
        if match is None:
            index += 1
            continue
        services_indent = len(match.group(1))
        index += 1
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped and not stripped.startswith("#") and indent <= services_indent:
                break
            image = re.match(r"^\s*image:\s*([^\s#]+)", line)
            if image is not None:
                images.append(image.group(1))
            index += 1
    return images


def validate_ci(workflow: str) -> None:
    require(
        f'  PSSCRIPTANALYZER_VERSION: "{PSSA_VERSION}"' in workflow,
        "PSScriptAnalyzer policy version is not exact",
    )
    require(
        workflow.count("PSSCRIPTANALYZER_VERSION") == 3,
        "PSScriptAnalyzer policy is missing or overridden outside the reviewed uses",
    )
    pssa_installs = re.findall(r"^\s*Install-Module PSScriptAnalyzer.*$", workflow, re.MULTILINE)
    require(len(pssa_installs) == 1, "expected one PSScriptAnalyzer install")
    require(
        "-Repository PSGallery -RequiredVersion $env:PSSCRIPTANALYZER_VERSION" in pssa_installs[0],
        "PSScriptAnalyzer install is not RequiredVersion-bound",
    )
    require(
        "Import-Module PSScriptAnalyzer -RequiredVersion $requiredPssaVersion -Force" in workflow,
        "PSScriptAnalyzer import is not RequiredVersion-bound",
    )
    require(
        "$loadedPssaVersions.Count -ne 1 -or $loadedPssaVersions[0] -ne $requiredPssaVersion"
        in workflow,
        "loaded PSScriptAnalyzer version is not asserted",
    )

    require(
        f'  PYTHON_ORACLEDB_VERSION: "{PYTHON_ORACLEDB_VERSION}"' in workflow,
        "python-oracledb fixture policy version is not exact",
    )
    require(
        workflow.count("PYTHON_ORACLEDB_VERSION") == 3,
        "python-oracledb policy is missing or overridden outside the reviewed uses",
    )
    python_installs = re.findall(
        r'^\s*python3 -m pip install[^\n]*"oracledb==\$\{PYTHON_ORACLEDB_VERSION\}"[^\n]*$',
        workflow,
        re.MULTILINE,
    )
    require(len(python_installs) == 1, "python-oracledb install is not exact-policy-bound")
    require(
        'if oracledb.__version__ != expected:' in workflow,
        "loaded python-oracledb version is not asserted",
    )

    images = service_images(workflow)
    require(images, "workflow has no service image to lint")
    require(ORACLE_SERVICE in images, "reviewed Oracle service digest is missing")
    for image in images:
        require(
            re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) is not None,
            f"service image is not digest-pinned: {image}",
        )
    sensitive_job = re.search(
        r"^  sensitive-data:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    require(sensitive_job is not None, "sensitive-data CI job is missing")
    sensitive_body = sensitive_job.group("body")
    require("needs: web-build" in sensitive_body, "context proof does not consume the reviewed dashboard build")
    require(
        "name: oraclemcp-dashboard-dist" in sensitive_body
        and "path: web/dist" in sensitive_body,
        "context proof does not restore the reviewed dashboard bundle",
    )
    require(
        "bash tests/container_supply_chain_contract_test.sh --context" in sensitive_body,
        "sensitive-data CI does not run the Docker context inventory proof",
    )


def validate_dockerfile(source: str) -> None:
    require(
        source.startswith(DOCKERFILE_FRONTEND + "\n"),
        "Dockerfile frontend is not digest-pinned",
    )
    stages: set[str] = set()
    external: list[str] = []
    for match in re.finditer(
        r"^FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+(\S+))?\s*$",
        source,
        re.IGNORECASE | re.MULTILINE,
    ):
        image, alias = match.group(1), match.group(2)
        if image.lower() not in stages:
            external.append(image)
        if alias is not None:
            stages.add(alias.lower())
    require(external == [ORACLELINUX, ORACLELINUX], f"unreviewed external FROM set: {external}")

    require("ARG RUSTUP_VERSION=1.28.2" in source, "rustup-init version is not pinned")
    require("https://sh.rustup.rs" not in source, "streamed rustup shell bootstrap remains")
    require(
        '"https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustup_target}/rustup-init"'
        in source,
        "pinned rustup-init archive URL is missing",
    )
    require(
        'echo "${rustup_sha}  /tmp/rustup-init" | sha256sum --check --strict' in source,
        "rustup-init bytes are not fail-closed SHA-256 checked",
    )
    for target, digest in RUSTUP_SHA.items():
        require(target in source, f"rustup-init target is missing: {target}")
        require(digest in source, f"rustup-init digest is missing: {target}")

    builds = re.findall(r"^RUN cargo build.*$", source, re.MULTILINE)
    require(len(builds) == 2, f"expected two release cargo builds, found {len(builds)}")
    require(all(" --locked " in f" {line} " for line in builds), "release cargo build lacks --locked")

    require("FROM runtime-base AS runtime\n" in source, "core runtime does not inherit runtime-base")
    require(
        "FROM runtime-base AS runtime-plsql-intelligence\n" in source,
        "PL/SQL runtime does not inherit runtime-base",
    )
    require("useradd --uid 10001 --gid 10001 --no-create-home" in source, "fixed runtime UID/GID is missing")
    require("USER 10001:10001" in source, "runtime user is not fixed and nonzero")
    require("USER root" not in source and "USER 0" not in source, "runtime resets to root")
    require(
        'RUN test "$(id -u)" -eq 10001' in source,
        "runtime build does not execute as the fixed nonzero UID",
    )
    require(
        "/home/oraclemcp/.config/oraclemcp" in source
        and "/home/oraclemcp/.local/state/oraclemcp" in source,
        "bounded config/state writable paths are missing",
    )


ALLOWED = {
    "!Cargo.toml",
    "!Cargo.lock",
    "!rust-toolchain.toml",
    "!.cargo/",
    "!.cargo/config.toml",
    "!scripts/",
    "!scripts/cargo_build_guard.sh",
    "!scripts/check_build_lease.sh",
    "!crates/",
    "!crates/*/",
    "!crates/*/Cargo.toml",
    "!crates/*/README.md",
    "!crates/*/src/",
    "!crates/*/src/**",
    "!crates/oraclemcp-db/benches/",
    "!crates/oraclemcp-db/benches/classify_type.rs",
    "!crates/oraclemcp-db/benches/lob_capping.rs",
    "!crates/oraclemcp-db/benches/page_serialization.rs",
    "!crates/oraclemcp/install.sh",
    "!crates/oraclemcp/install.ps1",
    "!crates/oraclemcp-core/ci_taxonomy.json",
    "!web/",
    "!web/dist/",
    "!web/dist/**",
}
BARRIERS = {
    ".cargo/**",
    "scripts/**",
    "crates/**",
    "crates/*/**",
    "crates/*/src/**",
    "crates/oraclemcp-db/benches/**",
    "web/**",
    "web/dist/**",
}
SENSITIVE = {
    "**/.env",
    "**/.env.*",
    "**/.aws/**",
    "**/.oci/**",
    "**/.azure/**",
    "**/.kube/**",
    "**/.docker/config.json",
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.npmrc",
    "**/.pypirc",
    "**/.netrc",
    "**/.git/**",
    "**/.beads/**",
    "**/.claude/**",
    "**/.codex/**",
    "**/.agents/**",
    "**/.ntm/**",
    "**/.cursor/**",
    "**/.continue/**",
    "**/.gemini/**",
    "**/.aider*",
    "**/todelete/**",
    "**/wallet/**",
    "**/Wallet_*/**",
    "**/node_modules/**",
    "**/playwright-report/**",
    "**/test-results/**",
    "**/tests/artifacts/**",
    "**/target/**",
    "**/tnsnames.ora",
    "**/sqlnet.ora",
    "**/oraaccess.xml",
    "**/id_rsa",
    "**/id_ed25519",
    "**/credentials.json",
    "**/*-credentials.json",
    "**/secrets.json",
    "**/*-secrets.json",
    "**/*.key",
    "**/*.pem",
    "**/*.p12",
    "**/*.pfx",
    "**/*.sso",
    "**/*.jks",
    "**/*.keystore",
    "**/*.dmp",
    "**/*.db",
    "**/*.sqlite",
    "**/*.sqlite3",
    "**/*.log",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.kdbx",
    "**/*.ovpn",
}


def validate_dockerignore(source: str) -> None:
    patterns = [
        line.strip()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    require(patterns and patterns[0] == "**", "Docker context is not deny-all by default")
    allowed = {pattern for pattern in patterns if pattern.startswith("!")}
    require(allowed == ALLOWED, f"Docker context allowlist drifted: {sorted(allowed ^ ALLOWED)}")
    missing_barriers = BARRIERS.difference(patterns)
    require(
        not missing_barriers,
        f"Docker context parent re-ignore barriers missing: {sorted(missing_barriers)}",
    )
    missing_sensitive = SENSITIVE.difference(patterns)
    require(not missing_sensitive, f"sensitive context exclusions missing: {sorted(missing_sensitive)}")


def rejects(label: str, validator, mutated: str) -> None:
    try:
        validator(mutated)
    except AssertionError:
        return
    raise AssertionError(f"negative fixture unexpectedly passed: {label}")


def validate_operations(source: str) -> None:
    match = re.search(
        r"# Against a configured profile\.(?P<block>.*?)\nfi\n```",
        source,
        re.DOTALL,
    )
    require(match is not None, "documented profile bind command is missing")
    block = match.group("block")
    root_guard = 'if [ "$(id -u)" -eq 0 ]; then'
    else_branch = "\nelse\n"
    docker_command = 'docker run -i --rm --user "$(id -u):$(id -g)"'
    require(root_guard in block, "documented profile bind does not refuse root")
    require(else_branch in block, "documented root refusal does not guard the Docker branch")
    require(docker_command in block, "documented profile bind lacks the nonroot UID override")
    require(
        block.index(root_guard) < block.index(else_branch) < block.index(docker_command),
        "documented Docker command is reachable from the root branch",
    )
    require(
        '$container_state:/home/oraclemcp/.local/state/oraclemcp' in block,
        "documented bind mounts do not preserve private host ownership",
    )


validate_ci(ci)
validate_dockerfile(dockerfile)
validate_dockerignore(dockerignore)
validate_operations(operations)
require(
    "/home/oraclemcp/.config/oraclemcp:ro" in operations
    and "/root/.config/oraclemcp:ro" not in operations,
    "container configuration mount documentation does not match the nonroot HOME",
)
require(
    'docker run -i --rm --user "$(id -u):$(id -g)"' in readme
    and "/home/oraclemcp/.config/oraclemcp:ro" in readme
    and "/home/oraclemcp/.local/state/oraclemcp" in readme
    and "/root/.config/oraclemcp:ro" not in readme,
    "README container quick start does not match the verified nonroot bind contract",
)
require(
    "runAsUser: 10001" in operations
    and "runAsGroup: 10001" in operations
    and "fsGroup: 10001" in operations
    and "/home/nonroot/" not in operations,
    "Kubernetes runtime identity does not match the image",
)

rejects("PSScriptAnalyzer version drift", validate_ci, ci.replace('"1.25.0"', '"1.25.1"', 1))
rejects(
    "PSScriptAnalyzer unpinned install",
    validate_ci,
    ci.replace(" -RequiredVersion $env:PSSCRIPTANALYZER_VERSION", "", 1),
)
rejects("python-oracledb version drift", validate_ci, ci.replace('"4.0.2"', '"4.0.3"', 1))
rejects("tag-only service", validate_ci, ci.replace(ORACLE_SERVICE, "gvenzl/oracle-free:23-slim", 1))
rejects(
    "tag-only Dockerfile frontend",
    validate_dockerfile,
    dockerfile.replace(DOCKERFILE_FRONTEND, "# syntax=docker/dockerfile:1", 1),
)
rejects("tag-only Docker base", validate_dockerfile, dockerfile.replace(ORACLELINUX, "oraclelinux:9", 1))
rejects(
    "wrong rustup-init digest",
    validate_dockerfile,
    dockerfile.replace(RUSTUP_SHA["x86_64-unknown-linux-gnu"], "0" * 64, 1),
)
rejects("unlocked Cargo build", validate_dockerfile, dockerfile.replace("cargo build --locked", "cargo build", 1))
rejects("root runtime", validate_dockerfile, dockerfile.replace("USER 10001:10001", "USER root", 1))
rejects("Docker context default allow", validate_dockerignore, dockerignore.replace("**\n", "", 1))
rejects(
    "Docker context parent barrier removed",
    validate_dockerignore,
    dockerignore.replace("crates/*/**\n", "", 1),
)
rejects("unexpected context inclusion", validate_dockerignore, dockerignore + "\n!secrets/**\n")
rejects("private-key exclusion removed", validate_dockerignore, dockerignore.replace("**/*.key\n", "", 1))
rejects(
    "root guard detached from Docker branch",
    validate_operations,
    operations.replace("\nelse\n", "\nfi\n", 1),
)

print("container-supply-chain-contract-test: static contracts OK")
PY

[ "$MODE" = "--context" ] || exit 0
command -v docker >/dev/null 2>&1 || fail "docker is required for --context"
docker buildx version >/dev/null 2>&1 || fail "docker buildx is required for --context"
command -v tar >/dev/null 2>&1 || fail "tar is required for --context"

documented_bind_block="$(python3 - "$ROOT/docs/operations.md" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("# Against a configured profile.")
end = source.index("\n```", start)
print(source[start:end])
PY
)"
root_guard_output="$(
  DOCUMENTED_BIND_BLOCK="$documented_bind_block" sh -c '
    id() {
      case "$1" in
        -u | -g) printf "%s\\n" 0 ;;
        *) command id "$@" ;;
      esac
    }
    docker() { printf "%s\\n" docker-called; }
    eval "$DOCUMENTED_BIND_BLOCK"
  '
)"
if grep -F "docker-called" <<<"$root_guard_output" >/dev/null; then
  fail "documented root refusal still reaches docker run"
fi

dockerfile_check="$(docker buildx build --check --progress=plain "$ROOT" 2>&1)" || {
  printf '%s\n' "$dockerfile_check" >&2
  fail "Dockerfile frontend check failed"
}
printf '%s\n' "$dockerfile_check"
grep -F "Check complete, no warnings found." <<<"$dockerfile_check" >/dev/null ||
  fail "Dockerfile frontend check reported warnings"

actual_inventory="$(
  printf '%s\n' \
    '# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89' \
    'FROM scratch' \
    'COPY . /context' |
    docker buildx build --progress=quiet -f - --output=type=tar,dest=- "$ROOT" |
    tar -tf -
)"
python3 - "$ROOT" "$actual_inventory" <<'PY'
from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
inventory = sys.argv[2].splitlines()
files = {
    entry.removeprefix("context/")
    for entry in inventory
    if entry.startswith("context/") and not entry.endswith("/")
}
exact = {
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "scripts/cargo_build_guard.sh",
    "scripts/check_build_lease.sh",
    "crates/oraclemcp/install.sh",
    "crates/oraclemcp/install.ps1",
    "crates/oraclemcp-core/ci_taxonomy.json",
    "crates/oraclemcp-db/benches/classify_type.rs",
    "crates/oraclemcp-db/benches/lob_capping.rs",
    "crates/oraclemcp-db/benches/page_serialization.rs",
}


def allowed(path: str) -> bool:
    return (
        path in exact
        or re.fullmatch(r"crates/[^/]+/Cargo\.toml", path) is not None
        or re.fullmatch(r"crates/[^/]+/README\.md", path) is not None
        or re.fullmatch(r"crates/[^/]+/src/.+", path) is not None
        or path.startswith("web/dist/")
    )


unexpected = sorted(path for path in files if not allowed(path))
if unexpected:
    raise AssertionError(f"unexpected actual Docker context files: {unexpected}")

tracked = set(
    subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
)
untracked = sorted(files.difference(tracked))
untracked_outside_dist = [path for path in untracked if not path.startswith("web/dist/")]
if untracked_outside_dist:
    raise AssertionError(
        f"untracked files reached actual Docker context: {untracked_outside_dist}"
    )

dist_prefix = "web/dist/"
dist_files = {path.removeprefix(dist_prefix) for path in files if path.startswith(dist_prefix)}
hash_name = "oraclemcp-dashboard.sha256"
hash_path = root / "web/dist" / hash_name
if not hash_path.is_file():
    raise AssertionError("reviewed dashboard hash inventory is missing from Docker context")
manifest: dict[str, str] = {}
for line in hash_path.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
    if match is None:
        raise AssertionError(f"invalid dashboard hash inventory line: {line!r}")
    digest, path = match.groups()
    if path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts or path in manifest:
        raise AssertionError(f"unsafe or duplicate dashboard inventory path: {path!r}")
    manifest[path] = digest

expected_dist = set(manifest) | {hash_name}
if dist_files != expected_dist:
    raise AssertionError(
        "dashboard Docker context differs from its reviewed hash inventory: "
        f"{sorted(dist_files ^ expected_dist)}"
    )

for path, expected_digest in manifest.items():
    actual_digest = hashlib.sha256((root / "web/dist" / path).read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        raise AssertionError(f"dashboard Docker context digest mismatch: {path}")

required = {
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "scripts/cargo_build_guard.sh",
    "scripts/check_build_lease.sh",
    "crates/oraclemcp/Cargo.toml",
    "crates/oraclemcp/src/main.rs",
    "crates/oraclemcp/install.sh",
    "crates/oraclemcp/install.ps1",
    "crates/oraclemcp-core/ci_taxonomy.json",
    "crates/oraclemcp-db/benches/classify_type.rs",
    "crates/oraclemcp-db/benches/lob_capping.rs",
    "crates/oraclemcp-db/benches/page_serialization.rs",
    "web/dist/index.html",
    "web/dist/oraclemcp-dashboard.cyclonedx.json",
    "web/dist/oraclemcp-dashboard.sha256",
}
missing = sorted(required.difference(files))
if missing:
    raise AssertionError(f"required actual Docker context files missing: {missing}")

print(f"container-supply-chain-contract-test: actual reviewed inventory OK ({len(files)} files)")
PY

context_root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/oraclemcp-container-context.XXXXXX")"
python3 - "$ROOT" "$context_root" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
context = pathlib.Path(sys.argv[2])


def add(path: str, data: bytes = b"sentinel\n") -> None:
    target = context / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


add(".dockerignore", (root / ".dockerignore").read_bytes())
add(
    "Dockerfile",
    b"# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89\n"
    b"FROM scratch\nCOPY . /context\n",
)

required = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "scripts/cargo_build_guard.sh",
    "scripts/check_build_lease.sh",
    "crates/oraclemcp/Cargo.toml",
    "crates/oraclemcp/src/main.rs",
    "crates/oraclemcp/install.sh",
    "crates/oraclemcp/install.ps1",
    "crates/oraclemcp-core/ci_taxonomy.json",
    "crates/oraclemcp-db/benches/classify_type.rs",
    "crates/oraclemcp-db/benches/lob_capping.rs",
    "crates/oraclemcp-db/benches/page_serialization.rs",
    "web/dist/index.html",
]
for path in required:
    add(path, b"required-build-input\n")

excluded = [
    ".env",
    ".env.production",
    ".aws/credentials",
    ".oci/config",
    ".azure/accessTokens.json",
    ".kube/config",
    ".docker/config.json",
    ".ssh/id_rsa",
    ".npmrc",
    ".netrc",
    ".beads/beads.db",
    ".claude/session.json",
    ".codex/history.jsonl",
    ".agents/state.json",
    ".ntm/pane.log",
    "todelete/quarantine.txt",
    "wallet/cwallet.sso",
    "network/tnsnames.ora",
    "certs/client.key",
    "secrets/token.pem",
    "target/debug/oraclemcp",
    "tests/artifacts/live-customer.json",
    "web/node_modules/pkg/index.js",
    "web/playwright-report/index.html",
    "crates/oraclemcp/src/.env",
    "crates/oraclemcp/src/client.key",
    "crates/oraclemcp/src/cloud-credentials.json",
    "crates/oraclemcp/src/local.tfstate",
    "web/dist/wallet/cwallet.sso",
    "web/dist/private.pem",
    "crates/oraclemcp-audit/fuzz/artifacts/crash-deadbeef",
    "crates/oraclemcp/benches/local.rs",
    "crates/oraclemcp-db/benches/local.rs",
    "crates/oraclemcp/tests/local.rs",
    "scripts/foreign-helper.sh",
    "web/src/app/local.tsx",
]
for path in excluded:
    add(path)
PY

inventory="$(
  docker buildx build --progress=plain --output=type=tar,dest=- "$context_root" |
    tar -tf -
)"

for path in \
  Cargo.toml \
  Cargo.lock \
  rust-toolchain.toml \
  .cargo/config.toml \
  scripts/cargo_build_guard.sh \
  scripts/check_build_lease.sh \
  crates/oraclemcp/Cargo.toml \
  crates/oraclemcp/src/main.rs \
  crates/oraclemcp/install.sh \
  crates/oraclemcp/install.ps1 \
  crates/oraclemcp-core/ci_taxonomy.json \
  crates/oraclemcp-db/benches/classify_type.rs \
  crates/oraclemcp-db/benches/lob_capping.rs \
  crates/oraclemcp-db/benches/page_serialization.rs \
  web/dist/index.html; do
  grep -Fx "context/$path" <<<"$inventory" >/dev/null ||
    fail "required build input was excluded from Docker context: $path"
done

for path in \
  .env \
  .env.production \
  .aws/credentials \
  .oci/config \
  .azure/accessTokens.json \
  .kube/config \
  .docker/config.json \
  .ssh/id_rsa \
  .npmrc \
  .netrc \
  .beads/beads.db \
  .claude/session.json \
  .codex/history.jsonl \
  .agents/state.json \
  .ntm/pane.log \
  todelete/quarantine.txt \
  wallet/cwallet.sso \
  network/tnsnames.ora \
  certs/client.key \
  secrets/token.pem \
  target/debug/oraclemcp \
  tests/artifacts/live-customer.json \
  web/node_modules/pkg/index.js \
  web/playwright-report/index.html \
  crates/oraclemcp/src/.env \
  crates/oraclemcp/src/client.key \
  crates/oraclemcp/src/cloud-credentials.json \
  crates/oraclemcp/src/local.tfstate \
  web/dist/wallet/cwallet.sso \
  web/dist/private.pem \
  crates/oraclemcp-audit/fuzz/artifacts/crash-deadbeef \
  crates/oraclemcp/benches/local.rs \
  crates/oraclemcp-db/benches/local.rs \
  crates/oraclemcp/tests/local.rs \
  scripts/foreign-helper.sh \
  web/src/app/local.tsx; do
  if grep -Fx "context/$path" <<<"$inventory" >/dev/null; then
    fail "excluded sentinel reached Docker context: $path"
  fi
done

host_config="$context_root/host-config"
host_state="$context_root/host-state"
mkdir -p "$host_config" "$host_state"
chmod 0700 "$host_config" "$host_state"
printf '%s\n' '[profiles.fixture]' >"$host_config/profiles.toml"
chmod 0600 "$host_config/profiles.toml"
test "$(id -u)" -ne 0 || fail "host-UID bind proof refuses root"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/home/oraclemcp \
  -e XDG_CONFIG_HOME=/home/oraclemcp/.config \
  -e XDG_STATE_HOME=/home/oraclemcp/.local/state \
  -v "$host_config:/home/oraclemcp/.config/oraclemcp:ro" \
  -v "$host_state:/home/oraclemcp/.local/state/oraclemcp" \
  oraclelinux:9@sha256:fe2c9e975c93c1b8c00712e5ad40e0127c0f1982c2d76031f1e09e5307e32aeb \
  sh -ceu '
    test "$(id -u)" -ne 0
    test -r "$XDG_CONFIG_HOME/oraclemcp/profiles.toml"
    test -w "$XDG_STATE_HOME/oraclemcp"
    printf "%s\n" verified >"$XDG_STATE_HOME/oraclemcp/bind-proof"
  '
test "$(cat "$host_state/bind-proof")" = "verified" ||
  fail "host-UID state bind did not persist the container write"

echo "container-supply-chain-contract-test: BuildKit sentinel and nonroot bind inventories OK ($context_root)"
