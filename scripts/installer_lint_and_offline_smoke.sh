#!/usr/bin/env bash
# Offline installer gate: syntax, shellcheck when available, dry-run contract,
# and no service-manager mutation unless explicitly requested.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'installer-smoke: %s\n' "$*" >&2
  exit 1
}

contains() {
  local haystack="$1" needle="$2"
  [[ "$haystack" == *"$needle"* ]] || fail "expected output to contain: $needle"
}

not_contains() {
  local haystack="$1" needle="$2"
  [[ "$haystack" != *"$needle"* ]] || fail "output unexpectedly contained: $needle"
}

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck install.sh scripts/installer_lint_and_offline_smoke.sh
elif [ "${ORACLEMCP_INSTALLER_REQUIRE_SHELLCHECK:-0}" = "1" ]; then
  fail "shellcheck is required but not installed"
else
  printf 'installer-smoke: shellcheck not installed; skipping shellcheck\n' >&2
fi

bash -n install.sh
bash -n scripts/installer_lint_and_offline_smoke.sh

SMOKE_ROOT="$ROOT/target/installer-smoke"
PREFIX="$SMOKE_ROOT/prefix"
HOME_DIR="$SMOKE_ROOT/home"
CONFIG_HOME="$SMOKE_ROOT/config"
SMOKE_VERSION="9.9.9-installer-smoke"
mkdir -p "$SMOKE_ROOT" "$HOME_DIR" "$CONFIG_HOME"

dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX"
)"

contains "$dry_output" "mode: prebuilt"
contains "$dry_output" "archive: https://github.com/MuhDur/oraclemcp/releases/download/v$SMOKE_VERSION/oraclemcp-x86_64-unknown-linux-musl.tar.gz"
contains "$dry_output" "checksum verifies transport integrity only; cosign verifies authenticity and provenance"
contains "$dry_output" "$PREFIX/bin/oraclemcp"
contains "$dry_output" "$PREFIX/bin/om"
contains "$dry_output" "$PREFIX/share/bash-completion/completions/oraclemcp"
contains "$dry_output" "$PREFIX/share/zsh/site-functions/_om"
contains "$dry_output" "$PREFIX/share/fish/vendor_completions.d/om.fish"
contains "$dry_output" "$PREFIX/share/powershell/Completions/oraclemcp.ps1"
contains "$dry_output" "service: not requested; no service-manager files or units will be touched"
contains "$dry_output" "client_registration: not requested; no clients.json credential will be issued"
not_contains "$dry_output" "service install --yes"
not_contains "$dry_output" "clients issue"

if [ -e "$PREFIX/bin/oraclemcp" ] || [ -e "$PREFIX/bin/om" ]; then
  fail "dry-run created installed files under $PREFIX"
fi

service_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX" \
      --service \
      --yes \
      --profile db_ro \
      --listen 127.0.0.1:7070
)"

contains "$service_output" "unit: $CONFIG_HOME/systemd/user/oraclemcp.service"
contains "$service_output" "$PREFIX/bin/oraclemcp service install --yes --name oraclemcp --listen 127.0.0.1:7070 --profile db_ro"
contains "$service_output" "readyz_gate: curl --fail --silent --show-error http://127.0.0.1:7070/readyz"

client_service_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX" \
      --service \
      --yes \
      --profile db_ro \
      --listen 127.0.0.1:7070 \
      --register-client codex-cli \
      --client-scope oracle:read \
      --client-scope oracle:execute
)"

contains "$client_service_output" "$PREFIX/bin/oraclemcp service install --yes --name oraclemcp --listen 127.0.0.1:7070 --profile db_ro --client-credentials"
contains "$client_service_output" "$PREFIX/bin/oraclemcp clients issue --label codex-cli --scope oracle:read --scope oracle:execute"
contains "$client_service_output" "secret_rule: bearer is printed once by the command"

source_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" \
    bash install.sh \
      --dry-run \
      --source \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX"
)"

contains "$source_output" "mode: source"
contains "$source_output" "cargo +nightly-2026-05-11 install oraclemcp --locked --version $SMOKE_VERSION --root $PREFIX"
contains "$source_output" "source builds are explicit opt-in"

printf 'installer-smoke: OK\n'
