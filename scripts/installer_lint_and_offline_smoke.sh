#!/usr/bin/env bash
# Offline installer gate: syntax, shellcheck/PSSA when available, dry-run
# contract, optional built-artifact offline install, and no service-manager
# mutation unless explicitly requested.
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

checksum_file() {
  local archive="$1" base
  base="$(basename "$archive")"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$archive")" && sha256sum "$base" > "$base.sha256")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$(dirname "$archive")" && shasum -a 256 "$base" > "$base.sha256")
  else
    fail "sha256sum or shasum is required for built artifact smoke"
  fi
}

run_built_artifact_smoke() {
  local built_binary="$1"
  local smoke_target="${ORACLEMCP_INSTALLER_SMOKE_TARGET:-x86_64-unknown-linux-musl}"
  local bundle_root dist archive fake_bin fake_log fake_cosign built_prefix install_output install_status reinstall_output reinstall_status cosign_output

  [ -x "$built_binary" ] || fail "ORACLEMCP_INSTALLER_BUILT_BINARY is not executable: $built_binary"
  case "$smoke_target" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | x86_64-apple-darwin | aarch64-apple-darwin)
      ;;
    *)
      fail "unsupported ORACLEMCP_INSTALLER_SMOKE_TARGET for install.sh smoke: $smoke_target"
      ;;
  esac

  bundle_root="$SMOKE_ROOT/built-artifact-$$"
  dist="$bundle_root/oraclemcp-$smoke_target"
  archive="$bundle_root/oraclemcp-$smoke_target.tar.gz"
  fake_bin="$bundle_root/fake-bin"
  fake_log="$bundle_root/fake-cosign.log"
  fake_cosign="$fake_bin/cosign"
  built_prefix="$SMOKE_ROOT/built-prefix-$$"

  mkdir -p "$dist" "$fake_bin"
  cp "$built_binary" "$dist/oraclemcp"
  chmod +x "$dist/oraclemcp"
  (cd "$bundle_root" && tar czf "$(basename "$archive")" "oraclemcp-$smoke_target")
  checksum_file "$archive"
  : >"$archive.sig"
  : >"$archive.crt"
  : >"$archive.attestation.sigstore.json"

  cat >"$fake_cosign" <<'COSIGN'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  verify-blob | verify-blob-attestation)
    ;;
  *)
    printf 'fake-cosign: unexpected command: %s\n' "${1:-<missing>}" >&2
    exit 2
    ;;
esac
printf '%s\n' "$1" >> "${ORACLEMCP_INSTALLER_FAKE_COSIGN_LOG:?}"
COSIGN
  chmod +x "$fake_cosign"

  set +e
  install_output="$(
    env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
      PATH="$fake_bin:$PATH" \
      ORACLEMCP_INSTALLER_FAKE_COSIGN_LOG="$fake_log" \
      bash install.sh \
        --offline "$archive" \
        --version "$SMOKE_VERSION" \
        --target "$smoke_target" \
        --prefix "$built_prefix" \
        --force \
        --no-service 2>&1
  )"
  install_status=$?
  set -e
  [ "$install_status" -eq 0 ] || fail "built artifact offline install failed: $install_output"

  contains "$install_output" "oraclemcp installer: service install skipped"
  not_contains "$install_output" "service install --yes"
  not_contains "$install_output" "clients issue"
  [ -x "$built_prefix/bin/oraclemcp" ] || fail "built artifact smoke did not install oraclemcp"
  [ -e "$built_prefix/bin/om" ] || fail "built artifact smoke did not install om alias"
  [ -f "$built_prefix/share/powershell/Completions/oraclemcp.ps1" ] || fail "built artifact smoke did not install PowerShell completion"

  cosign_output="$(cat "$fake_log")"
  contains "$cosign_output" "verify-blob"
  contains "$cosign_output" "verify-blob-attestation"

  set +e
  reinstall_output="$(
    env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
      PATH="$fake_bin:$PATH" \
      ORACLEMCP_INSTALLER_FAKE_COSIGN_LOG="$fake_log" \
      bash install.sh \
        --offline "$archive" \
        --version "$SMOKE_VERSION" \
        --target "$smoke_target" \
        --prefix "$built_prefix" \
        --no-service 2>&1
  )"
  reinstall_status=$?
  set -e
  [ "$reinstall_status" -eq 0 ] || fail "built artifact idempotent reinstall failed: $reinstall_output"
  contains "$reinstall_output" "oraclemcp installer: service install skipped"
  not_contains "$reinstall_output" "service install --yes"
  not_contains "$reinstall_output" "clients issue"
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

ps_text="$(tr -d '\r' < install.ps1)"
contains "$ps_text" "certutil.exe -hashfile"
contains "$ps_text" "cosign verify-blob"
contains "$ps_text" "cosign verify-blob-attestation"
contains "$ps_text" "completions powershell"
contains "$ps_text" "service install requires -Service -Yes or -DryRun"
contains "$ps_text" "service: not requested; no service-manager files or units will be touched"
contains "$ps_text" "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING"

if command -v pwsh >/dev/null 2>&1; then
  # shellcheck disable=SC2016 # PowerShell variables must not be expanded by Bash.
  pwsh -NoLogo -NoProfile -Command '
    $errors = $null
    [System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath "install.ps1" -Raw), [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
      $errors | Format-List | Out-String | Write-Error
      exit 1
    }
  '

  if pwsh -NoLogo -NoProfile -Command 'if (Get-Module -ListAvailable PSScriptAnalyzer) { exit 0 } exit 1'; then
    # shellcheck disable=SC2016 # PowerShell variables must not be expanded by Bash.
    pwsh -NoLogo -NoProfile -Command '
      Import-Module PSScriptAnalyzer
      $violations = Invoke-ScriptAnalyzer -Path "install.ps1" -Severity Error,Warning
      if ($violations) {
        $violations | Format-Table -AutoSize | Out-String | Write-Error
        exit 1
      }
    '
  elif [ "${ORACLEMCP_INSTALLER_REQUIRE_PSSA:-0}" = "1" ]; then
    fail "PSScriptAnalyzer is required but not installed"
  else
    printf 'installer-smoke: PSScriptAnalyzer not installed; skipping PSSA\n' >&2
  fi
elif [ "${ORACLEMCP_INSTALLER_REQUIRE_PWSH:-0}" = "1" ]; then
  fail "pwsh is required but not installed"
else
  printf 'installer-smoke: pwsh not installed; skipping install.ps1 parse/dry-run\n' >&2
fi

SMOKE_ROOT="$ROOT/target/installer-smoke"
PREFIX="$SMOKE_ROOT/prefix"
HOME_DIR="$SMOKE_ROOT/home"
CONFIG_HOME="$SMOKE_ROOT/config"
TMP_DIR="$SMOKE_ROOT/tmp"
SMOKE_VERSION="9.9.9-installer-smoke"
mkdir -p "$SMOKE_ROOT" "$HOME_DIR" "$CONFIG_HOME" "$TMP_DIR"

if [ -n "${ORACLEMCP_INSTALLER_BUILT_BINARY:-}" ]; then
  run_built_artifact_smoke "$ORACLEMCP_INSTALLER_BUILT_BINARY"
fi

if command -v pwsh >/dev/null 2>&1; then
  WIN_PREFIX="$SMOKE_ROOT/windows-prefix"
  WIN_OFFLINE_ARCHIVE="$SMOKE_ROOT/offline/oraclemcp-x86_64-pc-windows-msvc.zip"
  win_dry_output="$(
    pwsh -NoLogo -NoProfile -File ./install.ps1 \
      -DryRun \
      -Version "$SMOKE_VERSION" \
      -Prefix "$WIN_PREFIX" \
      -Offline "$WIN_OFFLINE_ARCHIVE"
  )"
  contains "$win_dry_output" "oraclemcp Windows installer plan"
  contains "$win_dry_output" "mode: offline"
  contains "$win_dry_output" "offline_archive: $WIN_OFFLINE_ARCHIVE"
  contains "$win_dry_output" "offline_checksum: $WIN_OFFLINE_ARCHIVE.sha256"
  contains "$win_dry_output" "oraclemcp.exe"
  contains "$win_dry_output" "om.exe"
  contains "$win_dry_output" "service: not requested; no service-manager files or units will be touched"
  not_contains "$win_dry_output" "service install --yes"

  win_service_output="$(
    pwsh -NoLogo -NoProfile -File ./install.ps1 \
      -DryRun \
      -Version "$SMOKE_VERSION" \
      -Prefix "$WIN_PREFIX" \
      -Service \
      -Yes \
      -Profile db_ro \
      -Listen 127.0.0.1:7070
  )"
  contains "$win_service_output" "service install --yes --name oraclemcp --listen 127.0.0.1:7070 --profile db_ro"
  contains "$win_service_output" "readyz_gate: Invoke-WebRequest -UseBasicParsing http://127.0.0.1:7070/readyz"
fi

dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX"
)"

contains "$dry_output" "mode: prebuilt"
contains "$dry_output" "lock: $TMP_DIR/oraclemcp-install-"
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
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
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
contains "$service_output" "readyz_gate: curl --fail --silent --show-error --noproxy '*' http://127.0.0.1:7070/readyz"

client_service_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
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
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
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

OFFLINE_DIR="$SMOKE_ROOT/offline"
OFFLINE_ARCHIVE="$OFFLINE_DIR/oraclemcp-x86_64-unknown-linux-musl.tar.gz"
mkdir -p "$OFFLINE_DIR"

offline_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --dry-run \
      --offline "$OFFLINE_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX"
)"

contains "$offline_output" "mode: offline"
contains "$offline_output" "offline_archive: $OFFLINE_ARCHIVE"
contains "$offline_output" "offline_checksum: $OFFLINE_ARCHIVE.sha256"
contains "$offline_output" "offline_cosign_signature: $OFFLINE_ARCHIVE.sig + $OFFLINE_ARCHIVE.crt"
contains "$offline_output" "offline_cosign_attestation: $OFFLINE_ARCHIVE.attestation.sigstore.json"
not_contains "$offline_output" "archive: https://github.com"

: >"$OFFLINE_ARCHIVE"
set +e
offline_missing_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --offline "$OFFLINE_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX" 2>&1
)"
offline_missing_status=$?
set -e
[ "$offline_missing_status" -ne 0 ] || fail "offline install without bundle metadata unexpectedly succeeded"
contains "$offline_missing_output" "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING"

UNINSTALL_PREFIX="$SMOKE_ROOT/uninstall-prefix-$$"
UNINSTALL_BIN="$UNINSTALL_PREFIX/bin"
mkdir -p \
  "$UNINSTALL_BIN" \
  "$UNINSTALL_PREFIX/share/bash-completion/completions" \
  "$UNINSTALL_PREFIX/share/zsh/site-functions" \
  "$UNINSTALL_PREFIX/share/fish/vendor_completions.d" \
  "$UNINSTALL_PREFIX/share/powershell/Completions"
printf '#!/bin/sh\n' >"$UNINSTALL_BIN/oraclemcp"
printf 'alias\n' >"$UNINSTALL_BIN/om"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/bash-completion/completions/oraclemcp"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/bash-completion/completions/om"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/zsh/site-functions/_oraclemcp"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/zsh/site-functions/_om"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/fish/vendor_completions.d/oraclemcp.fish"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/fish/vendor_completions.d/om.fish"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/powershell/Completions/oraclemcp.ps1"
printf 'complete\n' >"$UNINSTALL_PREFIX/share/powershell/Completions/om.ps1"

uninstall_dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --uninstall \
      --dry-run \
      --no-service \
      --prefix "$UNINSTALL_PREFIX"
)"

contains "$uninstall_dry_output" "oraclemcp uninstall plan"
contains "$uninstall_dry_output" "remove if present: $UNINSTALL_BIN/oraclemcp"
contains "$uninstall_dry_output" "service: not requested; no service-manager files or units will be touched"
[ -e "$UNINSTALL_BIN/oraclemcp" ] || fail "uninstall dry-run removed oraclemcp"

env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
  bash install.sh --uninstall --yes --no-service --prefix "$UNINSTALL_PREFIX" >/dev/null
env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
  bash install.sh --uninstall --yes --no-service --prefix "$UNINSTALL_PREFIX" >/dev/null

for removed in \
  "$UNINSTALL_BIN/oraclemcp" \
  "$UNINSTALL_BIN/om" \
  "$UNINSTALL_PREFIX/share/bash-completion/completions/oraclemcp" \
  "$UNINSTALL_PREFIX/share/bash-completion/completions/om" \
  "$UNINSTALL_PREFIX/share/zsh/site-functions/_oraclemcp" \
  "$UNINSTALL_PREFIX/share/zsh/site-functions/_om" \
  "$UNINSTALL_PREFIX/share/fish/vendor_completions.d/oraclemcp.fish" \
  "$UNINSTALL_PREFIX/share/fish/vendor_completions.d/om.fish" \
  "$UNINSTALL_PREFIX/share/powershell/Completions/oraclemcp.ps1" \
  "$UNINSTALL_PREFIX/share/powershell/Completions/om.ps1"
do
  if [ -e "$removed" ] || [ -L "$removed" ]; then
    fail "uninstall left installed file: $removed"
  fi
done

printf 'installer-smoke: OK\n'
