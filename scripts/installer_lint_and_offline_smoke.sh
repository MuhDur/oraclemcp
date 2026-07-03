#!/usr/bin/env bash
# Offline installer gate: syntax, shellcheck/PSSA when available, dry-run
# contract, optional built-artifact offline install, and no service-manager
# mutation unless explicitly requested.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

E2E_LOG=0
for arg in "$@"; do
  case "$arg" in
    --log)
      E2E_LOG=1
      ;;
    --help | -h)
      cat <<'USAGE'
Run installer lint, offline smoke, idempotency, update, and reversibility checks.

Options:
  --log       emit structured JSON-line events to stderr
  --help      show this help
USAGE
      exit 0
      ;;
    *)
      printf 'installer-smoke: unknown argument: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

E2E_SCENARIO="installer_lint_and_offline_smoke"
E2E_LANE="installer"
E2E_PROFILE="offline"
E2E_LEVEL="READ_ONLY"
export E2E_LOG E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL
# shellcheck disable=SC1091 # ROOT is computed from this script's location.
source "$ROOT/scripts/e2e/lib.sh"

note() {
  if [ "$E2E_LOG" = "1" ]; then
    printf 'installer-smoke: %s\n' "$*"
  else
    printf 'installer-smoke: %s\n' "$*" >&2
  fi
}

log_pass() {
  e2e_log_event "component_gate" "assert" "pass" 0 "$1"
}

log_skip() {
  e2e_log_event "component_gate" "assert" "skipped" 0 "$1"
}

fail() {
  e2e_log_event "component_gate" "assert" "fail" 0 "$*"
  if [ "$E2E_LOG" = "1" ]; then
    printf 'installer-smoke: %s\n' "$*"
  else
    printf 'installer-smoke: %s\n' "$*" >&2
  fi
  exit 1
}

contains() {
  local haystack="$1" needle="$2"
  [[ "$haystack" == *"$needle"* ]] || fail "expected output to contain: $needle"
}

contains_unwrapped_fragments() {
  local haystack="$1" label="$2" fragment normalized
  shift 2
  normalized="${haystack//$'\r'/}"
  normalized="${normalized//$'\n'/}"
  for fragment in "$@"; do
    [[ "$normalized" == *"$fragment"* ]] \
      || fail "expected unwrapped $label output to contain fragment: $fragment"
  done
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

write_fake_release_archive() {
  local archive="$1" target="$2" root dist
  root="$(dirname "$archive")"
  dist="$root/oraclemcp-$target"
  mkdir -p "$dist"
  cat >"$dist/oraclemcp" <<'BIN'
#!/usr/bin/env sh
echo "oraclemcp installer smoke binary"
BIN
  chmod +x "$dist/oraclemcp"
  (cd "$root" && tar czf "$(basename "$archive")" "oraclemcp-$target")
  checksum_file "$archive"
}

write_versioned_release_archive() {
  local archive="$1" target="$2" version="$3" root dist
  root="$(dirname "$archive")"
  dist="$root/oraclemcp-$target"
  mkdir -p "$dist"
  cat >"$dist/oraclemcp" <<BIN
#!/usr/bin/env sh
if [ "\${1:-}" = "--version" ]; then
  echo "oraclemcp $version"
  exit 0
fi
if [ "\${1:-}" = "doctor" ] || { [ "\${1:-}" = "--json" ] && [ "\${2:-}" = "doctor" ]; }; then
  echo '{"ok":true,"exit_code":0}'
  exit 0
fi
echo "oraclemcp $version installer smoke binary"
BIN
  chmod +x "$dist/oraclemcp"
  (cd "$root" && tar czf "$(basename "$archive")" "oraclemcp-$target")
  checksum_file "$archive"
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
  log_pass "built artifact offline install and idempotent reinstall"
}

e2e_log_event "scenario_start" "setup" "running" 0 "installer lint and offline acceptance suite"

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck install.sh scripts/installer_lint_and_offline_smoke.sh
elif [ "${ORACLEMCP_INSTALLER_REQUIRE_SHELLCHECK:-0}" = "1" ]; then
  fail "shellcheck is required but not installed"
else
  note "shellcheck not installed; skipping shellcheck"
  log_skip "shellcheck unavailable"
fi

bash -n install.sh
bash -n scripts/installer_lint_and_offline_smoke.sh

ps_text="$(tr -d '\r' < install.ps1)"
contains "$ps_text" "certutil.exe -hashfile"
contains "$ps_text" "cosign verify-blob"
contains "$ps_text" "cosign verify-blob-attestation"
contains "$ps_text" "Get-NormalizedVerifyPosture"
contains "$ps_text" "cosign is required by -Verify require"
contains "$ps_text" "authenticity unverified: cosign not installed; SHA-256 checksum verified"
contains "$ps_text" "cosign verification intentionally skipped by -Verify checksum-only"
contains "$ps_text" "completions powershell"
contains "$ps_text" "Test-AlreadyCurrentByVersion"
contains "$ps_text" "already current: installed oraclemcp \$installed matches target \$Version"
contains "$ps_text" "ORACLEMCP_INSTALL_DOWNGRADE_REFUSED"
contains "$ps_text" "Backup-ExistingFile"
contains "$ps_text" "Install-ExecutableAtomically"
contains "$ps_text" "Write-UninstallPlan"
contains "$ps_text" "uninstall requires -Yes or -DryRun"
contains "$ps_text" "-Uninstall cannot be combined with -Update"
contains "$ps_text" "Write-PathGuidance"
contains "$ps_text" "Run oraclemcp doctor now?"
contains "$ps_text" "Print an MCP client wiring snippet now?"
contains "$ps_text" "Install and start the local oraclemcp service now?"
contains "$ps_text" "-HonorYes \$false"
contains "$ps_text" "oraclemcp installer: next steps"
contains "$ps_text" "service install requires -Service -Yes or -DryRun"
contains "$ps_text" "service: not requested; no service-manager files or units will be touched"
contains "$ps_text" "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING"
log_pass "static installer contracts"

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
    note "PSScriptAnalyzer not installed; skipping PSSA"
    log_skip "PSScriptAnalyzer unavailable"
  fi
elif [ "${ORACLEMCP_INSTALLER_REQUIRE_PWSH:-0}" = "1" ]; then
  fail "pwsh is required but not installed"
else
  note "pwsh not installed; skipping install.ps1 parse/dry-run"
  log_skip "pwsh unavailable for Windows installer parse/dry-run"
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
else
  log_skip "built artifact smoke not requested"
fi

if command -v pwsh >/dev/null 2>&1; then
  WIN_PREFIX="$SMOKE_ROOT/windows-prefix"
  WIN_OFFLINE_ARCHIVE="$SMOKE_ROOT/offline/oraclemcp-x86_64-pc-windows-msvc.zip"
  win_dry_output="$(
    pwsh -NoLogo -NoProfile -File ./install.ps1 \
      -DryRun \
      -Version "$SMOKE_VERSION" \
      -Prefix "$WIN_PREFIX" \
      -Offline "$WIN_OFFLINE_ARCHIVE" \
      -Verify checksum-only \
      -NoService
  )"
  contains "$win_dry_output" "oraclemcp Windows installer plan"
  contains "$win_dry_output" "mode: offline"
  contains "$win_dry_output" "update: False"
  contains "$win_dry_output" "verify: checksum-only"
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

  win_uninstall_output="$(
    pwsh -NoLogo -NoProfile -File ./install.ps1 \
      -DryRun \
      -Uninstall \
      -Prefix "$WIN_PREFIX"
  )"
  contains "$win_uninstall_output" "oraclemcp Windows uninstall plan"
  contains "$win_uninstall_output" "$WIN_PREFIX"
  contains "$win_uninstall_output" "oraclemcp.exe"
  contains "$win_uninstall_output" "om.exe"
  log_pass "Windows installer dry-run service and uninstall contract"
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
contains "$dry_output" "verification_posture: prefer"
contains "$dry_output" "checksum verifies transport integrity; cosign verifies authenticity/provenance when available"
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
log_pass "non-TTY dry-run agent path"

# Field-test bead: gnu triples are reachable, but only via explicit --target
# (auto-detection stays musl); anything outside the release matrix still fails.
gnu_dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-gnu \
      --prefix "$PREFIX"
)"
contains "$gnu_dry_output" "mode: prebuilt"
contains "$gnu_dry_output" "archive: https://github.com/MuhDur/oraclemcp/releases/download/v$SMOKE_VERSION/oraclemcp-x86_64-unknown-linux-gnu.tar.gz"
log_pass "explicit --target linux-gnu dry-run plans the published gnu tarball"

set +e
unsupported_target_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-pc-windows-msvc \
      --prefix "$PREFIX" 2>&1
)"
unsupported_target_status=$?
set -e
[ "$unsupported_target_status" -ne 0 ] || fail "unsupported target triple unexpectedly accepted"
contains "$unsupported_target_output" "unsupported target"
log_pass "non-Unix target triple still rejected"

# Field-test bead: the dry-run plan must be honest about the cosign soft-skip.
# Without cosign, posture prefer skips authenticity (SHA-256 still enforced)
# and posture require will fail closed; with cosign present no notice appears.
no_cosign_dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    ORACLEMCP_COSIGN="$SMOKE_ROOT/missing-cosign" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX"
)"
contains "$no_cosign_dry_output" "verification_posture: prefer"
contains "$no_cosign_dry_output" "cosign: not installed - authenticity check will be skipped (SHA-256 still enforced); install cosign or use --verify require to change this"
log_pass "dry-run surfaces the cosign soft-skip under posture prefer"

no_cosign_require_dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    ORACLEMCP_COSIGN="$SMOKE_ROOT/missing-cosign" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX" \
      --verify require
)"
contains "$no_cosign_require_dry_output" "cosign: not installed - the real run will fail closed (ORACLEMCP_INSTALL_COSIGN_REQUIRED); install cosign before rerunning"
log_pass "dry-run surfaces the cosign fail-closed gap under posture require"

with_cosign_dry_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    ORACLEMCP_COSIGN="/bin/true" \
    bash install.sh \
      --dry-run \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$PREFIX"
)"
not_contains "$with_cosign_dry_output" "cosign: not installed"
log_pass "dry-run stays quiet about cosign when it is present"

NO_COSIGN_DIR="$SMOKE_ROOT/no-cosign"
NO_COSIGN_ARCHIVE="$NO_COSIGN_DIR/oraclemcp-x86_64-unknown-linux-musl.tar.gz"
NO_COSIGN_PREFIX="$SMOKE_ROOT/no-cosign-prefix"
mkdir -p "$NO_COSIGN_DIR"
write_fake_release_archive "$NO_COSIGN_ARCHIVE" x86_64-unknown-linux-musl

no_cosign_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    ORACLEMCP_COSIGN="$SMOKE_ROOT/missing-cosign" \
    PATH="/usr/bin:/bin" \
    bash install.sh \
      --offline "$NO_COSIGN_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$NO_COSIGN_PREFIX" \
      --verify prefer \
      --no-completions \
      --no-service 2>&1
)"
contains "$no_cosign_output" "authenticity unverified: cosign not installed; SHA-256 checksum verified"
contains "$no_cosign_output" "oraclemcp installer: $NO_COSIGN_PREFIX/bin is not on PATH"
contains "$no_cosign_output" "export PATH='$NO_COSIGN_PREFIX/bin':\"\$PATH\""
contains "$no_cosign_output" "$NO_COSIGN_PREFIX/bin/oraclemcp --json doctor"
contains "$no_cosign_output" "$NO_COSIGN_PREFIX/bin/oraclemcp --json setup --write --profile db_ro"
contains "$no_cosign_output" "$NO_COSIGN_PREFIX/bin/oraclemcp --json setup --profile db_ro"
not_contains "$no_cosign_output" "Add $NO_COSIGN_PREFIX/bin to PATH in"
[ -x "$NO_COSIGN_PREFIX/bin/oraclemcp" ] || fail "no-cosign prefer install did not install oraclemcp"
log_pass "cosign-absent prefer install path"

ON_PATH_PREFIX="$SMOKE_ROOT/on-path-prefix"
on_path_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    PATH="$ON_PATH_PREFIX/bin:/usr/bin:/bin" \
    bash install.sh \
      --offline "$NO_COSIGN_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$ON_PATH_PREFIX" \
      --verify checksum-only \
      --no-completions \
      --no-service 2>&1
)"
not_contains "$on_path_output" "is not on PATH"
not_contains "$on_path_output" "export PATH="
contains "$on_path_output" "oraclemcp --json doctor"
contains "$on_path_output" "oraclemcp --json setup --write --profile db_ro"
log_pass "PATH-present install path"

if command -v script >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  PTY_PREFIX="$SMOKE_ROOT/pty-prefix-$$"
  pty_command=""
  printf -v pty_command 'bash install.sh --offline %q --version %q --target %q --prefix %q --verify checksum-only --no-completions --no-service' \
    "$NO_COSIGN_ARCHIVE" \
    "$SMOKE_VERSION" \
    "x86_64-unknown-linux-musl" \
    "$PTY_PREFIX"
  # NO_COLOR=1 pins prompt_yes_no to its plain read-based prompts: the piped
  # line answers (and the prompt-text assertions below) are written for that
  # path, and a host-installed gum would otherwise swallow keypresses and hang.
  pty_output="$(
    printf 'y\nn\nn\nn\n' | env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
      CI= SHELL="/bin/bash" PATH="/usr/bin:/bin" NO_COLOR=1 \
      timeout 20s script -qefc "$pty_command" /dev/null 2>&1
  )"
  contains_unwrapped_fragments "$pty_output" "PATH prompt" \
    "Add " \
    " to PATH in " \
    ".bashrc? [y/N]"
  contains "$pty_output" "oraclemcp installer: appended PATH line to $HOME_DIR/.bashrc"
  rc_text="$(cat "$HOME_DIR/.bashrc")"
  contains "$rc_text" "export PATH='$PTY_PREFIX/bin':\"\$PATH\""

  PTY_DEFAULT_PREFIX="$SMOKE_ROOT/pty-default-prefix-$$"
  printf -v pty_command 'bash install.sh --offline %q --version %q --target %q --prefix %q --verify checksum-only --no-completions' \
    "$NO_COSIGN_ARCHIVE" \
    "$SMOKE_VERSION" \
    "x86_64-unknown-linux-musl" \
    "$PTY_DEFAULT_PREFIX"
  pty_default_output="$(
    printf '\n\n\n\n\n' | env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
      CI= SHELL="/bin/bash" PATH="/usr/bin:/bin" NO_COLOR=1 \
      timeout 20s script -qefc "$pty_command" /dev/null 2>&1
  )"
  contains_unwrapped_fragments "$pty_default_output" "PATH prompt" \
    "Add " \
    " to PATH in " \
    ".bashrc? [y/N]"
  contains "$pty_default_output" "Run oraclemcp doctor now? [Y/n]"
  contains "$pty_default_output" "Print an MCP client wiring snippet now? [Y/n]"
  contains "$pty_default_output" '"args": ["serve", "--profile", "db_ro"]'
  contains "$pty_default_output" "Install and start the local oraclemcp service now? [y/N]"
  contains "$pty_default_output" "oraclemcp installer: service install skipped"
  contains "$pty_default_output" "Discover databases from tnsnames.ora now? [y/N]"
  log_pass "TTY guided install path"
else
  note "script or timeout not installed; skipping TTY prompt smoke"
  log_skip "TTY prompt smoke unavailable"
fi

UPDATE_DIR="$SMOKE_ROOT/update"
UPDATE_TARGET="x86_64-unknown-linux-musl"
UPDATE_ARCHIVE="$UPDATE_DIR/oraclemcp-$UPDATE_TARGET.tar.gz"
UPDATE_PREFIX="$SMOKE_ROOT/update-prefix"
mkdir -p "$UPDATE_DIR" "$UPDATE_PREFIX/bin"
cat >"$UPDATE_PREFIX/bin/oraclemcp" <<'OLD_BIN'
#!/usr/bin/env sh
if [ "${1:-}" = "--version" ]; then
  echo "oraclemcp 1.0.0"
  exit 0
fi
echo old-oraclemcp
OLD_BIN
chmod +x "$UPDATE_PREFIX/bin/oraclemcp"
cp "$UPDATE_PREFIX/bin/oraclemcp" "$UPDATE_DIR/oraclemcp-old-copy"
write_versioned_release_archive "$UPDATE_ARCHIVE" "$UPDATE_TARGET" "1.1.0"

update_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    PATH="/usr/bin:/bin" \
    bash install.sh \
      --offline "$UPDATE_ARCHIVE" \
      --version 1.1.0 \
      --target "$UPDATE_TARGET" \
      --prefix "$UPDATE_PREFIX" \
      --verify checksum-only \
      --no-completions \
      --no-service 2>&1
)"
contains "$update_output" "oraclemcp installer: backed up previous binary to"
contains "$update_output" "oraclemcp installer: installed oraclemcp to $UPDATE_PREFIX/bin/oraclemcp"
contains "$update_output" "oraclemcp installer: $UPDATE_PREFIX/bin is not on PATH"
backup_file="$(find "$UPDATE_PREFIX/share/oraclemcp/backups" -type f -name 'oraclemcp-1.0.0-*' | head -n 1)"
[ -n "$backup_file" ] || fail "update did not create a versioned backup"
cmp -s "$backup_file" "$UPDATE_DIR/oraclemcp-old-copy" || fail "backup is not byte-identical to prior binary"
new_version="$("$UPDATE_PREFIX/bin/oraclemcp" --version)"
contains "$new_version" "oraclemcp 1.1.0"

already_current_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    PATH="/usr/bin:/bin" \
    bash install.sh \
      --offline "$UPDATE_ARCHIVE" \
      --version 1.1.0 \
      --target "$UPDATE_TARGET" \
      --prefix "$UPDATE_PREFIX" \
      --verify checksum-only \
      --no-completions \
      --no-service 2>&1
)"
contains "$already_current_output" "oraclemcp installer: already current: installed oraclemcp 1.1.0 matches target 1.1.0"
contains "$already_current_output" "$UPDATE_PREFIX/bin/oraclemcp --json doctor"

DOWNGRADE_DIR="$SMOKE_ROOT/downgrade"
DOWNGRADE_ARCHIVE="$DOWNGRADE_DIR/oraclemcp-$UPDATE_TARGET.tar.gz"
mkdir -p "$DOWNGRADE_DIR"
write_versioned_release_archive "$DOWNGRADE_ARCHIVE" "$UPDATE_TARGET" "0.9.0"
set +e
downgrade_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --offline "$DOWNGRADE_ARCHIVE" \
      --version 0.9.0 \
      --target "$UPDATE_TARGET" \
      --prefix "$UPDATE_PREFIX" \
      --verify checksum-only \
      --no-completions \
      --no-service 2>&1
)"
downgrade_status=$?
set -e
[ "$downgrade_status" -ne 0 ] || fail "forced downgrade guard did not reject older target"
contains "$downgrade_output" "ORACLEMCP_INSTALL_DOWNGRADE_REFUSED"

cp "$backup_file" "$UPDATE_PREFIX/bin/oraclemcp"
cmp -s "$UPDATE_PREFIX/bin/oraclemcp" "$UPDATE_DIR/oraclemcp-old-copy" || fail "rollback from backup did not restore prior bytes"
log_pass "update backup idempotency and rollback"

set +e
require_no_cosign_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    ORACLEMCP_COSIGN="$SMOKE_ROOT/missing-cosign" \
    bash install.sh \
      --offline "$NO_COSIGN_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$SMOKE_ROOT/require-no-cosign-prefix" \
      --verify require \
      --no-completions \
      --no-service 2>&1
)"
require_no_cosign_status=$?
set -e
[ "$require_no_cosign_status" -ne 0 ] || fail "--verify require without cosign unexpectedly succeeded"
contains "$require_no_cosign_output" "ORACLEMCP_INSTALL_COSIGN_REQUIRED"
log_pass "verify-require without cosign fails closed"

: >"$NO_COSIGN_ARCHIVE.sig"
: >"$NO_COSIGN_ARCHIVE.crt"
: >"$NO_COSIGN_ARCHIVE.attestation.sigstore.json"
FAILING_COSIGN="$NO_COSIGN_DIR/failing-cosign"
cat >"$FAILING_COSIGN" <<'COSIGN'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  version)
    exit 0
    ;;
  verify-blob | verify-blob-attestation)
    printf 'fake-cosign: forced verification failure for %s\n' "$1" >&2
    exit 9
    ;;
  *)
    printf 'fake-cosign: unexpected command: %s\n' "${1:-<missing>}" >&2
    exit 2
    ;;
esac
COSIGN
chmod +x "$FAILING_COSIGN"
set +e
bad_signature_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    ORACLEMCP_COSIGN="$FAILING_COSIGN" \
    bash install.sh \
      --offline "$NO_COSIGN_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$SMOKE_ROOT/bad-signature-prefix" \
      --verify prefer \
      --no-completions \
      --no-service 2>&1
)"
bad_signature_status=$?
set -e
[ "$bad_signature_status" -ne 0 ] || fail "bad cosign signature unexpectedly succeeded"
contains "$bad_signature_output" "fake-cosign: forced verification failure"
log_pass "bad cosign signature fails closed"

printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' \
  "$(basename "$NO_COSIGN_ARCHIVE")" >"$NO_COSIGN_ARCHIVE.sha256"
set +e
tampered_checksum_output="$(
  env HOME="$HOME_DIR" XDG_CONFIG_HOME="$CONFIG_HOME" TMPDIR="$TMP_DIR" \
    bash install.sh \
      --offline "$NO_COSIGN_ARCHIVE" \
      --version "$SMOKE_VERSION" \
      --target x86_64-unknown-linux-musl \
      --prefix "$SMOKE_ROOT/tampered-prefix" \
      --verify checksum-only \
      --no-completions \
      --no-service 2>&1
)"
tampered_checksum_status=$?
set -e
[ "$tampered_checksum_status" -ne 0 ] || fail "tampered checksum unexpectedly succeeded"
contains "$tampered_checksum_output" "FAILED"
log_pass "tampered checksum fails closed"

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
log_pass "service dry-run consent plan"

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
log_pass "client registration dry-run plan"

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
log_pass "explicit source dry-run path"

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
log_pass "offline plan and missing metadata failure"

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

log_pass "uninstall preview remove and idempotent rerun"
e2e_log_event "suite_summary" "assert" "pass" 0 "installer acceptance cases passed: static, agent dry-run, TTY, cosign, update, rollback, service, offline, uninstall"
e2e_finish_pass
printf 'installer-smoke: OK\n'
