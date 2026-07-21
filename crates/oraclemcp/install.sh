#!/usr/bin/env bash
#
# oraclemcp installer
#
# Dry-run preview with a cache-busted script fetch:
#   curl -fsSL "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)" | bash -s -- --dry-run
#
# Normal install with SHA-256 required and cosign preferred (latest release):
#   curl -fsSL "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)" | bash
#
# Install oraclemcp from a verified release archive, or from source when
# explicitly requested. Service-manager mutation is opt-in only.
if [ -z "${BASH_VERSION:-}" ]; then
  printf 'oraclemcp installer: this script requires bash; run with bash install.sh [options]\n' >&2
  exit 2
fi
set -euo pipefail
shopt -s lastpipe 2>/dev/null || true
umask 022

REPO="MuhDur/oraclemcp"
VERSION="latest"
RUST_TOOLCHAIN="nightly-2026-05-11"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_BIN="${ORACLEMCP_COSIGN:-cosign}"

PREFIX="${ORACLEMCP_INSTALL_PREFIX:-${HOME:-}/.local}"
BIN_DIR=""
TARGET=""
TARGET_EXPLICIT=0
DRY_RUN=0
YES=0
FORCE=0
SOURCE=0
UNINSTALL=0
UPDATE_REQUESTED=0
OFFLINE_ARCHIVE=""
VERIFY_POSTURE="${ORACLEMCP_INSTALL_VERIFY:-prefer}"
INSTALL_COMPLETIONS=1
SERVICE_REQUESTED=0
PROMPT_SERVICE=1
SERVICE_NAME="oraclemcp"
SERVICE_LISTEN="127.0.0.1:7070"
SERVICE_PROFILE=""
SERVICE_ALLOW_NO_AUTH=0
SERVICE_CLIENT_CREDENTIALS=0
SERVICE_SKIP_LINGER=0
CLIENT_REGISTER=0
CLIENT_LABEL=""
CLIENT_SCOPES=()
PROXY_ARGS=()
WORK_DIR=""
LOCK_DIR=""

cleanup() {
  if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf -- "$WORK_DIR"
  fi
  if [ -n "${LOCK_DIR:-}" ] && [ -d "$LOCK_DIR" ]; then
    rm -f -- "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Installs the oraclemcp release binary plus the om alias and shell completions.
By default this downloads a prebuilt archive, requires SHA-256 transport
integrity, verifies cosign authenticity/provenance when cosign is installed,
soft-skips cosign with an explicit notice when it is absent, and does not
install a service.

Options:
  --version <version>       Release version X.Y.Z or vX.Y.Z (default: latest published release)
  --target <triple>         Override detected target triple; Linux gnu triples
                            (x86_64/aarch64-unknown-linux-gnu) are accepted here
                            even though auto-detection always picks musl
  --prefix <dir>            Install prefix (default: $HOME/.local)
  --bin-dir <dir>           Binary directory (default: <prefix>/bin)
  --repo <owner/repo>       GitHub repository (default: MuhDur/oraclemcp)
  --source                  Build with cargo instead of downloading a release archive
  --offline <archive>       Install from a local release archive plus sibling verification files
  --verify <posture>        Verification posture: require, prefer, checksum-only (default: prefer)
  --update                  Explicitly run the install path as an update; re-running is already update-safe
  --uninstall               Remove installed oraclemcp files; add --service to remove the service
  --no-completions          Do not install shell completions
  --service                 Install/start the local service after binary install
  --no-service              Never prompt for service install
  --service-name <name>     Service name/label (default: oraclemcp)
  --listen <addr:port>      Service listen address (default: 127.0.0.1:7070)
  --profile <name>          Service profile passed to oraclemcp service install
  --allow-no-auth           Service dev-mode auth opt-in; loopback only
  --client-credentials      Enable service-owned per-client HTTP credentials
  --register-client <label> Issue one per-client HTTP bearer after install
  --client-scope <scope>    Scope for --register-client (repeat; default oracle:read)
  --skip-linger             Skip optional loginctl enable-linger on Linux
  --yes                     Answer yes to explicit prompts
  --force                   Replace existing installed files
  --dry-run                 Print every file/unit/command that would be touched
  -h, --help                Show this help

The installer never mutates the service manager unless --service is supplied,
--yes answers the guided service prompt, or an interactive user answers yes to
the service prompt. Use --no-service to suppress the service prompt.
Uninstall is also explicit: use --uninstall --dry-run to inspect, then
--uninstall --yes to remove installed files. Add --service to remove the local
service unit through oraclemcp service uninstall.
USAGE
}

fail() {
  printf 'oraclemcp installer: %s\n' "$*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

need() {
  have "$1" || fail "missing required command: $1"
}

setup_proxy() {
  PROXY_ARGS=()
  if [ -n "${HTTPS_PROXY:-}" ]; then
    PROXY_ARGS=(--proxy "$HTTPS_PROXY")
  elif [ -n "${HTTP_PROXY:-}" ]; then
    PROXY_ARGS=(--proxy "$HTTP_PROXY")
  fi
}

normalize_version() {
  local version="$1"
  if [ "$version" = "latest" ]; then
    printf '%s\n' "$version"
    return
  fi
  version="${version#v}"
  case "$version" in
    [0-9]*.[0-9]*.[0-9]* | [0-9]*.[0-9]*.[0-9]*-*)
      printf '%s\n' "$version"
      ;;
    *)
      fail "unsupported version '$1' (expected latest, X.Y.Z, or vX.Y.Z)"
      ;;
  esac
}

normalize_verify_posture() {
  case "$1" in
    require | prefer | checksum-only)
      printf '%s\n' "$1"
      ;;
    *)
      fail "unsupported --verify posture '$1' (expected require, prefer, or checksum-only)"
      ;;
  esac
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version)
        [ "$#" -ge 2 ] || fail "--version requires a value"
        VERSION="$(normalize_version "$2")"
        shift 2
        ;;
      --target)
        [ "$#" -ge 2 ] || fail "--target requires a value"
        TARGET="$2"
        TARGET_EXPLICIT=1
        shift 2
        ;;
      --prefix)
        [ "$#" -ge 2 ] || fail "--prefix requires a value"
        PREFIX="$2"
        shift 2
        ;;
      --bin-dir)
        [ "$#" -ge 2 ] || fail "--bin-dir requires a value"
        BIN_DIR="$2"
        shift 2
        ;;
      --repo)
        [ "$#" -ge 2 ] || fail "--repo requires a value"
        REPO="$2"
        shift 2
        ;;
      --source)
        SOURCE=1
        shift
        ;;
      --offline)
        [ "$#" -ge 2 ] || fail "--offline requires a release archive path"
        OFFLINE_ARCHIVE="$2"
        shift 2
        ;;
      --verify)
        [ "$#" -ge 2 ] || fail "--verify requires a value"
        VERIFY_POSTURE="$(normalize_verify_posture "$2")"
        shift 2
        ;;
      --update)
        UPDATE_REQUESTED=1
        shift
        ;;
      --uninstall)
        UNINSTALL=1
        shift
        ;;
      --no-completions)
        INSTALL_COMPLETIONS=0
        shift
        ;;
      --service)
        SERVICE_REQUESTED=1
        shift
        ;;
      --no-service)
        SERVICE_REQUESTED=0
        PROMPT_SERVICE=0
        shift
        ;;
      --service-name)
        [ "$#" -ge 2 ] || fail "--service-name requires a value"
        SERVICE_NAME="$2"
        shift 2
        ;;
      --listen)
        [ "$#" -ge 2 ] || fail "--listen requires a value"
        SERVICE_LISTEN="$2"
        shift 2
        ;;
      --profile)
        [ "$#" -ge 2 ] || fail "--profile requires a value"
        SERVICE_PROFILE="$2"
        shift 2
        ;;
      --allow-no-auth)
        SERVICE_ALLOW_NO_AUTH=1
        shift
        ;;
      --client-credentials)
        SERVICE_CLIENT_CREDENTIALS=1
        shift
        ;;
      --register-client)
        [ "$#" -ge 2 ] || fail "--register-client requires a value"
        CLIENT_REGISTER=1
        CLIENT_LABEL="$2"
        shift 2
        ;;
      --client-scope)
        [ "$#" -ge 2 ] || fail "--client-scope requires a value"
        CLIENT_SCOPES+=("$2")
        shift 2
        ;;
      --skip-linger)
        SERVICE_SKIP_LINGER=1
        shift
        ;;
      --yes)
        YES=1
        shift
        ;;
      --force)
        FORCE=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
  VERIFY_POSTURE="$(normalize_verify_posture "$VERIFY_POSTURE")"
}

detect_rosetta() {
  [ "$(uname -s)" = "Darwin" ] || return 1
  have sysctl || return 1
  [ "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" = "1" ]
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64 | Linux:amd64)
      printf '%s\n' "x86_64-unknown-linux-musl"
      ;;
    Linux:aarch64 | Linux:arm64)
      printf '%s\n' "aarch64-unknown-linux-musl"
      ;;
    Darwin:arm64 | Darwin:aarch64)
      printf '%s\n' "aarch64-apple-darwin"
      ;;
    Darwin:x86_64)
      if detect_rosetta; then
        printf '%s\n' "aarch64-apple-darwin"
      else
        printf '%s\n' "x86_64-apple-darwin"
      fi
      ;;
    *)
      fail "unsupported platform '$os/$arch'; use --source or download an archive manually"
      ;;
  esac
}

validate_target() {
  case "$1" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | x86_64-apple-darwin | aarch64-apple-darwin)
      ;;
    x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu)
      # Published gnu tarballs are reachable only by explicit request; the
      # static musl build stays the auto-detected default on Linux.
      if [ "$TARGET_EXPLICIT" -ne 1 ]; then
        fail "gnu target '$1' is only supported when passed explicitly via --target; the auto-detected Linux default is musl"
      fi
      ;;
    *)
      fail "install.sh supports Unix release tarballs only; unsupported target '$1'"
      ;;
  esac
}

release_tag() {
  if [ "$VERSION" = "latest" ]; then
    printf '%s\n' "latest"
  else
    printf 'v%s\n' "$VERSION"
  fi
}

release_base_url() {
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download\n' "$REPO"
  else
    printf 'https://github.com/%s/releases/download/%s\n' "$REPO" "$(release_tag)"
  fi
}

archive_name() {
  printf 'oraclemcp-%s.tar.gz\n' "$TARGET"
}

lock_path() {
  local sanitized
  sanitized="$(printf '%s' "$BIN_DIR" | sed 's#[^A-Za-z0-9._-]#_#g')"
  printf '%s/oraclemcp-install-%s.lock\n' "${TMPDIR:-/tmp}" "$sanitized"
}

acquire_lock() {
  local lock pid
  lock="$(lock_path)"
  if mkdir "$lock" 2>/dev/null; then
    LOCK_DIR="$lock"
    printf '%s\n' "$$" >"$LOCK_DIR/pid"
    return 0
  fi

  if [ -f "$lock/pid" ]; then
    pid="$(cat "$lock/pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      fail "another oraclemcp installer is already running for $BIN_DIR (pid $pid)"
    fi
  fi
  fail "installer lock exists at $lock; remove it after confirming no installer is running"
}

cosign_identity_args() {
  if [ "$VERSION" = "latest" ]; then
    printf '%s\0%s\0' \
      "--certificate-identity-regexp" \
      "https://github[.]com/${REPO}/[.]github/workflows/release[.]yml@refs/tags/v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?"
  else
    printf '%s\0%s\0' \
      "--certificate-identity" \
      "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${VERSION}"
  fi
}

completion_paths() {
  printf '%s\n' \
    "$PREFIX/share/bash-completion/completions/oraclemcp" \
    "$PREFIX/share/bash-completion/completions/om" \
    "$PREFIX/share/zsh/site-functions/_oraclemcp" \
    "$PREFIX/share/zsh/site-functions/_om" \
    "$PREFIX/share/fish/vendor_completions.d/oraclemcp.fish" \
    "$PREFIX/share/fish/vendor_completions.d/om.fish" \
    "$PREFIX/share/powershell/Completions/oraclemcp.ps1" \
    "$PREFIX/share/powershell/Completions/om.ps1"
}

service_unit_path() {
  local unit label
  case "$(uname -s)" in
    Linux)
      unit="$SERVICE_NAME"
      case "$unit" in
        *.service) ;;
        *) unit="${unit}.service" ;;
      esac
      printf '%s/systemd/user/%s\n' "${XDG_CONFIG_HOME:-${HOME:-}/.config}" "$unit"
      ;;
    Darwin)
      label="$SERVICE_NAME"
      case "$label" in
        *.*) ;;
        *) label="io.github.MuhDur.${label}" ;;
      esac
      printf '%s/Library/LaunchAgents/%s.plist\n' "${HOME:-}" "$label"
      ;;
    *)
      printf '%s\n' "(service unit path resolved by oraclemcp service install)"
      ;;
  esac
}

readyz_url() {
  local listen="$SERVICE_LISTEN" host port
  case "$listen" in
    http://* | https://*)
      printf '%s/readyz\n' "${listen%/}"
      ;;
    0.0.0.0:*)
      port="${listen##*:}"
      printf 'http://127.0.0.1:%s/readyz\n' "$port"
      ;;
    \[::\]:*)
      port="${listen##*:}"
      printf 'http://127.0.0.1:%s/readyz\n' "$port"
      ;;
    \[*\]:*)
      printf 'http://%s/readyz\n' "$listen"
      ;;
    *:*)
      host="${listen%:*}"
      port="${listen##*:}"
      [ "$host" = "localhost" ] && host="127.0.0.1"
      printf 'http://%s:%s/readyz\n' "$host" "$port"
      ;;
    *)
      printf 'http://%s/readyz\n' "$listen"
      ;;
  esac
}

interactive_install() {
  [ -t 0 ] && [ -t 1 ] && [ -z "${CI:-}" ]
}

prompt_yes_no() {
  local prompt="$1" default_yes="$2" suffix answer
  if [ "$YES" -eq 1 ]; then
    return 0
  fi
  interactive_install || return 1
  if have gum && [ -z "${NO_COLOR:-}" ]; then
    if gum confirm --default="$default_yes" "$prompt"; then
      return 0
    fi
    return 1
  fi
  if [ "$default_yes" = "true" ]; then
    suffix="[Y/n]"
  else
    suffix="[y/N]"
  fi
  printf '%s %s ' "$prompt" "$suffix" >&2
  if ! read -r answer; then
    return 1
  fi
  case "$answer" in
    "")
      [ "$default_yes" = "true" ]
      ;;
    y | Y | yes | YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

shell_name() {
  local shell_path="${SHELL:-}"
  if [ -z "$shell_path" ] && have ps; then
    shell_path="$(ps -p "$PPID" -o comm= 2>/dev/null || true)"
  fi
  shell_path="${shell_path##*/}"
  [ -n "$shell_path" ] || shell_path="sh"
  printf '%s\n' "$shell_path"
}

single_quote_shell() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
}

path_export_line() {
  case "$(shell_name)" in
    fish)
      printf 'fish_add_path "%s"\n' "$BIN_DIR"
      ;;
    csh | tcsh)
      printf '%s\n' "setenv PATH \"$BIN_DIR:\$PATH\""
      ;;
    *)
      printf "export PATH='%s':\"\$PATH\"\n" "$(single_quote_shell "$BIN_DIR")"
      ;;
  esac
}

path_rc_file() {
  case "$(shell_name)" in
    zsh)
      printf '%s\n' "${ZDOTDIR:-${HOME:-}}/.zshrc"
      ;;
    bash)
      printf '%s\n' "${HOME:-}/.bashrc"
      ;;
    fish)
      printf '%s\n' "${XDG_CONFIG_HOME:-${HOME:-}/.config}/fish/config.fish"
      ;;
    *)
      printf '%s\n' "${HOME:-}/.profile"
      ;;
  esac
}

bin_dir_on_path() {
  local part bin_phys part_phys
  [ -n "${PATH:-}" ] || return 1
  bin_phys="$(cd "$BIN_DIR" 2>/dev/null && pwd -P)" || bin_phys="$BIN_DIR"
  local IFS=:
  for part in $PATH; do
    [ -n "$part" ] || part="."
    if [ "$part" = "$BIN_DIR" ]; then
      return 0
    fi
    part_phys="$(cd "$part" 2>/dev/null && pwd -P)" || part_phys="$part"
    if [ "$part_phys" = "$bin_phys" ]; then
      return 0
    fi
  done
  return 1
}

append_path_to_rc() {
  local rc_file="$1" line="$2"
  [ -n "$rc_file" ] || return 1
  ensure_parent_dir "$rc_file"
  if [ -f "$rc_file" ] && grep -Fqx "$line" "$rc_file"; then
    printf 'oraclemcp installer: PATH line already present in %s\n' "$rc_file" >&2
    return 0
  fi
  {
    printf '\n# Added by oraclemcp installer.\n'
    printf '%s\n' "$line"
  } >>"$rc_file"
  printf 'oraclemcp installer: appended PATH line to %s\n' "$rc_file" >&2
}

maybe_prompt_path_append() {
  local rc_file="$1" line="$2"
  [ -n "${HOME:-}" ] || return 0
  if prompt_yes_no "Add $BIN_DIR to PATH in $rc_file?" false; then
    append_path_to_rc "$rc_file" "$line"
  else
    printf 'oraclemcp installer: PATH update skipped\n' >&2
  fi
}

print_path_guidance() {
  local line rc_file
  if bin_dir_on_path; then
    return 0
  fi
  line="$(path_export_line)"
  rc_file="$(path_rc_file)"
  printf 'oraclemcp installer: %s is not on PATH\n' "$BIN_DIR" >&2
  printf 'oraclemcp installer: add it for this shell with:\n  %s\n' "$line" >&2
  maybe_prompt_path_append "$rc_file" "$line"
}

installed_command() {
  if bin_dir_on_path; then
    printf '%s\n' "oraclemcp"
  else
    printf '%s/oraclemcp\n' "$BIN_DIR"
  fi
}

print_next_steps() {
  local cmd
  cmd="$(installed_command)"
  printf 'oraclemcp installer: next steps\n' >&2
  printf '  * Fastest path: discover databases from tnsnames.ora: %s setup --discover (non-interactive: add --discover-tns or --yes)\n' "$cmd" >&2
  printf '  1. Run diagnostics: %s --json doctor\n' "$cmd" >&2
  printf '  2. Write a starter profile: %s --json setup --write --profile db_ro\n' "$cmd" >&2
  printf '  3. Generate MCP client snippets: %s --json setup --profile db_ro\n' "$cmd" >&2
}

maybe_run_doctor() {
  if ! interactive_install && [ "$YES" -ne 1 ]; then
    return 0
  fi
  if ! prompt_yes_no "Run oraclemcp doctor now?" true; then
    printf 'oraclemcp installer: doctor skipped\n' >&2
    return 0
  fi
  if ! "$BIN_DIR/oraclemcp" --json doctor >&2; then
    printf 'oraclemcp installer: doctor reported issues; continue with the next-step commands above\n' >&2
  fi
}

# Offer zero-config TNS discovery, INTERACTIVE ONLY and defaulting to No. The
# installer never scans or parses tnsnames.ora itself: it delegates to
# `oraclemcp setup --discover`, which carries the fail-closed consent gate and
# writes READ_ONLY profiles through config-ops. A non-interactive install never
# scans; print_next_steps advertises the command so it can be run deliberately.
maybe_offer_discovery() {
  if ! interactive_install; then
    return 0
  fi
  if ! prompt_yes_no "Discover databases from tnsnames.ora now?" false; then
    printf 'oraclemcp installer: discovery skipped; run %s setup --discover anytime\n' "$(installed_command)" >&2
    return 0
  fi
  if ! "$BIN_DIR/oraclemcp" setup --discover >&2; then
    printf 'oraclemcp installer: discovery reported issues; re-run %s setup --discover\n' "$(installed_command)" >&2
  fi
}

print_client_snippet() {
  local cmd
  cmd="$(installed_command)"
  cat >&2 <<SNIPPET
oraclemcp installer: MCP client snippet (stdio)
{
  "mcpServers": {
    "oracle": {
      "command": "$cmd",
      "args": ["serve", "--profile", "db_ro"]
    }
  }
}
SNIPPET
}

maybe_print_client_snippet() {
  if ! interactive_install && [ "$YES" -ne 1 ]; then
    return 0
  fi
  if prompt_yes_no "Print an MCP client wiring snippet now?" true; then
    print_client_snippet
  else
    printf 'oraclemcp installer: MCP client snippet skipped\n' >&2
  fi
}

service_install_args() {
  local args=("service" "install" "--yes" "--name" "$SERVICE_NAME" "--listen" "$SERVICE_LISTEN")
  if [ -n "$SERVICE_PROFILE" ]; then
    args+=("--profile" "$SERVICE_PROFILE")
  fi
  if [ "$SERVICE_ALLOW_NO_AUTH" -eq 1 ]; then
    args+=("--allow-no-auth")
  fi
  if [ "$SERVICE_CLIENT_CREDENTIALS" -eq 1 ] || [ "$CLIENT_REGISTER" -eq 1 ]; then
    args+=("--client-credentials")
  fi
  if [ "$SERVICE_SKIP_LINGER" -eq 1 ]; then
    args+=("--skip-linger")
  fi
  printf '%s\0' "${args[@]}"
}

client_issue_args() {
  local args=("clients" "issue" "--label" "$CLIENT_LABEL")
  if [ "${#CLIENT_SCOPES[@]}" -eq 0 ]; then
    args+=("--scope" "oracle:read")
  else
    local scope
    for scope in "${CLIENT_SCOPES[@]}"; do
      args+=("--scope" "$scope")
    done
  fi
  printf '%s\0' "${args[@]}"
}

print_plan() {
  local asset base mode
  if [ "$UNINSTALL" -eq 1 ]; then
    print_uninstall_plan
    return
  fi

  asset="$(archive_name)"
  base="$(release_base_url)"
  mode="prebuilt"
  [ "$SOURCE" -eq 1 ] && mode="source"
  [ -n "$OFFLINE_ARCHIVE" ] && mode="offline"

  printf 'oraclemcp installer plan\n'
  printf '  mode: %s\n' "$mode"
  printf '  version: %s\n' "$VERSION"
  printf '  target: %s\n' "$TARGET"
  if [ "$TARGET_EXPLICIT" -eq 0 ] && detect_rosetta; then
    printf '  rosetta: detected; selecting native aarch64-apple-darwin unless --target overrides it\n'
  fi
  printf '  prefix: %s\n' "$PREFIX"
  printf '  bin_dir: %s\n' "$BIN_DIR"
  printf '  lock: %s\n' "$(lock_path)"

  if [ "$SOURCE" -eq 1 ]; then
    if [ "$VERSION" = "latest" ]; then
      printf '  command: cargo +%s install oraclemcp --locked --root %s\n' "$RUST_TOOLCHAIN" "$PREFIX"
    else
      printf '  command: cargo +%s install oraclemcp --locked --version %s --root %s\n' "$RUST_TOOLCHAIN" "$VERSION" "$PREFIX"
    fi
    printf '  verification: source builds are explicit opt-in; release archive checksum/cosign verification is skipped\n'
  else
    printf '  verification_posture: %s\n' "$VERIFY_POSTURE"
    if [ -n "$OFFLINE_ARCHIVE" ]; then
      printf '  offline_archive: %s\n' "$OFFLINE_ARCHIVE"
      printf '  offline_checksum: %s.sha256\n' "$OFFLINE_ARCHIVE"
      printf '  offline_cosign_signature: %s.sig + %s.crt\n' "$OFFLINE_ARCHIVE" "$OFFLINE_ARCHIVE"
      printf '  offline_cosign_attestation: %s.attestation.sigstore.json\n' "$OFFLINE_ARCHIVE"
    else
      printf '  archive: %s/%s\n' "$base" "$asset"
      printf '  checksum: %s/%s.sha256\n' "$base" "$asset"
      printf '  cosign_signature: %s/%s.sig + %s/%s.crt\n' "$base" "$asset" "$base" "$asset"
      printf '  cosign_attestation: %s/%s.attestation.sigstore.json\n' "$base" "$asset"
    fi
    case "$VERIFY_POSTURE" in
      require)
        printf '  sha256_note: checksum verifies transport integrity; cosign authenticity/provenance verification is required\n'
        ;;
      prefer)
        printf '  sha256_note: checksum verifies transport integrity; cosign verifies authenticity/provenance when available\n'
        ;;
      checksum-only)
        printf '  sha256_note: checksum verifies transport integrity only; cosign authenticity/provenance is intentionally skipped\n'
        ;;
    esac
    # Keep the plan honest about what the real run will do: without cosign the
    # run soft-skips the authenticity check (prefer) or fails closed (require).
    if ! have "$COSIGN_BIN"; then
      case "$VERIFY_POSTURE" in
        prefer)
          printf '  cosign: not installed - authenticity check will be skipped (SHA-256 still enforced); install cosign or use --verify require to change this\n'
          ;;
        require)
          printf '  cosign: not installed - the real run will fail closed (ORACLEMCP_INSTALL_COSIGN_REQUIRED); install cosign before rerunning\n'
          ;;
      esac
    fi
  fi

  printf '  files:\n'
  printf '    %s/oraclemcp\n' "$BIN_DIR"
  printf '    %s/om\n' "$BIN_DIR"
  if [ "$INSTALL_COMPLETIONS" -eq 1 ]; then
    completion_paths | sed 's/^/    /'
  fi

  if [ "$SERVICE_REQUESTED" -eq 1 ]; then
    printf '  service:\n'
    printf '    unit: %s\n' "$(service_unit_path)"
    printf '    command: %s/oraclemcp ' "$BIN_DIR"
    local service_args=()
    while IFS= read -r -d '' arg; do
      service_args+=("$arg")
    done < <(service_install_args)
    printf '%q ' "${service_args[@]}"
    printf '\n'
    printf '    readyz_gate: curl --fail --silent --show-error --noproxy '\''*'\'' %s\n' "$(readyz_url)"
  else
    printf '  service: not requested; no service-manager files or units will be touched\n'
  fi

  if [ "$CLIENT_REGISTER" -eq 1 ]; then
    printf '  client_registration:\n'
    printf '    command: %s/oraclemcp ' "$BIN_DIR"
    local client_args=()
    while IFS= read -r -d '' arg; do
      client_args+=("$arg")
    done < <(client_issue_args)
    printf '%q ' "${client_args[@]}"
    printf '\n'
    printf '    secret_rule: bearer is printed once by the command; do not write it to profiles.toml or committed client config\n'
  else
    printf '  client_registration: not requested; no clients.json credential will be issued\n'
  fi
}

print_uninstall_plan() {
  printf 'oraclemcp uninstall plan\n'
  printf '  prefix: %s\n' "$PREFIX"
  printf '  bin_dir: %s\n' "$BIN_DIR"
  printf '  files:\n'
  printf '    remove if present: %s/oraclemcp\n' "$BIN_DIR"
  printf '    remove if present: %s/om\n' "$BIN_DIR"
  completion_paths | sed 's/^/    remove if present: /'

  if [ "$SERVICE_REQUESTED" -eq 1 ]; then
    printf '  service:\n'
    printf '    unit: %s\n' "$(service_unit_path)"
    printf '    command: %s/oraclemcp service uninstall --dry-run --name %q\n' "$BIN_DIR" "$SERVICE_NAME"
  else
    printf '  service: not requested; no service-manager files or units will be touched\n'
  fi
}

download_file() {
  local url="$1" dest="$2"
  if have curl; then
    curl --fail --location --show-error --silent --proto '=https' --tlsv1.2 "${PROXY_ARGS[@]}" \
      --output "$dest" "$url"
  elif have wget; then
    wget --https-only --quiet --output-document "$dest" "$url"
  else
    fail "missing downloader: install curl or wget"
  fi
}

verify_checksum() {
  local archive="$1" checksum="$2"
  local archive_base line expected_digest sidecar_name actual_digest digest_output record_count
  local checksum_pattern
  archive_base="$(basename "$archive")"
  checksum_pattern='^([0-9A-Fa-f]{64}) ([ *])([^[:space:]]+)$'
  record_count=0

  while IFS= read -r line || [ -n "$line" ]; do
    record_count=$((record_count + 1))
    [ "$record_count" -eq 1 ] \
      || fail "ORACLEMCP_INSTALL_CHECKSUM_INVALID: checksum sidecar must contain exactly one record"
    if [[ ! "$line" =~ $checksum_pattern ]]; then
      fail "ORACLEMCP_INSTALL_CHECKSUM_INVALID: checksum sidecar record is malformed"
    fi
    expected_digest="${BASH_REMATCH[1]}"
    sidecar_name="${BASH_REMATCH[3]}"
  done <"$checksum"

  [ "$record_count" -eq 1 ] \
    || fail "ORACLEMCP_INSTALL_CHECKSUM_INVALID: checksum sidecar must contain exactly one record"
  [ "$sidecar_name" = "$archive_base" ] \
    || fail "ORACLEMCP_INSTALL_CHECKSUM_INVALID: checksum sidecar must name the selected archive $archive_base"

  if have sha256sum; then
    digest_output="$(sha256sum -- "$archive")" \
      || fail "ORACLEMCP_INSTALL_CHECKSUM_FAILED: could not hash the selected archive"
  elif have shasum; then
    digest_output="$(shasum -a 256 -- "$archive")" \
      || fail "ORACLEMCP_INSTALL_CHECKSUM_FAILED: could not hash the selected archive"
  else
    fail "missing checksum command: sha256sum or shasum"
  fi

  actual_digest="${digest_output%%[[:space:]]*}"
  [[ "$actual_digest" =~ ^[0-9A-Fa-f]{64}$ ]] \
    || fail "ORACLEMCP_INSTALL_CHECKSUM_FAILED: checksum command returned malformed output"
  expected_digest="$(printf '%s' "$expected_digest" | tr '[:upper:]' '[:lower:]')"
  actual_digest="$(printf '%s' "$actual_digest" | tr '[:upper:]' '[:lower:]')"
  [ "$actual_digest" = "$expected_digest" ] \
    || fail "ORACLEMCP_INSTALL_CHECKSUM_MISMATCH: selected archive SHA-256 does not match its sidecar"
}

cosign_required_message() {
  printf '%s\n' \
    "ORACLEMCP_INSTALL_COSIGN_REQUIRED: --verify require needs cosign. Install cosign from https://docs.sigstore.dev/cosign/system_config/installation/ or set ORACLEMCP_COSIGN=/path/to/cosign, then rerun the installer."
}

should_download_cosign_metadata() {
  case "$VERIFY_POSTURE" in
    checksum-only)
      return 1
      ;;
    require | prefer)
      have "$COSIGN_BIN"
      ;;
  esac
}

require_readable_file() {
  local path="$1"
  [ -f "$path" ] || fail "ORACLEMCP_INSTALL_VERIFICATION_BUNDLE_MISSING: required verification file is missing: $path"
  [ -r "$path" ] || fail "ORACLEMCP_INSTALL_VERIFICATION_BUNDLE_UNREADABLE: required verification file is not readable: $path"
}

verify_cosign() {
  local archive="$1" signature="$2" certificate="$3" attestation="$4"
  local identity_args=()

  if [ "$VERIFY_POSTURE" = "checksum-only" ]; then
    printf 'oraclemcp installer: verification posture checksum-only: SHA-256 verified; cosign authenticity/provenance checks intentionally skipped\n' >&2
    return 0
  fi

  if ! have "$COSIGN_BIN"; then
    if [ "$VERIFY_POSTURE" = "require" ]; then
      if [ -t 0 ] && [ -t 1 ]; then
        printf 'oraclemcp installer: cosign is not installed; install it and rerun, or use --verify prefer/checksum-only if your policy allows weaker authenticity verification.\n' >&2
      fi
      fail "$(cosign_required_message)"
    fi
    printf 'oraclemcp installer: authenticity unverified: cosign not installed; SHA-256 checksum verified; install cosign or rerun with --verify require to enforce signature and attestation verification\n' >&2
    return 0
  fi

  require_readable_file "$signature"
  require_readable_file "$certificate"
  require_readable_file "$attestation"

  while IFS= read -r -d '' arg; do
    identity_args+=("$arg")
  done < <(cosign_identity_args)

  "$COSIGN_BIN" verify-blob \
    --certificate "$certificate" \
    --signature "$signature" \
    "${identity_args[@]}" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$archive"

  "$COSIGN_BIN" verify-blob-attestation \
    --bundle "$attestation" \
    --type slsaprovenance1 \
    "${identity_args[@]}" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$archive"
}

require_offline_bundle() {
  local archive="$1" expected
  expected="$(archive_name)"
  [ "$(basename "$archive")" = "$expected" ] || fail "ORACLEMCP_INSTALL_OFFLINE_TARGET_MISMATCH: expected offline archive named $expected for target $TARGET"
  for path in \
    "$archive" \
    "$archive.sha256"
  do
    [ -f "$path" ] || fail "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING: required offline bundle file is missing: $path"
    [ -r "$path" ] || fail "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_UNREADABLE: required offline bundle file is not readable: $path"
  done

  should_download_cosign_metadata || return 0
  for path in \
    "$archive.sig" \
    "$archive.crt" \
    "$archive.attestation.sigstore.json"
  do
    [ -f "$path" ] || fail "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_MISSING: required offline bundle file is missing: $path"
    [ -r "$path" ] || fail "ORACLEMCP_INSTALL_OFFLINE_BUNDLE_UNREADABLE: required offline bundle file is not readable: $path"
  done
}

ensure_parent_dir() {
  mkdir -p "$(dirname "$1")"
}

assert_replaceable() {
  local path="$1"
  if [ "$FORCE" -eq 0 ] && [ -e "$path" ]; then
    fail "$path already exists; rerun with --force to replace it"
  fi
}

parse_semver_core() {
  local version="${1#v}" core major minor patch
  core="${version%%-*}"
  IFS=. read -r major minor patch <<EOF
$core
EOF
  case "$major:$minor:$patch" in
    *[!0-9:]* | :* | *: | *::*)
      return 1
      ;;
  esac
  printf '%s %s %s\n' "$major" "$minor" "$patch"
}

version_compare() {
  local left="$1" right="$2" l_major l_minor l_patch r_major r_minor r_patch
  read -r l_major l_minor l_patch < <(parse_semver_core "$left") || return 2
  read -r r_major r_minor r_patch < <(parse_semver_core "$right") || return 2
  if [ "$l_major" -gt "$r_major" ]; then
    printf '1\n'
  elif [ "$l_major" -lt "$r_major" ]; then
    printf -- '-1\n'
  elif [ "$l_minor" -gt "$r_minor" ]; then
    printf '1\n'
  elif [ "$l_minor" -lt "$r_minor" ]; then
    printf -- '-1\n'
  elif [ "$l_patch" -gt "$r_patch" ]; then
    printf '1\n'
  elif [ "$l_patch" -lt "$r_patch" ]; then
    printf -- '-1\n'
  else
    printf '0\n'
  fi
}

installed_oraclemcp_version() {
  local output version
  [ -x "$BIN_DIR/oraclemcp" ] || return 1
  output="$("$BIN_DIR/oraclemcp" --version 2>/dev/null || true)"
  case "$output" in
    oraclemcp\ *)
      version="${output#oraclemcp }"
      version="${version%%[[:space:]]*}"
      [ -n "$version" ] || return 1
      printf '%s\n' "$version"
      ;;
    *)
      return 1
      ;;
  esac
}

already_current_by_version() {
  local installed
  [ "$FORCE" -eq 0 ] || return 1
  [ "$VERSION" != "latest" ] || return 1
  installed="$(installed_oraclemcp_version || true)"
  [ "$installed" = "$VERSION" ] || return 1
  printf 'oraclemcp installer: already current: installed oraclemcp %s matches target %s\n' "$installed" "$VERSION" >&2
  return 0
}

guard_downgrade() {
  local installed cmp
  [ "$FORCE" -eq 0 ] || return 0
  [ "$VERSION" != "latest" ] || return 0
  installed="$(installed_oraclemcp_version || true)"
  [ -n "$installed" ] || return 0
  cmp="$(version_compare "$installed" "$VERSION" || true)"
  [ "$cmp" = "1" ] || return 0
  fail "ORACLEMCP_INSTALL_DOWNGRADE_REFUSED: installed oraclemcp $installed is newer than target $VERSION; rerun with --force only if you intentionally want to downgrade"
}

backup_existing_binary() {
  local dest="$1" installed backup_dir backup_path stamp
  [ -e "$dest" ] || return 0
  installed="$(installed_oraclemcp_version || true)"
  [ -n "$installed" ] || installed="unknown"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_dir="$PREFIX/share/oraclemcp/backups"
  mkdir -p "$backup_dir"
  backup_path="$backup_dir/oraclemcp-$installed-$stamp"
  cp -p "$dest" "$backup_path"
  printf 'oraclemcp installer: backed up previous binary to %s\n' "$backup_path" >&2
}

install_binary() {
  local src="$1" dest="$BIN_DIR/oraclemcp" tmp_dest
  ensure_parent_dir "$dest"
  guard_downgrade
  if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
    printf 'oraclemcp installer: already current: %s matches release archive\n' "$dest" >&2
    chmod 0755 "$dest"
    return 0
  fi
  backup_existing_binary "$dest"
  tmp_dest="$(dirname "$dest")/.oraclemcp.tmp.$$"
  install -m 0755 "$src" "$tmp_dest"
  mv -f "$tmp_dest" "$dest"
  printf 'oraclemcp installer: installed oraclemcp to %s\n' "$dest" >&2
}

install_om_alias() {
  local alias="$BIN_DIR/om"
  ensure_parent_dir "$alias"
  if [ -L "$alias" ] && [ "$(readlink "$alias")" = "oraclemcp" ]; then
    return
  fi
  assert_replaceable "$alias"
  ln -sfn oraclemcp "$alias"
}

install_completion() {
  local command_path="$1" shell="$2" dest="$3" content existing
  ensure_parent_dir "$dest"
  content="$("$command_path" completions "$shell")"
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    if [ "$FORCE" -eq 0 ]; then
      if [ -f "$dest" ]; then
        existing="$(cat "$dest")"
        if [ "$existing" = "$content" ]; then
          return
        fi
      fi
      fail "$dest already exists with different content; rerun with --force to replace it"
    fi
  fi
  printf '%s\n' "$content" >"$dest"
}

install_completions() {
  if [ "$INSTALL_COMPLETIONS" -ne 1 ]; then
    return 0
  fi
  install_completion "$BIN_DIR/oraclemcp" bash "$PREFIX/share/bash-completion/completions/oraclemcp"
  install_completion "$BIN_DIR/om" bash "$PREFIX/share/bash-completion/completions/om"
  install_completion "$BIN_DIR/oraclemcp" zsh "$PREFIX/share/zsh/site-functions/_oraclemcp"
  install_completion "$BIN_DIR/om" zsh "$PREFIX/share/zsh/site-functions/_om"
  install_completion "$BIN_DIR/oraclemcp" fish "$PREFIX/share/fish/vendor_completions.d/oraclemcp.fish"
  install_completion "$BIN_DIR/om" fish "$PREFIX/share/fish/vendor_completions.d/om.fish"
  install_completion "$BIN_DIR/oraclemcp" powershell "$PREFIX/share/powershell/Completions/oraclemcp.ps1"
  install_completion "$BIN_DIR/om" powershell "$PREFIX/share/powershell/Completions/om.ps1"
}

register_client() {
  if [ "$CLIENT_REGISTER" -ne 1 ]; then
    return 0
  fi
  local args=()
  while IFS= read -r -d '' arg; do
    args+=("$arg")
  done < <(client_issue_args)
  printf 'oraclemcp installer: issuing per-client credential for %s; bearer is shown once below\n' "$CLIENT_LABEL" >&2
  "$BIN_DIR/oraclemcp" --json "${args[@]}"
}

install_prebuilt() {
  local work_dir asset base archive checksum signature certificate attestation extracted
  need tar
  need install
  if already_current_by_version; then
    return 0
  fi
  if [ -n "$OFFLINE_ARCHIVE" ]; then
    require_offline_bundle "$OFFLINE_ARCHIVE"
  fi
  asset="$(archive_name)"
  base="$(release_base_url)"
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oraclemcp-install.XXXXXX")"
  work_dir="$WORK_DIR"

  if [ -n "$OFFLINE_ARCHIVE" ]; then
    archive="$OFFLINE_ARCHIVE"
    checksum="$archive.sha256"
    signature="$archive.sig"
    certificate="$archive.crt"
    attestation="$archive.attestation.sigstore.json"
  else
    archive="$work_dir/$asset"
    checksum="$archive.sha256"
    signature="$archive.sig"
    certificate="$archive.crt"
    attestation="$archive.attestation.sigstore.json"

    download_file "$base/$asset" "$archive"
    download_file "$base/$asset.sha256" "$checksum"
    if should_download_cosign_metadata; then
      download_file "$base/$asset.sig" "$signature"
      download_file "$base/$asset.crt" "$certificate"
      download_file "$base/$asset.attestation.sigstore.json" "$attestation"
    fi
  fi

  verify_checksum "$archive" "$checksum"
  verify_cosign "$archive" "$signature" "$certificate" "$attestation"

  tar -xzf "$archive" -C "$work_dir"
  extracted="$work_dir/oraclemcp-$TARGET/oraclemcp"
  [ -x "$extracted" ] || fail "release archive did not contain executable $extracted"
  install_binary "$extracted"
}

service_uninstall_args() {
  local args=("service" "uninstall" "--yes" "--name" "$SERVICE_NAME")
  printf '%s\0' "${args[@]}"
}

direct_uninstall_service() {
  local unit label plist_path
  case "$(uname -s)" in
    Linux)
      unit="$SERVICE_NAME"
      case "$unit" in
        *.service) ;;
        *) unit="${unit}.service" ;;
      esac
      if have systemctl; then
        systemctl --user disable --now "$unit" >/dev/null 2>&1 || true
      fi
      rm -f -- "$(service_unit_path)"
      if have systemctl; then
        systemctl --user daemon-reload >/dev/null 2>&1 || true
      fi
      ;;
    Darwin)
      label="$SERVICE_NAME"
      case "$label" in
        *.*) ;;
        *) label="io.github.MuhDur.${label}" ;;
      esac
      if have launchctl; then
        launchctl bootout "gui/$(id -u)/$label" >/dev/null 2>&1 || true
      fi
      plist_path="$(service_unit_path)"
      rm -f -- "$plist_path"
      ;;
    *)
      fail "ORACLEMCP_INSTALL_UNINSTALL_SERVICE_UNSUPPORTED: service uninstall fallback supports Linux and macOS only"
      ;;
  esac
}

uninstall_service() {
  if [ "$SERVICE_REQUESTED" -ne 1 ]; then
    return 0
  fi
  [ "$YES" -eq 1 ] || fail "uninstalling the service requires --service --yes or --service --dry-run"
  if [ -x "$BIN_DIR/oraclemcp" ]; then
    local args=()
    while IFS= read -r -d '' arg; do
      args+=("$arg")
    done < <(service_uninstall_args)
    "$BIN_DIR/oraclemcp" "${args[@]}"
  else
    printf 'oraclemcp installer: installed binary missing; falling back to direct service-unit removal for %s\n' "$SERVICE_NAME" >&2
    direct_uninstall_service
  fi
}

remove_if_present() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    rm -f -- "$path"
  fi
}

uninstall_files() {
  remove_if_present "$BIN_DIR/oraclemcp"
  remove_if_present "$BIN_DIR/om"
  while IFS= read -r path; do
    remove_if_present "$path"
  done < <(completion_paths)
}

uninstall_oraclemcp() {
  [ "$YES" -eq 1 ] || fail "uninstall requires --dry-run to inspect or --yes to remove files"
  uninstall_service
  uninstall_files
  printf 'oraclemcp installer: removed installed files under %s\n' "$PREFIX"
}

install_source() {
  local args=("+$RUST_TOOLCHAIN" "install" "oraclemcp" "--locked" "--root" "$PREFIX")
  need cargo
  if already_current_by_version; then
    return 0
  fi
  if [ "$VERSION" != "latest" ]; then
    args+=("--version" "$VERSION")
  fi
  cargo "${args[@]}"
}

confirm_service_install() {
  if [ "$YES" -eq 1 ]; then
    return 0
  fi
  if [ ! -t 0 ] || [ ! -t 1 ]; then
    fail "service install requires --service --yes or an interactive yes prompt"
  fi
  printf 'Install and start the local oraclemcp service now? This touches %s. [y/N] ' "$(service_unit_path)" >&2
  local answer
  read -r answer
  case "$answer" in
    y | Y | yes | YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

maybe_prompt_for_service() {
  if [ "$SERVICE_REQUESTED" -eq 1 ]; then
    return 0
  fi
  if [ "$PROMPT_SERVICE" -eq 0 ]; then
    return 1
  fi
  if prompt_yes_no "Install and start the local oraclemcp service now?" false; then
    SERVICE_REQUESTED=1
    return 0
  fi
  return 1
}

install_service() {
  local args=()
  need curl
  if ! confirm_service_install; then
    printf 'oraclemcp installer: service install skipped\n' >&2
    return
  fi
  while IFS= read -r -d '' arg; do
    args+=("$arg")
  done < <(service_install_args)
  "$BIN_DIR/oraclemcp" "${args[@]}"
  wait_readyz
}

wait_readyz() {
  local url attempt
  url="$(readyz_url)"
  attempt=1
  while [ "$attempt" -le 30 ]; do
    if curl --fail --silent --show-error --noproxy '*' "$url" >/dev/null; then
      printf 'oraclemcp installer: service ready at %s\n' "$url"
      return
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  fail "service installed but /readyz did not become healthy at $url"
}

main() {
  parse_args "$@"
  [ -n "$PREFIX" ] || fail "HOME is unset; pass --prefix"
  if [ "$CLIENT_REGISTER" -eq 0 ] && [ "${#CLIENT_SCOPES[@]}" -gt 0 ]; then
    fail "--client-scope requires --register-client"
  fi
  if [ "$CLIENT_REGISTER" -eq 1 ] && [ -z "$CLIENT_LABEL" ]; then
    fail "--register-client label must not be empty"
  fi
  if [ -z "$BIN_DIR" ]; then
    BIN_DIR="$PREFIX/bin"
  fi
  if [ "$SOURCE" -eq 1 ] && [ -n "$OFFLINE_ARCHIVE" ]; then
    fail "--source and --offline cannot be used together"
  fi
  if [ "$UNINSTALL" -eq 1 ] && [ "$SOURCE" -eq 1 ]; then
    fail "--uninstall cannot be combined with --source"
  fi
  if [ "$UNINSTALL" -eq 1 ] && [ -n "$OFFLINE_ARCHIVE" ]; then
    fail "--uninstall cannot be combined with --offline"
  fi
  if [ "$UNINSTALL" -eq 1 ] && [ "$CLIENT_REGISTER" -eq 1 ]; then
    fail "--uninstall cannot be combined with --register-client"
  fi
  if [ "$UNINSTALL" -eq 1 ] && [ "$UPDATE_REQUESTED" -eq 1 ]; then
    fail "--uninstall cannot be combined with --update"
  fi
  if [ -z "$TARGET" ]; then
    TARGET="$(detect_target)"
  fi
  validate_target "$TARGET"
  setup_proxy

  if [ "$DRY_RUN" -eq 1 ]; then
    print_plan
    exit 0
  fi

  acquire_lock

  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall_oraclemcp
    exit 0
  fi

  if [ "$SOURCE" -eq 1 ]; then
    install_source
  else
    install_prebuilt
  fi
  install_om_alias
  install_completions
  register_client

  print_path_guidance
  maybe_run_doctor
  maybe_offer_discovery
  maybe_print_client_snippet

  if [ "$SERVICE_REQUESTED" -eq 1 ] || maybe_prompt_for_service; then
    install_service
  else
    printf 'oraclemcp installer: service install skipped\n' >&2
  fi

  print_next_steps
  printf 'oraclemcp installer: installed %s/oraclemcp and %s/om\n' "$BIN_DIR" "$BIN_DIR" >&2
}

main "$@"
