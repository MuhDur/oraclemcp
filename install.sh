#!/usr/bin/env bash
# Install oraclemcp from a verified release archive, or from source when
# explicitly requested. Service-manager mutation is opt-in only.
set -euo pipefail

REPO="MuhDur/oraclemcp"
VERSION="latest"
RUST_TOOLCHAIN="nightly-2026-05-11"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

PREFIX="${ORACLEMCP_INSTALL_PREFIX:-${HOME:-}/.local}"
BIN_DIR=""
TARGET=""
TARGET_EXPLICIT=0
DRY_RUN=0
YES=0
FORCE=0
SOURCE=0
INSTALL_COMPLETIONS=1
SERVICE_REQUESTED=0
PROMPT_SERVICE=1
SERVICE_NAME="oraclemcp"
SERVICE_LISTEN="127.0.0.1:7070"
SERVICE_PROFILE=""
SERVICE_ALLOW_NO_AUTH=0
SERVICE_SKIP_LINGER=0

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Installs the verified oraclemcp release binary plus the om alias and shell
completions. By default this downloads a prebuilt archive, verifies SHA-256
transport integrity, verifies cosign blob authenticity, verifies the cosign
blob attestation, and does not install a service.

Options:
  --version <version>       Release version, e.g. 0.4.1 or v0.4.1 (default: latest)
  --target <triple>         Override detected target triple
  --prefix <dir>            Install prefix (default: $HOME/.local)
  --bin-dir <dir>           Binary directory (default: <prefix>/bin)
  --repo <owner/repo>       GitHub repository (default: MuhDur/oraclemcp)
  --source                  Build with cargo instead of downloading a release archive
  --no-completions          Do not install shell completions
  --service                 Install/start the local service after binary install
  --no-service              Never prompt for service install
  --service-name <name>     Service name/label (default: oraclemcp)
  --listen <addr:port>      Service listen address (default: 127.0.0.1:7070)
  --profile <name>          Service profile passed to oraclemcp service install
  --allow-no-auth           Service dev-mode auth opt-in; loopback only
  --skip-linger             Skip optional loginctl enable-linger on Linux
  --yes                     Answer yes to explicit prompts
  --force                   Replace existing installed files
  --dry-run                 Print every file/unit/command that would be touched
  -h, --help                Show this help

The installer never mutates the service manager unless --service is supplied or
an interactive user answers yes to the service prompt.
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

service_install_args() {
  local args=("service" "install" "--yes" "--name" "$SERVICE_NAME" "--listen" "$SERVICE_LISTEN")
  if [ -n "$SERVICE_PROFILE" ]; then
    args+=("--profile" "$SERVICE_PROFILE")
  fi
  if [ "$SERVICE_ALLOW_NO_AUTH" -eq 1 ]; then
    args+=("--allow-no-auth")
  fi
  if [ "$SERVICE_SKIP_LINGER" -eq 1 ]; then
    args+=("--skip-linger")
  fi
  printf '%s\0' "${args[@]}"
}

print_plan() {
  local asset base mode
  asset="$(archive_name)"
  base="$(release_base_url)"
  mode="prebuilt"
  [ "$SOURCE" -eq 1 ] && mode="source"

  printf 'oraclemcp installer plan\n'
  printf '  mode: %s\n' "$mode"
  printf '  version: %s\n' "$VERSION"
  printf '  target: %s\n' "$TARGET"
  if [ "$TARGET_EXPLICIT" -eq 0 ] && detect_rosetta; then
    printf '  rosetta: detected; selecting native aarch64-apple-darwin unless --target overrides it\n'
  fi
  printf '  prefix: %s\n' "$PREFIX"
  printf '  bin_dir: %s\n' "$BIN_DIR"

  if [ "$SOURCE" -eq 1 ]; then
    if [ "$VERSION" = "latest" ]; then
      printf '  command: cargo +%s install oraclemcp --locked --root %s\n' "$RUST_TOOLCHAIN" "$PREFIX"
    else
      printf '  command: cargo +%s install oraclemcp --locked --version %s --root %s\n' "$RUST_TOOLCHAIN" "$VERSION" "$PREFIX"
    fi
    printf '  verification: source builds are explicit opt-in; release archive checksum/cosign verification is skipped\n'
  else
    printf '  archive: %s/%s\n' "$base" "$asset"
    printf '  checksum: %s/%s.sha256\n' "$base" "$asset"
    printf '  cosign_signature: %s/%s.sig + %s/%s.crt\n' "$base" "$asset" "$base" "$asset"
    printf '  cosign_attestation: %s/%s.attestation.sigstore.json\n' "$base" "$asset"
    printf '  sha256_note: checksum verifies transport integrity only; cosign verifies authenticity and provenance\n'
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
    printf '    readyz_gate: curl --fail --silent --show-error %s\n' "$(readyz_url)"
  else
    printf '  service: not requested; no service-manager files or units will be touched\n'
  fi
}

download_file() {
  local url="$1" dest="$2"
  if have curl; then
    curl --fail --location --show-error --silent --proto '=https' --tlsv1.2 \
      --output "$dest" "$url"
  elif have wget; then
    wget --https-only --quiet --output-document "$dest" "$url"
  else
    fail "missing downloader: install curl or wget"
  fi
}

verify_checksum() {
  local checksum="$1"
  local dir base
  dir="$(dirname "$checksum")"
  base="$(basename "$checksum")"
  if have sha256sum; then
    (cd "$dir" && sha256sum -c "$base")
  elif have shasum; then
    (cd "$dir" && shasum -a 256 -c "$base")
  else
    fail "missing checksum command: sha256sum or shasum"
  fi
}

verify_cosign() {
  local archive="$1" signature="$2" certificate="$3" attestation="$4"
  local identity_args=()
  need cosign
  while IFS= read -r -d '' arg; do
    identity_args+=("$arg")
  done < <(cosign_identity_args)

  cosign verify-blob \
    --certificate "$certificate" \
    --signature "$signature" \
    "${identity_args[@]}" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$archive"

  cosign verify-blob-attestation \
    --bundle "$attestation" \
    --type slsaprovenance1 \
    "${identity_args[@]}" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$archive"
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

install_binary() {
  local src="$1" dest="$BIN_DIR/oraclemcp"
  ensure_parent_dir "$dest"
  assert_replaceable "$dest"
  install -m 0755 "$src" "$dest"
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
  local command_path="$1" shell="$2" dest="$3"
  ensure_parent_dir "$dest"
  assert_replaceable "$dest"
  "$command_path" completions "$shell" >"$dest"
}

install_completions() {
  [ "$INSTALL_COMPLETIONS" -eq 1 ] || return
  install_completion "$BIN_DIR/oraclemcp" bash "$PREFIX/share/bash-completion/completions/oraclemcp"
  install_completion "$BIN_DIR/om" bash "$PREFIX/share/bash-completion/completions/om"
  install_completion "$BIN_DIR/oraclemcp" zsh "$PREFIX/share/zsh/site-functions/_oraclemcp"
  install_completion "$BIN_DIR/om" zsh "$PREFIX/share/zsh/site-functions/_om"
  install_completion "$BIN_DIR/oraclemcp" fish "$PREFIX/share/fish/vendor_completions.d/oraclemcp.fish"
  install_completion "$BIN_DIR/om" fish "$PREFIX/share/fish/vendor_completions.d/om.fish"
  install_completion "$BIN_DIR/oraclemcp" powershell "$PREFIX/share/powershell/Completions/oraclemcp.ps1"
  install_completion "$BIN_DIR/om" powershell "$PREFIX/share/powershell/Completions/om.ps1"
}

install_prebuilt() {
  local work_dir asset base archive checksum signature certificate attestation extracted
  need tar
  need install
  asset="$(archive_name)"
  base="$(release_base_url)"
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/oraclemcp-install.XXXXXX")"
  trap 'if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then rm -rf -- "$work_dir"; fi' EXIT

  archive="$work_dir/$asset"
  checksum="$archive.sha256"
  signature="$archive.sig"
  certificate="$archive.crt"
  attestation="$archive.attestation.sigstore.json"

  download_file "$base/$asset" "$archive"
  download_file "$base/$asset.sha256" "$checksum"
  download_file "$base/$asset.sig" "$signature"
  download_file "$base/$asset.crt" "$certificate"
  download_file "$base/$asset.attestation.sigstore.json" "$attestation"

  verify_checksum "$checksum"
  verify_cosign "$archive" "$signature" "$certificate" "$attestation"

  tar -xzf "$archive" -C "$work_dir"
  extracted="$work_dir/oraclemcp-$TARGET/oraclemcp"
  [ -x "$extracted" ] || fail "release archive did not contain executable $extracted"
  install_binary "$extracted"
}

install_source() {
  local args=("+$RUST_TOOLCHAIN" "install" "oraclemcp" "--locked" "--root" "$PREFIX")
  need cargo
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
  if [ "$PROMPT_SERVICE" -eq 0 ] || [ ! -t 0 ] || [ ! -t 1 ]; then
    return 1
  fi
  printf 'Install and start the local oraclemcp service now? [y/N] ' >&2
  local answer
  read -r answer
  case "$answer" in
    y | Y | yes | YES)
      SERVICE_REQUESTED=1
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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
    if curl --fail --silent --show-error "$url" >/dev/null; then
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
  if [ -z "$BIN_DIR" ]; then
    BIN_DIR="$PREFIX/bin"
  fi
  if [ -z "$TARGET" ]; then
    TARGET="$(detect_target)"
  fi
  validate_target "$TARGET"

  if [ "$DRY_RUN" -eq 1 ]; then
    print_plan
    exit 0
  fi

  if [ "$SOURCE" -eq 1 ]; then
    install_source
  else
    install_prebuilt
  fi
  install_om_alias
  install_completions

  if [ "$SERVICE_REQUESTED" -eq 1 ] || maybe_prompt_for_service; then
    install_service
  else
    printf 'oraclemcp installer: service install skipped\n' >&2
  fi

  printf 'oraclemcp installer: installed %s/oraclemcp and %s/om\n' "$BIN_DIR" "$BIN_DIR"
}

main "$@"
