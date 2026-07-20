#!/usr/bin/env bash
# Mandatory Cargo compile interceptor for the E1/W3 build lease.
#
# Cargo invokes build.rustc-wrapper before every compiler process. That makes
# this the repo-local enforcement point for direct built-in commands such as
# `cargo test --workspace`, rather than another optional command wrapper.
# The originating Cargo argv is recovered from the process tree and delegated
# to check_build_lease.sh. If the argv cannot be recovered, an unleased compile
# fails closed. The check runs before rustc (or sccache) is executed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/scripts/cargo_build_guard.sh"
CHECK="$ROOT/scripts/check_build_lease.sh"

if [ "$#" -lt 1 ]; then
  echo "cargo_build_guard: missing rustc executable argument" >&2
  exit 64
fi

RUSTC="$1"
shift

declare -a CARGO_ARGV=()

is_cargo_process() {
  local name="${1##*/}"
  case "$name" in
    cargo|cargo.exe|cargo-*) return 0 ;;
    *) return 1 ;;
  esac
}

# Linux preserves the exact NUL-delimited argv in procfs. Walk upward because
# an outer cache wrapper or Cargo subcommand can add one process between this
# wrapper and the Cargo process we need to classify.
find_linux_cargo_argv() {
  local pid="$PPID" depth=0 name parent found=1
  declare -a argv=()
  while [ "$pid" -gt 1 ] && [ "$depth" -lt 8 ]; do
    name=""
    IFS= read -r name <"/proc/$pid/comm" || true
    if is_cargo_process "$name"; then
      mapfile -d '' -t argv <"/proc/$pid/cmdline"
      if [ "${#argv[@]}" -gt 0 ]; then
        # Keep walking: cargo-mutants/cargo-hack spawn an inner scoped Cargo.
        # Classifying only that nearest child would miss the heavy outer fanout.
        CARGO_ARGV+=("${argv[@]}")
        found=0
      fi
    fi
    # /proc/PID/stat is: pid (comm, which may contain spaces) state ppid ...
    parent="$(sed -E 's/^[0-9]+ \(.*\) [^ ]+ ([0-9]+) .*/\1/' "/proc/$pid/stat" 2>/dev/null || true)"
    case "$parent" in
      ''|*[!0-9]*) return 1 ;;
    esac
    pid="$parent"
    depth=$((depth + 1))
  done
  return "$found"
}

# macOS has no procfs. ps loses exact argument boundaries, but the lease
# classifier only needs Cargo's option tokens; paths containing spaces remain
# safe because a false ambiguity falls back to the fail-closed path below.
find_ps_cargo_argv() {
  local pid="$PPID" depth=0 name parent command_line found=1
  while [ "$pid" -gt 1 ] && [ "$depth" -lt 8 ]; do
    name="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
    if is_cargo_process "$name"; then
      command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
      if [ -n "$command_line" ]; then
        # Intentional shell tokenisation: Cargo flags never rely on quoting in
        # the supported repository paths. A path with spaces is ambiguous and
        # will be rejected by target validation instead of trusted.
        declare -a argv=()
        read -r -a argv <<<"$command_line"
        if [ "${#argv[@]}" -gt 0 ]; then
          CARGO_ARGV+=("${argv[@]}")
          found=0
        fi
      fi
    fi
    parent="$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ' || true)"
    case "$parent" in
      ''|*[!0-9]*) return 1 ;;
    esac
    pid="$parent"
    depth=$((depth + 1))
  done
  return "$found"
}

cargo_target_override() {
  local i arg next
  for ((i = 0; i < ${#CARGO_ARGV[@]}; i++)); do
    arg="${CARGO_ARGV[$i]}"
    case "$arg" in
      --target-dir)
        next=$((i + 1))
        [ "$next" -lt "${#CARGO_ARGV[@]}" ] || return 1
        printf '%s\n' "${CARGO_ARGV[$next]}"
        return 0
        ;;
      --target-dir=*)
        printf '%s\n' "${arg#--target-dir=}"
        return 0
        ;;
      build.target-dir=*)
        # Handles `cargo --config build.target-dir=PATH ...`.
        printf '%s\n' "${arg#build.target-dir=}"
        return 0
        ;;
    esac
  done
  return 1
}

rustc_out_dir() {
  local i arg next
  declare -a rustc_argv=("$@")
  for ((i = 0; i < ${#rustc_argv[@]}; i++)); do
    arg="${rustc_argv[$i]}"
    case "$arg" in
      --out-dir)
        next=$((i + 1))
        [ "$next" -lt "${#rustc_argv[@]}" ] || return 1
        printf '%s\n' "${rustc_argv[$next]}"
        return 0
        ;;
      --out-dir=*)
        printf '%s\n' "${arg#--out-dir=}"
        return 0
        ;;
    esac
  done
  return 1
}

TARGET_OVERRIDE=""
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
  TARGET_OVERRIDE="$(cargo_target_override || true)"
  if [ -z "$TARGET_OVERRIDE" ]; then
    # A configured target dir is visible in rustc's --out-dir even when Cargo
    # did not export CARGO_TARGET_DIR. check_build_lease.sh rejects descendants
    # of shared/RAM-backed roots, so the precise profile suffix is safe here.
    TARGET_OVERRIDE="$(rustc_out_dir "$@" || true)"
  fi
fi

run_preflight() {
  local output rc
  rc=0
  if [ "${#CARGO_ARGV[@]}" -gt 0 ]; then
    if [ -n "$TARGET_OVERRIDE" ]; then
      output="$(CARGO_TARGET_DIR="$TARGET_OVERRIDE" "$CHECK" -- "${CARGO_ARGV[@]}" 2>&1)" || rc=$?
    else
      output="$("$CHECK" -- "${CARGO_ARGV[@]}" 2>&1)" || rc=$?
    fi
  else
    echo "cargo_build_guard: Cargo argv unavailable; requiring a lease (fail closed)." >&2
    if [ -n "$TARGET_OVERRIDE" ]; then
      output="$(CARGO_TARGET_DIR="$TARGET_OVERRIDE" "$CHECK" --require-lease 2>&1)" || rc=$?
    else
      output="$("$CHECK" --require-lease 2>&1)" || rc=$?
    fi
  fi
  if [ "$rc" -ne 0 ] || [ "${ORACLEMCP_BUILD_GUARD_VERBOSE:-0}" = "1" ]; then
    printf '%s\n' "$output" >&2
  fi
  return "$rc"
}

if [ -d /proc/$$ ]; then
  find_linux_cargo_argv || true
else
  find_ps_cargo_argv || true
fi
run_preflight

# Repo-local config necessarily takes precedence over a user's global
# rustc-wrapper. Preserve the project's documented sccache acceleration when
# it is available; an explicit alternate cache wrapper may be supplied without
# weakening the guard because it runs only after the preflight succeeds.
CACHE_WRAPPER="${ORACLEMCP_RUSTC_CACHE_WRAPPER:-}"
if [ -z "$CACHE_WRAPPER" ] && [ "${ORACLEMCP_DISABLE_SCCACHE:-0}" != "1" ]; then
  CACHE_WRAPPER="$(command -v sccache 2>/dev/null || true)"
fi
if [ -n "$CACHE_WRAPPER" ] && [ "$CACHE_WRAPPER" != "$SELF" ]; then
  exec "$CACHE_WRAPPER" "$RUSTC" "$@"
fi
exec "$RUSTC" "$@"
