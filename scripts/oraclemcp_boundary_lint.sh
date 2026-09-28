#!/usr/bin/env bash
# oraclemcp one-way dependency boundary lint (plan §0 hard rule 1; beads P0-0, E-1).
#
# The engine-free oraclemcp-* core crates must NEVER depend on any plsql-*
# engine crate, in Cargo.toml or in source. Engine intelligence reaches the
# core only by the engine-side code implementing the core's Tool/registry
# contract — the core never reaches into the engine. This script is the CI
# gate that keeps the boundary structural and enforced, so the eventual
# Phase-E extraction is a mechanical git-filter-repo, not a rewrite.
#
# Exit 0 = boundary holds. Exit 1 = a violation (a core crate imports plsql-*).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/scripts/oraclemcp_boundary_lint.sh"
CRATES_DIR="$ROOT/crates"
violations=0

# `cargo tree --workspace` below is classified as a HEAVY Cargo operation by the
# compiler guard: Cargo starts rustc to probe target configuration, and the
# guard intercepts that probe. The guard can refuse for two independent reasons,
# and only the first is about the lease:
#
#   * exit 75 — no live build lease; re-enter through scripts/build_lease.sh so
#     the nested Cargo probe inherits a verified flock.
#   * exit 78 — the ambient CARGO_TARGET_DIR is a shared/RAM-backed cache the
#     guard refuses by name; a lease alone cannot fix it. The inspection selects
#     a dedicated per-agent target (the checkout's own target/) instead.
#
# resolve_target_dir() honors an ambient target dir only when the guard's own
# --target-only rule accepts it, so the guard stays the single authority and
# this script never widens or bypasses it.
resolve_target_dir() {
  local ambient="${CARGO_TARGET_DIR:-}"
  if [ -n "$ambient" ] &&
    "$ROOT/scripts/check_build_lease.sh" --target-only >/dev/null 2>&1; then
    printf '%s\n' "$ambient"
  else
    printf '%s\n' "$ROOT/target"
  fi
}

# Re-enter under build_lease.sh unless a live lease is already held by this
# process or one of its ancestors. check_build_lease.sh verifies the live flock
# itself; ORACLEMCP_BOUNDARY_LINT_LEASED only bounds the re-entry to one level so
# a persistent preflight refusal can never become an unbounded re-exec loop.
ensure_build_lease() {
  if "$ROOT/scripts/check_build_lease.sh" --require-lease >/dev/null 2>&1; then
    return 0
  fi
  if [ "${ORACLEMCP_BOUNDARY_LINT_LEASED:-0}" = "1" ]; then
    return 0
  fi
  export ORACLEMCP_BOUNDARY_LINT_LEASED=1
  exec "$ROOT/scripts/build_lease.sh" -- timeout 1800 bash "$SELF" "$@"
}

# --selftest: prove the lease inheritance and the preserved refusals without
# taking the full dependency walk. The one heavy step is a real leased
# `cargo tree --workspace` probe, so the integration is exercised end-to-end.
selftest() {
  local pass=0 fail=0 rc got
  selftest_check() { # WANT GOT DESCRIPTION
    if [ "$2" = "$1" ]; then
      echo "  PASS  $3 (got=$2)"
      pass=$((pass + 1))
    else
      echo "  FAIL  $3 (got=$2, want $1)" >&2
      fail=$((fail + 1))
    fi
  }

  # 1. Target-dir selection never runs the inspection against a shared cache.
  got="$( ( unset CARGO_TARGET_DIR; resolve_target_dir ) )"
  selftest_check "$ROOT/target" "$got" "unset ambient target -> checkout target/"
  got="$(CARGO_TARGET_DIR="$HOME/.cache/cargo-target" resolve_target_dir)"
  selftest_check "$ROOT/target" "$got" "shared ambient target -> checkout target/"
  got="$(CARGO_TARGET_DIR="$ROOT/target" resolve_target_dir)"
  selftest_check "$ROOT/target" "$got" "dedicated ambient target honored"

  # 2. The guard still classifies the inspection as heavy and refuses it with no
  #    lease (planted negative), and still refuses a shared target by name.
  rc=0
  ( unset CARGO_SWARM_BUILD_LEASE_DIR CARGO_SWARM_BUILD_LEASE_SLOT \
      CARGO_SWARM_BUILD_LEASE_PID CI
    CARGO_TARGET_DIR="$ROOT/target" "$ROOT/scripts/check_build_lease.sh" -- \
      cargo tree --locked --workspace -i oraclemcp >/dev/null 2>&1 ) || rc=$?
  selftest_check 75 "$rc" "un-leased 'cargo tree --workspace' refused"
  rc=0
  ( unset CARGO_SWARM_BUILD_LEASE_DIR CARGO_SWARM_BUILD_LEASE_SLOT \
      CARGO_SWARM_BUILD_LEASE_PID CI
    CARGO_TARGET_DIR="$HOME/.cache/cargo-target" \
      "$ROOT/scripts/check_build_lease.sh" -- \
      cargo tree --locked --workspace -i oraclemcp >/dev/null 2>&1 ) || rc=$?
  selftest_check 78 "$rc" "shared ambient target refused"

  # 3. A real leased probe of the exact heavy shape this fix unblocks succeeds.
  if [ -n "${CI:-}" ]; then
    echo "  SKIP  leased probe (single-tenant CI waives the lease)"
  else
    rc=0
    CARGO_TARGET_DIR="$ROOT/target" "$ROOT/scripts/build_lease.sh" \
      --timeout 240 --label boundary-lint-selftest -- \
      timeout 180 cargo tree --locked --workspace -e normal --target all \
      -i oraclemcp >/dev/null 2>&1 || rc=$?
    selftest_check 0 "$rc" "leased 'cargo tree --workspace' probe succeeds"
  fi

  echo
  if [ "$fail" -ne 0 ]; then
    echo "oraclemcp-boundary-lint: selftest FAILED ($fail of $((pass + fail)))" >&2
    exit 1
  fi
  echo "oraclemcp-boundary-lint: selftest OK ($pass checks)"
}

case "${1:-}" in
  --selftest)
    selftest
    exit $?
    ;;
  --help | -h)
    sed -n '2,12p' "$SELF" >&2
    exit 0
    ;;
esac

cd "$ROOT"
CARGO_TARGET_DIR="$(resolve_target_dir)"
export CARGO_TARGET_DIR
ensure_build_lease "$@"

mapfile -t core_crates < <(find "$CRATES_DIR" -maxdepth 1 -type d -name 'oraclemcp-*' | sort)

if [ "${#core_crates[@]}" -eq 0 ]; then
  echo "oraclemcp-boundary-lint: no oraclemcp-* crates found under $CRATES_DIR" >&2
  exit 1
fi

for crate in "${core_crates[@]}"; do
  name="$(basename "$crate")"

  # 1) Cargo.toml must not declare any plsql-* dependency.
  if [ -f "$crate/Cargo.toml" ]; then
    if grep -nE '^[[:space:]]*plsql-[a-z-]+[[:space:]]*=' "$crate/Cargo.toml" >/dev/null 2>&1; then
      echo "BOUNDARY VIOLATION: $name/Cargo.toml declares a plsql-* dependency:" >&2
      grep -nE '^[[:space:]]*plsql-[a-z-]+[[:space:]]*=' "$crate/Cargo.toml" >&2
      violations=$((violations + 1))
    fi
  fi

  # 2) No source file may import a plsql_* engine crate.
  if [ -d "$crate/src" ]; then
    if grep -rnE '(^|[^a-zA-Z_])plsql_[a-z_]+[[:space:]]*::|use[[:space:]]+plsql_[a-z_]+' \
        "$crate/src" 2>/dev/null | grep -v '//' >/dev/null 2>&1; then
      echo "BOUNDARY VIOLATION: $name/src imports a plsql_* engine crate:" >&2
      grep -rnE '(^|[^a-zA-Z_])plsql_[a-z_]+[[:space:]]*::|use[[:space:]]+plsql_[a-z_]+' \
        "$crate/src" 2>/dev/null | grep -v '//' >&2
      violations=$((violations + 1))
    fi
  fi
done

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-boundary-lint: $violations violation(s). The oraclemcp-* core must" >&2
  echo "stay engine-free (plan §0). Engine results reach a tool as AnalysisRun /" >&2
  echo "DepGraph / CatalogSnapshot parameters from the engine-side handler, never by" >&2
  echo "the core importing plsql-*." >&2
  exit 1
fi

echo "oraclemcp-boundary-lint: OK — ${#core_crates[@]} core crate(s) are engine-free."

forbidden_production_packages=(
  tokio
  tokio-stream
  tokio-util
  asupersync-tokio-compat
  rmcp
  axum
  hyper
  hyper-util
  oracle
  odpic-sys
  r2d2
  reqwest
  async-std
  smol
)

indent_text() {
  local line
  while IFS= read -r line; do
    printf '  %s\n' "$line"
  done
}

tree_package_present() {
  local label="$1"
  local package="$2"
  shift 2
  local output
  local status

  output="$(cargo tree --locked --workspace "$@" -i "$package" 2>&1)" && status=0 || status=$?
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output"
    return 0
  fi

  if grep -Eiq 'did not match|nothing to print|could not find package|not found' <<<"$output"; then
    return 1
  fi

  echo "oraclemcp-boundary-lint: could not inspect dependency '$package' for $label graph:" >&2
  indent_text <<<"$output" >&2
  return 2
}

check_production_dependency_graph() {
  echo "oraclemcp-boundary-lint: hard forbidden dependency gate for normal production graph."
  echo "oraclemcp-boundary-lint: cargo tree -e normal --workspace --target all -i <package>"

  local package
  local tree
  for package in "${forbidden_production_packages[@]}"; do
    if tree="$(tree_package_present "production" "$package" -e normal --target all)"; then
      echo "FORBIDDEN[production]: '$package' is present in the normal workspace dependency graph:" >&2
      indent_text <<<"$tree" >&2
      violations=$((violations + 1))
    else
      case "$?" in
        1) echo "OK[production]: $package absent from the normal workspace dependency graph." ;;
        2) violations=$((violations + 1)) ;;
      esac
    fi
  done
}

show_all_target_dependency_graph() {
  echo "oraclemcp-boundary-lint: all-target dependency visibility for forbidden package names."
  echo "oraclemcp-boundary-lint: cargo tree -e all --workspace --target all -i <package>"

  local package
  local tree
  for package in "${forbidden_production_packages[@]}"; do
    if tree="$(tree_package_present "all-target" "$package" -e all --target all)"; then
      echo "VISIBLE[all-target]: '$package' appears somewhere in all targets/edges:"
      indent_text <<<"$tree"
    else
      case "$?" in
        1) echo "OK[all-target]: $package absent from all workspace targets/edges." ;;
        2) violations=$((violations + 1)) ;;
      esac
    fi
  done
}

# Early-warning feature inspection (bead D4 / WP-D). opentelemetry-sdk is NOT a
# forbidden package — the telemetry crate may legitimately grow an OTLP exporter
# — but its `rt-tokio`/`rt-tokio-current-thread` runtime features pull Tokio in.
# If an upstream opentelemetry-sdk release ever flips one of those on by default,
# the Tokio gate above WILL fail; this check fires first and names the cause, so
# the Tokio failure is diagnosed as "opentelemetry-sdk dragged in a runtime"
# rather than chased blind. It complements the `-i tokio` / `-i reqwest` gates.
# Advisory: it explains, it does not itself fail the build (the Tokio gate does).
inspect_opentelemetry_runtime() {
  # The crate resolves under the underscore spelling (`opentelemetry_sdk`); the
  # hyphen form never matches `cargo tree -i`. Check the underscore name (and the
  # hyphen as a belt-and-braces fallback) so the early-warning actually fires for
  # the crate the asupersync `metrics` feature pulls in (bead D1/.1: catch an
  # upstream rt-tokio default flip before the Tokio gate above fails blind).
  local package
  local tree
  for package in opentelemetry_sdk opentelemetry-sdk; do
    if tree="$(tree_package_present "opentelemetry runtime" "$package" -e normal --target all)"; then
      echo "NOTE[otel]: '$package' is present in the production graph. Confirm no" \
        "rt-tokio* feature is enabled (that would pull Tokio and fail the gate above):"
      indent_text <<<"$tree"
      # Surface the resolved features so an rt-tokio flip is visible in the log.
      cargo tree --locked --workspace -e features --target all -i "$package" 2>/dev/null \
        | grep -iE 'rt-tokio|tokio' | indent_text || true
      return
    fi
    case "$?" in
      2)
        violations=$((violations + 1))
        return
        ;;
      *) ;;
    esac
  done
  echo "OK[otel]: opentelemetry_sdk absent from the production graph (no rt-tokio runtime risk)."
}

check_compat_markers() {
  local hits

  hits="$(grep -RIn 'COMPAT-REMOVE' "$ROOT/Cargo.toml" "$ROOT/crates" 2>/dev/null || true)"
  if [ -n "$hits" ]; then
    echo "FORBIDDEN[compat-marker]: temporary compat marker(s) remain in production paths:" >&2
    indent_text <<<"$hits" >&2
    echo "oraclemcp-boundary-lint: remove compat code or tie it to an open bead before release." >&2
    violations=$((violations + 1))
  else
    echo "OK[compat-marker]: no COMPAT-REMOVE markers remain in production paths."
  fi
}

check_production_dependency_graph
show_all_target_dependency_graph
inspect_opentelemetry_runtime
check_compat_markers
bash "$ROOT/scripts/rig/rig_boundary_lint.sh"

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-boundary-lint: $violations violation(s). The thin-native release" >&2
  echo "must stay free of Tokio, rmcp, Axum, Hyper, ODPI-C/oracle, r2d2, and" >&2
  echo "temporary Tokio compatibility dependencies in the production graph." >&2
  exit 1
fi

echo "oraclemcp-boundary-lint: OK — thin-native dependency boundary holds."
