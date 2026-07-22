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
CRATES_DIR="$ROOT/crates"
violations=0
cd "$ROOT"

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
