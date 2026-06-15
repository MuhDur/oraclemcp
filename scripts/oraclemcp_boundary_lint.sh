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

core_crates=$(find "$CRATES_DIR" -maxdepth 1 -type d -name 'oraclemcp-*' | sort)

if [ -z "$core_crates" ]; then
  echo "oraclemcp-boundary-lint: no oraclemcp-* crates found under $CRATES_DIR" >&2
  exit 1
fi

for crate in $core_crates; do
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

echo "oraclemcp-boundary-lint: OK — $(echo "$core_crates" | wc -l | tr -d ' ') core crate(s) are engine-free."

advisory_packages=(
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

check_dependency_graph() {
  local label="$1"
  shift
  local cargo_args=("$@")

  echo "oraclemcp-boundary-lint: advisory dependency holdouts for $label graph (non-failing until W12)."

  for package in "${advisory_packages[@]}"; do
    tree_file="$(mktemp)"
    if cargo tree -e normal --workspace "${cargo_args[@]}" -i "$package" >"$tree_file" 2>&1; then
      echo "ADVISORY[$label]: forbidden final dependency currently present: $package" >&2
      sed 's/^/  /' "$tree_file" >&2
    else
      if grep -Eiq 'did not match|nothing to print|could not find package|not found' "$tree_file"; then
        echo "OK[$label]: $package absent from the normal workspace dependency graph."
      else
        echo "ADVISORY[$label]: could not inspect dependency '$package'; cargo tree said:" >&2
        sed 's/^/  /' "$tree_file" >&2
      fi
    fi
    rm -f "$tree_file"
  done
}

check_dependency_graph "default"
