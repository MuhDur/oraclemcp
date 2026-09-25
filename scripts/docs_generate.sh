#!/usr/bin/env bash
# Generated-docs drift gate (beads oraclemcp-2q4em.3.1 / .3.2).
#
# README.md and docs/configuration.md hold generated, fenced blocks:
#
#   <!-- generated:<id> --> ... <!-- /generated:<id> -->
#
# filled from the code that actually serves the surface, never hand-written:
#   * `tools`         and `tools-aliases` — from crates/oraclemcp/src/registry.rs
#     via `oraclemcp robot-docs tools --markdown`
#   * `config`        — from the typed config structs via
#     `oraclemcp robot-docs config --markdown`
#
# `--write` regenerates every block in place. `--check` renders fresh blocks and
# fails (exit 1) with a unified diff on any drift. The README tables document
# the default distribution, so every mode requires a renderer built with the
# default `plsql-intelligence` feature. `--selftest` proves the gate refuses a
# tampered block and a renderer missing that default feature.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'USAGE'
Generated-docs drift gate.

Usage:
  scripts/docs_generate.sh --write     # rewrite every generated block in place
  scripts/docs_generate.sh --check     # fail (exit 1) with a diff on drift
  scripts/docs_generate.sh --selftest  # prove the gate can refuse tampering

The default-feature renderer binary is $ORACLEMCP_BIN, or
${CARGO_TARGET_DIR:-<repo>/target}/debug/oraclemcp when unset. Build it first:
  CARGO_TARGET_DIR=<repo>/target scripts/build_lease.sh -- cargo build -p oraclemcp
USAGE
}

mode="${1:-}"
case "$mode" in
  --write | --check | --selftest) ;;
  --help | -h | "") usage; exit 0 ;;
  *) echo "docs-generate: unknown argument: $mode" >&2; usage >&2; exit 2 ;;
esac

# Resolve the renderer. An explicit binary wins, followed by the target the
# caller explicitly selected for Cargo; only then fall back to the checkout's
# conventional target. Otherwise a stale `$ROOT/target` binary can shadow the
# binary an operator just built in `CARGO_TARGET_DIR`.
resolve_renderer() {
  local explicit_bin="$1" cargo_target_dir="$2" repo_default="$3" candidate
  for candidate in \
    "$explicit_bin" \
    "${cargo_target_dir:+$cargo_target_dir/debug/oraclemcp}" \
    "$repo_default"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! BIN="$(resolve_renderer "${ORACLEMCP_BIN:-}" "${CARGO_TARGET_DIR:-}" "$ROOT/target/debug/oraclemcp")"; then
  echo "docs-generate: renderer binary not found or not executable" >&2
  echo "  build it with: CARGO_TARGET_DIR=$ROOT/target scripts/build_lease.sh -- cargo build -p oraclemcp" >&2
  exit 2
fi

# README's tool and alias tables describe the default distribution. The config
# reference is feature-independent, but handling the two outputs together means
# docs must always be rendered from the default-feature build.
require_default_renderer() {
  local renderer="$1" engine
  if ! engine="$("$renderer" --json info | python3 -c '
import json
import sys

payload = json.load(sys.stdin)
engine = payload.get("engine")
if not isinstance(engine, bool):
    raise SystemExit("oraclemcp --json info did not contain boolean engine")
print(str(engine).lower())
')"; then
    echo "docs-generate: could not verify renderer feature set from $renderer --json info" >&2
    return 1
  fi
  if [ "$engine" = "true" ]; then
    return 0
  fi
  if [ "$engine" = "false" ]; then
    echo "docs-generate: renderer $renderer is missing default plsql-intelligence; refusing to generate default-distribution docs" >&2
    echo "  build the default renderer with: CARGO_TARGET_DIR=$ROOT scripts/build_lease.sh -- cargo build -p oraclemcp" >&2
    return 1
  fi
  echo "docs-generate: renderer $renderer reported invalid engine value $engine" >&2
  return 1
}

if ! require_default_renderer "$BIN"; then
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
BLOCK_DIR="$TMP_DIR/blocks"
mkdir -p "$BLOCK_DIR"

# Render every marked block from the code. Each `--markdown` command emits one
# or more `<!-- generated:<id> --> ... <!-- /generated:<id> -->` blocks.
render_all() {
  "$BIN" robot-docs tools --markdown
  "$BIN" robot-docs config --markdown
}

split_render() {
  awk -v dir="$BLOCK_DIR" '
    /^<!-- generated:/ {
      id = $0
      sub(/^<!-- generated:/, "", id)
      sub(/ -->.*$/, "", id)
      inside = 1
      next
    }
    /^<!-- \/generated:/ { inside = 0; next }
    inside && id != "" { print > (dir "/" id) }
  '
}

render_all | split_render

if [ -z "$(ls -A "$BLOCK_DIR")" ]; then
  echo "docs-generate: renderer produced no marked blocks; refusing to report success" >&2
  exit 1
fi

# Rewrite every generated block in $1; each generated line gets $2 prepended so
# the same block can live commented inside a TOML example. Reads bodies from
# $BLOCK_DIR; prints the transformed document to stdout.
apply_writes() {
  local file="$1" prefix="$2"
  awk -v dir="$BLOCK_DIR" -v pfx="$prefix" '
    index($0, "<!-- generated:") > 0 {
      id = $0
      sub(/^.*<!-- generated:/, "", id)
      sub(/ -->.*$/, "", id)
      print
      body = dir "/" id
      while ((getline line < body) > 0) print pfx line
      close(body)
      skip = 1
      next
    }
    index($0, "<!-- /generated:") > 0 { skip = 0; print; next }
    skip { next }
    { print }
  ' "$file"
}

# Ids declared in one target file, one per line.
block_ids() {
  grep -o '<!-- generated:[a-z0-9-]* -->' "$1" | sed 's/.*generated://; s/ -->//' | sort -u
}

# Fail when a target file references a block id the renderer does not produce.
require_blocks_present() {
  local file="$1" id
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if [ ! -f "$BLOCK_DIR/$id" ]; then
      echo "docs-generate: $file references <!-- generated:$id --> but the renderer has no such block" >&2
      exit 1
    fi
  done < <(block_ids "$file")
}

# Compare one file's committed blocks against a fresh render. Returns nonzero on
# drift and prints the unified diff.
compare_file() {
  local file="$1" prefix="$2" rendered
  rendered="$TMP_DIR/$(basename "$file").rendered"
  apply_writes "$file" "$prefix" > "$rendered"
  diff -u "$file" "$rendered"
}

# target file -> generated-line prefix ("" or "# " for the commented TOML copy).
TARGET_FILES=(README.md docs/configuration.md oraclemcp.example.toml)
TARGET_PREFIXES=("" "" "# ")

for file in "${TARGET_FILES[@]}"; do
  [ -f "$file" ] || { echo "docs-generate: missing target file $file" >&2; exit 2; }
  require_blocks_present "$file"
done

# Prove the comparison actually detects drift before trusting a pass.
selftest() {
  local clean="README.md" tampered="$TMP_DIR/README.tampered.md"
  local default_renderer="$TMP_DIR/default-renderer"
  local no_engine_renderer="$TMP_DIR/no-engine-renderer" no_engine_output
  local explicit_target="$TMP_DIR/explicit-target" explicit_renderer
  local fallback_target="$TMP_DIR/fallback-target/debug/oraclemcp" selected

  # The default README must come from the default engine-enabled binary. Tiny
  # renderer fixtures exercise the exact `--json info` contract used above,
  # independent of which feature set compiled the real binary.
  printf '%s\n' \
    '#!/usr/bin/env sh' \
    "printf '%s\\n' '{\"engine\":true}'" > "$default_renderer"
  chmod +x "$default_renderer"
  if ! require_default_renderer "$default_renderer"; then
    echo "docs-generate: selftest failed: the default feature renderer was refused" >&2
    return 1
  fi
  printf '%s\n' \
    '#!/usr/bin/env sh' \
    "printf '%s\\n' '{\"engine\":false}'" > "$no_engine_renderer"
  chmod +x "$no_engine_renderer"
  if no_engine_output="$(require_default_renderer "$no_engine_renderer" 2>&1)"; then
    echo "docs-generate: selftest failed: a renderer missing the default feature was accepted" >&2
    return 1
  fi
  if ! printf '%s\n' "$no_engine_output" | grep -Fq 'plsql-intelligence'; then
    echo "docs-generate: selftest failed: missing-default-feature refusal was not diagnostic" >&2
    return 1
  fi

  # An explicit CARGO_TARGET_DIR must not be shadowed by an older checkout
  # target. Give both candidates executable fixtures and assert the target
  # requested by the caller wins.
  explicit_renderer="$explicit_target/debug/oraclemcp"
  mkdir -p "$(dirname "$explicit_renderer")" "$(dirname "$fallback_target")"
  printf '%s\n' '#!/usr/bin/env sh' 'exit 0' > "$explicit_renderer"
  printf '%s\n' '#!/usr/bin/env sh' 'exit 0' > "$fallback_target"
  chmod +x "$explicit_renderer" "$fallback_target"
  if ! selected="$(resolve_renderer "" "$explicit_target" "$fallback_target")"; then
    echo "docs-generate: selftest failed: explicit CARGO_TARGET_DIR renderer was not found" >&2
    return 1
  fi
  if [ "$selected" != "$explicit_renderer" ]; then
    echo "docs-generate: selftest failed: explicit CARGO_TARGET_DIR was shadowed by fallback renderer" >&2
    return 1
  fi

  if ! compare_file "$clean" "" >/dev/null; then
    echo "docs-generate: selftest failed: a clean README reported drift" >&2
    return 1
  fi
  # Tamper a line that only exists inside the generated tools block.
  sed 's/^| Tool | Title | Purpose | Visible from | Destructive |$/& TAMPERED/' \
    "$clean" > "$tampered"
  if compare_file "$tampered" "" >/dev/null; then
    echo "docs-generate: selftest failed: a tampered generated block was accepted" >&2
    return 1
  fi
  echo "docs-generate: selftest OK (default renderer required, drift detected, clean render accepted)"
}

case "$mode" in
  --write)
    for i in "${!TARGET_FILES[@]}"; do
      file="${TARGET_FILES[$i]}"
      prefix="${TARGET_PREFIXES[$i]}"
      rendered="$TMP_DIR/$(basename "$file").rendered"
      apply_writes "$file" "$prefix" > "$rendered"
      mv "$rendered" "$file"
    done
    echo "docs-generate: wrote ${#TARGET_FILES[@]} generated-docs targets"
    ;;
  --check)
    drift=0
    for i in "${!TARGET_FILES[@]}"; do
      file="${TARGET_FILES[$i]}"
      prefix="${TARGET_PREFIXES[$i]}"
      if ! compare_file "$file" "$prefix"; then
        drift=1
      fi
    done
    if [ "$drift" -ne 0 ]; then
      echo "docs-generate: DRIFT — run 'bash scripts/docs_generate.sh --write' and commit the result" >&2
      exit 1
    fi
    echo "docs-generate: OK (README.md, docs/configuration.md, oraclemcp.example.toml match the registry/config types)"
    ;;
  --selftest)
    selftest
    ;;
esac
