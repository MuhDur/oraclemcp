#!/usr/bin/env bash
# D9 — governance gate for the vendored MIT sample schemas (rig L2).
#
# Vendoring third-party SQL is only safe while three things stay true, and none
# of them stays true on its own:
#
#   1. the bytes are still the upstream bytes at the pinned commit (no local
#      edits, no silent drift);
#   2. nothing UNVETTED has been added alongside them — this is the one that
#      actually happens, because a vendored directory looks like a convenient
#      place to drop "one more schema";
#   3. the licence text is still present, because vendoring MIT code without its
#      licence is the whole compliance failure.
#
# So this gate refuses on drift, on absence, AND on extra files. Adding a schema
# is a deliberate act: re-run the vendoring, regenerate MANIFEST.json, and record
# provenance in PROVENANCE.md. See that file for who may do it and when.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENDOR_DIR="${ORACLEMCP_SAMPLE_SCHEMA_DIR:-$ROOT/tests/fixtures/sample_schemas/upstream}"
MANIFEST="$VENDOR_DIR/MANIFEST.json"

FINDINGS=0

fail() {
  FINDINGS=$((FINDINGS + 1))
  echo "  REFUSED  $1" >&2
}

verify() {
  [ -f "$MANIFEST" ] || { echo "verify_sample_schemas: no manifest at $MANIFEST" >&2; exit 2; }

  # The licence is not merely a file in the list: vendoring MIT code without it
  # is a compliance failure, so it gets its own named refusal.
  local license_file
  license_file="$(python3 -c "import json;print(json.load(open('$MANIFEST'))['upstream'].get('license_file',''))" 2>/dev/null)"
  if [ -z "$license_file" ] || [ ! -f "$VENDOR_DIR/$license_file" ]; then
    fail "the upstream licence text ($license_file) is missing from $VENDOR_DIR"
  fi

  # Drift + absence, file by file against the pinned hashes.
  local rel expected actual
  while IFS=$'\t' read -r rel expected; do
    [ -n "$rel" ] || continue
    if [ ! -f "$VENDOR_DIR/$rel" ]; then
      fail "$rel is in the manifest but missing from the tree"
      continue
    fi
    actual="$(git hash-object "$VENDOR_DIR/$rel")"
    if [ "$actual" != "$expected" ]; then
      fail "$rel does not match the pinned upstream bytes (manifest ${expected:0:12}, found ${actual:0:12}) — vendored files are never edited in place; re-vendor from the pinned commit instead"
    fi
  done < <(python3 -c "
import json
m=json.load(open('$MANIFEST'))
for k,v in m['files'].items():
    print(f'{k}\t{v}')
")

  # Unvetted additions. This is the governance half: an unreviewed schema
  # dropped in here would otherwise inherit the vendored directory's implied
  # 'this was checked' status.
  local found
  while IFS= read -r found; do
    [ -n "$found" ] || continue
    [ "$found" = "MANIFEST.json" ] && continue
    if ! python3 -c "
import json,sys
m=json.load(open('$MANIFEST'))
sys.exit(0 if '$found' in m['files'] else 1)
"; then
      fail "$found is present but NOT in the manifest — nothing enters the vendored tree without recorded provenance (see PROVENANCE.md)"
    fi
  done < <(cd "$VENDOR_DIR" && find . -type f -printf '%P\n' | sort)

  if [ "$FINDINGS" -ne 0 ]; then
    echo "verify_sample_schemas: FAIL ($FINDINGS refusals)" >&2
    return 1
  fi
  local count
  count="$(python3 -c "import json;print(len(json.load(open('$MANIFEST'))['files']))")"
  echo "verify_sample_schemas: OK ($count files match the pinned upstream commit; licence present; no unvetted additions)"
  return 0
}

# A gate only ever observed passing is indistinguishable from one that returns
# true, so each refusal is aimed at a tree that must be rejected.
selftest() {
  local work failures=0
  work="$(mktemp -d)"
  cp -r "$VENDOR_DIR/." "$work/"

  local out
  out="$(ORACLEMCP_SAMPLE_SCHEMA_DIR="$work" bash "${BASH_SOURCE[0]}" 2>&1)"
  if [ $? -ne 0 ]; then
    echo "selftest: an untouched copy of the vendored tree was refused: $out" >&2
    failures=1
  fi

  # 1. drift: one byte changed in a vendored file
  printf '\n-- local edit\n' >> "$work/human_resources/hr_create.sql"
  if ORACLEMCP_SAMPLE_SCHEMA_DIR="$work" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "selftest: an edited vendored file was NOT refused" >&2
    failures=1
  fi
  cp "$VENDOR_DIR/human_resources/hr_create.sql" "$work/human_resources/hr_create.sql"

  # 2. an unvetted addition
  echo "-- unvetted" > "$work/unvetted_schema.sql"
  if ORACLEMCP_SAMPLE_SCHEMA_DIR="$work" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "selftest: an unvetted extra file was NOT refused" >&2
    failures=1
  fi
  mv "$work/unvetted_schema.sql" "$work/../unvetted_schema.sql.moved" 2>/dev/null

  # 3. the licence removed
  mv "$work/LICENSE.txt" "$work/../LICENSE.txt.moved"
  if ORACLEMCP_SAMPLE_SCHEMA_DIR="$work" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "selftest: a missing upstream licence was NOT refused" >&2
    failures=1
  fi
  mv "$work/../LICENSE.txt.moved" "$work/LICENSE.txt"

  # 4. a manifest entry whose file is gone
  mv "$work/sales_history/sh_create.sql" "$work/../sh_create.sql.moved"
  if ORACLEMCP_SAMPLE_SCHEMA_DIR="$work" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "selftest: a missing manifest file was NOT refused" >&2
    failures=1
  fi
  mv "$work/../sh_create.sql.moved" "$work/sales_history/sh_create.sql"

  if [ "$failures" -ne 0 ]; then
    echo "verify_sample_schemas selftest: FAIL" >&2
    exit 1
  fi
  echo "verify_sample_schemas selftest: OK (drift, unvetted additions, missing licence and missing files are all refused; a clean tree passes)"
  exit 0
}

case "${1:-}" in
  --selftest) selftest ;;
  --help|-h)
    cat <<'USAGE'
Verify the vendored MIT sample schemas against their pinned upstream commit.

Usage:
  bash scripts/rig/verify_sample_schemas.sh            # verify
  bash scripts/rig/verify_sample_schemas.sh --selftest # prove the gate can fail
USAGE
    exit 0 ;;
  "") verify; exit $? ;;
  *) echo "verify_sample_schemas: unknown argument: $1" >&2; exit 2 ;;
esac
