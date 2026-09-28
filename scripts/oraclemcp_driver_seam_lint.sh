#!/usr/bin/env bash
# oraclemcp driver-adapter seam lint (B2; plan §8 release gate).
#
# Each Oracle backend is isolated behind EXACTLY ONE adapter file. Every real
# backend-crate call (connect, execute, fetch, LOB, REF CURSOR, auth,
# commit/rollback, ping, error sanitization) must live in that backend's adapter
# and nowhere else. This script is the CI gate that keeps the two seams
# structural and enforced:
#
#   * driver-cx -> crates/oraclemcp-db/src/connection.rs
#   * official  -> crates/oraclemcp-db/src/oracledb_backend.rs
#
# It FAILS if a backend crate path appears outside that backend's adapter, i.e.
# if a SECOND file names either path. It matches the backend CRATE path (with a
# left word boundary) and not the workspace/protocol crate: the exact identifier
# and boundary prevent `oraclemcp_db::` and `oraclemcp_driver_cx_protocol::`
# from matching.
#
# Comment mentions are ignored: the `//`-to-end-of-line portion is stripped
# before matching, so a doc comment that names a backend path (e.g.
# `/// oracledb::Connection is thread-confined`) is not a violation. Only a code
# path counts.
#
# Mirrored by the `driver_seam` test in crates/oraclemcp-db/src/connection.rs so
# `cargo test` catches a leak even without this shell script. If a new legitimate
# backend-crate site is ever required, add it to BOTH allowlists with an inline
# justification. Adding a second file per backend is NOT an accepted fix.
#
# Exit 0 = both seams hold. Exit 1 = a backend call leaked outside its adapter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# One adapter file per backend. Paths are relative to the scanned root ($ROOT in
# the real run). Each entry is the ONLY place that backend's crate path may
# appear in code.
declare -A BACKEND_ADAPTER=(
  [driver-cx]="crates/oraclemcp-db/src/connection.rs"
  [official]="crates/oraclemcp-db/src/oracledb_backend.rs"
)
declare -A BACKEND_PATTERN=(
  [driver-cx]='(^|[^A-Za-z0-9_])oraclemcp_driver_cx[[:space:]]*::'
  [official]='(^|[^A-Za-z0-9_])oracledb[[:space:]]*::'
)
BACKEND_ORDER=(driver-cx official)

# Strip the `//`-to-end-of-line portion, then test the remaining code against the
# backend pattern. Prints `line:text` for each code hit.
seam_hits() { # FILE PATTERN
  local file="$1" pattern="$2" n=0 line code
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    code="${line%%//*}"
    if [[ "$code" =~ $pattern ]]; then
      printf '%d:%s\n' "$n" "$line"
    fi
  done <"$file"
}

violations=0

# scan_seam CRATES_DIR REL_ROOT: walk every Rust source under CRATES_DIR and
# refuse a backend path outside that backend's adapter. Build output under any
# `target/` directory is not source and is pruned.
scan_seam() {
  local crates_dir="$1" rel_root="$2"
  local file rel backend adapter pattern hits
  [ -d "$crates_dir" ] || return 0
  while IFS= read -r -d '' file; do
    rel="${file#"$rel_root"/}"
    for backend in "${BACKEND_ORDER[@]}"; do
      adapter="${BACKEND_ADAPTER[$backend]}"
      pattern="${BACKEND_PATTERN[$backend]}"
      if [ "$rel" = "$adapter" ]; then
        continue
      fi
      hits="$(seam_hits "$file" "$pattern")"
      if [ -n "$hits" ]; then
        echo "SEAM VIOLATION[$backend]: $rel names an ${backend} backend path outside its adapter:" >&2
        while IFS= read -r hit; do
          printf '  %s\n' "$hit" >&2
        done <<<"$hits"
        echo "  allowlisted ${backend} adapter: $adapter" >&2
        violations=$((violations + 1))
      fi
    done
  done < <(find "$crates_dir" -type d -name target -prune -o -type f -name '*.rs' -print0 | sort -z)
}

# --selftest: prove the seam predicate catches a SECOND file naming EACH backend
# path and does not fire on a comment-only mention. Each case prints
# {case_id, expected, actual}.
selftest() {
  local pass=0 fail=0 dir got
  selftest_case() { # ID EXPECTED ACTUAL
    local id="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
      echo "PASS {case_id=$id, expected=$expected, actual=$actual}"
      pass=$((pass + 1))
    else
      echo "FAIL {case_id=$id, expected=$expected, actual=$actual}" >&2
      fail=$((fail + 1))
    fi
  }

  # One temp tree per case: the backend adapter itself plus a second file whose
  # body is the planted leak. The same predicate the real run uses is applied.
  # The caller removes the tree after scanning it.
  build_fixture() { # ADAPTER_REL SECOND_FILE_BODY
    local adapter_rel="$1" body="$2"
    dir="$(mktemp -d "${TMPDIR:-/tmp}/oraclemcp-seam-selftest.XXXXXX")"
    mkdir -p "$dir/crates/oraclemcp-db/src"
    : >"$dir/$adapter_rel"
    printf '%s\n' "$body" >"$dir/crates/oraclemcp-db/src/leak.rs"
  }

  # 1. A SECOND file naming a driver-cx path fails (pre-change lint passes it
  #    only because the driver-cx adapter was already allowlisted; a new file
  #    still leaks).
  violations=0
  build_fixture "crates/oraclemcp-db/src/connection.rs" \
    'fn leak() { oraclemcp_driver_cx::Connection::connect(); }'
  scan_seam "$dir/crates" "$dir"
  got=$([ "$violations" -gt 0 ] && echo fail || echo pass)
  rm -rf "$dir"
  selftest_case "seam_second_file_driver_cx_path_fails" "fail" "$got"

  # 2. A SECOND file naming the official path fails.
  violations=0
  build_fixture "crates/oraclemcp-db/src/oracledb_backend.rs" \
    'fn leak() { let _ = oracledb::Connection::connect(cfg); }'
  scan_seam "$dir/crates" "$dir"
  got=$([ "$violations" -gt 0 ] && echo fail || echo pass)
  rm -rf "$dir"
  selftest_case "seam_second_file_official_path_fails" "fail" "$got"

  # 3. A comment-only mention passes (the official pattern ignores `//` lines).
  violations=0
  build_fixture "crates/oraclemcp-db/src/oracledb_backend.rs" \
    $'// oracledb::Connection is thread-confined and never leaves the actor.\nfn ok() {}'
  scan_seam "$dir/crates" "$dir"
  got=$([ "$violations" -gt 0 ] && echo fail || echo pass)
  rm -rf "$dir"
  selftest_case "seam_comment_mention_passes" "pass" "$got"

  echo
  if [ "$fail" -ne 0 ]; then
    echo "oraclemcp-driver-seam-lint: selftest FAILED ($fail of $((pass + fail)))" >&2
    exit 1
  fi
  echo "oraclemcp-driver-seam-lint: selftest OK ($pass checks)"
}

case "${1:-}" in
  --selftest)
    selftest
    exit $?
    ;;
  --help | -h)
    sed -n '2,12p' "$0" >&2
    exit 0
    ;;
esac

cd "$ROOT"

echo "oraclemcp-driver-seam-lint: exactly one adapter file per Oracle backend:"
for backend in "${BACKEND_ORDER[@]}"; do
  echo "  $backend: ${BACKEND_ADAPTER[$backend]}"
done

scan_seam "$ROOT/crates" "$ROOT"

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-driver-seam-lint: $violations violation(s): a backend crate path leaked." >&2
  echo "Each backend MUST stay behind its one adapter. Move the call behind an" >&2
  echo "OracleConnection / adapter method. Do NOT add a second file per backend." >&2
  exit 1
fi

echo "oraclemcp-driver-seam-lint: OK — driver-cx is confined to ${BACKEND_ADAPTER[driver-cx]}"
echo "oraclemcp-driver-seam-lint: OK — official is confined to ${BACKEND_ADAPTER[official]}"
