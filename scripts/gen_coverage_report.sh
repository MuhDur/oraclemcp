#!/usr/bin/env bash
# Conformance coverage-accounting generator (bead D6.3a / iec3.4.3).
#
# Renders the generated region of tests/conformance/COVERAGE.md from the
# machine-readable clause manifest tests/conformance/clauses.tsv and the
# divergence ledger tests/conformance/DISCREPANCIES.md:
#   * a per-section MUST/SHOULD x tested x passing x XFAIL x score matrix,
#   * the total tracked-requirement counts,
#   * an overall MUST-clause coverage score (target >= 0.95),
#   * the per-clause Requirement IDs table (id, level, tested, verdict), and
#   * a Divergence Ledger tying every DISC id to its status/review date.
#
# Modes:
#   --write (default)  Regenerate the region in place.
#   --check            Fail if the committed doc is stale (would change) or if
#                      MUST-clause coverage is below the target.
#
# The prose outside the generated markers is hand-authored and preserved.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/tests/conformance/clauses.tsv"
DISCREPANCIES="$ROOT/tests/conformance/DISCREPANCIES.md"
COVERAGE="$ROOT/tests/conformance/COVERAGE.md"
THRESHOLD="0.95"

BEGIN_MARK="<!-- BEGIN GENERATED: conformance-coverage (scripts/gen_coverage_report.sh) -->"
END_MARK="<!-- END GENERATED: conformance-coverage -->"

# Canonical Matrix section order (independent of manifest row order).
SECTION_ORDER='Initialize
Notifications
Resources
Subscriptions
Prompts
Tools
Completion
Pagination
JSON-RPC errors
Security
HTTP OAuth
HTTP client credentials
HTTP guards
HTTP sessions
HTTP routing
HTTP negotiation
Operator v1
Dashboard B.8
HTTP auth/no-leak
HTTPS / mTLS
Oracle structured cells
Durable SQL idempotency
WP-S persistent service
WP-N concurrency/session
WP-G hardening/docs'

MODE="write"
case "${1:-}" in
  ""|--write) MODE="write" ;;
  --check) MODE="check" ;;
  -h|--help)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  *) echo "gen_coverage_report: unknown argument: $1" >&2; exit 2 ;;
esac

for f in "$MANIFEST" "$DISCREPANCIES" "$COVERAGE"; do
  [ -f "$f" ] || { echo "gen_coverage_report: missing required file: $f" >&2; exit 2; }
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
summary="$tmpdir/summary"
block="$tmpdir/block.md"

# --- Pass 1: manifest -> matrix + score + requirement-id rows ----------------
awk -F'\t' -v order="$SECTION_ORDER" -v summaryfile="$summary" '
  function esc(s){ return s }
  BEGIN {
    n=split(order, ord, "\n")
    for (i=1;i<=n;i++){ known[ord[i]]=1; secorder[i]=ord[i] }
    norder=n
  }
  /^#/ { next }
  /^[[:space:]]*$/ { next }
  {
    id=$1; lvl=$2; sec=$3; tested=$4; verdict=$5; disc=$6; desc=$7
    if (!(sec in known)) {
      printf("gen_coverage_report: manifest section not in SECTION_ORDER: %s (clause %s)\n", sec, id) > "/dev/stderr"
      bad=1
    }
    # per-section tallies
    must[sec]+=0; should[sec]+=0; tcount[sec]+=0; xf[sec]+=0; fl[sec]+=0
    if (lvl=="MUST") must[sec]++
    else if (lvl=="SHOULD") should[sec]++
    else { printf("gen_coverage_report: bad level %s for %s\n", lvl, id) > "/dev/stderr"; bad=1 }
    if (tested=="y") tcount[sec]++
    if (verdict=="xfail") { xf[sec]++; if (disc=="-"||disc=="") { printf("gen_coverage_report: xfail clause %s lacks a DISC id\n", id) > "/dev/stderr"; bad=1 } }
    else if (verdict=="fail") fl[sec]++
    else if (verdict!="pass") { printf("gen_coverage_report: bad verdict %s for %s\n", verdict, id) > "/dev/stderr"; bad=1 }
    # global MUST tallies
    if (lvl=="MUST") {
      must_total++
      if (tested=="y") must_tested++
      if (verdict=="pass"||verdict=="xfail") must_pass++
    }
    if (lvl=="SHOULD") should_total++
    if (verdict=="xfail") xfail_total++
    # requirement-id rows in manifest order
    tword = (tested=="y") ? "yes" : "no"
    vword = verdict
    if (verdict=="xfail" && disc!="-") vword = verdict " (" disc ")"
    idrows[++nid] = sprintf("| %s | %s | %s | %s | %s | %s |", id, lvl, sec, tword, vword, desc)
    seen[sec]=1
  }
  END {
    if (bad) exit 3
    # Matrix in canonical order
    print "MATRIX_START"
    tot_must=0; tot_should=0; tot_tested=0; tot_pass=0; tot_xf=0
    for (i=1;i<=norder;i++){
      s=secorder[i]
      if (!(s in seen)) continue
      m=must[s]+0; sh=should[s]+0; t=tcount[s]+0; x=xf[s]+0; f=fl[s]+0
      p=t-f
      score=(t>0)? int((p/t)*100 + 0.5) : 0
      printf("| %s | %d | %d | %d | %d | %d | %d%% |\n", s, m, sh, t, p, x, score)
      tot_must+=m; tot_should+=sh; tot_tested+=t; tot_pass+=p; tot_xf+=x
    }
    print "MATRIX_END"
    printf("TOTAL\t%d\t%d\t%d\n", tot_must, tot_should, tot_tested)
    print "IDROWS_START"
    for (i=1;i<=nid;i++) print idrows[i]
    print "IDROWS_END"
    # summary for the gate
    mcov = (must_total>0) ? (must_pass/must_total) : 0
    printf("must_total=%d\nmust_tested=%d\nmust_pass=%d\nshould_total=%d\nxfail_total=%d\nmust_cov=%.2f\n",
           must_total, must_tested, must_pass, should_total+0, xfail_total+0, mcov) > summaryfile
  }
' "$MANIFEST" > "$tmpdir/pass1" || { echo "gen_coverage_report: manifest validation failed" >&2; exit 3; }

# Pre-declare the fields the awk summary assigns, so the sourced values are
# obviously scoped (and shellcheck sees them assigned).
must_total=""; must_tested=""; must_pass=""; should_total=""; xfail_total=""; must_cov=""
# shellcheck disable=SC1090
. "$summary"

# --- Pass 2: DISCREPANCIES.md -> divergence ledger rows -----------------------
awk '
  function flush(){
    if (cur!="") {
      if (status=="") { printf("gen_coverage_report: %s has no Status field\n", cur) > "/dev/stderr"; bad=1 }
      if (review=="") { printf("gen_coverage_report: %s has no Review date field\n", cur) > "/dev/stderr"; bad=1 }
      printf("| %s | %s | %s | %s |\n", cur, status, review, tests)
    }
    cur=""; status=""; review=""; tests=""
  }
  /^##[[:space:]]+DISC-[0-9]+:/ {
    flush()
    line=$0
    sub(/^##[[:space:]]+/,"",line)
    split(line, a, ":")
    cur=a[1]
    next
  }
  cur!="" && /^[-*][[:space:]]*Status:/ { s=$0; sub(/^[-*][[:space:]]*Status:[[:space:]]*/,"",s); status=s; next }
  cur!="" && /^[-*][[:space:]]*Review date:/ { s=$0; sub(/^[-*][[:space:]]*Review date:[[:space:]]*/,"",s); sub(/\.[[:space:]]*$/,"",s); review=s; next }
  cur!="" && /^[-*][[:space:]]*Tests affected:/ { s=$0; sub(/^[-*][[:space:]]*Tests affected:[[:space:]]*/,"",s); sub(/\.[[:space:]]*$/,"",s); tests=s; next }
  END { flush(); if (bad) exit 3 }
' "$DISCREPANCIES" > "$tmpdir/ledger" || { echo "gen_coverage_report: DISCREPANCIES.md validation failed" >&2; exit 3; }

# --- Assemble the generated block --------------------------------------------
{
  echo "## Matrix"
  echo
  echo "This section is generated by \`scripts/gen_coverage_report.sh\` from"
  echo "\`tests/conformance/clauses.tsv\`. Do not hand-edit between the generated"
  echo "markers. \`Passing\` counts every green clause (an accepted XFAIL asserts its"
  echo "documented limit and passes); \`Score\` is Passing / Tested."
  echo
  echo "| Section | MUST Clauses | SHOULD Clauses | Tested | Passing | XFAIL | Score |"
  echo "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
  sed -n '/^MATRIX_START$/,/^MATRIX_END$/p' "$tmpdir/pass1" | sed '1d;$d'
  echo
  read -r _ t_must t_should t_tested < <(grep '^TOTAL' "$tmpdir/pass1")
  echo "Total tracked requirements: ${t_must} MUST, ${t_should} SHOULD, ${t_tested} tested."
  echo
  echo "## Coverage Score"
  echo
  echo "| Metric | Value |"
  echo "| --- | ---: |"
  echo "| MUST clauses | ${must_total} |"
  echo "| MUST tested | ${must_tested} |"
  echo "| MUST passing (pass or accepted XFAIL) | ${must_pass} |"
  echo "| MUST coverage score | ${must_cov} |"
  echo "| MUST coverage target | ${THRESHOLD} |"
  echo "| SHOULD clauses | ${should_total} |"
  echo "| Accepted clause XFAILs | ${xfail_total} |"
  echo
  echo "MUST-clause coverage is **${must_cov}** (target >= ${THRESHOLD}). A \`fail\`"
  echo "verdict in the manifest drops this below target and fails CI."
  echo
  echo "## Requirement IDs"
  echo
  echo "| ID | Level | Section | Tested | Verdict | Covered Behavior |"
  echo "| --- | --- | --- | --- | --- | --- |"
  sed -n '/^IDROWS_START$/,/^IDROWS_END$/p' "$tmpdir/pass1" | sed '1d;$d'
  echo
  echo "## Divergence Ledger"
  echo
  echo "Every intentional divergence from python-oracledb or strict JSON-RPC is an"
  echo "XFAIL-tracked entry in \`tests/conformance/DISCREPANCIES.md\` (never a silent"
  echo "skip). Clause-level XFAILs also appear in the matrix above; behavioral"
  echo "divergences are tested green and asserted by their named tests."
  echo
  echo "| DISC | Status | Review date | Affected tests |"
  echo "| --- | --- | --- | --- |"
  cat "$tmpdir/ledger"
  echo
} > "$block"

# --- Gate: MUST coverage must clear the target -------------------------------
if ! awk -v s="$must_cov" -v t="$THRESHOLD" 'BEGIN{ exit !((s+0) >= (t+0)) }'; then
  echo "gen_coverage_report: MUST-clause coverage ${must_cov} is below target ${THRESHOLD}" >&2
  exit 1
fi

# --- Splice the block between the markers -------------------------------------
grep -qF "$BEGIN_MARK" "$COVERAGE" || { echo "gen_coverage_report: BEGIN marker missing in $COVERAGE" >&2; exit 2; }
grep -qF "$END_MARK" "$COVERAGE" || { echo "gen_coverage_report: END marker missing in $COVERAGE" >&2; exit 2; }

rendered="$tmpdir/coverage.md"
awk -v begin="$BEGIN_MARK" -v end="$END_MARK" -v blockfile="$block" '
  $0==begin { print; while ((getline l < blockfile) > 0) print l; close(blockfile); skip=1; next }
  $0==end { skip=0; print; next }
  !skip { print }
' "$COVERAGE" > "$rendered"

if [ "$MODE" = "check" ]; then
  if ! diff -u "$COVERAGE" "$rendered" >/dev/null; then
    echo "gen_coverage_report: tests/conformance/COVERAGE.md is STALE." >&2
    echo "Run: bash scripts/gen_coverage_report.sh --write" >&2
    diff -u "$COVERAGE" "$rendered" >&2 || true
    exit 1
  fi
  echo "gen_coverage_report: COVERAGE.md is current; MUST coverage ${must_cov} (>= ${THRESHOLD})."
else
  cp "$rendered" "$COVERAGE"
  echo "gen_coverage_report: wrote COVERAGE.md; MUST coverage ${must_cov} (>= ${THRESHOLD})."
fi
