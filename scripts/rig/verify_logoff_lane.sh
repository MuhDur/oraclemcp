#!/usr/bin/env bash
# D7 — the AFTER LOGOFF lane: does the server RELEASE its session, or just let
# the socket die?
#
# An operator cannot tell those apart from the client side. Both look like "the
# process exited". Only the database knows, and it knows because a database-level
# logoff trigger fires on a LOGICAL close and never fires when PMON reclaims a
# session whose process vanished. So every assertion here is about what the
# DATABASE observed, never about what the client believes it did.
#
# WHY "THE TRIGGER FIRED" IS NOT THE PROPERTY
#
# A lane that only proves the trigger fires would pass against a server that
# leaks every session on shutdown: some other session logging off cleanly would
# satisfy it. The property is the DIFFERENCE — a clean exit must produce a row
# and an abrupt kill must not — and each half has to be attributed to the
# server's own session. B7b extends that guard across the two server-owned
# connection surfaces: one pinned session plus one pooled stateless session.
#
# THE ANTI-VACUITY GUARD, which is the whole reason this lane is trustworthy:
# "no logoff row" is also what you observe when THERE WAS NEVER A SESSION. This
# server connects LAZILY — it holds no Oracle session while idle, so starting and
# stopping it proves nothing at all. (Measured: with the server running and idle,
# v$session held zero sessions for its user; an early version of this lane
# "proved" a leak that way and was wrong.) So the lane drives a real query,
# reads back the server's own SID, and REQUIRES that session to be visible in
# v$session before it is allowed to conclude anything from a missing row.
#
# Requires the D9 governance overlay (the ORACLEMCP_D9_AFTER_LOGOFF trigger and
# its log table) loaded into the lane database.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="${ORACLEMCP_D7_CONTAINER:-rust-oracledb-free}"
PDB="${ORACLEMCP_D7_PDB:-FREEPDB1}"
HOST_PORT="${ORACLEMCP_D7_HOST_PORT:-1522}"
FIXTURE_USER="ORACLEMCP_D9_TARGET"
FIXTURE_PW="D9_Governance_Test_42"
BIN="${ORACLEMCP_D7_BIN:-$ROOT/target/debug/oraclemcp}"
WORK="${ORACLEMCP_D7_WORK:-${TMPDIR:-/tmp}/oraclemcp-d7-lane}"
FINDINGS=0

ok()   { printf '  OK      %s\n' "$1"; }
bad()  { FINDINGS=$((FINDINGS + 1)); printf '  FAILED  %s\n' "$1" >&2; }
note() { printf '  NOTE    %s\n' "$1"; }

admin_pw() {
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" 2>/dev/null \
    | awk -F= '$1 == "ORACLE_PASSWORD" { print substr($0, index($0, "=") + 1); exit }'
}

# A marked scalar: SQL*Plus decorates bare numeric columns, so values are always
# fetched as strings carrying a marker.
sys_value() {
  local pw expr from
  pw="$(admin_pw)"; expr="$1"; from="${2:-from dual}"
  printf "set heading off feedback off pagesize 0\nselect 'D7VAL:'||(%s) %s;\nexit\n" "$expr" "$from" \
    | timeout 90 docker exec -i "$CONTAINER" \
        sqlplus -S -L "system/${pw}@localhost:1521/${PDB}" 2>&1 \
    | grep -oE 'D7VAL:[0-9]+' | cut -d: -f2 | head -1
}

session_module() {
  printf 'oraclemcp-d7-%s-%s-%s' "$(date +%s)" "$$" "$1"
}

setup_workspace() {
  local module="$1"
  mkdir -p "$WORK/home"
  cat >"$WORK/oraclemcp.toml" <<EOF
[[profiles]]
name = "d7"
connect_string = "localhost:${HOST_PORT}/${PDB}"
username = "${FIXTURE_USER}"
credential_ref = "env:D7_FIXTURE_PW"

[profiles.pool]
max_size = 1
min_idle = 1
acquire_timeout_secs = 3
statement_cache_size = 50

[profiles.session_identity]
module = "${module}"
client_identifier = "${module}"
EOF
  # NOTE: the credential env var must NOT be named ORACLEMCP_*. The config
  # loader claims that entire namespace for config overrides, so ORACLEMCP_D7_PW
  # is rejected as "unknown field d7_pw" before the server ever starts.
}

# Rows written by this mode's SERVER sessions. The profile installs a unique
# MODULE per mode, so concurrent lanes and this script's own SQL*Plus probes are
# excluded by construction.
server_logoff_rows() {
  local module="$1"
  sys_value "count(*)" "from ${FIXTURE_USER}.ORACLEMCP_D9_LOGOFF_LOG where module='${module}'"
}

live_server_sessions() {
  local module="$1"
  sys_value "count(*)" "from v\$session where username='${FIXTURE_USER}' and module='${module}'"
}

# Runs the server, drives one real query so the pinned session exists (pool
# min_idle eagerly establishes the stateless session during profile connect),
# and shuts it down in the requested way. Echoes
# "<pinned_sid> <live_sessions> <delta> <ghosts> <module>".
run_mode() {
  local mode="$1" module before after sid alive ghosts srv
  module="$(session_module "$mode")"
  setup_workspace "$module"
  before="$(server_logoff_rows "$module")"

  rm -f "$WORK/fin" "$WORK/fout"
  mkfifo "$WORK/fin" "$WORK/fout"

  HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" \
    ORACLEMCP_CONFIG="$WORK/oraclemcp.toml" D7_FIXTURE_PW="$FIXTURE_PW" \
    "$BIN" serve --profile d7 --allow-no-auth <"$WORK/fin" >"$WORK/fout" 2>/dev/null &
  srv=$!
  exec 9>"$WORK/fin"

  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"d7","version":"0"}}}' >&9
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&9
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oracle_query","arguments":{"sql":"select sys_context(:1,:2) as sid from dual","binds":["USERENV","SID"]}}}' >&9

  # Blocking read: returns as soon as the server answers, so no sleep is needed.
  sid="$(timeout 120 head -2 "$WORK/fout" | python3 -c "
import json,sys
for line in sys.stdin:
    line=line.strip()
    if not line.startswith('{'):
        continue
    d=json.loads(line)
    if d.get('id')==3 and 'result' in d:
        print(d['result']['structuredContent']['rows'][0]['SID'])
" | head -1)"

  alive="$(live_server_sessions "$module")"

  case "$mode" in
    clean) exec 9>&- ;;                         # stdin EOF: the orderly path
    term)  kill -TERM "$srv" 2>/dev/null ;;     # what a service manager sends
    kill)  kill -KILL "$srv" 2>/dev/null ;;     # the abrupt control
  esac
  wait "$srv" 2>/dev/null
  [ "$mode" = "clean" ] || exec 9>&-

  after="$(server_logoff_rows "$module")"
  ghosts="$(live_server_sessions "$module")"
  printf '%s %s %s %s %s\n' "${sid:-none}" "${alive:-0}" "$(( ${after:-0} - ${before:-0} ))" "${ghosts:-0}" "$module"
}

assert_mode() {
  local mode="$1" expect="$2" result sid alive delta ghosts module
  result="$(run_mode "$mode")"
  sid="$(printf '%s' "$result" | awk '{print $1}')"
  alive="$(printf '%s' "$result" | awk '{print $2}')"
  delta="$(printf '%s' "$result" | awk '{print $3}')"
  ghosts="$(printf '%s' "$result" | awk '{print $4}')"
  module="$(printf '%s' "$result" | awk '{print $5}')"

  # The guard. Without a session there is nothing to close, and "no row" would
  # be true of a server that never touched the database. B7b requires both
  # server-owned surfaces to be present before interpreting any teardown result:
  # pinned oracle_query plus the server-owned stateless pool's min_idle session.
  if [ "$sid" = "none" ] || [ "${alive:-0}" -lt 2 ]; then
    bad "$mode: could not prove the server held pinned + pooled live sessions (module=$module, pinned_sid=$sid, v\$session=$alive) — a missing or partial logoff row would mean nothing"
    return
  fi

  case "$expect" in
    row)
      if [ "${delta:-0}" -ge 2 ] && [ "${ghosts:-0}" -eq 0 ]; then
        ok "$mode: pinned sid $sid and pooled session were live; database recorded LOGICAL CLOSE for both (+$delta rows, no v\$session ghosts)"
      elif [ "${delta:-0}" -ge 2 ]; then
        bad "$mode: pinned + pooled sessions logged off (+$delta rows) but ${ghosts:-0} v\$session row(s) remained for module $module"
      else
        bad "$mode: pinned + pooled sessions were live but the database recorded only ${delta:-0} logoff row(s) — one server-owned surface did not release logically"
      fi ;;
    no_row)
      if [ "${delta:-0}" -eq 0 ]; then
        ok "$mode: pinned sid $sid and pooled session were live; database recorded NO logoff, as an abrupt end must look"
      else
        bad "$mode: an abrupt end produced $delta logoff row(s); the lane cannot distinguish clean from abrupt"
      fi ;;
  esac
}

main() {
  command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
  [ -x "$BIN" ] || { echo "no oraclemcp binary at $BIN (build it, or set ORACLEMCP_D7_BIN)" >&2; exit 2; }

  echo "D7 AFTER LOGOFF lane against ${CONTAINER}/${PDB}"
  assert_mode clean row      # the orderly path must be observable
  assert_mode kill  no_row   # the control: abrupt must look different
  assert_mode term  row      # service-manager shutdown must release both surfaces

  if [ "$FINDINGS" -ne 0 ]; then
    echo "FAIL verify_logoff_lane: $FINDINGS finding(s)" >&2
    exit 1
  fi
  echo "PASS verify_logoff_lane"
}

main "$@"
