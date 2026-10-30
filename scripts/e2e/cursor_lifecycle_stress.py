#!/usr/bin/env python3
"""External MCP cursor stress on the existing loopback W4 Oracle labs.

Print samples as JSONL. Credentials stay in memory/environment. The lab admin
alone reads V$OPEN_CURSOR/V$SESSTAT; the served account gets no catalog grants.
OPEN_CURSORS is changed only in the selected lab PDB and restored in finally.
This regression requires flat cursor use after three warmup connection
descriptions. The full mixed-tool W4 case remains blocked by the driver's
failed-parse leak; this regression does not claim that broader coverage.
"""

import argparse
import collections
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent / "w4"))
from driver import StdioClient, tool_payload
from fixture import CONFIG, connect_admin, load_lane


class StressClient(StdioClient):
    def _drain(self):
        for line in self.process.stderr:
            self.stderr_tail.append(line.rstrip())
            sys.stderr.write(line)
            sys.stderr.flush()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def emit(**record):
    print(json.dumps(record), flush=True)


def call(client, tool, arguments, refusal=False):
    payload = tool_payload(client.rpc("tools/call", {"name": tool, "arguments": arguments}))
    data = payload.get("structuredContent", {})
    require("ORA-01000" not in json.dumps(payload), f"{tool}: ORA-01000: {data}")
    require(bool(payload.get("isError")) == refusal, f"{tool}: unexpected result: {data}")
    if tool == "oracle_connection_info":
        require(data.get("connected") is True, "connection description lost its Oracle session")
        require(data.get("connection", {}).get("backend") == "rust_oracle",
                "cursor regression requires driver-cx, without an alternate backend")
    return data


def sample(admin, sid, serial, client_tag, iteration, mix, bound):
    with admin.cursor() as cur:
        current = cur.execute("SELECT sid, serial# FROM v$session WHERE client_identifier=:1",
                              [client_tag]).fetchall()
        require(current == [(sid, serial)], "served Oracle session vanished, reconnected, or multiplied")
        opened = int(cur.execute("""SELECT s.value FROM v$sesstat s
            JOIN v$statname n ON n.statistic#=s.statistic#
            WHERE s.sid=:1 AND n.name='opened cursors current'""", [sid]).fetchone()[0])
        listed = cur.execute("SELECT COUNT(*) FROM v$open_cursor WHERE sid=:1", [sid]).fetchone()[0]
        types = dict(cur.execute("SELECT cursor_type, COUNT(*) FROM v$open_cursor WHERE sid=:1 GROUP BY cursor_type", [sid]).fetchall())
    emit(iteration=iteration, tool_mix=dict(mix), sid=sid, serial=serial,
         open_cursors=opened, v_open_cursor=listed, cursor_types=types, error=None)
    require(opened <= bound, f"opened cursors current {opened} exceeds cache + 8 ({bound})")
    return opened


def run(args):
    settings = load_lane(CONFIG, args.lane)
    admin, _version = connect_admin(args.lane, settings)
    root = Path(tempfile.mkdtemp(prefix="oraclemcp-cursor-"))
    password = os.environ.get("ORACLEMCP_TEST_PASSWORD")
    if password is None:
        ci = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
        password = re.search(r"APP_USER_PASSWORD: (\S+)", ci.read_text())[1]
    user = os.environ.get("ORACLEMCP_TEST_USER", "E2E_ORACLE")
    client_tag = "CURSOR_STRESS_" + secrets.token_hex(12).upper()
    config = root / "profiles.toml"
    config.write_text(f'''schema_version = 2
default_profile = "cursor_stress"
[[profiles]]
name = "cursor_stress"
connect_string = "{settings['dsn']}"
username = "{user}"
credential_ref = "env:CURSOR_STRESS_PASSWORD"
max_level = "READ_WRITE"
default_level = "READ_ONLY"
[profiles.session_identity]
client_identifier = "{client_tag}"
[profiles.pool]
min_idle = 0
max_size = 1
statement_cache_size = {args.statement_cache_size}
''')
    env = dict(os.environ, ORACLEMCP_CONFIG=str(config), XDG_STATE_HOME=str(root / "state"),
               ORACLEMCP_AUDIT_KEY=secrets.token_hex(32), CURSOR_STRESS_PASSWORD=password,
               RUST_LOG=os.environ.get("RUST_LOG", "warn"))
    client = None
    previous = None
    try:
        with admin.cursor() as cur:
            previous = int(cur.execute("SELECT value FROM v$parameter WHERE name='open_cursors'").fetchone()[0])
            if args.open_cursors is not None:
                cur.execute(f"ALTER SYSTEM SET open_cursors={args.open_cursors} SCOPE=MEMORY")
        client = StressClient(args.binary.resolve(), "cursor_stress", env)
        reply = client.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "cursor-stress", "version": "1"}})
        require("result" in reply, f"initialize failed: {reply}")
        client.notify("notifications/initialized")
        call(client, "oracle_connection_info", {})
        with admin.cursor() as cur:
            sessions = cur.execute("SELECT sid, serial# FROM v$session WHERE client_identifier=:1",
                                   [client_tag]).fetchall()
            require(len(sessions) == 1, "expected exactly one tagged served Oracle session")
            sid, serial = sessions[0]
        for _ in range(3):
            call(client, "oracle_connection_info", {})
        counts = collections.Counter()
        peak = sample(admin, sid, serial, client_tag, 0, counts, args.statement_cache_size + 8)
        baseline = peak
        for iteration in range(1, args.iterations + 1):
            call(client, "oracle_connection_info", {})
            counts["oracle_connection_info"] += 1
            if iteration % args.sample_every == 0 or iteration == args.iterations:
                opened = sample(admin, sid, serial, client_tag, iteration, counts,
                                args.statement_cache_size + 8)
                require(opened <= baseline, f"connection descriptions grew cursors from {baseline} to {opened}")
                peak = max(peak, opened)
        emit(case="cursor_describe_no_reconnect",
             outcome="pass", iterations=args.iterations, warmup_calls=3, lane=args.lane,
             baseline_open_cursors=baseline, peak_open_cursors=peak,
             session_replacements=0, tool_mix=dict(counts))
    finally:
        try:
            if client is not None:
                client.close()
        finally:
            try:
                if previous is not None:
                    with admin.cursor() as cur:
                        cur.execute(f"ALTER SYSTEM SET open_cursors={previous} SCOPE=MEMORY")
                    emit(lane=args.lane, restored_open_cursors=previous)
            finally:
                admin.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--lane", choices=("free23", "xe21", "xe18"), default="free23")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--sample-every", type=int, default=50)
    parser.add_argument("--open-cursors", type=int, default=64)
    parser.add_argument("--statement-cache-size", type=int, default=50)
    args = parser.parse_args()
    require(args.iterations > 0 and args.sample_every > 0, "iteration/sample counts must be positive")
    try:
        run(args)
    except Exception as error:
        emit(case="cursor_describe_no_reconnect", outcome="fail", error=str(error))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
