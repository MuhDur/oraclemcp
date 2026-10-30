#!/usr/bin/env python3
"""External MCP proof for isolated RLS/VPD policy observation (xrna0).

Drives the real server binary over stdio against a disposable lab user that
owns a 64-policy table, in two phases, each with a fresh server process:

1. healthy catalog: every `oracle_query` returns its real row and the isolated
   observation reports `policy_rows_visible`;
2. stalled catalog: a private `ALL_POLICIES` synonym makes the policy catalog
   sleep for 12 s. Reads must still return their row promptly, with an honest
   `visibility_unavailable` observation instead of a stalled or busy session.

Each phase also pipelines two `oracle_query` calls on one client session; both
must succeed (no SESSION_BUSY). Results are JSON lines on stdout.

The lab password is generated per run and passed only through the child's
environment; the profile file holds a credential reference, never a secret.
"""

import argparse
import json
import os
import pathlib
import queue
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
RIG = ROOT / "scripts/e2e/w4/rig.toml"
READ_SQL = "SELECT id FROM xr_plain"
PROMPT_MS = 5000
# Same predeclared settle as the Rust policy fixtures: a read whose snapshot
# straddles the just-created objects fails with ORA-01466.
DDL_SETTLE_SECONDS = 3


def emit(**record):
    print(json.dumps(record), flush=True)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Lab:
    def __init__(self, lane):
        settings = tomllib.loads(RIG.read_text())["lanes"][lane]
        require(settings.get("lab") is True, f"{lane} is not a disposable lab lane")
        self.dsn = settings["dsn"]
        self.container = settings["container"]
        self.pdb = self.dsn.rsplit("/", 1)[1]
        self.user = "XRNA0_" + secrets.token_hex(6).upper()
        self.password = "Xr" + secrets.token_hex(12)

    def sql(self, statements):
        script = ("whenever sqlerror exit failure\nset heading off feedback off pagesize 0\n"
                  f"alter session set container={self.pdb};\n{statements}\nexit\n")
        run = subprocess.run(["docker", "exec", "-i", self.container, "sqlplus", "-S", "/ as sysdba"],
                             input=script, text=True, capture_output=True, timeout=120)
        output = (run.stdout + run.stderr).replace(self.password, "<redacted>")
        require(run.returncode == 0, f"lab SQL failed: {output[-600:]}")
        return output

    def create(self):
        self.sql(f'''create user {self.user} identified by "{self.password}" quota 10m on users;
grant create session to {self.user};
grant execute on sys.dbms_lock to {self.user};
create table {self.user}.xr_64 (id number);
insert into {self.user}.xr_64 values (1);
create table {self.user}.xr_plain (id number);
insert into {self.user}.xr_plain values (1);
commit;
create function {self.user}.xr_fast_policy(s varchar2, t varchar2) return varchar2 as begin return '1=1'; end;
/
begin
for i in 1..64 loop
sys.dbms_rls.add_policy(object_schema=>'{self.user}',object_name=>'XR_64',policy_name=>'XR_P_'||i,function_schema=>'{self.user}',policy_function=>'XR_FAST_POLICY',statement_types=>'SELECT');
end loop;
end;
/''')

    def stall_policy_catalog(self):
        self.sql(f'''create function {self.user}.xr_slow_policy(s varchar2, t varchar2) return varchar2 as begin sys.dbms_lock.sleep(12); return '1=1'; end;
/
create view {self.user}.xr_policy_view as select p.* from sys.all_policies p;
begin
sys.dbms_rls.add_policy(object_schema=>'{self.user}',object_name=>'XR_POLICY_VIEW',policy_name=>'XR_SLOW_P',function_schema=>'{self.user}',policy_function=>'XR_SLOW_POLICY',statement_types=>'SELECT');
end;
/
create synonym {self.user}.all_policies for {self.user}.xr_policy_view;''')

    def drop(self):
        # A stalled catalog query can hold its session until the 12 s sleep ends.
        deadline = time.monotonic() + 90
        while True:
            try:
                self.sql(f"drop user {self.user} cascade;")
                return
            except AssertionError as error:
                if "ORA-01940" not in str(error) or time.monotonic() > deadline:
                    raise
                time.sleep(2)


class Server:
    def __init__(self, binary, lab, workdir, tag):
        config = workdir / f"{tag}.toml"
        config.write_text(f'''schema_version = 2
default_profile = "xrna0"
[[profiles]]
name = "xrna0"
connect_string = "{lab.dsn}"
username = "{lab.user}"
credential_ref = "env:XRNA0_PASSWORD"
protected = true
max_level = "READ_ONLY"
default_level = "READ_ONLY"
''')
        env = {name: value for name, value in os.environ.items() if not name.startswith("ORACLEMCP_")}
        env.update(ORACLEMCP_CONFIG=str(config), XRNA0_PASSWORD=lab.password,
                   XDG_STATE_HOME=str(workdir / f"{tag}-state"), ORACLEMCP_AUDIT_KEY=secrets.token_hex(32))
        self.password = lab.password
        self.process = subprocess.Popen([str(binary), "serve", "--profile", "xrna0", "--allow-no-auth"],
                                        env=env, text=True, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
        self.replies = queue.Queue()
        self.stderr = []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._errors, daemon=True).start()
        self.next_id = 1
        self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                    "clientInfo": {"name": "policy-observation-concurrency", "version": "1"}})
        self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self):
        for line in self.process.stdout:
            try:
                self.replies.put(json.loads(line))
            except json.JSONDecodeError:
                pass

    def _errors(self):
        for line in self.process.stderr:
            self.stderr.append(line.replace(self.password, "<redacted>").rstrip())

    def _write(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def send(self, method, params):
        request_id = self.next_id
        self.next_id += 1
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        return request_id

    def receive(self, request_id, seconds=40):
        deadline = time.monotonic() + seconds
        while True:
            message = self.replies.get(timeout=max(0.001, deadline - time.monotonic()))
            if message.get("id") == request_id:
                return message

    def request(self, method, params):
        return self.receive(self.send(method, params))

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=15)


def query_payload(reply):
    result = reply.get("result")
    require(isinstance(result, dict), f"oracle_query returned no result: {reply}")
    require(result.get("isError") is not True, f"oracle_query refused: {result}")
    content = result.get("structuredContent")
    if content is None:
        content = json.loads(next(item["text"] for item in result.get("content", [])
                                  if item.get("type") == "text"))
    require(content.get("rows") == [{"ID": "1"}], f"real row missing: {content}")
    return content


def check_observation(phase, content):
    rls = content.get("rls_vpd", {})
    if phase == "healthy":
        require(rls.get("all_policies_probe", {}).get("visibility") == "policy_rows_visible",
                f"healthy catalog was not observed: {rls}")
    else:
        require(rls.get("status") == "visibility_unavailable",
                f"stalled catalog must be reported unavailable: {rls}")
    return rls.get("status")


def run_phase(binary, lab, workdir, phase):
    server = Server(binary, lab, workdir, phase)
    try:
        for index in range(3):
            started = time.monotonic()
            reply = server.request("tools/call", {"name": "oracle_query", "arguments": {"sql": READ_SQL}})
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            status = check_observation(phase, query_payload(reply))
            emit(phase=phase, check="sequential_read", index=index, elapsed_ms=elapsed_ms,
                 rls_vpd_status=status)
            require(elapsed_ms < PROMPT_MS, f"{phase} read {index} took {elapsed_ms} ms")
        started = time.monotonic()
        pipelined = [server.send("tools/call", {"name": "oracle_query", "arguments": {"sql": READ_SQL}})
                     for _ in range(2)]
        statuses = [check_observation(phase, query_payload(server.receive(request_id)))
                    for request_id in pipelined]
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        emit(phase=phase, check="pipelined_reads", count=2, elapsed_ms=elapsed_ms, rls_vpd_status=statuses)
        require(elapsed_ms < 2 * PROMPT_MS, f"{phase} pipelined reads took {elapsed_ms} ms")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=pathlib.Path, required=True, help="oraclemcp server binary")
    parser.add_argument("--lane", choices=("free23", "xe21", "xe18"), default="free23")
    args = parser.parse_args()
    require(args.binary.is_file(), f"binary not found: {args.binary}")
    lab = Lab(args.lane)
    outcome = "fail"
    try:
        lab.create()
        time.sleep(DDL_SETTLE_SECONDS)
        with tempfile.TemporaryDirectory(prefix="xrna0-proof-") as workdir:
            run_phase(args.binary.resolve(), lab, pathlib.Path(workdir), "healthy")
            lab.stall_policy_catalog()
            time.sleep(DDL_SETTLE_SECONDS)
            run_phase(args.binary.resolve(), lab, pathlib.Path(workdir), "stalled")
        outcome = "pass"
    except Exception as error:  # report, then fail the run
        emit(check="error", error=str(error)[:600])
    finally:
        try:
            lab.drop()
        except Exception as error:
            emit(check="cleanup_error", user=lab.user, error=str(error)[:300])
            outcome = "fail"
    emit(case="policy_observation_concurrency", lane=args.lane, outcome=outcome)
    return 0 if outcome == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
