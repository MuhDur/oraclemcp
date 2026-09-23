#!/usr/bin/env python3
"""Run-owned W4 Oracle lab fixture. Requires python-oracledb 4.0.2 for live commands.

Only explicitly marked, loopback lab lanes in rig.toml are eligible. The
registry and a random token inside each created schema bind teardown to the
exact run. No schema is selected for deletion by a name prefix.
"""

import argparse
import datetime as dt
import json
import os
import re
import secrets
import subprocess
import sys
import time
import tomllib
from pathlib import Path


HERE = Path(__file__).resolve().parent
CONFIG = HERE / "rig.toml"
SQL_DIR = HERE / "fixture"
REGISTRY = "W4_RIG.W4_RUNS"
RUN_ID = re.compile(r"W4[0-9]{4}[A-F0-9]{6}\Z")
IDENTIFIER = re.compile(r"[A-Z][A-Z0-9_]{0,29}\Z")
STMT_MARKER = "-- @statement"
OWNER_FILES = ("01_tables.sql", "02_objects.sql", "03_package.sql")
CROSS_FILES = ("05_cross.sql",)
ADMIN_FILES = ("04_policy.sql",)
OWNER_OBJECTS = (
    ("TABLE", "T_RUN_"), ("TABLE", "T_TYPES_"),
    ("TABLE", "T_PARENT_"), ("TABLE", "T_CHILD_"),
    ("TABLE", "T_CHILD_AUD_"), ("TABLE", "T_SECURE_"),
    ("TABLE", "T_AUTO_"), ("VIEW", "V_TYPES_"),
    ("INDEX", "IX_TYPES_"), ("SEQUENCE", "SEQ_W4_"),
    ("TRIGGER", "TRG_CHILD_AUDIT_"), ("TYPE", "TY_POINT_"),
    ("TYPE BODY", "TY_POINT_"), ("PACKAGE", "PKG_W4_"),
    ("PACKAGE BODY", "PKG_W4_"),
)
CROSS_OBJECTS = (("TABLE", "T_RUN_"), ("TABLE", "T_CROSS_"))


class FixtureError(RuntimeError):
    pass


def refuse(message):
    raise FixtureError(message)


def run_id_or_refuse(value):
    if not isinstance(value, str) or RUN_ID.fullmatch(value) is None:
        refuse("run id must be W4 + four UTC HHMM digits + six uppercase hex digits")
    return value


def new_run_id():
    return "W4" + dt.datetime.now(dt.timezone.utc).strftime("%H%M") + secrets.token_hex(3).upper()


def owner_name(run_id):
    return "W4O_" + run_id_or_refuse(run_id)


def cross_name(run_id):
    return "W4X_" + run_id_or_refuse(run_id)


def exact_identifier(value):
    if IDENTIFIER.fullmatch(value) is None:
        refuse(f"invalid Oracle identifier: {value!r}")
    return value


def load_lane(config_path, lane):
    settings = tomllib.loads(config_path.read_text())["lanes"].get(lane)
    if not isinstance(settings, dict) or settings.get("lab") is not True:
        refuse(f"lane {lane!r} lacks lab = true in rig config")
    dsn = settings.get("dsn", "")
    if re.fullmatch(r"(?:localhost|127\.0\.0\.1):(?:1518|1520|1522)/(?:XEPDB1|FREEPDB1)", dsn, re.I) is None:
        refuse("W4 DDL requires a known loopback XE/FREE lab DSN")
    expected = {"xe18": "1518/XEPDB1", "xe21": "1520/XEPDB1", "free23": "1522/FREEPDB1"}
    if lane not in expected or not dsn.upper().endswith(expected[lane]):
        refuse(f"lane {lane!r} has the wrong lab port/service")
    return settings


def admin_password(lane, settings):
    upper = lane.upper()
    value = (os.environ.get(f"ORACLEMCP_RIG_L1_{upper}_ADMIN_PASSWORD")
             or os.environ.get("ORACLEMCP_RIG_L1_ADMIN_PASSWORD"))
    if value:
        return value
    container = settings.get("container")
    if not isinstance(container, str):
        refuse("rig config has no lab container for credential lookup")
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        refuse(f"no admin credential for lane {lane}; set its rig environment variable")
    for entry in result.stdout.splitlines():
        if entry.startswith("ORACLE_PASSWORD="):
            return entry.split("=", 1)[1]
    refuse(f"lab container for {lane} has no ORACLE_PASSWORD metadata")


def connect_admin(lane, settings):
    try:
        import oracledb
    except ImportError as exc:
        raise FixtureError("install pinned python-oracledb 4.0.2 for live W4 fixture commands") from exc
    if oracledb.__version__ != "4.0.2":
        refuse(f"python-oracledb 4.0.2 required; got {oracledb.__version__}")
    connection = oracledb.connect(user="system", password=admin_password(lane, settings),
                                  dsn=settings["dsn"], tcp_connect_timeout=8)
    connection.call_timeout = 30000
    version = int(connection.cursor().execute("SELECT VERSION FROM V$INSTANCE").fetchone()[0].split(".", 1)[0])
    if version != {"xe18": 18, "xe21": 21, "free23": 23}[lane]:
        connection.close()
        refuse(f"lane {lane} database version mismatch: observed {version}")
    return connection, version


def render_sql(filename, run_id, version):
    run_id_or_refuse(run_id)
    text = (SQL_DIR / filename).read_text()
    if not text.startswith(STMT_MARKER):
        refuse(f"{filename}: missing initial statement marker")
    json_check = "" if version >= 23 else f"CONSTRAINT CK_J_{run_id} CHECK (J_VAL IS JSON)"
    substitutions = {
        "&run_id": run_id,
        "&json_type": "JSON" if version >= 23 else "CLOB",
        "&json_check": json_check,
        "&vector_column": ", VEC_VAL VECTOR(3, FLOAT32)" if version >= 23 else "",
    }
    for key, value in substitutions.items():
        text = text.replace(key, value)
    if re.search(r"&[a-z_]+", text, re.I):
        refuse(f"{filename}: unresolved substitution")
    statements = [part.strip() for part in text.split(STMT_MARKER) if part.strip()]
    if not statements:
        refuse(f"{filename}: no statements")
    return statements


def event(run_id, obj, action, ok, started, detail=None):
    record = {"run_id": run_id, "object": obj, "action": action, "ok": ok,
              "ms": round((time.monotonic() - started) * 1000)}
    if detail:
        record["detail"] = detail
    print(json.dumps(record, sort_keys=True), flush=True)


def sql_object(statement):
    match = re.match(r"CREATE (?:OR REPLACE )?(TABLE|VIEW|INDEX|SEQUENCE|TRIGGER|TYPE(?: BODY)?|PACKAGE(?: BODY)?)\s+([A-Z0-9_]+)", statement, re.I)
    if match:
        return match.group(2).upper()
    if statement.startswith("GRANT SELECT"):
        return statement.split()[3]
    if "DBMS_RLS.ADD_POLICY" in statement:
        return "P_SECURE"
    return "statement"


def execute_sql_file(connection, filename, run_id, version):
    cursor = connection.cursor()
    for statement in render_sql(filename, run_id, version):
        obj = sql_object(statement)
        started = time.monotonic()
        try:
            cursor.execute(statement)
        except Exception as exc:
            event(run_id, obj, "create", False, started, type(exc).__name__)
            raise
        event(run_id, obj, "create", True, started)
    connection.commit()


def registry_exists(connection):
    cursor = connection.cursor()
    users = cursor.execute("SELECT COUNT(*) FROM DBA_USERS WHERE USERNAME = 'W4_RIG'").fetchone()[0]
    if not users:
        return False
    meta = cursor.execute("SELECT COUNT(*) FROM DBA_TABLES WHERE OWNER = 'W4_RIG' AND TABLE_NAME = 'W4_META'").fetchone()[0]
    if not meta:
        refuse("W4_RIG exists without the W4_META ownership marker")
    marker = cursor.execute("SELECT CONTROL_ID FROM W4_RIG.W4_META").fetchall()
    if marker != [("ORACLEMCP_W4_RIG_V1",)]:
        refuse("W4_RIG ownership marker mismatch")
    return True


def ensure_registry(connection):
    if registry_exists(connection):
        return
    password = secrets.token_hex(15)
    cursor = connection.cursor()
    cursor.execute(f'CREATE USER W4_RIG IDENTIFIED BY "{password}"')
    cursor.execute("GRANT CREATE SESSION, CREATE TABLE, UNLIMITED TABLESPACE TO W4_RIG")
    cursor.execute("CREATE TABLE W4_RIG.W4_META (CONTROL_ID VARCHAR2(40) PRIMARY KEY)")
    cursor.execute("INSERT INTO W4_RIG.W4_META VALUES ('ORACLEMCP_W4_RIG_V1')")
    cursor.execute("""CREATE TABLE W4_RIG.W4_RUNS (
        RUN_ID VARCHAR2(12) PRIMARY KEY,
        TOKEN VARCHAR2(32) NOT NULL,
        OWNER_NAME VARCHAR2(30) NOT NULL,
        CROSS_NAME VARCHAR2(30) NOT NULL,
        STARTED_AT TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
        FINISHED_AT TIMESTAMP WITH TIME ZONE,
        VERDICT VARCHAR2(32) NOT NULL,
        OBJECTS_JSON CLOB NOT NULL
    )""")
    connection.commit()


def require_registry(connection):
    if not registry_exists(connection):
        refuse("W4 run registry is absent; setup must create it first")
    count = connection.cursor().execute(
        "SELECT COUNT(*) FROM DBA_TABLES WHERE OWNER='W4_RIG' AND TABLE_NAME='W4_RUNS'").fetchone()[0]
    if count != 1:
        refuse("W4_RIG ownership marker exists without W4_RUNS")


def register_run(connection, run_id, token):
    owner, cross = owner_name(run_id), cross_name(run_id)
    inventory = {"owner": owner, "cross": cross,
                 "objects": [{"owner": owner, "type": kind, "name": prefix + run_id} for kind, prefix in OWNER_OBJECTS]
                            + [{"owner": cross, "type": kind, "name": prefix + run_id} for kind, prefix in CROSS_OBJECTS],
                 "policy": "P_SECURE_" + run_id,
                 "masking_column": "SECRET_TEXT"}
    connection.cursor().execute(
        f"INSERT INTO {REGISTRY}(RUN_ID,TOKEN,OWNER_NAME,CROSS_NAME,VERDICT,OBJECTS_JSON) VALUES (:1,:2,:3,:4,'SETTING_UP',:5)",
        (run_id, token, owner, cross, json.dumps(inventory, sort_keys=True)))
    connection.commit()
    return inventory


def create_fixture_user(admin, name):
    exact_identifier(name)
    password = secrets.token_hex(15)
    cursor = admin.cursor()
    cursor.execute(f'CREATE USER {name} IDENTIFIED BY "{password}"')
    cursor.execute(f"GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE, CREATE PROCEDURE, CREATE TRIGGER, CREATE TYPE, UNLIMITED TABLESPACE TO {name}")
    return password


def create_sentinel(connection, run_id, token):
    table = "T_RUN_" + run_id
    started = time.monotonic()
    cursor = connection.cursor()
    cursor.execute(f"CREATE TABLE {table} (RUN_ID VARCHAR2(12) PRIMARY KEY, TOKEN VARCHAR2(32) NOT NULL)")
    cursor.execute(f"INSERT INTO {table}(RUN_ID,TOKEN) VALUES (:1,:2)", (run_id, token))
    connection.commit()
    event(run_id, table, "create", True, started)


def seed_fixture(owner, cross, run_id, version):
    o = owner.cursor()
    table = "T_TYPES_" + run_id
    values = ("0", "-0", "1E-130", "9.9999999999999999999999999999999999999E125",
              "99999999999999999999999999999999999999", None)
    for index, value in enumerate(values, 1):
        o.execute(f"INSERT INTO {table}(ID,N_VAL) VALUES (:1,TO_NUMBER(:2))", (index, value))
    o.execute(f"""UPDATE {table} SET
        V_TEXT='fixture', NV_TEXT=:1, D_VAL=DATE '1900-01-01',
        TS_VAL=TO_TIMESTAMP('9999-12-31 23:59:59.123456','YYYY-MM-DD HH24:MI:SS.FF6'),
        TSTZ_VAL=TO_TIMESTAMP_TZ('2020-02-29 23:30:00 +05:45','YYYY-MM-DD HH24:MI:SS TZH:TZM'),
        TSLTZ_VAL=TO_TIMESTAMP('2020-02-29 23:30:00','YYYY-MM-DD HH24:MI:SS'),
        IYM_VAL=INTERVAL '2-3' YEAR TO MONTH,
        IDS_VAL=INTERVAL '3 04:05:06.123456' DAY TO SECOND,
        R_VAL=HEXTORAW('007FFF'), HIDDEN_VAL='hidden'
        WHERE ID=1""", ("نص仮",))
    import oracledb
    o.setinputsizes(c_val=oracledb.DB_TYPE_CLOB, nc_val=oracledb.DB_TYPE_NCLOB,
                    b_val=oracledb.DB_TYPE_BLOB)
    o.execute(f"UPDATE {table} SET C_VAL=:c_val, NC_VAL=:nc_val, B_VAL=:b_val WHERE ID=1",
              {"c_val": "c" * 33000, "nc_val": "ن" * 33000, "b_val": b"b" * 33000})
    if version >= 23:
        o.execute(f"UPDATE {table} SET J_VAL=JSON_OBJECT('kind' VALUE 'fixture' RETURNING JSON), VEC_VAL='[1,0,0]' WHERE ID=1")
    else:
        o.execute(f"UPDATE {table} SET J_VAL='{{\"kind\":\"fixture\"}}' WHERE ID=1")
    for parent_id in (1, 2):
        o.execute(f"INSERT INTO T_PARENT_{run_id}(ID,LABEL) VALUES (:1,:2)", (parent_id, f"parent-{parent_id}"))
    o.execute(f"INSERT INTO T_CHILD_{run_id}(ID,PARENT_ID) VALUES (1,1)")
    o.execute(f"INSERT INTO T_SECURE_{run_id}(ID,SECRET_TEXT) VALUES (1,:1)", (f"W4_MASK_CANARY_{run_id}",))
    cross.cursor().execute(f"INSERT INTO T_CROSS_{run_id}(ID,LABEL) VALUES (1,'cross-owner')")
    for table_name in ("T_TYPES_", "T_PARENT_", "T_CHILD_", "T_SECURE_"):
        o.execute(f"COMMENT ON TABLE {table_name}{run_id} IS 'W4 run {run_id}'")
    cross.cursor().execute(f"COMMENT ON TABLE T_CROSS_{run_id} IS 'W4 run {run_id}'")
    owner.commit()
    cross.commit()


def recorded_run(connection, run_id):
    row = connection.cursor().execute(
        f"SELECT TOKEN,OWNER_NAME,CROSS_NAME,VERDICT,OBJECTS_JSON FROM {REGISTRY} WHERE RUN_ID=:1",
        (run_id,)).fetchone()
    if row is None:
        refuse(f"no W4_RUNS row for exact run id {run_id}")
    token, owner, cross, verdict, inventory = row
    if owner != owner_name(run_id) or cross != cross_name(run_id):
        refuse(f"{run_id}: registry schema names disagree with exact run id")
    return {"run_id": run_id, "token": token, "owner": owner, "cross": cross,
            "verdict": verdict, "inventory": json.loads(inventory.read() if hasattr(inventory, "read") else inventory)}


def user_exists(connection, username):
    return connection.cursor().execute(
        "SELECT COUNT(*) FROM DBA_USERS WHERE USERNAME=:1", (exact_identifier(username),)).fetchone()[0] == 1


def verify_sentinel(connection, run):
    for username in (run["owner"], run["cross"]):
        if not user_exists(connection, username):
            continue
        table = "T_RUN_" + run["run_id"]
        exact_identifier(table)
        try:
            values = connection.cursor().execute(
                f"SELECT TOKEN FROM {username}.{table} WHERE RUN_ID=:1", (run["run_id"],)).fetchall()
        except Exception as exc:
            raise FixtureError(f"{username}: ownership sentinel unreadable; refusing DROP") from exc
        if values != [(run["token"],)]:
            refuse(f"{username}: ownership sentinel mismatch; refusing DROP")


def inventory_status(connection, run, version):
    cursor = connection.cursor()
    actual = set(cursor.execute(
        "SELECT OWNER,OBJECT_TYPE,OBJECT_NAME FROM DBA_OBJECTS WHERE OWNER IN (:1,:2)",
        (run["owner"], run["cross"])).fetchall())
    expected = {(item["owner"], item["type"], item["name"])
                for item in run["inventory"]["objects"]}
    missing = sorted(expected - actual)
    columns = {name: kind for name, kind in cursor.execute(
        "SELECT COLUMN_NAME,DATA_TYPE FROM DBA_TAB_COLUMNS WHERE OWNER=:1 AND TABLE_NAME=:2",
        (run["owner"], "T_TYPES_" + run["run_id"])).fetchall()}
    if columns.get("J_VAL") != ("JSON" if version >= 23 else "CLOB"):
        missing.append((run["owner"], "COLUMN", "J_VAL expected JSON/CLOB"))
    if ("VEC_VAL" in columns) != (version >= 23):
        missing.append((run["owner"], "COLUMN", "VEC_VAL version guard"))
    policy = "P_SECURE_" + run["run_id"]
    count = cursor.execute(
        "SELECT COUNT(*) FROM DBA_POLICIES WHERE OBJECT_OWNER=:1 AND OBJECT_NAME=:2 AND POLICY_NAME=:3",
        (run["owner"], "T_SECURE_" + run["run_id"], policy)).fetchone()[0]
    if count != 1:
        missing.append((run["owner"], "POLICY", policy))
    invalid = cursor.execute(
        "SELECT OBJECT_TYPE,OBJECT_NAME FROM DBA_OBJECTS WHERE OWNER IN (:1,:2) AND STATUS <> 'VALID'",
        (run["owner"], run["cross"])).fetchall()
    for kind, name in invalid:
        missing.append((run["owner"], "INVALID " + kind, name))
    table = run["owner"] + ".T_TYPES_" + run["run_id"]
    types = cursor.execute(
        f"SELECT COUNT(*),MIN(DBMS_LOB.GETLENGTH(C_VAL)),MIN(DBMS_LOB.GETLENGTH(NC_VAL)),"
        f"MIN(DBMS_LOB.GETLENGTH(B_VAL)),MIN(JSON_VALUE(J_VAL,'$.kind')) FROM {table}").fetchone()
    if types[0] != 6 or types[1:4] != (33000, 33000, 33000) or types[4] != "fixture":
        missing.append((run["owner"], "DATA", "type and LOB seed"))
    trigger_rows = cursor.execute(
        f"SELECT COUNT(*) FROM {run['owner']}.T_CHILD_AUD_{run['run_id']}").fetchone()[0]
    if trigger_rows != 1:
        missing.append((run["owner"], "DATA", "trigger audit row"))
    grant = cursor.execute(
        "SELECT COUNT(*) FROM DBA_TAB_PRIVS WHERE OWNER=:1 AND TABLE_NAME=:2 AND GRANTEE=:3 AND PRIVILEGE='SELECT'",
        (run["cross"], "T_CROSS_" + run["run_id"], run["owner"])).fetchone()[0]
    if grant != 1:
        missing.append((run["cross"], "GRANT", "cross-owner SELECT"))
    return {"expected": len(expected) + 1, "present": len(expected & actual) + count,
            "missing": missing, "objects": sorted(expected & actual)}


def setup(lane, settings, requested_id=None):
    run_id = run_id_or_refuse(requested_id or new_run_id())
    admin, version = connect_admin(lane, settings)
    owner = cross = None
    registered = False
    try:
        ensure_registry(admin)
        token = secrets.token_hex(16).upper()
        register_run(admin, run_id, token)
        registered = True
        owner_password = create_fixture_user(admin, owner_name(run_id))
        cross_password = create_fixture_user(admin, cross_name(run_id))
        import oracledb
        owner = oracledb.connect(user=owner_name(run_id), password=owner_password, dsn=settings["dsn"])
        cross = oracledb.connect(user=cross_name(run_id), password=cross_password, dsn=settings["dsn"])
        owner.call_timeout = cross.call_timeout = 30000
        create_sentinel(owner, run_id, token)
        create_sentinel(cross, run_id, token)
        for filename in OWNER_FILES:
            execute_sql_file(owner, filename, run_id, version)
        for filename in CROSS_FILES:
            execute_sql_file(cross, filename, run_id, version)
        for filename in ADMIN_FILES:
            execute_sql_file(admin, filename, run_id, version)
        seed_fixture(owner, cross, run_id, version)
        run = recorded_run(admin, run_id)
        inventory = inventory_status(admin, run, version)
        if inventory["missing"]:
            refuse(f"{run_id}: fixture inventory incomplete: {inventory['missing']}")
        admin.cursor().execute(f"UPDATE {REGISTRY} SET VERDICT='ACTIVE' WHERE RUN_ID=:1", (run_id,))
        admin.commit()
        print(json.dumps({"run_id": run_id, "lane": lane, "status": "ACTIVE", "inventory": inventory}, sort_keys=True))
        return run_id
    except Exception:
        if registered:
            admin.cursor().execute(f"UPDATE {REGISTRY} SET VERDICT='SETUP_FAILED' WHERE RUN_ID=:1", (run_id,))
            admin.commit()
        raise
    finally:
        if owner is not None:
            owner.close()
        if cross is not None:
            cross.close()
        admin.close()


def exact_drop_sql(username, run_id):
    run_id_or_refuse(run_id)
    if username not in {owner_name(run_id), cross_name(run_id)}:
        refuse("DROP USER target is not an exact schema name for this run")
    return f"DROP USER {exact_identifier(username)} CASCADE"


def drop_policy_if_present(connection, run):
    owner = run["owner"]
    table = "T_SECURE_" + run["run_id"]
    policy = "P_SECURE_" + run["run_id"]
    found = connection.cursor().execute(
        "SELECT COUNT(*) FROM DBA_POLICIES WHERE OBJECT_OWNER=:1 AND OBJECT_NAME=:2 AND POLICY_NAME=:3",
        (owner, table, policy)).fetchone()[0]
    if found:
        started = time.monotonic()
        connection.cursor().execute("BEGIN DBMS_RLS.DROP_POLICY(:1,:2,:3); END;", (owner, table, policy))
        event(run["run_id"], policy, "drop_policy", True, started)


def verdict_path(lane, run_id):
    path = Path("target/e2e/w4") / lane / run_id
    path.mkdir(parents=True, exist_ok=True)
    return path / "teardown.json"


def teardown_one(connection, lane, run_id):
    run = recorded_run(connection, run_id_or_refuse(run_id))
    dropped, dropped_objects, errors = [], [], []
    try:
        # Verify both identities before any destructive statement. A name
        # alone is never proof that a schema still belongs to this run.
        verify_sentinel(connection, run)
        drop_policy_if_present(connection, run)
        for username in (run["owner"], run["cross"]):
            if not user_exists(connection, username):
                continue
            objects = connection.cursor().execute(
                "SELECT OBJECT_TYPE,OBJECT_NAME FROM DBA_OBJECTS WHERE OWNER=:1",
                (username,)).fetchall()
            started = time.monotonic()
            connection.cursor().execute(exact_drop_sql(username, run_id))
            dropped.append(username)
            dropped_objects.extend({"owner": username, "type": kind, "name": name}
                                   for kind, name in objects)
            event(run_id, username, "drop_user", True, started)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        event(run_id, "teardown", "refuse_or_fail", False, time.monotonic(), type(exc).__name__)
    leftovers = [name for name in (run["owner"], run["cross"]) if user_exists(connection, name)]
    verdict = "PASS" if not errors and not leftovers else "FAIL"
    connection.cursor().execute(
        f"UPDATE {REGISTRY} SET FINISHED_AT=SYSTIMESTAMP, VERDICT=:1 WHERE RUN_ID=:2", (verdict, run_id))
    connection.commit()
    report = {"run_id": run_id, "lane": lane, "verdict": verdict,
              "dropped": dropped, "dropped_objects": dropped_objects,
              "leftovers": leftovers, "errors": errors}
    verdict_path(lane, run_id).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"run_id": run_id, "lane": lane, "verdict": verdict,
                      "dropped": dropped, "dropped_object_count": len(dropped_objects),
                      "leftovers": leftovers, "errors": errors}, sort_keys=True))
    if verdict != "PASS":
        refuse(f"{run_id}: teardown failed; see exact-run verdict JSON")
    return report


def teardown(lane, settings, run_id):
    connection, _ = connect_admin(lane, settings)
    try:
        require_registry(connection)
        return teardown_one(connection, lane, run_id)
    finally:
        connection.close()


def unregistered_owners(connection):
    registered = {row[0] for row in connection.cursor().execute(f"SELECT OWNER_NAME FROM {REGISTRY}")}
    # Prefix matching is read-only discovery. It is never used as a DROP target.
    found = {row[0] for row in connection.cursor().execute(
        "SELECT USERNAME FROM DBA_USERS WHERE USERNAME LIKE 'W4O\\_%' ESCAPE '\\'")}
    return sorted(found - registered)


def janitor_one_connection(connection, lane, hours):
    if not (0 < hours <= 24 * 365):
        refuse("--older-than must be in (0, 8760] hours")
    require_registry(connection)
    rows = connection.cursor().execute(
        f"SELECT RUN_ID FROM {REGISTRY} WHERE FINISHED_AT IS NOT NULL "
        "OR STARTED_AT < SYSTIMESTAMP - NUMTODSINTERVAL(:1,'HOUR') ORDER BY STARTED_AT",
        (hours,)).fetchall()
    removed, already_clean, failed = [], [], []
    for (run_id,) in rows:
        try:
            run = recorded_run(connection, run_id)
            if not any(user_exists(connection, name) for name in (run["owner"], run["cross"])):
                already_clean.append(run_id)
                continue
            teardown_one(connection, lane, run_id)
            removed.append(run_id)
        except FixtureError as exc:
            failed.append({"run_id": run_id, "class": type(exc).__name__})
    unregistered = unregistered_owners(connection)
    result = {"lane": lane, "removed_runs": removed, "already_clean_runs": already_clean,
              "failed_runs": failed,
              "unregistered_users_reported_not_dropped": unregistered}
    print(json.dumps(result, sort_keys=True))
    return result


def janitor(lane, settings, hours):
    connection, _ = connect_admin(lane, settings)
    try:
        return janitor_one_connection(connection, lane, hours)
    finally:
        connection.close()


def describe(lane, settings, run_id):
    connection, version = connect_admin(lane, settings)
    try:
        require_registry(connection)
        run = recorded_run(connection, run_id_or_refuse(run_id))
        status = inventory_status(connection, run, version)
        result = {"run_id": run_id, "lane": lane, "verdict": run["verdict"],
                  "inventory": status, "fixture": run["inventory"]}
        print(json.dumps(result, sort_keys=True))
        if status["missing"]:
            refuse(f"{run_id}: describe found missing fixture objects")
        return result
    finally:
        connection.close()


def lint_drop_path(statement, run_id):
    allowed = {exact_drop_sql(owner_name(run_id), run_id),
               exact_drop_sql(cross_name(run_id), run_id)}
    if statement not in allowed:
        refuse("DROP path is not an exact registered run schema")


def selftest():
    run_id = "W41234ABCDEF"
    assert len(run_id) == 12
    assert owner_name(run_id) == "W4O_W41234ABCDEF"
    for version in (18, 21, 23):
        created = set()
        for filename in OWNER_FILES + CROSS_FILES + ADMIN_FILES:
            statements = render_sql(filename, run_id, version)
            for statement in statements:
                obj = sql_object(statement)
                if obj not in {"statement", "P_SECURE"}:
                    exact_identifier(obj)
                    created.add(obj)
                if "DROP USER" in statement.upper() or "LIKE 'W4" in statement.upper():
                    refuse(f"{filename}: destructive prefix path in fixture SQL")
        expected = {prefix + run_id for _, prefix in OWNER_OBJECTS + CROSS_OBJECTS}
        expected.discard("T_RUN_" + run_id)  # created first by fixture.py
        if not expected.issubset(created):
            refuse(f"version {version}: missing rendered DDL for {sorted(expected - created)}")
        types = "\n".join(render_sql("01_tables.sql", run_id, version))
        if version == 23:
            if "J_VAL JSON" not in types or "VEC_VAL VECTOR(3, FLOAT32)" not in types:
                refuse("23ai JSON/VECTOR guard failed")
        elif "J_VAL CLOB CONSTRAINT" not in types or "VEC_VAL" in types:
            refuse(f"XE {version} JSON/VECTOR guard failed")
        print(json.dumps({"version": version, "case": "render_version_guards", "verdict": "pass"}))
    for name in (owner_name(run_id), cross_name(run_id)):
        lint_drop_path(exact_drop_sql(name, run_id), run_id)
    for planted in ("DROP USER W4O_% CASCADE", "DROP USER W4O_W41234ABCDEF CASCADE WHERE NAME LIKE 'W4%'",
                    "DROP USER W4O_OTHER CASCADE"):
        try:
            lint_drop_path(planted, run_id)
        except FixtureError:
            print(json.dumps({"case": "prefix_or_foreign_drop", "verdict": "rejected"}))
        else:
            refuse("selftest accepted a prefix/foreign DROP path")
    try:
        load_lane(CONFIG, "production")
    except FixtureError:
        print(json.dumps({"case": "non_lab_lane", "verdict": "rejected"}))
    else:
        refuse("selftest accepted a non-lab lane")
    print("selftest: pass")


def selftest_live(lane, settings):
    first = second = stale = None
    admin = None
    planted_created = False
    try:
        first = setup(lane, settings)
        second = setup(lane, settings)
        stale = setup(lane, settings)
        planted = "W4O_" + new_run_id()
        admin, _ = connect_admin(lane, settings)
        if first == second or not user_exists(admin, owner_name(first)) or not user_exists(admin, owner_name(second)):
            refuse("two active runs are not isolated")
        # This deliberately unregistered user is created by this invocation.
        # The janitor must report it and leave it present.
        create_fixture_user(admin, planted)
        planted_created = True
        admin.cursor().execute(
            f"UPDATE {REGISTRY} SET STARTED_AT=SYSTIMESTAMP-NUMTODSINTERVAL(2,'HOUR') WHERE RUN_ID=:1",
            (stale,))
        admin.commit()
        result = janitor_one_connection(admin, lane, 1)
        if result["removed_runs"] != [stale] or user_exists(admin, owner_name(stale)):
            refuse("janitor failed to remove only the registered stale run")
        if planted not in result["unregistered_users_reported_not_dropped"] or not user_exists(admin, planted):
            refuse("janitor touched or failed to report unregistered user")
        if not user_exists(admin, owner_name(first)) or not user_exists(admin, owner_name(second)):
            refuse("janitor touched a live run")
        teardown_one(admin, lane, first)
        if not user_exists(admin, owner_name(second)) or not user_exists(admin, cross_name(second)):
            refuse("first run teardown touched the second live run")
        print(json.dumps({"case": "overlapping_runs_stale_janitor_and_unregistered_user", "lane": lane,
                          "run_ids": [first, second, stale], "verdict": "pass"}, sort_keys=True))
    finally:
        if admin is None and first is not None:
            admin, _ = connect_admin(lane, settings)
        if admin is not None:
            if planted_created and user_exists(admin, planted):
                # Test cleanup is an exact name created in this function.
                # Janitor never reaches this path or selects by prefix.
                admin.cursor().execute(exact_drop_sql(planted, planted.removeprefix("W4O_")))
            if first is not None and (user_exists(admin, owner_name(first)) or user_exists(admin, cross_name(first))):
                teardown_one(admin, lane, first)
            if second is not None and (user_exists(admin, owner_name(second)) or user_exists(admin, cross_name(second))):
                teardown_one(admin, lane, second)
            if stale is not None and (user_exists(admin, owner_name(stale)) or user_exists(admin, cross_name(stale))):
                teardown_one(admin, lane, stale)
            admin.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="render and safety checks; no database access")
    sub = parser.add_subparsers(dest="command")
    for name in ("setup", "teardown", "janitor", "describe", "selftest-live"):
        command = sub.add_parser(name)
        command.add_argument("--lane", choices=("xe18", "xe21", "free23"), required=True)
        command.add_argument("--config", type=Path, default=CONFIG)
        if name in {"teardown", "describe"}:
            command.add_argument("--run-id", required=True)
        elif name == "setup":
            command.add_argument("--run-id")
        elif name == "janitor":
            command.add_argument("--older-than", type=float, required=True, metavar="HOURS")
    args = parser.parse_args()
    try:
        if args.selftest:
            if args.command:
                parser.error("--selftest takes no live command")
            selftest()
            return 0
        if not args.command:
            parser.error("choose a command or --selftest")
        settings = load_lane(args.config, args.lane)
        if args.command == "setup":
            setup(args.lane, settings, args.run_id)
        elif args.command == "teardown":
            teardown(args.lane, settings, args.run_id)
        elif args.command == "janitor":
            janitor(args.lane, settings, args.older_than)
        elif args.command == "describe":
            describe(args.lane, settings, args.run_id)
        elif args.command == "selftest-live":
            selftest_live(args.lane, settings)
    except FixtureError as exc:
        print(f"fixture: FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        code = re.search(r"(?:ORA|DPY)-\d+", str(exc))
        print(f"fixture: FAIL: {type(exc).__name__} {code.group(0) if code else 'unknown database error'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
