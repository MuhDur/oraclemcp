#!/usr/bin/env python3
"""Independent python-oracledb control actions for the tier-C OCI ADB lane.

This is the lane's control oracle, deliberately independent of oraclemcp and
its driver: a thin python-oracledb ADMIN connect over the downloaded wallet
proves the provisioned ADB, wallet and credentials are good even while
oraclemcp itself cannot yet connect (#54, T9.3). It never performs IAM token
auth; the IAM bootstrap and probe stay pure Rust behind the server boundary.

Usage (secrets only via environment, never argv):
  ADB_ADMIN_PASSWORD=... ADB_WALLET_PASSWORD=... \\
    oci_adb_control.py CONNECT_STRING_FILE WALLET_DIR control
  ... RUN_SCHEMA_PASSWORD=... oci_adb_control.py FILE DIR open-schema OMCP_RUN_X
  ... oci_adb_control.py FILE DIR close-schema OMCP_RUN_X
"""

import os
import re
import sys

import oracledb

SCHEMA = re.compile(r"OMCP_RUN_[A-Z0-9_]{1,100}")
PASSWORD = re.compile(r"[A-Za-z][A-Za-z0-9_#]{11,29}")


def main() -> None:
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    dsn_file, wallet, action = sys.argv[1:4]
    with open(dsn_file, encoding="utf-8") as handle:
        dsn = handle.read()
    conn = oracledb.connect(
        user="ADMIN",
        password=os.environ["ADB_ADMIN_PASSWORD"],
        dsn=dsn,
        config_dir=wallet,
        wallet_location=wallet,
        wallet_password=os.environ["ADB_WALLET_PASSWORD"],
        tcp_connect_timeout=60,
    )
    try:
        with conn.cursor() as cur:
            if action == "control":
                cur.execute("select 1 from dual")
                if cur.fetchone()[0] != 1:
                    raise SystemExit("control query returned an unexpected value")
                cur.execute("select version_full from v$instance")
                print(cur.fetchone()[0])
                return
            if len(sys.argv) != 5 or not SCHEMA.fullmatch(sys.argv[4]):
                raise SystemExit("open/close-schema need one OMCP_RUN_* schema name")
            user = sys.argv[4]
            if action == "open-schema":
                password = os.environ["RUN_SCHEMA_PASSWORD"]
                if not PASSWORD.fullmatch(password):
                    raise SystemExit("unsafe run schema password")
                cur.execute(f'create user {user} identified by "{password}"')
                cur.execute(
                    "grant create session, create table, create view, create sequence, "
                    f"create procedure, create synonym to {user}"
                )
                cur.execute(f"alter user {user} quota 100M on data")
            elif action == "close-schema":
                cur.execute(f"drop user {user} cascade")
            else:
                raise SystemExit(f"unknown action {action}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
