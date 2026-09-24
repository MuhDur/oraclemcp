#!/usr/bin/env python3
"""Re-run the external doctor connect-phase case for release issue #56.

The binary is supplied by the verifier (built or installed from the candidate
SHA). Password/token canaries stay in child-process environment variables;
generated TOML contains references only. One JSONL verdict is printed for
each wrong-password, closed-TCP-port, and invalid-wallet-path case.

Example:
  python3 scripts/e2e/doctor_online_connect_phase.py \
    --binary target/release/oraclemcp --lane free23
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANES = {
    "xe18": (1518, "XEPDB1"),
    "xe21": (1520, "XEPDB1"),
    "free23": (1523, "FREEPDB1"),
}
PASSWORD_CANARY = "doctor_i56_password_canary"
TOKEN_CANARY = "doctor_i56_token_canary"
OCID_CANARY = "ocid1.doctorcanary.synthetic"
DSN_CANARY = "doctor_i56_dsn_canary"
CASE_ID = "rel012_i56_connect_phase"


def closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def write_profile(path: Path, connect_string: str, wallet_location: str | None) -> None:
    wallet = ""
    if wallet_location is not None:
        wallet = (
            "\n[profiles.oci]\n"
            f'wallet_location = "{wallet_location}"\n'
            'wallet_password_ref = "env:LAB_DOCTOR_TOKEN_CANARY"\n'
        )
    path.write_text(
        "schema_version = 2\n\n"
        "[[profiles]]\n"
        'name = "doctor_i56"\n'
        f'connect_string = "{connect_string}"\n'
        'username = "pythontest"\n'
        'credential_ref = "env:LAB_DOCTOR_PASSWORD_CANARY"\n'
        f"{wallet}",
        encoding="utf-8",
    )


def actual_phase(stdout: str) -> str | None:
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    for check in report.get("checks", []):
        if check.get("name") == "Connectivity":
            detail = check.get("detail", "")
            marker = "[connect_phase="
            if marker in detail:
                return detail.split(marker, 1)[1].split("]", 1)[0]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="candidate or installed oraclemcp binary")
    parser.add_argument("--lane", required=True, choices=sorted(LANES))
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must name an executable oraclemcp binary")

    lane_port, service = LANES[args.lane]
    work = ROOT / "target" / "e2e" / "doctor-online-connect-phase" / secrets.token_hex(8)
    work.mkdir(parents=True, exist_ok=False)
    wallet_path = str(work / f"missing-{OCID_CANARY}" / "wallet")
    cases = [
        ("AuthTtc", f"localhost:{lane_port}/{service}", None),
        ("Tcp", f"127.0.0.1:{closed_port()}/{DSN_CANARY}", None),
        ("Wallet", f"tcps://localhost:{lane_port}/{service}", wallet_path),
    ]
    canaries = (PASSWORD_CANARY, TOKEN_CANARY, OCID_CANARY, DSN_CANARY)
    results = []
    for expected, connect_string, wallet in cases:
        profile_path = work / f"profiles-{expected.lower()}.toml"
        write_profile(profile_path, connect_string, wallet)
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ORACLEMCP_") and key != "TNS_ADMIN"
        }
        env.update(
            {
                "ORACLEMCP_CONFIG": str(profile_path),
                "LAB_DOCTOR_PASSWORD_CANARY": PASSWORD_CANARY,
                "LAB_DOCTOR_TOKEN_CANARY": TOKEN_CANARY,
            }
        )
        command = [str(binary), "--json", "doctor", "--online", "--profile", "doctor_i56"]
        default_run = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                     text=True, timeout=45, check=False)
        verbose_run = subprocess.run(command[:3] + ["--verbose"] + command[3:], cwd=ROOT,
                                     env=env, capture_output=True, text=True,
                                     timeout=45, check=False)
        combined = (default_run.stdout + "\n" + default_run.stderr + "\n"
                    + verbose_run.stdout + "\n" + verbose_run.stderr)
        actual = actual_phase(verbose_run.stdout)
        try:
            verbose_report = json.loads(verbose_run.stdout)
        except json.JSONDecodeError:
            verbose_report = {}
        connectivity = next((check for check in verbose_report.get("checks", [])
                             if check.get("name") == "Connectivity"), {})
        detail = connectivity.get("detail", "")
        fix = connectivity.get("fix", "")
        if expected == "AuthTtc":
            phase_ok = "ORA-01017" in detail and "authentication" in fix.lower() and "connect string" not in fix.lower()
        else:
            phase_ok = True
        try:
            default_report = json.loads(default_run.stdout)
        except json.JSONDecodeError:
            default_report = {}
        default_connectivity = next((check for check in default_report.get("checks", [])
                                     if check.get("name") == "Connectivity"), {})
        default_detail = default_connectivity.get("detail", "")
        verbose_ok = "[connect_phase=" not in default_detail and "driver detail suppressed" in default_detail
        result = {
            "case_id": CASE_ID,
            "lane": args.lane,
            "scenario": expected.lower(),
            "expected_phase": expected,
            "actual_phase": actual,
            "canary_leak": any(canary in combined for canary in canaries),
        }
        print(json.dumps(result, sort_keys=True), flush=True)
        results.append(default_run.returncode == 2 and verbose_run.returncode == 2
                       and actual == expected and phase_ok and verbose_ok and not result["canary_leak"])
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
