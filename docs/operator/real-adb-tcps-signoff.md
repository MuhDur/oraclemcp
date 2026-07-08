# Real ADB TCPS + OCI IAM Sign-Off

This runbook is for the operator-run C5 smoke and the D3.2 local pre-tag gate.
The committed repo contains only synthetic evidence. Real ADB wallet files,
connect strings, certificate DNs, usernames, passwords, and IAM database tokens
are supplied at runtime and must not be committed.

## What Is Auto-Verified

`scripts/local_release_gate.sh` is autonomous in its default mode. It runs a
synthetic TCPS terminator with `CN=oracle-test.invalid`, proves the wallet +
IAM-token path reaches TLS, checks that post-TLS Oracle Net bytes are observed,
and writes an optional sanitized proof.

```sh
export CARGO_TARGET_DIR=/home/durakovic/.cache/cargo-target-server
export CARGO_BUILD_JOBS=16

bash scripts/local_release_gate.sh --log
```

To produce the committed synthetic proof for a frozen source commit:

```sh
export CARGO_TARGET_DIR=/home/durakovic/.cache/cargo-target-server
export CARGO_BUILD_JOBS=16

bash scripts/local_release_gate.sh --log --commit-proof
git add tests/artifacts/local_gate/results-*.json
git commit -m "test(release): add local gate proof for frozen RC"
```

The tag-time metadata preflight validates the proof automatically when
`RELEASE_TAG` is set:

```sh
RELEASE_TAG=vX.Y.Z bash scripts/release_preflight.sh
```

## What Needs Real Operator Credentials

The real-cloud signoff needs a throwaway or non-customer ADB lane and a
prefetched OCI IAM database token. The script writes temporary profiles and raw
runtime output only under ignored `target/e2e/`.

Required env:

```sh
export CARGO_TARGET_DIR=/home/durakovic/.cache/cargo-target-server
export CARGO_BUILD_JOBS=16
export ORACLEMCP_REAL_ADB_SIGNOFF=1
export ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1
export ORACLEMCP_REAL_ADB_CONNECT_STRING='<ADB TCPS connect string or wallet alias>'
export ORACLEMCP_REAL_ADB_USER='<database user for the signoff lane>'
export ORACLEMCP_REAL_ADB_PASSWORD='<database password for wallet/password smoke>'
export ORACLEMCP_REAL_ADB_WALLET_LOCATION='<path to the unzipped ADB wallet directory>'
export ORACLEMCP_REAL_ADB_SSL_SERVER_CERT_DN='<exact server certificate DN from the wallet metadata>'
export ORACLEMCP_REAL_ADB_IAM_TOKEN='<prefetched OCI IAM database token>'
```

Optional env:

```sh
export ORACLEMCP_REAL_ADB_WALLET_PASSWORD='<wallet password if the wallet requires one>'
export ORACLEMCP_REAL_ADB_USE_SNI=true
```

Run the real signoff:

```sh
bash scripts/e2e/real_adb_tcps_signoff.sh --log
```

Or run synthetic + real signoff through the single local gate command:

```sh
bash scripts/local_release_gate.sh --log --real-adb
```

## Evidence Handling

Auto-verified and commit-safe:

- `tests/artifacts/local_gate/results-<source-sha>.json` from
  `scripts/local_release_gate.sh --commit-proof`.
- `scripts/local_release_gate_check.sh --require`, which validates the proof and
  rejects live-cloud markers.

Runtime-only and not commit-safe:

- `target/e2e/real_adb_tcps_signoff/**`
- Generated real ADB profile TOML files.
- Doctor output from the real wallet/password and OCI IAM token probes.

Before committing release evidence, run:

```sh
bash scripts/secret_scan.sh --self-test
bash scripts/secret_scan.sh
```
