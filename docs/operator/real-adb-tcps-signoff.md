# Real ADB TCPS + OCI IAM Sign-Off

**FREE TIER ONLY — NO COSTS.** The Terraform acceptance lane must provision
only an Always Free ADB (`is_free_tier = true`) with no paid shape or storage.
Never alter that assertion. The harness refuses to apply if the module does not
contain the explicit free-tier guard, and its exit trap attempts both Terraform
destroy and an OCI CLI delete fallback.

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
prefetched OCI IAM database token. The two authentication probes deliberately
use different database users: a password user (normally `ADMIN`) proves the
wallet/password path, while an `IDENTIFIED GLOBALLY` user proves the OCI IAM
token path. A global IAM user is not assumed to have a database password.
The script writes temporary profiles and raw runtime output only under ignored
`target/e2e/`.

Required env:

```sh
export CARGO_TARGET_DIR=/home/durakovic/.cache/cargo-target-server
export CARGO_BUILD_JOBS=16
export ORACLEMCP_REAL_ADB_SIGNOFF=1
export ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1
export ORACLEMCP_REAL_ADB_CONNECT_STRING='<ADB TCPS connect string or wallet alias>'
export ORACLEMCP_REAL_ADB_PASSWORD_USER='<password user, normally ADMIN>'
export ORACLEMCP_REAL_ADB_IAM_USER='<global user mapped to the OCI IAM principal>'
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

## Operator-Gated Always Free ADB Lane

`.github/workflows/oci-adb.yml` is the reproducible live-cloud acceptance
route. It is `workflow_dispatch` only: `plan` makes no cloud mutation;
`apply-and-signoff` requires the literal confirmation
`provision-and-destroy`, provisions a fresh Always Free ADB with Terraform,
creates a wallet, maps a throwaway global database user to the supplied IAM
principal, mints a database-scoped token, runs both real TCPS probes, and
destroys the database in an exit trap.

The repository stores these six OCI API-key inputs as GitHub Actions secrets:

- `OCI_TENANCY_OCID`, `OCI_USER_OCID`, `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY`
- `OCI_REGION`, `OCI_COMPARTMENT_OCID`

The `apply-and-signoff` dispatch also requires `iam_principal_name`. This is a
local IAM user principal name, optionally qualified as `domain/name`; it is not
an OCID. OCI API-key credentials can mint a token but do not create the
Autonomous Database global-user mapping required for that token to authenticate.

For an operator shell, the equivalent wiring is:

```sh
export TF_VAR_tenancy_ocid='<OCI tenancy OCID>'
export TF_VAR_user_ocid='<OCI API-key user OCID>'
export TF_VAR_fingerprint='<OCI API-key fingerprint>'
export TF_VAR_private_key_path='<path to OCI API-key PEM>'
export TF_VAR_region='<OCI region>'
export TF_VAR_compartment_ocid='<throwaway ADB compartment OCID>'
export ORACLEMCP_ADB_IAM_PRINCIPAL_NAME='<domain/name or local IAM user name>'
export ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1

bash scripts/e2e/oci_adb_terraform.sh --log --apply-and-signoff
```

An absent OCI input produces the typed, zero-success-exit result
`SKIP_BLOCKED_OCI_CREDS`; it is not presented as a live pass. A failed
teardown is an error: retain the runtime-only state under `target/e2e/` and
destroy the throwaway resource before retrying.

## Evidence Handling

Auto-verified and commit-safe:

- `tests/artifacts/local_gate/results-<source-sha>.json` from
  `scripts/local_release_gate.sh --commit-proof`.
- `scripts/local_release_gate_check.sh --require`, which validates the proof and
  rejects live-cloud markers.

Runtime-only and not commit-safe:

- `target/e2e/real_adb_tcps_signoff/**`
- `target/e2e/oci_adb_terraform/**` (Terraform state, wallet, OCI token, and
  raw provider/client output)
- Generated real ADB profile TOML files.
- Doctor output from the real wallet/password and OCI IAM token probes.

Before committing release evidence, run:

```sh
bash scripts/secret_scan.sh --self-test
bash scripts/secret_scan.sh
```
