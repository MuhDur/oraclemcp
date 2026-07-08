# Local Release Gate Evidence

`scripts/local_release_gate.sh --commit-proof` writes sanitized D3.2 proof files
here as `results-<source-sha>.json`.

Only synthetic autonomous evidence belongs in this directory. Real ADB wallet,
OCI IAM token, host, tenant, and user details are operator-supplied at runtime
and must stay in ignored `target/e2e/` artifacts or out-of-band release notes.
The committed synthetic proof uses only `CN=oracle-test.invalid`.
