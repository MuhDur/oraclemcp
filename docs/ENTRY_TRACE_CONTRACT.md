# Entry-trace contract

`scripts/entry_trace_contract.json` is the release-critical entry-point map for
this server repository.
It is checked by `scripts/check_entry_trace_contract.sh`, which runs in both
the direct fast CI workflow and the reusable Required-quality workflow.

The contract is deliberately offline: it verifies a real runner → result
relationship without inventing a database result. Live database and OCI
runners remain operator- or workflow-gated; no fixture, mock, or absent binary
can become a synthetic pass.

## Outcomes

All newly produced matrix artifacts use `PASS`, `SKIP`, or `FAIL`.

- A required-tier `SKIP` is a `FAIL`.
- A live-suite `SKIP` is accepted only when the registry supplies a stable
  machine-readable reason and its focused capability probe passes. The current
  `xe18:live_soda` reason is `pre-21c-soda-unsupported`.
- The release matrix has no typed-skip exception: every required lane,
  including `octcps`, must be `PASS` for release preflight to pass.

Historical artifacts may use the earlier `GREEN` spelling. They remain dated
evidence for their recorded commits; the contract rejects that spelling for
new runner output rather than rewriting history.

## Script inventory

Every top-level `scripts/*.sh` and `scripts/*.py` file is listed. An
`entry_point` names its trace; a `helper` must have an `excluded_reason` that
matches the contract's machine-readable reason grammar. Adding a script without
classifying it fails the check.

Run the gate locally:

```bash
bash scripts/check_entry_trace_contract.sh
bash scripts/check_entry_trace_contract.sh --self-test
```

The self-test is in memory and verifies the two failure modes that matter most:
an unregistered script and a required trace that attempts to admit a skip.
