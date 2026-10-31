# `oraclemcp demo` transcript (scrubbed)

Recorded from a real `oraclemcp demo --yes` run against the digest-pinned FREE 23ai
image. Volatile values are scrubbed: `[TOKEN]` is the per-run container and label
token, `[PORT]` the host port, `[IMAGE_STATE]` whether the image was already local.
`demo_e2e_full_flow` (crates/oraclemcp/tests/demo_e2e.rs) compares a live run with
the block below, line for line.

```text
oraclemcp demo: guarded writes on Oracle FREE 23ai
plan:
  image      gvenzl/oracle-free:23-slim@sha256:fbbd3023d5abc33e36d3814816e6fd740e8efabeaa70cf470ddeab5874a3f6f8 ([IMAGE_STATE])
  container  oraclemcp-demo-[TOKEN] (labels oraclemcp.demo=1, oraclemcp.demo.run=[TOKEN])
  listener   127.0.0.1:[PORT] -> 1521
  limits     --cpus 2 --memory 4g --memory-swap 4g --pids-limit 512
  budget     600s wall clock, including database start
  seed       6 statements (W4 fixture parent/child subset) as user OMCP_DEMO
  session    refuse -> preview -> confirm -> rollback -> audit verify
  teardown   stop and remove this run's container only
[ok] database ready
[ok] seeded T_PARENT_DEMO and T_CHILD_DEMO as OMCP_DEMO
[1/5] refuse   oracle_execute UPDATE at READ_ONLY -> refused: OPERATING_LEVEL_TOO_LOW
[2/5] preview  oracle_set_session_level READ_WRITE -> confirmation token issued
[3/5] confirm  session level READ_WRITE (temporary elevation)
[4/5] rollback oracle_execute UPDATE -> rows_affected=1, rolled back (committed=false); re-read LABEL='parent-1' (server and independent)
[5/5] audit    audit verify -> ok
teardown: completed
```
