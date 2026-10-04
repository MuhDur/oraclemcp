# Oracle MCP audit session report

**Verification:** VERIFIED

## Verification

| Field | Value |
| --- | --- |
| File digest | sha256:05835cfb31058fc9e0030e8e284b976a5666d3a2134bfc191fc6ac13e8faaf57 |
| Records | 3 |
| Record range | 1..3 |
| Time range | unix:1790639700..unix:1790639700 |

## Timeline

| Seq | Time | Subject | Tool | Level | Decision | Outcome | SQL | Rows | Failure |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | unix:1790639700 | process:stdio | security_feature_evidence_unavailable | READ_ONLY | ALLOWED | SUCCEEDED | sha256:16d825fec88856b6b3e4f9a4c32daeb0abcb3972d242bdcd817226f3bc64076f; &lt;sql text redacted; see sql_sha256&gt; | - | - |
| 2 | unix:1790639700 | process:stdio | oracle_query | READ_ONLY | ALLOWED | PENDING | sha256:94fe6909241361164d50ea56a8b94e068238b3ee1c2af138a85e7fe964f963c0; &lt;sql text redacted; see sql_sha256&gt; | - | - |
| 3 | unix:1790639700 | process:stdio | oracle_query | READ_ONLY | ALLOWED | SUCCEEDED | sha256:94fe6909241361164d50ea56a8b94e068238b3ee1c2af138a85e7fe964f963c0; &lt;sql text redacted; see sql_sha256&gt; | 1 | - |

## Level changes and elevation windows

| Seq | Tool | Decision | Outcome |
| --- | --- | --- | --- |
| - | none | - | - |

## Grants and tokens

| Seq | Tool | Decision | Outcome |
| --- | --- | --- | --- |
| - | none | - | - |

## Refusals

| Class | Count |
| --- | --- |
| none | 0 |

## Totals

| Metric | Count |
| --- | --- |
| Records | 3 |
| Refusals | 0 |
| Failed outcomes | 0 |
