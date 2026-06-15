# O1 Results

Optimization landed: lazy cache for static MCP tool discovery JSON in
`OracleMcpServer`.

Primary repeated-session measurement:

| Scenario | n | p50 | p95 | p99 | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline commit, initialize + 20 `tools/list` calls | 30 | 26.392 ms | 31.121 ms | 31.500 ms | 24.672 ms | 31.500 ms |
| Current lazy cache, initialize + 20 `tools/list` calls | 30 | 21.736 ms | 27.245 ms | 30.401 ms | 20.721 ms | 30.401 ms |

Delta:

- p50 improved by 4.656 ms, about 17.6%.
- p95 improved by 3.876 ms, about 12.5%.
- p99 improved by 1.099 ms, about 3.5%.

One-shot process measurement:

| Scenario | n | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Baseline initialize + one `tools/list` | 30 | 12.853 ms | 14.992 ms | 16.981 ms |
| Current lazy cache initialize + one `tools/list` | 30 | 13.907 ms | 16.073 ms | 16.193 ms |

The one-shot process path is dominated by process startup and does not show a
clear win. The cache is still useful for the long-running MCP session behavior
agents actually use when they probe tool metadata more than once.

Raw evidence:

- `raw/s1-tools-list-before.csv` and matching `before-*` files are an abandoned
  warm-up attempt from the stalled O1 worker; they are retained for provenance
  but not used for scoring.
- `raw/s1-tools-list-before2-summary.txt`
- `raw/s1-tools-list-after-summary.txt`
- `raw/s1-tools-list-20-before-archive-summary.txt`
- `raw/s1-tools-list-20-after-summary.txt`
- `raw/s1-before2-sample-output.jsonl`
- `raw/s1-after-sample-output.jsonl`

Next optimization candidates:

1. Split live Oracle first-connect measurements into connect, ping, simple
   query, and describe phases before changing connection behavior.
2. Revisit page serialization only if live steady-state DB measurements do not
   dominate.
3. Keep classifier changes out of the optimization path unless future profiles
   prove the fail-closed parser is a real hotspot.
