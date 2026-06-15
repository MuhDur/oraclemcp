# Hotspot Table - 20260615T182242Z-7dd4a60

This run did not capture CPU flamegraphs. The table ranks measured surfaces by
current cost and release risk, using the available artifacts.

| Rank | Location | Metric | Value | Category | Evidence |
|---:|---|---|---:|---|---|
| 1 | Docker builder dependencies | Release blocker | failed before fix | build/release | `BASELINE.md` Docker section |
| 2 | Docker runtime image | Size | 253,337,830 bytes | footprint | `BASELINE.md` Docker section |
| 3 | Release binary | Size | 15,560,416 bytes | footprint | `BASELINE.md` release build section |
| 4 | `read_query` page serialization, 1000 rows | Criterion estimate | 1.7810 ms | CPU/serialization | `BASELINE.md` synthetic read query section |
| 5 | `oraclemcp capabilities` offline startup | p95 wall time | 9.398 ms | startup | `BASELINE.md` offline CLI startup section |
| 6 | `oraclemcp-guard` classifier | per statement | 14,290 ns | CPU/parser | `BASELINE.md` SQL classifier section |
| 7 | CLI stdout broken pipe | Pipeline smoke | fixed | ergonomics | `BASELINE.md` CLI pipe smoke section |

## Interpretation

The only W13 blocker was release packaging, not runtime hot-path cost: Docker
could not build until the builder image gained `gcc`; the only CLI ergonomics
issue found during the run was fixed with fallible stdout writes. Offline
startup, classifier, and synthetic serialization numbers are low enough to
serve as future regression baselines rather than optimization targets.
