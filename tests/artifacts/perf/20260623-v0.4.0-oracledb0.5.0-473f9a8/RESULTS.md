# Performance re-measurement — 0.4.0 / oracledb 0.5.0

- Run id: `20260623-v0.4.0-oracledb0.5.0-473f9a8`
- Git SHA: `473f9a8` (branch `feat/0.4.0-production-hardening`); workspace version 0.4.0
- Driver: `oracledb = 0.5.0` (cut over from 0.2.2)
- Host: AMD EPYC 7713 (64c/128t), 259 GB RAM, Ubuntu 25.10, kernel 6.17, ext4
- Toolchain: `nightly-2026-05-11` (rustc 1.97.0-nightly 2026-05-10)
- See `fingerprint.json` for the full environment header.

## Offline micro-benchmarks (criterion, median of [low mid high])

| Benchmark | Median |
|---|---:|
| `classify_type/classify_per_call` | 363.91 ns |
| `classify_type/serialize_row_classifies_columns` | 555.33 ns |
| `page_serialization/read_query_10_rows` | 17.535 µs |
| `page_serialization/read_query_200_rows` | 429.58 µs |
| `page_serialization/read_query_1000_rows` | 2.1443 ms |
| `lob_capping/clob_under_cap` | 16.691 µs |
| `lob_capping/clob_over_cap_truncates` | 12.258 µs |
| `lob_capping/blob_base64_over_cap` | 135.56 µs |

Page serialization scales linearly (~2.1 µs/row at 1000 rows); per-column
classification is reused once per page (PERF T1/T2). No pathology, no regression
signal — no hotspot scores ≥ 2.0, so no optimization round is warranted
(profiling rule: no ranked hotspot → no change).

## Live latency (load/soak against real Oracle 23ai, gvenzl/oracle-free)

1,600 ops across 8 thread-per-connection clients (SELECT 1 / describe mix):

| Percentile | Latency |
|---|---:|
| p50 | 905 µs |
| p95 | 2984 µs |
| p99 | 3410 µs |

All per-client pools balanced (`PoolMetrics::is_balanced` — zero leaked sessions).

## Footprint

| Artifact | Size (bytes) |
|---|---:|
| Release binary `target/release/oraclemcp` | 18,518,328 |
| `oraclemcp-0.4.0.crate` | 164,266 |
| `oraclemcp-core-0.4.0.crate` | 175,694 |
| `oraclemcp-db-0.4.0.crate` | 194,185 |
| `oraclemcp-guard-0.4.0.crate` | 83,718 |
| `oraclemcp-telemetry-0.4.0.crate` | 48,868 |
| `oraclemcp-config-0.4.0.crate` | 30,451 |
| `oraclemcp-audit-0.4.0.crate` | 27,405 |
| `oraclemcp-auth-0.4.0.crate` | 20,619 |
| `oraclemcp-error-0.4.0.crate` | 10,650 |

Binary grew ~19% vs the 0.3.0 baseline (15,560,416 bytes), consistent with the
larger oracledb 0.5.0 driver surface plus the 0.4.0 hardening additions.

Raw logs: `benches.log`, `package.log`, `relbuild.log`.
