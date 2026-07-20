# Google ADK / oraclemcp local compatibility matrix

- Evidence revision: `20260720T105522Z`
- oraclemcp source SHA: `24c1dff84abbf11daa26564754bf5d5db423251d`
- orchestrator SHA at evidence end: `a40fb560c9641acc7c44845d1e2f6c1d9fdc9ad4`
- runtime source diff from target: `[]`
- copied binary SHA-256: `57e19497419e92870713f3fa0f238b43dff4c3354f8a2e611670f40b57ea20b9`
- Python: `3.12.13`
- uv: `uv 0.11.24 (x86_64-unknown-linux-gnu)`
- google-adk: `2.5.0`
- google-genai: `2.11.0`
- mcp: `1.28.1`
- Network posture: isolated network namespace; no cloud, Oracle, OCI, GCP, Vertex, or Gemini calls.

## Compatibility matrix

| Area | State | Evidence / limitation |
|---|---|---|
| stdio child process spawn | `PASS` | ADK launched the exact copied binary twice |
| stdio initialize | `PASS` | negotiated=['2025-11-25'] |
| initialized notification | `PASS` | ADK initialization completed before tools/list |
| protected tools/list | `PASS` | 43 protected READ_ONLY tools |
| full schema tools/list + ADK conversion | `PASS` | 60/60 full-catalog declarations converted |
| representative tools/call | `PASS` | metadata, preview, query refusal, invalid arguments, connection-info classification |
| structured tool refusal | `PASS` | typed OPERATING_LEVEL_TOO_LOW returned as MCP tool result |
| same-session recovery | `PASS` | metadata call succeeded after refusal and invalid arguments |
| stderr isolation | `PASS` | diagnostics captured separately; no synthetic secret values found |
| graceful close + repeated session | `PASS` | idempotent close; no child remains |
| stdio cancellation | `NOT_TESTED` | No long-running DB-free ADK tool call exists in this no-Oracle fixture |
| Gemini declaration acceptance | `NOT_TESTED` | Cloud/model calls expressly excluded from this audit |
| Streamable HTTP bearer | `PASS` | loopback-only, service-owned bearer, initialize/list/call/recovery/shutdown |
| OAuth/mTLS/remote HTTP | `NOT_TESTED` | Deferred by plan and outside local G5 scope |
| live Oracle calls | `NOT_TESTED` | Synthetic TEST-NET profiles in a network namespace; no database available or contacted |

## Coverage accounting

| Section | Local required checks | Passing | Explicit gaps | Score |
|---|---:|---:|---:|---:|
| Plan 5.3 local stdio lifecycle | 10 | 10 | 1 | 10/10 |
| Plan 5.4 local full-schema conversion | 60 | 60 | 60 | 60/60 ADK conversions; Gemini acceptance NOT_TESTED |
| Plan 5.5 DB-free representative calls | 7 | 7 | 1 | 7/7; live nested-input call NOT_TESTED |
| Plan 5.7 local HTTP bearer | 1 | 1 | 0 | 1/1 |

## Catalog conversion

Protected READ_ONLY catalog: **43** tools.
Schema-only ADMIN catalog: **60** tools; **60/60** converted into ADK/GenAI function declarations.
Gemini acceptance remains `NOT_TESTED`; local declaration construction is not a model API acceptance test.

| Tool | ADK conversion | Gemini acceptance | Representative call |
|---|---|---|---|
| `compile_object` | `PASS` | `NOT_TESTED` | no |
| `compile_with_warnings` | `PASS` | `NOT_TESTED` | no |
| `create_or_replace` | `PASS` | `NOT_TESTED` | no |
| `current_database` | `PASS` | `NOT_TESTED` | no |
| `deploy_ddl` | `PASS` | `NOT_TESTED` | no |
| `describe_index` | `PASS` | `NOT_TESTED` | no |
| `describe_table` | `PASS` | `NOT_TESTED` | no |
| `describe_trigger` | `PASS` | `NOT_TESTED` | no |
| `describe_view` | `PASS` | `NOT_TESTED` | no |
| `disable_writes` | `PASS` | `NOT_TESTED` | no |
| `enable_writes` | `PASS` | `NOT_TESTED` | no |
| `execute_approved` | `PASS` | `NOT_TESTED` | no |
| `get_clob` | `PASS` | `NOT_TESTED` | no |
| `get_ddl` | `PASS` | `NOT_TESTED` | no |
| `get_errors` | `PASS` | `NOT_TESTED` | no |
| `get_object_source` | `PASS` | `NOT_TESTED` | no |
| `get_schema` | `PASS` | `NOT_TESTED` | no |
| `list_objects` | `PASS` | `NOT_TESTED` | no |
| `list_schemas` | `PASS` | `NOT_TESTED` | no |
| `oracle_capabilities` | `PASS` | `NOT_TESTED` | no |
| `oracle_checkpoint` | `PASS` | `NOT_TESTED` | no |
| `oracle_compile_errors` | `PASS` | `NOT_TESTED` | no |
| `oracle_compile_object` | `PASS` | `NOT_TESTED` | no |
| `oracle_connection_info` | `PASS` | `NOT_TESTED` | yes |
| `oracle_create_or_replace` | `PASS` | `NOT_TESTED` | no |
| `oracle_db_health` | `PASS` | `NOT_TESTED` | no |
| `oracle_describe` | `PASS` | `NOT_TESTED` | no |
| `oracle_describe_index` | `PASS` | `NOT_TESTED` | no |
| `oracle_describe_trigger` | `PASS` | `NOT_TESTED` | no |
| `oracle_describe_view` | `PASS` | `NOT_TESTED` | no |
| `oracle_diff` | `PASS` | `NOT_TESTED` | no |
| `oracle_execute` | `PASS` | `NOT_TESTED` | no |
| `oracle_explain_plan` | `PASS` | `NOT_TESTED` | no |
| `oracle_get_ddl` | `PASS` | `NOT_TESTED` | no |
| `oracle_get_source` | `PASS` | `NOT_TESTED` | no |
| `oracle_list_profiles` | `PASS` | `NOT_TESTED` | yes |
| `oracle_list_schemas` | `PASS` | `NOT_TESTED` | no |
| `oracle_orient` | `PASS` | `NOT_TESTED` | no |
| `oracle_patch_source` | `PASS` | `NOT_TESTED` | no |
| `oracle_plan_timeline` | `PASS` | `NOT_TESTED` | no |
| `oracle_plscope_inspect` | `PASS` | `NOT_TESTED` | no |
| `oracle_preview_dml` | `PASS` | `NOT_TESTED` | no |
| `oracle_preview_sql` | `PASS` | `NOT_TESTED` | yes |
| `oracle_query` | `PASS` | `NOT_TESTED` | yes |
| `oracle_read_clob` | `PASS` | `NOT_TESTED` | no |
| `oracle_sample_rows` | `PASS` | `NOT_TESTED` | no |
| `oracle_schema_inspect` | `PASS` | `NOT_TESTED` | no |
| `oracle_search_objects` | `PASS` | `NOT_TESTED` | no |
| `oracle_search_source` | `PASS` | `NOT_TESTED` | no |
| `oracle_semantic_search` | `PASS` | `NOT_TESTED` | no |
| `oracle_set_session_level` | `PASS` | `NOT_TESTED` | no |
| `oracle_switch_profile` | `PASS` | `NOT_TESTED` | no |
| `oracle_top_queries` | `PASS` | `NOT_TESTED` | no |
| `oracle_undo_to` | `PASS` | `NOT_TESTED` | no |
| `patch_package` | `PASS` | `NOT_TESTED` | no |
| `patch_view` | `PASS` | `NOT_TESTED` | no |
| `preview_sql` | `PASS` | `NOT_TESTED` | no |
| `query` | `PASS` | `NOT_TESTED` | no |
| `read_patch_preview` | `PASS` | `NOT_TESTED` | no |
| `switch_database` | `PASS` | `NOT_TESTED` | no |

## Classification

- Server defects reproduced: **0**.
- ADK defects reproduced: **0**.
- Client setup failures encountered and corrected: an in-memory `StringIO` cannot be ADK's stdio `errlog` because subprocess setup requires `fileno()`; using a real evidence log is the documented-compatible setup.
- Environment limitation: `oracle_connection_info` returned typed `CONNECTION_FAILED` for the deliberately unreachable synthetic profile. The ADK session remained protocol-valid; live connection metadata semantics were not tested.
- Client diagnostic: ADK's HTTP factory attempted optional ADC-backed mTLS configuration, found no credentials in the cleared environment, logged that fact, and continued successfully over the explicitly configured plain loopback URL.
- Cloud/model limitation: Gemini declaration acceptance and live Vertex orchestration were not tested and must not be claimed.

## Decision

`no server changes required` for Wave-2 G5/F-S3 at this pinned version. The conditional fix bead has no reproduced client-neutral server defect to patch. The tracker record remains open and was not mutated by this audit.

## Official upstream references

- https://adk.dev/tools-custom/mcp-tools/
- https://github.com/google/adk-python/releases/tag/v2.5.0
- https://github.com/google/adk-python/blob/v2.5.0/pyproject.toml
- https://pypi.org/project/google-adk/
