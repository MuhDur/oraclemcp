# Native MCP Conformance Coverage

Spec sources:

- Model Context Protocol: `2025-11-25`
- JSON-RPC: `2.0`
- RFC 6750 Bearer Token Usage
- RFC 9728 OAuth 2.0 Protected Resource Metadata

Harnesses:

- Rust integration test: `crates/oraclemcp-core/tests/mcp_conformance.rs`
- Golden behavior test: `crates/oraclemcp-core/tests/golden_behavior.rs`,
  `crates/oraclemcp/tests/golden_behavior.rs`
  (`tests/golden/stdio/query_opaque_cursor_pagination.json` freezes the E2
  opaque-cursor round-trip + forged/cross-statement rejection;
  `tests/golden/stdio/query_export_resource_and_resource_link.json` freezes the
  E3/E3b export `resource_link` + `resources/read` CSV escaping + forged-id
  rejection;
  `tests/golden/stdio/resource_subscribe_and_updated.json` freezes the E1
  subscribe-capability gate + polling-fallback `resources/updated` notification;
  `tests/golden/stdio/search_objects_detail_levels.json` freezes the E4
  `oracle_search_objects` detail levels with the optimizer `ALL_TABLES.NUM_ROWS`
  estimate + `stats_stale` (never `COUNT(*)`);
  `tests/golden/stdio/completion_complete.json` freezes the E7
  `completion/complete` owner→type→object autocomplete with the capped
  `{values,total,hasMore}` envelope; `tests/golden/stdio/progress_and_list_changed.json`
  freezes the E6 `notifications/progress` bracket and the `tools.listChanged`
  capability)
- E5 connection-scope isolation is covered by unit + dispatch tests (the
  `mcp_exposed` flag fail-closed default, the served `oracle_list_profiles`
  filter, and the adversarial guessed-non-exposed-profile rejection by
  `oracle_switch_profile`): `crates/oraclemcp-config/src/lib.rs::tests`,
  `crates/oraclemcp/src/dispatch/tests.rs::e5_*`,
  `crates/oraclemcp-core/tests/mcp_conformance.rs::completion_complete_for_profile_honors_e5_exposure`
- Binary transport test: `crates/oraclemcp/tests/e2e_http_oauth.rs`
- Oracle structured-cell serialization schema and fixtures:
  `schemas/oracle-cell-structured.schema.json`,
  `crates/oraclemcp-db/tests/structured_schema_golden.rs`, and
  `tests/golden/oracle-cell-structured/*.json`
- Operator v1 generated schema and UI fixtures:
  `schemas/operator.schema.json`,
  `crates/oraclemcp-core/src/operator_protocol.rs`,
  `scripts/ui_fixtures_validate_against_rust_schema.sh`, and
  `tests/fixtures/ui/operator-v1/*.json`
- Durable SQL idempotency and cross-restart replay protection:
  `crates/oraclemcp-core/src/write_intent.rs`,
  `crates/oraclemcp/src/main.rs`, and
  `crates/oraclemcp/src/dispatch/tests.rs`
- Native listener TLS tests: `crates/oraclemcp-core/src/http.rs`
- Transports under test:
  - stdio: `OracleMcpServer::serve_stdio_with_io`
  - HTTP: `TcpListener -> serve_http_until -> native parser -> MCP dispatcher`
  - HTTPS: `TcpListener -> serve_https_until -> rustls -> native parser`
- Fixture style: spec-derived structural assertions plus Rust-generated
  operator UI fixtures; no external fixture corpora

## Matrix

| Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Divergent | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialize | 2 | 0 | 2 | 2 | 0 | 100% |
| Notifications | 3 | 0 | 3 | 3 | 0 | 100% |
| Resources | 3 | 0 | 3 | 3 | 0 | 100% |
| Subscriptions | 2 | 0 | 2 | 2 | 0 | 100% |
| Prompts | 1 | 0 | 1 | 1 | 0 | 100% |
| Tools | 5 | 0 | 5 | 5 | 0 | 100% |
| Completion | 1 | 0 | 1 | 1 | 0 | 100% |
| Pagination | 2 | 0 | 2 | 2 | 0 | 100% |
| JSON-RPC errors | 3 | 2 | 5 | 5 | 1 | 100% |
| Security | 1 | 0 | 1 | 1 | 0 | 100% |
| HTTP OAuth | 4 | 0 | 4 | 4 | 0 | 100% |
| HTTP guards | 1 | 0 | 1 | 1 | 0 | 100% |
| HTTP sessions | 2 | 0 | 2 | 2 | 0 | 100% |
| HTTP routing | 1 | 0 | 1 | 1 | 0 | 100% |
| HTTP negotiation | 2 | 0 | 2 | 2 | 0 | 100% |
| Operator v1 | 8 | 0 | 8 | 8 | 0 | 100% |
| HTTPS / mTLS | 2 | 0 | 2 | 2 | 0 | 100% |
| Oracle structured cells | 6 | 0 | 6 | 6 | 0 | 100% |
| Durable SQL idempotency | 1 | 0 | 1 | 1 | 0 | 100% |

Total tracked requirements: 50 MUST, 2 SHOULD, 52 tested.

## Requirement IDs

| ID | Level | Section | Covered Behavior |
| --- | --- | --- | --- |
| MCP-STDIO-001 | MUST | Initialize | `initialize` returns protocol version, server info, and tool capability. |
| MCP-STDIO-002 | MUST | Notifications | `notifications/initialized` produces no response. |
| MCP-STDIO-003 | MUST | Tools | `tools/list` returns MCP `inputSchema` objects. |
| MCP-STDIO-009 | MUST | Tools | `tools/list` returns non-empty titles and explicit `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` annotations. |
| MCP-STDIO-010 | MUST | Tools | `tools/list` preserves declared `outputSchema` for structured-content validation. |
| MCP-STDIO-004 | MUST | Tools | `tools/call` returns `content`, `structuredContent`, and `isError`. |
| MCP-STDIO-005 | MUST | Tools | Unknown tools are MCP tool errors, not transport crashes. |
| MCP-STDIO-006 | MUST | Initialize | Initialize capabilities advertise resources only after resource handlers are served. |
| MCP-STDIO-007 | MUST | Resources | `resources/list`, `resources/templates/list`, and `resources/read` are served with MCP resource content objects. |
| MCP-STDIO-008 | MUST | Prompts | `prompts/list` and `prompts/get` are served only after prompt capability negotiation. |
| JSONRPC-STDIO-001 | MUST | JSON-RPC errors | Malformed JSON returns parse error with null id. |
| JSONRPC-STDIO-002 | MUST | JSON-RPC errors | Unknown methods return method-not-found and echo id. |
| JSONRPC-STDIO-003 | MUST | JSON-RPC errors | Invalid params return invalid-params and echo id. |
| JSONRPC-STDIO-004 | SHOULD | JSON-RPC errors | Oversized frames fail closed before parsing. |
| JSONRPC-STDIO-005 | SHOULD | JSON-RPC errors | Batch arrays are explicitly rejected for stdio. |
| SEC-STDIO-001 | MUST | Security | Token mismatch errors do not echo the presented token. |
| MCP-STDIO-011 | MUST | Pagination | `tools/list`, `resources/list`, and `resources/templates/list` emit an opaque, tamper-evident `nextCursor` that round-trips to cover every item exactly once within a bounded page size. |
| MCP-STDIO-012 | MUST | Pagination | A forged, edited, or cross-endpoint pagination cursor (and a tampered `oracle_query` page cursor) is rejected with invalid-params / a structured error envelope, never silently followed. |
| MCP-STDIO-013 | MUST | Resources | A large `oracle_query` result is materialized as an `oracle-export://{id}` resource (E3) and returned as a `resource_link` (E3b); `resources/read` serves it with its MIME type and proper CSV escaping; a forged or expired export id fails closed (`OBJECT_NOT_FOUND`). |
| MCP-STDIO-014 | MUST | Resources | An export is access-controlled identically to the originating query: the export id is bound (HMAC) to the request's OAuth scope-grant fingerprint, so a `resources/read` under a different scope grant is refused. |
| MCP-STDIO-015 | MUST | Subscriptions | `resources.subscribe` is advertised, and `resources/subscribe` accepted, ONLY when a change source is confirmed (the `SubscriptionHub` polling fallback). With no source the capability stays `false` and `resources/subscribe` is refused (method-not-found). The thin-line binary ships with no source, so it does not advertise subscribe. |
| MCP-STDIO-016 | MUST | Subscriptions | A subscribed resource whose polled fingerprint changes (the DBMS_CHANGE_NOTIFICATION-vs-polling fallback path) emits a `notifications/resources/updated` for that uri on the next transport flush; the first observation only seeds the baseline. |
| MCP-STDIO-017 | MUST | Completion | `completion/complete` is advertised (`capabilities.completions`) and served as owner→type→object autocomplete for the dictionary tools' arguments and the `oracle://object/{owner}/{type}/{name}` template, scoped by `context.arguments`, routed through the read path, capped at 100 values with `{values,total,hasMore}`. A `profile`/`db` argument completes only the E5 `mcp_exposed` profiles (a non-exposed profile is never offered). |
| MCP-STDIO-018 | MUST | Notifications | A `tools/call` carrying `params._meta.progressToken` is bracketed by `notifications/progress` (a started 0/1 and a completed 1/1) that ride the transport after the response and are true notifications (no id); without a token no progress is emitted. |
| MCP-STDIO-019 | MUST | Notifications | `notifications/tools/list_changed` is advertised (`tools.listChanged: true`) and emitted when the served tool set changes (e.g. an `oracle_switch_profile` that alters the profile-scoped custom-tool catalog); it is a paramless, id-less notification. |
| HTTP-AUTH-001 | MUST | HTTP OAuth | OAuth-protected `/mcp` refuses anonymous requests with `WWW-Authenticate`. |
| HTTP-AUTH-002 | MUST | HTTP OAuth | A valid bearer token admits a served HTTP request and forwards the validated OAuth scope grant to tool dispatch. |
| HTTP-AUTH-003 | MUST | HTTP OAuth | A valid bearer token without the configured required scope returns `403` with `error="insufficient_scope"`. |
| HTTP-AUTH-004 | MUST | HTTP OAuth | Narrow, broad, and profile-protected OAuth scope ceilings are enforced at dispatch through the binary HTTP transport. |
| HTTP-GUARD-001 | MUST | HTTP guards | A disallowed browser `Origin` is rejected with `403` before MCP dispatch. |
| HTTP-SESSION-001 | MUST | HTTP sessions | Stateful HTTP rejects forged or unknown `mcp-session-id` values before MCP dispatch. |
| HTTP-SESSION-002 | MUST | HTTP sessions | Stateful GET replays buffered SSE responses after `cursor` / `Last-Event-ID`; stateless DELETE returns 405 instead of a false session-close acceptance. |
| HTTP-ROUTE-001 | MUST | HTTP routing | `/operator/v1` API routes return typed JSON 404 responses and preserve parsed query filters; they never fall through to a SPA/history HTML response. |
| HTTP-NEG-001 | MUST | HTTP negotiation | `/mcp` POST rejects unacceptable `Accept` and unsupported `Content-Type` values before JSON-RPC dispatch. |
| HTTP-MCP-VER-001 | MUST | HTTP negotiation | `/mcp` honors `MCP-Protocol-Version`; unsupported versions return typed JSON `400 unsupported_protocol_version` before dispatch. |
| OPERATOR-V1-001 | MUST | Operator v1 | `/operator/v1/schema` serves the generated machine-readable schema bundle with route and event schemas. |
| OPERATOR-V1-002 | MUST | Operator v1 | `/operator/v1/health`, `/metrics`, `/audit-tail`, `/active-lanes`, and `/vsession` return versioned, redacted REST envelopes with unavailable-source degradation where providers are absent. |
| OPERATOR-V1-003 | MUST | Operator v1 | `/operator/v1/events` emits SSE `operatorEvent` envelopes carrying `event_seq`, `event_id`, `lane_id`, `subject_id_hash`, `redaction_level`, and `schema_version`. |
| OPERATOR-V1-004 | MUST | Operator v1 | Gated-action operator routes forward to existing MCP `tools/call` dispatch mappings rather than bypassing the guarded dispatcher. |
| OPERATOR-V1-005 | MUST | Operator v1 | Generated operator TypeScript types and UI fixtures are checked against the Rust schema source of truth. |
| OPERATOR-V1-006 | MUST | Operator v1 | B.6 `mcp_and_operator_v1_conformance_matrix` records 1.00 MUST coverage and runs the UI fixture schema validator. |
| OPERATOR-V1-007 | MUST | Operator v1 | Gated-action operator routes accept or derive idempotency keys, return typed in-progress/conflict responses, and replay the original redacted response for same-key retries without re-entering guarded dispatch. |
| OPERATOR-V1-008 | MUST | Operator v1 | `/operator/v1/events` resumes by `cursor` / `Last-Event-ID` from a bounded subject+lane ring, emits gap markers or typed expiry for stale cursors, and rejects cross-lane cursors before replay. |
| HTTPS-001 | MUST | HTTPS / mTLS | Server-only native TLS accepts a valid HTTPS handshake. |
| HTTPS-002 | MUST | HTTPS / mTLS | Native mTLS rejects clients without a certificate and accepts a client certificate signed by the configured CA. |
| DB-SER-001 | MUST | Oracle structured cells | A published JSON Schema exists for `OracleCell::structured` and declares ARRAY, JSON/OSON, VECTOR, TSTZ, object marker, and generic unsupported variants. |
| DB-SER-002 | MUST | Oracle structured cells | Golden fixtures for ARRAY/JSON/VECTOR/TSTZ, OSON scalars, object/UDT unsupported, and generic unsupported parse and match the serializer output. |
| DB-SER-003 | MUST | Oracle structured cells | Structured payloads serialize verbatim rather than flattening through text. |
| DB-SER-004 | MUST | Oracle structured cells | Legacy silent-flattening shapes are rejected by the schema contract test. |
| DB-SER-005 | MUST | Oracle structured cells | `OracleCell::structured` carries the structured contract version, the published schema declares it, and metadata cache keys include it. |
| DB-SER-006 | MUST | Oracle structured cells | Structured ARRAY/JSON/VECTOR decode is capped by row, cell, byte, and depth budgets; larger query budgets require `deep_decode=true`. |
| WRITE-INTENT-001 | MUST | Durable SQL idempotency | Committing tools write a durable pre-execute intent, unresolved in-doubt intents fail writable startup closed, and recovered terminal history rejects exact confirmation-grant plus SQL replay after restart. |

## HTTP Proof Map

| Requirement | Primary proof |
| --- | --- |
| HTTP-AUTH-001 | `crates/oraclemcp-core/tests/golden_behavior.rs::golden_http_served_auth_scope_and_session_matrix`; `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_oauth_rejects_missing_invalid_and_insufficient_tokens` |
| HTTP-AUTH-002 | `crates/oraclemcp-core/tests/golden_behavior.rs::golden_http_served_auth_scope_and_session_matrix` |
| HTTP-AUTH-003 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_oauth_rejects_missing_invalid_and_insufficient_tokens` |
| HTTP-AUTH-004 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_oauth_serves_metadata_and_applies_scope_ceilings` |
| HTTP-GUARD-001 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_rejects_bad_origin_and_forged_stateful_sessions`; `tests/golden/http/served_auth_scope_session_matrix.json` |
| HTTP-SESSION-001 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_rejects_bad_origin_and_forged_stateful_sessions`; `tests/golden/http/served_auth_scope_session_matrix.json` |
| HTTP-SESSION-002 | `crates/oraclemcp-core/src/http.rs::tests::stateful_get_replays_buffered_lane_results_by_cursor`; `crates/oraclemcp-core/src/http.rs::tests::stateless_delete_is_method_not_allowed_not_false_accepted` |
| HTTP-ROUTE-001 | `crates/oraclemcp-core/src/http.rs::tests::operator_api_routes_are_typed_json_404_and_parse_query` |
| HTTP-NEG-001 | `crates/oraclemcp-core/src/http.rs::tests::mcp_post_enforces_accept_and_content_type_negotiation` |
| HTTP-MCP-VER-001 | `crates/oraclemcp-core/src/http.rs::tests::mcp_protocol_version_header_is_enforced_before_dispatch` |
| OPERATOR-V1-001 | `crates/oraclemcp-core/src/operator_protocol.rs::tests::operator_schema_declares_every_route_and_event_contract`; `crates/oraclemcp-core/src/http.rs::tests::operator_v1_serves_schema_health_events_and_action_mapping` |
| OPERATOR-V1-002 | `crates/oraclemcp-core/src/http.rs::tests::operator_v1_serves_schema_health_events_and_action_mapping`; `tests/fixtures/ui/operator-v1/*.json` |
| OPERATOR-V1-003 | `crates/oraclemcp-core/src/http.rs::tests::operator_v1_serves_schema_health_events_and_action_mapping`; `tests/fixtures/ui/operator-v1/event-snapshot.json` |
| OPERATOR-V1-004 | `crates/oraclemcp-core/src/http.rs::tests::operator_v1_serves_schema_health_events_and_action_mapping` |
| OPERATOR-V1-005 | `scripts/ui_fixtures_validate_against_rust_schema.sh`; `crates/oraclemcp-core/src/operator_protocol.rs::tests::generated_operator_schema_artifacts_match_rust_contract` |
| OPERATOR-V1-006 | `scripts/e2e/mcp_and_operator_v1_conformance_matrix.sh` |
| OPERATOR-V1-007 | `crates/oraclemcp-core/src/http.rs::tests::operator_action_idempotency_replays_same_response_and_conflicts_on_drift`; `crates/oraclemcp-core/src/http.rs::tests::operator_idempotency_ledger_reports_in_progress_before_completion` |
| OPERATOR-V1-008 | `crates/oraclemcp-core/src/http.rs::tests::operator_events_resume_is_lane_scoped`; `crates/oraclemcp-core/src/http.rs::tests::operator_events_last_event_id_reports_gap_for_slow_consumer` |
| HTTPS-001 | `crates/oraclemcp-core/src/http.rs::tests::serve_https_accepts_tls_handshake` |
| HTTPS-002 | `crates/oraclemcp-core/src/http.rs::tests::serve_https_requires_client_certificate_when_mtls_is_configured` |
| WRITE-INTENT-001 | `crates/oraclemcp-core/src/write_intent.rs::tests::resolved_intent_survives_reopen_and_rejects_same_grant_sql_replay`; `crates/oraclemcp/src/main.rs::tests::build_write_intent_log_fails_closed_on_unresolved_restart_intent`; `crates/oraclemcp/src/dispatch/tests.rs::execute_commit_in_doubt_leaves_durable_intent_unresolved` |

## Provenance

This harness was created from the native stdio implementation and the MCP
`2025-11-25` wire shape already frozen by `tests/golden/stdio/*.json` and
`tests/golden/http/*.json`. The HTTP/OAuth rows are derived from the native
listener, parser, OAuth challenge builder, scope dispatcher path, operator v1
Rust schema source, generated UI fixtures, and rustls TLS listener in this
repository. No third-party reference implementation or externally generated
fixture corpus is used.
