# Native MCP Conformance Coverage

Spec sources:

- Model Context Protocol: `2025-11-25`
- JSON-RPC: `2.0`
- RFC 6750 Bearer Token Usage
- RFC 9728 OAuth 2.0 Protected Resource Metadata

Harnesses:

- Rust integration test: `crates/oraclemcp-core/tests/mcp_conformance.rs`
- Golden behavior test: `crates/oraclemcp-core/tests/golden_behavior.rs`
- Binary transport test: `crates/oraclemcp/tests/e2e_http_oauth.rs`
- Native listener TLS tests: `crates/oraclemcp-core/src/http.rs`
- Transports under test:
  - stdio: `OracleMcpServer::serve_stdio_with_io`
  - HTTP: `TcpListener -> serve_http_until -> native parser -> MCP dispatcher`
  - HTTPS: `TcpListener -> serve_https_until -> rustls -> native parser`
- Fixture style: spec-derived structural assertions, no external/generated fixtures

## Matrix

| Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Divergent | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialize | 2 | 0 | 2 | 2 | 0 | 100% |
| Notifications | 1 | 0 | 1 | 1 | 0 | 100% |
| Resources | 1 | 0 | 1 | 1 | 0 | 100% |
| Prompts | 1 | 0 | 1 | 1 | 0 | 100% |
| Tools | 4 | 0 | 4 | 4 | 0 | 100% |
| JSON-RPC errors | 3 | 2 | 5 | 5 | 1 | 100% |
| Security | 1 | 0 | 1 | 1 | 0 | 100% |
| HTTP OAuth | 4 | 0 | 4 | 4 | 0 | 100% |
| HTTP guards | 1 | 0 | 1 | 1 | 0 | 100% |
| HTTP sessions | 1 | 0 | 1 | 1 | 0 | 100% |
| HTTPS / mTLS | 2 | 0 | 2 | 2 | 0 | 100% |

Total tracked requirements: 21 MUST, 2 SHOULD, 23 tested.

## Requirement IDs

| ID | Level | Section | Covered Behavior |
| --- | --- | --- | --- |
| MCP-STDIO-001 | MUST | Initialize | `initialize` returns protocol version, server info, and tool capability. |
| MCP-STDIO-002 | MUST | Notifications | `notifications/initialized` produces no response. |
| MCP-STDIO-003 | MUST | Tools | `tools/list` returns MCP `inputSchema` objects. |
| MCP-STDIO-009 | MUST | Tools | `tools/list` returns non-empty titles and explicit `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` annotations. |
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
| HTTP-AUTH-001 | MUST | HTTP OAuth | OAuth-protected `/mcp` refuses anonymous requests with `WWW-Authenticate`. |
| HTTP-AUTH-002 | MUST | HTTP OAuth | A valid bearer token admits a served HTTP request and forwards the validated OAuth scope grant to tool dispatch. |
| HTTP-AUTH-003 | MUST | HTTP OAuth | A valid bearer token without the configured required scope returns `403` with `error="insufficient_scope"`. |
| HTTP-AUTH-004 | MUST | HTTP OAuth | Narrow, broad, and profile-protected OAuth scope ceilings are enforced at dispatch through the binary HTTP transport. |
| HTTP-GUARD-001 | MUST | HTTP guards | A disallowed browser `Origin` is rejected with `403` before MCP dispatch. |
| HTTP-SESSION-001 | MUST | HTTP sessions | Stateful HTTP rejects forged or unknown `mcp-session-id` values before MCP dispatch. |
| HTTPS-001 | MUST | HTTPS / mTLS | Server-only native TLS accepts a valid HTTPS handshake. |
| HTTPS-002 | MUST | HTTPS / mTLS | Native mTLS rejects clients without a certificate and accepts a client certificate signed by the configured CA. |

## HTTP Proof Map

| Requirement | Primary proof |
| --- | --- |
| HTTP-AUTH-001 | `crates/oraclemcp-core/tests/golden_behavior.rs::golden_http_served_auth_scope_and_session_matrix`; `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_oauth_rejects_missing_invalid_and_insufficient_tokens` |
| HTTP-AUTH-002 | `crates/oraclemcp-core/tests/golden_behavior.rs::golden_http_served_auth_scope_and_session_matrix` |
| HTTP-AUTH-003 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_oauth_rejects_missing_invalid_and_insufficient_tokens` |
| HTTP-AUTH-004 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_oauth_serves_metadata_and_applies_scope_ceilings` |
| HTTP-GUARD-001 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_rejects_bad_origin_and_forged_stateful_sessions`; `tests/golden/http/served_auth_scope_session_matrix.json` |
| HTTP-SESSION-001 | `crates/oraclemcp/tests/e2e_http_oauth.rs::binary_http_rejects_bad_origin_and_forged_stateful_sessions`; `tests/golden/http/served_auth_scope_session_matrix.json` |
| HTTPS-001 | `crates/oraclemcp-core/src/http.rs::tests::serve_https_accepts_tls_handshake` |
| HTTPS-002 | `crates/oraclemcp-core/src/http.rs::tests::serve_https_requires_client_certificate_when_mtls_is_configured` |

## Provenance

This harness was created from the native stdio implementation and the MCP
`2025-11-25` wire shape already frozen by `tests/golden/stdio/*.json` and
`tests/golden/http/*.json`. The HTTP/OAuth rows are derived from the native
listener, parser, OAuth challenge builder, scope dispatcher path, and rustls
TLS listener in this repository. No third-party reference implementation or
generated fixture corpus is used.
