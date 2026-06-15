# Native Stdio MCP Conformance Coverage

Spec sources:

- Model Context Protocol: `2025-11-25`
- JSON-RPC: `2.0`

Harness:

- Rust integration test: `crates/oraclemcp-core/tests/mcp_conformance.rs`
- Transport under test: `OracleMcpServer::serve_stdio_with_io`
- Fixture style: spec-derived structural assertions, no external/generated fixtures

## Matrix

| Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Divergent | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialize | 1 | 0 | 1 | 1 | 0 | 100% |
| Notifications | 1 | 0 | 1 | 1 | 0 | 100% |
| Tools | 3 | 0 | 3 | 3 | 0 | 100% |
| JSON-RPC errors | 3 | 2 | 5 | 5 | 1 | 100% |
| Security | 1 | 0 | 1 | 1 | 0 | 100% |

Total tracked requirements: 9 MUST, 2 SHOULD, 11 tested.

## Requirement IDs

| ID | Level | Section | Covered Behavior |
| --- | --- | --- | --- |
| MCP-STDIO-001 | MUST | Initialize | `initialize` returns protocol version, server info, and tool capability. |
| MCP-STDIO-002 | MUST | Notifications | `notifications/initialized` produces no response. |
| MCP-STDIO-003 | MUST | Tools | `tools/list` returns MCP `inputSchema` objects. |
| MCP-STDIO-004 | MUST | Tools | `tools/call` returns `content`, `structuredContent`, and `isError`. |
| MCP-STDIO-005 | MUST | Tools | Unknown tools are MCP tool errors, not transport crashes. |
| JSONRPC-STDIO-001 | MUST | JSON-RPC errors | Malformed JSON returns parse error with null id. |
| JSONRPC-STDIO-002 | MUST | JSON-RPC errors | Unknown methods return method-not-found and echo id. |
| JSONRPC-STDIO-003 | MUST | JSON-RPC errors | Invalid params return invalid-params and echo id. |
| JSONRPC-STDIO-004 | SHOULD | JSON-RPC errors | Oversized frames fail closed before parsing. |
| JSONRPC-STDIO-005 | SHOULD | JSON-RPC errors | Batch arrays are explicitly rejected for stdio. |
| SEC-STDIO-001 | MUST | Security | Token mismatch errors do not echo the presented token. |

## Provenance

This harness was created from the native stdio implementation and the MCP
`2025-11-25` wire shape already frozen by `tests/golden/stdio/*.json`. No
third-party reference implementation or generated fixture corpus is used.
