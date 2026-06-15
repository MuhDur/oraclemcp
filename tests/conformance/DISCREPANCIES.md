# Native Stdio MCP Conformance Discrepancies

## DISC-001: JSON-RPC Batch Arrays Rejected

- Reference: JSON-RPC 2.0 defines batch request arrays.
- oraclemcp behavior: native stdio rejects top-level arrays with
  `Invalid Request` and `id: null`.
- Impact: clients must send one MCP request per newline-delimited stdio frame.
- Resolution: ACCEPTED for stdio transport. This keeps local-agent stdio simple,
  bounded, and aligned with current MCP client behavior.
- Tests affected: `batch_requests_are_explicitly_rejected_for_stdio`.
- Review date: 2026-06-15.

## DISC-002: Unknown Tool Names Are Tool Errors

- Reference: MCP `tools/call` represents tool execution failures inside the
  tool result object.
- oraclemcp behavior: unadvertised tool names return JSON-RPC success with
  `isError: true` and a structured `INVALID_ARGUMENTS` envelope.
- Impact: clients should inspect MCP `isError` for tool-level failures.
- Resolution: ACCEPTED and intentional; the transport remains healthy and the
  agent receives a structured recovery surface.
- Tests affected: `unadvertised_tool_is_mcp_tool_error_not_jsonrpc_error`.
- Review date: 2026-06-15.
