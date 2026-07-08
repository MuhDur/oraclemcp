# Native Stdio MCP Conformance Discrepancies

Accepted intentional divergences (from python-oracledb parity or strict
JSON-RPC) and documented representation limits are tracked here as XFAIL
entries. They must stay **tested**, named here, and reviewed before release;
unknown or untested gaps are not acceptable. A skipped test is invisible; an
XFAIL documents *and* tracks, so every divergence surfaces in the compliance
report.

`scripts/gen_coverage_report.sh` renders these entries into the Divergence
Ledger of `tests/conformance/COVERAGE.md`, so each entry below MUST carry a
`Status:` and a `Review date:` field. Clause-level XFAILs additionally appear in
the coverage matrix (their `Coverage clause:` points at the matrix row);
behavioral divergences are tested green and asserted by their named tests.

- **Status** is one of `ACCEPTED`, `INVESTIGATING`, or `WILL-FIX`.
- **Ids** are sequential `DISC-NNN`; never reuse or renumber a retired id.

## DISC-001: JSON-RPC Batch Arrays Rejected

- Status: ACCEPTED
- Divergence from: JSON-RPC 2.0, which defines batch request arrays.
- oraclemcp behavior: native stdio rejects top-level arrays with
  `Invalid Request` and `id: null`.
- Impact: clients must send one MCP request per newline-delimited stdio frame.
- Resolution: XFAIL-ACCEPTED for the stdio transport. This keeps local-agent
  stdio simple, bounded, and aligned with current MCP client behavior.
- Tests affected: `batch_requests_are_explicitly_rejected_for_stdio`.
- Coverage clause: JSONRPC-STDIO-005 (`JSON-RPC errors` XFAIL).
- Review date: 2026-06-15.

## DISC-002: Unknown Tool Names Are Tool Errors

- Status: ACCEPTED
- Divergence from: a naive JSON-RPC expectation that an unknown name is a
  method-level error. MCP `tools/call` instead represents tool execution
  failures inside the tool result object, which is what oraclemcp does.
- oraclemcp behavior: unadvertised tool names return JSON-RPC success with
  `isError: true` and a structured `INVALID_ARGUMENTS` envelope.
- Impact: clients should inspect MCP `isError` for tool-level failures.
- Resolution: XFAIL-ACCEPTED and intentional; the transport stays healthy and
  the agent receives a structured recovery surface.
- Tests affected: `unadvertised_tool_is_mcp_tool_error_not_jsonrpc_error`.
- Coverage clause: MCP-STDIO-005 (`Tools` XFAIL).
- Review date: 2026-06-15.

## DISC-003: NUMBER Serializes As A Lossless String

- Status: ACCEPTED
- Divergence from: python-oracledb, which materializes Oracle `NUMBER` as a
  Python `int` / `float` / `decimal.Decimal`.
- oraclemcp behavior: `NUMBER` serializes to a JSON **string** by default so no
  precision is lost across the 38-digit (and negative-scale) range; a lossy
  `numbers_as_float` opt-in exists but is never the default.
- Impact: agents parse numeric magnitudes from strings; exact wide integers and
  high-precision decimals round-trip byte-for-byte.
- Resolution: ACCEPTED — the fidelity guarantee outranks JSON-number ergonomics
  and is a hard project invariant.
- Tests affected: `number_is_lossless_string_by_default`, `number_boundary_values_include_negative_scale`, `contract_type_number_is_lossless_string`.
- Coverage clause: covered green under `Oracle structured cells` (DB-SER-003);
  behavioral divergence, not a failing clause.
- Review date: 2026-07-08.

## DISC-004: Unsupported Types Emit An Explicit Marker

- Status: ACCEPTED
- Divergence from: python-oracledb, which returns a live `DbObject` for object /
  UDT / spatial types.
- oraclemcp behavior: object, UDT, and spatial types (e.g. `SDO_GEOMETRY`)
  serialize to an explicit `{ "unsupported": "<type>", "value": null,
  "warning": ... }` marker — never a silent best-effort flatten.
- Impact: a caller always sees, in-band, that a value was not representable,
  rather than receiving a lossy or empty stand-in.
- Resolution: ACCEPTED — fail-loud beats silent-flatten; the thin server does
  not materialize live object handles.
- Tests affected: `unsupported_type_emits_explicit_marker_never_silent`, `contract_type_unsupported_is_explicit_marker_never_silent`.
- Coverage clause: covered green under `Oracle structured cells` (DB-SER-004);
  behavioral divergence, not a failing clause.
- Review date: 2026-07-08.

## DISC-005: TIMESTAMP WITH TIME ZONE Surfaces A Numeric Offset

- Status: ACCEPTED
- Divergence from / limit vs: Oracle stores `TIMESTAMP WITH TIME ZONE` with a
  named region id (e.g. `US/Eastern`); the region name is not surfaced.
- oraclemcp behavior: the session pins `NLS_TIMESTAMP_TZ_FORMAT` to a numeric
  `TZH:TZM` offset, so TSTZ values serialize as offset-bearing ISO-8601 strings
  (`2026-06-29T12:34:56.987654321-05:30`) that are NLS- and locale-decoupled and
  lossless for the represented instant. The original named region is therefore
  reported as its resolved numeric offset, not the region name — a deliberate
  representation limit (python-oracledb thin mode likewise materializes a
  fixed-offset datetime).
- Impact: consumers get a stable, unambiguous instant + offset; they do not get
  the abstract region id and so cannot re-derive future DST transitions from the
  value alone.
- Resolution: ACCEPTED — deterministic, locale-independent serialization is
  worth more than region-name fidelity for an agent-facing wire format.
- Tests affected: `canonical_nls_covers_date_timestamp_and_decimal`, `date_and_timestamp_are_iso_8601`, `tstz_round_trips_with_offset_in_structured_carrier`.
- Coverage clause: covered green under `Oracle structured cells` (DB-SER-002);
  documented representation limit, not a failing clause.
- Review date: 2026-07-08.

## Not applicable in this repository

The thin `oraclemcp` server intentionally implements neither SODA collections
nor a python-oracledb API shim (`pyshim`). There is consequently no SODA-edge or
shim-edge behavior to diverge, so no `DISC` entry is warranted; those parity
surfaces belong to the driver / `plsql-mcp` line. This note records the state so
the absence is a *known* gap, never an unknown one.
