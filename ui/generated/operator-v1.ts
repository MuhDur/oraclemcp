// Generated from crates/oraclemcp-core/src/operator_protocol.rs.
// Do not edit by hand. Run scripts/generate_operator_schema.sh.

export const OPERATOR_PROTOCOL_VERSION = "operator.v1" as const;
export const OPERATOR_SCHEMA_VERSION = 1 as const;
export const OPERATOR_REDACTION_LEVEL = "operator_redacted" as const;

export interface OperatorRouteSpec {
  method: "GET" | "POST";
  path: string;
  schema: string;
  sse: boolean;
  mcp_tool: string | null;
}

export interface OperatorResponse<T extends Record<string, unknown> = Record<string, unknown>> {
  protocol_version: typeof OPERATOR_PROTOCOL_VERSION;
  schema_version: typeof OPERATOR_SCHEMA_VERSION;
  route: string;
  redaction_level: typeof OPERATOR_REDACTION_LEVEL;
  data: T;
}

export interface OperatorEvent<T extends Record<string, unknown> = Record<string, unknown>> {
  protocol_version: typeof OPERATOR_PROTOCOL_VERSION;
  schema_version: typeof OPERATOR_SCHEMA_VERSION;
  event_seq: number;
  event_id: string;
  lane_id: string;
  subject_id_hash: string;
  redaction_level: typeof OPERATOR_REDACTION_LEVEL;
  event_type: string;
  data: T;
}

export interface OperatorLaneSummary {
  lane_id: string;
  generation: number;
  status: "starting" | "running" | "stopped" | "quarantined";
  subject_id_hash: string;
}
