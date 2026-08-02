export type DashboardActionTicket = {
  method: string;
  path: string;
  ticket: string;
};

export type DashboardSession = {
  csrf_token: string;
  csrf_header: string;
  action_ticket_header: string;
  expires_unix: number;
  action_tickets: DashboardActionTicket[];
};

export class DashboardSessionProtocolError extends Error {
  readonly kind = "invalid_dashboard_session";

  constructor(message: string) {
    super(message);
    this.name = "DashboardSessionProtocolError";
  }
}

export function validateDashboardSession(value: unknown): DashboardSession {
  const session = recordValue(value);
  if (!session) {
    throw invalidDashboardSession("response must be an object");
  }
  const csrfToken = boundedNonEmptyString(session["csrf_token"], 4_096);
  const csrfHeader = boundedHeaderName(session["csrf_header"]);
  const actionTicketHeader = boundedHeaderName(session["action_ticket_header"]);
  const expiresUnix = session["expires_unix"];
  if (!Number.isSafeInteger(expiresUnix) || (expiresUnix as number) < 0) {
    throw invalidDashboardSession("expires_unix must be a non-negative safe integer");
  }
  const rawTickets = session["action_tickets"];
  if (!Array.isArray(rawTickets) || rawTickets.length === 0 || rawTickets.length > 256) {
    throw invalidDashboardSession("action_tickets must be a bounded non-empty array");
  }
  const actionTickets = rawTickets.map((value) => {
    const ticket = recordValue(value);
    if (!ticket) {
      throw invalidDashboardSession("each action ticket must be an object");
    }
    const method = boundedNonEmptyString(ticket["method"], 16);
    const path = boundedNonEmptyString(ticket["path"], 512);
    const token = boundedNonEmptyString(ticket["ticket"], 4_096);
    if (!/^[A-Z]+$/.test(method) || !path.startsWith("/operator/v1/")) {
      throw invalidDashboardSession("action ticket method or path is invalid");
    }
    return { method, path, ticket: token };
  });
  return {
    csrf_token: csrfToken,
    csrf_header: csrfHeader,
    action_ticket_header: actionTicketHeader,
    expires_unix: expiresUnix as number,
    action_tickets: actionTickets
  };
}

export function actionTicketFor(session: DashboardSession, path: string): string {
  if (Date.now() >= session.expires_unix * 1_000) {
    throw new DashboardSessionProtocolError("dashboard session has expired");
  }
  const ticket = session.action_tickets.find(
    (candidate) => candidate.method === "POST" && candidate.path === path
  );
  if (!ticket) {
    throw new DashboardSessionProtocolError(`missing dashboard action ticket for ${path}`);
  }
  return ticket.ticket;
}

function boundedNonEmptyString(value: unknown, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw invalidDashboardSession("required string field is missing or out of range");
  }
  return value;
}

function boundedHeaderName(value: unknown): string {
  const header = boundedNonEmptyString(value, 128);
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header)) {
    throw invalidDashboardSession("dashboard header name is invalid");
  }
  return header;
}

function invalidDashboardSession(message: string): DashboardSessionProtocolError {
  return new DashboardSessionProtocolError(`invalid dashboard session response: ${message}`);
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
