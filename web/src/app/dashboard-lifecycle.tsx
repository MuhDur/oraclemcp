import * as React from "react";
import { QueryClient, useQuery } from "@tanstack/react-query";
import { RefreshCcw } from "lucide-react";

import { Button } from "../components/ui/primitives";
import {
  clearOperatorSessionState,
  fetchDashboardSession,
  type DashboardSession,
  type OperatorEventEnvelope,
  type OperatorLaneTarget
} from "./operator-client";
import {
  remainingSeconds,
  scheduleAbsoluteExpiry,
  scheduleDebouncedValue
} from "./dashboard-view-state";

export const LIVE_TELEMETRY_REFETCH_MS = 5_000;

export function createDashboardQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        retry: 1
      }
    }
  });
}

type QueryActivity = {
  isPending: boolean;
  isFetching: boolean;
  fetchStatus?: "fetching" | "paused" | "idle";
};

export function queryActivity(...queries: QueryActivity[]): {
  blocking: boolean;
  refreshing: boolean;
} {
  const blocking = queries.some(
    (query) => query.isPending && (query.fetchStatus === undefined || query.fetchStatus !== "idle")
  );
  return {
    blocking,
    refreshing: !blocking && queries.some((query) => query.isFetching)
  };
}

export function useDashboardAuthorityPurge(
  authority: string | null,
  purge: () => void
): void {
  const priorAuthority = React.useRef(authority);
  const purgeRef = React.useRef(purge);
  React.useLayoutEffect(() => {
    purgeRef.current = purge;
  }, [purge]);
  React.useLayoutEffect(() => {
    if (priorAuthority.current !== authority) {
      priorAuthority.current = authority;
      purgeRef.current();
    }
  }, [authority]);
}

export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [published, setPublished] = React.useState(value);
  React.useEffect(
    () => scheduleDebouncedValue(value, delayMs, setPublished),
    [delayMs, value]
  );
  return published;
}

export function useAbsoluteExpiryCountdown(
  expiresUnix: number | null,
  onExpire: () => void
): number | null {
  const [nowMs, setNowMs] = React.useState(Date.now);
  const onExpireRef = React.useRef(onExpire);
  React.useLayoutEffect(() => {
    onExpireRef.current = onExpire;
  }, [onExpire]);
  React.useEffect(() => {
    if (expiresUnix === null) {
      return;
    }
    const cancelExpiry = scheduleAbsoluteExpiry(expiresUnix, () => {
      setNowMs(Date.now());
      onExpireRef.current();
    });
    const clock = globalThis.setInterval(() => setNowMs(Date.now()), 1_000);
    return () => {
      cancelExpiry();
      globalThis.clearInterval(clock);
    };
  }, [expiresUnix]);
  return expiresUnix === null
    ? null
    : remainingSeconds(expiresUnix, Math.max(nowMs, Date.now()));
}

export function dashboardSessionIsValidAt(
  session: DashboardSession | undefined,
  nowMs = Date.now()
): boolean {
  return Boolean(session && nowMs < session.expires_unix * 1_000);
}

export function expireDashboardAuthority(
  client: QueryClient,
  session: DashboardSession | undefined,
  nowMs = Date.now()
): boolean {
  if (dashboardSessionIsValidAt(session, nowMs)) {
    return false;
  }
  for (const query of client.getQueryCache().getAll()) {
    query.reset();
  }
  client.removeQueries({ type: "inactive" });
  client.getMutationCache().clear();
  clearOperatorSessionState();
  return true;
}

export function purgeDashboardSessionQueries(client: QueryClient): void {
  const isSessionQuery = (query: { queryKey: readonly unknown[] }): boolean =>
    query.queryKey[0] === "dashboard-session";
  void client.resetQueries({ predicate: (query) => !isSessionQuery(query) });
  client.removeQueries({
    predicate: (query) => !isSessionQuery(query),
    type: "inactive"
  });
  client.getMutationCache().clear();
}

export function expireDashboardAuthorityAfterSessionError(client: QueryClient): void {
  purgeDashboardSessionQueries(client);
  clearOperatorSessionState();
}

export function BackgroundRefreshStatus({
  refreshing
}: {
  refreshing: boolean;
}): React.ReactElement | null {
  if (!refreshing) {
    return null;
  }
  return (
    <p
      className="flex items-center justify-end gap-2 text-xs font-semibold text-[var(--om-text-muted)]"
      role="status"
      aria-live="polite"
    >
      <RefreshCcw className="size-3 animate-spin" aria-hidden="true" />
      Updating live data
    </p>
  );
}

export function DashboardSessionBanner({
  client
}: {
  client: QueryClient;
}): React.ReactElement | null {
  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const [nowMs, setNowMs] = React.useState(Date.now);
  const [expired, setExpired] = React.useState(false);
  const priorAuthority = React.useRef<string | null>(null);
  const authority = session.data
    ? `${session.data.expires_unix}\0${session.data.csrf_token}`
    : null;

  React.useEffect(() => {
    if (session.data && dashboardSessionIsValidAt(session.data)) {
      setExpired(false);
    }
    if (priorAuthority.current && authority && priorAuthority.current !== authority) {
      purgeDashboardSessionQueries(client);
    }
    priorAuthority.current = authority;
  }, [authority, client, session.data]);

  React.useEffect(() => {
    const current = session.data;
    if (!current) {
      return;
    }
    const expire = (): void => {
      const now = Date.now();
      setNowMs(now);
      if (expireDashboardAuthority(client, current, now)) {
        setExpired(true);
      }
    };
    const remainingMs = current.expires_unix * 1_000 - Date.now();
    if (remainingMs <= 0) {
      expire();
      return;
    }
    const expiryTimer = globalThis.setTimeout(expire, remainingMs);
    const clock = globalThis.setInterval(() => setNowMs(Date.now()), 1_000);
    return () => {
      globalThis.clearTimeout(expiryTimer);
      globalThis.clearInterval(clock);
    };
  }, [client, session.data]);

  React.useEffect(() => {
    if (session.isError) {
      expireDashboardAuthorityAfterSessionError(client);
    }
  }, [client, session.isError]);

  if (expired) {
    return <ExpiredSessionNotice />;
  }
  if (session.isError) {
    return (
      <div
        className="rounded-lg border border-[var(--om-rust)] bg-[color-mix(in_srgb,var(--om-rust)_12%,transparent)] p-4"
        role="alert"
      >
        <p className="font-semibold text-[var(--om-text-bright)]">Dashboard session unavailable</p>
        <p className="mt-1 text-sm leading-6 text-[var(--om-text-muted)]">
          Run <code className="font-mono text-[var(--om-gold)]">oraclemcp dashboard</code> on the server, open the new pairing page, and enter its one-time code.
        </p>
        <Button
          type="button"
          variant="secondary"
          className="mt-3"
          disabled={session.isFetching}
          onClick={() => void session.refetch()}
        >
          <RefreshCcw className={session.isFetching ? "size-4 animate-spin" : "size-4"} aria-hidden="true" />
          {session.isFetching ? "Retrying dashboard session" : "Retry dashboard session"}
        </Button>
      </div>
    );
  }
  if (!session.data) {
    return null;
  }
  const remainingSeconds = Math.max(
    0,
    Math.ceil((session.data.expires_unix * 1_000 - nowMs) / 1_000)
  );
  if (remainingSeconds > 15 * 60) {
    return null;
  }
  return (
    <div
      className="rounded-lg border border-[var(--om-copper)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] p-3 text-sm text-[var(--om-text)]"
      role={remainingSeconds === 0 ? "alert" : "status"}
    >
      {remainingSeconds === 0
        ? "This dashboard session has expired. Pair this browser again before continuing."
        : `This dashboard session expires in about ${Math.ceil(remainingSeconds / 60)} minute(s). Finish or save your work, then pair again.`}
    </div>
  );
}

function ExpiredSessionNotice(): React.ReactElement {
  return (
    <div
      className="rounded-lg border border-[var(--om-copper)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] p-3 text-sm text-[var(--om-text)]"
      role="alert"
    >
      This dashboard session has expired. Pair this browser again before continuing.
    </div>
  );
}

export type EventStreamStatus = "connecting" | "live" | "reconnecting" | "closed";

type OperatorEventStreamControllerOptions = {
  lane?: OperatorLaneTarget;
  session?: DashboardSession;
  onStatus: (status: EventStreamStatus) => void;
  onEvent: (event: OperatorEventEnvelope) => void;
  onInvalidate: () => void;
  eventSourceFactory?: (url: string, init: EventSourceInit) => EventSource;
  invalidationWindowMs?: number;
};

export function startOperatorEventStream({
  lane,
  session,
  onStatus,
  onEvent,
  onInvalidate,
  eventSourceFactory = (url, init) => new EventSource(url, init),
  invalidationWindowMs = 100
}: OperatorEventStreamControllerOptions): () => void {
  if (!session || !dashboardSessionIsValidAt(session)) {
    onStatus("closed");
    return () => undefined;
  }

  const laneId = lane?.laneId.trim();
  if (
    lane &&
    (!laneId || !Number.isSafeInteger(lane.generation) || lane.generation <= 0)
  ) {
    onStatus("closed");
    return () => undefined;
  }

  let active = true;
  let invalidationTimer: ReturnType<typeof globalThis.setTimeout> | null = null;
  onStatus("connecting");
  const logicalLaneId = laneId ?? "operator";
  const streamId = lane ? `${logicalLaneId}@${lane.generation}` : logicalLaneId;
  const params = new URLSearchParams({ lane_id: logicalLaneId });
  if (lane) {
    params.set("lane_generation", String(lane.generation));
  }
  const source = eventSourceFactory(`/operator/v1/events?${params.toString()}`, {
    withCredentials: true
  });
  const flushInvalidation = (): void => {
    invalidationTimer = null;
    if (active) {
      onInvalidate();
    }
  };
  const scheduleInvalidation = (): void => {
    if (invalidationTimer === null) {
      invalidationTimer = globalThis.setTimeout(flushInvalidation, invalidationWindowMs);
    }
  };
  const handleEvent = (message: MessageEvent<string>): void => {
    const parsed = parseOperatorEvent(message.data);
    if (
      !active ||
      !parsed ||
      parsed.lane_id !== logicalLaneId ||
      parsed.event_id !== `${streamId}/${parsed.event_seq}`
    ) {
      return;
    }
    onStatus("live");
    onEvent(parsed);
    scheduleInvalidation();
  };
  const handleSnapshot = handleEvent as EventListener;
  source.addEventListener("operator.snapshot", handleSnapshot);
  source.addEventListener("operator.stream_gap", handleSnapshot);
  source.onopen = () => {
    if (active) {
      onStatus("live");
    }
  };
  source.onmessage = handleEvent;
  source.onerror = () => {
    if (active) {
      onStatus(source.readyState === 2 ? "closed" : "reconnecting");
    }
  };

  const stop = (notify: boolean): void => {
    if (!active) {
      return;
    }
    active = false;
    if (invalidationTimer !== null) {
      globalThis.clearTimeout(invalidationTimer);
      invalidationTimer = null;
    }
    source.removeEventListener("operator.snapshot", handleSnapshot);
    source.removeEventListener("operator.stream_gap", handleSnapshot);
    source.onopen = null;
    source.onmessage = null;
    source.onerror = null;
    source.close();
    if (notify) {
      onStatus("closed");
    }
  };
  const expiryTimer = globalThis.setTimeout(
    () => stop(true),
    Math.max(0, session.expires_unix * 1_000 - Date.now())
  );

  return () => {
    globalThis.clearTimeout(expiryTimer);
    stop(false);
  };
}

function parseOperatorEvent(raw: string): OperatorEventEnvelope | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) {
      return null;
    }
    if (
      parsed["protocol_version"] !== "operator.v1" ||
      typeof parsed["event_id"] !== "string" ||
      typeof parsed["event_seq"] !== "number" ||
      typeof parsed["lane_id"] !== "string" ||
      typeof parsed["subject_id_hash"] !== "string" ||
      typeof parsed["event_type"] !== "string" ||
      !isRecord(parsed["data"])
    ) {
      return null;
    }
    return parsed as OperatorEventEnvelope;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
