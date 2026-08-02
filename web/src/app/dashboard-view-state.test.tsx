import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CLIENT_ROTATION_MUTATION_KEY,
  absoluteExpiryIsActive,
  authoritativeQueryData,
  authoritativeMetric,
  collectionViewState,
  connectionHealthModel,
  configurationAuthority,
  dashboardAuthorityIdentity,
  elevationCompletionIsCurrent,
  laneCancelFailure,
  laneCancelSuccess,
  purgeClientRotationMutation,
  reconcileLaneSelection,
  remainingSeconds,
  sameLaneIdentity,
  scheduleAbsoluteExpiry,
  scheduleDebouncedValue,
  sessionLevelSummary,
  sourceAvailability,
  type ElevationRequestBinding,
  type HealthSourceDiagnostics
} from "./dashboard-view-state";

afterEach(() => {
  vi.useRealTimers();
});

describe("authoritative collection presentation", () => {
  it("reserves empty and zero for successful responses", () => {
    expect(collectionViewState("error", 0)).toBe("unavailable");
    expect(collectionViewState("pending", 0)).toBe("pending");
    expect(collectionViewState("success", 0)).toBe("empty");
    expect(authoritativeMetric("error", 0)).toBe("unavailable");
    expect(authoritativeMetric("success", 0)).toBe(0);
  });

  it("rejects cached data when the current query status is not successful", () => {
    const cached = { enabled: true };
    expect(authoritativeQueryData("success", cached)).toBe(cached);
    expect(authoritativeQueryData("error", cached)).toBeUndefined();
    expect(authoritativeQueryData("pending", cached)).toBeUndefined();
  });

  it("blocks configuration edits until both sources are authoritative", () => {
    expect(configurationAuthority("error", "success")).toEqual({
      ready: false,
      state: "unavailable"
    });
    expect(configurationAuthority("success", "error").ready).toBe(false);
    expect(configurationAuthority("success", "pending").state).toBe("pending");
    expect(configurationAuthority("success", "success")).toEqual({
      ready: true,
      state: "available"
    });
  });
});

describe("lane action truth and identity", () => {
  it("keeps cancellation failure distinct from success", () => {
    expect(laneCancelSuccess("lane-a")).toEqual({
      kind: "success",
      message: "Session lane-a ended."
    });
    const failure = laneCancelFailure(new Error("server refused"));
    expect(failure.kind).toBe("error");
    expect(failure.message).toContain("server refused");
    expect(failure.message.toLowerCase()).not.toContain("cancelled");
  });

  it("clears a removed lane and refuses an id reused with a new generation", () => {
    const bound = { laneId: "lane-a", generation: 7 };
    expect(reconcileLaneSelection(bound, "lane-a", [])).toEqual({
      identity: null,
      invalidated: true
    });
    expect(
      reconcileLaneSelection(bound, "lane-a", [{ lane_id: "lane-a", generation: 8 }])
    ).toEqual({ identity: null, invalidated: true });
  });

  it("binds an initial URL lane to its generation but preserves an explicit clear", () => {
    const lanes = [
      { lane_id: "lane-a", generation: 3 },
      { lane_id: "lane-b", generation: 4 }
    ];
    expect(reconcileLaneSelection(undefined, "", lanes).identity).toEqual({
      laneId: "lane-a",
      generation: 3
    });
    expect(reconcileLaneSelection(undefined, "lane-b", lanes).identity).toEqual({
      laneId: "lane-b",
      generation: 4
    });
    expect(reconcileLaneSelection(null, "lane-b", lanes).identity).toBeNull();
  });

  it("distinguishes an uninitialized binding from an explicit clear", () => {
    expect(sameLaneIdentity(undefined, null)).toBe(false);
    expect(sameLaneIdentity(null, null)).toBe(true);
  });
});

describe("elevation request binding", () => {
  it("ignores a late preview after a newer request completes", async () => {
    const current = {
      lane: { laneId: "lane-a", generation: 2 },
      targetLevel: "DDL",
      ttlSeconds: 60
    };
    const first: ElevationRequestBinding = { ...current, requestGeneration: 1 };
    const second: ElevationRequestBinding = { ...current, requestGeneration: 2 };
    const accepted: number[] = [];
    let resolveFirst!: () => void;
    let resolveSecond!: () => void;
    const settle = (request: ElevationRequestBinding, promise: Promise<void>) =>
      promise.then(() => {
        if (elevationCompletionIsCurrent(request, current, 2)) {
          accepted.push(request.requestGeneration);
        }
      });
    const firstDone = settle(first, new Promise<void>((resolve) => { resolveFirst = resolve; }));
    const secondDone = settle(second, new Promise<void>((resolve) => { resolveSecond = resolve; }));
    resolveSecond();
    await secondDone;
    resolveFirst();
    await firstDone;
    expect(accepted).toEqual([2]);
  });

  it("rejects completion after lane generation, level, or TTL changes", () => {
    const request: ElevationRequestBinding = {
      lane: { laneId: "lane-a", generation: 2 },
      targetLevel: "DDL",
      ttlSeconds: 60,
      requestGeneration: 5
    };
    expect(elevationCompletionIsCurrent(request, { ...request, lane: { laneId: "lane-a", generation: 3 } }, 5)).toBe(false);
    expect(elevationCompletionIsCurrent(request, { ...request, targetLevel: "ADMIN" }, 5)).toBe(false);
    expect(elevationCompletionIsCurrent(request, { ...request, ttlSeconds: 61 }, 5)).toBe(false);
  });
});

describe("authoritative expiries", () => {
  it("does not add response latency to an elevation window", () => {
    const summary = sessionLevelSummary({
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/lanes/lane-a/session-level",
      redaction_level: "operator_redacted",
      data: {
        mcp_response: {
          result: {
            structuredContent: {
              action: "apply",
              preview: false,
              ttl_seconds: 60,
              elevation_expires_unix: 100
            }
          }
        }
      }
    });
    expect(summary.elevationExpiresUnix).toBe(100);
    expect(remainingSeconds(100, 99_250)).toBe(1);
    expect(remainingSeconds(100, 100_000)).toBe(0);
    expect(absoluteExpiryIsActive(100, 99_999)).toBe(true);
    expect(absoluteExpiryIsActive(100, 100_000)).toBe(false);
  });

  it("expires a configuration preview at the exact server boundary", () => {
    vi.useFakeTimers();
    vi.setSystemTime(99_000);
    const expired = vi.fn();
    const cancel = scheduleAbsoluteExpiry(100, expired);
    vi.advanceTimersByTime(999);
    expect(expired).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(expired).toHaveBeenCalledOnce();
    cancel();
  });
});

describe("health source honesty", () => {
  it("keeps independent failures and stale data distinct", () => {
    expect(sourceAvailability("error", false, false)).toBe("unavailable");
    expect(sourceAvailability("error", true, false)).toBe("stale");
    expect(sourceAvailability("success", true, true)).toBe("stale");
    expect(sourceAvailability("success", true, false)).toBe("available");
  });

  it("renders a successful zero but not a null metrics snapshot as zero", () => {
    expect(authoritativeMetric("success", 0)).toBe(0);
    expect(authoritativeMetric("success", null)).toBe("unavailable");
    const model = connectionHealthModel(null, null, undefined, {
      health: { availability: "unavailable", error: null },
      metrics: { availability: "unavailable", error: null },
      connection: { availability: "pending", error: null }
    });
    expect(model.pool).toEqual({
      availability: "unavailable",
      active: null,
      waitMeanMs: null,
      waitMaxMs: null,
      queryMeanMs: null,
      queryMaxMs: null
    });
  });

  it("marks cached facts stale after refresh failure and masks facts with no source", () => {
    const health = {
      source: "self",
      liveness: { status: "live", live: true },
      readiness: { status: "ready", ready: true, db_reachable: true, draining: false }
    };
    const snapshot = {
      requests: [],
      errors: [],
      query_duration_ms: { count: 1, sum: 5, max: 5, mean: 5 },
      pool_wait_ms: { count: 1, sum: 2, max: 2, mean: 2 },
      pool_active_connections: 3
    };
    const stale = connectionHealthModel(health, snapshot, undefined, {
      health: { availability: "stale", error: "health refresh failed" },
      metrics: { availability: "stale", error: "metrics refresh failed" },
      connection: { availability: "unavailable", error: "connection failed" }
    });
    expect(stale.readiness).toMatchObject({
      availability: "stale",
      liveness: "live",
      readiness: "ready",
      live: true,
      ready: true
    });
    expect(stale.pool).toMatchObject({ availability: "stale", active: 3, queryMeanMs: 5 });
    expect(stale.sources.find((row) => row.key === "operator-health")).toMatchObject({
      status: "stale",
      detail: "stale after refresh failure: health refresh failed"
    });

    const unavailable = connectionHealthModel(health, snapshot, undefined, {
      health: { availability: "unavailable", error: "health unavailable" },
      metrics: { availability: "unavailable", error: "metrics unavailable" },
      connection: { availability: "unavailable", error: "connection unavailable" }
    });
    expect(unavailable.readiness).toMatchObject({
      availability: "unavailable",
      liveness: "unavailable",
      readiness: "unavailable",
      live: false,
      ready: false
    });
    expect(unavailable.pool).toMatchObject({ availability: "unavailable", active: null });
  });

  it("preserves each source failure independently", () => {
    const health = {
      source: "self",
      liveness: { status: "live", live: true },
      readiness: { status: "ready", ready: true, db_reachable: true, draining: false }
    };
    const snapshot = {
      requests: [],
      errors: [],
      query_duration_ms: { count: 0, sum: 0, max: 0, mean: 0 },
      pool_wait_ms: { count: 0, sum: 0, max: 0, mean: 0 },
      pool_active_connections: 0
    };
    const connection = {
      protocol_version: "operator.v1" as const,
      schema_version: 1,
      route: "/operator/v1/lanes/lane-a/capabilities",
      redaction_level: "operator_redacted" as const,
      data: {
        mcp_response: {
          result: {
            structuredContent: {
              connected: true,
              active_profile: "dev",
              connection: { database_role: "PRIMARY", open_mode: "READ WRITE" }
            }
          }
        }
      }
    };
    for (const failed of ["health", "metrics", "connection"] as const) {
      const diagnostics: HealthSourceDiagnostics = {
        health: { availability: "available", error: null },
        metrics: { availability: "available", error: null },
        connection: { availability: "available", error: null }
      };
      diagnostics[failed] = { availability: "unavailable", error: `${failed} failed` };
      const model = connectionHealthModel(health, snapshot, connection, diagnostics);
      const key = failed === "connection" ? "db-native" : failed === "health" ? "operator-health" : "metrics";
      expect(model.sources.find((row) => row.key === key)).toMatchObject({
        status: "error",
        detail: `${failed} failed`
      });
    }
  });
});

describe("dashboard authority identity", () => {
  const authority = {
    csrf_token: "csrf-a",
    csrf_header: "x-csrf",
    action_ticket_header: "x-ticket",
    expires_unix: 100,
    action_tickets: [
      { method: "POST", path: "/operator/v1/a", ticket: "ticket-a" },
      { method: "POST", path: "/operator/v1/b", ticket: "ticket-b" }
    ]
  };

  it("changes for every authority-bearing field but not ticket ordering", () => {
    const identity = dashboardAuthorityIdentity(authority);
    expect(dashboardAuthorityIdentity({
      ...authority,
      action_tickets: [...authority.action_tickets].reverse()
    })).toBe(identity);
    expect(dashboardAuthorityIdentity({ ...authority, csrf_token: "csrf-b" })).not.toBe(identity);
    expect(dashboardAuthorityIdentity({
      ...authority,
      action_tickets: [
        { ...authority.action_tickets[0], ticket: "rotated" },
        authority.action_tickets[1]
      ]
    })).not.toBe(identity);
    expect(dashboardAuthorityIdentity(undefined)).toBeNull();
  });
});

describe("credential secret lifecycle", () => {
  for (const lifecycle of ["explicit clear", "navigation", "session loss"]) {
    it(`purges mutation data on ${lifecycle}`, async () => {
      const client = new QueryClient();
      const mutation = client.getMutationCache().build(client, {
        mutationKey: CLIENT_ROTATION_MUTATION_KEY,
        mutationFn: async () => ({ bearer: "secret-value" })
      });
      await mutation.execute(undefined);
      expect(mutation.state.data).toEqual({ bearer: "secret-value" });
      const reset = vi.fn();
      purgeClientRotationMutation(client, reset);
      expect(reset).toHaveBeenCalledOnce();
      expect(client.getMutationCache().findAll({ mutationKey: CLIENT_ROTATION_MUTATION_KEY })).toEqual([]);
    });
  }
});

describe("Explorer request pacing", () => {
  it("publishes only the final value after rapid typing", () => {
    vi.useFakeTimers();
    const published: string[] = [];
    let cancel = scheduleDebouncedValue("E", 300, (value) => published.push(value));
    cancel();
    cancel = scheduleDebouncedValue("EM", 300, (value) => published.push(value));
    cancel();
    scheduleDebouncedValue("EMP", 300, (value) => published.push(value));
    vi.advanceTimersByTime(299);
    expect(published).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(published).toEqual(["EMP"]);
  });

  it("aborts a superseded query and publishes only the final result", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    let firstAborted = false;
    let resolveFinal!: (value: string) => void;
    const firstQuery = ({ signal }: { signal: AbortSignal }) =>
      new Promise<string>((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          firstAborted = true;
          reject(new Error("aborted"));
        });
      });
    const finalQuery = () =>
      new Promise<string>((resolve) => { resolveFinal = resolve; });
    const observer = new QueryObserver(client, {
      queryKey: ["explorer-filter", "old"],
      queryFn: firstQuery
    });
    const rendered: string[] = [];
    const unsubscribe = observer.subscribe((result) => {
      if (result.data) rendered.push(result.data);
    });
    observer.setOptions({
      queryKey: ["explorer-filter", "final"],
      queryFn: finalQuery
    });
    expect(firstAborted).toBe(true);
    resolveFinal("final");
    await vi.waitFor(() => expect(rendered).toEqual(["final"]));
    unsubscribe();
  });
});
