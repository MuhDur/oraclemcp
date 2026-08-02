import { renderToStaticMarkup } from "react-dom/server";
import { QueryObserver } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AuditProofSummary,
  AuditProofBundlePanel,
  AuditRecordProof,
  AuditTimelineTable,
  ExplorerObjectsPanel,
  OperatorOutcomeNotice,
  LIVE_TELEMETRY_REFETCH_MS,
  SourceHistoryPanel,
  applyAuditFilterDraft,
  authoritativeClientCredentials,
  authoritativeEditionData,
  authoritativeExplorerConnection,
  authoritativeExplorerValue,
  authoritativeMetricsData,
  authoritativeProfileReachability,
  authoritativeReviewCapabilities,
  authoritativeReviewProfiles,
  authoritativeServerMode,
  auditHashValidity,
  buildRefactorPreview,
  clientCredentialConfirmationReady,
  combinedQueryStatus,
  consumedReviewGrantState,
  consumedWorkbenchConfirmationState,
  createDashboardQueryClient,
  createAuditFilterControlState,
  createExplorerGlobalSearchRequest,
  currentSchemaDiffPreview,
  dashboardSessionIsValidAt,
  decodeExplorerObjectRows,
  decodeExplorerSourceRows,
  expireDashboardAuthorityAfterSessionError,
  expireDashboardAuthority,
  explorerDetailCompletionIsCurrent,
  explorerDetailRequestIdentity,
  explorerSearchAuthorityReady,
  identifierOccurrences,
  objectRefKey,
  queryActivity,
  resolveReviewSelection,
  reviewsAuthoritativeState,
  reviewCompletionIsCurrent,
  reviewGrantReady,
  reviewProposalRevisionIdentity,
  startOperatorEventStream,
  schemaDiffInputIdentity,
  sessionAuthorityQueriesReady,
  invalidReviewCursorError,
  updateAuditFilterDraft,
  visibleReviewProposals,
  workbenchActionContextIdentity,
  workbenchCompletionIsCurrent,
  workbenchIdeInputIdentity,
  workbenchRequestIdentity,
  workbenchSourceIdentity,
  workbenchSourceIsDirty
} from "./App";
import {
  DashboardSessionProtocolError,
  OperatorGetCache,
  OperatorOutcomeError,
  activateOperatorSession,
  applyChangeProposal,
  cachedExplorerMetadata,
  cancelLane,
  clearExplorerMetadataCache,
  clearOperatorSessionState,
  coalesceAuditTimelineRecords,
  decodeOperatorOutcome,
  executeWorkbenchSql,
  explorerMetadataCacheSummary,
  fetchDashboardSession,
  fetchOperatorHealth,
  fetchProbe,
  operatorGetCacheSummary,
  setSessionLevel,
  type AuditTailRecord,
  type ActiveLanesData,
  type ChangeProposalListData,
  type ChangeProposalListView,
  type ChangeProposalView,
  type DashboardSession,
  type ClientCredentialsData,
  type ConfigOpsStatusData,
  type EditionProposalsData,
  type ExplorerMetadataCacheKey,
  type OperatorResponse,
  type OperatorOutcome,
  type OperatorMetricsData,
  type OperatorHealthData,
  type SourceHistoryListData,
  type SourceSnapshotView,
  type WorkbenchActionData,
  validateDashboardSession
} from "./operator-client";
import {
  OperatorHttpClientError,
  fetchOperatorRequest,
  parseOperatorHttpResponse
} from "./operator-http";

function auditRecord(
  seq: number,
  outcome: string,
  correlation?: AuditTailRecord["correlation"]
): AuditTailRecord {
  return {
    schema_version: 7,
    seq,
    timestamp: "unix:1",
    subject_id_hash: "subject-sha256:test",
    tool: "operator_api",
    danger_level: "OPERATOR",
    decision: outcome === "FAILED" ? "BLOCKED" : "ALLOWED",
    outcome,
    correlation,
    sql_sha256: "sha256:route"
  };
}

function changeProposalList(id: string, title = id): ChangeProposalListView {
  return {
    schema_version: 1,
    id,
    profile: "default",
    author: "human",
    author_id_hash: "sha256:author",
    title,
    created_at: "unix:1",
    updated_at: "unix:2",
    statement_count: 1,
    statements: [
      {
        id: `${id}-statement`,
        unit: "dml",
        sql_sha256: `sha256:${id}`,
        bind_count: 0,
        commit: false,
        capture_dbms_output: false,
        draft_verdict: { danger: "DML", reason: "write" },
        stored_verdict_present: true
      }
    ],
    stored_verdict_present: true
  };
}

function changeProposal(id: string, sql = "UPDATE accounts SET active = 0"): ChangeProposalView {
  const list = changeProposalList(id);
  return {
    ...list,
    statements: list.statements.map((statement) => ({ ...statement, sql_template: sql }))
  };
}

function sourceSnapshot(id = "snapshot-1"): SourceSnapshotView {
  return {
    schema_version: 1,
    id,
    created_at: "unix:1",
    profile: "default",
    owner: "APP",
    name: "PKG",
    object_type: "PACKAGE BODY",
    source_kind: "stored_source",
    source_sha256: "sha256:source",
    source_lines: 10,
    source_chars: 100,
    proposal_id: "proposal-1",
    statement_id: "statement-1",
    statement_sql_sha256: "sha256:statement",
    subject_id_hash: "sha256:subject"
  };
}

const session: DashboardSession = {
  csrf_token: "csrf",
  csrf_header: "x-oraclemcp-csrf",
  action_ticket_header: "x-oraclemcp-action-ticket",
  expires_unix: 4_102_444_800,
  action_tickets: [
    {
      method: "POST",
      path: "/operator/v1/actions/execute",
      ticket: "execute-ticket"
    },
    {
      method: "POST",
      path: "/operator/v1/change-proposals/apply",
      ticket: "apply-ticket"
    },
    {
      method: "POST",
      path: "/operator/v1/lanes/cancel",
      ticket: "cancel-ticket"
    },
    {
      method: "POST",
      path: "/operator/v1/session/set-level",
      ticket: "set-level-ticket"
    }
  ]
};

const laneATarget = { laneId: "lane-a", generation: 7 } as const;

function response(
  route: string,
  data: Record<string, unknown>
): OperatorResponse<Record<string, unknown>> {
  return {
    protocol_version: "operator.v1",
    schema_version: 1,
    route,
    redaction_level: "operator_redacted",
    data
  };
}

function forwarded(mcpResponse: unknown): OperatorResponse<WorkbenchActionData> {
  return response("/operator/v1/actions/execute", {
    status: "forwarded",
    mcp_tool: "oracle_execute",
    mcp_response: mcpResponse
  }) as OperatorResponse<WorkbenchActionData>;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}

function hangingResponse(onCancel: () => void): Response {
  const reader = {
    read: () => new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined),
    cancel: async () => {
      onCancel();
    }
  } as ReadableStreamDefaultReader<Uint8Array>;
  const body = {
    getReader: () => reader,
    cancel: async () => {
      onCancel();
    }
  } as ReadableStream<Uint8Array>;
  return {
    body,
    headers: new Headers(),
    ok: true,
    status: 200,
    statusText: "OK"
  } as Response;
}

afterEach(() => {
  clearOperatorSessionState();
  clearExplorerMetadataCache();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("workbench lexical text replacement", () => {
  it("excludes comments, ordinary strings, q-quotes, and quoted identifiers", () => {
    const source = `BEGIN
  foo := 1;
  value := 'foo';
  -- foo
  /* foo */
  value := q'[foo]';
  "foo" := 2;
  pkg.foo := foo;
END;`;
    const occurrences = identifierOccurrences(source, "foo");
    expect(occurrences.map((occurrence) => source.slice(occurrence.offset, occurrence.endOffset))).toEqual([
      "foo",
      "foo",
      "foo"
    ]);
    const preview = buildRefactorPreview(source, "foo", "renamed");
    expect(preview.error).toBeNull();
    expect(preview.preview).toContain("renamed := 1");
    expect(preview.preview).toContain("pkg.renamed := renamed");
    expect(preview.preview).toContain("'foo'");
    expect(preview.preview).toContain("q'[foo]'");
    expect(preview.preview).toContain('"foo" := 2');
  });

  it("matches quoted identifiers exactly and preserves JavaScript selection offsets", () => {
    const source = `π := "Mixed"; x := "MIXED";`;
    const occurrences = identifierOccurrences(source, '"Mixed"');
    expect(occurrences).toHaveLength(1);
    expect(occurrences[0]?.offset).toBe(source.indexOf('"Mixed"'));
    expect(occurrences[0]?.endOffset).toBe(source.indexOf('"Mixed"') + '"Mixed"'.length);
  });

  it("rejects invalid replacement syntax instead of presenting a rename artifact", () => {
    const preview = buildRefactorPreview("BEGIN foo := 1; END;", "foo", "bad name");
    expect(preview.preview).toBe("{}");
    expect(preview.error).toMatch(/valid Oracle identifier/);
  });
});

describe("client credential destructive confirmation", () => {
  const client = {
    client_id: "client-prod-7",
    label: "production agent",
    scopes: ["oracle:read"],
    status: "active" as const,
    subject_id_hash: "sha256:client",
    generation: 4,
    created_at: "unix:1"
  };

  it("requires the exact selected client ID for both rotation and revocation", () => {
    for (const kind of ["rotate", "revoke"] as const) {
      const action = { kind, client };
      expect(clientCredentialConfirmationReady(action, "")).toBe(false);
      expect(clientCredentialConfirmationReady(action, "client-prod")).toBe(false);
      expect(clientCredentialConfirmationReady(action, "CLIENT-PROD-7")).toBe(false);
      expect(clientCredentialConfirmationReady(action, client.client_id)).toBe(true);
    }
  });
});

const explorerScope: ExplorerMetadataCacheKey = {
  db_fingerprint: "db-fingerprint",
  profile: "db_ro",
  user: "APP_USER",
  visible_schema: "APP",
  serialization_contract_version: 1
};

describe("schema diff preview input binding", () => {
  it("invalidates a preview on title or either snapshot edit", () => {
    const identity = schemaDiffInputIdentity("migration", "before", "after");
    const binding = { inputIdentity: identity, data: { artifact: "reviewed" } };

    expect(currentSchemaDiffPreview(binding, identity)).toEqual({ artifact: "reviewed" });
    expect(
      currentSchemaDiffPreview(
        binding,
        schemaDiffInputIdentity("renamed migration", "before", "after")
      )
    ).toBeNull();
    expect(
      currentSchemaDiffPreview(
        binding,
        schemaDiffInputIdentity("migration", "changed before", "after")
      )
    ).toBeNull();
    expect(
      currentSchemaDiffPreview(
        binding,
        schemaDiffInputIdentity("migration", "before", "changed after")
      )
    ).toBeNull();
  });
});

describe("review query authority", () => {
  it("drops a retained dashboard session after a successful query starts failing", () => {
    const initial = reviewsAuthoritativeState({
      sessionStatus: "success",
      session,
      proposalsStatus: "pending",
      proposals: undefined,
      historyStatus: "pending",
      history: undefined
    });
    expect(initial.session).toBe(session);

    const afterBackgroundFailure = reviewsAuthoritativeState({
      sessionStatus: "error",
      session,
      proposalsStatus: "pending",
      proposals: undefined,
      historyStatus: "pending",
      history: undefined
    });
    expect(afterBackgroundFailure.session).toBeNull();
  });

  it("drops retained proposal and source-history pages after background failures", () => {
    const proposals: OperatorResponse<ChangeProposalListData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/change-proposals",
      redaction_level: "operator_redacted",
      data: {
        source: "self_lane",
        proposals: [changeProposalList("proposal-1")],
        nextCursor: "proposal-cursor"
      }
    };
    const history: OperatorResponse<SourceHistoryListData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/source-history",
      redaction_level: "operator_redacted",
      data: {
        source: "self_lane",
        snapshots: [sourceSnapshot()],
        nextCursor: "history-cursor"
      }
    };
    const initial = reviewsAuthoritativeState({
      sessionStatus: "success",
      session,
      proposalsStatus: "success",
      proposals,
      historyStatus: "success",
      history
    });
    expect(initial.proposals.map((proposal) => proposal.id)).toEqual(["proposal-1"]);
    expect(initial.proposalsNextCursor).toBe("proposal-cursor");
    expect(initial.snapshots.map((snapshot) => snapshot.id)).toEqual(["snapshot-1"]);
    expect(initial.historyNextCursor).toBe("history-cursor");

    const afterBackgroundFailure = reviewsAuthoritativeState({
      sessionStatus: "success",
      session,
      proposalsStatus: "error",
      proposals,
      historyStatus: "error",
      history
    });
    expect(afterBackgroundFailure.proposals).toEqual([]);
    expect(afterBackgroundFailure.proposalsNextCursor).toBeNull();
    expect(afterBackgroundFailure.snapshots).toEqual([]);
    expect(afterBackgroundFailure.historyNextCursor).toBeNull();
  });
});

describe("capacity query authority", () => {
  it("drops retained metrics after a successful query starts failing", () => {
    const metrics: OperatorResponse<OperatorMetricsData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/metrics",
      redaction_level: "operator_redacted",
      data: {
        source: "self_lane",
        snapshot: null,
        capacity: null
      }
    };
    expect(authoritativeMetricsData("success", metrics)).toBe(metrics.data);
    expect(authoritativeMetricsData("error", metrics)).toBeNull();
  });
});

describe("dashboard retained-data projections", () => {
  it("projects server mode only from a successful active-lanes query", () => {
    for (const stateful of [true, false]) {
      const lanes: OperatorResponse<ActiveLanesData> = {
        protocol_version: "operator.v1",
        schema_version: 1,
        route: "/operator/v1/lanes",
        redaction_level: "operator_redacted",
        data: { source: "self_lane", stateful, lanes: [] }
      };
      expect(authoritativeServerMode("success", lanes)).toBe(stateful);
      expect(authoritativeServerMode("error", lanes)).toBeNull();
      expect(authoritativeServerMode("pending", lanes)).toBeNull();
    }
  });

  it("revokes session action authority when any supporting query fails", () => {
    expect(sessionAuthorityQueriesReady("success", "success", "success")).toBe(true);
    expect(sessionAuthorityQueriesReady("error", "success", "success")).toBe(false);
    expect(sessionAuthorityQueriesReady("success", "error", "success")).toBe(false);
    expect(sessionAuthorityQueriesReady("success", "success", "error")).toBe(false);
    expect(combinedQueryStatus("success", "error")).toBe("error");
    expect(combinedQueryStatus("success", "pending")).toBe("pending");
  });

  it("drops retained Explorer connection and metadata after background failures", () => {
    const connection = forwarded({
      jsonrpc: "2.0",
      id: "operator-v1",
      result: { structuredContent: { connected: true } }
    });
    const metadata = { value: { rows: [{ owner: "APP" }] } };
    expect(authoritativeExplorerConnection("success", connection)).toBe(connection);
    expect(authoritativeExplorerConnection("error", connection)).toBeUndefined();
    expect(authoritativeExplorerValue("success", metadata)).toBe(metadata.value);
    expect(authoritativeExplorerValue("error", metadata)).toBeUndefined();
    expect(
      explorerSearchAuthorityReady({
        includeObjects: true,
        objectStatus: "error",
        includeSource: false,
        sourceStatus: "success"
      })
    ).toBe(false);
    expect(
      explorerSearchAuthorityReady({
        includeObjects: false,
        objectStatus: "error",
        includeSource: true,
        sourceStatus: "success"
      })
    ).toBe(true);
  });

  it("drops retained Edition topology after a background failure", () => {
    const editions: OperatorResponse<EditionProposalsData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/edition-proposals",
      redaction_level: "operator_redacted",
      data: {
        source: "self_lane",
        proposals: [
          {
            proposal_id: "edition-1",
            base_edition: "ORA$BASE",
            child_edition: "APP_V2",
            status: "reviewing"
          }
        ]
      }
    };
    expect(authoritativeEditionData("success", editions)).toBe(editions.data);
    expect(authoritativeEditionData("error", editions)).toBeNull();
  });

  it("drops retained default-profile reachability after health failure", () => {
    const health: OperatorResponse<OperatorHealthData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/health",
      redaction_level: "operator_redacted",
      data: { source: "self_lane", readiness: { db_reachable: true } }
    };
    expect(authoritativeProfileReachability("success", health)).toBe(true);
    expect(authoritativeProfileReachability("error", health)).toBeUndefined();
  });

  it("drops retained client provenance after inventory failure", () => {
    const clients: OperatorResponse<ClientCredentialsData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/client-credentials",
      redaction_level: "operator_redacted",
      data: { source: "self_lane", clients: [] }
    };
    expect(authoritativeClientCredentials("success", clients)).toBe(clients.data);
    expect(authoritativeClientCredentials("error", clients)).toBeNull();
  });

  it("drops retained Review profiles after configuration failure", () => {
    const config: OperatorResponse<ConfigOpsStatusData> = {
      protocol_version: "operator.v1",
      schema_version: 1,
      route: "/operator/v1/config",
      redaction_level: "operator_redacted",
      data: {
        source: "self_lane",
        status: {
          target_path: "/config/oraclemcp.toml",
          target_exists: true,
          current_sha256: "sha256:config",
          profiles: [{ name: "default", is_default: true }]
        }
      }
    };
    expect(authoritativeReviewProfiles("success", config).map((profile) => profile.name)).toEqual([
      "default"
    ]);
    expect(authoritativeReviewProfiles("error", config)).toEqual([]);
  });

  it("drops retained Review lane capabilities after a background failure", () => {
    const capabilities = forwarded({
      jsonrpc: "2.0",
      id: "operator-v1",
      result: {
        structuredContent: {
          connection: { profile: "default" },
          operating_level: { current: "READ_ONLY", max: "READ_WRITE" }
        }
      }
    });
    expect(authoritativeReviewCapabilities("success", capabilities)).toBe(capabilities);
    expect(authoritativeReviewCapabilities("error", capabilities)).toBeUndefined();
  });
});

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function jsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

describe("Explorer metadata cache concurrency", () => {
  it("coalesces same-key misses, keeps byte accounting exact, and does not evict unrelated data", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-11T00:00:00Z"));
    const unrelated = { payload: "u".repeat(300_000) };
    await cachedExplorerMetadata(explorerScope, "unrelated", async () => unrelated);

    vi.advanceTimersByTime(1);
    const next = deferred<{ payload: string }>();
    const load = vi.fn(() => next.promise);
    const first = cachedExplorerMetadata(explorerScope, "same-key", load);
    const second = cachedExplorerMetadata(explorerScope, "same-key", load);
    expect(load).toHaveBeenCalledTimes(1);

    const value = { payload: "n".repeat(110_000) };
    next.resolve(value);
    const [firstResult, secondResult] = await Promise.all([first, second]);
    expect(firstResult.value).toEqual(value);
    expect(secondResult.value).toEqual(value);
    expect(explorerMetadataCacheSummary()).toEqual({
      entries: 2,
      bytes: jsonBytes(unrelated) + jsonBytes(value)
    });

    const unexpectedReload = vi.fn(async () => ({ payload: "wrong" }));
    const unrelatedHit = await cachedExplorerMetadata(
      explorerScope,
      "unrelated",
      unexpectedReload
    );
    expect(unrelatedHit.status).toBe("hit");
    expect(unexpectedReload).not.toHaveBeenCalled();
  });

  it("does not let a pre-invalidation load overwrite a newer generation", async () => {
    const oldLoad = deferred<{ generation: string }>();
    const oldResult = cachedExplorerMetadata(explorerScope, "same-key", () => oldLoad.promise);
    clearExplorerMetadataCache();

    const newLoad = deferred<{ generation: string }>();
    const newResult = cachedExplorerMetadata(explorerScope, "same-key", () => newLoad.promise);
    newLoad.resolve({ generation: "new" });
    expect((await newResult).status).toBe("miss");

    oldLoad.resolve({ generation: "old" });
    expect((await oldResult).status).toBe("bypass");
    const fallback = vi.fn(async () => ({ generation: "fallback" }));
    const current = await cachedExplorerMetadata(explorerScope, "same-key", fallback);
    expect(current).toMatchObject({ status: "hit", value: { generation: "new" } });
    expect(fallback).not.toHaveBeenCalled();
  });

  it("removes a rejected in-flight load so the next call can retry", async () => {
    const failure = deferred<{ ok: boolean }>();
    const first = cachedExplorerMetadata(explorerScope, "retry", () => failure.promise);
    failure.reject(new Error("temporary metadata failure"));
    await expect(first).rejects.toThrow("temporary metadata failure");

    const retry = vi.fn(async () => ({ ok: true }));
    await expect(cachedExplorerMetadata(explorerScope, "retry", retry)).resolves.toMatchObject({
      status: "miss",
      value: { ok: true }
    });
    expect(retry).toHaveBeenCalledTimes(1);
  });
});

describe("operator outcome decoder", () => {
  it("does not confuse an HTTP 200 JSON-RPC error with success", () => {
    const outcome = decodeOperatorOutcome(
      200,
      forwarded({
        jsonrpc: "2.0",
        id: "operator-v1",
        error: { code: -32603, message: "dispatch crashed" }
      })
    );

    expect(outcome).toMatchObject({ state: "failed", message: "dispatch crashed" });
    const markup = renderToStaticMarkup(<OperatorOutcomeNotice outcome={outcome} />);
    expect(markup).toContain('data-operator-outcome="failed"');
    expect(markup).toContain('data-outcome-tone="warn"');
    expect(markup).toContain("dispatch crashed");
  });

  it("renders a policy refusal separately from an internal failure", () => {
    const refused = decodeOperatorOutcome(
      200,
      forwarded({
        jsonrpc: "2.0",
        id: "operator-v1",
        result: {
          isError: true,
          structuredContent: {
            error_class: "CHALLENGE_REQUIRED",
            message: "confirmation is required",
            next_steps: ["preview the exact statement"]
          }
        }
      })
    );
    const failed = decodeOperatorOutcome(
      200,
      forwarded({
        jsonrpc: "2.0",
        id: "operator-v1",
        result: {
          isError: true,
          structuredContent: {
            error_class: "INTERNAL",
            message: "audit append failed"
          }
        }
      })
    );

    expect(refused.state).toBe("refused");
    expect(failed.state).toBe("failed");
    const refusedMarkup = renderToStaticMarkup(<OperatorOutcomeNotice outcome={refused} />);
    const failedMarkup = renderToStaticMarkup(<OperatorOutcomeNotice outcome={failed} />);
    expect(refusedMarkup).toContain('data-operator-outcome="refused"');
    expect(refusedMarkup).toContain('data-outcome-tone="info"');
    expect(refusedMarkup).toContain("preview the exact statement");
    expect(failedMarkup).toContain('data-operator-outcome="failed"');
    expect(failedMarkup).toContain('data-outcome-tone="warn"');
    expect(failedMarkup).toContain("audit append failed");
    expect(refusedMarkup).not.toBe(failedMarkup);
  });

  it("marks stopped proposal application partial and preserves the failed statement detail", () => {
    const outcome = decodeOperatorOutcome(
      200,
      response("/operator/v1/change-proposals/apply", {
        status: "stopped_on_failure",
        results: [
          {
            statement_index: 0,
            action_response: forwarded({
              jsonrpc: "2.0",
              id: "operator-v1",
              result: {
                isError: true,
                structuredContent: {
                  error_class: "OPERATING_LEVEL_TOO_LOW",
                  message: "READ_WRITE is required",
                  next_steps: ["preview and elevate the active lane"]
                }
              }
            })
          }
        ]
      })
    );

    expect(outcome.state).toBe("partial");
    expect(outcome.message).toContain("READ_WRITE is required");
    expect(outcome.nextSteps).toContain("preview and elevate the active lane");
    expect(renderToStaticMarkup(<OperatorOutcomeNotice outcome={outcome} />)).toContain(
      'data-operator-outcome="partial"'
    );
    expect(renderToStaticMarkup(<OperatorOutcomeNotice outcome={outcome} />)).toContain(
      'data-outcome-tone="neutral"'
    );
  });

  it("keeps true MCP and proposal successes authoritative and green", () => {
    const actionSuccesses = [
      ["/operator/v1/actions/preview", "oracle_preview_sql"],
      ["/operator/v1/actions/execute", "oracle_query"],
      ["/operator/v1/actions/execute", "oracle_execute"]
    ].map(([route, tool]) =>
      decodeOperatorOutcome(
        200,
        response(route, {
          status: "forwarded",
          mcp_tool: tool,
          mcp_response: {
            jsonrpc: "2.0",
            id: "operator-v1",
            result: { isError: false, structuredContent: { ok: true } }
          }
        })
      )
    );
    const applySuccess = decodeOperatorOutcome(
      200,
      response("/operator/v1/change-proposals/apply", {
        status: "applied",
        results: [{ statement_index: 0 }]
      })
    );

    expect(actionSuccesses.map((outcome) => outcome.state)).toEqual([
      "success",
      "success",
      "success"
    ]);
    expect(applySuccess.state).toBe("success");
    for (const successful of [...actionSuccesses, applySuccess]) {
      expect(renderToStaticMarkup(<OperatorOutcomeNotice outcome={successful} />)).toContain(
        'data-outcome-tone="ok"'
      );
    }
  });

  it("uses the HTTP status and treats accepted-without-result as partial", () => {
    expect(decodeOperatorOutcome(503, { error: "unavailable" }).state).toBe("failed");
    expect(
      decodeOperatorOutcome(
        202,
        response("/operator/v1/actions/execute", { status: "accepted", mcp_response: null })
      ).state
    ).toBe("partial");
  });
});

describe("audit timeline action correlation", () => {
  it("shows one terminal action per completed pair and keeps unmatched pending attempts", () => {
    const records = [
      auditRecord(1, "PENDING", {
        request_sha256: "sha256:complete"
      }),
      auditRecord(2, "FAILED", {
        request_sha256: "sha256:complete",
        parent_seq: 1
      }),
      auditRecord(3, "PENDING", {
        request_sha256: "sha256:crash-window"
      }),
      auditRecord(4, "SUCCEEDED")
    ];

    expect(coalesceAuditTimelineRecords(records).map((record) => record.seq)).toEqual([2, 3, 4]);
  });

  it("does not coalesce a mismatched or dangling parent link", () => {
    const records = [
      auditRecord(10, "PENDING", { request_sha256: "sha256:a" }),
      auditRecord(11, "FAILED", {
        request_sha256: "sha256:b",
        parent_seq: 10
      })
    ];

    expect(coalesceAuditTimelineRecords(records)).toHaveLength(2);
  });
});

describe("Audit query and evidence-state hardening", () => {
  it("keeps rapid typing out of the applied query until one explicit apply", async () => {
    vi.useFakeTimers();
    let state = createAuditFilterControlState();
    const appliedQueries = [JSON.stringify(state.applied)];

    for (let index = 0; index < 100; index += 1) {
      state = updateAuditFilterDraft(state, { subjectIdHash: `subject-sha256:${index}` });
      appliedQueries.push(JSON.stringify(state.applied));
    }
    await vi.advanceTimersByTimeAsync(60_000);
    expect(new Set(appliedQueries).size).toBe(1);

    state = applyAuditFilterDraft(state);
    appliedQueries.push(JSON.stringify(state.applied));
    expect(new Set(appliedQueries).size).toBe(2);
    expect(state.applied.subjectIdHash).toBe("subject-sha256:99");
  });

  it("renders true, false, and missing record hash validity as distinct states", () => {
    expect(auditHashValidity({ hash_valid: true })).toEqual({
      label: "hash ok",
      tone: "ok",
      verified: true
    });
    expect(auditHashValidity({ hash_valid: false })).toEqual({
      label: "hash fail",
      tone: "warn",
      verified: false
    });
    expect(auditHashValidity(undefined)).toEqual({
      label: "hash unverified",
      tone: "off",
      verified: null
    });
    const markup = renderToStaticMarkup(
      <>
        <AuditRecordProof proof={{ hash_valid: true }} />
        <AuditRecordProof proof={{ hash_valid: false }} />
        <AuditRecordProof proof={undefined} />
      </>
    );
    expect(markup).toContain("hash ok");
    expect(markup).toContain("hash fail");
    expect(markup).toContain("hash unverified");
  });

  it("never converts a ledger outage into zero or an empty-ledger claim", () => {
    const outage = renderToStaticMarkup(
      <>
        <AuditProofSummary data={null} pending={false} error="request failed" />
        <AuditTimelineTable records={null} pending={false} error="request failed" />
        <AuditProofBundlePanel bundle={null} pending={false} error="request failed" />
      </>
    );
    expect(outage).toContain("unavailable");
    expect(outage).not.toContain("0 actions");
    expect(outage).not.toContain("No audit records");

    const empty = renderToStaticMarkup(
      <AuditTimelineTable records={[]} pending={false} error={null} />
    );
    expect(empty).toContain("0 actions");
    expect(empty).toContain("No audit records");
  });
});

describe("Explorer identity and completion hardening", () => {
  it("keeps displayed search criteria bound to the submitted snapshot", () => {
    const controls = {
      needle: "customer",
      includeObjects: true,
      includeSource: false,
      allSchemas: false,
      sourceType: "PACKAGE",
      owner: "APP",
      maxRows: 100
    };
    const submitted = createExplorerGlobalSearchRequest(controls);

    controls.needle = "orders";
    controls.includeObjects = false;
    controls.includeSource = true;
    controls.owner = "HR";

    expect(submitted).toEqual({
      needle: "customer",
      includeObjects: true,
      includeSource: false,
      allSchemas: false,
      sourceType: "PACKAGE",
      owner: "APP",
      maxRows: 100
    });
    expect(Object.isFrozen(submitted)).toBe(true);
  });

  it("discards a reversed late detail completion after object or lane generation changes", async () => {
    const oldRequest = {
      identity: explorerDetailRequestIdentity({
        kind: "source",
        ref: { owner: "APP", name: "A", objectType: "PACKAGE" },
        lane: { laneId: "lane-a", generation: 7 },
        maxChars: 40_000,
        requestGeneration: 1
      }),
      requestGeneration: 1
    };
    const newRequest = {
      identity: explorerDetailRequestIdentity({
        kind: "ddl",
        ref: { owner: "APP", name: "B", objectType: "VIEW" },
        lane: { laneId: "lane-a", generation: 8 },
        maxChars: 40_000,
        requestGeneration: 2
      }),
      requestGeneration: 2
    };
    const oldCompletion = deferred<string>();
    const newCompletion = deferred<string>();
    let visible = "";
    const accept = async (
      pending: Promise<string>,
      binding: { identity: string; requestGeneration: number }
    ): Promise<void> => {
      const value = await pending;
      if (explorerDetailCompletionIsCurrent(binding, newRequest.identity, 2)) {
        visible = value;
      }
    };
    const oldApplied = accept(oldCompletion.promise, oldRequest);
    const newApplied = accept(newCompletion.promise, newRequest);

    newCompletion.resolve("new detail");
    await newApplied;
    oldCompletion.resolve("old detail");
    await oldApplied;

    expect(visible).toBe("new detail");
    expect(explorerDetailCompletionIsCurrent(oldRequest, newRequest.identity, 2)).toBe(false);
  });

  it("quarantines every malformed Oracle object identity and reports a bounded warning", () => {
    const decoded = decodeExplorerObjectRows([
      { owner: "APP", object_name: "ORDERS", object_type: "TABLE" },
      { object_name: "NO_OWNER", object_type: "TABLE" },
      { owner: "APP", object_type: "TABLE" },
      { owner: "APP", object_name: "NO_TYPE" },
      { owner: "   ", object_name: "BLANK_OWNER", object_type: "VIEW" }
    ]);
    const source = decodeExplorerSourceRows([
      { owner: "APP", name: "PKG", type: "PACKAGE", line: 1, text: "x" },
      { owner: "APP", name: "PKG", type: "PACKAGE", text: "missing line" }
    ]);

    expect(decoded.rows.map((row) => row.objectName)).toEqual(["ORDERS"]);
    expect(decoded.invalidCount).toBe(4);
    expect(source.rows).toHaveLength(1);
    expect(source.invalidCount).toBe(1);
    const markup = renderToStaticMarkup(
      <ExplorerObjectsPanel
        rows={decoded.rows}
        selectedRef={null}
        pending={false}
        error={null}
        invalidRows={decoded.invalidCount}
        onSelect={() => undefined}
      />
    );
    expect(markup).toContain("Ignored 4 malformed object row(s)");
    expect(markup).not.toContain("NO_OWNER");
  });

  it("uses structured tuple keys for separator-bearing quoted identifiers", () => {
    const first = objectRefKey({ owner: "A.B", name: "C", objectType: "VIEW" });
    const second = objectRefKey({ owner: "A", name: "B.C", objectType: "VIEW" });
    const third = objectRefKey({ owner: "A", name: "B", objectType: "C:VIEW" });

    expect(new Set([first, second, third]).size).toBe(3);
    expect(JSON.parse(first)).toEqual(["A.B", "C", "VIEW"]);
  });
});

describe("Review selection and one-shot grant hardening", () => {
  it("requires an exact deep-link match and never falls back to the first plan", () => {
    const proposals = [changeProposalList("first"), changeProposalList("second")];

    expect(resolveReviewSelection(proposals, "")).toBeNull();
    expect(resolveReviewSelection(proposals, "stale-id")).toBeNull();
    expect(resolveReviewSelection(proposals, "second")?.id).toBe("second");
  });

  it("keeps an exact selected proposal visible when the filter excludes it", () => {
    const selected = changeProposalList("selected", "Selected plan");
    const matching = changeProposalList("matching", "Filter match");

    expect(visibleReviewProposals([matching], selected).map((proposal) => proposal.id)).toEqual([
      "selected",
      "matching"
    ]);
    expect(visibleReviewProposals([selected, matching], selected)).toHaveLength(2);
  });

  it("binds late preview completion to the exact revision and lane generation", async () => {
    const original = changeProposal("proposal", "UPDATE accounts SET active = 0");
    const revised = {
      ...changeProposal("proposal", "UPDATE accounts SET active = 1"),
      updated_at: "unix:3"
    };
    const oldIdentity = reviewProposalRevisionIdentity(original, {
      laneId: "lane-a",
      generation: 7
    });
    const newIdentity = reviewProposalRevisionIdentity(revised, {
      laneId: "lane-a",
      generation: 8
    });
    expect(oldIdentity).not.toBe(newIdentity);
    const oldCompletion = deferred<string>();
    const newCompletion = deferred<string>();
    let confirmation = "";
    const accept = async (pending: Promise<string>, requestIdentity: string): Promise<void> => {
      const value = await pending;
      if (reviewCompletionIsCurrent(requestIdentity, newIdentity)) {
        confirmation = value;
      }
    };
    const oldApplied = accept(oldCompletion.promise, oldIdentity as string);
    const newApplied = accept(newCompletion.promise, newIdentity as string);

    newCompletion.resolve("new-grant");
    await newApplied;
    oldCompletion.resolve("old-grant");
    await oldApplied;

    expect(confirmation).toBe("new-grant");
  });

  it("consumes a grant before an apply attempt so retries require a fresh preview", () => {
    expect(reviewGrantReady(true, "one-shot-grant", true)).toBe(true);

    const afterFirstAttempt = consumedReviewGrantState();
    expect(reviewGrantReady(true, afterFirstAttempt.confirm, afterFirstAttempt.acknowledged)).toBe(
      false
    );
    const afterRetry = consumedReviewGrantState();
    expect(reviewGrantReady(true, afterRetry.confirm, afterRetry.acknowledged)).toBe(false);
  });

  it("resets pagination only for typed invalid-cursor responses", () => {
    const outcome: OperatorOutcome = {
      state: "failed",
      message: "invalid cursor",
      nextSteps: [],
      errorClass: null
    };
    const invalidCursor = new OperatorOutcomeError(
      outcome,
      response("/operator/v1/change-proposals", { error: "invalid_change_proposal" }),
      400
    );
    const transient = new OperatorOutcomeError(
      { ...outcome, message: "temporary outage" },
      response("/operator/v1/change-proposals", { error: "temporarily_unavailable" }),
      503
    );

    expect(invalidReviewCursorError(invalidCursor)).toBe(true);
    expect(invalidReviewCursorError(transient)).toBe(false);
    expect(invalidReviewCursorError(new TypeError("network failed"))).toBe(false);
  });
});

describe("Workbench submission identity hardening", () => {
  it("keeps reversed responses bound to the newest exact SQL, action, and lane generation", async () => {
    const oldContext = workbenchActionContextIdentity({
      authority: "session-a",
      source: "SELECT 1 FROM dual",
      mode: "read_query",
      lane: { laneId: "lane-a", generation: 7 },
      maxRows: 100,
      captureDbmsOutput: false
    });
    const newContext = workbenchActionContextIdentity({
      authority: "session-a",
      source: "SELECT 2 FROM dual",
      mode: "read_query",
      lane: { laneId: "lane-a", generation: 8 },
      maxRows: 100,
      captureDbmsOutput: false
    });
    const oldRequest = workbenchRequestIdentity(oldContext, "preview", 1);
    const newRequest = workbenchRequestIdentity(newContext, "read", 2);
    const oldCompletion = deferred<string>();
    const newCompletion = deferred<string>();
    let visible = "";
    const accept = async (
      pending: Promise<string>,
      requestIdentity: string,
      contextIdentity: string
    ): Promise<void> => {
      const value = await pending;
      if (
        workbenchCompletionIsCurrent(
          { requestIdentity, contextIdentity },
          newRequest,
          newContext
        )
      ) {
        visible = value;
      }
    };
    const oldApplied = accept(oldCompletion.promise, oldRequest, oldContext);
    const newApplied = accept(newCompletion.promise, newRequest, newContext);

    newCompletion.resolve("new output");
    await newApplied;
    oldCompletion.resolve("old output");
    await oldApplied;

    expect(oldContext).not.toBe(newContext);
    expect(oldRequest).not.toBe(newRequest);
    expect(visible).toBe("new output");
  });

  it("invalidates PL/SQL ranges after any source, project, or lane-generation change", () => {
    const oldInput = {
      source: "CREATE PROCEDURE p AS BEGIN NULL; END;",
      lane: { laneId: "lane-a", generation: 7 },
      projectRoot: "/workspace/old",
      target: "P",
      direction: "bidirectional" as const,
      maxDepth: 2,
      changesetJson: '{"objects":[]}'
    };
    const oldContext = workbenchIdeInputIdentity("session-a", oldInput);
    const oldRequest = workbenchRequestIdentity(oldContext, "parse", 1);
    const editedContext = workbenchIdeInputIdentity("session-a", {
      ...oldInput,
      source: "CREATE PROCEDURE q AS BEGIN NULL; END;",
      lane: { laneId: "lane-a", generation: 8 },
      projectRoot: "/workspace/new"
    });

    expect(editedContext).not.toBe(oldContext);
    expect(
      workbenchCompletionIsCurrent(
        { requestIdentity: oldRequest, contextIdentity: oldContext },
        oldRequest,
        editedContext
      )
    ).toBe(false);
  });

  it("marks only source not represented by the latest successful action as dirty", () => {
    const submitted = "SELECT employee_id FROM employees";
    const submittedIdentity = workbenchSourceIdentity(submitted);

    expect(workbenchSourceIsDirty("SELECT * FROM dual", null)).toBe(false);
    expect(workbenchSourceIsDirty(submitted, null)).toBe(true);
    expect(workbenchSourceIsDirty(submitted, submittedIdentity)).toBe(false);
    expect(workbenchSourceIsDirty(`${submitted}\n`, submittedIdentity)).toBe(true);
  });

  it("consumes a confirmation before a new attempt and never restores it after failure", () => {
    expect(reviewGrantReady(true, "old-confirmation", true)).toBe(true);
    const duringAttempt = consumedWorkbenchConfirmationState();
    expect(reviewGrantReady(true, duringAttempt.confirm, duringAttempt.acknowledged)).toBe(false);
    const afterFailure = duringAttempt;
    expect(reviewGrantReady(true, afterFailure.confirm, afterFailure.acknowledged)).toBe(false);
  });
});

describe("success-only side effects", () => {
  it("turns a bounded plain-text GET failure into an operator outcome", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(`upstream gateway failure ${"x".repeat(20_000)}`, {
          status: 502,
          statusText: "Bad Gateway",
          headers: { "content-type": "text/plain" }
        })
      )
    );

    const error = await fetchOperatorHealth().catch((candidate: unknown) => candidate);
    expect(error).toMatchObject({
      httpStatus: 502,
      outcome: {
        state: "failed",
        message: expect.stringContaining("upstream gateway failure")
      }
    });
    expect(error).toBeInstanceOf(OperatorOutcomeError);
    expect((error as OperatorOutcomeError).message).toContain("[truncated]");
    expect((error as OperatorOutcomeError).message.length).toBeLessThan(700);
  });

  it("reports an empty POST failure without leaking a JSON parser exception", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(null, {
          status: 503,
          statusText: "Service Unavailable"
        })
      )
    );

    await expect(cancelLane(session, laneATarget)).rejects.toMatchObject({
      httpStatus: 503,
      outcome: {
        state: "failed",
        message: "operator request failed with HTTP 503: Service Unavailable"
      }
    });
  });

  it("reports a non-JSON HTTP-200 body as an invalid operator response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response("not json", {
          status: 200,
          headers: { "content-type": "text/plain" }
        })
      )
    );

    await expect(cancelLane(session, laneATarget)).rejects.toMatchObject({
      httpStatus: 200,
      outcome: {
        state: "failed",
        message: "operator returned an empty or non-JSON response with HTTP 200"
      }
    });
  });

  it("sends the lane kill switch with its scoped ticket and CSRF header", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        response("/operator/v1/lanes/cancel", {
          status: "terminated",
          terminated: true,
          lane_id: "lane-a"
        })
      )
    );
    vi.stubGlobal("fetch", fetchMock);

    await cancelLane(session, laneATarget);

    expect(fetchMock).toHaveBeenCalledWith(
      "/operator/v1/lanes/cancel",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        headers: expect.objectContaining({
          "x-oraclemcp-csrf": "csrf",
          "x-oraclemcp-action-ticket": "cancel-ticket"
        }),
        body: JSON.stringify({ lane_id: "lane-a", lane_generation: 7 })
      })
    );
  });

  it("rejects malformed lane generations before issuing an operator request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      cancelLane(session, { laneId: "lane-a", generation: 0 })
    ).rejects.toThrow("positive integer generation");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("binds session elevation to the active lane generation", async () => {
    let postedBody = "";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      postedBody = String(init?.body ?? "");
      return jsonResponse(
        response("/operator/v1/session/set-level", {
          status: "applied"
        })
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    await setSessionLevel(session, {
      lane: laneATarget,
      action: "apply",
      level: "READ_WRITE",
      ttlSeconds: 120,
      confirm: "fresh-grant"
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/operator/v1/session/set-level",
      expect.objectContaining({
        body: expect.stringContaining('"lane_generation":7')
      })
    );
    expect(JSON.parse(postedBody)).toMatchObject({
      lane_id: "lane-a",
      lane_generation: 7
    });
  });

  it("rejects HTTP-200 MCP errors before a Workbench success effect can run", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          forwarded({
            jsonrpc: "2.0",
            id: "operator-v1",
            result: {
              isError: true,
              structuredContent: {
                error_class: "CHALLENGE_REQUIRED",
                message: "confirmation is required"
              }
            }
          })
        )
      )
    );
    let successEffects = 0;

    await expect(
      executeWorkbenchSql(session, {
        sql: "UPDATE accounts SET status = 'HOLD'",
        mode: "dml_preview_confirm",
        commit: true,
        confirm: "consumed-grant",
        captureDbmsOutput: false
      }).then(() => {
        successEffects += 1;
      })
    ).rejects.toMatchObject({
      outcome: { state: "refused" }
    });
    expect(successEffects).toBe(0);
  });

  it("rejects stopped proposal application before metadata invalidation can run", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          response("/operator/v1/change-proposals/apply", {
            status: "stopped_on_failure",
            results: []
          })
        )
      )
    );
    let successEffects = 0;

    await expect(
      applyChangeProposal(session, { proposalId: "proposal-1", commit: true }).then(() => {
        successEffects += 1;
      })
    ).rejects.toBeInstanceOf(OperatorOutcomeError);
    expect(successEffects).toBe(0);
  });

  it("allows the same success effect after authoritative MCP success", async () => {
    let postedBody = "";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      postedBody = String(init?.body ?? "");
      return jsonResponse(
        forwarded({
          jsonrpc: "2.0",
          id: "operator-v1",
          result: { isError: false, structuredContent: { rows_affected: 1 } }
        })
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    let successEffects = 0;

    await executeWorkbenchSql(session, {
      sql: "UPDATE accounts SET status = 'HOLD'",
      mode: "dml_preview_confirm",
      lane: laneATarget,
      commit: true,
      confirm: "fresh-grant",
      captureDbmsOutput: false
    }).then(() => {
      successEffects += 1;
    });
    expect(successEffects).toBe(1);
    expect(JSON.parse(postedBody)).toMatchObject({
      lane_id: "lane-a",
      lane_generation: 7,
      tool: "oracle_execute"
    });
  });
});

describe("frontend transport and live-data hardening", () => {
  it("does not blanket-poll static queries while explicit live telemetry keeps polling", async () => {
    vi.useFakeTimers();
    const client = createDashboardQueryClient();
    const defaultInterval = client.getDefaultOptions().queries?.refetchInterval;
    const staticRequest = vi.fn();
    const liveRequest = vi.fn();
    staticRequest();
    liveRequest();

    let staticTimer: number | undefined;
    if (typeof defaultInterval === "number") {
      staticTimer = setInterval(staticRequest, defaultInterval);
    }
    const liveTimer = setInterval(liveRequest, LIVE_TELEMETRY_REFETCH_MS);
    await vi.advanceTimersByTimeAsync(20_000);

    expect(defaultInterval).toBeUndefined();
    expect(staticRequest).toHaveBeenCalledTimes(1);
    expect(liveRequest).toHaveBeenCalledTimes(5);
    if (staticTimer) {
      clearInterval(staticTimer);
    }
    clearInterval(liveTimer);
    client.clear();
  });

  it("classifies caller cancellation and absolute timeouts without accepting stale completion", async () => {
    let resolveFetch!: (response: Response) => void;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            resolveFetch = resolve;
          })
      )
    );
    const controller = new AbortController();
    let completed = false;
    const cancelled = fetchOperatorRequest("/operator/v1/health", {}, {
      signal: controller.signal,
      timeoutMs: 60_000
    }).then(() => {
      completed = true;
    });
    const cancelledAssertion = expect(cancelled).rejects.toMatchObject({ kind: "cancelled" });
    controller.abort();
    await cancelledAssertion;
    resolveFetch(new Response("{}"));
    await Promise.resolve();
    expect(completed).toBe(false);

    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => undefined)));
    const timedOut = fetchOperatorRequest("/operator/v1/health", {}, { timeoutMs: 25 });
    const timeoutAssertion = expect(timedOut).rejects.toMatchObject({ kind: "timeout" });
    await vi.advanceTimersByTimeAsync(25);
    await timeoutAssertion;
  });

  it("keeps the absolute deadline active while a response body is hanging", async () => {
    vi.useFakeTimers();
    let bodyCancelled = false;
    vi.stubGlobal("fetch", vi.fn(async () => hangingResponse(() => { bodyCancelled = true; })));

    const response = await fetchOperatorRequest("/operator/v1/health", {}, { timeoutMs: 25 });
    const parsing = parseOperatorHttpResponse(response);
    const assertion = expect(parsing).rejects.toMatchObject({ kind: "timeout" });
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
    expect(bodyCancelled).toBe(true);
  });

  it("keeps caller cancellation active while a response body is hanging", async () => {
    let bodyCancelled = false;
    vi.stubGlobal("fetch", vi.fn(async () => hangingResponse(() => { bodyCancelled = true; })));
    const controller = new AbortController();

    const response = await fetchOperatorRequest("/operator/v1/health", {}, {
      signal: controller.signal,
      timeoutMs: 60_000
    });
    const parsing = parseOperatorHttpResponse(response);
    const assertion = expect(parsing).rejects.toMatchObject({ kind: "cancelled" });
    controller.abort();
    await assertion;
    expect(bodyCancelled).toBe(true);
  });

  it("accepts an exact-limit success body and rejects declared or streamed overflow", async () => {
    const exactBody = JSON.stringify({ ok: true });
    await expect(
      parseOperatorHttpResponse(
        new Response(exactBody, {
          headers: {
            "content-length": String(new TextEncoder().encode(exactBody).byteLength),
            "content-type": "application/json"
          }
        }),
        new TextEncoder().encode(exactBody).byteLength
      )
    ).resolves.toEqual({ ok: true });

    await expect(
      parseOperatorHttpResponse(new Response("{}", { headers: { "content-length": "9" } }), 8)
    ).rejects.toMatchObject({ kind: "body_too_large" });

    let cancelled = false;
    let sent = false;
    const streamed = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!sent) {
          sent = true;
          controller.enqueue(new TextEncoder().encode("123456789"));
        }
      },
      cancel() {
        cancelled = true;
      }
    });
    await expect(parseOperatorHttpResponse(new Response(streamed), 8)).rejects.toMatchObject({
      kind: "body_too_large"
    });
    expect(cancelled).toBe(true);
  });

  it("bounds and cancels oversized probe bodies", async () => {
    let cancelled = false;
    let sent = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!sent) {
          sent = true;
          controller.enqueue(new TextEncoder().encode("x".repeat(64 * 1024 + 1)));
        }
      },
      cancel() {
        cancelled = true;
      }
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { headers: { "content-type": "text/plain" } }))
    );

    const result = await fetchProbe({
      id: "metrics",
      label: "Metrics",
      path: "/metrics",
      kind: "public",
      group: "Runtime"
    });

    expect(cancelled).toBe(true);
    expect(result.detail.endsWith("[truncated]")).toBe(true);
    expect(result.detail.length).toBeLessThan(200);
  });

  it("enforces deterministic LRU count, byte, and TTL bounds", () => {
    let now = 0;
    const cache = new OperatorGetCache(
      { maxEntries: 2, maxBytes: 10_000, ttlMs: 10 },
      () => now
    );
    cache.set("/a", 1, "a", { value: "a" });
    cache.set("/b", 1, "b", { value: "b" });
    expect(cache.get("/a", 1)).toBeDefined();
    cache.set("/c", 1, "c", { value: "c" });
    expect(cache.get("/b", 1)).toBeUndefined();
    expect(cache.get("/a", 1)).toBeDefined();
    expect(cache.get("/c", 1)).toBeDefined();
    expect(cache.summary().entries).toBe(2);

    now = 10;
    expect(cache.summary()).toEqual({ entries: 0, bytes: 0 });

    const byteBounded = new OperatorGetCache({ maxEntries: 8, maxBytes: 32, ttlMs: 10 });
    byteBounded.set("/oversized", 1, "etag", { value: "x".repeat(256) });
    expect(byteBounded.summary()).toEqual({ entries: 0, bytes: 0 });
  });

  it("purges ETags across session epochs and never serves an old payload on 304", async () => {
    activateOperatorSession({ ...session, csrf_token: "csrf-1" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(response("/operator/v1/health", { status: "ok" })), {
          headers: { "content-type": "application/json", etag: '"health-1"' }
        })
      )
      .mockResolvedValueOnce(new Response(null, { status: 304 }))
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchOperatorHealth()).resolves.toMatchObject({
      route: "/operator/v1/health",
      data: { status: "ok" }
    });
    expect(operatorGetCacheSummary().entries).toBe(1);
    await expect(fetchOperatorHealth()).resolves.toMatchObject({
      route: "/operator/v1/health",
      data: { status: "ok" }
    });
    const cachedInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(cachedInit.headers).toHaveProperty("if-none-match", '"health-1"');
    activateOperatorSession({ ...session, csrf_token: "csrf-2" });
    expect(operatorGetCacheSummary().entries).toBe(0);

    await expect(fetchOperatorHealth()).rejects.toBeInstanceOf(OperatorOutcomeError);
    const newSessionInit = fetchMock.mock.calls[2]?.[1] as RequestInit;
    expect(newSessionInit.headers).not.toHaveProperty("if-none-match");
  });

  it("validates dashboard-session fields before they become authorization state", async () => {
    expect(validateDashboardSession(session)).toEqual(session);
    const invalidSessions: unknown[] = [
      {
        csrf_header: session.csrf_header,
        action_ticket_header: session.action_ticket_header,
        expires_unix: session.expires_unix,
        action_tickets: session.action_tickets
      },
      { ...session, csrf_token: "" },
      { ...session, expires_unix: "later" },
      { ...session, csrf_header: "bad header" },
      { ...session, action_tickets: [] },
      {
        ...session,
        action_tickets: [{ method: "post", path: "/operator/v1/actions/execute", ticket: "x" }]
      },
      {
        ...session,
        action_tickets: [{ method: "POST", path: "/outside/operator", ticket: "x" }]
      }
    ];
    for (const invalid of invalidSessions) {
      expect(() => validateDashboardSession(invalid)).toThrow(DashboardSessionProtocolError);
    }

    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ...session, expires_unix: -1 })));
    await expect(fetchDashboardSession()).rejects.toBeInstanceOf(DashboardSessionProtocolError);
  });

  it("expires dashboard authority exactly at the absolute deadline", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(100_000));
    const expiringSession = { ...session, expires_unix: 101 };
    activateOperatorSession(expiringSession);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify(response("/operator/v1/health", { secret: "bounded" })), {
          headers: { "content-type": "application/json", etag: '"health"' }
        })
      )
    );
    await fetchOperatorHealth();
    const client = createDashboardQueryClient();
    client.setQueryData(["dashboard-session"], expiringSession);
    client.setQueryData(["operator-health"], { secret: "query-cache" });
    const observer = new QueryObserver<DashboardSession>(client, {
      queryKey: ["dashboard-session"],
      enabled: false
    });
    const unsubscribe = observer.subscribe(() => undefined);

    expect(dashboardSessionIsValidAt(expiringSession, 100_999)).toBe(true);
    expect(expireDashboardAuthority(client, expiringSession, 100_999)).toBe(false);
    expect(client.getQueryData(["operator-health"])).toBeDefined();
    expect(dashboardSessionIsValidAt(expiringSession, 101_000)).toBe(false);
    expect(dashboardSessionIsValidAt(expiringSession, 101_001)).toBe(false);
    expect(expireDashboardAuthority(client, expiringSession, 101_000)).toBe(true);
    expect(client.getQueryData(["dashboard-session"])).toBeUndefined();
    expect(client.getQueryData(["operator-health"])).toBeUndefined();
    expect(observer.getCurrentResult()).toMatchObject({ status: "pending", data: undefined });
    expect(operatorGetCacheSummary().entries).toBe(0);
    vi.setSystemTime(new Date(101_000));
    const fetchMock = vi.mocked(fetch);
    const requestCount = fetchMock.mock.calls.length;
    await expect(
      executeWorkbenchSql(expiringSession, {
        sql: "UPDATE accounts SET status = 'HOLD'",
        mode: "dml_preview_confirm",
        commit: false,
        captureDbmsOutput: false
      })
    ).rejects.toBeInstanceOf(DashboardSessionProtocolError);
    expect(fetchMock).toHaveBeenCalledTimes(requestCount);
    unsubscribe();
  });

  it("preserves the mounted dashboard-session error while purging other authority", () => {
    const client = createDashboardQueryClient();
    client.setQueryData(["dashboard-session"], session);
    client.setQueryData(["operator-health"], { secret: "stale-authority" });
    const sessionQuery = client.getQueryCache().find({ queryKey: ["dashboard-session"] });
    expect(sessionQuery).toBeDefined();
    const sessionError = new Error("session endpoint unavailable");
    sessionQuery?.setState({
      ...sessionQuery.state,
      data: undefined,
      error: sessionError,
      errorUpdatedAt: Date.now(),
      status: "error"
    });
    const observer = new QueryObserver<DashboardSession>(client, {
      queryKey: ["dashboard-session"],
      enabled: false
    });
    const unsubscribe = observer.subscribe(() => undefined);

    expireDashboardAuthorityAfterSessionError(client);

    expect(observer.getCurrentResult()).toMatchObject({
      status: "error",
      error: sessionError,
      data: undefined
    });
    expect(client.getQueryData(["operator-health"])).toBeUndefined();
    unsubscribe();
  });

  it("opens SSE only for a live session, reports onopen, coalesces bursts, and closes at expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(100_000));
    const statuses: string[] = [];
    const events: unknown[] = [];
    const invalidations = vi.fn();
    let factoryCalls = 0;

    const invalidCleanup = startOperatorEventStream({
      lane: laneATarget,
      session: { ...session, expires_unix: 100 },
      onStatus: (status) => statuses.push(status),
      onEvent: (event) => events.push(event),
      onInvalidate: invalidations,
      eventSourceFactory: () => {
        factoryCalls += 1;
        throw new Error("expired sessions must not open EventSource");
      }
    });
    invalidCleanup();
    expect(factoryCalls).toBe(0);
    expect(statuses).toEqual(["closed"]);

    const listeners = new Map<string, EventListener>();
    const source = {
      readyState: 0,
      onopen: null as EventSource["onopen"],
      onmessage: null as EventSource["onmessage"],
      onerror: null as EventSource["onerror"],
      addEventListener: vi.fn((type: string, listener: EventListener) => {
        listeners.set(type, listener);
      }),
      removeEventListener: vi.fn((type: string) => {
        listeners.delete(type);
      }),
      close: vi.fn()
    } as unknown as EventSource;
    let streamUrl = "";
    const cleanup = startOperatorEventStream({
      lane: laneATarget,
      session: { ...session, expires_unix: 110 },
      onStatus: (status) => statuses.push(status),
      onEvent: (event) => events.push(event),
      onInvalidate: invalidations,
      eventSourceFactory: (url) => {
        factoryCalls += 1;
        streamUrl = url;
        return source;
      }
    });

    expect(factoryCalls).toBe(1);
    expect(streamUrl).toBe("/operator/v1/events?lane_id=lane-a&lane_generation=7");
    source.onopen?.call(source, new Event("open"));
    expect(statuses.at(-1)).toBe("live");
    expect(events).toHaveLength(0);

    const message = JSON.stringify({
      protocol_version: "operator.v1",
      event_id: "lane-a@7/1",
      event_seq: 1,
      lane_id: "lane-a",
      subject_id_hash: "sha256:subject",
      event_type: "operator.snapshot",
      data: {}
    });
    source.onmessage?.call(
      source,
      new MessageEvent("message", {
        data: message.replace("lane-a@7/1", "lane-a@6/1")
      })
    );
    source.onmessage?.call(
      source,
      new MessageEvent("message", {
        data: message.replace('"lane_id":"lane-a"', '"lane_id":"lane-b"')
      })
    );
    expect(events).toHaveLength(0);
    for (let index = 0; index < 100; index += 1) {
      source.onmessage?.call(source, new MessageEvent("message", { data: message }));
    }
    expect(events).toHaveLength(100);
    expect(invalidations).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(100);
    expect(invalidations).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(9_900);
    expect(source.close).toHaveBeenCalledTimes(1);
    expect(statuses.at(-1)).toBe("closed");
    expect(factoryCalls).toBe(1);
    cleanup();
    expect(source.close).toHaveBeenCalledTimes(1);
  });

  it("keeps workflow controls enabled during background fetches", () => {
    expect(queryActivity({ isPending: true, isFetching: true })).toEqual({
      blocking: true,
      refreshing: false
    });
    expect(queryActivity({ isPending: false, isFetching: true })).toEqual({
      blocking: false,
      refreshing: true
    });
    expect(
      queryActivity(
        { isPending: false, isFetching: false },
        { isPending: false, isFetching: true }
      )
    ).toEqual({ blocking: false, refreshing: true });
    expect(
      queryActivity({ isPending: true, isFetching: false, fetchStatus: "idle" })
    ).toEqual({ blocking: false, refreshing: false });

    const background = queryActivity({ isPending: false, isFetching: true });
    const markup = renderToStaticMarkup(
      <SourceHistoryPanel
        snapshots={[sourceSnapshot()]}
        pending={background.blocking}
        blocked={false}
        onDraftRevert={() => undefined}
        atStart
        onFirst={() => undefined}
        hasPager={false}
      />
    );
    expect(markup).toContain("Create restore plan");
    expect(markup).not.toContain("disabled=\"\"");
  });

  it("disables retained source-history actions during a background failure", () => {
    const markup = renderToStaticMarkup(
      <SourceHistoryPanel
        snapshots={[sourceSnapshot()]}
        pending={false}
        blocked
        onDraftRevert={() => undefined}
        atStart
        onFirst={() => undefined}
        hasPager={false}
      />
    );
    expect(markup).toContain("Create restore plan");
    expect(markup).toContain("disabled=\"\"");
  });

  it("uses the dedicated typed transport error for bounded failures", () => {
    const error = new OperatorHttpClientError("timeout", "operator request timed out");
    expect(error).toBeInstanceOf(Error);
    expect(error.kind).toBe("timeout");
  });
});
