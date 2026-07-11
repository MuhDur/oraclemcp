import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OperatorOutcomeNotice } from "./App";
import {
  OperatorOutcomeError,
  applyChangeProposal,
  cachedExplorerMetadata,
  clearExplorerMetadataCache,
  decodeOperatorOutcome,
  executeWorkbenchSql,
  explorerMetadataCacheSummary,
  type DashboardSession,
  type ExplorerMetadataCacheKey,
  type OperatorResponse,
  type WorkbenchActionData
} from "./operator-client";

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
    }
  ]
};

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

afterEach(() => {
  clearExplorerMetadataCache();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const explorerScope: ExplorerMetadataCacheKey = {
  db_fingerprint: "db-fingerprint",
  profile: "db_ro",
  user: "APP_USER",
  visible_schema: "APP",
  serialization_contract_version: 1
};

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

describe("success-only side effects", () => {
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
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          forwarded({
            jsonrpc: "2.0",
            id: "operator-v1",
            result: { isError: false, structuredContent: { rows_affected: 1 } }
          })
        )
      )
    );
    let successEffects = 0;

    await executeWorkbenchSql(session, {
      sql: "UPDATE accounts SET status = 'HOLD'",
      mode: "dml_preview_confirm",
      commit: true,
      confirm: "fresh-grant",
      captureDbmsOutput: false
    }).then(() => {
      successEffects += 1;
    });
    expect(successEffects).toBe(1);
  });
});
