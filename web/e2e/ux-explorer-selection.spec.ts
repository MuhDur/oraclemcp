import { expect, test, type Page } from "@playwright/test";

function operatorEnvelope(path: string, data: Record<string, unknown>): string {
  return JSON.stringify({
    protocol_version: "operator.v1",
    schema_version: 1,
    route: path,
    redaction_level: "operator_redacted",
    data
  });
}

function actionResult(tool: string, structuredContent: Record<string, unknown>): Record<string, unknown> {
  return {
    status: "forwarded",
    mcp_tool: tool,
    mcp_response: {
      jsonrpc: "2.0",
      id: "operator-v1",
      result: { isError: false, structuredContent }
    }
  };
}

async function stubExplorerDashboard(page: Page): Promise<void> {
  const lane = {
    lane_id: "lane-explorer",
    generation: 1,
    status: "active",
    subject_id_hash: "subject-sha256-test"
  };
  await page.route("**/dashboard/session", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        csrf_token: "csrf-test",
        csrf_header: "x-oraclemcp-csrf",
        action_ticket_header: "x-oraclemcp-action-ticket",
        expires_unix: 4_102_444_800,
        action_tickets: [
          {
            method: "POST",
            path: "/operator/v1/actions/execute",
            ticket: "ticket-explorer-test"
          }
        ]
      })
    });
  });
  await page.route("**/operator/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/operator/v1/events") {
      await route.fulfill({ status: 204, body: "" });
      return;
    }
    if (path === "/operator/v1/actions/execute") {
      const request = route.request().postDataJSON() as {
        tool?: string;
        arguments?: { name_like?: string | null };
      };
      const tool = request.tool ?? "unknown";
      const structuredContent =
        tool === "oracle_connection_info"
          ? {
              connected: true,
              metadata_cache_key: {
                db_fingerprint: "db-test",
                profile: "dev_ro",
                user: "HR",
                visible_schema: "HR",
                serialization_contract_version: 1
              }
            }
          : tool === "oracle_list_schemas"
            ? { schemas: [] }
            : tool === "oracle_search_objects"
              ? request.arguments?.name_like === "%payroll%"
                ? {
                    results: [
                      {
                        owner: "HR",
                        object_name: "PAYROLL_API",
                        object_type: "PACKAGE",
                        status: "VALID",
                        num_rows: "0",
                        column_count: "0",
                        last_analyzed: "2026-08-02",
                        comment: "Payroll package"
                      }
                    ]
                  }
                : { results: [] }
              : tool === "oracle_search_source"
                ? {
                    matches: [
                      {
                        owner: "HR",
                        name: "PAYROLL_API",
                        type: "PACKAGE",
                        line: "42",
                        text: "procedure reconcile_payroll is"
                      },
                      {
                        owner: "HR",
                        name: "PAYROLL_API",
                        type: "PACKAGE",
                        line: "43",
                        text: "end reconcile_payroll;"
                      }
                    ]
                  }
                : tool === "oracle_get_ddl"
                  ? { ddl: "create package HR.PAYROLL_API as end;" }
                  : {};
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: operatorEnvelope(path, actionResult(tool, structuredContent))
      });
      return;
    }
    const data =
      path === "/operator/v1/active-lanes"
        ? { source: "self_lane", stateful: true, lanes: [lane] }
        : path === "/operator/v1/config"
          ? {
              source: "config_ops",
              status: {
                target_path: "/config/profiles.toml",
                target_exists: true,
                current_sha256: "sha256:test",
                default_profile: "dev_ro",
                profiles: [],
                dashboard_workbench: false
              }
            }
          : path === "/operator/v1/health"
            ? {
                source: "self",
                readiness: {
                  status: "ready",
                  ready: true,
                  db_reachable: true,
                  draining: false
                }
              }
            : path === "/operator/v1/metrics"
              ? { source: "self", snapshot: null, capacity: null }
              : { source: "unavailable" };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: operatorEnvelope(path, data)
    });
  });
}

test("Explorer global matches announce the exact selected hit and clear prior details", async ({ page }) => {
  await stubExplorerDashboard(page);
  await page.goto("/explorer");

  const search = page.getByRole("button", { name: "Search" });
  await page.getByLabel("Search term").fill("payroll");
  await expect(search).toBeEnabled();
  await search.click();

  const objectHit = page.getByRole("button", {
    name: "Select HR.PAYROLL_API (PACKAGE) for details"
  });
  const sourceHit = page.getByRole("button", {
    name: "Select HR.PAYROLL_API (PACKAGE, line 42) for details"
  });
  const secondSourceHit = page.getByRole("button", {
    name: "Select HR.PAYROLL_API (PACKAGE, line 43) for details"
  });
  await expect(objectHit).toBeVisible();
  await expect(sourceHit).toBeVisible();

  await objectHit.click();
  await expect(objectHit).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("explorer-global-selection")).toHaveText(
    "Selected HR.PAYROLL_API (PACKAGE). Details are available below."
  );

  await page.getByRole("button", { name: "View creation DDL" }).click();
  await expect(page.getByText("create package HR.PAYROLL_API as end;", { exact: true })).toBeVisible();

  await sourceHit.click();
  await expect(sourceHit).toHaveAttribute("aria-pressed", "true");
  await expect(objectHit).toHaveAttribute("aria-pressed", "false");
  await expect(secondSourceHit).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByText("create package HR.PAYROLL_API as end;", { exact: true })).toHaveCount(0);
});
