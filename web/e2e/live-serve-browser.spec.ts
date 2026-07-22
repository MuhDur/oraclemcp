import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { test, expect, type Page } from "@playwright/test";

const BIN = process.env.OMCP_BIN ?? "";
const ENABLED = process.env.OMCP_BROWSER_LANE === "1";
const ARTIFACT_ROOT = process.env.OMCP_BROWSER_LANE_ARTIFACT_DIR ?? "../target/e2e/browser-lane";

test.skip(!ENABLED, "set OMCP_BROWSER_LANE=1 to run the live serve browser lane");
test.setTimeout(60_000);

type DashboardActionTicket = {
  method: string;
  path: string;
  ticket: string;
};

type DashboardSession = {
  csrf_token: string;
  csrf_header: string;
  action_ticket_header: string;
  action_tickets: DashboardActionTicket[];
};

type JsonFetchResult = {
  status: number;
  headers: Record<string, string>;
  body: unknown;
};

type PairingOutcome = {
  paired: boolean;
  status: number;
  origin: string | undefined;
  body: string;
};

let server: ChildProcess | undefined;
let baseUrl = "";
let configPath = "";
let runDir = "";
let serverLog = "";

async function freeLoopbackPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const listener = createServer();
    listener.on("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const address = listener.address();
      if (address === null || typeof address === "string") {
        listener.close(() => reject(new Error("failed to allocate a TCP port")));
        return;
      }
      const port = address.port;
      listener.close(() => resolve(port));
    });
  });
}

async function waitReady(): Promise<void> {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const res = await fetch(`${baseUrl}/healthz`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) {
        return;
      }
    } catch {
      // The listener is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`oraclemcp serve did not become ready; log=${serverLog}`);
}

function writeConfig(): void {
  mkdirSync(runDir, { recursive: true });
  for (const dir of ["home", "config", "state", "cache", "runtime"]) {
    mkdirSync(join(runDir, dir), { recursive: true });
  }
  configPath = join(runDir, "oraclemcp.toml");
  writeFileSync(
    configPath,
    `schema_version = 2

[http]
json_response = true
allowed_hosts = ["${baseUrl.replace("http://", "")}"]
allowed_origins = ["${baseUrl}"]

[audit]
path = "${join(runDir, "audit.jsonl")}"
key_ref = "literal:0123456789abcdef0123456789abcdef"
key_id = "browser-lane"
`,
    "utf8"
  );
}

function isolatedEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HOME: join(runDir, "home"),
    XDG_CONFIG_HOME: join(runDir, "config"),
    XDG_STATE_HOME: join(runDir, "state"),
    XDG_CACHE_HOME: join(runDir, "cache"),
    XDG_RUNTIME_DIR: join(runDir, "runtime"),
    ORACLEMCP_CONFIG: configPath
  };
}

function startServer(): void {
  serverLog = join(runDir, "serve.log");
  server = spawn(BIN, ["serve", "--listen", baseUrl.replace("http://", ""), "--allow-no-auth"], {
    env: isolatedEnv(),
    stdio: ["ignore", "pipe", "pipe"]
  });
  server.stdout?.on("data", (chunk) => appendFileSync(serverLog, chunk));
  server.stderr?.on("data", (chunk) => appendFileSync(serverLog, chunk));
}

function mintPairingTicket(): { url: string; pairing_code: string } {
  const stdout = execFileSync(BIN, ["--json", "dashboard", "--url", baseUrl, "--no-open"], {
    env: isolatedEnv(),
    encoding: "utf8"
  });
  const payload = JSON.parse(stdout.trim().split("\n").pop() ?? "{}") as {
    url?: string;
    pairing_code?: string;
  };
  expect(payload.url, "dashboard should mint a pairing URL").toContain("/dashboard/pair");
  expect(payload.pairing_code, "dashboard should mint a one-time pairing code").toBeTruthy();
  expect(payload.url, "pairing URL must not carry the bootstrap secret").not.toContain(payload.pairing_code);
  return { url: payload.url ?? "", pairing_code: payload.pairing_code ?? "" };
}

async function pairBrowser(page: Page): Promise<PairingOutcome> {
  const ticket = mintPairingTicket();
  const pairingPost = page.waitForResponse(
    (response) =>
      response.url() === ticket.url &&
      response.request().method() === "POST"
  );
  await page.goto(ticket.url);
  await page.locator('input[name="pairing_code"]').fill(ticket.pairing_code);
  await page.locator('button[type="submit"]').click();
  const postResponse = await pairingPost;
  const headers = await postResponse.request().allHeaders();
  const status = postResponse.status();
  const body = status === 303 ? "" : await postResponse.text();
  expect(status, `pairing form POST should redirect after setting the session: body=${body}`).toBe(303);
  await page.waitForURL(`${baseUrl}/`);
  return {
    paired: true,
    status: postResponse.status(),
    origin: headers.origin,
    body
  };
}

async function dashboardSession(page: Page): Promise<DashboardSession> {
  const result = await page.evaluate(async (): Promise<JsonFetchResult> => {
    const res = await fetch("/dashboard/session", {
      headers: { accept: "application/json" },
      credentials: "same-origin"
    });
    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: await res.json()
    };
  });
  expect(result.status, "/dashboard/session should be authorized after pairing").toBe(200);
  return result.body as DashboardSession;
}

async function executeCapabilities(page: Page, session: DashboardSession): Promise<JsonFetchResult> {
  const ticket = session.action_tickets.find(
    (candidate) => candidate.method === "POST" && candidate.path === "/operator/v1/actions/execute"
  );
  expect(ticket, "dashboard session should include an execute action ticket").toBeTruthy();
  return page.evaluate(
    async ({ csrfHeader, csrfToken, ticketHeader, actionTicket }) => {
      const res = await fetch("/operator/v1/actions/execute", {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          [csrfHeader]: csrfToken,
          [ticketHeader]: actionTicket
        },
        credentials: "same-origin",
        body: JSON.stringify({
          idempotency_key: `browser-lane-${crypto.randomUUID()}`,
          tool: "oracle_capabilities",
          arguments: { detail_level: "compact" }
        })
      });
      return {
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        body: await res.json()
      };
    },
    {
      csrfHeader: session.csrf_header,
      csrfToken: session.csrf_token,
      ticketHeader: session.action_ticket_header,
      actionTicket: ticket?.ticket ?? ""
    }
  );
}

async function observeSseResume(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    return new Promise<string[]>((resolve, reject) => {
      const ids: string[] = [];
      const source = new EventSource("/operator/v1/events");
      const timeout = window.setTimeout(() => {
        source.close();
        reject(new Error(`timed out waiting for SSE resume; received=${ids.join(",")}`));
      }, 15_000);
      source.addEventListener("operator.snapshot", (event) => {
        const message = event as MessageEvent;
        const data = JSON.parse(message.data) as { event_id?: string };
        ids.push(message.lastEventId || data.event_id || "");
        if (ids.length >= 2) {
          window.clearTimeout(timeout);
          source.close();
          resolve(ids);
        }
      });
    });
  });
}

test.beforeAll(async () => {
  expect(BIN, "OMCP_BIN must point at the built oraclemcp binary").toBeTruthy();
  const port = process.env.OMCP_BROWSER_LANE_PORT
    ? Number(process.env.OMCP_BROWSER_LANE_PORT)
    : await freeLoopbackPort();
  baseUrl = `http://127.0.0.1:${port}`;
  runDir = join(ARTIFACT_ROOT, `run-${Date.now()}-${randomUUID()}`);
  writeConfig();
  startServer();
  await waitReady();
});

test.afterAll(() => {
  server?.kill("SIGTERM");
});

test("Chromium pairs, performs an authenticated operator action, and resumes SSE", async ({
  page
}) => {
  const pairing = await pairBrowser(page);
  const session = await dashboardSession(page);

  const action = await executeCapabilities(page, session);
  expect(action.status, "authenticated browser action POST should return 200, not 403").toBe(200);
  expect((action.body as { data?: { mcp_tool?: string } }).data?.mcp_tool).toBe("oracle_capabilities");

  const resumed = await observeSseResume(page);
  expect(resumed[0], "first EventSource delivery should start the operator stream").toBe("operator/1");
  expect(resumed[1], "Chromium should reconnect with Last-Event-ID and receive only the next event").toBe(
    "operator/2"
  );
  writeFileSync(
    join(runDir, "browser-lane-result.json"),
    JSON.stringify(
      {
        browser_pairing: pairing,
        action_status: action.status,
        action_tool: (action.body as { data?: { mcp_tool?: string } }).data?.mcp_tool,
        sse_event_ids: resumed
      },
      null,
      2
    ),
    "utf8"
  );
});

test("C4: Chromium pairing and authenticated action POST are enforced", async ({ page }) => {
  const pairing = await pairBrowser(page);
  const session = await dashboardSession(page);

  const action = await executeCapabilities(page, session);
  expect(action.status, "authenticated browser action POST should return 200, not 403").toBe(200);
  expect((action.body as { data?: { mcp_tool?: string } }).data?.mcp_tool).toBe("oracle_capabilities");
  writeFileSync(
    join(runDir, "c4-browser-flow-result.json"),
    JSON.stringify(
      {
        browser_pairing: pairing,
        action_status: action.status,
        action_tool: (action.body as { data?: { mcp_tool?: string } }).data?.mcp_tool
      },
      null,
      2
    ),
    "utf8"
  );
});
