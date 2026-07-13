// Served-console E2E (Arc L, oraclemcp-rxf6): prove the shipped affordances
// against a REAL served backend — no mocks, no fixtures.
//
// This spawns the real `oraclemcp serve` binary over Streamable HTTP, pairs with
// its operator surface exactly the way the browser does (the `om dashboard`
// pairing URL → the `oraclemcp_dashboard_session` cookie), drives real MCP tool
// calls and real operator API requests, and feeds every response through the
// ACTUAL console parsers the dashboard ships (`operator-client.ts` +
// `presentation-model.ts`). The assertions are the honesty bar the console set
// for itself: a real ceiling is shown, a real refusal is a refusal, and where
// the backend does not emit a field the console says so rather than inventing a
// healthy state.
//
// It is gated on OMCP_SERVED_E2E=1 and skips otherwise, so a machine without the
// built binary (or without permission to open a loopback port) does not fail the
// unit suite. scripts/e2e/served_console.sh sets the flag and the binary path.

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  parseFleetMap,
  parseMaskCertificate,
  parsePolicyTightening,
  parseQueryCostRefusal,
  parseVerdictProofs,
  profileCostCeiling,
  type AuditTailData,
  type ConfigOpsStatusData,
  type WorkbenchActionData
} from "./operator-client";
import {
  toCostBadgeViewModel,
  toFleetMapViewModel,
  toMaskBadgeViewModel,
  toPolicyBadgeViewModel,
  toVerdictProofViewModel
} from "./presentation-model";

const ENABLED = process.env.OMCP_SERVED_E2E === "1";
const BIN = process.env.OMCP_BIN ?? "";
const PORT = Number(process.env.OMCP_SERVED_PORT ?? "7393");
const BASE = `http://127.0.0.1:${PORT}`;
// When a live Oracle is configured, a real SELECT produces a real proof-carrying
// record and the positive-path proofs run. Otherwise only the honest negatives.
const LIVE_DSN = process.env.OMCP_LIVE_DSN ?? "";
const LIVE_USER = process.env.OMCP_LIVE_USER ?? "";
const LIVE_CRED = process.env.OMCP_LIVE_CRED ?? "";
const LIVE = LIVE_DSN !== "";

type Cookie = string;

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body)
  });
}

/** One MCP tools/call over the real Streamable HTTP transport. */
async function mcp(name: string, args: Record<string, unknown>): Promise<WorkbenchActionData> {
  const res = await post(
    "/mcp",
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } },
    { "mcp-protocol-version": "2025-06-18" }
  );
  const json = (await res.json()) as {
    result?: { structuredContent?: Record<string, unknown>; isError?: boolean };
  };
  // The console never sees the raw JSON-RPC envelope: the operator action
  // forwarder hands its WorkbenchActionData.mcp_response the tool's structured
  // payload. Mirror that exactly, so the real parsers consume what they consume
  // in the browser. `isError` is preserved so a refusal is still legible.
  const structured = json.result?.structuredContent ?? {};
  return {
    status: "ok",
    mcp_tool: name,
    mcp_response: { ...structured, isError: json.result?.isError === true }
  } as WorkbenchActionData;
}

let server: ChildProcess | undefined;
let cookie: Cookie = "";
let workdir = "";

async function waitReady(): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const res = await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) {
        return;
      }
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("served backend never became ready");
}

/** Pair with the operator surface the way the browser does. */
async function pair(): Promise<void> {
  const minted = spawnSync(BIN, ["dashboard", "--url", BASE, "--no-open"], {
    env: { ...process.env, ORACLEMCP_CONFIG: join(workdir, "config.toml") },
    encoding: "utf8"
  });
  const url = minted.stdout.trim().split("\n").pop() ?? "";
  expect(url, "om dashboard should mint a pairing URL").toContain("/dashboard/pair?ticket=");
  // The pairing GET 303-redirects and sets the session cookie on that response.
  const res = await fetch(url, { redirect: "manual" });
  const setCookie = res.headers.get("set-cookie") ?? "";
  const match = /oraclemcp_dashboard_session=[^;]+/.exec(setCookie);
  expect(match, "pairing should set the dashboard session cookie").not.toBeNull();
  cookie = match![0];
}

async function operatorGet<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { headers: { accept: "application/json", cookie } });
  expect(res.status, `${path} should be authorized after pairing`).toBe(200);
  return (await res.json()) as T;
}

beforeAll(async () => {
  if (!ENABLED) {
    return;
  }
  expect(BIN, "OMCP_BIN must point at the built oraclemcp binary").not.toBe("");
  workdir = mkdtempSync(join(tmpdir(), "omcp-served-console-"));
  // The default "reader" profile points at a live DB when OMCP_LIVE_DSN is set,
  // so a real SELECT executes and produces a REAL proof-carrying audit record
  // (verdict certificate + observed_scn). Without a live DB it points at a dead
  // address, and the suite proves the honest negatives instead. Either way the
  // "unreachable" profile is a genuinely dead lane for the fleet map, and
  // "capped" carries a real cost ceiling for the config badge.
  const readerDsn = LIVE_DSN || "127.0.0.1:1599/NOPE";
  const readerUser = LIVE_USER || "e2e_reader";
  const readerCred = LIVE_CRED || "not-a-real-password";
  const config = `schema_version = 2
default_profile = "reader"

[http]
json_response = true

[audit]
path = "${join(workdir, "audit.jsonl")}"
key_ref = "literal:0123456789abcdef0123456789abcdef"
key_id = "e2e"

[[profiles]]
name = "reader"
connect_string = "${readerDsn}"
username = "${readerUser}"
credential_ref = "literal:${readerCred}"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[[profiles]]
name = "capped"
connect_string = "${readerDsn}"
username = "${readerUser}"
credential_ref = "literal:${readerCred}"
max_level = "READ_ONLY"
max_query_cost = 50000

[[profiles]]
name = "unreachable"
connect_string = "127.0.0.1:1598/GONE"
username = "e2e_reader"
credential_ref = "literal:not-a-real-password"
max_level = "READ_ONLY"
`;
  writeFileSync(join(workdir, "config.toml"), config);
  server = spawn(BIN, ["serve", "--listen", `127.0.0.1:${PORT}`, "--allow-no-auth"], {
    env: { ...process.env, ORACLEMCP_CONFIG: join(workdir, "config.toml") },
    stdio: "ignore"
  });
  await waitReady();
  await pair();
}, 60_000);

afterAll(() => {
  server?.kill("SIGTERM");
  if (workdir) {
    rmSync(workdir, { recursive: true, force: true });
  }
});

describe.runIf(ENABLED)("shipped console affordances against a served backend", () => {
  it("cost badge shows the REAL ceiling the operator config publishes", async () => {
    const envelope = await operatorGet<{ data: ConfigOpsStatusData }>("/operator/v1/config");
    const config = envelope.data;
    const ceiling = profileCostCeiling(config, "capped");
    // The number is real — it came off /operator/v1/config, not a refusal.
    expect(ceiling.ceiling).toBe(50_000);
    expect(ceiling.source).toBe("config");

    const badge = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: ceiling.ceiling,
      ceilingSource: ceiling.source,
      ungated: ceiling.ungated
    });
    expect(badge.verdict).toBe("within_ceiling");
    expect(badge.ceiling).toBe(50_000);

    // The second profile declares no ceiling: the console must say "ungated",
    // not invent an unlimited or zero budget.
    const ungated = profileCostCeiling(config, "unreachable");
    expect(ungated.ungated).toBe(true);
    expect(toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: ungated.ceiling,
      ceilingSource: ungated.source,
      ungated: ungated.ungated
    }).verdict).toBe("ungated");
  });

  it("the guard REALLY refuses a DDL statement at READ_ONLY", async () => {
    const drop = ["DROP", "TABLE", "hr.employees"].join(" ");
    const response = await mcp("oracle_execute", { sql: drop, commit: false });
    const payload = response.mcp_response as { error_class?: string };
    // A real refusal from the real classifier + level gate — no cost refusal here.
    expect(payload.error_class).toBe("OPERATING_LEVEL_TOO_LOW");
    expect(parseQueryCostRefusal(response.mcp_response)).toBeNull();
  });

  it("verdict-proof inspector: real proof when the DB completes a read, honest absence otherwise", async () => {
    if (LIVE) {
      // A real governed SELECT executed against the live DB, so the audit tail
      // now carries a REAL proof-carrying record. The inspector must render it
      // as VERIFIED — every client-side check (audit binding, statement digest,
      // rule registry, chain hash) passing against real bytes.
      await mcp("oracle_query", { sql: "SELECT 1 AS one FROM dual" });
    }
    const tail = await operatorGet<{ data: AuditTailData }>("/operator/v1/audit-tail?limit=10");
    expect(tail.data.source).toBe("self_lane");
    const proofs = parseVerdictProofs(tail.data);
    expect(proofs.source).toBe("self_lane");
    // The parser never fabricates: every record is either a rendered proof or is
    // counted as uncertified.
    expect(proofs.proofs.length + proofs.uncertified).toBe(tail.data.records.length);

    if (LIVE) {
      expect(proofs.proofs.length).toBeGreaterThan(0);
      const proof = proofs.proofs[0];
      const model = toVerdictProofViewModel(proof);
      // The REAL certificate verifies end to end through the console's own checks.
      expect(model.proofStatus).toBe("verified");
      expect(model.certHash).not.toBe("");
      expect(model.auditHash).not.toBeNull();
      expect(model.derivation.every((step) => step.registered)).toBe(true);
      expect(model.checks.every((check) => check.ok)).toBe(true);
    } else {
      for (const proof of proofs.proofs) {
        expect(proof.certHash).not.toBe("");
        expect(proof.auditHash).not.toBeNull();
      }
    }
  });

  it.runIf(LIVE)("SCN scrubber binds to a REAL observed_scn from a completed read", async () => {
    await mcp("oracle_query", { sql: "SELECT 1 AS one FROM dual" });
    const tail = await operatorGet<{ data: AuditTailData }>("/operator/v1/audit-tail?limit=10");
    // The proof carries the exact SCN the read observed — a real forensic handle,
    // not a fabricated timeline. The scrubber consumes exactly this field.
    const proofs = parseVerdictProofs(tail.data);
    const withScn = proofs.proofs.map((p) => toVerdictProofViewModel(p)).find((m) => m.observedScn);
    expect(withScn, "a completed read records an observed SCN").toBeTruthy();
    expect(Number(withScn!.observedScn)).toBeGreaterThan(0);
  });

  it("egress mask badge treats 'no certificate' as absence of proof, not proof of no masking", async () => {
    // A read the server refused (no live DB) carries no mask certificate. The
    // badge must render no_certificate — NOT a reassuring 'nothing was masked'.
    const read = await mcp("oracle_query", { sql: "SELECT 1 FROM dual", max_rows: 1 });
    const badge = toMaskBadgeViewModel(parseMaskCertificate(read));
    expect(badge.status).toBe("no_certificate");
    expect(badge.maskedColumns).toBe(0);
    expect(badge.detail).toContain("not proof that nothing was masked");
  });

  it("fleet map shows every lane — the UNREACHABLE one visible and drift-unknown", async () => {
    const orient = await mcp("oracle_orient", { fleet: true, include: ["schema", "freshness"] });
    const model = toFleetMapViewModel(parseFleetMap(orient));

    if (LIVE) {
      // The active lane is up, so the real federated map lists every profile.
      // The dead "unreachable" lane is a VISIBLE node, not dropped, and carries
      // no drift verdict because nothing was read from it.
      const unreachable = model.nodes.find((node) => node.dbId === "unreachable");
      expect(unreachable, "the dead lane must stay on the map").toBeTruthy();
      expect(unreachable!.status).toBe("unreachable");
      expect(unreachable!.drift).toBeNull();
      expect(model.nodes.length).toBe(model.profileCount);
      expect(model.reachableCount).toBeGreaterThan(0);
      expect(model.unreachableCount).toBe(1);
    } else {
      // With the active lane's DB down, oracle_orient returns a whole-tool
      // CONNECTION_FAILED — no per-lane map. The parser yields ZERO nodes rather
      // than a green "0 issues" fleet, and the App surfaces the error notice.
      const result = orient.mcp_response as { isError?: boolean };
      expect(result.isError).toBe(true);
      expect(model.nodes).toHaveLength(0);
      expect(model.reachableCount).toBe(0);
    }
  });

  it("policy badge reports 'not reported' honestly when the response carries no verdict", async () => {
    // The gated profile carries no policy verdict on a refused statement, so the
    // badge must NOT claim 'no policy applied' — it says the verdict was not
    // reported, which is a different, honest statement.
    const drop = ["DROP", "TABLE", "hr.employees"].join(" ");
    const response = await mcp("oracle_execute", { sql: drop, commit: false });
    const badge = toPolicyBadgeViewModel(parsePolicyTightening(response.mcp_response));
    expect(["not_reported", "evaluated"]).toContain(badge.status);
    if (badge.status === "not_reported") {
      expect(badge.detail).toContain("not a statement that no policy applied");
    }
  });
});
