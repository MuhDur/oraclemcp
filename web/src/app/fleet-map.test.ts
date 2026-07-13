import { describe, expect, it } from "vitest";

import { toFleetMapViewModel } from "./presentation-model";
import { parseFleetMap, type WorkbenchActionData } from "./operator-client";

// Arc H fleet map. `oracle_orient fleet=true` types every lane REACHABLE /
// UNREACHABLE / FAIL_CLOSED precisely so one dead database never omits or fails
// the others. The console honors that: a lane it could not read stays on the
// map, with its error, and is never reported as drift-free.

const action = (mcp: Record<string, unknown>): WorkbenchActionData => ({
  status: "ok",
  mcp_tool: "oracle_orient",
  mcp_response: mcp
});

const FLEET = {
  profiles: [
    {
      profile: "prod_read",
      status: "REACHABLE",
      connection: {
        server_version: "23.4.0.0",
        database_role: "PRIMARY",
        open_mode: "READ WRITE",
        read_only: false,
        pool_open_connections: 2
      },
      drift: {
        baseline_profile: "prod_read",
        schema_changed: false,
        foreign_keys_changed: false,
        freshness_changed: false,
        recent_ddl_changed: false
      }
    },
    {
      profile: "staging",
      status: "REACHABLE",
      connection: {
        server_version: "21.3.0.0",
        database_role: "PRIMARY",
        open_mode: "READ WRITE",
        read_only: false,
        pool_open_connections: 1
      },
      drift: {
        baseline_profile: "prod_read",
        schema_changed: true,
        foreign_keys_changed: false,
        freshness_changed: false,
        recent_ddl_changed: true
      }
    },
    {
      profile: "dr_site",
      status: "UNREACHABLE",
      error: {
        code: "UNREACHABLE",
        message: "profile connection or orientation metadata is unavailable"
      }
    },
    {
      profile: "locked_down",
      status: "FAIL_CLOSED",
      error: { code: "FAIL_CLOSED", message: "profile is not admissible for this subject" }
    }
  ],
  summary: {
    profile_count: 4,
    reachable_count: 2,
    unreachable_count: 1,
    fail_closed_count: 1
  }
};

describe("fleet map parsing", () => {
  it("keeps every lane the server typed, including the ones it could not read", () => {
    const input = parseFleetMap(action(FLEET));
    expect(input.profiles.map((profile) => profile.profile)).toEqual([
      "prod_read",
      "staging",
      "dr_site",
      "locked_down"
    ]);
    expect(input.summary).toEqual({
      profileCount: 4,
      reachableCount: 2,
      unreachableCount: 1,
      failClosedCount: 1
    });
    const dr = input.profiles[2];
    expect(dr.status).toBe("unreachable");
    expect(dr.errorCode).toBe("UNREACHABLE");
    expect(dr.drift).toBeNull();
  });

  it("reads the connection evidence and the drift flags of a reachable lane", () => {
    const staging = parseFleetMap(action(FLEET)).profiles[1];
    expect(staging.serverVersion).toBe("21.3.0.0");
    expect(staging.databaseRole).toBe("PRIMARY");
    expect(staging.poolOpenConnections).toBe(1);
    expect(staging.drift?.baselineProfile).toBe("prod_read");
    expect(staging.drift?.changedSections).toEqual(["schema", "recent_ddl"]);
  });

  it("drops a lane whose status the console cannot decode", () => {
    // An unknown status must not be quietly rendered as reachable.
    const input = parseFleetMap(
      action({ profiles: [{ profile: "mystery", status: "SCHRODINGER" }] })
    );
    expect(input.profiles).toHaveLength(0);
  });
});

describe("fleet map view-model", () => {
  it("renders an unreachable database as a node, never as a gap", () => {
    const model = toFleetMapViewModel(parseFleetMap(action(FLEET)));
    expect(model.nodes).toHaveLength(4);
    expect(model.profileCount).toBe(4);

    const dr = model.nodes.find((node) => node.dbId === "dr_site");
    expect(dr?.status).toBe("unreachable");
    expect(dr?.detail).toContain("unavailable");
    // Crucially: no drift verdict at all for a lane nothing was read from.
    expect(dr?.drift).toBeNull();

    const locked = model.nodes.find((node) => node.dbId === "locked_down");
    expect(locked?.status).toBe("fail_closed");
    expect(locked?.errorMessage).toContain("not admissible");

    expect(model.unreachableCount).toBe(1);
    expect(model.failClosedCount).toBe(1);
    expect(model.headline).toContain("degraded");
    expect(model.tone).toBe("warn");
  });

  it("names the drifted sections of a reachable lane against the baseline", () => {
    const model = toFleetMapViewModel(parseFleetMap(action(FLEET)));
    const staging = model.nodes.find((node) => node.dbId === "staging");
    expect(staging?.status).toBe("reachable");
    expect(staging?.drift?.changedSections).toEqual(["schema", "recent_ddl"]);
    expect(staging?.detail).toContain("drift vs prod_read");
    expect(model.baselineProfile).toBe("prod_read");
    expect(model.driftedCount).toBe(1);

    const baseline = model.nodes.find((node) => node.dbId === "prod_read");
    expect(baseline?.detail).toContain("no drift");
  });

  it("reports an all-green fleet without inventing degradation", () => {
    const model = toFleetMapViewModel({
      summary: null,
      profiles: [
        {
          profile: "only_db",
          status: "reachable",
          serverVersion: "23.4.0.0",
          databaseRole: "PRIMARY",
          openMode: "READ WRITE",
          readOnly: false,
          poolOpenConnections: 1,
          drift: null,
          errorCode: null,
          errorMessage: null
        }
      ]
    });
    expect(model.reachableCount).toBe(1);
    expect(model.unreachableCount).toBe(0);
    expect(model.tone).toBe("ok");
    expect(model.headline).toBe("1 database(s) reachable");
  });
});
