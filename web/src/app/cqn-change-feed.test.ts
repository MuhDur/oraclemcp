import { describe, expect, it } from "vitest";

import { isResourceScope, toCqnChangeFeedViewModel } from "./presentation-model";
import { parseCqnChangeFeed, type OperatorEventEnvelope } from "./operator-client";

// Arc C1 CQN change feed. A change event carries ONLY the bound resource URI —
// the proven query's scope — never row data, never an object name, never a
// value. Delivery is best-effort and coalesced. When the operator surface emits
// no feed the console says so rather than showing a healthy, quiet stream.

function event(data: Record<string, unknown>): OperatorEventEnvelope {
  return {
    protocol_version: "operator.v1",
    schema_version: 1,
    event_seq: 1,
    event_id: "e1",
    lane_id: "operator",
    subject_id_hash: "subject-sha256:abc",
    redaction_level: "operator_redacted",
    event_type: "change_notification",
    data
  };
}

describe("cqn change feed parsing", () => {
  it("reads change events carrying only the bound resource scope", () => {
    const input = parseCqnChangeFeed(
      event({
        change_feed: {
          events: [
            { event_id: "evt-1", scope: "oracle-mcp://query/sha256:aa" },
            { event_id: "evt-2", resource_uri: "oracle-mcp://query/sha256:bb", count: 3 }
          ]
        }
      })
    );
    expect(input.events).toHaveLength(2);
    expect(input.events?.[0].scope).toBe("oracle-mcp://query/sha256:aa");
    expect(input.events?.[1].scope).toBe("oracle-mcp://query/sha256:bb");
    expect(input.events?.[1].count).toBe(3);
  });

  it("reports no feed when the event does not project one", () => {
    expect(parseCqnChangeFeed(event({})).events).toBeNull();
    expect(parseCqnChangeFeed(null).events).toBeNull();
    // An event with a change_feed object but no events array is still "no feed".
    expect(parseCqnChangeFeed(event({ change_feed: {} })).events).toBeNull();
  });
});

describe("cqn change feed view-model", () => {
  it("coalesces repeat callbacks for one scope into a single entry", () => {
    const model = toCqnChangeFeedViewModel({
      events: [
        { eventId: "a", scope: "oracle-mcp://query/sha256:aa" },
        { eventId: "b", scope: "oracle-mcp://query/sha256:aa" },
        { eventId: "c", scope: "oracle-mcp://query/sha256:bb" }
      ]
    });
    expect(model.status).toBe("streaming");
    expect(model.events).toHaveLength(2);
    const aa = model.events.find((e) => e.scope.endsWith("aa"));
    expect(aa?.coalesced).toBe(true);
    expect(aa?.count).toBe(2);
    const bb = model.events.find((e) => e.scope.endsWith("bb"));
    expect(bb?.coalesced).toBe(false);
    expect(bb?.count).toBe(1);
  });

  it("flags a scope that is not a resource URI (an object-level scope)", () => {
    expect(isResourceScope("oracle-mcp://query/sha256:aa")).toBe(true);
    expect(isResourceScope("HR.EMPLOYEES")).toBe(false);
    const model = toCqnChangeFeedViewModel({
      events: [{ eventId: "a", scope: "HR.EMPLOYEES" }]
    });
    expect(model.events[0].scopeIsResource).toBe(false);
  });

  it("reports not_reported when the surface projects no feed", () => {
    const model = toCqnChangeFeedViewModel({ events: null });
    expect(model.status).toBe("not_reported");
    expect(model.events).toHaveLength(0);
    expect(model.detail).toContain("not a claim that nothing changed");
  });

  it("reports idle (not not_reported) for an empty feed the surface did emit", () => {
    const model = toCqnChangeFeedViewModel({ events: [] });
    expect(model.status).toBe("idle");
    expect(model.headline).toBe("No changes in this window");
  });
});
