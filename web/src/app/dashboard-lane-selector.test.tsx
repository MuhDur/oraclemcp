import { describe, expect, it } from "vitest";

import {
  laneIdentityFromOption,
  laneOptionLabel,
  laneOptionValue
} from "./dashboard-lane-selector";

const reusedLane = [
  {
    lane_id: "lane-a",
    generation: 7,
    status: "active",
    subject_id_hash: "sha256:operator-previous-generation"
  },
  {
    lane_id: "lane-a",
    generation: 8,
    status: "active",
    subject_id_hash: "sha256:operator-replacement-generation"
  }
];

describe("operator lane selector", () => {
  it("encodes and resolves the full lane identity, never a reused id alone", () => {
    const oldValue = laneOptionValue(reusedLane[0]);
    const replacementValue = laneOptionValue(reusedLane[1]);

    expect(oldValue).not.toBe(replacementValue);
    expect(laneIdentityFromOption(reusedLane, oldValue)).toEqual({ laneId: "lane-a", generation: 7 });
    expect(laneIdentityFromOption(reusedLane, replacementValue)).toEqual({ laneId: "lane-a", generation: 8 });
  });

  it("makes the generation and session context visible in the option label", () => {
    const label = laneOptionLabel(reusedLane[1]);

    expect(label).toContain("lane-a");
    expect(label).toContain("generation 8");
    expect(label).toContain("active");
    expect(label).toContain("sha256:operator-rep");
  });
});
