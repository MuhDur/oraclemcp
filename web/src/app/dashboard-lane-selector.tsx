import type { ActiveLane } from "./operator-client";
import { laneIdentity, type LaneIdentity } from "./dashboard-view-state";
import { shortHash } from "./dashboard-ui";

export function laneOptionValue(lane: ActiveLane): string {
  return JSON.stringify([lane.lane_id, lane.generation]);
}

export function laneIdentityFromOption(
  lanes: readonly ActiveLane[],
  value: string
): LaneIdentity | null {
  const lane = lanes.find((candidate) => laneOptionValue(candidate) === value);
  return lane ? laneIdentity(lane) : null;
}

export function laneOptionLabel(lane: ActiveLane): string {
  return `${lane.lane_id} | generation ${lane.generation} | ${lane.status} | ${shortHash(lane.subject_id_hash)}`;
}
