import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { CiLaneHealthPanel } from "./App";
import { normalizeCiLaneHealthData } from "./operator-client";

function lane(checkName: string, conclusion: string, runId: number): Record<string, unknown> {
  return {
    check_name: checkName,
    tier: checkName.includes("mutants") ? "scheduled" : "advisory",
    workflow: checkName.includes("mutants") ? "Mutation Safety" : "CI",
    workflow_file: checkName.includes("mutants") ? "mutation-safety.yml" : "ci.yml",
    job_id: `job-${runId}`,
    event: checkName.includes("mutants") ? "schedule" : "push",
    path_filtered: false,
    state: conclusion === "success" ? "success" : "not_green",
    last_status: "completed",
    last_conclusion: conclusion,
    streak: { conclusion, count: 3, capped: false },
    run_id: runId,
    run_url: `https://github.com/MuhDur/oraclemcp/actions/runs/${runId}`,
    head_sha: "e004ebd5b5532a4b85984a62f8ad48a81aa3460c",
    completed_at: "2026-07-18T00:00:00Z",
    source_error: null
  };
}

function data(
  lanes: Record<string, unknown>[],
  freshness: string = "fresh"
): Record<string, unknown> {
  return {
    source: "github_actions",
    catalog_schema: "ci-taxonomy/v1",
    catalog_complete: true,
    repo: "MuhDur/oraclemcp",
    refresh_state: "ready",
    freshness,
    refreshed_at: "unix:1784332800",
    last_attempt_at: "unix:1784332800",
    age_seconds: 30,
    streak_window: 4,
    refresh_interval_seconds: 1800,
    stale_after_seconds: 3600,
    lanes,
    errors: []
  };
}

describe("Ground Control CI lane health", () => {
  it("renders every lane supplied by the machine catalog", () => {
    const names = [
      "fuzz targets compile (nightly)",
      "multi-nightly early-warning (advisory) (nightly)",
      "guard + audit cargo-mutants"
    ];
    const model = normalizeCiLaneHealthData(data(names.map((name, index) => lane(name, "success", index + 1))));
    const markup = renderToStaticMarkup(
      <CiLaneHealthPanel data={model} pending={false} error={null} />
    );

    expect(markup.match(/data-ci-lane-name=/g)).toHaveLength(names.length);
    for (const name of names) {
      expect(markup).toContain(`data-ci-lane-name="${name}"`);
    }
    expect(markup).toContain('data-ci-lane-posture="green"');
    expect(markup).toContain("Every catalogued scheduled and advisory lane");
  });

  it("keeps the exact red conclusion and streak visible", () => {
    const model = normalizeCiLaneHealthData(
      data([lane("guard + audit cargo-mutants", "cancelled", 41)])
    );
    const markup = renderToStaticMarkup(
      <CiLaneHealthPanel data={model} pending={false} error={null} />
    );

    expect(model.summary.posture).toBe("not_green");
    expect(markup).toContain('data-ci-lane-state="not_green"');
    expect(markup).toContain("cancelled");
    expect(markup).toContain("3 × cancelled");
    expect(markup).toContain('role="alert"');
  });

  it("downgrades stale success to unknown instead of painting it green", () => {
    const model = normalizeCiLaneHealthData(
      data([lane("fuzz targets compile (nightly)", "success", 42)], "stale")
    );
    const markup = renderToStaticMarkup(
      <CiLaneHealthPanel data={model} pending={false} error={null} />
    );

    expect(model.lanes[0]?.state).toBe("unknown");
    expect(model.summary.posture).toBe("unknown");
    expect(markup).toContain('data-ci-lane-state="unknown"');
    expect(markup).toContain(">stale<");
    expect(markup).toContain("No all-green claim is available");
  });

  it("downgrades malformed or off-repository evidence to unknown", () => {
    const malformed = lane("fuzz targets compile (nightly)", "success", 42);
    malformed.run_url = "https://example.invalid/paint-me-green";
    malformed.streak = { conclusion: "failure", count: 3, capped: false };
    const model = normalizeCiLaneHealthData(data([malformed]));

    expect(model.lanes[0]?.state).toBe("unknown");
    expect(model.lanes[0]?.run_url).toBeNull();
    expect(model.lanes[0]?.source_error).toMatch(/outside the expected repository|incomplete/);
    expect(model.summary.posture).toBe("unknown");
  });

  it("refuses an empty, duplicate, or malformed-fresh catalog", () => {
    const empty = normalizeCiLaneHealthData(data([]));
    expect(empty.catalog_complete).toBe(false);
    expect(empty.summary.posture).toBe("unknown");

    const duplicateLane = lane("fuzz targets compile (nightly)", "success", 42);
    const duplicate = normalizeCiLaneHealthData(data([duplicateLane, duplicateLane]));
    expect(duplicate.catalog_complete).toBe(false);
    expect(duplicate.summary.posture).toBe("unknown");

    const malformedFreshness = data([duplicateLane]);
    malformedFreshness.refreshed_at = "not-a-timestamp";
    const malformed = normalizeCiLaneHealthData(malformedFreshness);
    expect(malformed.lanes[0]?.state).toBe("unknown");
    expect(malformed.summary.posture).toBe("unknown");
  });

  it("states transport absence explicitly", () => {
    const markup = renderToStaticMarkup(
      <CiLaneHealthPanel data={null} pending={false} error={new Error("operator API offline")} />
    );
    expect(markup).toContain('data-ci-lane-posture="unknown"');
    expect(markup).toContain("operator API offline");
    expect(markup).toContain("No trustworthy lane catalog");
  });
});
