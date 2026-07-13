import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  CLEARANCE_LADDER,
  DASHBOARD_GRAMMAR,
  REQUIRED_BIG_BOARD_RENDERERS,
  REQUIRED_THEME_MODES,
  VERDICT_RULE_REGISTRY,
  costBadgeFixture,
  defaultSkinCapabilities,
  fleetMapFixture,
  isRegisteredDerivationStep,
  maskBadgeFixture,
  vectorClusterFixture,
  editionTimelineFixture,
  cqnChangeFeedFixture,
  columnLineageFixture,
  policyBadgeFixture,
  scnScrubberFixture,
  skinContractFixture,
  toCostBadgeViewModel,
  toMaskBadgeViewModel,
  toVectorClusterViewModel,
  toEditionTimelineViewModel,
  toCqnChangeFeedViewModel,
  toColumnLineageViewModel,
  toPolicyBadgeViewModel,
  toScnScrubberViewModel,
  toUndoTreeViewModel,
  toVerdictProofViewModel,
  undoTreeFixture,
  verdictProofFixture,
  type SkinCapability
} from "./presentation-model";

// React escapes attribute values in static markup; mirror that when asserting on
// a server-issued reason string rendered into a data-* attribute.
const escapeAttr = (value: string): string =>
  value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
import {
  OMCP_SKIN,
  assertDashboardSkinConformance,
  selectBigBoardRenderer
} from "./skin";

// B4.6 skin-conformance contract (iec3.2.26). These gate the release: every
// view-model must render in the single shipped Carved Light theme AND resolve to
// the mandatory 2D/table fallback, and the OMCP grammar (the I-II-III-IV
// operating-level ladder, GO/NO-GO verdict) must hold unchanged.

const caps = (overrides: Partial<SkinCapability> = {}): SkinCapability => ({
  ...defaultSkinCapabilities(),
  ...overrides
});

describe("OMCP skin conformance", () => {
  it("passes the built-in conformance assertion", () => {
    expect(() => assertDashboardSkinConformance(OMCP_SKIN)).not.toThrow();
  });

  it("ships exactly the Carved Light theme with the --om clearance ramp", () => {
    expect(OMCP_SKIN.theme.name).toBe("carved-light");
    for (const level of ["read-only", "read-write", "ddl", "admin"] as const) {
      expect(OMCP_SKIN.theme.cssVars[`--om-clearance-${level}`]).toMatch(/^#/);
    }
    // A WebGL uniform per clearance level keeps the 3D and 2D skins in lockstep.
    expect(Object.keys(OMCP_SKIN.theme.webglUniforms).sort()).toEqual(
      ["ADMIN", "DDL", "READ_ONLY", "READ_WRITE"]
    );
  });

  it("covers every required theme mode and big-board renderer", () => {
    expect([...OMCP_SKIN.theme.modes].sort()).toEqual([...REQUIRED_THEME_MODES].sort());
    expect(Object.keys(OMCP_SKIN.bigBoardRenderers).sort()).toEqual(
      [...REQUIRED_BIG_BOARD_RENDERERS].sort()
    );
  });

  it("keeps the operating-level ladder grammar in order", () => {
    expect(CLEARANCE_LADDER.map((step) => step.level).join(">")).toBe(
      "READ_ONLY>READ_WRITE>DDL>ADMIN"
    );
    expect(DASHBOARD_GRAMMAR.meanings.color).toBe("clearance");
  });

  it("always resolves a working 2D fallback and never auto-selects WebGL", () => {
    // Both non-WebGL renderers must exist and be available.
    expect(OMCP_SKIN.bigBoardRenderers.board2d.available).toBe(true);
    expect(OMCP_SKIN.bigBoardRenderers.table.available).toBe(true);
    // Default: the 2D board.
    expect(selectBigBoardRenderer(OMCP_SKIN, caps()).kind).toBe("board2d");
    // Forced-colors / high-contrast: the table fallback.
    expect(selectBigBoardRenderer(OMCP_SKIN, caps({ forcedColors: true, preferTable: true })).kind).toBe(
      "table"
    );
    // Reduced motion with WebGL present still avoids the Orrery (unavailable + lazy).
    expect(
      selectBigBoardRenderer(OMCP_SKIN, caps({ webgl: true, reducedMotion: true })).kind
    ).not.toBe("orrery3d");
  });

  it("renders Ground Control in the Carved Light theme with the grammar intact", () => {
    const GroundControl = OMCP_SKIN.renderers.GroundControl;
    const markup = renderToStaticMarkup(
      <GroundControl model={skinContractFixture().groundControl} />
    );
    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-verdict="GO"');
    for (const level of ["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"]) {
      expect(markup).toContain(`data-clearance-level="${level}"`);
    }
  });

  it("renders the verdict-proof inspector with its rule derivation and certificate hash", () => {
    const VerdictProof = OMCP_SKIN.renderers.VerdictProof;
    const model = verdictProofFixture();
    const markup = renderToStaticMarkup(<VerdictProof model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain(`data-verdict="${model.verdict}"`);
    expect(markup).toContain(`data-cert-hash="${model.certHash}"`);
    expect(model.certHash).not.toBe("");
    expect(markup).toContain(`data-audit-hash="${model.auditHash ?? ""}"`);
    expect(markup).toContain('data-go-no-go="GO"');
    expect(markup).toContain('data-proof-status="verified"');

    // The rendered rule-id set is exactly the certificate's derivation — the
    // inspector may not drop, reorder into, or invent a rule.
    const renderedRuleIds = [...markup.matchAll(/data-rule-id="([^"]+)"/g)].map(
      (match) => match[1]
    );
    expect(renderedRuleIds).toEqual(model.derivation.map((step) => step.ruleId));
    expect(new Set(renderedRuleIds)).toEqual(
      new Set(Object.keys(VERDICT_RULE_REGISTRY).filter((id) => renderedRuleIds.includes(id)))
    );
    for (const step of model.derivation) {
      expect(markup).toContain(`data-construct="${step.construct}"`);
      expect(isRegisteredDerivationStep(step.ruleId, step.construct)).toBe(true);
    }
    for (const check of model.checks) {
      expect(markup).toContain(`data-check-id="${check.id}"`);
    }
  });

  it("refuses to call a proof verified when a rule id is outside the registry", () => {
    // Fail-closed: an unknown rule id or a broken binding downgrades the proof,
    // it never renders as a verified certificate.
    const unknownRule = toVerdictProofViewModel({
      seq: 7,
      timestamp: "2026-07-13T00:00:00Z",
      tool: "oracle_execute",
      subjectIdHash: "subject-sha256:fixture",
      certHash: "sha256:aa",
      auditHash: "sha256:bb",
      certificate: {
        stmt_digest: "sha256:cc",
        level: "READ_ONLY",
        verdict: "SAFE",
        derivation: [{ rule_id: "R99", construct: "final_verdict:SAFE" }],
        classifier_version: "oraclemcp-guard/0.8.0;registry=1",
        observed_scn: null,
        bound_audit_hash: "sha256:bb"
      },
      checks: [{ id: "audit_binding", label: "Bound to audit entry", ok: true, detail: "bound" }]
    });
    expect(unknownRule.proofStatus).toBe("unverified");

    const VerdictProof = OMCP_SKIN.renderers.VerdictProof;
    const markup = renderToStaticMarkup(<VerdictProof model={unknownRule} />);
    expect(markup).toContain('data-proof-status="unverified"');
    expect(markup).toContain('data-rule-id="R99"');
    expect(markup).toContain('data-registered="false"');

    const brokenBinding = toVerdictProofViewModel({
      seq: 8,
      timestamp: "2026-07-13T00:00:01Z",
      tool: "oracle_execute",
      subjectIdHash: "subject-sha256:fixture",
      certHash: "sha256:aa",
      auditHash: "sha256:bb",
      certificate: {
        stmt_digest: "sha256:cc",
        level: "READ_ONLY",
        verdict: "SAFE",
        derivation: [{ rule_id: "R16", construct: "final_verdict:SAFE" }],
        classifier_version: "oraclemcp-guard/0.8.0;registry=1",
        observed_scn: null,
        bound_audit_hash: "sha256:zz"
      },
      checks: [
        {
          id: "audit_binding",
          label: "Bound to audit entry",
          ok: false,
          detail: "bound_audit_hash does not match record.entry_hash"
        }
      ]
    });
    expect(brokenBinding.proofStatus).toBe("unverified");
    expect(brokenBinding.tone).toBe("warn");
  });

  it("renders a policy narrowing with the level it narrowed from", () => {
    const PolicyBadge = OMCP_SKIN.renderers.PolicyBadge;
    const model = policyBadgeFixture();
    const markup = renderToStaticMarkup(<PolicyBadge model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-policy-effect="Narrow"');
    // The pre-narrow level is what makes the narrowing legible: the policy took
    // this statement from READ_ONLY up to READ_WRITE.
    expect(markup).toContain('data-narrowed-from="READ_ONLY"');
    expect(markup).toContain('data-narrowed-to="READ_WRITE"');
    expect(model.narrowedFrom).toBe("READ_ONLY");
    expect(model.narrowedTo).toBe("READ_WRITE");
    expect(markup).toContain("READ_ONLY → READ_WRITE");

    // Every rule that fired, and the predicate the policy bolted on.
    expect(markup).toContain('data-policy-rule-id="hr-salary-guard"');
    expect(markup).toContain('data-policy-rule-id="tenant-scope"');
    expect(markup).toContain('data-policy-predicate-target="HR.EMPLOYEES"');
  });

  it("renders a policy denial, and reports a missing verdict as not-reported", () => {
    const PolicyBadge = OMCP_SKIN.renderers.PolicyBadge;
    const denied = toPolicyBadgeViewModel({
      effect: "Deny",
      reason: "matching_deny_rule",
      matchedRuleIds: ["no-prod-deletes"]
    });
    const deniedMarkup = renderToStaticMarkup(<PolicyBadge model={denied} />);
    expect(deniedMarkup).toContain('data-policy-effect="Deny"');
    expect(deniedMarkup).toContain('data-policy-rule-id="no-prod-deletes"');
    // A denial has no narrowed-from: nothing was narrowed, it was refused.
    expect(denied.narrowedFrom).toBeNull();
    expect(deniedMarkup).toContain('data-narrowed-from=""');

    // No verdict on the response: "not reported" — NOT "no policy applied".
    const silent = toPolicyBadgeViewModel(null);
    expect(silent.status).toBe("not_reported");
    expect(silent.effect).toBeNull();
    expect(silent.detail).toContain("not a statement that no policy applied");
    const silentMarkup = renderToStaticMarkup(<PolicyBadge model={silent} />);
    expect(silentMarkup).toContain('data-policy-effect="not_reported"');
    expect(silentMarkup).toContain('data-policy-narrowed="false"');
  });

  it("renders every database on the fleet map, including an unreachable one", () => {
    const FleetMap = OMCP_SKIN.renderers.FleetMap;
    const model = fleetMapFixture();
    const markup = renderToStaticMarkup(<FleetMap model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    for (const node of model.nodes) {
      expect(markup).toContain(`data-db-id="${node.dbId}"`);
    }
    expect(markup).toContain('data-db-status="reachable"');

    // The unreachable lane is still a node on the map — Arc H types it precisely
    // so one dead database never omits the others.
    const dead = model.nodes.find((node) => node.status === "unreachable");
    expect(dead?.dbId).toBe("dr_site");
    expect(markup).toContain('data-db-status="unreachable"');
    expect(markup).toContain('data-db-id="dr_site"');
    // And it reports no drift verdict, because nothing was compared.
    expect(dead?.drift).toBeNull();
    expect(markup).toContain('data-db-drift="unknown"');
    expect(markup).toContain("drift not evaluated");

    // Drift is named per section against the baseline the server chose.
    const drifted = model.nodes.find((node) => node.dbId === "staging");
    expect(drifted?.drift?.changedSections).toContain("schema");
    expect(markup).toContain('data-db-drift="drifted"');
  });

  it("renders each typed column-lineage edge status, injected drift included", () => {
    const ColumnLineage = OMCP_SKIN.renderers.ColumnLineage;
    const model = columnLineageFixture();
    const markup = renderToStaticMarkup(<ColumnLineage model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-lineage-status="edges"');

    // Every one of the four typed markers renders.
    for (const status of ["verified", "drift-missing", "drift-type-mismatch", "partial"]) {
      expect(markup).toContain(`data-edge-status="${status}"`);
    }

    // An injected drift renders its OWN marker and is never upgraded to verified.
    const drift = toColumnLineageViewModel({
      edges: [{ from: "HR.V.C", to: "HR.T.C", status: "drift-type-mismatch" }]
    });
    expect(drift.edges[0].status).toBe("drift-type-mismatch");
    expect(drift.driftCount).toBe(1);
    expect(drift.verifiedCount).toBe(0);
    const driftMarkup = renderToStaticMarkup(<ColumnLineage model={drift} />);
    expect(driftMarkup).toContain('data-edge-status="drift-type-mismatch"');
    expect(driftMarkup).not.toContain('data-edge-status="verified"');
  });

  it("reports lineage 'not reported' rather than implying a clean graph", () => {
    const ColumnLineage = OMCP_SKIN.renderers.ColumnLineage;
    const none = toColumnLineageViewModel({ edges: null });
    expect(none.status).toBe("not_reported");
    expect(none.detail).toContain("not a clean-graph claim");
    const markup = renderToStaticMarkup(<ColumnLineage model={none} />);
    expect(markup).toContain('data-lineage-status="not_reported"');
    expect(markup).not.toContain("data-edge-status");
  });

  it("renders the CQN change feed with resource-scoped, coalesced events", () => {
    const CqnChangeFeed = OMCP_SKIN.renderers.CqnChangeFeed;
    const model = cqnChangeFeedFixture();
    const markup = renderToStaticMarkup(<CqnChangeFeed model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-feed-status="streaming"');

    // Each event has an id and a scope; the scope is the proven query's resource
    // URI, NEVER a bare object name.
    const scopes = [...markup.matchAll(/data-change-scope="([^"]+)"/g)].map((m) => m[1]);
    expect(scopes.length).toBeGreaterThan(0);
    for (const scope of scopes) {
      expect(scope).toMatch(/^[a-z][a-z0-9+.-]*:\/\//i);
      expect(scope).not.toMatch(/^[A-Z_]+\.[A-Z_]+$/); // not OWNER.OBJECT
    }
    expect(markup).toContain("data-change-event-id=");

    // The two events for one scope folded into a single coalesced entry.
    const coalesced = model.events.find((event) => event.coalesced);
    expect(coalesced?.count).toBe(2);
    expect(markup).toContain('data-coalesced="true"');
  });

  it("reports 'not reported' when the operator surface projects no change feed", () => {
    const CqnChangeFeed = OMCP_SKIN.renderers.CqnChangeFeed;
    const none = toCqnChangeFeedViewModel({ events: null });
    expect(none.status).toBe("not_reported");
    expect(none.detail).toContain("not a claim that nothing changed");
    const markup = renderToStaticMarkup(<CqnChangeFeed model={none} />);
    expect(markup).toContain('data-feed-status="not_reported"');
    expect(markup).not.toContain("data-change-scope");
  });

  it("renders the edition timeline as a single-child LINEAR chain", () => {
    const EditionTimeline = OMCP_SKIN.renderers.EditionTimeline;
    const model = editionTimelineFixture();
    const markup = renderToStaticMarkup(<EditionTimeline model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-edition-linear="true"');
    expect(model.linear).toBe(true);

    // Each stage names one parent and a strict linear order — never a branch node.
    expect(markup).toContain('data-edition-stage="REVIEW_1"');
    expect(markup).toContain('data-edition-parent="ORA$BASE"');
    expect(markup).toContain('data-linear-order="1"');
    const orders = [...markup.matchAll(/data-linear-order="(\d+)"/g)].map((m) => Number(m[1]));
    expect(orders).toEqual([...orders].sort((a, b) => a - b));
    // Every non-root stage has exactly one parent.
    for (const stage of model.stages.slice(1)) {
      expect(stage.parentEdition).not.toBeNull();
    }

    // A branch (a base with two children) is flagged, never flattened to a line.
    const branched = toEditionTimelineViewModel([
      { proposalId: "a", baseEdition: "ORA$BASE", childEdition: "LEFT", status: "requested", objectCount: 1 },
      { proposalId: "b", baseEdition: "ORA$BASE", childEdition: "RIGHT", status: "requested", objectCount: 1 }
    ]);
    expect(branched.linear).toBe(false);
    expect(branched.branchedFrom).toContain("ORA$BASE");
    expect(renderToStaticMarkup(<EditionTimeline model={branched} />)).toContain(
      'data-edition-linear="false"'
    );
  });

  it("renders the vector cluster with k monotonic-rank neighbors", () => {
    const VectorCluster = OMCP_SKIN.renderers.VectorCluster;
    const model = vectorClusterFixture();
    const markup = renderToStaticMarkup(<VectorCluster model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-metric="COSINE"');
    expect(markup).toContain('data-k="3"');

    // k neighbors render, and their distances (ranks) are monotonic non-decreasing.
    expect(model.k).toBe(3);
    const ranks = [...markup.matchAll(/data-neighbor-distance="(\d+)"/g)].map((m) => Number(m[1]));
    expect(ranks).toHaveLength(3);
    expect(ranks).toEqual([0, 1, 2]);
    for (let i = 1; i < ranks.length; i++) {
      expect(ranks[i]).toBeGreaterThanOrEqual(ranks[i - 1]);
    }
  });

  it("is honest about what the vector surface does not emit", () => {
    const VectorCluster = OMCP_SKIN.renderers.VectorCluster;
    const model = vectorClusterFixture();
    const markup = renderToStaticMarkup(<VectorCluster model={model} />);

    // The server orders by distance but never egresses the value — the panel says so.
    expect(model.distanceReported).toBe(false);
    expect(markup).toContain('data-distance-reported="false"');
    // used_index was null (server did not inspect a plan) — never inferred.
    expect(model.usedIndex).toBeNull();
    expect(markup).toContain('data-used-index="not_reported"');
    // The masked column is reflected, never rendered as a real value.
    expect(model.maskedColumns).toBeGreaterThan(0);
    expect(markup).toContain('data-neighbor-masked="true"');
    for (const neighbor of model.neighbors) {
      expect(neighbor.cells).toContain("'?'");
    }

    // A refused search (e.g. an unproven filter predicate) shows the refusal,
    // not an empty cluster pretending nothing was searched.
    const refused = toVectorClusterViewModel({
      metric: null,
      k: null,
      columns: [],
      rows: [],
      usedIndex: null,
      maskPolicyId: null,
      maskedColumns: 0,
      refusalReason: "oracle_semantic_search filter is unavailable; refusing an unproven predicate"
    });
    expect(refused.status).toBe("refused");
    const refusedMarkup = renderToStaticMarkup(<VectorCluster model={refused} />);
    expect(refusedMarkup).toContain('data-vector-status="refused"');
    expect(refusedMarkup).toContain("refusing an unproven predicate");
    expect(refusedMarkup).not.toContain("data-neighbor-rank");
  });

  it("renders the egress mask badge with a policy id and a per-column decision", () => {
    const MaskBadge = OMCP_SKIN.renderers.MaskBadge;
    const model = maskBadgeFixture();
    const markup = renderToStaticMarkup(<MaskBadge model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-mask-status="certified"');
    expect(markup).toContain(`data-mask-policy-id="${model.policyId}"`);

    // A transformed column is masked, and says which rule transformed it.
    const email = model.columns.find((column) => column.column === "EMAIL");
    expect(email?.masked).toBe(true);
    expect(email?.action).toBe("tokenize");
    expect(markup).toContain('data-masked="true"');
    expect(markup).toContain('data-mask-action="tokenize"');
    expect(markup).toContain('data-mask-rule-index="0"');

    // An unmasked column carries data-masked="false" — the pass-through decision
    // is itself certified, not an absence of information.
    const id = model.columns.find((column) => column.column === "EMPLOYEE_ID");
    expect(id?.masked).toBe(false);
    expect(id?.action).toBe("pass");
    expect(markup).toContain('data-masked="false"');

    // The fail-closed default is visible as its own source.
    expect(markup).toContain('data-mask-source="mask_unknown_default"');
  });

  it("treats a missing certificate as absence of proof, not as 'nothing was masked'", () => {
    const MaskBadge = OMCP_SKIN.renderers.MaskBadge;
    const none = toMaskBadgeViewModel(null);
    expect(none.status).toBe("no_certificate");
    expect(none.maskedColumns).toBe(0);
    expect(none.columns).toHaveLength(0);
    expect(none.detail).toContain("not proof that nothing was masked");
    const markup = renderToStaticMarkup(<MaskBadge model={none} />);
    expect(markup).toContain('data-mask-status="no_certificate"');
    expect(markup).toContain('data-mask-policy-id=""');
    // Crucially it does NOT claim any column passed through unmasked.
    expect(markup).not.toContain('data-masked="false"');
  });

  it("renders the SCN scrubber with the current SCN clamped inside the confirmed range", () => {
    const ScnScrubber = OMCP_SKIN.renderers.ScnScrubber;
    const model = scnScrubberFixture();
    const markup = renderToStaticMarkup(<ScnScrubber model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-scn-current="15200400"');
    expect(markup).toContain('data-scn-min="15200000"');
    expect(markup).toContain('data-scn-max="15200400"');
    expect(model.current).toBeGreaterThanOrEqual(model.min!);
    expect(model.current).toBeLessThanOrEqual(model.max!);

    // The refused snapshot (SCN 15900000) is listed with its ORA- reason but is
    // NOT allowed to widen the range — the console only claims snapshots the
    // server actually served.
    expect(markup).toContain('data-mark-status="refused"');
    expect(model.max).toBe(15_200_400);
    expect(model.marks.some((mark) => mark.scn === 15_900_000)).toBe(true);
  });

  it("draws no axis at all when the server has served no snapshot", () => {
    const ScnScrubber = OMCP_SKIN.renderers.ScnScrubber;
    // No confirmed read: the server publishes neither the current SCN nor the
    // retention window, so there is no timeline to draw and the scrubber says so.
    const empty = toScnScrubberViewModel({ current: null, marks: [], refusal: null });
    expect(empty.rangeKnown).toBe(false);
    expect(empty.status).toBe("unavailable");
    const markup = renderToStaticMarkup(<ScnScrubber model={empty} />);
    expect(markup).toContain('data-scn-min="unknown"');
    expect(markup).toContain('data-scn-max="unknown"');
    expect(markup).toContain('data-scn-current="live"');
    expect(markup).not.toContain('type="range"');

    // An out-of-range request is clamped into the confirmed window, not honored.
    const clamped = toScnScrubberViewModel({
      current: 99_000_000,
      refusal: null,
      marks: [
        {
          id: "m1",
          scn: 100,
          label: "SCN 100",
          status: "confirmed",
          detail: "1 row",
          tone: "ok"
        },
        {
          id: "m2",
          scn: 200,
          label: "SCN 200",
          status: "confirmed",
          detail: "1 row",
          tone: "ok"
        }
      ]
    });
    expect(clamped.current).toBe(200);
    expect(clamped.clamped).toBe(true);
    expect(clamped.position).toBe(1);
  });

  it("renders the cost badge with the estimate and the ceiling the refusal disclosed", () => {
    const CostBadge = OMCP_SKIN.renderers.CostBadge;
    const model = costBadgeFixture();
    const markup = renderToStaticMarkup(<CostBadge model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-cost-verdict="refused"');
    expect(markup).toContain('data-cost-estimate="190000"');
    expect(markup).toContain('data-cost-ceiling="50000"');
    expect(model.estimate).toBe(190_000);
    expect(model.ceiling).toBe(50_000);
    expect(model.ratio).toBe(1);
    // The plan rows and predicate hints that explain the price ride along.
    expect(markup).toContain('data-plan-row-cost="189800"');
    expect(markup).toContain("TABLE ACCESS FULL");
    expect(markup).toContain('data-hint-count="1"');
  });

  it("renders the ceiling the operator config publishes, with no refusal in play", () => {
    const CostBadge = OMCP_SKIN.renderers.CostBadge;
    // The ceiling is on the wire: /operator/v1/config carries each profile's
    // max_query_cost, so the badge shows it BEFORE the gate refuses anything.
    const priced = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: "optimizer costs are relative estimates",
      planRows: [],
      ceiling: 50_000,
      ceilingSource: "config",
      ungated: false
    });
    expect(priced.verdict).toBe("within_ceiling");
    const markup = renderToStaticMarkup(<CostBadge model={priced} />);
    expect(markup).toContain('data-cost-verdict="within_ceiling"');
    expect(markup).toContain('data-cost-estimate="1200"');
    expect(markup).toContain('data-cost-ceiling="50000"');
    expect(markup).toContain('data-cost-ceiling-source="config"');
  });

  it("never invents a ceiling, and never confuses 'ungated' with 'unknown'", () => {
    const CostBadge = OMCP_SKIN.renderers.CostBadge;
    // The console could not identify the active profile: it says nothing about a
    // budget it cannot see — not zero, not unlimited.
    const unknown = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null,
      ceilingSource: "unknown",
      ungated: false
    });
    expect(unknown.verdict).toBe("unknown");
    const unknownMarkup = renderToStaticMarkup(<CostBadge model={unknown} />);
    expect(unknownMarkup).toContain('data-cost-estimate="unknown"');
    expect(unknownMarkup).toContain('data-cost-ceiling="undisclosed"');

    // The config positively says this profile declares no max_query_cost: the
    // gate is off. That is a fact, and it renders differently from "unknown".
    const ungated = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null,
      ceilingSource: "unknown",
      ungated: true
    });
    expect(ungated.verdict).toBe("ungated");
    const ungatedMarkup = renderToStaticMarkup(<CostBadge model={ungated} />);
    expect(ungatedMarkup).toContain('data-cost-verdict="ungated"');
    expect(ungatedMarkup).toContain('data-cost-ceiling="none"');
  });

  it("renders the undo tree and refuses a plain Undo for effects that escape rollback", () => {
    const UndoTree = OMCP_SKIN.renderers.UndoTree;
    const model = undoTreeFixture();
    const markup = renderToStaticMarkup(<UndoTree model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain('data-workspace-open="true"');
    expect(markup).toContain('data-checkpoint-name="SP_BEFORE_BACKFILL"');

    // The sequence-touching node: not undoable, and it says why, in the server's
    // own words. This is the Arc I honesty rule — the label, not a button.
    const sequenceNode = model.nodes.find((node) => node.label.includes("NEXTVAL"));
    expect(sequenceNode?.undoable).toBe(false);
    expect(sequenceNode?.status).toBe("escaped");
    expect(sequenceNode?.cannotUndoReason).toContain("sequence.NEXTVAL");
    expect(markup).toContain('data-node-status="escaped"');
    expect(markup).toContain('data-undoable="false"');
    expect(markup).toContain(`data-cannot-undo-reason="${escapeAttr(sequenceNode!.cannotUndoReason!)}"`);
    expect(markup).toContain("CANNOT UNDO");

    // A checkpoint with escaped work above it degrades to an explicitly-labeled
    // partial rollback; the plain "Undo to checkpoint" button is not rendered.
    const checkpoint = model.nodes.find((node) => node.kind === "checkpoint");
    expect(checkpoint?.undoable).toBe(false);
    expect(checkpoint?.partialUndo).toBe(true);
    expect(markup).toContain('data-partial-undo="true"');
    expect(markup).toContain("Partial rollback");
    expect(markup).not.toContain("Undo to checkpoint");

    // The reversible held statement keeps its plain, unqualified undo.
    const held = model.nodes.find((node) => node.status === "held");
    expect(held?.undoable).toBe(true);
    expect(held?.cannotUndoReason).toBeNull();
  });

  it("renders a plain Undo only when the whole workspace is reversible", () => {
    const UndoTree = OMCP_SKIN.renderers.UndoTree;
    const reversible = toUndoTreeViewModel({
      workspace: { open: true, checkpoints: ["SP_A"], heldStatements: 1 },
      entries: [
        {
          id: "cp-1",
          kind: "checkpoint",
          checkpointName: "SP_A",
          label: "SP_A",
          cannotUndo: [],
          fullyReverted: null
        },
        {
          id: "st-1",
          kind: "statement",
          checkpointName: "SP_A",
          label: "UPDATE hr.employees SET salary = salary * 1.03",
          cannotUndo: [],
          fullyReverted: true
        }
      ]
    });
    const markup = renderToStaticMarkup(<UndoTree model={reversible} />);
    expect(reversible.escapedEffects).toBe(0);
    expect(markup).toContain("Undo to checkpoint");
    expect(markup).not.toContain("Partial rollback");
    expect(markup).toContain('data-undoable="true"');
  });

  it("renders both the 2D board and the table fallback for the fleet view-model", () => {
    const fleet = skinContractFixture().fleet;
    for (const kind of ["board2d", "table"] as const) {
      const renderer = OMCP_SKIN.bigBoardRenderers[kind];
      const Renderer = renderer.component;
      const markup = renderToStaticMarkup(<Renderer model={fleet} renderer={renderer} />);
      expect(markup).toContain(`data-renderer="${kind}"`);
      expect(markup).toContain('data-grammar-version="1"');
    }
  });
});
