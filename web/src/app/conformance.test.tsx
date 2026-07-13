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
  policyBadgeFixture,
  scnScrubberFixture,
  skinContractFixture,
  toCostBadgeViewModel,
  toMaskBadgeViewModel,
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

  it("never invents a ceiling the server did not disclose", () => {
    const CostBadge = OMCP_SKIN.renderers.CostBadge;
    // A priced statement with no refusal: the gate discloses max_query_cost only
    // when it refuses, so the badge must say the ceiling is undisclosed.
    const priced = toCostBadgeViewModel({
      refusal: null,
      estimate: 1_200,
      estimateUnavailable: null,
      note: "optimizer costs are relative estimates",
      planRows: [],
      ceiling: null
    });
    expect(priced.verdict).toBe("estimated");
    expect(priced.ceiling).toBeNull();
    expect(priced.ratio).toBeNull();
    const markup = renderToStaticMarkup(<CostBadge model={priced} />);
    expect(markup).toContain('data-cost-verdict="estimated"');
    expect(markup).toContain('data-cost-estimate="1200"');
    expect(markup).toContain('data-cost-ceiling="undisclosed"');

    // Nothing priced at all: "unknown", not a zero cost and not a green light.
    const unpriced = toCostBadgeViewModel({
      refusal: null,
      estimate: null,
      estimateUnavailable: null,
      note: null,
      planRows: [],
      ceiling: null
    });
    expect(unpriced.verdict).toBe("unknown");
    expect(renderToStaticMarkup(<CostBadge model={unpriced} />)).toContain(
      'data-cost-estimate="unknown"'
    );
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
