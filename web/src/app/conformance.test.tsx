import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  CLEARANCE_LADDER,
  DASHBOARD_GRAMMAR,
  REQUIRED_THEME_MODES,
  VERDICT_RULE_REGISTRY,
  editionTimelineFixture,
  isRegisteredDerivationStep,
  maskBadgeFixture,
  policyBadgeFixture,
  toEditionTimelineViewModel,
  toMaskBadgeViewModel,
  toPolicyBadgeViewModel,
  toVerdictProofViewModel,
  verdictProofFixture
} from "./presentation-model";
import { OMCP_SKIN, assertDashboardSkinConformance } from "./skin";

const RETAINED_RENDERERS = [
  "EditionTimeline",
  "MaskBadge",
  "PolicyBadge",
  "VerdictProof"
] as const;

function relativeLuminance(hex: string): number {
  const channels = hex
    .slice(1)
    .match(/.{2}/g)
    ?.map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
    );
  if (!channels || channels.length !== 3) {
    throw new Error(`expected a six-digit hex color, received ${hex}`);
  }
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

function contrastRatio(foreground: string, background: string): number {
  const lighter = Math.max(relativeLuminance(foreground), relativeLuminance(background));
  const darker = Math.min(relativeLuminance(foreground), relativeLuminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

describe("OMCP skin conformance", () => {
  it("passes the production skin assertion", () => {
    expect(() => assertDashboardSkinConformance(OMCP_SKIN)).not.toThrow();
  });

  it("registers only renderers mounted by the end-user dashboard", () => {
    expect(Object.keys(OMCP_SKIN.renderers).sort()).toEqual([...RETAINED_RENDERERS].sort());
    expect(Object.keys(OMCP_SKIN).sort()).toEqual(
      ["grammarVersion", "layout", "name", "renderers", "theme"].sort()
    );

    const retiredNames = [
      "GroundControl",
      "FleetMap",
      "VectorCluster",
      "CqnChangeFeed",
      "ColumnLineage",
      "ScnScrubber",
      "UndoTree",
      "CostBadge"
    ];
    for (const retiredName of retiredNames) {
      expect(retiredName in OMCP_SKIN.renderers).toBe(false);
    }
  });

  it("keeps accessible theme modes, contrast, focus, and skip navigation", () => {
    expect(OMCP_SKIN.theme.name).toBe("carved-light");
    expect([...OMCP_SKIN.theme.modes].sort()).toEqual([...REQUIRED_THEME_MODES].sort());

    const background = OMCP_SKIN.theme.cssVars["--om-bg"];
    const text = OMCP_SKIN.theme.cssVars["--om-text"];
    const focus = OMCP_SKIN.theme.cssVars["--om-focus"];
    expect(contrastRatio(text, background)).toBeGreaterThanOrEqual(7);
    expect(contrastRatio(focus, background)).toBeGreaterThanOrEqual(3);

    for (const level of ["read-only", "read-write", "ddl", "admin"] as const) {
      expect(OMCP_SKIN.theme.cssVars[`--om-clearance-${level}`]).toMatch(/^#[0-9a-f]{6}$/i);
    }
    expect(OMCP_SKIN.layout.skipLink).toContain("focus-visible:not-sr-only");
    expect(OMCP_SKIN.layout.navLink).toContain("focus-visible");
    expect(OMCP_SKIN.layout.navLink).toContain("data-status=active");
  });

  it("keeps the operating-level grammar in order", () => {
    expect(CLEARANCE_LADDER.map((step) => step.level).join(">")).toBe(
      "READ_ONLY>READ_WRITE>DDL>ADMIN"
    );
    expect(DASHBOARD_GRAMMAR.meanings.color).toBe("clearance");
  });

  it("renders a verified verdict proof with its complete derivation", () => {
    const VerdictProof = OMCP_SKIN.renderers.VerdictProof;
    const model = verdictProofFixture();
    const markup = renderToStaticMarkup(<VerdictProof model={model} />);

    expect(markup).toContain('data-grammar-version="1"');
    expect(markup).toContain(`data-verdict="${model.verdict}"`);
    expect(markup).toContain(`data-cert-hash="${model.certHash}"`);
    expect(markup).toContain(`data-audit-hash="${model.auditHash ?? ""}"`);
    expect(markup).toContain('data-proof-status="verified"');

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
  });

  it("never labels an unknown rule or broken audit binding as verified", () => {
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
    const VerdictProof = OMCP_SKIN.renderers.VerdictProof;
    const unknownMarkup = renderToStaticMarkup(<VerdictProof model={unknownRule} />);
    expect(unknownRule.proofStatus).toBe("unverified");
    expect(unknownMarkup).toContain('data-proof-status="unverified"');
    expect(unknownMarkup).toContain('data-registered="false"');

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
      checks: [{
        id: "audit_binding",
        label: "Bound to audit entry",
        ok: false,
        detail: "bound_audit_hash does not match record.entry_hash"
      }]
    });
    expect(brokenBinding.proofStatus).toBe("unverified");
    expect(brokenBinding.tone).toBe("warn");
  });

  it("renders policy narrowing and distinguishes denial from missing evidence", () => {
    const PolicyBadge = OMCP_SKIN.renderers.PolicyBadge;
    const narrowed = policyBadgeFixture();
    const narrowedMarkup = renderToStaticMarkup(<PolicyBadge model={narrowed} />);
    expect(narrowedMarkup).toContain('data-policy-effect="Narrow"');
    expect(narrowedMarkup).toContain('data-narrowed-from="READ_ONLY"');
    expect(narrowedMarkup).toContain('data-narrowed-to="READ_WRITE"');
    expect(narrowedMarkup).toContain('data-policy-rule-id="hr-salary-guard"');

    const denied = toPolicyBadgeViewModel({
      effect: "Deny",
      reason: "matching_deny_rule",
      matchedRuleIds: ["no-prod-deletes"]
    });
    const deniedMarkup = renderToStaticMarkup(<PolicyBadge model={denied} />);
    expect(deniedMarkup).toContain('data-policy-effect="Deny"');
    expect(deniedMarkup).toContain('data-policy-rule-id="no-prod-deletes"');
    expect(denied.narrowedFrom).toBeNull();

    const unreported = toPolicyBadgeViewModel(null);
    const unreportedMarkup = renderToStaticMarkup(<PolicyBadge model={unreported} />);
    expect(unreported.status).toBe("not_reported");
    expect(unreportedMarkup).toContain('data-policy-effect="not_reported"');
    expect(unreported.detail).toContain("not a statement that no policy applied");
  });

  it("renders an edition timeline as a strict single-parent chain", () => {
    const EditionTimeline = OMCP_SKIN.renderers.EditionTimeline;
    const model = editionTimelineFixture();
    const markup = renderToStaticMarkup(<EditionTimeline model={model} />);

    expect(markup).toContain('data-edition-linear="true"');
    const orders = [...markup.matchAll(/data-linear-order="(\d+)"/g)].map((match) =>
      Number(match[1])
    );
    expect(orders).toEqual([...orders].sort((left, right) => left - right));
    for (const stage of model.stages.slice(1)) {
      expect(stage.parentEdition).not.toBeNull();
    }

    const branched = toEditionTimelineViewModel([
      {
        proposalId: "a",
        baseEdition: "ORA$BASE",
        childEdition: "LEFT",
        status: "requested",
        objectCount: 1
      },
      {
        proposalId: "b",
        baseEdition: "ORA$BASE",
        childEdition: "RIGHT",
        status: "requested",
        objectCount: 1
      }
    ]);
    expect(branched.linear).toBe(false);
    expect(renderToStaticMarkup(<EditionTimeline model={branched} />)).toContain(
      'data-edition-linear="false"'
    );
  });

  it("renders certified mask decisions without inventing a pass-through", () => {
    const MaskBadge = OMCP_SKIN.renderers.MaskBadge;
    const certified = maskBadgeFixture();
    const markup = renderToStaticMarkup(<MaskBadge model={certified} />);

    expect(markup).toContain('data-mask-status="certified"');
    expect(markup).toContain(`data-mask-policy-id="${certified.policyId}"`);
    expect(markup).toContain('data-masked="true"');
    expect(markup).toContain('data-mask-action="tokenize"');
    expect(markup).toContain('data-masked="false"');

    const absent = toMaskBadgeViewModel(null);
    const absentMarkup = renderToStaticMarkup(<MaskBadge model={absent} />);
    expect(absent.status).toBe("no_certificate");
    expect(absent.detail).toContain("not proof that nothing was masked");
    expect(absentMarkup).toContain('data-mask-status="no_certificate"');
    expect(absentMarkup).not.toContain('data-masked="false"');
  });
});
