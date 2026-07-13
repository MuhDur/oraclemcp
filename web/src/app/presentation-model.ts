export type DashboardTone = "neutral" | "ok" | "warn" | "off" | "info";

export type ClearanceLevel = "READ_ONLY" | "READ_WRITE" | "DDL" | "ADMIN";

export type GoNoGoVerdict = "GO" | "NO-GO" | "SYNC";

export type HealthPosture = "nominal" | "working" | "blocked" | "syncing" | "idle";

export type SignatureId = "go_no_go" | "countdown" | "logbook";

export type ThemeMode =
  | "light"
  | "dark"
  | "colorblind"
  | "high-contrast"
  | "reduced-motion";

export type BigBoardRendererKind = "orrery3d" | "board2d" | "table";

export type SkinCapability = {
  webgl: boolean;
  reducedMotion: boolean;
  highContrast: boolean;
  forcedColors: boolean;
  preferTable: boolean;
};

export type ClearanceViewModel = {
  level: ClearanceLevel;
  ordinal: number;
  label: ClearanceLevel;
};

export type SignatureViewModel = {
  id: SignatureId;
  label: string;
  value: string;
  detail: string;
  tone: DashboardTone;
  activity: number;
};

export type GroundControlCounts = {
  lanes: number;
  prod: number;
  held: number;
};

export type GroundControlChain = {
  status: "intact" | "broken" | "syncing" | "unavailable";
  label: string;
  height: number | null;
  // Epoch millis of the last successful verify fetch; the strip renders a live
  // "verified Ns ago" from it. Null when the tail has never resolved.
  verifiedAtMs: number | null;
};

export type GroundControlViewModel = {
  grammarVersion: 1;
  verdict: GoNoGoVerdict;
  health: HealthPosture;
  clearanceLadder: readonly ClearanceViewModel[];
  clearanceStatus: {
    label: string;
    tone: DashboardTone;
    blocked: number;
  };
  signatures: readonly SignatureViewModel[];
  // Optional status-strip extensions (Appendix G): the headline the operator
  // reads first, the lane/prod/held counts, and the audit hash-chain summary.
  // Optional so the session mission header and skin fixture stay valid without
  // synthesizing them.
  statusLine?: {
    headline: string;
    tone: DashboardTone;
  };
  counts?: GroundControlCounts;
  chain?: GroundControlChain;
};

export type FleetSessionViewModel = {
  laneId: string;
  subjectIdHash: string;
  status: HealthPosture;
  clearance: ClearanceLevel;
  activity: number;
  requests: number;
  blocked: number;
  latencyMs: number;
};

export type FleetViewModel = {
  grammarVersion: 1;
  verdict: GoNoGoVerdict;
  health: HealthPosture;
  activity: number;
  totals: {
    activeLanes: number;
    requests: number;
    blocked: number;
    errors: number;
    meanLatencyMs: number;
    poolActive: number;
  };
  sessions: readonly FleetSessionViewModel[];
};

// ── Verdict proofs (Arc B1) ──────────────────────────────────────────────────
// A verdict certificate (ADR 0010) is a redacted witness of the classifier
// decision that already gated a statement. The console never treats it as an
// authorization: it re-checks the binding client-side and renders the rule
// derivation that produced the GO/NO-GO.

export type VerdictKind = "SAFE" | "GUARDED" | "DESTRUCTIVE" | "FORBIDDEN";

/**
 * Certificate rule registry, generation 1 (ADR 0010).
 *
 * Rule ids are immutable and `construct` labels are an allowlist, never free
 * text. A derivation step outside this table is an unverifiable proof, so the
 * inspector marks it unregistered and refuses to call the certificate verified
 * — it never invents a meaning for an id it does not know.
 */
export const VERDICT_RULE_REGISTRY: Readonly<Record<string, readonly string[]>> = {
  R15: [
    "routine_calls:absent",
    "routine_purity:all_proven_read_only",
    "routine_purity:unproven_present"
  ],
  R16: [
    "final_verdict:SAFE",
    "final_verdict:GUARDED",
    "final_verdict:DESTRUCTIVE",
    "final_verdict:FORBIDDEN"
  ]
};

export type VerdictDerivationView = {
  ruleId: string;
  construct: string;
  // False when the id or its construct label is outside the registry above.
  registered: boolean;
};

export type VerdictProofCheckView = {
  id: "audit_binding" | "statement_digest" | "rule_registry" | "chain_hash";
  label: string;
  ok: boolean;
  detail: string;
};

export type VerdictProofViewModel = {
  grammarVersion: 1;
  seq: number;
  timestamp: string;
  tool: string;
  subjectIdHash: string;
  verdict: VerdictKind;
  // GO when the classifier admitted the statement at a level, NO-GO when it
  // refused it outright (FORBIDDEN has no required level).
  goNoGo: GoNoGoVerdict;
  admitted: boolean;
  level: ClearanceLevel | null;
  // Domain-separated hash of the certificate core, as covered by the audit chain.
  certHash: string;
  auditHash: string | null;
  stmtDigest: string;
  classifierVersion: string;
  observedScn: string | null;
  derivation: readonly VerdictDerivationView[];
  checks: readonly VerdictProofCheckView[];
  proofStatus: "verified" | "unverified";
  tone: DashboardTone;
};

/** The wire shape the inspector reads (see `parseVerdictProofs`). */
export type VerdictProofInput = {
  seq: number;
  timestamp: string;
  tool: string;
  subjectIdHash: string;
  certHash: string;
  auditHash: string | null;
  certificate: {
    stmt_digest: string;
    level: ClearanceLevel | null;
    verdict: VerdictKind;
    derivation: readonly { rule_id: string; construct: string }[];
    classifier_version: string;
    observed_scn: string | null;
    bound_audit_hash: string | null;
  };
  checks: readonly VerdictProofCheckView[];
};

export function isRegisteredDerivationStep(ruleId: string, construct: string): boolean {
  const constructs = VERDICT_RULE_REGISTRY[ruleId];
  return constructs !== undefined && constructs.includes(construct);
}

export function toVerdictProofViewModel(proof: VerdictProofInput): VerdictProofViewModel {
  const certificate = proof.certificate;
  const derivation = certificate.derivation.map((step) => ({
    ruleId: step.rule_id,
    construct: step.construct,
    registered: isRegisteredDerivationStep(step.rule_id, step.construct)
  }));
  const admitted = certificate.verdict !== "FORBIDDEN" && certificate.level !== null;
  // Fail closed: an unregistered rule id or any failed binding check leaves the
  // proof unverified, even when the certificate claims a benign verdict.
  const verified =
    derivation.length > 0 &&
    derivation.every((step) => step.registered) &&
    proof.checks.length > 0 &&
    proof.checks.every((check) => check.ok);
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    seq: proof.seq,
    timestamp: proof.timestamp,
    tool: proof.tool,
    subjectIdHash: proof.subjectIdHash,
    verdict: certificate.verdict,
    goNoGo: admitted ? "GO" : "NO-GO",
    admitted,
    level: certificate.level,
    certHash: proof.certHash,
    auditHash: proof.auditHash,
    stmtDigest: certificate.stmt_digest,
    classifierVersion: certificate.classifier_version,
    observedScn: certificate.observed_scn,
    derivation,
    checks: proof.checks,
    proofStatus: verified ? "verified" : "unverified",
    tone: !verified ? "warn" : admitted ? "ok" : "info"
  };
}

// ── Policy-narrowing badge (Arc N) ───────────────────────────────────────────
// The policy evaluator is monotone: it composes as `base AND policy` and has no
// Allow outcome. It can only Deny a statement or Narrow it — raise the required
// level (never lower it) and add conjunctive row predicates. So the badge's job
// is to show what the policy TOOK AWAY: the level it narrowed from, the level it
// narrowed to, and every rule id that fired.
//
// When a response carries no policy evaluation the badge says "not reported" —
// which is NOT the same claim as "no policy applied", and it must never be
// rendered as a clean bill of health.

export type PolicyEffect = "Deny" | "Narrow";

export type PolicyPredicateViewModel = {
  ruleId: string;
  target: string;
  sqlFragment: string;
};

export type PolicyBadgeViewModel = {
  grammarVersion: 1;
  status: "evaluated" | "not_reported";
  effect: PolicyEffect | null;
  // The classifier's level BEFORE the policy narrowed it. Policy never lowers it.
  narrowedFrom: ClearanceLevel | null;
  narrowedTo: ClearanceLevel | null;
  narrowed: boolean;
  denialReason: string | null;
  matchedRuleIds: readonly string[];
  predicates: readonly PolicyPredicateViewModel[];
  headline: string;
  detail: string;
  tone: DashboardTone;
};

export type PolicyTighteningInput =
  | {
      effect: "Deny";
      reason: string;
      matchedRuleIds: readonly string[];
    }
  | {
      effect: "Narrow";
      baseRequiredLevel: ClearanceLevel;
      requiredLevel: ClearanceLevel;
      matchedRuleIds: readonly string[];
      predicates: readonly PolicyPredicateViewModel[];
    };

const CLEARANCE_ORDINAL: Readonly<Record<ClearanceLevel, number>> = {
  READ_ONLY: 0,
  READ_WRITE: 1,
  DDL: 2,
  ADMIN: 3
};

export function toPolicyBadgeViewModel(
  tightening: PolicyTighteningInput | null
): PolicyBadgeViewModel {
  if (!tightening) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      status: "not_reported",
      effect: null,
      narrowedFrom: null,
      narrowedTo: null,
      narrowed: false,
      denialReason: null,
      matchedRuleIds: [],
      predicates: [],
      headline: "No policy evaluation reported",
      detail:
        "This response carried no policy verdict. That is not a statement that no policy applied — the console reports only what the server proves.",
      tone: "off"
    };
  }
  if (tightening.effect === "Deny") {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      status: "evaluated",
      effect: "Deny",
      narrowedFrom: null,
      narrowedTo: null,
      narrowed: false,
      denialReason: tightening.reason,
      matchedRuleIds: tightening.matchedRuleIds,
      predicates: [],
      headline: "Denied by policy",
      detail: `The policy refused this statement before dispatch (${tightening.reason}).`,
      tone: "warn"
    };
  }
  const narrowed =
    CLEARANCE_ORDINAL[tightening.requiredLevel] > CLEARANCE_ORDINAL[tightening.baseRequiredLevel] ||
    tightening.predicates.length > 0 ||
    tightening.matchedRuleIds.length > 0;
  const levelRaised =
    CLEARANCE_ORDINAL[tightening.requiredLevel] > CLEARANCE_ORDINAL[tightening.baseRequiredLevel];
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    status: "evaluated",
    effect: "Narrow",
    narrowedFrom: tightening.baseRequiredLevel,
    narrowedTo: tightening.requiredLevel,
    narrowed,
    denialReason: null,
    matchedRuleIds: tightening.matchedRuleIds,
    predicates: tightening.predicates,
    headline: levelRaised
      ? `Level raised ${tightening.baseRequiredLevel} → ${tightening.requiredLevel}`
      : narrowed
        ? `Narrowed at ${tightening.requiredLevel}`
        : `No policy constraint added at ${tightening.requiredLevel}`,
    detail: narrowed
      ? "Policy is monotone: it can only raise the required level and add row predicates, never grant authority."
      : "Every matched rule was the identity; the classifier's own decision still gates this statement.",
    tone: narrowed ? "info" : "ok"
  };
}

/** A narrowing that raises READ_ONLY to READ_WRITE and adds a row predicate. */
export function policyBadgeFixture(): PolicyBadgeViewModel {
  return toPolicyBadgeViewModel({
    effect: "Narrow",
    baseRequiredLevel: "READ_ONLY",
    requiredLevel: "READ_WRITE",
    matchedRuleIds: ["hr-salary-guard", "tenant-scope"],
    predicates: [
      {
        ruleId: "tenant-scope",
        target: "HR.EMPLOYEES",
        sqlFragment: "TENANT_ID = SYS_CONTEXT('OMCP', 'TENANT')"
      }
    ]
  });
}

// ── Fleet map (Arc H) ────────────────────────────────────────────────────────
// `oracle_orient fleet=true` maps every MCP-visible profile independently and
// returns a typed lane status per profile: REACHABLE, UNREACHABLE, FAIL_CLOSED.
// The whole point of that design is that one dead lane never omits or fails the
// others — so the map must never DROP a node it could not reach. An unreachable
// database is a fact about the fleet, not a gap in the picture.

export type FleetDbStatus = "reachable" | "unreachable" | "fail_closed";

export type FleetDriftViewModel = {
  baselineProfile: string;
  schemaChanged: boolean;
  foreignKeysChanged: boolean;
  freshnessChanged: boolean;
  recentDdlChanged: boolean;
  changedSections: readonly string[];
};

export type FleetDbViewModel = {
  dbId: string;
  status: FleetDbStatus;
  serverVersion: string | null;
  databaseRole: string | null;
  openMode: string | null;
  readOnly: boolean | null;
  poolOpenConnections: number | null;
  // Null whenever the lane was not read — an unread lane has no drift, and the
  // console must not render "no drift" for a database it never reached.
  drift: FleetDriftViewModel | null;
  errorCode: string | null;
  errorMessage: string | null;
  detail: string;
  tone: DashboardTone;
};

export type FleetMapViewModel = {
  grammarVersion: 1;
  profileCount: number;
  reachableCount: number;
  unreachableCount: number;
  failClosedCount: number;
  baselineProfile: string | null;
  driftedCount: number;
  headline: string;
  detail: string;
  nodes: readonly FleetDbViewModel[];
  tone: DashboardTone;
};

export type FleetMapInput = {
  profiles: readonly {
    profile: string;
    status: FleetDbStatus;
    serverVersion: string | null;
    databaseRole: string | null;
    openMode: string | null;
    readOnly: boolean | null;
    poolOpenConnections: number | null;
    drift: FleetDriftViewModel | null;
    errorCode: string | null;
    errorMessage: string | null;
  }[];
  summary: {
    profileCount: number;
    reachableCount: number;
    unreachableCount: number;
    failClosedCount: number;
  } | null;
};

export function driftSections(drift: {
  schemaChanged: boolean;
  foreignKeysChanged: boolean;
  freshnessChanged: boolean;
  recentDdlChanged: boolean;
}): string[] {
  const sections: string[] = [];
  if (drift.schemaChanged) {
    sections.push("schema");
  }
  if (drift.foreignKeysChanged) {
    sections.push("foreign_keys");
  }
  if (drift.freshnessChanged) {
    sections.push("freshness");
  }
  if (drift.recentDdlChanged) {
    sections.push("recent_ddl");
  }
  return sections;
}

export function toFleetMapViewModel(input: FleetMapInput): FleetMapViewModel {
  const nodes = input.profiles.map((profile): FleetDbViewModel => {
    if (profile.status === "reachable") {
      const changed = profile.drift?.changedSections ?? [];
      return {
        dbId: profile.profile,
        status: "reachable",
        serverVersion: profile.serverVersion,
        databaseRole: profile.databaseRole,
        openMode: profile.openMode,
        readOnly: profile.readOnly,
        poolOpenConnections: profile.poolOpenConnections,
        drift: profile.drift,
        errorCode: null,
        errorMessage: null,
        detail:
          changed.length > 0
            ? `drift vs ${profile.drift?.baselineProfile}: ${changed.join(", ")}`
            : profile.drift
              ? `no drift vs ${profile.drift.baselineProfile}`
              : "reachable",
        tone: changed.length > 0 ? "info" : "ok"
      };
    }
    return {
      dbId: profile.profile,
      status: profile.status,
      serverVersion: null,
      databaseRole: null,
      openMode: null,
      readOnly: null,
      poolOpenConnections: null,
      // Never "no drift": an unread lane was not compared to anything.
      drift: null,
      errorCode: profile.errorCode,
      errorMessage: profile.errorMessage,
      detail:
        profile.errorMessage ??
        (profile.status === "unreachable"
          ? "profile connection or orientation metadata is unavailable"
          : "the lane refused fail-closed"),
      tone: "warn"
    };
  });

  const summary = input.summary;
  const reachableCount = summary?.reachableCount ?? nodes.filter((n) => n.status === "reachable").length;
  const unreachableCount =
    summary?.unreachableCount ?? nodes.filter((n) => n.status === "unreachable").length;
  const failClosedCount =
    summary?.failClosedCount ?? nodes.filter((n) => n.status === "fail_closed").length;
  const driftedCount = nodes.filter((node) => (node.drift?.changedSections.length ?? 0) > 0).length;
  const degraded = unreachableCount + failClosedCount;

  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    profileCount: summary?.profileCount ?? nodes.length,
    reachableCount,
    unreachableCount,
    failClosedCount,
    baselineProfile: nodes.find((node) => node.drift)?.drift?.baselineProfile ?? null,
    driftedCount,
    headline:
      degraded > 0
        ? `${reachableCount} of ${nodes.length} database(s) reachable — ${degraded} degraded`
        : `${reachableCount} database(s) reachable`,
    detail:
      degraded > 0
        ? "A lane that could not be read is shown as it is; it is never dropped from the map and never reported as drift-free."
        : "Every visible profile answered its own orientation read.",
    nodes,
    tone: degraded > 0 ? "warn" : "ok"
  };
}

/** Two healthy databases, one drifted, and one unreachable that must still render. */
export function fleetMapFixture(): FleetMapViewModel {
  return toFleetMapViewModel({
    summary: {
      profileCount: 4,
      reachableCount: 3,
      unreachableCount: 1,
      failClosedCount: 0
    },
    profiles: [
      {
        profile: "prod_read",
        status: "reachable",
        serverVersion: "23.4.0.0",
        databaseRole: "PRIMARY",
        openMode: "READ WRITE",
        readOnly: false,
        poolOpenConnections: 2,
        drift: {
          baselineProfile: "prod_read",
          schemaChanged: false,
          foreignKeysChanged: false,
          freshnessChanged: false,
          recentDdlChanged: false,
          changedSections: []
        },
        errorCode: null,
        errorMessage: null
      },
      {
        profile: "prod_standby",
        status: "reachable",
        serverVersion: "23.4.0.0",
        databaseRole: "PHYSICAL STANDBY",
        openMode: "READ ONLY",
        readOnly: true,
        poolOpenConnections: 1,
        drift: {
          baselineProfile: "prod_read",
          schemaChanged: false,
          foreignKeysChanged: false,
          freshnessChanged: true,
          recentDdlChanged: false,
          changedSections: ["freshness"]
        },
        errorCode: null,
        errorMessage: null
      },
      {
        profile: "staging",
        status: "reachable",
        serverVersion: "21.3.0.0",
        databaseRole: "PRIMARY",
        openMode: "READ WRITE",
        readOnly: false,
        poolOpenConnections: 1,
        drift: {
          baselineProfile: "prod_read",
          schemaChanged: true,
          foreignKeysChanged: true,
          freshnessChanged: false,
          recentDdlChanged: true,
          changedSections: ["schema", "foreign_keys", "recent_ddl"]
        },
        errorCode: null,
        errorMessage: null
      },
      {
        profile: "dr_site",
        status: "unreachable",
        serverVersion: null,
        databaseRole: null,
        openMode: null,
        readOnly: null,
        poolOpenConnections: null,
        drift: null,
        errorCode: "UNREACHABLE",
        errorMessage: "profile connection or orientation metadata is unavailable"
      }
    ]
  });
}

// ── Egress mask badge (Arc M) ────────────────────────────────────────────────
// A result page carries a `mask_certificate` ONLY when the active policy
// actually transformed a column. So an absent certificate is not proof that
// nothing was masked — it is the absence of proof, and the badge says exactly
// that. When the certificate is there it lists every column in select-list
// order, including the ones that passed through, and each decision names the
// rule that made it.

export type MaskAction = "pass" | "mask" | "tokenize" | "null";

export type MaskSource = "rule" | "mask_unknown_default" | "pass";

export type MaskColumnViewModel = {
  column: string;
  oracleType: string;
  masked: boolean;
  action: MaskAction;
  source: MaskSource;
  ruleIndex: number | null;
  ruleTag: string | null;
  saltId: string | null;
  detail: string;
  tone: DashboardTone;
};

export type MaskBadgeViewModel = {
  grammarVersion: 1;
  status: "certified" | "no_certificate";
  policyId: string | null;
  profile: string | null;
  // The audit entry the certificate was durably committed against.
  auditHash: string | null;
  maskedColumns: number;
  passedColumns: number;
  headline: string;
  detail: string;
  columns: readonly MaskColumnViewModel[];
  tone: DashboardTone;
};

export type MaskCertificateInput = {
  policyId: string;
  profile: string | null;
  auditHash: string | null;
  decisions: readonly {
    column: string;
    oracleType: string;
    action: MaskAction;
    source: MaskSource;
    ruleIndex: number | null;
    ruleTag: string | null;
    saltId: string | null;
  }[];
};

function maskColumnDetail(decision: MaskCertificateInput["decisions"][number]): string {
  switch (decision.source) {
    case "rule":
      return decision.ruleTag
        ? `rule ${decision.ruleIndex ?? "?"} (${decision.ruleTag})`
        : `rule ${decision.ruleIndex ?? "?"}`;
    case "mask_unknown_default":
      return "no rule matched — masked by the fail-closed mask_unknown_default";
    case "pass":
      return "no rule matched — the policy passed this column through";
  }
}

export function toMaskBadgeViewModel(
  certificate: MaskCertificateInput | null
): MaskBadgeViewModel {
  if (!certificate) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      status: "no_certificate",
      policyId: null,
      profile: null,
      auditHash: null,
      maskedColumns: 0,
      passedColumns: 0,
      headline: "No mask certificate",
      detail:
        "The server emits a mask certificate only when the policy transformed a column, so this page carries no proof either way — absence of a certificate is not proof that nothing was masked.",
      columns: [],
      tone: "off"
    };
  }
  const columns = certificate.decisions.map((decision): MaskColumnViewModel => {
    const masked = decision.action !== "pass";
    return {
      column: decision.column,
      oracleType: decision.oracleType,
      masked,
      action: decision.action,
      source: decision.source,
      ruleIndex: decision.ruleIndex,
      ruleTag: decision.ruleTag,
      saltId: decision.saltId,
      detail: maskColumnDetail(decision),
      tone: masked ? "warn" : "ok"
    };
  });
  const maskedColumns = columns.filter((column) => column.masked).length;
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    status: "certified",
    policyId: certificate.policyId,
    profile: certificate.profile,
    auditHash: certificate.auditHash,
    maskedColumns,
    passedColumns: columns.length - maskedColumns,
    headline: `${maskedColumns} of ${columns.length} column(s) transformed on egress`,
    detail: certificate.auditHash
      ? "Every decision below was committed to the audit chain before the page was released."
      : "The certificate is not yet bound to an audit entry.",
    columns,
    tone: maskedColumns > 0 ? "warn" : "ok"
  };
}

/** A policy that tokenizes one column, nulls another, and passes a third. */
export function maskBadgeFixture(): MaskBadgeViewModel {
  return toMaskBadgeViewModel({
    policyId: "sha256:pol".padEnd(71, "0"),
    profile: "prod_read",
    auditHash: "sha256:aud".padEnd(71, "0"),
    decisions: [
      {
        column: "EMPLOYEE_ID",
        oracleType: "NUMBER",
        action: "pass",
        source: "pass",
        ruleIndex: null,
        ruleTag: null,
        saltId: null
      },
      {
        column: "EMAIL",
        oracleType: "VARCHAR2",
        action: "tokenize",
        source: "rule",
        ruleIndex: 0,
        ruleTag: "pii:email",
        saltId: "salt-2026-07"
      },
      {
        column: "SALARY",
        oracleType: "NUMBER",
        action: "null",
        source: "rule",
        ruleIndex: 1,
        ruleTag: "pii:compensation",
        saltId: null
      },
      {
        column: "NOTES",
        oracleType: "CLOB",
        action: "mask",
        source: "mask_unknown_default",
        ruleIndex: null,
        ruleTag: null,
        saltId: null
      }
    ]
  });
}

// ── SCN time-scrubber (Arc A) ────────────────────────────────────────────────
// `oracle_query as_of {scn|timestamp}` replays a proven-read-only SELECT against
// a past committed snapshot. That is the only time-travel the server offers the
// console: no operator endpoint publishes the database's CURRENT SCN, and none
// publishes the flashback retention window. So the scrubber's axis is not the
// database's history — it is exactly the snapshots this console has SUCCESSFULLY
// read, and the view-model says so rather than drawing a timeline it cannot see.

export type ScnMarkStatus =
  | "confirmed" // the server replayed the query at this SCN and returned rows
  | "refused" // the server refused this snapshot (privilege, too old, …)
  | "pending" // in flight
  | "timestamp"; // pinned by wall clock; Oracle resolved it, but never echoed the SCN

export type ScnMarkViewModel = {
  id: string;
  scn: number | null;
  label: string;
  status: ScnMarkStatus;
  detail: string;
  tone: DashboardTone;
};

export type ScnScrubberViewModel = {
  grammarVersion: 1;
  current: number | null;
  min: number | null;
  max: number | null;
  // True when `current` had to be pulled back inside [min, max].
  clamped: boolean;
  // The axis exists only once a snapshot has been confirmed by the server.
  rangeKnown: boolean;
  // Position of `current` on [min, max], 0..1. Null when the range is unknown.
  position: number | null;
  status: "idle" | "pinned" | "refused" | "unavailable";
  headline: string;
  detail: string;
  marks: readonly ScnMarkViewModel[];
  tone: DashboardTone;
};

export type ScnScrubberInput = {
  current: number | null;
  marks: readonly ScnMarkViewModel[];
  // The verbatim server refusal for the snapshot currently pinned, if it refused.
  refusal: string | null;
};

export function clampScn(current: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, current));
}

export function toScnScrubberViewModel(input: ScnScrubberInput): ScnScrubberViewModel {
  const confirmed = input.marks
    .filter((mark) => mark.status === "confirmed" && mark.scn !== null)
    .map((mark) => mark.scn as number);
  const min = confirmed.length > 0 ? Math.min(...confirmed) : null;
  const max = confirmed.length > 0 ? Math.max(...confirmed) : null;
  const rangeKnown = min !== null && max !== null;

  const requested = input.current;
  const current =
    requested !== null && rangeKnown ? clampScn(requested, min, max) : requested;
  const clamped = requested !== null && current !== null && current !== requested;
  const span = rangeKnown ? max - min : 0;
  const position =
    rangeKnown && current !== null ? (span === 0 ? 1 : (current - min) / span) : null;

  if (input.refusal) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      current,
      min,
      max,
      clamped,
      rangeKnown,
      position,
      status: "refused",
      headline: "Snapshot refused",
      detail: input.refusal,
      marks: input.marks,
      tone: "warn"
    };
  }
  if (current === null) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      current: null,
      min,
      max,
      clamped: false,
      rangeKnown,
      position: null,
      status: rangeKnown ? "idle" : "unavailable",
      headline: rangeKnown ? "Live (no snapshot pinned)" : "No snapshot read yet",
      detail:
        "The server publishes neither the current SCN nor the flashback retention window, so this axis spans only the snapshots this console has read.",
      marks: input.marks,
      tone: "off"
    };
  }
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    current,
    min,
    max,
    clamped,
    rangeKnown,
    position,
    status: "pinned",
    headline: `Reading as of SCN ${current}`,
    detail: clamped
      ? "The requested SCN sat outside the snapshots this console has confirmed; it was clamped to the known range."
      : "This SELECT was replayed against that committed snapshot by the server.",
    marks: input.marks,
    tone: "info"
  };
}

/** Two confirmed snapshots and one refused one, with the current SCN in range. */
export function scnScrubberFixture(): ScnScrubberViewModel {
  return toScnScrubberViewModel({
    current: 15_200_400,
    refusal: null,
    marks: [
      {
        id: "m1",
        scn: 15_200_000,
        label: "SCN 15200000",
        status: "confirmed",
        detail: "42 rows",
        tone: "ok"
      },
      {
        id: "m2",
        scn: 15_200_400,
        label: "SCN 15200400",
        status: "confirmed",
        detail: "41 rows",
        tone: "ok"
      },
      {
        id: "m3",
        scn: 15_900_000,
        label: "SCN 15900000",
        status: "refused",
        detail: "ORA-01031: insufficient privileges (the profile lacks FLASHBACK)",
        tone: "warn"
      }
    ]
  });
}

// ── Cost/gas badge (Arc G) ───────────────────────────────────────────────────
// The cost gate prices a statement with the optimizer before it runs. Two facts
// reach the console, and only these two:
//   • a refusal carries `query_cost_refusal` — the estimate AND the ceiling it
//     broke, plus the plan rows and predicate hints that explain the price;
//   • `oracle_explain_plan` carries `cost_estimate.summary.total_cost`.
// The server never publishes `max_query_cost` on the happy path, so a statement
// that merely passed the gate has NO ceiling to show. The badge says that in as
// many words instead of implying an unlimited budget.

export type CostVerdict =
  | "refused" // priced above the ceiling; the gate refused it before execution
  | "within_ceiling" // an estimate and a ceiling in force, and it fits
  | "estimated" // estimate known, but no ceiling is in force as far as we know
  | "ungated" // the active profile declares no max_query_cost: the gate is off
  | "unavailable" // the optimizer could not price it — the gate fails closed
  | "unknown"; // nothing priced this statement yet

export type CostPlanRowViewModel = {
  id: number;
  operation: string;
  objectName: string | null;
  cost: number | null;
  cardinality: number | null;
};

export type CostBadgeViewModel = {
  grammarVersion: 1;
  verdict: CostVerdict;
  estimate: number | null;
  ceiling: number | null;
  ceilingSource: CostCeilingSource;
  // estimate / ceiling, clamped to [0, 1] for the meter. Null when either is.
  ratio: number | null;
  headline: string;
  detail: string;
  // The server's own reminder that optimizer costs are relative estimates.
  note: string | null;
  hints: readonly string[];
  planRows: readonly CostPlanRowViewModel[];
  tone: DashboardTone;
};

export type CostRefusalInput = {
  estimatedCost: number;
  maxQueryCost: number;
  predicateHints: readonly string[];
  planRows: readonly CostPlanRowViewModel[];
  note: string | null;
};

export type CostCeilingSource = "refusal" | "config" | "unknown";

export type CostBadgeInput = {
  // The `query_cost_refusal` payload of a refused statement, when there is one.
  refusal: CostRefusalInput | null;
  // `cost_estimate.summary.total_cost` from an explain-plan run, when there is one.
  estimate: number | null;
  // The reason the optimizer could not price the statement, verbatim.
  estimateUnavailable: string | null;
  note: string | null;
  planRows: readonly CostPlanRowViewModel[];
  // The ceiling in force, from the active profile's published `max_query_cost`
  // or from a refusal. A refusal wins: the server has already met the profile
  // ceiling with any per-call one via min(), so its number is the effective one.
  ceiling: number | null;
  ceilingSource?: CostCeilingSource;
  // True only when the config positively says the active profile declares NO
  // `max_query_cost` — `oracle_query` is not cost-gated for it. That is a fact,
  // and it is not the same as "we do not know the ceiling".
  ungated?: boolean;
};

export function toCostBadgeViewModel(input: CostBadgeInput): CostBadgeViewModel {
  const ungated = input.ungated === true && input.ceiling === null;
  const ceilingSource: CostCeilingSource =
    input.refusal !== null
      ? "refusal"
      : (input.ceilingSource ?? (input.ceiling !== null ? "config" : "unknown"));

  if (input.refusal) {
    const { estimatedCost, maxQueryCost } = input.refusal;
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      verdict: "refused",
      estimate: estimatedCost,
      ceiling: maxQueryCost,
      ceilingSource: "refusal",
      ratio: maxQueryCost > 0 ? Math.min(1, estimatedCost / maxQueryCost) : 1,
      headline: `Refused — estimated cost ${estimatedCost} exceeds the ceiling ${maxQueryCost}`,
      detail: "The cost gate priced this statement before execution and refused it. Nothing ran.",
      note: input.refusal.note,
      hints: input.refusal.predicateHints,
      planRows: input.refusal.planRows,
      tone: "warn"
    };
  }
  if (input.estimateUnavailable) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      verdict: "unavailable",
      estimate: null,
      ceiling: input.ceiling,
      ceilingSource,
      ratio: null,
      headline: "Cost unavailable",
      detail: input.estimateUnavailable,
      note: input.note,
      hints: [],
      planRows: [],
      tone: "warn"
    };
  }
  if (input.estimate !== null) {
    const ceiling = input.ceiling;
    const fits = ceiling !== null && input.estimate <= ceiling;
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      verdict: ungated ? "ungated" : fits ? "within_ceiling" : "estimated",
      estimate: input.estimate,
      ceiling,
      ceilingSource,
      ratio: ceiling !== null && ceiling > 0 ? Math.min(1, input.estimate / ceiling) : null,
      headline: ungated
        ? `Estimated cost ${input.estimate} — no ceiling configured`
        : fits
          ? `Estimated cost ${input.estimate} of ceiling ${ceiling}`
          : `Estimated cost ${input.estimate}`,
      detail: ungated
        ? "The active profile declares no max_query_cost, so oracle_query is not cost-gated on it."
        : fits
          ? `The optimizer priced this statement under the ceiling in force (from the ${ceilingSource === "config" ? "profile configuration" : "gate's own refusal"}).`
          : "No ceiling is in force for this statement as far as the server has told the console.",
      note: input.note,
      hints: [],
      planRows: input.planRows,
      tone: ungated ? "info" : fits ? "ok" : "info"
    };
  }
  if (ungated) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      verdict: "ungated",
      estimate: null,
      ceiling: null,
      ceilingSource,
      ratio: null,
      headline: "No cost ceiling configured",
      detail:
        "The active profile declares no max_query_cost, so oracle_query is not cost-gated on it. This is the configuration speaking, not a missing reading.",
      note: null,
      hints: [],
      planRows: [],
      tone: "info"
    };
  }
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    verdict: "unknown",
    estimate: null,
    ceiling: input.ceiling,
    ceilingSource,
    ratio: null,
    headline:
      input.ceiling !== null ? `Ceiling ${input.ceiling} — not yet priced` : "Not priced",
    detail:
      input.ceiling !== null
        ? "The ceiling in force comes from the active profile's configuration. Run an EXPLAIN PLAN estimate to price this statement against it."
        : "Nothing has priced this statement, and no ceiling is known. Run an EXPLAIN PLAN estimate, or read the ceiling off a cost refusal.",
    note: null,
    hints: [],
    planRows: [],
    tone: "off"
  };
}

/** The refusal case: over the ceiling, with the plan rows that explain why. */
export function costBadgeFixture(): CostBadgeViewModel {
  return toCostBadgeViewModel({
    refusal: {
      estimatedCost: 190_000,
      maxQueryCost: 50_000,
      predicateHints: ["line 2 TABLE ACCESS FULL: filter \"SALARY\">:B1"],
      planRows: [
        {
          id: 0,
          operation: "SELECT STATEMENT",
          objectName: null,
          cost: 190_000,
          cardinality: 4_200_000
        },
        {
          id: 2,
          operation: "TABLE ACCESS FULL",
          objectName: "EMPLOYEES",
          cost: 189_800,
          cardinality: 4_200_000
        }
      ],
      note: "optimizer costs are relative estimates, not runtime measurements"
    },
    estimate: null,
    estimateUnavailable: null,
    note: null,
    planRows: [],
    ceiling: null
  });
}

// ── Reversible undo-tree (Arc I) ─────────────────────────────────────────────
// The workspace is a labeled-linear savepoint stack: named checkpoints, with
// statements held (uncommitted) above them. The console must never offer a
// plain Undo for work a ROLLBACK TO SAVEPOINT cannot take back — a sequence
// NEXTVAL, an autonomous transaction, a trigger, non-source-replaceable DDL.
// The server already labels those (`cannot_undo`, `fully_reverted: false`); the
// tree surfaces that label instead of an Undo button.

export type UndoNodeKind = "checkpoint" | "statement";

export type UndoNodeStatus =
  | "live" // checkpoint Oracle still holds; a valid undo target
  | "released" // checkpoint Oracle has erased (undone past, or a txn boundary)
  | "held" // statement pending above a live checkpoint; a rollback takes it back
  | "escaped" // statement whose effect outlives the rollback — NOT undoable
  | "unproven"; // no reversibility evidence (not executed from this console)

export type UndoTreeNodeViewModel = {
  id: string;
  kind: UndoNodeKind;
  // For a checkpoint, its own savepoint name. For a statement, the checkpoint it
  // is held above, or null when it sits outside any workspace.
  checkpointName: string | null;
  label: string;
  status: UndoNodeStatus;
  // True only when this node can be walked back with no caveat. A checkpoint
  // with escaped work above it is deliberately NOT undoable: rolling back to it
  // is a *partial* revert, and a plain Undo would promise more than Oracle does.
  undoable: boolean;
  // Verbatim server-side reason(s) an undo cannot restore this. Null when the
  // node is plainly reversible — the honesty is targeted, not noise.
  cannotUndoReason: string | null;
  // A checkpoint that is still a usable rollback target, but only partially:
  // some effect above it escapes the rollback.
  partialUndo: boolean;
  tone: DashboardTone;
};

export type UndoTreeViewModel = {
  grammarVersion: 1;
  open: boolean;
  heldStatements: number;
  escapedEffects: number;
  liveCheckpoints: readonly string[];
  nodes: readonly UndoTreeNodeViewModel[];
};

/** One observation the tree is built from (see `buildUndoTree`). */
export type UndoTreeEntry = {
  id: string;
  kind: UndoNodeKind;
  checkpointName: string | null;
  label: string;
  // Server-side escape labels, verbatim from `cannot_undo`. Empty = reversible.
  cannotUndo: readonly string[];
  // `fully_reverted` from the tool response; null when this console never saw a
  // response for the statement (for example, an audit record from another lane
  // participant). Null is not evidence of reversibility.
  fullyReverted: boolean | null;
};

export type UndoTreeInput = {
  // The authoritative live workspace, straight from the lane's tool response.
  workspace: { open: boolean; checkpoints: readonly string[]; heldStatements: number } | null;
  entries: readonly UndoTreeEntry[];
};

function escapeReason(entry: UndoTreeEntry): string | null {
  if (entry.cannotUndo.length > 0) {
    return entry.cannotUndo.join(" · ");
  }
  if (entry.fullyReverted === false) {
    return "the server reported this statement was not fully reverted";
  }
  return null;
}

/**
 * Reconcile the console's observations against the live workspace.
 *
 * Fail-closed in three ways: a checkpoint Oracle no longer holds is never an
 * undo target; a statement whose effect escapes rollback is never undoable and
 * always carries its reason; and a statement this console has no reversibility
 * evidence for is `unproven`, not assumed reversible.
 */
export function toUndoTreeViewModel(input: UndoTreeInput): UndoTreeViewModel {
  const live = new Set(input.workspace?.checkpoints ?? []);
  const escapedByCheckpoint = new Map<string, string[]>();
  for (const entry of input.entries) {
    const reason = entry.kind === "statement" ? escapeReason(entry) : null;
    if (reason && entry.checkpointName) {
      const reasons = escapedByCheckpoint.get(entry.checkpointName) ?? [];
      reasons.push(reason);
      escapedByCheckpoint.set(entry.checkpointName, reasons);
    }
  }

  const nodes = input.entries.map((entry): UndoTreeNodeViewModel => {
    if (entry.kind === "checkpoint") {
      const name = entry.checkpointName ?? entry.label;
      const isLive = live.has(name);
      const escaped = escapedByCheckpoint.get(name) ?? [];
      const partialUndo = isLive && escaped.length > 0;
      return {
        id: entry.id,
        kind: "checkpoint",
        checkpointName: name,
        label: name,
        status: isLive ? "live" : "released",
        undoable: isLive && escaped.length === 0,
        cannotUndoReason: !isLive
          ? "Oracle has released this savepoint; it is no longer an undo target"
          : partialUndo
            ? `${escaped.length} statement(s) above this checkpoint escape rollback: ${escaped.join(" · ")}`
            : null,
        partialUndo,
        tone: !isLive ? "off" : partialUndo ? "warn" : "ok"
      };
    }

    const reason = escapeReason(entry);
    if (reason !== null) {
      return {
        id: entry.id,
        kind: "statement",
        checkpointName: entry.checkpointName,
        label: entry.label,
        status: "escaped",
        undoable: false,
        cannotUndoReason: reason,
        partialUndo: false,
        tone: "warn"
      };
    }
    if (entry.fullyReverted === null) {
      return {
        id: entry.id,
        kind: "statement",
        checkpointName: entry.checkpointName,
        label: entry.label,
        status: "unproven",
        undoable: false,
        cannotUndoReason:
          "no reversibility evidence for this statement — it was not executed from this console",
        partialUndo: false,
        tone: "info"
      };
    }
    const held = entry.checkpointName !== null && live.has(entry.checkpointName);
    return {
      id: entry.id,
      kind: "statement",
      checkpointName: entry.checkpointName,
      label: entry.label,
      status: held ? "held" : "released",
      undoable: held,
      cannotUndoReason: held
        ? null
        : "this statement is no longer held in an open workspace; there is nothing left to undo",
      partialUndo: false,
      tone: held ? "ok" : "off"
    };
  });

  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    open: input.workspace?.open ?? false,
    heldStatements: input.workspace?.heldStatements ?? 0,
    escapedEffects: nodes.filter((node) => node.status === "escaped").length,
    liveCheckpoints: input.workspace?.checkpoints ?? [],
    nodes
  };
}

// ── Vector cluster panel (Arc F) ─────────────────────────────────────────────
// `oracle_semantic_search` runs a bounded 23ai VECTOR search through the SAME
// policy, masking, and audit path as oracle_query. Two honesty facts shape this
// panel:
//   • The server orders neighbors by VECTOR_DISTANCE(...) FETCH FIRST k, but it
//     selects only `t.*` — the distance VALUE is never egressed. So the panel's
//     "distance" is the returned RANK (0,1,2,…), which is monotonic by
//     construction, and it says plainly that the numeric distance is not emitted
//     rather than inventing one.
//   • `used_index` is null when the read did not inspect a plan; the panel shows
//     "not reported", never an inferred index.
// And the mask rule holds: a neighbor row is never shown as unmasked when the
// result's mask certificate transformed its columns.

export type VectorMetric = "COSINE" | "EUCLIDEAN" | "DOT";

export type VectorNeighborViewModel = {
  // 0-based position in the server's distance ordering. This IS the neighbor's
  // distance rank — monotonic non-decreasing by construction.
  rank: number;
  // The row's cells in select-list order, already mask-transformed by the server
  // when a mask certificate applied. Never the raw value when masked.
  cells: readonly string[];
  // True when at least one cell of this row was transformed by the mask policy.
  masked: boolean;
};

export type VectorClusterViewModel = {
  grammarVersion: 1;
  status: "results" | "refused" | "empty" | "unavailable";
  metric: VectorMetric | null;
  k: number | null;
  returned: number;
  columns: readonly string[];
  neighbors: readonly VectorNeighborViewModel[];
  // The guarded surface orders by distance but does not emit the distance value.
  distanceReported: false;
  // null = the server did not inspect a plan (never inferred from a request).
  usedIndex: boolean | null;
  // The mask certificate summary for the whole result, or null when the page
  // carried none (absence of proof, not proof of no masking).
  maskPolicyId: string | null;
  maskedColumns: number;
  headline: string;
  detail: string;
  // Verbatim server refusal (e.g. an unproven filter predicate rejected as a
  // data-egress bypass), when the search was refused.
  refusalReason: string | null;
  tone: DashboardTone;
};

export type VectorClusterInput = {
  metric: VectorMetric | null;
  k: number | null;
  columns: readonly string[];
  // Rows in the server's returned (distance) order; each a list of cells.
  rows: readonly (readonly string[])[];
  // Per-row masked flag, derived from the mask certificate (aligned to `rows`).
  rowMasked?: readonly boolean[];
  usedIndex: boolean | null;
  maskPolicyId: string | null;
  maskedColumns: number;
  // Set when the tool refused the search (filter predicate, capability, level).
  refusalReason?: string | null;
};

export function toVectorClusterViewModel(input: VectorClusterInput): VectorClusterViewModel {
  if (input.refusalReason) {
    return {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      status: "refused",
      metric: input.metric,
      k: input.k,
      returned: 0,
      columns: input.columns,
      neighbors: [],
      distanceReported: false,
      usedIndex: input.usedIndex,
      maskPolicyId: input.maskPolicyId,
      maskedColumns: input.maskedColumns,
      headline: "Search refused",
      detail: input.refusalReason,
      refusalReason: input.refusalReason,
      tone: "warn"
    };
  }
  const neighbors = input.rows.map((cells, rank): VectorNeighborViewModel => ({
    rank,
    cells,
    masked: input.rowMasked?.[rank] === true
  }));
  const maskedColumns = input.maskedColumns;
  const status = neighbors.length > 0 ? "results" : "empty";
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    status,
    metric: input.metric,
    k: input.k,
    returned: neighbors.length,
    columns: input.columns,
    neighbors,
    distanceReported: false,
    usedIndex: input.usedIndex,
    maskPolicyId: input.maskPolicyId,
    maskedColumns,
    headline:
      status === "empty"
        ? "No neighbors returned"
        : `${neighbors.length} nearest neighbor(s) by ${input.metric ?? "distance"}`,
    detail:
      maskedColumns > 0
        ? `${maskedColumns} column(s) masked on egress; ordered by distance rank (the server does not emit the distance value).`
        : "Ordered by distance rank; the guarded surface orders by VECTOR_DISTANCE but does not emit the distance value.",
    refusalReason: null,
    tone: maskedColumns > 0 ? "warn" : status === "empty" ? "off" : "ok"
  };
}

/** A k=3 cosine result with one masked column, ordered by distance rank. */
export function vectorClusterFixture(): VectorClusterViewModel {
  return toVectorClusterViewModel({
    metric: "COSINE",
    k: 3,
    columns: ["DOC_ID", "TITLE", "SECRET_NOTE"],
    rows: [
      ["1001", "Onboarding guide", "'?'"],
      ["1042", "Expense policy", "'?'"],
      ["1099", "Travel FAQ", "'?'"]
    ],
    rowMasked: [true, true, true],
    usedIndex: null,
    maskPolicyId: "sha256:pol".padEnd(71, "0"),
    maskedColumns: 1
  });
}

// ── Edition linear timeline (Arc D) ──────────────────────────────────────────
// Oracle editions are inherently LINEAR: every child edition has exactly one
// parent (`base_edition`). The Reviews board renders the proposal chain as a
// timeline, NOT a git graph. The honesty guarantee is that a non-linear shape is
// detected and flagged, never quietly drawn as a straight line — if a base
// edition ever has two children, that is a branch and the model says so.

export type EditionStatus = "requested" | "reviewing" | "withdrawn";

export type EditionStageViewModel = {
  edition: string;
  // The base edition this stage derives from; null for the root of the chain.
  parentEdition: string | null;
  order: number;
  status: EditionStatus | null;
  proposalId: string | null;
  objectCount: number;
  tone: DashboardTone;
};

export type EditionTimelineViewModel = {
  grammarVersion: 1;
  linear: boolean;
  stages: readonly EditionStageViewModel[];
  // Base editions that have more than one child — a branch. Empty when linear.
  branchedFrom: readonly string[];
  headline: string;
  detail: string;
  tone: DashboardTone;
};

export type EditionProposalInput = {
  proposalId: string;
  baseEdition: string;
  childEdition: string;
  status: EditionStatus | null;
  objectCount: number;
};

const EDITION_STATUS_TONE: Readonly<Record<EditionStatus, DashboardTone>> = {
  requested: "info",
  reviewing: "ok",
  withdrawn: "off"
};

export function toEditionTimelineViewModel(
  proposals: readonly EditionProposalInput[]
): EditionTimelineViewModel {
  // One edge per proposal: base_edition -> child_edition.
  const childrenByBase = new Map<string, EditionProposalInput[]>();
  const childEditions = new Set<string>();
  for (const proposal of proposals) {
    const list = childrenByBase.get(proposal.baseEdition) ?? [];
    list.push(proposal);
    childrenByBase.set(proposal.baseEdition, list);
    childEditions.add(proposal.childEdition);
  }
  // A branch = a base edition with more than one child.
  const branchedFrom = [...childrenByBase.entries()]
    .filter(([, children]) => children.length > 1)
    .map(([base]) => base)
    .sort();

  // Roots: base editions that are not themselves a child of any proposal.
  const roots = [...childrenByBase.keys()].filter((base) => !childEditions.has(base)).sort();

  const stages: EditionStageViewModel[] = [];
  const stageOf = (
    edition: string,
    parentEdition: string | null,
    proposal: EditionProposalInput | null
  ): EditionStageViewModel => ({
    edition,
    parentEdition,
    order: stages.length,
    status: proposal?.status ?? null,
    proposalId: proposal?.proposalId ?? null,
    objectCount: proposal?.objectCount ?? 0,
    tone: proposal?.status ? EDITION_STATUS_TONE[proposal.status] : "neutral"
  });

  // Walk the single chain from the first root. Stop if a fork or cycle appears —
  // the flags carry the truth, the walk never fabricates a straight line past a
  // branch.
  const visited = new Set<string>();
  let cursor: string | null = roots[0] ?? proposals[0]?.baseEdition ?? null;
  let parent: string | null = null;
  let parentProposal: EditionProposalInput | null = null;
  while (cursor && !visited.has(cursor)) {
    visited.add(cursor);
    stages.push(stageOf(cursor, parent, parentProposal));
    const children: EditionProposalInput[] = childrenByBase.get(cursor) ?? [];
    const next: EditionProposalInput | null = children[0] ?? null;
    parent = cursor;
    parentProposal = next;
    cursor = next?.childEdition ?? null;
  }

  const linear = branchedFrom.length === 0 && stages.length === childEditions.size + roots.length;
  const tone = proposals.length === 0 ? "off" : linear ? "ok" : "warn";
  return {
    grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
    linear,
    stages,
    branchedFrom,
    headline:
      proposals.length === 0
        ? "No edition proposals"
        : linear
          ? `${stages.length}-stage linear edition chain`
          : `Non-linear edition graph (${branchedFrom.length} branch point(s))`,
    detail: linear
      ? "Each edition derives from exactly one parent; rendered as a straight timeline."
      : "A base edition has more than one child — this is a branch, shown truthfully rather than flattened into a line.",
    tone
  };
}

/** A three-stage linear chain: ORA$BASE -> REVIEW_1 -> REVIEW_2. */
export function editionTimelineFixture(): EditionTimelineViewModel {
  return toEditionTimelineViewModel([
    {
      proposalId: "prop-1",
      baseEdition: "ORA$BASE",
      childEdition: "REVIEW_1",
      status: "reviewing",
      objectCount: 2
    },
    {
      proposalId: "prop-2",
      baseEdition: "REVIEW_1",
      childEdition: "REVIEW_2",
      status: "requested",
      objectCount: 1
    }
  ]);
}

export const DASHBOARD_GRAMMAR = {
  grammarVersion: 1,
  meanings: {
    position: "structure",
    color: "clearance",
    motion: "activity",
    verdict: "GO/NO-GO",
    ladder: "operating-level order"
  }
} as const;

export const CLEARANCE_LADDER: readonly ClearanceViewModel[] = [
  { level: "READ_ONLY", ordinal: 0, label: "READ_ONLY" },
  { level: "READ_WRITE", ordinal: 1, label: "READ_WRITE" },
  { level: "DDL", ordinal: 2, label: "DDL" },
  { level: "ADMIN", ordinal: 3, label: "ADMIN" }
];

export const REQUIRED_THEME_MODES: readonly ThemeMode[] = [
  "light",
  "dark",
  "colorblind",
  "high-contrast",
  "reduced-motion"
];

export const REQUIRED_BIG_BOARD_RENDERERS: readonly BigBoardRendererKind[] = [
  "board2d",
  "table",
  "orrery3d"
];

export function clampActivity(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.min(1, Math.max(0, value));
}

export function defaultSkinCapabilities(): SkinCapability {
  return {
    webgl: false,
    reducedMotion: false,
    highContrast: false,
    forcedColors: false,
    preferTable: false
  };
}

export function normalizeRendererChoice(
  preferred: BigBoardRendererKind,
  capabilities: SkinCapability,
  rendererAvailable: (kind: BigBoardRendererKind) => boolean
): BigBoardRendererKind {
  if (capabilities.preferTable || capabilities.forcedColors) {
    return "table";
  }
  if (preferred === "orrery3d") {
    return capabilities.webgl && !capabilities.reducedMotion && rendererAvailable("orrery3d")
      ? "orrery3d"
      : "board2d";
  }
  if (preferred === "table") {
    return "table";
  }
  return rendererAvailable("board2d") ? "board2d" : "table";
}

/**
 * A GUARDED certificate whose derivation is exactly the registry rules the
 * classifier emits today (R15 purity, R16 terminal verdict) and whose four
 * binding checks all hold — the shape the inspector must render verbatim.
 */
export function verdictProofFixture(): VerdictProofViewModel {
  return toVerdictProofViewModel({
    seq: 41,
    timestamp: "2026-07-13T00:00:00Z",
    tool: "oracle_execute",
    subjectIdHash: "subject-sha256:fixture",
    certHash: "sha256:11".padEnd(71, "0"),
    auditHash: "sha256:22".padEnd(71, "0"),
    certificate: {
      stmt_digest: "sha256:33".padEnd(71, "0"),
      level: "READ_WRITE",
      verdict: "GUARDED",
      derivation: [
        { rule_id: "R15", construct: "routine_calls:absent" },
        { rule_id: "R16", construct: "final_verdict:GUARDED" }
      ],
      classifier_version: "oraclemcp-guard/0.8.0;registry=1",
      observed_scn: null,
      bound_audit_hash: "sha256:22".padEnd(71, "0")
    },
    checks: [
      {
        id: "audit_binding",
        label: "Bound to audit entry",
        ok: true,
        detail: "bound_audit_hash == record.entry_hash"
      },
      {
        id: "statement_digest",
        label: "Statement digest",
        ok: true,
        detail: "stmt_digest == record.sql_sha256"
      },
      {
        id: "rule_registry",
        label: "Rule registry",
        ok: true,
        detail: "2 of 2 derivation steps registered"
      },
      {
        id: "chain_hash",
        label: "Chain hash",
        ok: true,
        detail: "record hash is valid"
      }
    ]
  });
}

/**
 * A workspace with one live checkpoint, one plainly reversible held UPDATE, and
 * one sequence-touching statement whose effect escapes the rollback — the case
 * the tree must never offer a plain Undo for.
 */
export function undoTreeFixture(): UndoTreeViewModel {
  return toUndoTreeViewModel({
    workspace: { open: true, checkpoints: ["SP_BEFORE_BACKFILL"], heldStatements: 2 },
    entries: [
      {
        id: "cp-1",
        kind: "checkpoint",
        checkpointName: "SP_BEFORE_BACKFILL",
        label: "SP_BEFORE_BACKFILL",
        cannotUndo: [],
        fullyReverted: null
      },
      {
        id: "st-1",
        kind: "statement",
        checkpointName: "SP_BEFORE_BACKFILL",
        label: "UPDATE … SET … (held)",
        cannotUndo: [],
        fullyReverted: true
      },
      {
        id: "st-2",
        kind: "statement",
        checkpointName: "SP_BEFORE_BACKFILL",
        label: "INSERT … VALUES (seq.NEXTVAL, …)",
        cannotUndo: [
          "sequence.NEXTVAL: the sequence is advanced outside the transaction, so a rollback does not restore it"
        ],
        fullyReverted: false
      }
    ]
  });
}

export function skinContractFixture(): {
  groundControl: GroundControlViewModel;
  fleet: FleetViewModel;
  verdictProof: VerdictProofViewModel;
  undoTree: UndoTreeViewModel;
  costBadge: CostBadgeViewModel;
  scnScrubber: ScnScrubberViewModel;
  maskBadge: MaskBadgeViewModel;
  fleetMap: FleetMapViewModel;
  policyBadge: PolicyBadgeViewModel;
  vectorCluster: VectorClusterViewModel;
  editionTimeline: EditionTimelineViewModel;
} {
  return {
    policyBadge: policyBadgeFixture(),
    verdictProof: verdictProofFixture(),
    undoTree: undoTreeFixture(),
    costBadge: costBadgeFixture(),
    scnScrubber: scnScrubberFixture(),
    maskBadge: maskBadgeFixture(),
    fleetMap: fleetMapFixture(),
    vectorCluster: vectorClusterFixture(),
    editionTimeline: editionTimelineFixture(),
    groundControl: {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      verdict: "GO",
      health: "nominal",
      clearanceLadder: CLEARANCE_LADDER,
      clearanceStatus: {
        label: "clear",
        tone: "ok",
        blocked: 0
      },
      signatures: [
        {
          id: "go_no_go",
          label: "GO/NO-GO",
          value: "GO",
          detail: "ready",
          tone: "ok",
          activity: 1
        },
        {
          id: "countdown",
          label: "Countdown",
          value: "idle",
          detail: "0 lanes",
          tone: "off",
          activity: 0
        },
        {
          id: "logbook",
          label: "Logbook",
          value: "ok",
          detail: "audit",
          tone: "ok",
          activity: 0.5
        }
      ]
    },
    fleet: {
      grammarVersion: DASHBOARD_GRAMMAR.grammarVersion,
      verdict: "GO",
      health: "nominal",
      activity: 0.6,
      totals: {
        activeLanes: 1,
        requests: 42,
        blocked: 0,
        errors: 0,
        meanLatencyMs: 24,
        poolActive: 1
      },
      sessions: [
        {
          laneId: "operator",
          subjectIdHash: "subject-sha256:fixture",
          status: "working",
          clearance: "READ_ONLY",
          activity: 0.6,
          requests: 42,
          blocked: 0,
          latencyMs: 24
        }
      ]
    }
  };
}
