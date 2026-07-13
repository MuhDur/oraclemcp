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
} {
  return {
    verdictProof: verdictProofFixture(),
    undoTree: undoTreeFixture(),
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
