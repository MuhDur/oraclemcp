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

export function skinContractFixture(): {
  groundControl: GroundControlViewModel;
  fleet: FleetViewModel;
} {
  return {
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
