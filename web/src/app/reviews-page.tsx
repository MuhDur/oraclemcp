import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  Code2,
  Download,
  FileClock,
  GitPullRequest,
  RefreshCcw,
  RotateCcw,
  Search,
  SquarePen
} from "lucide-react";

import { Badge, Button } from "../components/ui/primitives";
import { cn } from "../lib/utils";
import { OMCP_SKIN } from "./skin";
import { toEditionTimelineViewModel } from "./presentation-model";
import {
  applyChangeProposal,
  clearExplorerMetadataCache,
  decodeOperatorOutcome,
  draftChangeProposal,
  draftSourceHistoryRevert,
  fetchActiveLanes,
  fetchChangeProposals,
  fetchChangeProposalDetail,
  fetchDashboardSession,
  fetchEditionProposals,
  fetchLaneCapabilities,
  fetchOperatorConfig,
  fetchSourceHistory,
  operatorOutcomeFromError,
  operatorResponseFromError,
  parseEditionProposals,
  previewSchemaDiff,
  previewWorkbenchSql,
  type ActiveLane,
  type ChangeProposalListData,
  type ChangeProposalListView,
  type ChangeProposalView,
  type ConfigOpsStatusData,
  type ConfigProfileMetadata,
  type DashboardSession,
  type EditionProposalsData,
  type OperatorOutcome,
  type OperatorOutcomeState,
  type OperatorLaneTarget,
  type OperatorResponse,
  OperatorOutcomeError,
  type SchemaDiffExportData,
  type SchemaDiffObjectView,
  type SchemaDiffStepView,
  type SchemaSnapshotInput,
  type SourceHistoryListData,
  type SourceSnapshotView,
  type WorkbenchActionData
} from "./operator-client";
import { useDashboardAuthorityPurge } from "./dashboard-lifecycle";
import {
  authoritativeQueryData,
  authoritativeServerMode,
  dashboardAuthorityIdentity,
  laneIdentity,
  resolveExactLane,
  type DashboardQueryStatus,
  type LaneIdentity
} from "./dashboard-view-state";
import { laneIdentityFromOption, laneOptionLabel, laneOptionValue } from "./dashboard-lane-selector";
import { ErrorNotice, QueryErrorNotice } from "./dashboard-recovery";
import {
  ConsoleFact,
  ConsolePanel,
  formatNumber,
  OM_CHECKBOX,
  OM_CHECK_LABEL,
  OM_CODE,
  OM_INPUT,
  OM_LABEL,
  OM_TEXTAREA,
  PageFrame,
  prettyJson,
  shortHash
} from "./dashboard-ui";

const EMPTY_ACTIVE_LANES: ActiveLane[] = [];
const EMPTY_CHANGE_PROPOSALS: ChangeProposalListView[] = [];
const EMPTY_SOURCE_SNAPSHOTS: SourceSnapshotView[] = [];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function mcpResult(value: unknown): unknown {
  if (!isRecord(value)) {
    return null;
  }
  const result = value["result"];
  return isRecord(result) && "structuredContent" in result ? result["structuredContent"] : result ?? null;
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim().length > 0 ? value : fallback;
}

function reviewSessionProfile(response: OperatorResponse<WorkbenchActionData> | undefined): string {
  const result = mcpResult(response?.data.mcp_response);
  const connection = isRecord(result) && isRecord(result["connection"]) ? result["connection"] : {};
  return stringValue(connection["profile"], "unknown");
}

function confirmationFromResponse(response: OperatorResponse<WorkbenchActionData>): string | null {
  const result = mcpResult(response.data.mcp_response);
  if (!isRecord(result)) {
    return null;
  }
  for (const field of ["execute_confirmation", "confirmation"]) {
    const block = result[field];
    if (isRecord(block) && typeof block["confirm"] === "string") {
      return block["confirm"];
    }
  }
  return null;
}


const EMPTY_SCHEMA_SNAPSHOT = JSON.stringify({ objects: [] }, null, 2);

type ReviewResult = {
  state: OperatorOutcomeState;
  label: string;
  response: unknown;
  outcome: OperatorOutcome;
};

function reviewSuccess(label: string, response: unknown): ReviewResult {
  const outcome = decodeOperatorOutcome(200, response);
  return { state: outcome.state, label, response, outcome };
}

function reviewFailure(label: string, error: unknown, fallback: string): ReviewResult {
  const outcome = operatorOutcomeFromError(error, fallback);
  return {
    state: outcome.state,
    label,
    response: operatorResponseFromError(error),
    outcome
  };
}

export function resolveReviewSelection(
  proposals: readonly ChangeProposalListView[],
  selectedId: string
): ChangeProposalListView | null {
  return selectedId
    ? proposals.find((proposal) => proposal.id === selectedId) ?? null
    : null;
}

export function visibleReviewProposals(
  filtered: readonly ChangeProposalListView[],
  selected: ChangeProposalListView | null
): ChangeProposalListView[] {
  if (!selected || filtered.some((proposal) => proposal.id === selected.id)) {
    return [...filtered];
  }
  return [selected, ...filtered];
}

export function reviewProposalRevisionIdentity(
  proposal: ChangeProposalView | null,
  lane: OperatorLaneTarget | undefined
): string | null {
  if (!proposal) {
    return null;
  }
  return JSON.stringify([
    proposal.id,
    proposal.updated_at,
    proposal.statements.map((statement) => [
      statement.id,
      statement.sql_sha256,
      statement.sql_template,
      statement.unit,
      statement.bind_count,
      statement.commit,
      statement.capture_dbms_output
    ]),
    lane?.laneId ?? "stateless",
    lane?.generation ?? 0
  ]);
}

export function reviewCompletionIsCurrent(
  requestIdentity: string,
  currentIdentity: string | null
): boolean {
  return requestIdentity === currentIdentity;
}

export function invalidReviewCursorError(error: unknown): boolean {
  if (!(error instanceof OperatorOutcomeError) || error.httpStatus !== 400) {
    return false;
  }
  const envelope = isRecord(error.response) ? error.response : null;
  const data = envelope && isRecord(envelope["data"]) ? envelope["data"] : envelope;
  const code = data && typeof data["error"] === "string" ? data["error"] : null;
  return code === "invalid_change_proposal" || code === "invalid_source_history_request";
}

export function consumedReviewGrantState(): { confirm: ""; acknowledged: false } {
  return { confirm: "", acknowledged: false };
}

export function reviewGrantReady(
  needsConfirm: boolean,
  confirm: string,
  acknowledged: boolean
): boolean {
  return !needsConfirm || (confirm.trim().length > 0 && acknowledged);
}

type ReviewPreviewRequest = {
  authority: string;
  identity: string;
  proposalId: string;
  lane?: OperatorLaneTarget;
  sql: string;
};

type ReviewApplyRequest = {
  authority: string;
  identity: string;
  proposalId: string;
  lane?: OperatorLaneTarget;
  confirm: string;
};

export function reviewsAuthoritativeState(input: {
  sessionStatus: DashboardQueryStatus;
  session: DashboardSession | undefined;
  proposalsStatus: DashboardQueryStatus;
  proposals: OperatorResponse<ChangeProposalListData> | undefined;
  historyStatus: DashboardQueryStatus;
  history: OperatorResponse<SourceHistoryListData> | undefined;
}): {
  session: DashboardSession | null;
  proposals: ChangeProposalListView[];
  proposalsNextCursor: string | null;
  snapshots: SourceSnapshotView[];
  historyNextCursor: string | null;
} {
  const session = authoritativeQueryData(input.sessionStatus, input.session) ?? null;
  const proposals = authoritativeQueryData(input.proposalsStatus, input.proposals)?.data;
  const history = authoritativeQueryData(input.historyStatus, input.history)?.data;
  return {
    session,
    proposals: proposals?.proposals ?? EMPTY_CHANGE_PROPOSALS,
    proposalsNextCursor: proposals?.nextCursor ?? null,
    snapshots: history?.snapshots ?? EMPTY_SOURCE_SNAPSHOTS,
    historyNextCursor: history?.nextCursor ?? null
  };
}

export function authoritativeReviewProfiles(
  status: DashboardQueryStatus,
  response: OperatorResponse<ConfigOpsStatusData> | undefined
): ConfigProfileMetadata[] {
  return authoritativeQueryData(status, response)?.data.status.profiles ?? [];
}

export function authoritativeReviewCapabilities(
  status: DashboardQueryStatus,
  response: OperatorResponse<WorkbenchActionData> | undefined
): OperatorResponse<WorkbenchActionData> | undefined {
  return authoritativeQueryData(status, response);
}

export type ReviewsPageProps = {
  selectedId: string;
  onSelectedIdChange: (next: string) => void;
};

export function ReviewsPage({
  selectedId,
  onSelectedIdChange
}: ReviewsPageProps): React.ReactElement {
  const queryClient = useQueryClient();
  const [filter, setFilter] = React.useState("");
  const [profile, setProfile] = React.useState("");
  const [title, setTitle] = React.useState("Inspect database time");
  const [sqlTemplate, setSqlTemplate] = React.useState(
    "SELECT CURRENT_TIMESTAMP AS database_time FROM dual"
  );
  const [bindsJson, setBindsJson] = React.useState("[]");
  const [draftCommit, setDraftCommit] = React.useState(false);
  const [captureDbmsOutput, setCaptureDbmsOutput] = React.useState(false);
  const [selectedLaneBinding, setSelectedLaneBinding] = React.useState<LaneIdentity | null>(null);
  const [confirm, setConfirm] = React.useState("");
  const [applyAcknowledged, setApplyAcknowledged] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<ReviewResult | null>(null);
  const [proposalsCursor, setProposalsCursor] = React.useState<string | undefined>(undefined);
  const [historyCursor, setHistoryCursor] = React.useState<string | undefined>(undefined);

  const session = useQuery({
    queryKey: ["dashboard-session"],
    queryFn: fetchDashboardSession,
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: 1
  });
  const proposalsQuery = useQuery({
    queryKey: ["change-proposals", proposalsCursor ?? "start"],
    queryFn: ({ signal }) => fetchChangeProposals(proposalsCursor, { signal })
  });
  const config = useQuery({
    queryKey: ["operator-config"],
    queryFn: fetchOperatorConfig,
    staleTime: 30_000
  });
  const activeLanes = useQuery({
    queryKey: ["active-lanes"],
    queryFn: fetchActiveLanes,
    refetchInterval: 5_000
  });
  const lanes = activeLanes.status === "success" ? activeLanes.data.data.lanes : EMPTY_ACTIVE_LANES;
  const stateful = authoritativeServerMode(activeLanes.status, activeLanes.data) !== false;
  const laneSelection =
    stateful && activeLanes.status === "success"
      ? resolveExactLane(selectedLaneBinding, lanes)
      : { lane: null, invalidated: false };
  const selectedLane = laneSelection.lane ?? undefined;
  const reviewLane = selectedLane ? laneIdentity(selectedLane) : undefined;
  const laneReady = activeLanes.status === "success" && (!stateful || Boolean(reviewLane));
  const sourceHistoryQuery = useQuery({
    queryKey: ["source-history", historyCursor ?? "start"],
    queryFn: ({ signal }) => fetchSourceHistory(historyCursor, { signal })
  });
  const authoritative = reviewsAuthoritativeState({
    sessionStatus: session.status,
    session: session.data,
    proposalsStatus: proposalsQuery.status,
    proposals: proposalsQuery.data,
    historyStatus: sourceHistoryQuery.status,
    history: sourceHistoryQuery.data
  });
  const { proposals, proposalsNextCursor, snapshots, historyNextCursor } = authoritative;
  const sessionAuthority = dashboardAuthorityIdentity(authoritative.session ?? undefined);
  const reviewProfiles = authoritativeReviewProfiles(config.status, config.data);
  const profileAvailable = reviewProfiles.some((item) => item.name === profile);
  React.useEffect(() => {
    if (profile && !profileAvailable) {
      setProfile("");
    }
  }, [profile, profileAvailable]);
  const filtered = React.useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return proposals;
    }
    return proposals.filter((proposal) => proposalSearchText(proposal).includes(needle));
  }, [filter, proposals]);
  const selected = resolveReviewSelection(proposals, selectedId);
  const visibleProposals = React.useMemo(
    () => visibleReviewProposals(filtered, selected),
    [filtered, selected]
  );
  const selectedOutsideFilter = Boolean(
    selected && !filtered.some((proposal) => proposal.id === selected.id)
  );
  const unresolvedSelectedId = Boolean(
    selectedId && proposalsQuery.status === "success" && !selected
  );
  const selectedProposalId = selected?.id ?? null;

  // The polled list omits sql_template bodies; fetch the full detail (with SQL
  // text) for the selected proposal on demand.
  const detailQuery = useQuery({
    queryKey: ["change-proposal-detail", selectedProposalId],
    queryFn: ({ signal }) => fetchChangeProposalDetail(selectedProposalId as string, { signal }),
    enabled: Boolean(selectedProposalId)
  });
  const selectedDetail =
    authoritativeQueryData(detailQuery.status, detailQuery.data)?.data.proposal ?? null;
  const reviewIdentity = reviewProposalRevisionIdentity(selectedDetail, reviewLane);
  const reviewIdentityRef = React.useRef(reviewIdentity);
  React.useLayoutEffect(() => {
    reviewIdentityRef.current = reviewIdentity;
  }, [reviewIdentity]);
  const consumeReviewGrant = React.useCallback(() => {
    const consumed = consumedReviewGrantState();
    setConfirm(consumed.confirm);
    setApplyAcknowledged(consumed.acknowledged);
  }, []);
  const invalidateReviewGrant = React.useCallback(() => {
    reviewIdentityRef.current = null;
    consumeReviewGrant();
  }, [consumeReviewGrant]);
  const setSelectedId = React.useCallback(
    (next: string) => {
      invalidateReviewGrant();
      onSelectedIdChange(next);
    },
    [invalidateReviewGrant, onSelectedIdChange]
  );
  const selectReviewLane = React.useCallback(
    (next: LaneIdentity | null) => {
      invalidateReviewGrant();
      setSelectedLaneBinding(next);
    },
    [invalidateReviewGrant]
  );
  React.useEffect(() => {
    if (laneSelection.invalidated) {
      invalidateReviewGrant();
      setSelectedLaneBinding(null);
    }
  }, [invalidateReviewGrant, laneSelection.invalidated]);
  const writeStatements = selectedDetail?.statements.filter((statement) => statement.unit !== "read") ?? [];
  const needsConfirm = writeStatements.length > 0;
  const hasDdl = selectedDetail?.statements.some((statement) => statement.unit === "ddl") ?? false;
  const hasHiddenBinds = selectedDetail?.statements.some((statement) => statement.bind_count > 0) ?? false;
  const laneCapabilities = useQuery({
    queryKey: [
      "reviews",
      "capabilities",
      reviewLane?.laneId ?? "stateless",
      reviewLane?.generation ?? 0
    ],
    queryFn: async ({ signal }) => {
      if (!session.data || !laneReady) {
        throw new Error("database connection is not ready");
      }
      return fetchLaneCapabilities(session.data, reviewLane, { signal });
    },
    enabled: session.status === "success" && laneReady,
    retry: 1
  });
  const selectedLaneCapabilities = authoritativeReviewCapabilities(
    laneCapabilities.status,
    laneCapabilities.data
  );
  const selectedLaneProfile = selectedLaneCapabilities
    ? reviewSessionProfile(selectedLaneCapabilities)
    : "unknown";
  const profileMatches = Boolean(selectedDetail) && selectedLaneProfile === selectedDetail?.profile;

  React.useEffect(() => {
    if (laneCapabilities.status === "error") {
      invalidateReviewGrant();
    }
  }, [invalidateReviewGrant, laneCapabilities.status]);

  // An acknowledgement is about one specific proposal. Never let it carry over
  // to another revision, statement digest, SQL body, or lane generation.
  React.useEffect(() => {
    setApplyAcknowledged(false);
    setConfirm("");
  }, [reviewIdentity]);

  // Cursors are bound to the board revision; if the store changed under a held
  // cursor the server rejects it, so fall back to the first page.
  React.useEffect(() => {
    if (proposalsCursor && invalidReviewCursorError(proposalsQuery.error)) {
      setProposalsCursor(undefined);
    }
  }, [proposalsCursor, proposalsQuery.error]);
  React.useEffect(() => {
    if (historyCursor && invalidReviewCursorError(sourceHistoryQuery.error)) {
      setHistoryCursor(undefined);
    }
  }, [historyCursor, sourceHistoryQuery.error]);

  const draftMutation = useMutation({
    mutationFn: async (requestAuthority: string) => {
      if (
        !session.data ||
        !sessionAuthority ||
        requestAuthority !== sessionAuthority ||
        !profileAvailable
      ) {
        throw new Error("dashboard session is not ready");
      }
      const binds = parseBindsJson(bindsJson);
      return draftChangeProposal(session.data, {
        profile: profile.trim(),
        author: "human",
        title: title.trim() || undefined,
        statements: [
          {
            sql_template: sqlTemplate.trim(),
            binds,
            commit: draftCommit,
            capture_dbms_output: captureDbmsOutput
          }
        ]
      });
    },
    onSuccess: (response, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewSuccess("Draft", response));
      setSelectedId(response.data.proposal.id);
      setProposalsCursor(undefined);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
    },
    onError: (error, requestAuthority) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewFailure("Draft", error, "proposal draft failed"));
    }
  });

  const applyMutation = useMutation({
    mutationFn: async (request: ReviewApplyRequest) => {
      if (
        !session.data ||
        !sessionAuthority ||
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        throw new Error("dashboard session is not ready");
      }
      if (!laneReady) {
        throw new Error("select a proposal and ready database connection");
      }
      return applyChangeProposal(session.data, {
        proposalId: request.proposalId,
        lane: request.lane,
        confirm: request.confirm
      });
    },
    onMutate: consumeReviewGrant,
    onSuccess: (response, request) => {
      clearExplorerMetadataCache();
      queryClient.invalidateQueries({ queryKey: ["explorer"] });
      queryClient.invalidateQueries({ queryKey: ["operator-metrics"] });
      queryClient.invalidateQueries({ queryKey: ["audit-tail"] });
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setLastResult(reviewSuccess("Apply", response));
    },
    onError: (error, request) => {
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setLastResult(reviewFailure("Apply", error, "proposal apply failed"));
    }
  });

  const previewSelectedMutation = useMutation({
    mutationFn: async (request: ReviewPreviewRequest) => {
      if (
        !session.data ||
        !sessionAuthority ||
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current) ||
        !laneReady
      ) {
        throw new Error("select a loaded change plan and ready database connection");
      }
      return previewWorkbenchSql(session.data, {
        lane: request.lane,
        mode: "dml_preview_confirm",
        sql: request.sql
      });
    },
    onMutate: consumeReviewGrant,
    onSuccess: (response, request) => {
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setConfirm(confirmationFromResponse(response) ?? "");
      setLastResult(reviewSuccess("Preview selected change", response));
    },
    onError: (error, request) => {
      if (
        request.authority !== sessionAuthority ||
        !reviewCompletionIsCurrent(request.identity, reviewIdentityRef.current)
      ) {
        return;
      }
      setLastResult(reviewFailure("Preview selected change", error, "change preview failed"));
    }
  });

  const revertMutation = useMutation({
    mutationFn: async ({
      snapshot,
      authority: requestAuthority
    }: {
      snapshot: SourceSnapshotView;
      authority: string;
    }) => {
      if (!session.data || !sessionAuthority || requestAuthority !== sessionAuthority) {
        throw new Error("dashboard session is not ready");
      }
      return draftSourceHistoryRevert(session.data, snapshot.id, snapshot.profile);
    },
    onSuccess: (response, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewSuccess("Revert draft", response));
      setSelectedId(response.data.proposal.id);
      setProposalsCursor(undefined);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
    },
    onError: (error, { authority: requestAuthority }) => {
      if (requestAuthority !== sessionAuthority) {
        return;
      }
      setLastResult(reviewFailure("Revert draft", error, "revert draft failed"));
    }
  });
  const purgeReviewAuthorityState = React.useCallback(() => {
    setConfirm("");
    setApplyAcknowledged(false);
    setLastResult(null);
    draftMutation.reset();
    applyMutation.reset();
    previewSelectedMutation.reset();
    revertMutation.reset();
  }, [
    applyMutation.reset,
    draftMutation.reset,
    previewSelectedMutation.reset,
    revertMutation.reset
  ]);
  useDashboardAuthorityPurge(sessionAuthority, purgeReviewAuthorityState);

  const canDraft =
    session.status === "success" &&
    config.status === "success" &&
    profileAvailable &&
    sqlTemplate.trim().length > 0 &&
    !draftMutation.isPending;
  // Name the strongest thing this proposal does, so the acknowledgement says
  // what the operator is agreeing to rather than "are you sure?".
  const applyDangerSummary = React.useMemo(() => {
    const units = new Set(
      (selectedDetail?.statements ?? [])
        .filter((statement) => statement.unit !== "read")
        .map((statement) => statement.unit.toUpperCase())
    );
    return units.size > 0 ? Array.from(units).sort().join(" + ") : "non-read";
  }, [selectedDetail]);
  const canPreviewSelected =
    session.status === "success" &&
    detailQuery.status === "success" &&
    laneCapabilities.status === "success" &&
    Boolean(reviewIdentity && selectedDetail) &&
    laneReady &&
    profileMatches &&
    !hasHiddenBinds &&
    writeStatements.length === 1 &&
    writeStatements[0]?.unit === "dml" &&
    !applyMutation.isPending &&
    !previewSelectedMutation.isPending;
  const canApply =
    session.status === "success" &&
    detailQuery.status === "success" &&
    laneCapabilities.status === "success" &&
    Boolean(selected && selectedDetail && reviewIdentity) &&
    laneReady &&
    profileMatches &&
    !hasHiddenBinds &&
    !hasDdl &&
    writeStatements.length <= 1 &&
    !applyMutation.isPending &&
    !previewSelectedMutation.isPending &&
    reviewGrantReady(needsConfirm, confirm, applyAcknowledged);
  const previewSelectedChange = (): void => {
    if (
      !selectedDetail ||
      !reviewIdentity ||
      writeStatements.length !== 1 ||
      writeStatements[0].unit !== "dml"
    ) {
      return;
    }
    previewSelectedMutation.mutate({
      authority: sessionAuthority ?? "",
      identity: reviewIdentity,
      proposalId: selectedDetail.id,
      lane: reviewLane,
      sql: writeStatements[0].sql_template
    });
  };
  const applySelectedChange = (): void => {
    if (!selected || !reviewIdentity) {
      return;
    }
    applyMutation.mutate({
      authority: sessionAuthority ?? "",
      identity: reviewIdentity,
      proposalId: selected.id,
      lane: reviewLane,
      confirm
    });
  };

  return (
    <PageFrame
      title="Change review"
      eyebrow="Saved database changes"
      description="Inspect exact SQL, target the matching database profile, and let the server re-check every statement at apply time."
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.2fr)]">
        <div className="space-y-4">
          <ConsolePanel>
            <div className="border-b border-[var(--om-border)] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
                    <GitPullRequest className="size-4" aria-hidden="true" />
                    Saved change plans
                  </h3>
                  <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
                    {proposalsQuery.isPending
                      ? "loading"
                      : `${formatNumber(filtered.length)} filter match(es)${selectedOutsideFilter ? " + selected" : ""}`}
                  </p>
                </div>
                <Badge tone={proposalsQuery.isError ? "warn" : proposalsQuery.data ? "ok" : "info"}>
                  {proposalsQuery.isError ? "unavailable" : proposalsQuery.data ? "loaded" : "loading"}
                </Badge>
              </div>
              <label className="mt-4 block">
                <span className={OM_LABEL}>Filter</span>
                <input
                  className={OM_INPUT}
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                  placeholder="profile, title, author, or digest"
                />
              </label>
            </div>
            <div className="max-h-[560px] overflow-auto">
              {visibleProposals.length === 0 ? (
                <div className="px-4 py-8 text-sm font-semibold text-[var(--om-text-muted)]">
                  {proposalsQuery.isPending
                    ? "Loading saved change plans…"
                    : proposalsQuery.isError
                      ? "Saved change plans are unavailable."
                      : filter.trim()
                        ? "No plans match this filter."
                        : "No saved change plans."}
                </div>
              ) : (
                visibleProposals.map((proposal) => (
                  <button
                    key={proposal.id}
                    type="button"
                    className={cn(
                      "block min-h-11 w-full border-b border-[var(--om-border)] px-4 py-3 text-left transition-colors hover:bg-[var(--om-surface-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--om-focus)]",
                      selected?.id === proposal.id
                        ? "bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)]"
                        : "bg-transparent"
                    )}
                    aria-pressed={selected?.id === proposal.id}
                    onClick={() => setSelectedId(proposal.id)}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 truncate text-sm font-semibold text-[var(--om-text-bright)]">
                        {proposal.title}
                      </span>
                      <Badge tone={proposalLevelTone(proposal)}>{proposal.profile}</Badge>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold text-[var(--om-text-muted)]">
                      <span>{proposal.author}</span>
                      <span>{formatNumber(proposal.statement_count)} stmt</span>
                      <span>{proposal.updated_at}</span>
                      {selectedOutsideFilter && selected?.id === proposal.id ? (
                        <span>selected outside filter</span>
                      ) : null}
                    </div>
                  </button>
                ))
              )}
            </div>
            {proposalsCursor || proposalsNextCursor ? (
              <ListPager
                atStart={!proposalsCursor}
                onFirst={() => setProposalsCursor(undefined)}
                onNext={
                  proposalsNextCursor
                    ? () => setProposalsCursor(proposalsNextCursor)
                    : undefined
                }
                pending={proposalsQuery.isPending}
              />
            ) : null}
          </ConsolePanel>
          <SourceHistoryPanel
            snapshots={snapshots}
            pending={sourceHistoryQuery.isPending || revertMutation.isPending}
            blocked={sourceHistoryQuery.isError}
            onDraftRevert={(snapshot) =>
              revertMutation.mutate({ snapshot, authority: sessionAuthority ?? "" })
            }
            atStart={!historyCursor}
            onFirst={() => setHistoryCursor(undefined)}
            onNext={
              historyNextCursor ? () => setHistoryCursor(historyNextCursor) : undefined
            }
            hasPager={Boolean(historyCursor || historyNextCursor)}
          />
          <SchemaDiffPanel
            session={authoritative.session}
            profile={profileAvailable ? profile : ""}
            onDrafted={(proposal, response) => {
              setLastResult(reviewSuccess("Migration draft", response));
              setSelectedId(proposal.id);
              setProposalsCursor(undefined);
              queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
            }}
          />
        </div>

        <div className="space-y-4">
          {config.error instanceof Error ? (
            <QueryErrorNotice
              title="Review profiles are unavailable"
              error={config.error}
              retryLabel="Retry profiles"
              retryingLabel="Retrying profiles"
              retrying={config.isFetching}
              onRetry={() => void config.refetch()}
            />
          ) : null}
          <ConsolePanel className="p-4">
            <div className="mb-4">
              <h3 className="text-base font-semibold text-[var(--om-text-bright)]">Create a saved change plan</h3>
              <p className="mt-1 text-sm leading-6 text-[var(--om-text-muted)]">
                Plans created in this browser are recorded as human-authored. Saving a plan does not run SQL.
              </p>
            </div>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_180px]">
              <label className="block">
                <span className={OM_LABEL}>Title</span>
                <input
                  className={OM_INPUT}
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                />
              </label>
              <label className="block">
                <span className={OM_LABEL}>Profile</span>
                <select
                  className={OM_INPUT}
                  value={profile}
                  onChange={(event) => setProfile(event.target.value)}
                >
                  <option value="">Select a profile</option>
                  {reviewProfiles.map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name}{item.is_default ? " (default)" : ""}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <label className="mt-4 block">
              <span className={OM_LABEL}>SQL</span>
              <textarea
                className={cn(OM_TEXTAREA, "min-h-[220px]")}
                spellCheck={false}
                value={sqlTemplate}
                onChange={(event) => setSqlTemplate(event.target.value)}
              />
            </label>
            <label className="mt-4 block">
              <span className={OM_LABEL}>Bind values (JSON array)</span>
              <textarea
                className={cn(OM_TEXTAREA, "min-h-[92px] leading-5")}
                spellCheck={false}
                value={bindsJson}
                onChange={(event) => setBindsJson(event.target.value)}
              />
            </label>
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <p className="max-w-xl text-sm leading-6 text-[var(--om-text-muted)]">
                The server classifies the SQL and assigns Read, DML, or DDL. This cannot be
                overridden in the browser.
              </p>
              <label className={OM_CHECK_LABEL}>
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={draftCommit}
                  onChange={(event) => setDraftCommit(event.target.checked)}
                />
                Commit when applied
              </label>
              <label className={OM_CHECK_LABEL}>
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={captureDbmsOutput}
                  onChange={(event) => setCaptureDbmsOutput(event.target.checked)}
                />
                DBMS_OUTPUT
              </label>
              <Button
                type="button"
                variant="primary"
                disabled={!canDraft}
                onClick={() => draftMutation.mutate(sessionAuthority ?? "")}
              >
                <GitPullRequest className="size-4" aria-hidden="true" />
                Save plan
              </Button>
            </div>
          </ConsolePanel>

          <ConsolePanel className="p-4">
            <div>
              <h3 className="text-base font-semibold text-[var(--om-text-bright)]">Review and apply</h3>
              <p className="mt-1 text-sm leading-6 text-[var(--om-text-muted)]">
                Apply is bound to a database connection whose active profile matches the saved plan.
              </p>
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              {stateful ? (
                <label className="block">
                  <span className={OM_LABEL}>Agent session</span>
                  <select
                    className={OM_INPUT}
                    value={selectedLane ? laneOptionValue(selectedLane) : ""}
                    onChange={(event) =>
                      selectReviewLane(laneIdentityFromOption(lanes, event.target.value))
                    }
                    disabled={activeLanes.isPending || lanes.length === 0}
                  >
                    <option value="">Select a session</option>
                    {lanes.map((lane) => (
                      <option key={`${lane.lane_id}:${lane.generation}`} value={laneOptionValue(lane)}>
                        {laneOptionLabel(lane)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <div>
                  <span className={OM_LABEL}>Connection mode</span>
                  <p className={cn(OM_INPUT, "flex items-center font-semibold")}>Direct server profile</p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2">
                <ConsoleFact label="Plan profile" value={selectedDetail?.profile ?? "none"} mono />
                <ConsoleFact label="Connection profile" value={laneReady ? selectedLaneProfile : "select a session"} mono />
              </div>
            </div>
            {selected ? (
              selectedDetail ? (
                <ProposalStatementTable proposal={selectedDetail} />
              ) : (
                <p className="mt-4 text-sm font-semibold text-[var(--om-text-muted)]">
                  {detailQuery.isError
                    ? "statement detail unavailable"
                    : "loading statement detail…"}
                </p>
              )
            ) : null}
            {!selected ? (
              unresolvedSelectedId ? (
                <ErrorNotice message={`Change plan ${selectedId} was not found. No plan is selected and Apply remains disabled.`} />
              ) : (
                <p className="mt-4 text-sm text-[var(--om-text-muted)]">Select a saved change plan to review it.</p>
              )
            ) : detailQuery.isError ? (
              <ErrorNotice message="The exact statement detail is unavailable, so this plan cannot be applied." />
            ) : null}
            {reviewLane && selectedLaneCapabilities && !profileMatches ? (
              <ErrorNotice
                message={`This plan targets ${selectedDetail?.profile ?? "an unknown profile"}, but the selected session uses ${selectedLaneProfile}. Choose a matching session.`}
              />
            ) : null}
            {hasDdl ? (
              <ErrorNotice message="DDL plans are preview/export only in the browser. Apply them through an approved non-browser client with the required profile level." />
            ) : null}
            {hasHiddenBinds ? (
              <ErrorNotice message="This plan contains bind values that the redacted review record does not expose. Browser apply is disabled because those values cannot be reviewed here." />
            ) : null}
            {writeStatements.length > 1 ? (
              <ErrorNotice message="This plan contains multiple writes. Browser apply is disabled because confirmations are single-use and sequential execution could partially commit." />
            ) : null}
            {needsConfirm ? (
              // The grant auto-fills from the preview, so a non-empty confirm
              // field is not a deliberate act. Name what is about to change and
              // make the operator acknowledge it — the same pattern Config uses
              // for a sensitive draft. The server-side grant is still the gate.
              <label className={cn(OM_CHECK_LABEL, "mt-4")}>
                <input
                  className={OM_CHECKBOX}
                  type="checkbox"
                  checked={applyAcknowledged}
                  onChange={(event) => setApplyAcknowledged(event.target.checked)}
                />
                I reviewed the full {applyDangerSummary} statement, bind count, and saved commit setting for {selected?.profile ?? "this profile"}
              </label>
            ) : null}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              {needsConfirm ? (
                <Button
                  type="button"
                  variant="secondary"
                  disabled={!canPreviewSelected}
                  onClick={previewSelectedChange}
                >
                  <Search className="size-4" aria-hidden="true" />
                  Preview selected change
                </Button>
              ) : null}
              <Button
                type="button"
                variant="primary"
                disabled={!canApply}
                onClick={applySelectedChange}
              >
                <CheckCircle2 className="size-4" aria-hidden="true" />
                Apply selected plan
              </Button>
              <Badge tone={confirm ? "ok" : needsConfirm ? "off" : "neutral"}>
                {confirm ? "confirmation ready" : needsConfirm ? "preview required" : "read-only plan"}
              </Badge>
              <Badge tone={session.status === "success" ? "ok" : session.status === "error" ? "warn" : "info"}>
                {session.status === "success" ? "paired" : session.status === "error" ? "blocked" : "pairing"}
              </Badge>
            </div>
          </ConsolePanel>

          <ReviewResultPanel
            result={lastResult}
            pending={draftMutation.isPending || applyMutation.isPending || previewSelectedMutation.isPending}
          />

          <details className="rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] p-4">
            <summary className="cursor-pointer font-semibold text-[var(--om-text-bright)]">
              Edition-based redefinition
            </summary>
            <div className="mt-4"><EditionTimelinePanel /></div>
          </details>
        </div>
      </div>
    </PageFrame>
  );
}

/**
 * The edition linear timeline (Arc D) on the Reviews board.
 *
 * Reads /operator/v1/edition-proposals and renders the base→child edition chain
 * as a straight timeline. A non-linear shape (a base with two children) is
 * flagged, never drawn as a line.
 */
export function authoritativeEditionData(
  status: DashboardQueryStatus,
  response: OperatorResponse<EditionProposalsData> | undefined
): EditionProposalsData | null {
  return authoritativeQueryData(status, response)?.data ?? null;
}

function EditionTimelinePanel(): React.ReactElement {
  const EditionTimeline = OMCP_SKIN.renderers.EditionTimeline;
  const editions = useQuery({
    queryKey: ["edition-proposals"],
    queryFn: fetchEditionProposals
  });
  const editionData = authoritativeEditionData(editions.status, editions.data);
  const model = toEditionTimelineViewModel(parseEditionProposals(editionData));
  return (
    <div className="space-y-3" data-testid="edition-timeline-panel">
      <p className="text-sm leading-6 text-[var(--om-text-muted)]">
        Optional Oracle Edition-Based Redefinition proposals for profiles that use editions.
      </p>
      {editionData ? (
        <EditionTimeline model={model} />
      ) : (
        <p className="text-sm text-[var(--om-text-muted)]">
          {editions.isPending
            ? "Loading edition proposals…"
            : editions.isError
              ? "Edition proposals are unavailable."
              : "No edition proposals are available."}
        </p>
      )}
    </div>
  );
}

function ListPager({
  atStart,
  onFirst,
  onNext,
  pending
}: {
  atStart: boolean;
  onFirst: () => void;
  onNext?: () => void;
  pending: boolean;
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between gap-3 border-t border-[var(--om-border)] px-4 py-3">
      <Button type="button" variant="secondary" disabled={atStart || pending} onClick={onFirst}>
        First page
      </Button>
      <Button
        type="button"
        variant="secondary"
        disabled={!onNext || pending}
        onClick={() => onNext?.()}
      >
        Next page
      </Button>
    </div>
  );
}

function ProposalStatementTable({ proposal }: { proposal: ChangeProposalView }): React.ReactElement {
  return (
    <div
      className="mt-4 overflow-x-auto rounded-md border border-[var(--om-border)]"
      role="region"
      aria-label="Statements in selected change plan"
      tabIndex={0}
    >
      <table className="w-full min-w-[760px] border-collapse text-sm">
        <caption className="sr-only">Exact statements in the selected saved change plan</caption>
        <thead className="bg-[var(--om-surface-muted)] text-left text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
          <tr>
            <th className="px-3 py-2 font-semibold">Unit</th>
            <th className="px-3 py-2 font-semibold">Exact SQL and digest</th>
            <th className="px-3 py-2 font-semibold">Required permission</th>
            <th className="px-3 py-2 font-semibold">Saved behavior</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--om-border)]">
          {proposal.statements.map((statement) => (
            <tr key={statement.id}>
              <td className="px-3 py-2">
                <Badge tone={statement.unit === "ddl" ? "warn" : statement.unit === "dml" ? "info" : "ok"}>
                  {statement.unit}
                </Badge>
              </td>
              <td className="max-w-[520px] px-3 py-2">
                <pre className="whitespace-pre-wrap break-words font-mono text-xs text-[var(--om-text-bright)]">{statement.sql_template}</pre>
                <p className="mt-2 break-all font-mono text-xs text-[var(--om-text-muted)]">SHA-256 {statement.sql_sha256}</p>
              </td>
              <td className="px-3 py-2 font-semibold text-[var(--om-text)]">
                {statement.draft_verdict.required_level ?? "none"}
              </td>
              <td className="px-3 py-2 text-xs text-[var(--om-text)]">
                <p>{formatNumber(statement.bind_count)} bind value(s)</p>
                <p className="mt-1">{statement.commit ? "commit" : "rollback after execution"}</p>
                <p className="mt-1">{statement.capture_dbms_output ? "capture DBMS_OUTPUT" : "no DBMS_OUTPUT"}</p>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SourceHistoryPanel({
  snapshots,
  pending,
  blocked,
  onDraftRevert,
  atStart,
  onFirst,
  onNext,
  hasPager
}: {
  snapshots: SourceSnapshotView[];
  pending: boolean;
  blocked: boolean;
  onDraftRevert: (snapshot: SourceSnapshotView) => void;
  atStart: boolean;
  onFirst: () => void;
  onNext?: () => void;
  hasPager: boolean;
}): React.ReactElement {
  return (
    <ConsolePanel>
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <FileClock className="size-4" aria-hidden="true" />
            Source history
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "loading" : `${formatNumber(snapshots.length)} snapshots`}
          </p>
        </div>
        <Badge tone={blocked ? "warn" : snapshots.length ? "ok" : "off"}>
          {blocked ? "blocked" : snapshots.length ? "ready" : "empty"}
        </Badge>
      </div>
      <div className="max-h-[320px] overflow-auto">
        {snapshots.length === 0 ? (
          <div className="px-4 py-6 text-sm font-semibold text-[var(--om-text-muted)]">
            {pending ? "Loading source snapshots…" : blocked ? "Source history is unavailable." : "No source snapshots have been recorded."}
          </div>
        ) : (
          snapshots.map((snapshot) => (
            <div
              key={`${snapshot.id}-${snapshot.statement_id}`}
              className="grid gap-3 border-b border-[var(--om-border)] px-4 py-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-[var(--om-text-bright)]">
                    {snapshot.owner}.{snapshot.name}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold text-[var(--om-text-muted)]">
                    <span>{snapshot.object_type}</span>
                    <span>{snapshot.profile}</span>
                    <span>{formatNumber(snapshot.source_lines)} lines</span>
                    <span>{snapshot.created_at}</span>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  disabled={pending || blocked}
                  onClick={() => onDraftRevert(snapshot)}
                  title="Create a restore plan without changing the database"
                >
                  <RotateCcw className="size-4" aria-hidden="true" />
                  Create restore plan
                </Button>
              </div>
              <p className="truncate font-mono text-xs text-[var(--om-text-muted)]">
                {snapshot.source_sha256}
              </p>
            </div>
          ))
        )}
      </div>
      {hasPager ? (
        <ListPager atStart={atStart} onFirst={onFirst} onNext={onNext} pending={pending} />
      ) : null}
    </ConsolePanel>
  );
}

export interface SchemaDiffPreviewBinding<T> {
  inputIdentity: string;
  data: T;
}

export function schemaDiffInputIdentity(
  title: string,
  beforeJson: string,
  afterJson: string
): string {
  return JSON.stringify([title, beforeJson, afterJson]);
}

export function currentSchemaDiffPreview<T>(
  binding: SchemaDiffPreviewBinding<T> | null,
  inputIdentity: string
): T | null {
  return binding?.inputIdentity === inputIdentity ? binding.data : null;
}

function SchemaDiffPanel({
  session,
  profile,
  onDrafted
}: {
  session: DashboardSession | null;
  profile: string;
  onDrafted: (proposal: ChangeProposalView, response: unknown) => void;
}): React.ReactElement {
  const queryClient = useQueryClient();
  const [title, setTitle] = React.useState("Schema snapshot comparison");
  const [beforeJson, setBeforeJson] = React.useState(EMPTY_SCHEMA_SNAPSHOT);
  const [afterJson, setAfterJson] = React.useState(EMPTY_SCHEMA_SNAPSHOT);
  const [previewBinding, setPreviewBinding] = React.useState<
    SchemaDiffPreviewBinding<SchemaDiffExportData> | null
  >(null);
  const [lastError, setLastError] = React.useState<string | null>(null);
  const inputIdentity = schemaDiffInputIdentity(title, beforeJson, afterJson);
  const sessionAuthority = dashboardAuthorityIdentity(session ?? undefined);
  const authorityInputIdentity = JSON.stringify([sessionAuthority, inputIdentity]);
  const preview = currentSchemaDiffPreview(previewBinding, authorityInputIdentity);

  const previewMutation = useMutation({
    mutationFn: async (input: {
      title: string;
      beforeJson: string;
      afterJson: string;
      inputIdentity: string;
    }) => {
      if (!session) {
        throw new Error("dashboard session is not ready");
      }
      const before = parseSchemaSnapshotInput(input.beforeJson);
      const after = parseSchemaSnapshotInput(input.afterJson);
      return previewSchemaDiff(session, before, after, input.title);
    },
    onSuccess: (response, input) => {
      setPreviewBinding({ inputIdentity: input.inputIdentity, data: response.data });
      setLastError(null);
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "schema diff preview failed");
    }
  });

  const draftMutation = useMutation({
    mutationFn: async () => {
      if (!session) {
        throw new Error("dashboard session is not ready");
      }
      if (!preview) {
        throw new Error("preview a schema diff first");
      }
      if (preview.proposal_statements.length === 0) {
        throw new Error("no executable migration steps to draft");
      }
      return draftChangeProposal(session, {
        profile: profile.trim(),
        author: "human",
        title: preview.title,
        statements: preview.proposal_statements
      });
    },
    onSuccess: (response) => {
      setLastError(null);
      queryClient.invalidateQueries({ queryKey: ["change-proposals"] });
      onDrafted(response.data.proposal, response);
    },
    onError: (error) => {
      setLastError(error instanceof Error ? error.message : "migration draft failed");
    }
  });
  const purgeSchemaDiffAuthorityState = React.useCallback(() => {
    setPreviewBinding(null);
    setLastError(null);
    previewMutation.reset();
    draftMutation.reset();
  }, [draftMutation.reset, previewMutation.reset]);
  useDashboardAuthorityPurge(sessionAuthority, purgeSchemaDiffAuthorityState);

  const busy = previewMutation.isPending || draftMutation.isPending;
  const canPreview = Boolean(session) && !busy;
  const canDraft =
    Boolean(session && profile.trim() && preview && preview.proposal_statements.length > 0) && !busy;

  return (
    <ConsolePanel>
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <SquarePen className="size-4" aria-hidden="true" />
            Compare schema snapshots
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {preview ? `${formatNumber(preview.summary.migration_steps)} steps` : "pasted JSON snapshots"}
          </p>
        </div>
        <Badge tone={preview ? "ok" : lastError ? "warn" : "off"}>
          {preview ? "previewed" : lastError ? "blocked" : "idle"}
        </Badge>
      </div>
      <div className="grid gap-3 p-4">
        <p className="text-sm leading-6 text-[var(--om-text-muted)]">
          Paste exported snapshots to compare them. This does not read either snapshot from the database. Generated DDL is preview/export only in the browser.
        </p>
        <label className="block">
          <span className={OM_LABEL}>Title</span>
          <input
            className={OM_INPUT}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
        </label>
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="block">
            <span className={OM_LABEL}>Current snapshot JSON</span>
            <textarea
              className={cn(OM_TEXTAREA, "min-h-[180px] text-xs leading-5")}
              aria-label="schema diff before snapshot"
              spellCheck={false}
              value={beforeJson}
              onChange={(event) => setBeforeJson(event.target.value)}
            />
          </label>
          <label className="block">
            <span className={OM_LABEL}>Desired snapshot JSON</span>
            <textarea
              className={cn(OM_TEXTAREA, "min-h-[180px] text-xs leading-5")}
              aria-label="schema diff after snapshot"
              spellCheck={false}
              value={afterJson}
              onChange={(event) => setAfterJson(event.target.value)}
            />
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="secondary"
            disabled={!canPreview}
            onClick={() =>
              previewMutation.mutate({
                title,
                beforeJson,
                afterJson,
                inputIdentity: authorityInputIdentity
              })
            }
          >
            <RefreshCcw className="size-4" aria-hidden="true" />
            Compare snapshots
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={!preview || busy}
            onClick={() =>
              preview
                ? downloadTextFile(`${safeFilename(preview.title)}.sql`, preview.migration_script)
                : undefined
            }
          >
            <Download className="size-4" aria-hidden="true" />
            Export SQL
          </Button>
          <Button type="button" variant="primary" disabled={!canDraft} onClick={() => draftMutation.mutate()}>
            <GitPullRequest className="size-4" aria-hidden="true" />
            Save DDL plan
          </Button>
          {lastError ? (
            <Badge tone="warn" role="alert" className="max-w-full whitespace-normal break-all">
              {lastError}
            </Badge>
          ) : null}
        </div>
        {preview ? <SchemaDiffSummaryPanel preview={preview} /> : null}
      </div>
    </ConsolePanel>
  );
}

function SchemaDiffSummaryPanel({ preview }: { preview: SchemaDiffExportData }): React.ReactElement {
  return (
    <div className="grid gap-3">
      <div className="grid gap-2 sm:grid-cols-3">
        <ConsoleFact label="Added" value={preview.summary.added} />
        <ConsoleFact label="Changed" value={preview.summary.changed} />
        <ConsoleFact label="Dropped" value={preview.summary.dropped} />
      </div>
      <div className="grid gap-3 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
        <SchemaDiffObjectList title="Objects" objects={schemaDiffObjects(preview)} />
        <SchemaDiffStepTable steps={preview.migration_steps} />
      </div>
      <div className="grid gap-2 rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-semibold text-[var(--om-text)]">Migration Script</span>
          <Badge tone="info">{shortHash(preview.migration_script_sha256)}</Badge>
        </div>
        <pre className={cn(OM_CODE, "max-h-[240px]")}>{preview.migration_script}</pre>
      </div>
    </div>
  );
}

function SchemaDiffObjectList({
  title,
  objects
}: {
  title: string;
  objects: SchemaDiffObjectView[];
}): React.ReactElement {
  return (
    <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
      <div className="border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--om-text)]">
        {title}
      </div>
      <div className="max-h-[260px] divide-y divide-[var(--om-border)] overflow-auto">
        {objects.length === 0 ? (
          <div className="px-3 py-4 text-sm font-semibold text-[var(--om-text-muted)]">
            No object changes
          </div>
        ) : (
          objects.map((object) => (
            <div key={`${object.kind}:${object.object_type}:${object.name}`} className="grid gap-1 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={object.kind === "dropped" ? "warn" : object.kind === "added" ? "ok" : "info"}>
                  {object.kind}
                </Badge>
                <span className="min-w-0 truncate font-mono text-sm font-semibold text-[var(--om-text-bright)]">
                  {object.object_type} {object.name}
                </span>
              </div>
              <p className="truncate font-mono text-xs text-[var(--om-text-muted)]">
                {shortHash(object.ddl_sha256)} · {formatNumber(object.ddl_chars)} chars
              </p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function SchemaDiffStepTable({ steps }: { steps: SchemaDiffStepView[] }): React.ReactElement {
  return (
    <div className="overflow-hidden rounded-md border border-[var(--om-border)]">
      <div className="border-b border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--om-text)]">
        Migration Steps
      </div>
      <div className="overflow-x-auto" role="region" aria-label="Migration steps" tabIndex={0}>
        <table className="w-full min-w-[560px] border-collapse text-left text-sm">
          <caption className="sr-only">Migration steps generated from the schema comparison</caption>
          <thead className="bg-[var(--om-surface)] text-2xs uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            <tr>
              <th className="px-3 py-2 font-semibold">#</th>
              <th className="px-3 py-2 font-semibold">Kind</th>
              <th className="px-3 py-2 font-semibold">Object</th>
              <th className="px-3 py-2 font-semibold">Gate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--om-border)]">
            {steps.map((step) => (
              <tr key={`${step.order}:${step.object_type}:${step.name}`}>
                <td className="px-3 py-2 font-mono text-xs text-[var(--om-text-muted)]">
                  {step.order + 1}
                </td>
                <td className="px-3 py-2">
                  <Badge tone={step.kind === "manual_review" ? "warn" : "info"}>{step.kind}</Badge>
                </td>
                <td className="px-3 py-2 font-mono text-xs font-semibold text-[var(--om-text-bright)]">
                  {step.object_type} {step.name}
                </td>
                <td className="px-3 py-2">
                  <Badge tone={step.executable ? "ok" : "warn"}>
                    {step.executable ? "proposal" : "review"}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function operatorOutcomeTone(
  state: OperatorOutcomeState
): "ok" | "warn" | "info" | "neutral" {
  switch (state) {
    case "success":
      return "ok";
    case "refused":
      return "info";
    case "partial":
      return "neutral";
    case "failed":
      return "warn";
  }
}

export function OperatorOutcomeNotice({
  outcome
}: {
  outcome: OperatorOutcome;
}): React.ReactElement {
  const tone = operatorOutcomeTone(outcome.state);
  const stateClass = {
    success:
      "border-[color-mix(in_srgb,var(--om-sage)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-sage)_12%,transparent)] text-[var(--om-sage)]",
    refused:
      "border-[color-mix(in_srgb,var(--om-gold)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-gold)_12%,transparent)] text-[var(--om-gold)]",
    partial:
      "border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text-bright)]",
    failed:
      "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] text-[var(--om-copper)]"
  }[outcome.state];
  return (
    <div
      className={cn("rounded-md border p-3", stateClass)}
      data-operator-outcome={outcome.state}
      data-outcome-tone={tone}
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold">{outcome.message}</p>
        <Badge tone={tone}>{outcome.state}</Badge>
      </div>
      {outcome.errorClass ? (
        <p className="mt-2 font-mono text-xs">{outcome.errorClass}</p>
      ) : null}
      {outcome.nextSteps.length > 0 ? (
        <div className="mt-3">
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)]">
            Next steps
          </p>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
            {outcome.nextSteps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function ReviewResultPanel({
  result,
  pending
}: {
  result: ReviewResult | null;
  pending: boolean;
}): React.ReactElement {
  return (
    <ConsolePanel>
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-base font-semibold text-[var(--om-text-bright)]">
            <Code2 className="size-4" aria-hidden="true" />
            Latest action
          </h3>
          <p className="mt-1 truncate text-sm text-[var(--om-text-muted)]">
            {pending ? "request in flight" : result ? result.label : "idle"}
          </p>
        </div>
        <Badge tone={pending ? "info" : result ? operatorOutcomeTone(result.state) : "off"}>
          {pending ? "running" : result?.state ?? "empty"}
        </Badge>
      </div>
      <div className="space-y-3 p-4">
        {result ? <OperatorOutcomeNotice outcome={result.outcome} /> : null}
        {result?.response ? (
          <details className="rounded-md border border-[var(--om-border)] p-3">
            <summary className="cursor-pointer text-sm font-semibold text-[var(--om-text)]">Technical response</summary>
            <pre className={cn(OM_CODE, "mt-3 max-h-[560px]")}>{prettyJson(result.response)}</pre>
          </details>
        ) : (
          <p className="text-sm text-[var(--om-text-muted)]">No review action has run yet.</p>
        )}
      </div>
    </ConsolePanel>
  );
}

function parseBindsJson(text: string): unknown[] {
  const trimmed = text.trim();
  if (!trimmed) {
    return [];
  }
  const parsed = JSON.parse(trimmed) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error("binds must be a JSON array");
  }
  return parsed;
}

function parseSchemaSnapshotInput(text: string): SchemaSnapshotInput {
  const parsed = JSON.parse(text.trim()) as unknown;
  const candidate = Array.isArray(parsed) ? { objects: parsed } : parsed;
  if (!candidate || typeof candidate !== "object" || !Array.isArray((candidate as { objects?: unknown }).objects)) {
    throw new Error("schema snapshot must be an object with an objects array");
  }
  const objects = (candidate as { objects: unknown[] }).objects.map((item, index) => {
    if (!item || typeof item !== "object") {
      throw new Error(`schema snapshot object ${index + 1} must be an object`);
    }
    const object = item as Record<string, unknown>;
    return {
      object_type: requiredString(object.object_type, `objects[${index}].object_type`),
      name: requiredString(object.name, `objects[${index}].name`),
      ddl: requiredString(object.ddl, `objects[${index}].ddl`)
    };
  });
  return { objects };
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function schemaDiffObjects(preview: SchemaDiffExportData): SchemaDiffObjectView[] {
  return [...preview.diff.added, ...preview.diff.changed, ...preview.diff.dropped];
}

function downloadTextFile(filename: string, text: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function safeFilename(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || "schema-diff-migration";
}

function proposalSearchText(proposal: ChangeProposalListView): string {
  // The list projection omits sql_template bodies; search over the metadata and
  // the per-statement SQL digest instead. Full text is available in the detail
  // view fetched on selection.
  return [
    proposal.title,
    proposal.profile,
    proposal.author,
    proposal.id,
    ...proposal.statements.map((statement) => statement.sql_sha256)
  ]
    .join(" ")
    .toLowerCase();
}

function proposalLevelTone(
  proposal: ChangeProposalListView
): "neutral" | "ok" | "warn" | "off" | "info" {
  if (proposal.statements.some((statement) => statement.unit === "ddl")) {
    return "warn";
  }
  if (proposal.statements.some((statement) => statement.unit === "dml")) {
    return "info";
  }
  return "ok";
}
