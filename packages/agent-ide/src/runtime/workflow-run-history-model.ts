import type {
  WorkflowHarnessNodeAttemptRecord,
  WorkflowHarnessShadowComparison,
  WorkflowProject,
  WorkflowRunResult,
  WorkflowRunStatus,
  WorkflowRunSummary,
  WorkflowStreamEvent,
} from "../types/graph";
import {
  compareRunRecords,
  type WorkflowRunComparison,
} from "./workflow-rail-model";
import {
  workflowInterruptPreview,
  type WorkflowInterruptPreview,
} from "./workflow-bottom-panel-model";
import {
  projectRuntimeTuiControlStateToWorkflowProjection,
  projectRuntimeThreadEventsToWorkflowProjection,
  type WorkflowRuntimeTuiControlStateInput,
  type WorkflowRuntimeTuiControlStateProjection,
  type WorkflowRuntimeTuiControlStateRow,
  type WorkflowRuntimeEventProjection,
  type WorkflowRuntimeComputerUseVisualTargetBounds,
  type WorkflowRuntimeComputerUseVisualTargetSummary,
  type WorkflowRuntimeThreadEventLike,
} from "./workflow-runtime-event-projection";
import {
  workflowRuntimePolicyStackFromEvents,
  type WorkflowRuntimePolicyStack,
} from "./workflow-runtime-policy-stack";
import {
  workflowRuntimeEditProposalPolicyStackFromEvents,
  type WorkflowRuntimeEditProposalPolicyStack,
} from "./workflow-runtime-edit-proposal-policy";
import {
  workflowRuntimeTelemetrySummaryFromProjection,
  type WorkflowRuntimeTelemetrySummary,
} from "./workflow-runtime-telemetry-summary";
import {
  workflowModelInvocationTraceSearchText,
  workflowModelInvocationTraces,
  type WorkflowModelInvocationTraceView,
} from "./workflow-model-invocation-trace";

export type WorkflowRunHistoryRow = {
  run: WorkflowRunSummary;
  selected: boolean;
  compare: boolean;
};

export type WorkflowRunHistoryStatusCounts = Partial<
  Record<WorkflowRunStatus, number>
>;

export type WorkflowRunHistoryModelInput = {
  workflow: WorkflowProject;
  runs: WorkflowRunSummary[];
  lastRunResult: WorkflowRunResult | null;
  compareRunResult: WorkflowRunResult | null;
  selectedRunId: string | null;
  compareRunId: string | null;
  runEvents: WorkflowStreamEvent[];
  runtimeThreadEvents?: WorkflowRuntimeThreadEventLike[];
  tuiControlState?: WorkflowRuntimeTuiControlStateInput;
  searchQuery: string;
  statusFilter: string;
  sourceFilter?: string;
};

export type WorkflowRunTelemetrySourceFilter = {
  sourceKind: string;
  label: string;
  count: number;
  active: boolean;
  blocksMutation: boolean;
};

export type WorkflowRunCodingToolBudgetEvidence = {
  sourceKind: "tui_coding_tool_rows";
  label: string;
  status: WorkflowRuntimeTelemetrySummary["status"];
  rowCount: number;
  eventIds: string[];
  workflowNodeIds: string[];
  toolNames: string[];
  toolCallIds: string[];
  budgetStatuses: string[];
  contextBudgetStatuses: string[];
  totalTokens: number | null;
  costEstimateUsd: number | null;
  contextPressure: number | null;
  contextPressureStatus: string | null;
  mutationBlocked: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
};

export type WorkflowRunComputerUseWorkbench = {
  status: string;
  lane: string | null;
  sessionMode: string | null;
  leaseId: string | null;
  controlledRelaunchLaunchRef: string | null;
  controlledRelaunchLaunchStatus: string | null;
  controlledRelaunchProcessRef: string | null;
  controlledRelaunchProfileDirRef: string | null;
  controlledRelaunchEndpointRef: string | null;
  controlledRelaunchApprovalRef: string | null;
  observationRef: string | null;
  screenRef: string | null;
  somRef: string | null;
  coordinateSpaceId: string | null;
  targetIndexRef: string | null;
  targetCount: number;
  affordanceCount: number;
  detectedPatterns: string[];
  proposalRef: string | null;
  actionRef: string | null;
  actionKind: string | null;
  executionRef: string | null;
  executionStatus: string | null;
  executionAdapterId: string | null;
  executionProviderId: string | null;
  executionPreflightStatus: string | null;
  executionRequiresReobserve: boolean | null;
  verificationStatus: string | null;
  commitGateStatus: string | null;
  cleanupRef: string | null;
  cleanupStatus: string | null;
  policyDecisionRef: string | null;
  policyOutcome: string | null;
  policyAuthorityScope: string | null;
  policyApprovalRef: string | null;
  policyExternalEffect: boolean | null;
  policyFailClosed: boolean | null;
  blocker: string | null;
  retentionMode: string | null;
  authorityRequired: string | null;
  eventIds: string[];
  workflowNodeIds: string[];
  artifactRefs: string[];
  artifactPreviews: WorkflowRunComputerUseArtifactPreview[];
  overlayViewport: WorkflowRunComputerUseOverlayViewport | null;
  visualTargetSummaries: WorkflowRuntimeComputerUseVisualTargetSummary[];
};

export type WorkflowRunComputerUseArtifactPreview = {
  artifactRef: string;
  label: string;
  previewKind: "embedded_image" | "runtime_artifact" | "opaque_ref";
  fetchPath: string | null;
  embeddableUrl: string | null;
};

export type WorkflowRunComputerUseOverlayViewport = {
  coordinateSpaceId: string | null;
  width: number;
  height: number;
};

export type WorkflowRunComputerUseScorecardRow = {
  id: string;
  lane: string;
  label: string;
  status: string;
  sessionMode: string | null;
  actionKind: string | null;
  modelPromptTrace: string | null;
  runtimeEvents: number;
  projectedNodes: number;
  targets: number;
  affordances: number;
  policy: string | null;
  verification: string | null;
  cleanup: string | null;
  proofPath: string | null;
  blockers: string[];
};

export type WorkflowRunComputerUseScorecardBlocker = {
  id: string;
  check: string;
  severity: string;
  title: string;
  detail: string;
  lanes: string[];
};

export type WorkflowRunComputerUseScorecardDeferral = {
  id: string;
  status: string;
  reason: string;
};

export type WorkflowRunComputerUseScorecard = {
  status: string;
  headline: string;
  summaryRows: WorkflowRunComputerUseScorecardRow[];
  blockers: WorkflowRunComputerUseScorecardBlocker[];
  externalDeferrals: WorkflowRunComputerUseScorecardDeferral[];
  proofPaths: string[];
};

export type WorkflowRunHistoryModel = {
  normalizedSearch: string;
  totalRuns: number;
  runStatuses: WorkflowRunStatus[];
  statusCounts: WorkflowRunHistoryStatusCounts;
  filteredRuns: WorkflowRunSummary[];
  visibleRows: WorkflowRunHistoryRow[];
  selectedRun: WorkflowRunResult | null;
  comparison: WorkflowRunComparison | null;
  runtimeEventProjection: WorkflowRuntimeEventProjection;
  runtimePolicyStack: WorkflowRuntimePolicyStack;
  runtimeEditProposalPolicyStack: WorkflowRuntimeEditProposalPolicyStack;
  runtimeTelemetrySummary: WorkflowRuntimeTelemetrySummary;
  runtimeTelemetrySourceFilter: string;
  runtimeTelemetrySourceFilters: WorkflowRunTelemetrySourceFilter[];
  runtimeCodingToolBudgetEvidence: WorkflowRunCodingToolBudgetEvidence | null;
  computerUseWorkbench: WorkflowRunComputerUseWorkbench | null;
  computerUseScorecard: WorkflowRunComputerUseScorecard | null;
  modelInvocationTraces: WorkflowModelInvocationTraceView[];
  tuiControlStateProjection: WorkflowRuntimeTuiControlStateProjection;
  visibleTuiControlStateRows: WorkflowRuntimeTuiControlStateRow[];
  defaultCompareRun: WorkflowRunSummary | null;
  timelineEvents: WorkflowStreamEvent[];
  interruptPreview: WorkflowInterruptPreview | undefined;
  interrupt: WorkflowRunResult["interrupt"] | null;
  harnessAttempts: WorkflowHarnessNodeAttemptRecord[];
  harnessComparisons: WorkflowHarnessShadowComparison[];
};

function workflowRunMatchesSearch(
  run: WorkflowRunSummary,
  normalizedSearch: string,
  traceSearchText = "",
): boolean {
  if (!normalizedSearch) return true;
  return [run.id, run.status, run.summary, traceSearchText]
    .join(" ")
    .toLowerCase()
    .includes(normalizedSearch);
}

export function workflowRunHistoryModel({
  workflow,
  runs,
  lastRunResult,
  compareRunResult,
  selectedRunId,
  compareRunId,
  runEvents,
  runtimeThreadEvents,
  tuiControlState,
  searchQuery,
  statusFilter,
  sourceFilter = "all",
}: WorkflowRunHistoryModelInput): WorkflowRunHistoryModel {
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const selectedRun =
    lastRunResult?.summary.id === selectedRunId ? lastRunResult : null;
  const comparison =
    selectedRun &&
    compareRunResult &&
    compareRunResult.summary.id !== selectedRun.summary.id
      ? compareRunRecords(workflow, selectedRun, compareRunResult)
      : null;
  const defaultCompareRun =
    runs.find((run) => run.id !== selectedRunId) ?? null;
  const timelineEvents = selectedRun?.events ?? runEvents;
  const canonicalRuntimeThreadEvents =
    runtimeThreadEvents ?? runtimeThreadEventsForRunResult(selectedRun);
  const runtimeEventProjection = projectRuntimeThreadEventsToWorkflowProjection(
    canonicalRuntimeThreadEvents,
    { columns: 2 },
  );
  const runtimePolicyStack = workflowRuntimePolicyStackFromEvents(
    canonicalRuntimeThreadEvents,
    { workflowGraphId: workflow.metadata.id },
  );
  const runtimeEditProposalPolicyStack =
    workflowRuntimeEditProposalPolicyStackFromEvents(
      canonicalRuntimeThreadEvents,
      { workflowGraphId: workflow.metadata.id },
    );
  const tuiControlStateProjection = projectRuntimeTuiControlStateToWorkflowProjection(
    tuiControlState ?? tuiControlStateForRunResult(selectedRun),
  );
  const runtimeTelemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
    runtimeThreadEvents: canonicalRuntimeThreadEvents,
    runtimeEventProjection,
    tuiControlStateProjection,
  });
  const telemetrySourceKinds = new Set(runtimeTelemetrySummary.sourceKinds);
  const runtimeTelemetrySourceFilter =
    sourceFilter === "all" || telemetrySourceKinds.has(sourceFilter)
      ? sourceFilter
      : "all";
  const runtimeTelemetrySourceFilters = workflowRunTelemetrySourceFilters(
    runtimeTelemetrySummary,
    runtimeTelemetrySourceFilter,
  );
  const runtimeCodingToolBudgetEvidence = workflowRunCodingToolBudgetEvidence(
    runtimeTelemetrySummary,
    tuiControlStateProjection.rows,
  );
  const computerUseWorkbench =
    workflowRunComputerUseWorkbench(
      runtimeEventProjection,
      selectedRun?.summary.id ?? selectedRunId,
    );
  const computerUseScorecard = workflowRunComputerUseScorecard(selectedRun);
  const selectedModelInvocationTraces = workflowModelInvocationTraces(
    selectedRun,
    workflow,
  );
  const modelInvocationTraceTextByRunId = new Map<string, string>();
  if (lastRunResult) {
    modelInvocationTraceTextByRunId.set(
      lastRunResult.summary.id,
      workflowModelInvocationTraceSearchText(
        workflowModelInvocationTraces(lastRunResult, workflow),
      ),
    );
  }
  if (compareRunResult) {
    modelInvocationTraceTextByRunId.set(
      compareRunResult.summary.id,
      workflowModelInvocationTraceSearchText(
        workflowModelInvocationTraces(compareRunResult, workflow),
      ),
    );
  }
  const visibleTuiControlStateRows = tuiControlStateProjection.rows.filter((row) =>
    tuiRowMatchesTelemetrySourceFilter(row, runtimeTelemetrySourceFilter),
  );
  const runStatuses = Array.from(new Set(runs.map((run) => run.status))).sort();
  const statusCounts = runs.reduce<WorkflowRunHistoryStatusCounts>(
    (counts, run) => {
      counts[run.status] = (counts[run.status] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const filteredRuns = runs.filter((run) => {
    const matchesStatus = statusFilter === "all" || run.status === statusFilter;
    return (
      matchesStatus &&
      workflowRunMatchesSearch(
        run,
        normalizedSearch,
        modelInvocationTraceTextByRunId.get(run.id),
      )
    );
  });
  const visibleRows = filteredRuns.slice(0, 8).map<WorkflowRunHistoryRow>(
    (run) => ({
      run,
      selected: selectedRunId === run.id,
      compare: compareRunId === run.id,
    }),
  );

  return {
    normalizedSearch,
    totalRuns: runs.length,
    runStatuses,
    statusCounts,
    filteredRuns,
    visibleRows,
    selectedRun,
    comparison,
    runtimeEventProjection,
    runtimePolicyStack,
    runtimeEditProposalPolicyStack,
    runtimeTelemetrySummary,
    runtimeTelemetrySourceFilter,
    runtimeTelemetrySourceFilters,
    runtimeCodingToolBudgetEvidence,
    computerUseWorkbench,
    computerUseScorecard,
    modelInvocationTraces: selectedModelInvocationTraces,
    tuiControlStateProjection,
    visibleTuiControlStateRows,
    defaultCompareRun,
    timelineEvents,
    interruptPreview: workflowInterruptPreview(lastRunResult),
    interrupt: lastRunResult?.interrupt ?? null,
    harnessAttempts: selectedRun?.harnessAttempts ?? [],
    harnessComparisons: selectedRun?.harnessShadowComparisons ?? [],
  };
}

function workflowRunComputerUseWorkbench(
  projection: WorkflowRuntimeEventProjection,
  runId: string | null,
): WorkflowRunComputerUseWorkbench | null {
  const nodes = projection.nodes.filter((node) => node.computerUse);
  if (nodes.length === 0) return null;
  const latestNode = nodes[nodes.length - 1];
  const latestComputerUse = latestNode?.computerUse;
  if (!latestComputerUse) return null;
  const latestScreenNode =
    [...nodes]
      .reverse()
      .find((node) =>
        Boolean(
          node.computerUse?.screenRef ??
            node.computerUse?.somRef ??
            node.computerUse?.observationRef,
        ),
      ) ?? latestNode;
  const latestScreen = latestScreenNode.computerUse ?? latestComputerUse;
  const targetSummaries = uniqueTargets(
    nodes.flatMap((node) => node.computerUse?.visualTargetSummaries ?? []),
  );
  const artifactRefs = uniqueStrings(nodes.flatMap((node) => node.artifactRefs));
  const latestExecution = [...nodes]
    .reverse()
    .find(
      (node) =>
        node.computerUse?.executionStatus ||
        node.computerUse?.executionRef ||
        node.computerUse?.executionAdapterId,
    )?.computerUse;
  return {
    status: latestComputerUse.status,
    lane: latestComputerUse.lane ?? latestScreen.lane,
    sessionMode: latestComputerUse.sessionMode ?? latestScreen.sessionMode,
    leaseId: latestComputerUse.leaseId ?? latestScreen.leaseId,
    controlledRelaunchLaunchRef:
      [...nodes].reverse().find((node) => node.computerUse?.controlledRelaunchLaunchRef)
        ?.computerUse?.controlledRelaunchLaunchRef ?? null,
    controlledRelaunchLaunchStatus:
      [...nodes].reverse().find((node) => node.computerUse?.controlledRelaunchLaunchStatus)
        ?.computerUse?.controlledRelaunchLaunchStatus ?? null,
    controlledRelaunchProcessRef:
      [...nodes].reverse().find((node) => node.computerUse?.controlledRelaunchProcessRef)
        ?.computerUse?.controlledRelaunchProcessRef ?? null,
    controlledRelaunchProfileDirRef:
      [...nodes].reverse().find((node) => node.computerUse?.controlledRelaunchProfileDirRef)
        ?.computerUse?.controlledRelaunchProfileDirRef ?? null,
    controlledRelaunchEndpointRef:
      [...nodes].reverse().find((node) => node.computerUse?.controlledRelaunchEndpointRef)
        ?.computerUse?.controlledRelaunchEndpointRef ?? null,
    controlledRelaunchApprovalRef:
      [...nodes].reverse().find((node) => node.computerUse?.controlledRelaunchApprovalRef)
        ?.computerUse?.controlledRelaunchApprovalRef ?? null,
    observationRef: latestScreen.observationRef,
    screenRef: latestScreen.screenRef,
    somRef: latestScreen.somRef,
    coordinateSpaceId: latestScreen.coordinateSpaceId,
    targetIndexRef: latestScreen.targetIndexRef,
    targetCount: Math.max(
      latestScreen.targetCount ?? 0,
      targetSummaries.length,
    ),
    affordanceCount: nodes.reduce(
      (count, node) => Math.max(count, node.computerUse?.affordanceCount ?? 0),
      latestScreen.affordanceCount ?? 0,
    ),
    detectedPatterns: uniqueStrings(
      nodes.flatMap((node) => node.computerUse?.detectedPatterns ?? []),
    ),
    proposalRef:
      [...nodes].reverse().find((node) => node.computerUse?.proposalRef)
        ?.computerUse?.proposalRef ?? null,
    actionRef:
      [...nodes].reverse().find((node) => node.computerUse?.actionRef)
        ?.computerUse?.actionRef ?? null,
    actionKind:
      [...nodes].reverse().find((node) => node.computerUse?.actionKind)
        ?.computerUse?.actionKind ?? null,
    executionRef: latestExecution?.executionRef ?? null,
    executionStatus: latestExecution?.executionStatus ?? null,
    executionAdapterId: latestExecution?.executionAdapterId ?? null,
    executionProviderId: latestExecution?.executionProviderId ?? null,
    executionPreflightStatus: latestExecution?.executionPreflightStatus ?? null,
    executionRequiresReobserve:
      latestExecution?.executionRequiresReobserve ?? null,
    verificationStatus:
      [...nodes].reverse().find((node) => node.computerUse?.verificationStatus)
        ?.computerUse?.verificationStatus ?? null,
    commitGateStatus:
      [...nodes].reverse().find((node) => node.computerUse?.commitGateStatus)
        ?.computerUse?.commitGateStatus ?? null,
    cleanupRef:
      [...nodes].reverse().find((node) => node.computerUse?.cleanupRef)
        ?.computerUse?.cleanupRef ?? null,
    cleanupStatus:
      [...nodes].reverse().find((node) => node.computerUse?.cleanupStatus)
        ?.computerUse?.cleanupStatus ?? null,
    policyDecisionRef:
      [...nodes].reverse().find((node) => node.computerUse?.policyDecisionRef)
        ?.computerUse?.policyDecisionRef ?? null,
    policyOutcome:
      [...nodes].reverse().find((node) => node.computerUse?.policyOutcome)
        ?.computerUse?.policyOutcome ?? null,
    policyAuthorityScope:
      [...nodes].reverse().find((node) => node.computerUse?.policyAuthorityScope)
        ?.computerUse?.policyAuthorityScope ?? null,
    policyApprovalRef:
      [...nodes].reverse().find((node) => node.computerUse?.policyApprovalRef)
        ?.computerUse?.policyApprovalRef ?? null,
    policyExternalEffect:
      [...nodes].reverse().find((node) => node.computerUse?.policyExternalEffect !== null)
        ?.computerUse?.policyExternalEffect ?? null,
    policyFailClosed:
      [...nodes].reverse().find((node) => node.computerUse?.policyFailClosed !== null)
        ?.computerUse?.policyFailClosed ?? null,
    blocker:
      [...nodes].reverse().find((node) => node.computerUse?.blocker)
        ?.computerUse?.blocker ?? null,
    retentionMode:
      latestScreen.retentionMode ?? latestComputerUse.retentionMode,
    authorityRequired:
      latestComputerUse.authorityRequired ?? latestScreen.authorityRequired,
    eventIds: uniqueStrings(nodes.flatMap((node) => node.eventIds)),
    workflowNodeIds: uniqueStrings(
      nodes.flatMap((node) => [
        node.computerUse?.workflowNodeId,
        ...(node.computerUse?.workflowNodeIds ?? []),
        node.workflowNodeId,
      ]),
    ),
    artifactRefs,
    artifactPreviews: computerUseArtifactPreviews({
      runId,
      screenRef: latestScreen.screenRef,
      somRef: latestScreen.somRef,
      artifactRefs,
    }),
    overlayViewport: overlayViewportForTargets(
      targetSummaries,
      latestScreen.coordinateSpaceId,
    ),
    visualTargetSummaries: targetSummaries,
  };
}

function workflowRunComputerUseScorecard(
  run: WorkflowRunResult | null,
): WorkflowRunComputerUseScorecard | null {
  if (!run) return null;
  for (const candidate of workflowRunComputerUseScorecardCandidates(run)) {
    const scorecard = normalizeWorkflowRunComputerUseScorecard(candidate);
    if (scorecard) return scorecard;
  }
  return null;
}

function workflowRunComputerUseScorecardCandidates(
  run: WorkflowRunResult,
): unknown[] {
  const candidates: unknown[] = [];
  pushComputerUseScorecardCandidates(candidates, run.finalState.values);
  for (const nodeRun of run.nodeRuns) {
    pushComputerUseScorecardCandidates(candidates, nodeRun.output);
  }
  return candidates;
}

function pushComputerUseScorecardCandidates(
  candidates: unknown[],
  value: unknown,
) {
  const record = asRecord(value);
  if (!record) return;
  candidates.push(
    record.computerUseTriLaneScorecard,
    record.workflowComputerUseTriLaneScorecard,
    record.workflow_computer_use_tri_lane_scorecard,
  );
  const evidenceAssessment = asRecord(record.evidenceAssessment);
  candidates.push(evidenceAssessment?.computerUseTriLaneScorecard);
  const guiEvidence = asRecord(record.guiEvidence);
  const guiEvidenceAssessment = asRecord(guiEvidence?.evidenceAssessment);
  candidates.push(guiEvidenceAssessment?.computerUseTriLaneScorecard);
  const result = asRecord(record.result);
  if (result) {
    candidates.push(
      result.computerUseTriLaneScorecard,
      result.workflowComputerUseTriLaneScorecard,
      result.workflow_computer_use_tri_lane_scorecard,
    );
  }
  if (record.operatorSummary || record.summaryRows) {
    candidates.push(record);
  }
}

function normalizeWorkflowRunComputerUseScorecard(
  candidate: unknown,
): WorkflowRunComputerUseScorecard | null {
  const record = asRecord(candidate);
  if (!record) return null;
  const summary = asRecord(record.operatorSummary) ?? record;
  const summaryRows = arrayOfRecords(summary.summaryRows)
    .map(normalizeWorkflowRunComputerUseScorecardRow)
    .filter(
      (row): row is WorkflowRunComputerUseScorecardRow => Boolean(row),
    );
  const blockers = arrayOfRecords(summary.blockers).map(
    normalizeWorkflowRunComputerUseScorecardBlocker,
  );
  const externalDeferrals = arrayOfRecords(
    summary.externalDeferrals ?? record.externalDeferrals,
  ).map(normalizeWorkflowRunComputerUseScorecardDeferral);
  if (
    summaryRows.length === 0 &&
    blockers.length === 0 &&
    externalDeferrals.length === 0
  ) {
    return null;
  }
  return {
    status:
      readString(summary.status) ??
      readString(record.promotionStatus) ??
      (record.passed === true ? "passed" : "unknown"),
    headline:
      readString(summary.headline) ??
      "Computer-use tri-lane scorecard summary is available.",
    summaryRows,
    blockers,
    externalDeferrals,
    proofPaths: uniqueStrings(summaryRows.map((row) => row.proofPath)),
  };
}

function normalizeWorkflowRunComputerUseScorecardRow(
  row: Record<string, unknown>,
): WorkflowRunComputerUseScorecardRow | null {
  const lane = readString(row.lane);
  const label = readString(row.label) ?? lane;
  if (!label) return null;
  return {
    id: readString(row.id) ?? `lane:${lane ?? label}`,
    lane: lane ?? label,
    label,
    status: readString(row.status) ?? "unknown",
    sessionMode: readString(row.sessionMode),
    actionKind: readString(row.actionKind),
    modelPromptTrace: readString(row.modelPromptTrace),
    runtimeEvents: readNumber(row.runtimeEvents),
    projectedNodes: readNumber(row.projectedNodes),
    targets: readNumber(row.targets),
    affordances: readNumber(row.affordances),
    policy: readString(row.policy),
    verification: readString(row.verification),
    cleanup: readString(row.cleanup),
    proofPath: readString(row.proofPath),
    blockers: uniqueStrings(Array.isArray(row.blockers) ? row.blockers : []),
  };
}

function normalizeWorkflowRunComputerUseScorecardBlocker(
  blocker: Record<string, unknown>,
): WorkflowRunComputerUseScorecardBlocker {
  const check = readString(blocker.check) ?? "unknown_check";
  return {
    id: readString(blocker.id) ?? `blocker:${check}`,
    check,
    severity: readString(blocker.severity) ?? "blocking",
    title: readString(blocker.title) ?? check,
    detail:
      readString(blocker.detail) ??
      "Inspect the computer-use scorecard lane rows for missing evidence.",
    lanes: uniqueStrings(Array.isArray(blocker.lanes) ? blocker.lanes : []),
  };
}

function normalizeWorkflowRunComputerUseScorecardDeferral(
  deferral: Record<string, unknown>,
): WorkflowRunComputerUseScorecardDeferral {
  const id = readString(deferral.id) ?? "external_deferral";
  return {
    id,
    status: readString(deferral.status) ?? "external_deferral",
    reason:
      readString(deferral.reason) ??
      "This evidence depends on a selected external provider or eval.",
  };
}

function computerUseArtifactPreviews({
  runId,
  screenRef,
  somRef,
  artifactRefs,
}: {
  runId: string | null;
  screenRef: string | null | undefined;
  somRef: string | null | undefined;
  artifactRefs: readonly string[];
}): WorkflowRunComputerUseArtifactPreview[] {
  return uniqueStrings([screenRef, somRef, ...artifactRefs]).map((artifactRef) => {
    const embeddableUrl = embeddableComputerUseArtifactRef(artifactRef);
    const fetchPath =
      runId && !embeddableUrl
        ? `/v1/runs/${encodeURIComponent(runId)}/artifacts/${encodeURIComponent(artifactRef)}`
        : null;
    return {
      artifactRef,
      label: computerUseArtifactLabel(artifactRef),
      previewKind: embeddableUrl
        ? "embedded_image"
        : fetchPath
          ? "runtime_artifact"
          : "opaque_ref",
      fetchPath,
      embeddableUrl,
    };
  });
}

function embeddableComputerUseArtifactRef(ref: string | null | undefined): string | null {
  const value = ref?.trim();
  if (!value) return null;
  return /^(https?:\/\/|data:image\/|blob:|\/)/i.test(value) ? value : null;
}

function computerUseArtifactLabel(ref: string): string {
  const value = ref.trim();
  if (!value) return "artifact";
  if (value.includes("/")) {
    const segments = value.split("/").filter(Boolean);
    return segments[segments.length - 1] ?? value;
  }
  if (value.includes(":")) {
    const segments = value.split(":").filter(Boolean);
    return segments[segments.length - 1] ?? value;
  }
  return value;
}

function uniqueTargets(
  targets: readonly WorkflowRuntimeComputerUseVisualTargetSummary[],
): WorkflowRuntimeComputerUseVisualTargetSummary[] {
  const seen = new Set<string>();
  const unique: WorkflowRuntimeComputerUseVisualTargetSummary[] = [];
  for (const target of targets) {
    if (seen.has(target.targetRef)) continue;
    seen.add(target.targetRef);
    unique.push(target);
  }
  return unique;
}

function overlayViewportForTargets(
  targets: readonly WorkflowRuntimeComputerUseVisualTargetSummary[],
  coordinateSpaceId: string | null,
): WorkflowRunComputerUseOverlayViewport | null {
  const bounds = targets
    .map((target) => target.bounds)
    .filter((value): value is WorkflowRuntimeComputerUseVisualTargetBounds =>
      Boolean(value),
    );
  if (bounds.length === 0) return null;
  const width = Math.max(...bounds.map((box) => box.x + box.width));
  const height = Math.max(...bounds.map((box) => box.y + box.height));
  if (!Number.isFinite(width) || !Number.isFinite(height)) return null;
  return {
    coordinateSpaceId: coordinateSpaceId ?? bounds[0]?.coordinateSpaceId ?? null,
    width: Math.max(1, Math.ceil(width)),
    height: Math.max(1, Math.ceil(height)),
  };
}

function workflowRunTelemetrySourceFilters(
  summary: WorkflowRuntimeTelemetrySummary,
  activeSourceKind: string,
): WorkflowRunTelemetrySourceFilter[] {
  return summary.sourceKinds.map((sourceKind) => ({
    sourceKind,
    label: telemetrySourceLabel(sourceKind),
    count: telemetrySourceCount(summary, sourceKind),
    active: activeSourceKind === sourceKind,
    blocksMutation:
      sourceKind === "tui_coding_tool_rows" && summary.status === "blocked",
  }));
}

function workflowRunCodingToolBudgetEvidence(
  summary: WorkflowRuntimeTelemetrySummary,
  rows: readonly WorkflowRuntimeTuiControlStateRow[],
): WorkflowRunCodingToolBudgetEvidence | null {
  const budgetRows = rows.filter((row) => row.rowKind === "coding_tool_budget");
  if (budgetRows.length === 0 && summary.codingToolBudgetRowCount === 0) {
    return null;
  }
  return {
    sourceKind: "tui_coding_tool_rows",
    label: "TUI coding budget evidence",
    status: summary.status,
    rowCount: summary.codingToolBudgetRowCount || budgetRows.length,
    eventIds: uniqueStrings([
      ...budgetRows.map((row) => row.eventId),
      ...summary.eventIds,
    ]),
    workflowNodeIds: uniqueStrings([
      ...budgetRows.map((row) => row.reactFlowNodeId),
      ...summary.workflowNodeIds,
    ]),
    toolNames: uniqueStrings(budgetRows.map((row) => row.toolName)),
    toolCallIds: uniqueStrings(budgetRows.map((row) => row.toolCallId)),
    budgetStatuses: uniqueStrings(
      budgetRows.map((row) => row.codingToolBudgetStatus),
    ),
    contextBudgetStatuses: uniqueStrings(
      budgetRows.map((row) => row.codingToolContextBudgetStatus),
    ),
    totalTokens: summary.totalTokens,
    costEstimateUsd: summary.costEstimateUsd,
    contextPressure: summary.contextPressure,
    contextPressureStatus: summary.contextPressureStatus,
    mutationBlocked: budgetRows.some(
      (row) => row.codingToolMutationBlocked === true,
    ),
    receiptRefs: uniqueStrings([
      ...budgetRows.flatMap((row) => row.receiptRefs),
      ...summary.receiptRefs,
    ]),
    policyDecisionRefs: uniqueStrings([
      ...budgetRows.flatMap((row) => row.policyDecisionRefs),
      ...summary.policyDecisionRefs,
    ]),
  };
}

function tuiRowMatchesTelemetrySourceFilter(
  row: WorkflowRuntimeTuiControlStateRow,
  sourceFilter: string,
): boolean {
  if (sourceFilter === "all") return true;
  switch (sourceFilter) {
    case "tui_usage_rows":
      return row.rowKind === "usage_status";
    case "tui_cost_rows":
      return row.rowKind === "cost_status";
    case "tui_context_rows":
      return row.rowKind === "context_budget" || row.rowKind === "compaction_policy";
    case "tui_subagent_rows":
      return row.rowKind === "subagent";
    case "tui_coding_tool_rows":
      return row.rowKind === "coding_tool_budget";
    default:
      return false;
  }
}

function telemetrySourceLabel(sourceKind: string): string {
  switch (sourceKind) {
    case "runtime_usage_events":
      return "runtime usage";
    case "runtime_context_pressure_events":
      return "context pressure";
    case "runtime_context_pressure_alerts":
      return "context alerts";
    case "tui_usage_rows":
      return "TUI usage";
    case "tui_cost_rows":
      return "TUI cost";
    case "tui_context_rows":
      return "TUI context";
    case "tui_subagent_rows":
      return "TUI subagents";
    case "tui_coding_tool_rows":
      return "TUI coding budgets";
    default:
      return sourceKind.replace(/_/g, " ");
  }
}

function telemetrySourceCount(
  summary: WorkflowRuntimeTelemetrySummary,
  sourceKind: string,
): number {
  switch (sourceKind) {
    case "runtime_usage_events":
      return summary.usageEventCount;
    case "runtime_context_pressure_events":
      return summary.contextPressureEventCount;
    case "runtime_context_pressure_alerts":
      return summary.contextPressureAlertCount;
    case "tui_usage_rows":
      return summary.usageRowCount;
    case "tui_cost_rows":
      return summary.costRowCount;
    case "tui_context_rows":
      return summary.contextRowCount;
    case "tui_subagent_rows":
      return summary.subagentRowCount;
    case "tui_coding_tool_rows":
      return summary.codingToolBudgetRowCount;
    default:
      return 0;
  }
}

function tuiControlStateForRunResult(
  run: WorkflowRunResult | null,
): WorkflowRuntimeTuiControlStateInput | undefined {
  const state = (run as { tuiControlState?: unknown } | null)?.tuiControlState;
  if (!state || typeof state !== "object" || Array.isArray(state)) return undefined;
  return state as WorkflowRuntimeTuiControlStateInput;
}

function runtimeThreadEventsForRunResult(
  run: WorkflowRunResult | null,
): WorkflowRuntimeThreadEventLike[] {
  const events = (run as { runtimeThreadEvents?: unknown } | null)
    ?.runtimeThreadEvents;
  if (!Array.isArray(events)) return [];
  return events.filter(isWorkflowRuntimeThreadEventLike);
}

function isWorkflowRuntimeThreadEventLike(
  event: unknown,
): event is WorkflowRuntimeThreadEventLike {
  if (!event || typeof event !== "object") return false;
  const candidate = event as Partial<WorkflowRuntimeThreadEventLike>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.cursor === "string" &&
    typeof candidate.seq === "number" &&
    typeof candidate.threadId === "string" &&
    typeof candidate.type === "string" &&
    typeof candidate.eventKind === "string" &&
    typeof candidate.sourceEventKind === "string" &&
    typeof candidate.status === "string" &&
    typeof candidate.payloadSchemaVersion === "string" &&
    Array.isArray(candidate.receiptRefs) &&
    Array.isArray(candidate.artifactRefs) &&
    Array.isArray(candidate.policyDecisionRefs) &&
    Array.isArray(candidate.rollbackRefs)
  );
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function arrayOfRecords(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (item): item is Record<string, unknown> =>
      Boolean(item) && typeof item === "object" && !Array.isArray(item),
  );
}

function readString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text || null;
}

function readNumber(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  const strings: string[] = [];
  for (const value of values.flat()) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) strings.push(text);
  }
  return [...new Set(strings)];
}
