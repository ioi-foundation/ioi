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
  verificationStatus: string | null;
  commitGateStatus: string | null;
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
  return {
    status: latestComputerUse.status,
    lane: latestComputerUse.lane ?? latestScreen.lane,
    sessionMode: latestComputerUse.sessionMode ?? latestScreen.sessionMode,
    leaseId: latestComputerUse.leaseId ?? latestScreen.leaseId,
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
    verificationStatus:
      [...nodes].reverse().find((node) => node.computerUse?.verificationStatus)
        ?.computerUse?.verificationStatus ?? null,
    commitGateStatus:
      [...nodes].reverse().find((node) => node.computerUse?.commitGateStatus)
        ?.computerUse?.commitGateStatus ?? null,
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
    workflowNodeIds: uniqueStrings(nodes.map((node) => node.workflowNodeId)),
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

function uniqueStrings(values: readonly unknown[]): string[] {
  const strings: string[] = [];
  for (const value of values.flat()) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) strings.push(text);
  }
  return [...new Set(strings)];
}
