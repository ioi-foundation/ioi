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
