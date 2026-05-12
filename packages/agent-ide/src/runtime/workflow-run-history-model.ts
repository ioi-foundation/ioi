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
  searchQuery: string;
  statusFilter: string;
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
): boolean {
  if (!normalizedSearch) return true;
  return [run.id, run.status, run.summary]
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
  searchQuery,
  statusFilter,
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
    return matchesStatus && workflowRunMatchesSearch(run, normalizedSearch);
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
    defaultCompareRun,
    timelineEvents,
    interruptPreview: workflowInterruptPreview(lastRunResult),
    interrupt: lastRunResult?.interrupt ?? null,
    harnessAttempts: selectedRun?.harnessAttempts ?? [],
    harnessComparisons: selectedRun?.harnessShadowComparisons ?? [],
  };
}
