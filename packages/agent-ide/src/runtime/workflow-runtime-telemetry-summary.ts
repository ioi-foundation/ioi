import type {
  WorkflowRuntimeEventProjection,
  WorkflowRuntimeThreadEventLike,
  WorkflowRuntimeTuiControlStateProjection,
  WorkflowRuntimeTuiControlStateRow,
} from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION =
  "ioi.workflow.runtime-telemetry-summary.v1" as const;

export type WorkflowRuntimeTelemetrySummaryStatus =
  | "not_available"
  | "nominal"
  | "elevated"
  | "high"
  | "blocked";

export interface WorkflowRuntimeTelemetrySummaryInput {
  runtimeThreadEvents?: readonly WorkflowRuntimeThreadEventLike[];
  runtimeEventProjection?: WorkflowRuntimeEventProjection;
  tuiControlStateProjection?: WorkflowRuntimeTuiControlStateProjection;
}

export interface WorkflowRuntimeTelemetrySummary {
  schemaVersion: typeof WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION;
  status: WorkflowRuntimeTelemetrySummaryStatus;
  sourceKinds: string[];
  threadIds: string[];
  turnIds: string[];
  workflowGraphIds: string[];
  workflowNodeIds: string[];
  eventIds: string[];
  latestSeq: number | null;
  latestCursor: string | null;
  latestEventId: string | null;
  runtimeEventCount: number;
  usageEventCount: number;
  contextPressureEventCount: number;
  contextPressureAlertCount: number;
  tuiRowCount: number;
  usageRowCount: number;
  costRowCount: number;
  contextRowCount: number;
  subagentRowCount: number;
  totalTokens: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  costEstimateUsd: number | null;
  contextPressure: number | null;
  contextPressureStatus: string | null;
  runCount: number | null;
  subagentCount: number | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimeTelemetrySummaryUsageTelemetry {
  schema_version: typeof WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION;
  schemaVersion: typeof WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION;
  object: "ioi.workflow_runtime_telemetry_summary_usage";
  scope: "thread" | "workflow";
  thread_id: string | null;
  threadId: string | null;
  turn_id: string | null;
  turnId: string | null;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  total_tokens: number;
  totalTokens: number;
  input_tokens: number;
  inputTokens: number;
  output_tokens: number;
  outputTokens: number;
  estimated_cost_usd: number;
  estimatedCostUsd: number;
  cost_estimate_usd: number;
  costEstimateUsd: number;
  context_pressure: number;
  contextPressure: number;
  context_pressure_status: string;
  contextPressureStatus: string;
  source_counts: { runs: number; subagents: number };
  sourceCounts: { runs: number; subagents: number };
  source_refs: string[];
  sourceRefs: string[];
  receipt_refs: string[];
  receiptRefs: string[];
  policy_decision_refs: string[];
  policyDecisionRefs: string[];
  runtime_telemetry_summary_schema_version: typeof WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION;
  runtimeTelemetrySummarySchemaVersion: typeof WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION;
}

interface UsageSnapshot {
  totalTokens: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  costEstimateUsd: number | null;
  contextPressure: number | null;
  contextPressureStatus: string | null;
  runCount: number | null;
  subagentCount: number | null;
}

export function workflowRuntimeTelemetrySummaryFromProjection({
  runtimeThreadEvents = [],
  runtimeEventProjection,
  tuiControlStateProjection,
}: WorkflowRuntimeTelemetrySummaryInput): WorkflowRuntimeTelemetrySummary {
  const sortedEvents = [...runtimeThreadEvents].sort((left, right) => {
    if (left.seq !== right.seq) return left.seq - right.seq;
    return left.id.localeCompare(right.id);
  });
  const runtimeUsageEvents = sortedEvents.filter(isUsageTelemetryEvent);
  const runtimeContextPressureEvents = sortedEvents.filter(isContextPressureEvent);
  const runtimeContextPressureAlertEvents = sortedEvents.filter(
    isContextPressureAlertEvent,
  );
  const tuiRows = tuiControlStateProjection?.rows ?? [];
  const usageRows = tuiRows.filter((row) => row.rowKind === "usage_status");
  const costRows = tuiRows.filter((row) => row.rowKind === "cost_status");
  const contextRows = tuiRows.filter(
    (row) =>
      row.rowKind === "context_budget" || row.rowKind === "compaction_policy",
  );
  const subagentRows = tuiRows.filter((row) => row.rowKind === "subagent");
  const sourceKinds = sourceKindsForTelemetry({
    runtimeUsageEvents,
    runtimeContextPressureEvents,
    runtimeContextPressureAlertEvents,
    usageRows,
    costRows,
    contextRows,
    subagentRows,
  });
  const snapshots = [
    ...runtimeUsageEvents.map(usageSnapshotFromEvent),
    ...runtimeContextPressureEvents.map(usageSnapshotFromContextPressureEvent),
    ...runtimeContextPressureAlertEvents.map(
      usageSnapshotFromContextPressureAlertEvent,
    ),
    ...usageRows.map(usageSnapshotFromTuiRow),
    ...costRows.map(usageSnapshotFromTuiRow),
    ...contextRows.map(usageSnapshotFromTuiRow),
    ...subagentRows.map(usageSnapshotFromSubagentRow),
  ].filter(snapshotHasTelemetry);
  const combinedSnapshot = combineUsageSnapshots(snapshots);
  const latestEvent = sortedEvents[sortedEvents.length - 1] ?? null;

  return {
    schemaVersion: WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION,
    status: telemetrySummaryStatus({
      snapshot: combinedSnapshot,
      contextRows,
      alertEvents: runtimeContextPressureAlertEvents,
    }),
    sourceKinds,
    threadIds: uniqueStrings([
      ...(runtimeEventProjection?.threadIds ?? []),
      ...sortedEvents.map((event) => event.threadId),
      tuiControlStateProjection?.threadId,
      ...tuiRows.map((row) => row.threadId),
    ]),
    turnIds: uniqueStrings([
      ...(runtimeEventProjection?.turnIds ?? []),
      ...sortedEvents.map((event) => event.turnId),
      tuiControlStateProjection?.currentTurnId,
      ...tuiRows.map((row) => row.turnId),
    ]),
    workflowGraphIds: uniqueStrings([
      ...(runtimeEventProjection?.workflowGraphIds ?? []),
      ...sortedEvents.map((event) => event.workflowGraphId),
      tuiControlStateProjection?.workflowGraphId,
      ...tuiRows.map((row) => row.workflowGraphId),
    ]),
    workflowNodeIds: uniqueStrings([
      ...sortedEvents.map((event) => event.workflowNodeId),
      ...tuiRows.map((row) => row.reactFlowNodeId),
    ]),
    eventIds: uniqueStrings([
      ...sortedEvents.map((event) => event.id),
      ...tuiRows.map((row) => row.eventId),
    ]),
    latestSeq: runtimeEventProjection?.latestSeq ?? latestEvent?.seq ?? null,
    latestCursor:
      runtimeEventProjection?.latestCursor ??
      latestEvent?.cursor ??
      tuiControlStateProjection?.lastCursor ??
      null,
    latestEventId:
      runtimeEventProjection?.latestEventId ??
      latestEvent?.id ??
      tuiControlStateProjection?.lastEventId ??
      null,
    runtimeEventCount: runtimeEventProjection?.eventCount ?? sortedEvents.length,
    usageEventCount: runtimeUsageEvents.length,
    contextPressureEventCount: runtimeContextPressureEvents.length,
    contextPressureAlertCount: runtimeContextPressureAlertEvents.length,
    tuiRowCount: tuiControlStateProjection?.rowCount ?? tuiRows.length,
    usageRowCount: tuiControlStateProjection?.usageRowCount ?? usageRows.length,
    costRowCount: tuiControlStateProjection?.costRowCount ?? costRows.length,
    contextRowCount:
      tuiControlStateProjection?.contextRowCount ?? contextRows.length,
    subagentRowCount:
      tuiControlStateProjection?.subagentRowCount ?? subagentRows.length,
    totalTokens: combinedSnapshot.totalTokens,
    inputTokens: combinedSnapshot.inputTokens,
    outputTokens: combinedSnapshot.outputTokens,
    costEstimateUsd: combinedSnapshot.costEstimateUsd,
    contextPressure: combinedSnapshot.contextPressure,
    contextPressureStatus: combinedSnapshot.contextPressureStatus,
    runCount: combinedSnapshot.runCount,
    subagentCount: combinedSnapshot.subagentCount,
    receiptRefs: uniqueStrings([
      ...sortedEvents.flatMap((event) => event.receiptRefs),
      ...tuiRows.flatMap((row) => row.receiptRefs),
    ]),
    policyDecisionRefs: uniqueStrings([
      ...sortedEvents.flatMap((event) => event.policyDecisionRefs),
      ...tuiRows.flatMap((row) => row.policyDecisionRefs),
    ]),
  };
}

export function workflowRuntimeTelemetrySummaryToUsageTelemetry(
  summary: unknown,
): WorkflowRuntimeTelemetrySummaryUsageTelemetry | null {
  if (!isWorkflowRuntimeTelemetrySummary(summary)) return null;
  const totalTokens = summary.totalTokens ?? 0;
  const inputTokens = summary.inputTokens ?? 0;
  const outputTokens = summary.outputTokens ?? 0;
  const costEstimateUsd = summary.costEstimateUsd ?? 0;
  const contextPressure = summary.contextPressure ?? 0;
  const contextPressureStatus =
    summary.contextPressureStatus ??
    statusFromContextPressure(summary.contextPressure) ??
    "nominal";
  const sourceCounts = {
    runs: summary.runCount ?? 0,
    subagents: summary.subagentCount ?? 0,
  };
  const threadId = summary.threadIds[0] ?? null;
  const turnId = summary.turnIds[0] ?? null;
  const workflowGraphId = summary.workflowGraphIds[0] ?? null;

  return {
    schema_version: WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION,
    schemaVersion: WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION,
    object: "ioi.workflow_runtime_telemetry_summary_usage",
    scope: threadId ? "thread" : "workflow",
    thread_id: threadId,
    threadId,
    turn_id: turnId,
    turnId,
    workflow_graph_id: workflowGraphId,
    workflowGraphId,
    total_tokens: totalTokens,
    totalTokens,
    input_tokens: inputTokens,
    inputTokens,
    output_tokens: outputTokens,
    outputTokens,
    estimated_cost_usd: costEstimateUsd,
    estimatedCostUsd: costEstimateUsd,
    cost_estimate_usd: costEstimateUsd,
    costEstimateUsd,
    context_pressure: contextPressure,
    contextPressure,
    context_pressure_status: contextPressureStatus,
    contextPressureStatus,
    source_counts: sourceCounts,
    sourceCounts,
    source_refs: summary.eventIds,
    sourceRefs: summary.eventIds,
    receipt_refs: summary.receiptRefs,
    receiptRefs: summary.receiptRefs,
    policy_decision_refs: summary.policyDecisionRefs,
    policyDecisionRefs: summary.policyDecisionRefs,
    runtime_telemetry_summary_schema_version:
      WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION,
    runtimeTelemetrySummarySchemaVersion:
      WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION,
  };
}

function sourceKindsForTelemetry({
  runtimeUsageEvents,
  runtimeContextPressureEvents,
  runtimeContextPressureAlertEvents,
  usageRows,
  costRows,
  contextRows,
  subagentRows,
}: {
  runtimeUsageEvents: readonly WorkflowRuntimeThreadEventLike[];
  runtimeContextPressureEvents: readonly WorkflowRuntimeThreadEventLike[];
  runtimeContextPressureAlertEvents: readonly WorkflowRuntimeThreadEventLike[];
  usageRows: readonly WorkflowRuntimeTuiControlStateRow[];
  costRows: readonly WorkflowRuntimeTuiControlStateRow[];
  contextRows: readonly WorkflowRuntimeTuiControlStateRow[];
  subagentRows: readonly WorkflowRuntimeTuiControlStateRow[];
}): string[] {
  const kinds: string[] = [];
  if (runtimeUsageEvents.length > 0) kinds.push("runtime_usage_events");
  if (runtimeContextPressureEvents.length > 0) {
    kinds.push("runtime_context_pressure_events");
  }
  if (runtimeContextPressureAlertEvents.length > 0) {
    kinds.push("runtime_context_pressure_alerts");
  }
  if (usageRows.length > 0) kinds.push("tui_usage_rows");
  if (costRows.length > 0) kinds.push("tui_cost_rows");
  if (contextRows.length > 0) kinds.push("tui_context_rows");
  if (subagentRows.length > 0) kinds.push("tui_subagent_rows");
  return kinds;
}

function usageSnapshotFromEvent(
  event: WorkflowRuntimeThreadEventLike,
): UsageSnapshot {
  const payload = event.payload ?? {};
  return {
    totalTokens: numberField(payload, "total_tokens", "totalTokens"),
    inputTokens: numberField(payload, "input_tokens", "inputTokens"),
    outputTokens: numberField(payload, "output_tokens", "outputTokens"),
    costEstimateUsd: numberField(
      payload,
      "estimated_cost_usd",
      "estimatedCostUsd",
      "usage_cost_estimate_usd",
      "usageCostEstimateUsd",
    ),
    contextPressure: numberField(
      payload,
      "context_pressure",
      "contextPressure",
      "usage_context_pressure",
      "usageContextPressure",
    ),
    contextPressureStatus: stringField(
      payload,
      "context_pressure_status",
      "contextPressureStatus",
      "usage_context_pressure_status",
      "usageContextPressureStatus",
    ),
    runCount: numberField(payload, "usage_run_count", "usageRunCount"),
    subagentCount: numberField(
      payload,
      "usage_subagent_count",
      "usageSubagentCount",
    ),
  };
}

function usageSnapshotFromContextPressureEvent(
  event: WorkflowRuntimeThreadEventLike,
): UsageSnapshot {
  const payload = event.payload ?? {};
  return {
    totalTokens: numberField(
      payload,
      "usage_total_tokens",
      "usageTotalTokens",
      "total_tokens",
      "totalTokens",
    ),
    inputTokens: null,
    outputTokens: null,
    costEstimateUsd: numberField(
      payload,
      "usage_cost_estimate_usd",
      "usageCostEstimateUsd",
      "estimated_cost_usd",
      "estimatedCostUsd",
    ),
    contextPressure: numberField(
      payload,
      "usage_context_pressure",
      "usageContextPressure",
      "context_pressure",
      "contextPressure",
    ),
    contextPressureStatus: stringField(
      payload,
      "usage_context_pressure_status",
      "usageContextPressureStatus",
      "context_pressure_status",
      "contextPressureStatus",
    ),
    runCount: null,
    subagentCount: null,
  };
}

function usageSnapshotFromContextPressureAlertEvent(
  event: WorkflowRuntimeThreadEventLike,
): UsageSnapshot {
  const payload = event.payload ?? {};
  return {
    totalTokens: numberField(
      payload,
      "usage_total_tokens",
      "usageTotalTokens",
    ),
    inputTokens: null,
    outputTokens: null,
    costEstimateUsd: numberField(
      payload,
      "usage_cost_estimate_usd",
      "usageCostEstimateUsd",
    ),
    contextPressure: numberField(payload, "pressure", "contextPressure"),
    contextPressureStatus: stringField(
      payload,
      "pressure_status",
      "pressureStatus",
      "contextPressureStatus",
    ),
    runCount: null,
    subagentCount: null,
  };
}

function usageSnapshotFromTuiRow(
  row: WorkflowRuntimeTuiControlStateRow,
): UsageSnapshot {
  return {
    totalTokens: row.usageTotalTokens ?? null,
    inputTokens: row.usageInputTokens ?? null,
    outputTokens: row.usageOutputTokens ?? null,
    costEstimateUsd: row.usageCostEstimateUsd ?? null,
    contextPressure: row.usageContextPressure ?? null,
    contextPressureStatus: row.usageContextPressureStatus ?? null,
    runCount: row.usageRunCount ?? null,
    subagentCount: row.usageSubagentCount ?? null,
  };
}

function usageSnapshotFromSubagentRow(
  row: WorkflowRuntimeTuiControlStateRow,
): UsageSnapshot {
  return {
    totalTokens: row.subagentTokenEstimate ?? null,
    inputTokens: null,
    outputTokens: null,
    costEstimateUsd: row.subagentCostEstimateUsd ?? null,
    contextPressure: null,
    contextPressureStatus: null,
    runCount: row.subagentRunId ? 1 : null,
    subagentCount: 1,
  };
}

function combineUsageSnapshots(
  snapshots: readonly UsageSnapshot[],
): UsageSnapshot {
  if (snapshots.length === 0) return emptyUsageSnapshot();
  const base = snapshots.reduce<UsageSnapshot>((current, next) => ({
    totalTokens: maxNullable(current.totalTokens, next.totalTokens),
    inputTokens: maxNullable(current.inputTokens, next.inputTokens),
    outputTokens: maxNullable(current.outputTokens, next.outputTokens),
    costEstimateUsd: maxNullable(current.costEstimateUsd, next.costEstimateUsd),
    contextPressure: maxNullable(current.contextPressure, next.contextPressure),
    contextPressureStatus: strongerContextStatus(
      current.contextPressureStatus,
      next.contextPressureStatus,
    ),
    runCount: maxNullable(current.runCount, next.runCount),
    subagentCount: maxNullable(current.subagentCount, next.subagentCount),
  }), emptyUsageSnapshot());
  return {
    ...base,
    contextPressureStatus:
      base.contextPressureStatus ?? statusFromContextPressure(base.contextPressure),
  };
}

function telemetrySummaryStatus({
  snapshot,
  contextRows,
  alertEvents,
}: {
  snapshot: UsageSnapshot;
  contextRows: readonly WorkflowRuntimeTuiControlStateRow[];
  alertEvents: readonly WorkflowRuntimeThreadEventLike[];
}): WorkflowRuntimeTelemetrySummaryStatus {
  if (alertEvents.some((event) => event.status === "blocked")) return "blocked";
  if (
    contextRows.some(
      (row) =>
        row.status === "blocked" ||
        row.contextBudgetStatus === "blocked" ||
        row.compactionPolicyStatus === "blocked",
    )
  ) {
    return "blocked";
  }
  const contextStatus =
    snapshot.contextPressureStatus ?? statusFromContextPressure(snapshot.contextPressure);
  if (contextStatus === "high") return "high";
  if (contextStatus === "elevated" || contextStatus === "warning") return "elevated";
  if (
    snapshot.totalTokens !== null ||
    snapshot.costEstimateUsd !== null ||
    snapshot.contextPressure !== null
  ) {
    return "nominal";
  }
  return "not_available";
}

function isUsageTelemetryEvent(event: WorkflowRuntimeThreadEventLike): boolean {
  return (
    event.type === "usage_delta" ||
    event.type === "usage_final" ||
    event.eventKind === "usage.delta" ||
    event.eventKind === "usage.final" ||
    event.sourceEventKind.startsWith("RuntimeUsageTelemetry") ||
    event.componentKind === "usage_telemetry"
  );
}

function isContextPressureEvent(event: WorkflowRuntimeThreadEventLike): boolean {
  return (
    event.type === "context_pressure_delta" ||
    event.eventKind === "context.pressure_delta" ||
    event.sourceEventKind === "RuntimeContextPressure.Delta" ||
    event.componentKind === "context_pressure"
  );
}

function isContextPressureAlertEvent(
  event: WorkflowRuntimeThreadEventLike,
): boolean {
  return (
    event.type === "context_pressure_alert" ||
    event.eventKind === "context.pressure_alert" ||
    event.sourceEventKind === "RuntimeContextPressure.Alert" ||
    event.componentKind === "context_pressure_alert"
  );
}

function snapshotHasTelemetry(snapshot: UsageSnapshot): boolean {
  return (
    snapshot.totalTokens !== null ||
    snapshot.inputTokens !== null ||
    snapshot.outputTokens !== null ||
    snapshot.costEstimateUsd !== null ||
    snapshot.contextPressure !== null ||
    snapshot.contextPressureStatus !== null ||
    snapshot.runCount !== null ||
    snapshot.subagentCount !== null
  );
}

function emptyUsageSnapshot(): UsageSnapshot {
  return {
    totalTokens: null,
    inputTokens: null,
    outputTokens: null,
    costEstimateUsd: null,
    contextPressure: null,
    contextPressureStatus: null,
    runCount: null,
    subagentCount: null,
  };
}

function maxNullable(left: number | null, right: number | null): number | null {
  if (left === null) return right;
  if (right === null) return left;
  return Math.max(left, right);
}

function strongerContextStatus(
  left: string | null,
  right: string | null,
): string | null {
  if (!left) return right;
  if (!right) return left;
  return contextStatusRank(right) > contextStatusRank(left) ? right : left;
}

function contextStatusRank(status: string): number {
  switch (status.toLowerCase()) {
    case "blocked":
    case "high":
      return 4;
    case "elevated":
    case "warning":
    case "warn":
      return 3;
    case "nominal":
    case "ok":
      return 2;
    default:
      return 1;
  }
}

function statusFromContextPressure(pressure: number | null): string | null {
  if (pressure === null) return null;
  if (pressure >= 0.85) return "high";
  if (pressure >= 0.6) return "elevated";
  return "nominal";
}

function isWorkflowRuntimeTelemetrySummary(
  value: unknown,
): value is WorkflowRuntimeTelemetrySummary {
  return (
    value !== null &&
    typeof value === "object" &&
    (value as { schemaVersion?: unknown }).schemaVersion ===
      WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION
  );
}

function numberField(
  value: Record<string, unknown>,
  ...keys: string[]
): number | null {
  for (const key of keys) {
    const field = value[key];
    if (field === undefined || field === null || field === "") continue;
    const number = Number(field);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function stringField(
  value: Record<string, unknown>,
  ...keys: string[]
): string | null {
  for (const key of keys) {
    const field = value[key];
    if (field === undefined || field === null) continue;
    const text = String(field).trim();
    if (text) return text;
  }
  return null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  const strings: string[] = [];
  for (const value of values.flat()) {
    const text = stringValue(value);
    if (text) strings.push(text);
  }
  return [...new Set(strings)];
}

function stringValue(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}
