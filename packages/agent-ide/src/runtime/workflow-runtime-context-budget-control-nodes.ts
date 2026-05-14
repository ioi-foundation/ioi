import type { Node, NodeLogic } from "../types/graph";
import {
  workflowRuntimeTelemetrySummaryToUsageTelemetry,
  type WorkflowRuntimeTelemetrySummary,
} from "./workflow-runtime-telemetry-summary";

export const WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-context-budget-control.v1" as const;
export const RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID =
  "runtime.context-budget" as const;
export const RUNTIME_CONTEXT_BUDGET_SOURCE = "react_flow" as const;
export const RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND =
  "RuntimeContextBudget.Evaluate" as const;
export const RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND = "context_budget" as const;
export const RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.context-budget-policy.v1" as const;

export type RuntimeContextBudgetScope = "run" | "thread" | "workflow";
export type RuntimeContextBudgetMode = "simulate" | "warn" | "block";

export interface RuntimeContextBudgetControlRequestBody {
  schemaVersion: typeof WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION;
  source: typeof RUNTIME_CONTEXT_BUDGET_SOURCE;
  actor: string;
  eventKind: typeof RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND;
  event_kind: typeof RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND;
  component_kind: typeof RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION;
  payload_schema_version: typeof RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION;
  workflowGraphId: string | null;
  workflow_graph_id: string | null;
  workflowNodeId: string;
  workflow_node_id: string;
  scope: RuntimeContextBudgetScope;
  threadId: string | null;
  thread_id: string | null;
  runId: string | null;
  run_id: string | null;
  mode: RuntimeContextBudgetMode;
  simulationMode: boolean;
  simulation_mode: boolean;
  thresholds: {
    maxTotalTokens: number | null;
    max_total_tokens: number | null;
    maxCostUsd: number | null;
    max_cost_usd: number | null;
    maxContextPressure: number | null;
    max_context_pressure: number | null;
    warnAtRatio: number;
    warn_at_ratio: number;
  };
  usageTelemetry: unknown | null;
  usage_telemetry: unknown | null;
}

export interface RuntimeContextBudgetControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_context_budget";
  scope: RuntimeContextBudgetScope;
  nodeId: string | null;
  threadId: string | null;
  runId: string | null;
  endpoint: string;
  method: "POST";
  body: RuntimeContextBudgetControlRequestBody;
}

export interface RuntimeContextBudgetControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  scope?: string | null;
  scopeField?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  runId?: string | null;
  runIdField?: string | null;
  endpoint?: string | null;
  usageTelemetry?: unknown;
  usageTelemetryField?: string | null;
  runtimeTelemetrySummary?: WorkflowRuntimeTelemetrySummary | null;
  mode?: string | null;
  modeField?: string | null;
  maxTotalTokens?: number | string | null;
  maxTotalTokensField?: string | null;
  maxCostUsd?: number | string | null;
  maxCostUsdField?: string | null;
  maxContextPressure?: number | string | null;
  maxContextPressureField?: string | null;
  warnAtRatio?: number | string | null;
  warnAtRatioField?: string | null;
  simulationMode?: boolean | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeContextBudgetWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeContextBudgetControlRequest(
  params: RuntimeContextBudgetControlRequestInput,
): RuntimeContextBudgetControlRequest {
  const scope = runtimeContextBudgetScope(
    cleanString(params.scope) ??
      stringAtPath(params.input, params.scopeField ?? "usageScope") ??
      stringAtPath(params.input, "scope"),
  );
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id") ??
    null;
  const runId =
    cleanString(params.runId) ??
    stringAtPath(params.input, params.runIdField ?? "runId") ??
    stringAtPath(params.input, "run_id") ??
    null;

  if (scope === "thread" && !threadId) {
    throw new Error("runtime_context_budget thread scope needs a threadId input.");
  }
  if (scope === "run" && !runId) {
    throw new Error("runtime_context_budget run scope needs a runId input.");
  }

  const mode = runtimeContextBudgetMode(
    cleanString(params.mode) ??
      stringAtPath(params.input, params.modeField ?? "contextBudgetMode") ??
      stringAtPath(params.input, "mode"),
  );
  const workflowNodeId =
    cleanString(params.workflowNodeId) ?? RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID;
  const workflowGraphId = cleanString(params.workflowGraphId);
  const simulationMode = params.simulationMode !== false;
  const rawUsageTelemetry =
    params.usageTelemetry ??
    params.runtimeTelemetrySummary ??
    valueAtPath(params.input, params.usageTelemetryField ?? "runtimeUsageMeter") ??
    valueAtPath(params.input, "runtimeTelemetrySummary") ??
    valueAtPath(params.input, "runtime_telemetry_summary") ??
    valueAtPath(params.input, "usageTelemetry") ??
    valueAtPath(params.input, "usage_telemetry") ??
    null;
  const usageTelemetry =
    workflowRuntimeTelemetrySummaryToUsageTelemetry(rawUsageTelemetry) ??
    rawUsageTelemetry ??
    null;
  const thresholds = {
    maxTotalTokens: numberOption(
      params.maxTotalTokens,
      valueAtPath(params.input, params.maxTotalTokensField ?? "maxTotalTokens"),
      valueAtPath(params.input, "max_total_tokens"),
    ),
    maxCostUsd: numberOption(
      params.maxCostUsd,
      valueAtPath(params.input, params.maxCostUsdField ?? "maxCostUsd"),
      valueAtPath(params.input, "max_cost_usd"),
    ),
    maxContextPressure: numberOption(
      params.maxContextPressure,
      valueAtPath(
        params.input,
        params.maxContextPressureField ?? "maxContextPressure",
      ),
      valueAtPath(params.input, "max_context_pressure"),
    ),
    warnAtRatio:
      numberOption(
        params.warnAtRatio,
        valueAtPath(params.input, params.warnAtRatioField ?? "warnAtRatio"),
        valueAtPath(params.input, "warn_at_ratio"),
      ) ?? 0.8,
  };
  const body: RuntimeContextBudgetControlRequestBody = {
    schemaVersion: WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION,
    source: RUNTIME_CONTEXT_BUDGET_SOURCE,
    actor: cleanString(params.actor) ?? "operator",
    eventKind: RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND,
    event_kind: RUNTIME_CONTEXT_BUDGET_SOURCE_EVENT_KIND,
    componentKind: RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND,
    component_kind: RUNTIME_CONTEXT_BUDGET_COMPONENT_KIND,
    payloadSchemaVersion: RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION,
    payload_schema_version: RUNTIME_CONTEXT_BUDGET_PAYLOAD_SCHEMA_VERSION,
    workflowGraphId,
    workflow_graph_id: workflowGraphId,
    workflowNodeId,
    workflow_node_id: workflowNodeId,
    scope,
    threadId,
    thread_id: threadId,
    runId,
    run_id: runId,
    mode,
    simulationMode,
    simulation_mode: simulationMode,
    thresholds: {
      maxTotalTokens: thresholds.maxTotalTokens,
      max_total_tokens: thresholds.maxTotalTokens,
      maxCostUsd: thresholds.maxCostUsd,
      max_cost_usd: thresholds.maxCostUsd,
      maxContextPressure: thresholds.maxContextPressure,
      max_context_pressure: thresholds.maxContextPressure,
      warnAtRatio: thresholds.warnAtRatio,
      warn_at_ratio: thresholds.warnAtRatio,
    },
    usageTelemetry,
    usage_telemetry: usageTelemetry,
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_CONTEXT_BUDGET_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_context_budget",
    scope,
    nodeId: cleanString(params.nodeId),
    threadId,
    runId,
    endpoint: contextBudgetEndpoint({
      scope,
      threadId,
      runId,
      endpoint: cleanString(params.endpoint),
    }),
    method: "POST",
    body,
  };
}

export function createRuntimeContextBudgetControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeContextBudgetWorkflowNodeOptions = {},
): RuntimeContextBudgetControlRequest {
  const logic = contextBudgetWorkflowNodeLogic(node);
  return createRuntimeContextBudgetControlRequest({
    nodeId: node.id,
    input,
    scope: cleanString(logic.runtimeContextBudgetScope),
    scopeField: cleanString(logic.runtimeContextBudgetScopeField),
    threadId: cleanString(logic.runtimeContextBudgetThreadId),
    threadIdField: cleanString(logic.runtimeContextBudgetThreadIdField) ?? "threadId",
    runId: cleanString(logic.runtimeContextBudgetRunId),
    runIdField: cleanString(logic.runtimeContextBudgetRunIdField) ?? "runId",
    endpoint: cleanString(logic.runtimeContextBudgetEndpoint),
    usageTelemetry: logic.runtimeContextBudget,
    usageTelemetryField:
      cleanString(logic.runtimeContextBudgetUsageField) ?? "runtimeUsageMeter",
    mode: cleanString(logic.runtimeContextBudgetMode),
    modeField: cleanString(logic.runtimeContextBudgetModeField),
    maxTotalTokens: logic.runtimeContextBudgetMaxTotalTokens,
    maxTotalTokensField: cleanString(logic.runtimeContextBudgetMaxTotalTokensField),
    maxCostUsd: logic.runtimeContextBudgetMaxCostUsd,
    maxCostUsdField: cleanString(logic.runtimeContextBudgetMaxCostUsdField),
    maxContextPressure: logic.runtimeContextBudgetMaxContextPressure,
    maxContextPressureField: cleanString(
      logic.runtimeContextBudgetMaxContextPressureField,
    ),
    warnAtRatio: logic.runtimeContextBudgetWarnAtRatio,
    warnAtRatioField: cleanString(logic.runtimeContextBudgetWarnAtRatioField),
    simulationMode:
      typeof logic.runtimeContextBudgetSimulationMode === "boolean"
        ? logic.runtimeContextBudgetSimulationMode
        : null,
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeContextBudgetWorkflowNodeId) ??
      RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID,
    actor: cleanString(options.actor) ?? cleanString(logic.runtimeContextBudgetActor),
  });
}

function contextBudgetEndpoint({
  scope,
  threadId,
  runId,
  endpoint,
}: {
  scope: RuntimeContextBudgetScope;
  threadId: string | null;
  runId: string | null;
  endpoint: string | null;
}): string {
  const template =
    endpoint ??
    (scope === "run"
      ? "/v1/runs/{runId}/context-budget"
      : scope === "thread"
        ? "/v1/threads/{threadId}/context-budget"
        : "/v1/context-budget");
  return endpointFromTemplate(template, {
    threadId: threadId ?? "",
    runId: runId ?? "",
  });
}

function contextBudgetWorkflowNodeLogic(
  node: Pick<Node, "type" | "config">,
): NodeLogic {
  if (node.type !== "runtime_context_budget") {
    throw new Error(`Expected runtime_context_budget node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function runtimeContextBudgetScope(value: string | null): RuntimeContextBudgetScope {
  if (value === "run" || value === "workflow") return value;
  return "thread";
}

function runtimeContextBudgetMode(value: string | null): RuntimeContextBudgetMode {
  if (value === "warn" || value === "block") return value;
  return "simulate";
}

function endpointFromTemplate(
  template: string,
  values: Record<string, string>,
): string {
  return Object.entries(values).reduce(
    (current, [key, value]) =>
      current.replace(new RegExp(`\\{${key}\\}`, "g"), encodeURIComponent(value)),
    template,
  );
}

function stringAtPath(input: unknown, path: string | null | undefined): string | null {
  const value = valueAtPath(input, path);
  return cleanString(value);
}

function valueAtPath(input: unknown, path: string | null | undefined): unknown {
  const clean = cleanString(path);
  if (!clean || input === null || typeof input !== "object") return null;
  return clean.split(".").reduce<unknown>((current, segment) => {
    if (current === null || typeof current !== "object") return null;
    return (current as Record<string, unknown>)[segment];
  }, input);
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean ? clean : null;
}

function numberOption(...values: unknown[]): number | null {
  for (const value of values) {
    const parsed =
      typeof value === "number"
        ? value
        : typeof value === "string" && value.trim()
          ? Number(value)
          : null;
    if (typeof parsed === "number" && Number.isFinite(parsed)) return parsed;
  }
  return null;
}
