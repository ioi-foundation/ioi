import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_USAGE_METER_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-usage-meter-control.v1" as const;
export const RUNTIME_USAGE_METER_WORKFLOW_NODE_ID = "runtime.usage-meter" as const;
export const RUNTIME_USAGE_METER_SOURCE = "react_flow" as const;
export const RUNTIME_USAGE_METER_SOURCE_EVENT_KIND =
  "RuntimeUsageTelemetry.Read" as const;
export const RUNTIME_USAGE_METER_COMPONENT_KIND = "usage_telemetry" as const;
export const RUNTIME_USAGE_METER_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.usage-telemetry.v1" as const;

export type RuntimeUsageMeterScope = "run" | "thread" | "workflow";

export interface RuntimeUsageMeterControlMetadata {
  source: typeof RUNTIME_USAGE_METER_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_USAGE_METER_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_USAGE_METER_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_USAGE_METER_COMPONENT_KIND;
  componentKind: typeof RUNTIME_USAGE_METER_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_USAGE_METER_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_USAGE_METER_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  usage_meter_scope: RuntimeUsageMeterScope;
  usageMeterScope: RuntimeUsageMeterScope;
  simulation_mode: boolean;
  simulationMode: boolean;
}

export interface RuntimeUsageMeterControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_USAGE_METER_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_usage_meter";
  scope: RuntimeUsageMeterScope;
  nodeId: string | null;
  threadId: string | null;
  runId: string | null;
  endpoint: string;
  method: "GET";
  body: null;
  metadata: RuntimeUsageMeterControlMetadata;
}

export interface RuntimeUsageMeterControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  scope?: string | null;
  scopeField?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  runId?: string | null;
  runIdField?: string | null;
  endpoint?: string | null;
  groupBy?: string | null;
  simulationMode?: boolean | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeUsageMeterWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeUsageMeterControlRequest(
  params: RuntimeUsageMeterControlRequestInput,
): RuntimeUsageMeterControlRequest {
  const scope = runtimeUsageMeterScope(
    cleanString(params.scope) ??
      stringAtPath(params.input, params.scopeField ?? "usageScope") ??
      stringAtPath(params.input, "usage_scope"),
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
    throw new Error("runtime_usage_meter thread scope needs a threadId input.");
  }
  if (scope === "run" && !runId) {
    throw new Error("runtime_usage_meter run scope needs a runId input.");
  }

  const workflowNodeId =
    cleanString(params.workflowNodeId) ?? RUNTIME_USAGE_METER_WORKFLOW_NODE_ID;
  const workflowGraphId = cleanString(params.workflowGraphId);
  const simulationMode = params.simulationMode !== false;
  const metadata = usageMeterMetadata({
    actor: cleanString(params.actor) ?? "operator",
    workflowGraphId,
    workflowNodeId,
    scope,
    simulationMode,
  });
  const endpoint = usageMeterEndpoint({
    scope,
    threadId,
    runId,
    endpoint: cleanString(params.endpoint),
    groupBy: cleanString(params.groupBy),
    metadata,
  });

  return {
    schemaVersion: WORKFLOW_RUNTIME_USAGE_METER_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_usage_meter",
    scope,
    nodeId: cleanString(params.nodeId),
    threadId,
    runId,
    endpoint,
    method: "GET",
    body: null,
    metadata,
  };
}

export function createRuntimeUsageMeterControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeUsageMeterWorkflowNodeOptions = {},
): RuntimeUsageMeterControlRequest {
  const logic = usageMeterWorkflowNodeLogic(node);
  return createRuntimeUsageMeterControlRequest({
    nodeId: node.id,
    input,
    scope: cleanString(logic.runtimeUsageMeterScope),
    scopeField: cleanString(logic.runtimeUsageMeterScopeField),
    threadId: cleanString(logic.runtimeUsageMeterThreadId),
    threadIdField: cleanString(logic.runtimeUsageMeterThreadIdField) ?? "threadId",
    runId: cleanString(logic.runtimeUsageMeterRunId),
    runIdField: cleanString(logic.runtimeUsageMeterRunIdField) ?? "runId",
    endpoint: cleanString(logic.runtimeUsageMeterEndpoint),
    groupBy: cleanString(logic.runtimeUsageMeterGroupBy),
    simulationMode:
      typeof logic.runtimeUsageMeterSimulationMode === "boolean"
        ? logic.runtimeUsageMeterSimulationMode
        : null,
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeUsageMeterWorkflowNodeId) ??
      RUNTIME_USAGE_METER_WORKFLOW_NODE_ID,
    actor: cleanString(options.actor) ?? cleanString(logic.runtimeUsageMeterActor),
  });
}

function usageMeterMetadata({
  actor,
  workflowGraphId,
  workflowNodeId,
  scope,
  simulationMode,
}: {
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  scope: RuntimeUsageMeterScope;
  simulationMode: boolean;
}): RuntimeUsageMeterControlMetadata {
  return {
    source: RUNTIME_USAGE_METER_SOURCE,
    actor,
    event_kind: RUNTIME_USAGE_METER_SOURCE_EVENT_KIND,
    eventKind: RUNTIME_USAGE_METER_SOURCE_EVENT_KIND,
    component_kind: RUNTIME_USAGE_METER_COMPONENT_KIND,
    componentKind: RUNTIME_USAGE_METER_COMPONENT_KIND,
    payload_schema_version: RUNTIME_USAGE_METER_PAYLOAD_SCHEMA_VERSION,
    payloadSchemaVersion: RUNTIME_USAGE_METER_PAYLOAD_SCHEMA_VERSION,
    workflow_graph_id: workflowGraphId,
    workflowGraphId,
    workflow_node_id: workflowNodeId,
    workflowNodeId,
    usage_meter_scope: scope,
    usageMeterScope: scope,
    simulation_mode: simulationMode,
    simulationMode,
  };
}

function usageMeterEndpoint({
  scope,
  threadId,
  runId,
  endpoint,
  groupBy,
  metadata,
}: {
  scope: RuntimeUsageMeterScope;
  threadId: string | null;
  runId: string | null;
  endpoint: string | null;
  groupBy: string | null;
  metadata: RuntimeUsageMeterControlMetadata;
}): string {
  const template =
    endpoint ??
    (scope === "run"
      ? "/v1/runs/{runId}/usage"
      : scope === "thread"
        ? "/v1/threads/{threadId}/usage"
        : "/v1/usage");
  const base = endpointFromTemplate(template, {
    threadId: threadId ?? "",
    runId: runId ?? "",
  });
  return withQuery(base, {
    source: metadata.source,
    actor: metadata.actor,
    event_kind: metadata.event_kind,
    component_kind: metadata.component_kind,
    payload_schema_version: metadata.payload_schema_version,
    workflow_graph_id: metadata.workflow_graph_id,
    workflow_node_id: metadata.workflow_node_id,
    usage_meter_scope: metadata.usage_meter_scope,
    simulation_mode: metadata.simulation_mode,
    group_by: scope === "workflow" ? groupBy ?? "thread" : null,
  });
}

function usageMeterWorkflowNodeLogic(
  node: Pick<Node, "type" | "config">,
): NodeLogic {
  if (node.type !== "runtime_usage_meter") {
    throw new Error(`Expected runtime_usage_meter node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function runtimeUsageMeterScope(value: string | null): RuntimeUsageMeterScope {
  if (value === "run" || value === "workflow") return value;
  return "thread";
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

function withQuery(route: string, values: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  if (!query) return route;
  return route.includes("?") ? `${route}&${query}` : `${route}?${query}`;
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
