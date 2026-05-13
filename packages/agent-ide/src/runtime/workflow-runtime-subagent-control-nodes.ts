import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_SUBAGENT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-subagent-control.v1" as const;
export const RUNTIME_SUBAGENT_SOURCE = "react_flow" as const;
export const RUNTIME_SUBAGENT_COMPONENT_KIND = "subagent_lifecycle" as const;
export const RUNTIME_SUBAGENT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.subagent-manager-control.v1" as const;
export const RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT = [
  "SUMMARY",
  "CHANGES",
  "EVIDENCE",
  "RISKS",
  "BLOCKERS",
  "RECEIPTS",
] as const;

export type RuntimeSubagentOperation =
  | "list"
  | "spawn"
  | "wait"
  | "result"
  | "send_input"
  | "cancel"
  | "propagate_cancel"
  | "resume"
  | "assign";

export const RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION = {
  list: "OperatorControl.SubagentList",
  spawn: "OperatorControl.SubagentSpawn",
  wait: "OperatorControl.SubagentWait",
  result: "OperatorControl.SubagentResult",
  send_input: "OperatorControl.SubagentSendInput",
  cancel: "OperatorControl.SubagentCancel",
  propagate_cancel: "OperatorControl.SubagentCancel",
  resume: "OperatorControl.SubagentResume",
  assign: "OperatorControl.SubagentAssign",
} as const satisfies Record<RuntimeSubagentOperation, string>;

export interface RuntimeSubagentControlRequestBody {
  source: typeof RUNTIME_SUBAGENT_SOURCE;
  actor: string;
  event_kind: string;
  eventKind: string;
  component_kind: typeof RUNTIME_SUBAGENT_COMPONENT_KIND;
  componentKind: typeof RUNTIME_SUBAGENT_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_SUBAGENT_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_SUBAGENT_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  operation: RuntimeSubagentOperation;
  parent_thread_id: string;
  parentThreadId: string;
  parent_turn_id: string | null;
  parentTurnId: string | null;
  agent_id: string | null;
  agentId: string | null;
  subagent_id: string | null;
  subagentId: string | null;
  target_agent_id: string | null;
  targetAgentId: string | null;
  role: string;
  prompt: string;
  message: string;
  reason: string | null;
  cancellation_reason: string | null;
  cancellationReason: string | null;
  fork_context: boolean;
  forkContext: boolean;
  context_mode: "fresh" | "forked";
  contextMode: "fresh" | "forked";
  model_route_id: string | null;
  modelRouteId: string | null;
  tool_pack: string | null;
  toolPack: string | null;
  max_concurrency: number | null;
  maxConcurrency: number | null;
  wait_timeout_ms: number | null;
  waitTimeoutMs: number | null;
  budget: Record<string, unknown> | null;
  output_contract: unknown[];
  outputContract: unknown[];
  merge_policy: string;
  mergePolicy: string;
  cancellation_inheritance: string;
  cancellationInheritance: string;
}

export interface RuntimeSubagentControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_SUBAGENT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_subagent";
  operation: RuntimeSubagentOperation;
  nodeId: string | null;
  threadId: string;
  subagentId: string | null;
  endpoint: string;
  method: "GET" | "POST";
  body: RuntimeSubagentControlRequestBody | null;
}

export interface RuntimeSubagentControlRequestInput {
  nodeId?: string | null;
  operation: RuntimeSubagentOperation;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  parentTurnId?: string | null;
  parentTurnIdField?: string | null;
  subagentId?: string | null;
  subagentIdField?: string | null;
  role?: string | null;
  roleField?: string | null;
  prompt?: string | null;
  promptField?: string | null;
  message?: string | null;
  messageField?: string | null;
  forkContext?: boolean | null;
  modelRouteId?: string | null;
  modelRouteIdField?: string | null;
  toolPack?: string | null;
  toolPackField?: string | null;
  maxConcurrency?: number | null;
  waitTimeoutMs?: number | null;
  budgetJson?: string | null;
  budget?: Record<string, unknown> | null;
  outputContractJson?: string | null;
  outputContract?: unknown[] | null;
  mergePolicy?: string | null;
  cancellationInheritance?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeSubagentWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeSubagentControlRequest(
  params: RuntimeSubagentControlRequestInput,
): RuntimeSubagentControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_subagent nodes need a parent threadId input before dispatch.");
  }

  const subagentId =
    cleanString(params.subagentId) ??
    stringAtPath(params.input, params.subagentIdField ?? "subagentId") ??
    stringAtPath(params.input, "agentId") ??
    stringAtPath(params.input, "agent_id");
  if (needsSubagentId(params.operation) && !subagentId) {
    throw new Error(
      `runtime_subagent ${params.operation} nodes need a subagentId or agentId input.`,
    );
  }

  const parentTurnId =
    cleanString(params.parentTurnId) ??
    stringAtPath(params.input, params.parentTurnIdField ?? "parentTurnId") ??
    stringAtPath(params.input, "parent_turn_id") ??
    null;
  const role =
    cleanString(params.role) ??
    stringAtPath(params.input, params.roleField ?? "role") ??
    "general";
  const prompt =
    cleanString(params.prompt) ??
    stringAtPath(params.input, params.promptField ?? "prompt") ??
    "";
  if (params.operation === "spawn" && !prompt) {
    throw new Error("runtime_subagent spawn nodes need a prompt.");
  }
  const message =
    cleanString(params.message) ??
    stringAtPath(params.input, params.messageField ?? "message") ??
    prompt;
  const modelRouteId =
    cleanString(params.modelRouteId) ??
    stringAtPath(params.input, params.modelRouteIdField ?? "modelRouteId") ??
    stringAtPath(params.input, "model_route_id") ??
    null;
  const toolPack =
    cleanString(params.toolPack) ??
    stringAtPath(params.input, params.toolPackField ?? "toolPack") ??
    stringAtPath(params.input, "tool_pack") ??
    null;
  const forkContext = params.forkContext === true;
  const outputContract =
    params.outputContract ??
    parseJsonArray(params.outputContractJson, [
      ...RUNTIME_SUBAGENT_DEFAULT_OUTPUT_CONTRACT,
    ]);
  const budget = params.budget ?? parseJsonObject(params.budgetJson, null);
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    `runtime.subagent.${params.operation}.${safeId(role)}`;
  const method = params.operation === "list" || params.operation === "result" ? "GET" : "POST";
  const endpoint = subagentEndpoint(params.operation, threadId, subagentId);

  if (method === "GET") {
    return {
      schemaVersion: WORKFLOW_RUNTIME_SUBAGENT_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_subagent",
      operation: params.operation,
      nodeId: params.nodeId ?? null,
      threadId,
      subagentId: subagentId ?? null,
      endpoint: withQuery(endpoint, {
        source: RUNTIME_SUBAGENT_SOURCE,
        role: params.operation === "list" ? role : null,
        workflow_graph_id: cleanString(params.workflowGraphId),
        workflow_node_id: workflowNodeId,
      }),
      method,
      body: null,
    };
  }

  return {
    schemaVersion: WORKFLOW_RUNTIME_SUBAGENT_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_subagent",
    operation: params.operation,
    nodeId: params.nodeId ?? null,
    threadId,
    subagentId: subagentId ?? null,
    endpoint,
    method,
    body: {
      source: RUNTIME_SUBAGENT_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      event_kind: RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION[params.operation],
      eventKind: RUNTIME_SUBAGENT_EVENT_KIND_BY_OPERATION[params.operation],
      component_kind: RUNTIME_SUBAGENT_COMPONENT_KIND,
      componentKind: RUNTIME_SUBAGENT_COMPONENT_KIND,
      payload_schema_version: RUNTIME_SUBAGENT_PAYLOAD_SCHEMA_VERSION,
      payloadSchemaVersion: RUNTIME_SUBAGENT_PAYLOAD_SCHEMA_VERSION,
      workflow_graph_id: cleanString(params.workflowGraphId) ?? null,
      workflowGraphId: cleanString(params.workflowGraphId) ?? null,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      operation: params.operation,
      parent_thread_id: threadId,
      parentThreadId: threadId,
      parent_turn_id: parentTurnId,
      parentTurnId,
      agent_id: subagentId ?? null,
      agentId: subagentId ?? null,
      subagent_id: subagentId ?? null,
      subagentId: subagentId ?? null,
      target_agent_id: subagentId ?? null,
      targetAgentId: subagentId ?? null,
      role,
      prompt,
      message,
      reason:
        params.operation === "cancel" || params.operation === "propagate_cancel"
          ? message || null
          : null,
      cancellation_reason:
        params.operation === "cancel" || params.operation === "propagate_cancel"
          ? message || null
          : null,
      cancellationReason:
        params.operation === "cancel" || params.operation === "propagate_cancel"
          ? message || null
          : null,
      fork_context: forkContext,
      forkContext,
      context_mode: forkContext ? "forked" : "fresh",
      contextMode: forkContext ? "forked" : "fresh",
      model_route_id: modelRouteId,
      modelRouteId,
      tool_pack: toolPack,
      toolPack,
      max_concurrency: numberOrNull(params.maxConcurrency),
      maxConcurrency: numberOrNull(params.maxConcurrency),
      wait_timeout_ms: numberOrNull(params.waitTimeoutMs),
      waitTimeoutMs: numberOrNull(params.waitTimeoutMs),
      budget,
      output_contract: outputContract,
      outputContract,
      merge_policy: cleanString(params.mergePolicy) ?? "manual",
      mergePolicy: cleanString(params.mergePolicy) ?? "manual",
      cancellation_inheritance: cleanString(params.cancellationInheritance) ?? "propagate",
      cancellationInheritance: cleanString(params.cancellationInheritance) ?? "propagate",
    },
  };
}

export function createRuntimeSubagentControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeSubagentWorkflowNodeOptions = {},
): RuntimeSubagentControlRequest {
  const logic = subagentWorkflowNodeLogic(node);
  return createRuntimeSubagentControlRequest({
    nodeId: node.id,
    input,
    operation: operationForStateOperation(logic.stateOperation),
    threadIdField: "threadId",
    parentTurnId: cleanString(logic.subagentParentTurnId),
    subagentId: cleanString(logic.subagentId),
    role: cleanString(logic.subagentRole),
    prompt: cleanString(logic.subagentPrompt),
    message: cleanString(logic.subagentInput),
    forkContext: logic.subagentForkContext === true,
    modelRouteId: cleanString(logic.subagentModelRoute),
    toolPack: cleanString(logic.subagentToolPack),
    maxConcurrency:
      typeof logic.subagentMaxConcurrency === "number"
        ? logic.subagentMaxConcurrency
        : null,
    waitTimeoutMs:
      typeof logic.subagentWaitTimeoutMs === "number"
        ? logic.subagentWaitTimeoutMs
        : null,
    budgetJson: cleanString(logic.subagentBudgetJson),
    outputContractJson: cleanString(logic.subagentOutputContractJson),
    mergePolicy: cleanString(logic.subagentMergePolicy),
    cancellationInheritance: cleanString(logic.subagentCancellationInheritance),
    workflowGraphId: cleanString(options.workflowGraphId),
    actor: cleanString(options.actor),
  });
}

function operationForStateOperation(
  stateOperation: NodeLogic["stateOperation"],
): RuntimeSubagentOperation {
  if (stateOperation === "subagent_list") return "list";
  if (stateOperation === "subagent_spawn") return "spawn";
  if (stateOperation === "subagent_wait") return "wait";
  if (stateOperation === "subagent_result") return "result";
  if (stateOperation === "subagent_send_input") return "send_input";
  if (stateOperation === "subagent_cancel") return "cancel";
  if (stateOperation === "subagent_cancel_propagation") return "propagate_cancel";
  if (stateOperation === "subagent_resume") return "resume";
  if (stateOperation === "subagent_assign") return "assign";
  throw new Error(
    `Expected subagent state operation, received ${String(stateOperation ?? "unknown")}.`,
  );
}

function subagentWorkflowNodeLogic(node: Pick<Node, "type" | "config">): NodeLogic {
  if (node.type !== "state") {
    throw new Error(`Expected state node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function subagentEndpoint(
  operation: RuntimeSubagentOperation,
  threadId: string,
  subagentId: string | null | undefined,
): string {
  const threadRoute = `/v1/threads/${encodeSegment(threadId)}/subagents`;
  if (operation === "list" || operation === "spawn") return threadRoute;
  if (operation === "propagate_cancel") return `${threadRoute}/cancel`;
  const targetRoute = `${threadRoute}/${encodeSegment(subagentId ?? "")}`;
  if (operation === "wait") return `${targetRoute}/wait`;
  if (operation === "result") return `${targetRoute}/result`;
  if (operation === "send_input") return `${targetRoute}/input`;
  if (operation === "cancel") return `${targetRoute}/cancel`;
  if (operation === "resume") return `${targetRoute}/resume`;
  return `${targetRoute}/assign`;
}

function needsSubagentId(operation: RuntimeSubagentOperation): boolean {
  return operation !== "list" && operation !== "spawn" && operation !== "propagate_cancel";
}

function parseJsonObject(
  text: string | null | undefined,
  fallback: Record<string, unknown> | null,
): Record<string, unknown> | null {
  const clean = cleanString(text);
  if (!clean) return fallback;
  const parsed = JSON.parse(clean);
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    return parsed as Record<string, unknown>;
  }
  throw new Error("Subagent budget JSON must parse to an object.");
}

function parseJsonArray(text: string | null | undefined, fallback: unknown[]): unknown[] {
  const clean = cleanString(text);
  if (!clean) return fallback;
  const parsed = JSON.parse(clean);
  if (Array.isArray(parsed)) return parsed;
  throw new Error("Subagent output contract JSON must parse to an array.");
}

function withQuery(route: string, values: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  return query ? `${route}?${query}` : route;
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

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean ? clean : null;
}

function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "subagent"
  );
}
