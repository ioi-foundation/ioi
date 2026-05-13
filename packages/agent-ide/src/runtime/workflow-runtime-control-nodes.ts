import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-thread-fork-control.v1" as const;
export const RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID = "runtime.thread-fork" as const;
export const RUNTIME_THREAD_FORK_COMPONENT_KIND = "thread_fork" as const;
export const RUNTIME_THREAD_FORK_SOURCE = "react_flow" as const;
export const RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND = "OperatorControl.Fork" as const;
export const RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.thread-fork.v1" as const;
export const WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-operator-interrupt-control.v1" as const;
export const RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID =
  "runtime.operator-interrupt" as const;
export const RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND = "operator_control" as const;
export const RUNTIME_OPERATOR_INTERRUPT_SOURCE = "react_flow" as const;
export const RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND =
  "OperatorControl.Interrupt" as const;
export const RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.operator-control.v1" as const;
export const WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-operator-steer-control.v1" as const;
export const RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID =
  "runtime.operator-steer" as const;
export const RUNTIME_OPERATOR_STEER_COMPONENT_KIND = "operator_control" as const;
export const RUNTIME_OPERATOR_STEER_SOURCE = "react_flow" as const;
export const RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND =
  "OperatorControl.Steer" as const;
export const RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.operator-control.v1" as const;

export interface RuntimeThreadForkControlRequestBody {
  reason: string;
  source: typeof RUNTIME_THREAD_FORK_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_THREAD_FORK_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeThreadForkControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_thread_fork";
  nodeId: string | null;
  threadId: string;
  endpoint: string;
  body: RuntimeThreadForkControlRequestBody;
}

export interface RuntimeThreadForkControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeThreadForkWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorInterruptControlRequestBody {
  reason: string;
  source: typeof RUNTIME_OPERATOR_INTERRUPT_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeOperatorInterruptControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_operator_interrupt";
  nodeId: string | null;
  threadId: string;
  turnId: string;
  endpoint: string;
  body: RuntimeOperatorInterruptControlRequestBody;
}

export interface RuntimeOperatorInterruptControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorInterruptWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorSteerControlRequestBody {
  guidance: string;
  source: typeof RUNTIME_OPERATOR_STEER_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_OPERATOR_STEER_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeOperatorSteerControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_operator_steer";
  nodeId: string | null;
  threadId: string;
  turnId: string;
  endpoint: string;
  body: RuntimeOperatorSteerControlRequestBody;
}

export interface RuntimeOperatorSteerControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  guidance?: string | null;
  guidanceField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeOperatorSteerWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeThreadForkControlRequest(
  params: RuntimeThreadForkControlRequestInput,
): RuntimeThreadForkControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_thread_fork nodes need a threadId input before dispatch.");
  }

  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Fork thread from React Flow workflow control.";
  const workflowNodeId =
    cleanString(params.workflowNodeId) ?? RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID;
  const workflowGraphId = cleanString(params.workflowGraphId);
  const endpointTemplate =
    cleanString(params.endpoint) ?? "/v1/threads/{threadId}/fork";
  const endpoint = endpointFromTemplate(endpointTemplate, { threadId });

  return {
    schemaVersion: WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_thread_fork",
    nodeId: cleanString(params.nodeId),
    threadId,
    endpoint,
    body: {
      reason,
      source: RUNTIME_THREAD_FORK_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      workflowGraphId,
      workflowNodeId,
      eventKind: RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_THREAD_FORK_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION,
    },
  };
}

export function createRuntimeOperatorInterruptControlRequest(
  params: RuntimeOperatorInterruptControlRequestInput,
): RuntimeOperatorInterruptControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_operator_interrupt nodes need a threadId input before dispatch.");
  }

  const turnId =
    cleanString(params.turnId) ??
    stringAtPath(params.input, params.turnIdField ?? "turnId") ??
    stringAtPath(params.input, "turn_id");
  if (!turnId) {
    throw new Error("runtime_operator_interrupt nodes need a turnId input before dispatch.");
  }

  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Interrupt turn from React Flow workflow control.";
  const workflowNodeId =
    cleanString(params.workflowNodeId) ?? RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID;
  const workflowGraphId = cleanString(params.workflowGraphId);
  const endpointTemplate =
    cleanString(params.endpoint) ??
    "/v1/threads/{threadId}/turns/{turnId}/interrupt";
  const endpoint = endpointFromTemplate(endpointTemplate, { threadId, turnId });

  return {
    schemaVersion: WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_operator_interrupt",
    nodeId: cleanString(params.nodeId),
    threadId,
    turnId,
    endpoint,
    body: {
      reason,
      source: RUNTIME_OPERATOR_INTERRUPT_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      workflowGraphId,
      workflowNodeId,
      eventKind: RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION,
    },
  };
}

export function createRuntimeOperatorSteerControlRequest(
  params: RuntimeOperatorSteerControlRequestInput,
): RuntimeOperatorSteerControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_operator_steer nodes need a threadId input before dispatch.");
  }

  const turnId =
    cleanString(params.turnId) ??
    stringAtPath(params.input, params.turnIdField ?? "turnId") ??
    stringAtPath(params.input, "turn_id");
  if (!turnId) {
    throw new Error("runtime_operator_steer nodes need a turnId input before dispatch.");
  }

  const guidance =
    stringAtPath(params.input, params.guidanceField ?? "") ??
    cleanString(params.guidance) ??
    "Steer turn from React Flow workflow control.";
  const workflowNodeId =
    cleanString(params.workflowNodeId) ?? RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID;
  const workflowGraphId = cleanString(params.workflowGraphId);
  const endpointTemplate =
    cleanString(params.endpoint) ?? "/v1/threads/{threadId}/turns/{turnId}/steer";
  const endpoint = endpointFromTemplate(endpointTemplate, { threadId, turnId });

  return {
    schemaVersion: WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_operator_steer",
    nodeId: cleanString(params.nodeId),
    threadId,
    turnId,
    endpoint,
    body: {
      guidance,
      source: RUNTIME_OPERATOR_STEER_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      workflowGraphId,
      workflowNodeId,
      eventKind: RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_OPERATOR_STEER_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION,
    },
  };
}

export function createRuntimeThreadForkControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeThreadForkWorkflowNodeOptions = {},
): RuntimeThreadForkControlRequest {
  if (node.type !== "runtime_thread_fork") {
    throw new Error(`Expected runtime_thread_fork node, received ${node.type}.`);
  }
  const logic: NodeLogic = node.config?.logic ?? {};
  return createRuntimeThreadForkControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeThreadForkThreadId),
    threadIdField: cleanString(logic.runtimeThreadForkThreadIdField) ?? "threadId",
    reason: cleanString(logic.runtimeThreadForkReason),
    reasonField: cleanString(logic.runtimeThreadForkReasonField),
    endpoint: cleanString(logic.runtimeThreadForkEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeThreadForkWorkflowNodeId) ??
      RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
    actor:
      cleanString(options.actor) ??
      cleanString(logic.runtimeThreadForkActor) ??
      "operator",
  });
}

export function createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeOperatorInterruptWorkflowNodeOptions = {},
): RuntimeOperatorInterruptControlRequest {
  if (node.type !== "runtime_operator_interrupt") {
    throw new Error(`Expected runtime_operator_interrupt node, received ${node.type}.`);
  }
  const logic: NodeLogic = node.config?.logic ?? {};
  return createRuntimeOperatorInterruptControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeOperatorInterruptThreadId),
    threadIdField:
      cleanString(logic.runtimeOperatorInterruptThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeOperatorInterruptTurnId),
    turnIdField: cleanString(logic.runtimeOperatorInterruptTurnIdField) ?? "turnId",
    reason: cleanString(logic.runtimeOperatorInterruptReason),
    reasonField: cleanString(logic.runtimeOperatorInterruptReasonField),
    endpoint: cleanString(logic.runtimeOperatorInterruptEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeOperatorInterruptWorkflowNodeId) ??
      RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
    actor:
      cleanString(options.actor) ??
      cleanString(logic.runtimeOperatorInterruptActor) ??
      "operator",
  });
}

export function createRuntimeOperatorSteerControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeOperatorSteerWorkflowNodeOptions = {},
): RuntimeOperatorSteerControlRequest {
  if (node.type !== "runtime_operator_steer") {
    throw new Error(`Expected runtime_operator_steer node, received ${node.type}.`);
  }
  const logic: NodeLogic = node.config?.logic ?? {};
  return createRuntimeOperatorSteerControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeOperatorSteerThreadId),
    threadIdField: cleanString(logic.runtimeOperatorSteerThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeOperatorSteerTurnId),
    turnIdField: cleanString(logic.runtimeOperatorSteerTurnIdField) ?? "turnId",
    guidance: cleanString(logic.runtimeOperatorSteerGuidance),
    guidanceField: cleanString(logic.runtimeOperatorSteerGuidanceField),
    endpoint: cleanString(logic.runtimeOperatorSteerEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeOperatorSteerWorkflowNodeId) ??
      RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
    actor:
      cleanString(options.actor) ??
      cleanString(logic.runtimeOperatorSteerActor) ??
      "operator",
  });
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : null;
}

function stringAtPath(value: unknown, path: string | null | undefined): string | null {
  const normalizedPath = cleanString(path);
  if (!normalizedPath) return null;
  const found = valueAtPath(value, normalizedPath);
  return cleanString(found);
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

function valueAtPath(value: unknown, path: string): unknown {
  let current = value;
  for (const segment of path.split(".").filter(Boolean)) {
    if (current === null || current === undefined) return undefined;
    if (segment === "[]") {
      current = Array.isArray(current) ? current[0] : undefined;
      continue;
    }
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}
