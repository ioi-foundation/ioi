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
export const WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-context-compact-control.v1" as const;
export const RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID =
  "runtime.context-compact" as const;
export const RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND = "context_compaction" as const;
export const RUNTIME_CONTEXT_COMPACT_SOURCE = "react_flow" as const;
export const RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND =
  "OperatorControl.Compact" as const;
export const RUNTIME_CONTEXT_COMPACT_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.context-compaction.v1" as const;

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

export interface RuntimeContextCompactControlRequestBody {
  reason: string;
  scope: string;
  turnId: string | null;
  source: typeof RUNTIME_CONTEXT_COMPACT_SOURCE;
  actor: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventKind: typeof RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND;
  componentKind: typeof RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND;
  payloadSchemaVersion: typeof RUNTIME_CONTEXT_COMPACT_PAYLOAD_SCHEMA_VERSION;
}

export interface RuntimeContextCompactControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_context_compact";
  nodeId: string | null;
  threadId: string;
  turnId: string | null;
  endpoint: string;
  body: RuntimeContextCompactControlRequestBody;
}

export interface RuntimeContextCompactControlRequestInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  reason?: string | null;
  reasonField?: string | null;
  scope?: string | null;
  scopeField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export interface RuntimeContextCompactWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

type RuntimeControlTurnIdMode = "none" | "required" | "optional";

interface RuntimeControlRequestEnvelope<
  SchemaVersion extends string,
  NodeType extends string,
  Source extends string,
  EventKind extends string,
  ComponentKind extends string,
  PayloadSchemaVersion extends string,
> {
  schemaVersion: SchemaVersion;
  nodeType: NodeType;
  nodeId: string | null;
  threadId: string;
  turnId: string | null;
  endpoint: string;
  metadata: {
    source: Source;
    actor: string;
    workflowGraphId: string | null;
    workflowNodeId: string;
    eventKind: EventKind;
    componentKind: ComponentKind;
    payloadSchemaVersion: PayloadSchemaVersion;
  };
}

interface RuntimeControlRequestEnvelopeConfig<
  SchemaVersion extends string,
  NodeType extends string,
  Source extends string,
  EventKind extends string,
  ComponentKind extends string,
  PayloadSchemaVersion extends string,
> {
  schemaVersion: SchemaVersion;
  nodeType: NodeType;
  source: Source;
  eventKind: EventKind;
  componentKind: ComponentKind;
  payloadSchemaVersion: PayloadSchemaVersion;
  defaultWorkflowNodeId: string;
  defaultEndpoint: string;
  turnIdMode: RuntimeControlTurnIdMode;
}

interface RuntimeControlRequestEnvelopeInput {
  nodeId?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  turnId?: string | null;
  turnIdField?: string | null;
  input?: unknown;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

export function createRuntimeThreadForkControlRequest(
  params: RuntimeThreadForkControlRequestInput,
): RuntimeThreadForkControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_thread_fork",
      source: RUNTIME_THREAD_FORK_SOURCE,
      eventKind: RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_THREAD_FORK_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/fork",
      turnIdMode: "none",
    },
    params,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Fork thread from React Flow workflow control.";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    endpoint: envelope.endpoint,
    body: {
      reason,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeOperatorInterruptControlRequest(
  params: RuntimeOperatorInterruptControlRequestInput,
): RuntimeOperatorInterruptControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_OPERATOR_INTERRUPT_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_operator_interrupt",
      source: RUNTIME_OPERATOR_INTERRUPT_SOURCE,
      eventKind: RUNTIME_OPERATOR_INTERRUPT_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_OPERATOR_INTERRUPT_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_OPERATOR_INTERRUPT_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_OPERATOR_INTERRUPT_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
      turnIdMode: "required",
    },
    params,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Interrupt turn from React Flow workflow control.";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: requiredTurnId(envelope),
    endpoint: envelope.endpoint,
    body: {
      reason,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeOperatorSteerControlRequest(
  params: RuntimeOperatorSteerControlRequestInput,
): RuntimeOperatorSteerControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_OPERATOR_STEER_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_operator_steer",
      source: RUNTIME_OPERATOR_STEER_SOURCE,
      eventKind: RUNTIME_OPERATOR_STEER_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_OPERATOR_STEER_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_OPERATOR_STEER_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_OPERATOR_STEER_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
      turnIdMode: "required",
    },
    params,
  );
  const guidance =
    stringAtPath(params.input, params.guidanceField ?? "") ??
    cleanString(params.guidance) ??
    "Steer turn from React Flow workflow control.";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: requiredTurnId(envelope),
    endpoint: envelope.endpoint,
    body: {
      guidance,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeContextCompactControlRequest(
  params: RuntimeContextCompactControlRequestInput,
): RuntimeContextCompactControlRequest {
  const envelope = createRuntimeControlRequestEnvelope(
    {
      schemaVersion: WORKFLOW_RUNTIME_CONTEXT_COMPACT_CONTROL_SCHEMA_VERSION,
      nodeType: "runtime_context_compact",
      source: RUNTIME_CONTEXT_COMPACT_SOURCE,
      eventKind: RUNTIME_CONTEXT_COMPACT_SOURCE_EVENT_KIND,
      componentKind: RUNTIME_CONTEXT_COMPACT_COMPONENT_KIND,
      payloadSchemaVersion: RUNTIME_CONTEXT_COMPACT_PAYLOAD_SCHEMA_VERSION,
      defaultWorkflowNodeId: RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
      defaultEndpoint: "/v1/threads/{threadId}/compact",
      turnIdMode: "optional",
    },
    params,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "Compact thread context from React Flow workflow control.";
  const scope =
    stringAtPath(params.input, params.scopeField ?? "") ??
    cleanString(params.scope) ??
    "thread";

  return {
    schemaVersion: envelope.schemaVersion,
    nodeType: envelope.nodeType,
    nodeId: envelope.nodeId,
    threadId: envelope.threadId,
    turnId: envelope.turnId,
    endpoint: envelope.endpoint,
    body: {
      reason,
      scope,
      turnId: envelope.turnId,
      ...envelope.metadata,
    },
  };
}

export function createRuntimeThreadForkControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeThreadForkWorkflowNodeOptions = {},
): RuntimeThreadForkControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_thread_fork");
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
    actor: runtimeControlWorkflowActor(options, logic, "runtimeThreadForkActor"),
  });
}

export function createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeOperatorInterruptWorkflowNodeOptions = {},
): RuntimeOperatorInterruptControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_operator_interrupt");
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
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeOperatorInterruptActor",
    ),
  });
}

export function createRuntimeOperatorSteerControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeOperatorSteerWorkflowNodeOptions = {},
): RuntimeOperatorSteerControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_operator_steer");
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
    actor: runtimeControlWorkflowActor(options, logic, "runtimeOperatorSteerActor"),
  });
}

export function createRuntimeContextCompactControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeContextCompactWorkflowNodeOptions = {},
): RuntimeContextCompactControlRequest {
  const logic = runtimeControlWorkflowNodeLogic(node, "runtime_context_compact");
  return createRuntimeContextCompactControlRequest({
    nodeId: node.id,
    input,
    threadId: cleanString(logic.runtimeContextCompactThreadId),
    threadIdField: cleanString(logic.runtimeContextCompactThreadIdField) ?? "threadId",
    turnId: cleanString(logic.runtimeContextCompactTurnId),
    turnIdField: cleanString(logic.runtimeContextCompactTurnIdField) ?? "turnId",
    reason: cleanString(logic.runtimeContextCompactReason),
    reasonField: cleanString(logic.runtimeContextCompactReasonField),
    scope: cleanString(logic.runtimeContextCompactScope),
    scopeField: cleanString(logic.runtimeContextCompactScopeField),
    endpoint: cleanString(logic.runtimeContextCompactEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeContextCompactWorkflowNodeId) ??
      RUNTIME_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
    actor: runtimeControlWorkflowActor(
      options,
      logic,
      "runtimeContextCompactActor",
    ),
  });
}

function runtimeControlWorkflowNodeLogic(
  node: Pick<Node, "type" | "config">,
  expectedType: string,
): NodeLogic {
  if (node.type !== expectedType) {
    throw new Error(`Expected ${expectedType} node, received ${node.type}.`);
  }
  return node.config?.logic ?? {};
}

function runtimeControlWorkflowActor(
  options: { actor?: string | null },
  logic: NodeLogic,
  actorKey: keyof NodeLogic,
): string {
  return cleanString(options.actor) ?? cleanString(logic[actorKey]) ?? "operator";
}

function createRuntimeControlRequestEnvelope<
  SchemaVersion extends string,
  NodeType extends string,
  Source extends string,
  EventKind extends string,
  ComponentKind extends string,
  PayloadSchemaVersion extends string,
>(
  config: RuntimeControlRequestEnvelopeConfig<
    SchemaVersion,
    NodeType,
    Source,
    EventKind,
    ComponentKind,
    PayloadSchemaVersion
  >,
  params: RuntimeControlRequestEnvelopeInput,
): RuntimeControlRequestEnvelope<
  SchemaVersion,
  NodeType,
  Source,
  EventKind,
  ComponentKind,
  PayloadSchemaVersion
> {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error(`${config.nodeType} nodes need a threadId input before dispatch.`);
  }

  const turnId =
    config.turnIdMode === "none"
      ? null
      : cleanString(params.turnId) ??
        stringAtPath(params.input, params.turnIdField ?? "turnId") ??
        stringAtPath(params.input, "turn_id");
  if (config.turnIdMode === "required" && !turnId) {
    throw new Error(`${config.nodeType} nodes need a turnId input before dispatch.`);
  }

  const endpointTemplate = cleanString(params.endpoint) ?? config.defaultEndpoint;
  const endpointValues: Record<string, string> = { threadId };
  if (config.turnIdMode !== "none") {
    endpointValues.turnId = turnId ?? "";
  }

  return {
    schemaVersion: config.schemaVersion,
    nodeType: config.nodeType,
    nodeId: cleanString(params.nodeId),
    threadId,
    turnId,
    endpoint: endpointFromTemplate(endpointTemplate, endpointValues),
    metadata: {
      source: config.source,
      actor: cleanString(params.actor) ?? "operator",
      workflowGraphId: cleanString(params.workflowGraphId),
      workflowNodeId:
        cleanString(params.workflowNodeId) ?? config.defaultWorkflowNodeId,
      eventKind: config.eventKind,
      componentKind: config.componentKind,
      payloadSchemaVersion: config.payloadSchemaVersion,
    },
  };
}

function requiredTurnId(
  envelope: RuntimeControlRequestEnvelope<
    string,
    string,
    string,
    string,
    string,
    string
  >,
): string {
  if (!envelope.turnId) {
    throw new Error(`${envelope.nodeType} nodes need a turnId input before dispatch.`);
  }
  return envelope.turnId;
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
