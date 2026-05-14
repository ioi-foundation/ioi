import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_CODING_TOOL_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-coding-tool-control.v1" as const;
export const RUNTIME_CODING_TOOL_SOURCE = "react_flow" as const;
export const RUNTIME_CODING_TOOL_SOURCE_EVENT_KIND = "CodingTool.Invoke" as const;
export const RUNTIME_CODING_TOOL_COMPONENT_KIND = "coding_tool" as const;
export const RUNTIME_CODING_TOOL_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-request.v1" as const;

export interface RuntimeCodingToolControlRequestBody {
  source: typeof RUNTIME_CODING_TOOL_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_CODING_TOOL_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_CODING_TOOL_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_CODING_TOOL_COMPONENT_KIND;
  componentKind: typeof RUNTIME_CODING_TOOL_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_CODING_TOOL_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_CODING_TOOL_PAYLOAD_SCHEMA_VERSION;
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  tool_id: string;
  toolId: string;
  input: Record<string, unknown>;
  arguments: Record<string, unknown>;
  requires_approval: boolean;
  requiresApproval: boolean;
  approval_mode: string;
  approvalMode: string;
  trust_profile: string;
  trustProfile: string;
  node_approval_override: string;
  nodeApprovalOverride: string;
  toolPack: {
    coding: Record<string, unknown>;
  };
}

export interface RuntimeCodingToolControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_CODING_TOOL_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_coding_tool";
  nodeId: string | null;
  threadId: string;
  toolId: string;
  endpoint: string;
  method: "POST";
  body: RuntimeCodingToolControlRequestBody;
}

export interface RuntimeCodingToolControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  threadId?: string | null;
  threadIdField?: string | null;
  toolId?: string | null;
  toolIdField?: string | null;
  toolInput?: Record<string, unknown> | null;
  toolInputJson?: string | null;
  toolInputField?: string | null;
  approvalMode?: string | null;
  trustProfile?: string | null;
  nodeApprovalOverride?: string | null;
  requiresApproval?: boolean | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
  toolPack?: Record<string, unknown> | null;
}

export interface RuntimeCodingToolWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeCodingToolControlRequest(
  params: RuntimeCodingToolControlRequestInput,
): RuntimeCodingToolControlRequest {
  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  if (!threadId) {
    throw new Error("runtime_coding_tool nodes need a threadId input before dispatch.");
  }

  const toolId =
    cleanString(params.toolId) ??
    stringAtPath(params.input, params.toolIdField ?? "toolId") ??
    stringAtPath(params.input, "tool_id") ??
    "workspace.status";
  const toolInput =
    params.toolInput ??
    objectAtPath(params.input, params.toolInputField ?? "input") ??
    parseJsonObject(params.toolInputJson, {});
  const toolPack = {
    ...(params.toolPack ?? {}),
  };
  const requiresApproval =
    params.requiresApproval ??
    booleanAtPath(params.input, "requiresApproval", "requires_approval") ??
    booleanField(toolPack, "requiresApproval", "requires_approval") ??
    false;
  const approvalMode =
    cleanString(params.approvalMode) ??
    stringAtPath(params.input, "approvalMode") ??
    stringAtPath(params.input, "approval_mode") ??
    stringField(toolPack, "approvalMode", "approval_mode") ??
    (requiresApproval ? "human_required" : "suggest");
  const trustProfile =
    cleanString(params.trustProfile) ??
    stringAtPath(params.input, "trustProfile") ??
    stringAtPath(params.input, "trust_profile") ??
    stringField(toolPack, "trustProfile", "trust_profile") ??
    "local_private";
  const nodeApprovalOverride =
    cleanString(params.nodeApprovalOverride) ??
    stringAtPath(params.input, "nodeApprovalOverride") ??
    stringAtPath(params.input, "node_approval_override") ??
    stringField(toolPack, "nodeApprovalOverride", "node_approval_override") ??
    (requiresApproval ? "require_approval" : "inherit");
  const workflowNodeId =
    cleanString(params.workflowNodeId) ?? `runtime.coding-tool.${safeId(toolId)}`;
  const codingPolicyPack = {
    ...toolPack,
    requiresApproval,
    requires_approval: requiresApproval,
    approvalMode,
    approval_mode: approvalMode,
    trustProfile,
    trust_profile: trustProfile,
    nodeApprovalOverride,
    node_approval_override: nodeApprovalOverride,
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_CODING_TOOL_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_coding_tool",
    nodeId: params.nodeId ?? null,
    threadId,
    toolId,
    endpoint: `/v1/threads/${encodeSegment(threadId)}/tools/${encodeSegment(toolId)}/invoke`,
    method: "POST",
    body: {
      source: RUNTIME_CODING_TOOL_SOURCE,
      actor: cleanString(params.actor) ?? "operator",
      event_kind: RUNTIME_CODING_TOOL_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_CODING_TOOL_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_CODING_TOOL_COMPONENT_KIND,
      componentKind: RUNTIME_CODING_TOOL_COMPONENT_KIND,
      payload_schema_version: RUNTIME_CODING_TOOL_PAYLOAD_SCHEMA_VERSION,
      payloadSchemaVersion: RUNTIME_CODING_TOOL_PAYLOAD_SCHEMA_VERSION,
      workflow_graph_id: cleanString(params.workflowGraphId) ?? null,
      workflowGraphId: cleanString(params.workflowGraphId) ?? null,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      tool_id: toolId,
      toolId,
      input: toolInput,
      arguments: toolInput,
      requires_approval: requiresApproval,
      requiresApproval,
      approval_mode: approvalMode,
      approvalMode,
      trust_profile: trustProfile,
      trustProfile,
      node_approval_override: nodeApprovalOverride,
      nodeApprovalOverride,
      toolPack: { coding: codingPolicyPack },
    },
  };
}

export function createRuntimeCodingToolControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeCodingToolWorkflowNodeOptions = {},
): RuntimeCodingToolControlRequest {
  const logic = codingToolWorkflowNodeLogic(node);
  const binding = logic.toolBinding;
  const toolPack = binding?.toolPack ?? {};
  return createRuntimeCodingToolControlRequest({
    nodeId: node.id,
    input,
    threadIdField: "threadId",
    toolId: binding?.toolRef,
    toolInput: binding?.arguments,
    toolPack,
    requiresApproval: binding?.requiresApproval ?? booleanField(toolPack, "requiresApproval", "requires_approval"),
    approvalMode: stringField(toolPack, "approvalMode", "approval_mode"),
    trustProfile: stringField(toolPack, "trustProfile", "trust_profile"),
    nodeApprovalOverride: stringField(toolPack, "nodeApprovalOverride", "node_approval_override"),
    workflowGraphId: options.workflowGraphId,
    workflowNodeId:
      stringField(logic, "workflowNodeId", "workflow_node_id") ??
      `runtime.coding-tool.${safeId(binding?.toolRef ?? "workspace.status")}`,
    actor: options.actor,
  });
}

function codingToolWorkflowNodeLogic(node: Pick<Node, "config">): NodeLogic {
  const logic = node.config?.logic;
  return logic && typeof logic === "object" ? (logic as NodeLogic) : {};
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function stringField(source: unknown, ...keys: string[]): string | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  for (const key of keys) {
    const value = (source as Record<string, unknown>)[key];
    const text = cleanString(value);
    if (text) return text;
  }
  return null;
}

function booleanField(source: unknown, ...keys: string[]): boolean | null {
  if (!source || typeof source !== "object" || Array.isArray(source)) return null;
  for (const key of keys) {
    const value = (source as Record<string, unknown>)[key];
    if (typeof value === "boolean") return value;
  }
  return null;
}

function stringAtPath(source: unknown, path: string): string | null {
  const value = valueAtPath(source, path);
  return cleanString(value);
}

function booleanAtPath(source: unknown, ...paths: string[]): boolean | null {
  for (const path of paths) {
    const value = valueAtPath(source, path);
    if (typeof value === "boolean") return value;
  }
  return null;
}

function objectAtPath(source: unknown, path: string): Record<string, unknown> | null {
  const value = valueAtPath(source, path);
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function valueAtPath(source: unknown, path: string): unknown {
  if (!source || typeof source !== "object" || Array.isArray(source)) return undefined;
  return path.split(".").reduce<unknown>((current, segment) => {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    return (current as Record<string, unknown>)[segment];
  }, source);
}

function parseJsonObject(text: unknown, fallback: Record<string, unknown>): Record<string, unknown> {
  if (typeof text !== "string" || !text.trim()) return fallback;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : fallback;
  } catch {
    return fallback;
  }
}

function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

function safeId(value: unknown): string {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
