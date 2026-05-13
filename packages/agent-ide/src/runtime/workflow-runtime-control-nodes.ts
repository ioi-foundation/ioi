import type { Node, NodeLogic } from "../types/graph";

export const WORKFLOW_RUNTIME_THREAD_FORK_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-thread-fork-control.v1" as const;
export const RUNTIME_THREAD_FORK_WORKFLOW_NODE_ID = "runtime.thread-fork" as const;
export const RUNTIME_THREAD_FORK_COMPONENT_KIND = "thread_fork" as const;
export const RUNTIME_THREAD_FORK_SOURCE = "react_flow" as const;
export const RUNTIME_THREAD_FORK_SOURCE_EVENT_KIND = "OperatorControl.Fork" as const;
export const RUNTIME_THREAD_FORK_PAYLOAD_SCHEMA_VERSION =
  "ioi.runtime.thread-fork.v1" as const;

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
  const endpoint = endpointTemplate.replace(
    /\{threadId\}/g,
    encodeURIComponent(threadId),
  );

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
