import type { WorkflowNodeKind } from "../types/graph";

export const WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION =
  "ioi.workflow.runtime-event-projection.v1" as const;

export type WorkflowRuntimeThreadEventType =
  | "thread_started"
  | "turn_started"
  | "turn_completed"
  | "turn_failed"
  | "turn_canceled"
  | "turn_interrupted"
  | "turn_steered"
  | "reasoning_delta"
  | "tool_completed"
  | "tool_failed"
  | "approval_required"
  | "policy_blocked"
  | "receipt_emitted"
  | "model_route_decision"
  | "tool_route_decision"
  | "runtime_step";

export type WorkflowRuntimeProjectedStatus =
  | "queued"
  | "running"
  | "waiting"
  | "completed"
  | "failed"
  | "blocked"
  | "canceled"
  | "interrupted"
  | "unknown";

export interface WorkflowRuntimeThreadEventLike {
  id: string;
  cursor: string;
  seq: number;
  threadId: string;
  turnId: string | null;
  type: WorkflowRuntimeThreadEventType | string;
  eventKind: string;
  sourceEventKind: string;
  status: string;
  createdAt?: string;
  componentKind: string | null;
  workflowNodeId: string | null;
  workflowGraphId: string | null;
  toolCallId?: string | null;
  toolName?: string | null;
  approvalId?: string | null;
  agentStatus?: string | null;
  stepIndex?: number | null;
  payloadSchemaVersion: string;
  receiptRefs: string[];
  artifactRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
  payload?: Record<string, unknown>;
}

export interface WorkflowRuntimeProjectionOptions {
  includeSequentialEdges?: boolean;
  columns?: number;
  horizontalSpacing?: number;
  verticalSpacing?: number;
}

export interface WorkflowRuntimeReactFlowPosition {
  x: number;
  y: number;
}

export interface WorkflowRuntimeReactFlowNodeData {
  schemaVersion: typeof WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION;
  nodeKind: WorkflowNodeKind;
  componentKind: string;
  workflowNodeId: string;
  workflowGraphId: string | null;
  label: string;
  status: WorkflowRuntimeProjectedStatus;
  threadId: string;
  turnIds: string[];
  eventIds: string[];
  eventKinds: string[];
  sourceEventKinds: string[];
  firstSeq: number;
  latestSeq: number;
  latestCursor: string;
  latestEventId: string;
  latestPayloadSchemaVersion: string;
  receiptRefs: string[];
  artifactRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
  toolName: string | null;
  approvalId: string | null;
  agentStatus: string | null;
  summary: string | null;
}

export interface WorkflowRuntimeReactFlowNode {
  id: string;
  type: "runtimeEventProjection";
  position: WorkflowRuntimeReactFlowPosition;
  data: WorkflowRuntimeReactFlowNodeData;
}

export interface WorkflowRuntimeProjectedNode
  extends WorkflowRuntimeReactFlowNodeData {
  id: string;
  reactFlowNode: WorkflowRuntimeReactFlowNode;
}

export interface WorkflowRuntimeReactFlowEdgeData {
  schemaVersion: typeof WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION;
  sourceLatestSeq: number;
  targetFirstSeq: number;
  eventIds: string[];
}

export interface WorkflowRuntimeReactFlowEdge {
  id: string;
  source: string;
  target: string;
  type: "runtimeEventTransition";
  data: WorkflowRuntimeReactFlowEdgeData;
}

export interface WorkflowRuntimeProjectedEdge
  extends WorkflowRuntimeReactFlowEdgeData {
  id: string;
  source: string;
  target: string;
  reactFlowEdge: WorkflowRuntimeReactFlowEdge;
}

export interface WorkflowRuntimeEventProjection {
  schemaVersion: typeof WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION;
  threadIds: string[];
  turnIds: string[];
  workflowGraphIds: string[];
  latestSeq: number | null;
  latestCursor: string | null;
  latestEventId: string | null;
  eventCount: number;
  nodes: WorkflowRuntimeProjectedNode[];
  edges: WorkflowRuntimeProjectedEdge[];
  reactFlowNodes: WorkflowRuntimeReactFlowNode[];
  reactFlowEdges: WorkflowRuntimeReactFlowEdge[];
}

interface MutableProjectedNode {
  events: WorkflowRuntimeThreadEventLike[];
  nodeId: string;
}

export function projectRuntimeThreadEventsToWorkflowProjection(
  events: readonly WorkflowRuntimeThreadEventLike[],
  options: WorkflowRuntimeProjectionOptions = {},
): WorkflowRuntimeEventProjection {
  const sortedEvents = sortRuntimeThreadEvents(events);
  const nodeBuckets = new Map<string, MutableProjectedNode>();

  for (const event of sortedEvents) {
    const nodeId = workflowNodeIdForRuntimeThreadEvent(event);
    const bucket = nodeBuckets.get(nodeId);
    if (bucket) {
      bucket.events.push(event);
    } else {
      nodeBuckets.set(nodeId, { nodeId, events: [event] });
    }
  }

  const nodes = Array.from(nodeBuckets.values()).map((bucket, index) =>
    projectedNodeForBucket(bucket, index, options),
  );
  const edges = options.includeSequentialEdges === false
    ? []
    : projectedEdgesForEvents(sortedEvents, nodes);
  const latestEvent =
    sortedEvents.length > 0 ? sortedEvents[sortedEvents.length - 1] : null;

  return {
    schemaVersion: WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
    threadIds: uniqueStrings(sortedEvents.map((event) => event.threadId)),
    turnIds: uniqueStrings(
      sortedEvents
        .map((event) => event.turnId)
        .filter((turnId): turnId is string => Boolean(turnId)),
    ),
    workflowGraphIds: uniqueStrings(
      sortedEvents
        .map((event) => event.workflowGraphId)
        .filter((graphId): graphId is string => Boolean(graphId)),
    ),
    latestSeq: latestEvent?.seq ?? null,
    latestCursor: latestEvent?.cursor ?? null,
    latestEventId: latestEvent?.id ?? null,
    eventCount: sortedEvents.length,
    nodes,
    edges,
    reactFlowNodes: nodes.map((node) => node.reactFlowNode),
    reactFlowEdges: edges.map((edge) => edge.reactFlowEdge),
  };
}

export function projectRuntimeThreadEventsToWorkflowNodes(
  events: readonly WorkflowRuntimeThreadEventLike[],
  options: WorkflowRuntimeProjectionOptions = {},
): WorkflowRuntimeProjectedNode[] {
  return projectRuntimeThreadEventsToWorkflowProjection(events, options).nodes;
}

export function workflowNodeIdForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string {
  if (event.workflowNodeId) return event.workflowNodeId;
  switch (event.type) {
    case "thread_started":
      return "runtime.thread";
    case "turn_started":
      return "runtime.turn";
    case "turn_completed":
      return "runtime.turn-completed";
    case "turn_failed":
      return "runtime.turn-failed";
    case "turn_canceled":
      return "runtime.turn-canceled";
    case "turn_interrupted":
      return "runtime.operator-interrupt";
    case "turn_steered":
      return "runtime.operator-steer";
    case "reasoning_delta":
      return "runtime.reasoning";
    case "tool_completed":
    case "tool_failed":
      return `runtime.tool-result.${slug(event.toolName ?? event.toolCallId ?? event.eventKind)}`;
    case "approval_required":
      return `runtime.approval.${slug(event.approvalId ?? event.eventKind)}`;
    case "policy_blocked":
      return "runtime.policy";
    case "receipt_emitted":
      return `runtime.receipt.${slug(event.receiptRefs[0] ?? event.id)}`;
    case "model_route_decision":
      return "runtime.model-router";
    case "tool_route_decision":
      return "runtime.tool-router";
    default:
      return `runtime.${slug(event.componentKind ?? event.eventKind)}`;
  }
}

export function workflowNodeKindForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): WorkflowNodeKind {
  switch (event.type) {
    case "thread_started":
    case "turn_started":
      return "trigger";
    case "turn_completed":
    case "turn_failed":
    case "turn_canceled":
    case "turn_interrupted":
      return "output";
    case "turn_steered":
      return "state";
    case "reasoning_delta":
      return "task_state";
    case "tool_completed":
    case "tool_failed":
      return "plugin_tool";
    case "approval_required":
      return "human_gate";
    case "policy_blocked":
      return "hook_policy";
    case "receipt_emitted":
      return "quality_ledger";
    case "model_route_decision":
      return "model_binding";
    case "tool_route_decision":
      return "adapter";
    default:
      return "state";
  }
}

function projectedNodeForBucket(
  bucket: MutableProjectedNode,
  index: number,
  options: WorkflowRuntimeProjectionOptions,
): WorkflowRuntimeProjectedNode {
  const events = sortRuntimeThreadEvents(bucket.events);
  const firstEvent = events[0];
  const latestEvent = events[events.length - 1];
  const nodeData: WorkflowRuntimeReactFlowNodeData = {
    schemaVersion: WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
    nodeKind: workflowNodeKindForRuntimeThreadEvent(latestEvent),
    componentKind: componentKindForRuntimeThreadEvent(latestEvent),
    workflowNodeId: bucket.nodeId,
    workflowGraphId: latestEvent.workflowGraphId,
    label: labelForRuntimeThreadEvent(latestEvent),
    status: projectedStatusForRuntimeThreadEvent(latestEvent),
    threadId: latestEvent.threadId,
    turnIds: uniqueStrings(
      events
        .map((event) => event.turnId)
        .filter((turnId): turnId is string => Boolean(turnId)),
    ),
    eventIds: events.map((event) => event.id),
    eventKinds: uniqueStrings(events.map((event) => event.eventKind)),
    sourceEventKinds: uniqueStrings(events.map((event) => event.sourceEventKind)),
    firstSeq: firstEvent.seq,
    latestSeq: latestEvent.seq,
    latestCursor: latestEvent.cursor,
    latestEventId: latestEvent.id,
    latestPayloadSchemaVersion: latestEvent.payloadSchemaVersion,
    receiptRefs: uniqueStrings(events.flatMap((event) => event.receiptRefs)),
    artifactRefs: uniqueStrings(events.flatMap((event) => event.artifactRefs)),
    policyDecisionRefs: uniqueStrings(
      events.flatMap((event) => event.policyDecisionRefs),
    ),
    rollbackRefs: uniqueStrings(events.flatMap((event) => event.rollbackRefs)),
    toolName: latestEvent.toolName ?? null,
    approvalId: latestEvent.approvalId ?? null,
    agentStatus: latestEvent.agentStatus ?? null,
    summary: summaryForRuntimeThreadEvent(latestEvent),
  };
  const reactFlowNode: WorkflowRuntimeReactFlowNode = {
    id: bucket.nodeId,
    type: "runtimeEventProjection",
    position: positionForIndex(index, options),
    data: nodeData,
  };
  return {
    id: bucket.nodeId,
    ...nodeData,
    reactFlowNode,
  };
}

function projectedEdgesForEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  nodes: readonly WorkflowRuntimeProjectedNode[],
): WorkflowRuntimeProjectedEdge[] {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const edgeBuckets = new Map<
    string,
    { source: string; target: string; eventIds: string[]; targetFirstSeq: number }
  >();
  let previousNodeId: string | null = null;
  let previousEvent: WorkflowRuntimeThreadEventLike | null = null;

  for (const event of events) {
    const nodeId = workflowNodeIdForRuntimeThreadEvent(event);
    if (previousNodeId && previousNodeId !== nodeId && previousEvent) {
      const edgeKey = `${previousNodeId}->${nodeId}`;
      const bucket = edgeBuckets.get(edgeKey);
      if (bucket) {
        bucket.eventIds.push(event.id);
      } else {
        edgeBuckets.set(edgeKey, {
          source: previousNodeId,
          target: nodeId,
          eventIds: [event.id],
          targetFirstSeq: event.seq,
        });
      }
    }
    previousNodeId = nodeId;
    previousEvent = event;
  }

  return Array.from(edgeBuckets.entries()).map(([edgeKey, bucket]) => {
    const sourceNode = nodesById.get(bucket.source);
    const edgeData: WorkflowRuntimeReactFlowEdgeData = {
      schemaVersion: WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
      sourceLatestSeq: sourceNode?.latestSeq ?? 0,
      targetFirstSeq: bucket.targetFirstSeq,
      eventIds: uniqueStrings(bucket.eventIds),
    };
    const edgeId = `runtime-event:${slug(edgeKey)}`;
    const reactFlowEdge: WorkflowRuntimeReactFlowEdge = {
      id: edgeId,
      source: bucket.source,
      target: bucket.target,
      type: "runtimeEventTransition",
      data: edgeData,
    };
    return {
      id: edgeId,
      source: bucket.source,
      target: bucket.target,
      ...edgeData,
      reactFlowEdge,
    };
  });
}

function componentKindForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string {
  if (event.componentKind) return event.componentKind;
  switch (event.type) {
    case "thread_started":
      return "runtime_thread";
    case "turn_started":
    case "turn_completed":
    case "turn_failed":
    case "turn_canceled":
    case "turn_interrupted":
      return "runtime_turn";
    case "turn_steered":
      return "operator_control";
    case "reasoning_delta":
      return "reasoning_delta";
    case "tool_completed":
    case "tool_failed":
      return "tool_result";
    case "approval_required":
      return "approval_gate";
    case "policy_blocked":
      return "policy_gate";
    case "receipt_emitted":
      return "receipt";
    case "model_route_decision":
      return "model_router";
    case "tool_route_decision":
      return "tool_router";
    default:
      return "runtime_step";
  }
}

function labelForRuntimeThreadEvent(event: WorkflowRuntimeThreadEventLike): string {
  if (event.toolName) return `Tool: ${event.toolName}`;
  switch (event.type) {
    case "thread_started":
      return "Thread";
    case "turn_started":
      return "Turn";
    case "turn_completed":
      return "Turn completed";
    case "turn_failed":
      return "Turn failed";
    case "turn_canceled":
      return "Turn canceled";
    case "turn_interrupted":
      return "Turn interrupted";
    case "turn_steered":
      return "Turn steered";
    case "reasoning_delta":
      return "Reasoning";
    case "tool_completed":
      return "Tool result";
    case "tool_failed":
      return "Tool failed";
    case "approval_required":
      return "Approval gate";
    case "policy_blocked":
      return "Policy gate";
    case "receipt_emitted":
      return "Receipt";
    case "model_route_decision":
      return "Model router";
    case "tool_route_decision":
      return "Tool router";
    default:
      return "Runtime step";
  }
}

function projectedStatusForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): WorkflowRuntimeProjectedStatus {
  if (event.type === "approval_required") return "waiting";
  if (event.type === "policy_blocked") return "blocked";
  if (event.type === "tool_failed" || event.type === "turn_failed") return "failed";
  if (event.type === "turn_canceled") return "canceled";
  if (event.type === "turn_interrupted") return "interrupted";

  const normalizedStatus = event.status.toLowerCase();
  if (normalizedStatus.includes("queued")) return "queued";
  if (normalizedStatus.includes("running")) return "running";
  if (normalizedStatus.includes("waiting")) return "waiting";
  if (normalizedStatus.includes("blocked")) return "blocked";
  if (normalizedStatus.includes("failed") || normalizedStatus.includes("error")) {
    return "failed";
  }
  if (normalizedStatus.includes("canceled") || normalizedStatus.includes("cancelled")) {
    return "canceled";
  }
  if (normalizedStatus.includes("interrupted")) return "interrupted";
  if (normalizedStatus.includes("completed") || normalizedStatus.includes("succeeded")) {
    return "completed";
  }
  return "unknown";
}

function summaryForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string | null {
  const payload = event.payload ?? {};
  for (const key of ["summary", "message", "text", "content"]) {
    const value = payload[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return null;
}

function sortRuntimeThreadEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
): WorkflowRuntimeThreadEventLike[] {
  return [...events].sort((left, right) => {
    if (left.seq !== right.seq) return left.seq - right.seq;
    const createdAtCompare = (left.createdAt ?? "").localeCompare(right.createdAt ?? "");
    if (createdAtCompare !== 0) return createdAtCompare;
    return left.id.localeCompare(right.id);
  });
}

function positionForIndex(
  index: number,
  options: WorkflowRuntimeProjectionOptions,
): WorkflowRuntimeReactFlowPosition {
  const columns = Math.max(1, options.columns ?? 3);
  const horizontalSpacing = options.horizontalSpacing ?? 280;
  const verticalSpacing = options.verticalSpacing ?? 160;
  return {
    x: (index % columns) * horizontalSpacing,
    y: Math.floor(index / columns) * verticalSpacing,
  };
}

function uniqueStrings(values: readonly string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function slug(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || "unknown";
}
