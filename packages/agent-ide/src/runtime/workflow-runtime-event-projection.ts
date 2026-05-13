import type { WorkflowNodeKind } from "../types/graph";

export const WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION =
  "ioi.workflow.runtime-event-projection.v1" as const;
export const WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION =
  "ioi.workflow.runtime-tui-deeplink.v1" as const;
export const WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION =
  "ioi.workflow.runtime-tui-control-state.v1" as const;

export type WorkflowRuntimeThreadEventType =
  | "thread_started"
  | "thread_forked"
  | "turn_started"
  | "turn_completed"
  | "turn_failed"
  | "turn_canceled"
  | "turn_interrupted"
  | "turn_steered"
  | "context_compacted"
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
  tuiDeepLink: WorkflowRuntimeTuiDeepLinkDescriptor;
}

export interface WorkflowRuntimeTuiDeepLinkDescriptor {
  schemaVersion: typeof WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION;
  command: "ioi agent tui";
  args: string[];
  reopenCommand: string;
  threadId: string;
  turnId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventId: string;
  eventKind: string;
  componentKind: string;
  seq: number;
  cursor: string;
  sinceSeq: number;
  lastEventId: string;
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

export type WorkflowRuntimeTuiControlRowKind =
  | "summary"
  | "mode_status"
  | "approval"
  | "approval_decision"
  | "command"
  | "validation_error";

export type WorkflowRuntimeTuiControlRowStatus =
  | "current"
  | "pending"
  | "approved"
  | "rejected"
  | "blocked"
  | "accepted"
  | "applied"
  | "failed"
  | "validation_error"
  | "unknown";

export interface WorkflowRuntimeTuiControlStateInput {
  schemaVersion?: string;
  schema_version?: string;
  surface?: string;
  threadId?: string | null;
  thread_id?: string | null;
  currentTurnId?: string | null;
  current_turn_id?: string | null;
  lastCursor?: string | null;
  last_cursor?: string | null;
  lastEventId?: string | null;
  last_event_id?: string | null;
  modeStatus?: unknown;
  mode_status?: unknown;
  approvalRows?: unknown[];
  approval_rows?: unknown[];
  approvalDecisions?: unknown[];
  approval_decisions?: unknown[];
  commandHistory?: unknown[];
  command_history?: unknown[];
  validationErrors?: unknown[];
  validation_errors?: unknown[];
}

export interface WorkflowRuntimeTuiControlStateRow {
  id: string;
  rowKind: WorkflowRuntimeTuiControlRowKind;
  status: WorkflowRuntimeTuiControlRowStatus;
  label: string;
  command: string | null;
  rawInput: string | null;
  message: string | null;
  approvalId: string | null;
  threadId: string | null;
  turnId: string | null;
  cursor: string | null;
  eventId: string | null;
  sequence: number | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  reactFlowNodeId: string;
}

export interface WorkflowRuntimeTuiControlStateProjection {
  schemaVersion: typeof WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION;
  sourceSchemaVersion: string | null;
  surface: string;
  threadId: string | null;
  currentTurnId: string | null;
  lastCursor: string | null;
  lastEventId: string | null;
  commandCount: number;
  validationErrorCount: number;
  approvalCount: number;
  approvalDecisionCount: number;
  rowCount: number;
  rows: WorkflowRuntimeTuiControlStateRow[];
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

export function projectRuntimeTuiControlStateToWorkflowProjection(
  state: WorkflowRuntimeTuiControlStateInput | null | undefined,
): WorkflowRuntimeTuiControlStateProjection {
  const threadId = stringField(state, "threadId", "thread_id");
  const currentTurnId = stringField(state, "currentTurnId", "current_turn_id");
  const lastCursor = stringField(state, "lastCursor", "last_cursor");
  const lastEventId = stringField(state, "lastEventId", "last_event_id");
  const commandHistory = arrayField(state, "commandHistory", "command_history");
  const validationErrors = arrayField(
    state,
    "validationErrors",
    "validation_errors",
  );
  const modeStatus = recordField(state, "modeStatus", "mode_status");
  const approvalRows = arrayField(state, "approvalRows", "approval_rows");
  const approvalDecisions = arrayField(
    state,
    "approvalDecisions",
    "approval_decisions",
  );
  const rows: WorkflowRuntimeTuiControlStateRow[] = [];

  if (threadId || currentTurnId || lastCursor || lastEventId) {
    rows.push({
      id: `tui-control-summary:${slug(threadId ?? "detached")}`,
      rowKind: "summary",
      status: "current",
      label: "TUI control state",
      command: null,
      rawInput: null,
      message: currentTurnId ? `Current turn ${currentTurnId}` : "No active turn",
      approvalId: null,
      threadId,
      turnId: currentTurnId,
      cursor: lastCursor,
      eventId: lastEventId,
      sequence: null,
      receiptRefs: [],
      policyDecisionRefs: [],
      reactFlowNodeId: "runtime.tui-control-state",
    });
  }

  if (modeStatus) {
    const mode = stringField(modeStatus, "mode") ?? "agent";
    const approvalMode =
      stringField(modeStatus, "approvalMode", "approval_mode") ?? "suggest";
    const trustProfile =
      stringField(modeStatus, "trustProfile", "trust_profile") ??
      "local_private";
    rows.push({
      id: `tui-mode-status:${slug(threadId ?? "detached")}`,
      rowKind: "mode_status",
      status: "current",
      label: "Mode status",
      command: null,
      rawInput: null,
      message: `${mode} · ${approvalMode} · ${trustProfile}`,
      approvalId: null,
      threadId,
      turnId: currentTurnId,
      cursor: lastCursor,
      eventId: lastEventId,
      sequence: null,
      receiptRefs: [],
      policyDecisionRefs: [],
      reactFlowNodeId: "runtime.tui-control-state.mode-status",
    });
  }

  approvalRows.forEach((entry, index) => {
    const approvalId = stringField(entry, "approvalId", "approval_id");
    const status = tuiControlRowStatus(stringField(entry, "status"));
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    rows.push({
      id: stringField(entry, "id") ?? `tui-approval:${approvalId ?? sequence}`,
      rowKind: "approval",
      status,
      label: approvalId ? `Approval ${approvalId}` : "Approval required",
      command: null,
      rawInput: null,
      message: stringField(entry, "message", "summary") ?? "Waiting for operator decision",
      approvalId,
      threadId: stringField(entry, "threadId", "thread_id") ?? threadId,
      turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
      cursor: stringField(entry, "cursor") ?? lastCursor,
      eventId: stringField(entry, "eventId", "event_id") ?? lastEventId,
      sequence,
      receiptRefs: stringArrayField(entry, "receiptRefs", "receipt_refs"),
      policyDecisionRefs: stringArrayField(
        entry,
        "policyDecisionRefs",
        "policy_decision_refs",
      ),
      reactFlowNodeId:
        stringField(entry, "workflowNodeId", "workflow_node_id") ??
        `runtime.approval.${slug(approvalId ?? String(sequence))}`,
    });
  });

  approvalDecisions.forEach((entry, index) => {
    const approvalId = stringField(entry, "approvalId", "approval_id");
    const decision = stringField(entry, "decision");
    const status = tuiControlRowStatus(stringField(entry, "status") ?? decision);
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-approval-decision:${approvalId ?? sequence}`,
      rowKind: "approval_decision",
      status,
      label: decision ? `Approval ${decision}` : "Approval decision",
      command: decision,
      rawInput: null,
      message: stringField(entry, "message", "reason") ?? approvalId,
      approvalId,
      threadId: stringField(entry, "threadId", "thread_id") ?? threadId,
      turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
      cursor: stringField(entry, "cursor") ?? lastCursor,
      eventId: stringField(entry, "eventId", "event_id") ?? lastEventId,
      sequence,
      receiptRefs: stringArrayField(entry, "receiptRefs", "receipt_refs"),
      policyDecisionRefs: stringArrayField(
        entry,
        "policyDecisionRefs",
        "policy_decision_refs",
      ),
      reactFlowNodeId:
        stringField(entry, "workflowNodeId", "workflow_node_id") ??
        `runtime.approval.${slug(approvalId ?? String(sequence))}`,
    });
  });

  commandHistory.forEach((entry, index) => {
    const command = stringField(entry, "command");
    const rawInput = stringField(entry, "rawInput", "raw_input") ?? command;
    const status = tuiControlRowStatus(stringField(entry, "status"));
    const sequence = numberField(entry, "sequence", "index") ?? index + 1;
    rows.push({
      id: stringField(entry, "id") ?? `tui-command:${sequence}`,
      rowKind: "command",
      status,
      label: command ? `/${command}` : "TUI command",
      command,
      rawInput,
      message: stringField(entry, "message"),
      approvalId: stringField(entry, "approvalId", "approval_id"),
      threadId: stringField(entry, "threadId", "thread_id") ?? threadId,
      turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
      cursor: stringField(entry, "cursor") ?? lastCursor,
      eventId: stringField(entry, "eventId", "event_id") ?? lastEventId,
      sequence,
      receiptRefs: stringArrayField(entry, "receiptRefs", "receipt_refs"),
      policyDecisionRefs: stringArrayField(
        entry,
        "policyDecisionRefs",
        "policy_decision_refs",
      ),
      reactFlowNodeId: `runtime.tui-control-state.command.${slug(command ?? String(sequence))}`,
    });
  });

  validationErrors.forEach((entry, index) => {
    const command = stringField(entry, "command");
    const rawInput = stringField(entry, "rawInput", "raw_input") ?? command;
    const sequence = numberField(entry, "sequence", "index") ?? index + 1;
    rows.push({
      id: stringField(entry, "id") ?? `tui-validation-error:${sequence}`,
      rowKind: "validation_error",
      status: "validation_error",
      label: command ? `/${command} validation` : "TUI validation",
      command,
      rawInput,
      message: stringField(entry, "message", "error") ?? "Invalid TUI command",
      approvalId: stringField(entry, "approvalId", "approval_id"),
      threadId: stringField(entry, "threadId", "thread_id") ?? threadId,
      turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
      cursor: stringField(entry, "cursor") ?? lastCursor,
      eventId: stringField(entry, "eventId", "event_id") ?? lastEventId,
      sequence,
      receiptRefs: [],
      policyDecisionRefs: [],
      reactFlowNodeId: `runtime.tui-control-state.validation.${slug(command ?? String(sequence))}`,
    });
  });

  return {
    schemaVersion: WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    sourceSchemaVersion: stringField(state, "schemaVersion", "schema_version"),
    surface: stringField(state, "surface") ?? "tui",
    threadId,
    currentTurnId,
    lastCursor,
    lastEventId,
    commandCount: commandHistory.length,
    validationErrorCount: validationErrors.length,
    approvalCount: approvalRows.length,
    approvalDecisionCount: approvalDecisions.length,
    rowCount: rows.length,
    rows,
  };
}

export function workflowNodeIdForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string {
  if (event.workflowNodeId) return event.workflowNodeId;
  switch (event.type) {
    case "thread_started":
      return "runtime.thread";
    case "thread_forked":
      return "runtime.thread-fork";
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
    case "context_compacted":
      return "runtime.context-compact";
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
  if (event.componentKind === "workspace_snapshot") return "quality_ledger";
  if (event.componentKind === "restore_gate") return "hook_policy";
  switch (event.type) {
    case "thread_started":
    case "turn_started":
      return "trigger";
    case "thread_forked":
      return "runtime_thread_fork";
    case "turn_completed":
    case "turn_failed":
    case "turn_canceled":
      return "output";
    case "turn_interrupted":
      return "runtime_operator_interrupt";
    case "turn_steered":
      return "runtime_operator_steer";
    case "context_compacted":
      return "runtime_context_compact";
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
    tuiDeepLink: tuiDeepLinkForRuntimeThreadEvent(latestEvent, bucket.nodeId),
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
    case "thread_forked":
      return "thread_fork";
    case "turn_started":
    case "turn_completed":
    case "turn_failed":
    case "turn_canceled":
      return "runtime_turn";
    case "turn_interrupted":
    case "turn_steered":
      return "operator_control";
    case "context_compacted":
      return "context_compaction";
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
  if (event.componentKind === "coding_tool" && event.toolName) return `Coding tool: ${event.toolName}`;
  if (event.componentKind === "workspace_snapshot") return "Workspace snapshot";
  if (event.componentKind === "restore_gate") return "Restore preview";
  if (event.componentKind === "lsp_diagnostics") return "Diagnostics injected";
  if (event.componentKind === "lsp_diagnostics_gate") return "Diagnostics blocking gate";
  if (event.toolName) return `Tool: ${event.toolName}`;
  switch (event.type) {
    case "thread_started":
      return "Thread";
    case "thread_forked":
      return "Thread forked";
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
    case "context_compacted":
      return "Context compacted";
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
  if (normalizedStatus.includes("rejected") || normalizedStatus.includes("denied")) {
    return "blocked";
  }
  if (normalizedStatus.includes("canceled") || normalizedStatus.includes("cancelled")) {
    return "canceled";
  }
  if (normalizedStatus.includes("interrupted")) return "interrupted";
  if (
    normalizedStatus.includes("completed") ||
    normalizedStatus.includes("succeeded") ||
    normalizedStatus.includes("approved")
  ) {
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

function tuiDeepLinkForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
  workflowNodeId: string,
): WorkflowRuntimeTuiDeepLinkDescriptor {
  const args = [
    "agent",
    "tui",
    "--thread-id",
    event.threadId,
    "--since-seq",
    String(event.seq),
  ];
  return {
    schemaVersion: WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    command: "ioi agent tui",
    args,
    reopenCommand: `ioi ${args.join(" ")}`,
    threadId: event.threadId,
    turnId: event.turnId,
    workflowGraphId: event.workflowGraphId,
    workflowNodeId,
    eventId: event.id,
    eventKind: event.eventKind,
    componentKind: componentKindForRuntimeThreadEvent(event),
    seq: event.seq,
    cursor: event.cursor,
    sinceSeq: event.seq,
    lastEventId: event.id,
  };
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

function objectField(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringField(
  value: unknown,
  camelKey: string,
  snakeKey?: string,
): string | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate =
    objectValue[camelKey] ?? (snakeKey ? objectValue[snakeKey] : undefined);
  return typeof candidate === "string" && candidate.trim()
    ? candidate
    : null;
}

function numberField(
  value: unknown,
  camelKey: string,
  snakeKey?: string,
): number | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate =
    objectValue[camelKey] ?? (snakeKey ? objectValue[snakeKey] : undefined);
  return typeof candidate === "number" && Number.isFinite(candidate)
    ? candidate
    : null;
}

function arrayField(
  value: unknown,
  camelKey: string,
  snakeKey?: string,
): unknown[] {
  const objectValue = objectField(value);
  if (!objectValue) return [];
  const candidate =
    objectValue[camelKey] ?? (snakeKey ? objectValue[snakeKey] : undefined);
  return Array.isArray(candidate) ? candidate : [];
}

function recordField(
  value: unknown,
  camelKey: string,
  snakeKey?: string,
): Record<string, unknown> | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate =
    objectValue[camelKey] ?? (snakeKey ? objectValue[snakeKey] : undefined);
  return objectField(candidate);
}

function stringArrayField(
  value: unknown,
  camelKey: string,
  snakeKey?: string,
): string[] {
  return arrayField(value, camelKey, snakeKey).filter(
    (candidate): candidate is string =>
      typeof candidate === "string" && Boolean(candidate.trim()),
  );
}

function tuiControlRowStatus(
  status: string | null,
): WorkflowRuntimeTuiControlRowStatus {
  const normalizedStatus = status?.toLowerCase() ?? null;
  if (normalizedStatus === "approve") return "approved";
  if (normalizedStatus === "reject") return "rejected";
  if (normalizedStatus?.includes("waiting")) return "pending";
  if (normalizedStatus?.includes("approved")) return "approved";
  if (normalizedStatus?.includes("rejected") || normalizedStatus?.includes("denied")) {
    return "rejected";
  }
  switch (normalizedStatus) {
    case "current":
    case "pending":
    case "approved":
    case "rejected":
    case "blocked":
    case "accepted":
    case "applied":
    case "failed":
    case "validation_error":
      return normalizedStatus;
    default:
      return "unknown";
  }
}

function slug(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || "unknown";
}
