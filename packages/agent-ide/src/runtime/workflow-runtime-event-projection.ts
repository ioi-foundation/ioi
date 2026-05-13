import type { WorkflowNodeKind } from "../types/graph";
import { diagnosticsRepairActionsForEvents } from "./workflow-runtime-diagnostics-repair-actions";
import type { WorkflowRuntimeDiagnosticsRepairActionDescriptor } from "./workflow-runtime-diagnostics-repair-actions";
export type {
  WorkflowRuntimeDiagnosticsRepairAction,
  WorkflowRuntimeDiagnosticsRepairActionDescriptor,
} from "./workflow-runtime-diagnostics-repair-actions";

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
  diagnosticsRepairActions: WorkflowRuntimeDiagnosticsRepairActionDescriptor[];
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
  | "model_route"
  | "thinking"
  | "mcp_server"
  | "mcp_tool"
  | "mcp_resource"
  | "mcp_prompt"
  | "memory_status"
  | "memory_policy"
  | "memory_record"
  | "subagent"
  | "approval"
  | "approval_decision"
  | "job"
  | "run_lifecycle"
  | "command"
  | "validation_error";

export type WorkflowRuntimeTuiControlRowStatus =
  | "current"
  | "queued"
  | "running"
  | "waiting"
  | "completed"
  | "canceled"
  | "interrupted"
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
  workflowGraphId?: string | null;
  workflow_graph_id?: string | null;
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
  jobRows?: unknown[];
  job_rows?: unknown[];
  runLifecycleRows?: unknown[];
  run_lifecycle_rows?: unknown[];
  mcpRows?: unknown[];
  mcp_rows?: unknown[];
  memoryRows?: unknown[];
  memory_rows?: unknown[];
  subagentRows?: unknown[];
  subagent_rows?: unknown[];
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
  jobId: string | null;
  runId: string | null;
  modelId: string | null;
  mcpServerId?: string | null;
  mcpToolName?: string | null;
  mcpToolCallId?: string | null;
  mcpResourceUri?: string | null;
  mcpPromptName?: string | null;
  mcpOperation?: string | null;
  memoryRecordId?: string | null;
  memoryScope?: string | null;
  memoryKey?: string | null;
  memoryOperation?: string | null;
  subagentId?: string | null;
  subagentRole?: string | null;
  subagentOperation?: string | null;
  subagentLifecycleStatus?: string | null;
  subagentOutputContractStatus?: string | null;
  subagentCancellationInheritance?: string | null;
  subagentMergePolicy?: string | null;
  subagentToolPack?: string | null;
  subagentBudgetStatus?: string | null;
  subagentCostEstimateUsd?: number | null;
  subagentTokenEstimate?: number | null;
  subagentRunId?: string | null;
  subagentChildThreadId?: string | null;
  subagentRestartCount?: number | null;
  subagentInputCount?: number | null;
  subagentAssignmentCount?: number | null;
  routeId: string | null;
  reasoningEffort: string | null;
  threadId: string | null;
  turnId: string | null;
  workflowGraphId?: string | null;
  cursor: string | null;
  eventId: string | null;
  sequence: number | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  reactFlowNodeId: string;
}

export interface WorkflowRuntimeSubagentChildSubflowNodeData {
  schemaVersion: typeof WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION;
  nodeKind: "subagent_child_subflow" | "subagent_child_run";
  label: string;
  collapsed: boolean;
  status: WorkflowRuntimeTuiControlRowStatus;
  workflowGraphId: string | null;
  workflowNodeId: string;
  parentReactFlowNodeId: string;
  parentThreadId: string | null;
  parentTurnId: string | null;
  rowId: string;
  rowReactFlowNodeId: string;
  subagentId: string | null;
  subagentRole: string | null;
  subagentOperation: string | null;
  subagentLifecycleStatus: string | null;
  subagentOutputContractStatus: string | null;
  subagentCancellationInheritance: string | null;
  subagentMergePolicy: string | null;
  subagentToolPack: string | null;
  subagentBudgetStatus: string | null;
  subagentCostEstimateUsd: number | null;
  subagentTokenEstimate: number | null;
  childThreadId: string;
  childRunId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimeSubagentChildSubflowReactFlowNode {
  id: string;
  type: "runtimeSubagentSubflow" | "runtimeSubagentRun";
  parentId?: string;
  parentNode?: string;
  extent?: "parent";
  position: WorkflowRuntimeReactFlowPosition;
  data: WorkflowRuntimeSubagentChildSubflowNodeData;
}

export interface WorkflowRuntimeSubagentChildSubflowEdgeData {
  schemaVersion: typeof WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION;
  edgeKind: "subagent_parent_to_subflow" | "subagent_subflow_to_run";
  workflowGraphId: string | null;
  workflowNodeId: string;
  parentReactFlowNodeId: string;
  rowId: string;
  subagentId: string | null;
  childThreadId: string;
  childRunId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimeSubagentChildSubflowReactFlowEdge {
  id: string;
  source: string;
  target: string;
  type: "runtimeSubagentSubflowEdge";
  data: WorkflowRuntimeSubagentChildSubflowEdgeData;
}

export interface WorkflowRuntimeSubagentChildSubflowDescriptor {
  schemaVersion: typeof WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION;
  id: string;
  kind: "subagent_child_subflow";
  collapsed: boolean;
  label: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  parentReactFlowNodeId: string;
  parentThreadId: string | null;
  parentTurnId: string | null;
  rowId: string;
  rowReactFlowNodeId: string;
  subagentId: string | null;
  subagentRole: string | null;
  subagentOperation: string | null;
  subagentLifecycleStatus: string | null;
  subagentOutputContractStatus: string | null;
  subagentCancellationInheritance: string | null;
  subagentMergePolicy: string | null;
  subagentToolPack: string | null;
  subagentBudgetStatus: string | null;
  subagentCostEstimateUsd: number | null;
  subagentTokenEstimate: number | null;
  childThreadId: string;
  childRunId: string | null;
  childReactFlowNodeId: string;
  childRunReactFlowNodeId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  reactFlowGroupNode: WorkflowRuntimeSubagentChildSubflowReactFlowNode;
  reactFlowRunNode: WorkflowRuntimeSubagentChildSubflowReactFlowNode | null;
  reactFlowEdges: WorkflowRuntimeSubagentChildSubflowReactFlowEdge[];
}

export interface WorkflowRuntimeTuiControlStateProjection {
  schemaVersion: typeof WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION;
  sourceSchemaVersion: string | null;
  surface: string;
  threadId: string | null;
  workflowGraphId: string | null;
  currentTurnId: string | null;
  lastCursor: string | null;
  lastEventId: string | null;
  commandCount: number;
  validationErrorCount: number;
  approvalCount: number;
  approvalDecisionCount: number;
  jobCount: number;
  runLifecycleCount: number;
  mcpRowCount: number;
  memoryRowCount: number;
  subagentRowCount: number;
  subagentChildSubflowCount: number;
  rowCount: number;
  rows: WorkflowRuntimeTuiControlStateRow[];
  subagentChildSubflows: WorkflowRuntimeSubagentChildSubflowDescriptor[];
  subagentChildSubflowReactFlowNodes: WorkflowRuntimeSubagentChildSubflowReactFlowNode[];
  subagentChildSubflowReactFlowEdges: WorkflowRuntimeSubagentChildSubflowReactFlowEdge[];
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
  const workflowGraphId = stringField(state, "workflowGraphId", "workflow_graph_id");
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
  const jobRows = arrayField(state, "jobRows", "job_rows");
  const runLifecycleRows = arrayField(
    state,
    "runLifecycleRows",
    "run_lifecycle_rows",
  );
  const mcpRows = arrayField(state, "mcpRows", "mcp_rows");
  const memoryRows = arrayField(state, "memoryRows", "memory_rows");
  const subagentRows = arrayField(state, "subagentRows", "subagent_rows");
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
      jobId: null,
      runId: null,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
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
      jobId: null,
      runId: null,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
      threadId,
      turnId: currentTurnId,
      cursor: lastCursor,
      eventId: lastEventId,
      sequence: null,
      receiptRefs: [],
      policyDecisionRefs: [],
      reactFlowNodeId: "runtime.tui-control-state.mode-status",
    });
    const modelId = stringField(modeStatus, "requestedModel", "requested_model");
    const selectedModel = stringField(modeStatus, "selectedModel", "selected_model");
    const routeId = stringField(modeStatus, "modelRouteId", "model_route_id");
    const reasoningEffort = stringField(modeStatus, "reasoningEffort", "reasoning_effort");
    const modelNodeId =
      stringField(modeStatus, "workflowNodeId", "workflow_node_id") ??
      "runtime.model-router";
    if (modelId || selectedModel || routeId) {
      rows.push({
        id: `tui-model-route:${slug(threadId ?? "detached")}`,
        rowKind: "model_route",
        status: "current",
        label: "Model route",
        command: "model",
        rawInput: "/model",
        message: [modelId, selectedModel, routeId].filter(Boolean).join(" · ") || null,
        approvalId: null,
        jobId: null,
        runId: null,
        modelId: modelId ?? selectedModel ?? null,
        routeId,
        reasoningEffort,
        threadId,
        turnId: currentTurnId,
        cursor: lastCursor,
        eventId: lastEventId,
        sequence: null,
        receiptRefs: stringArrayField(modeStatus, "receiptRefs", "receipt_refs"),
        policyDecisionRefs: [],
        reactFlowNodeId: modelNodeId,
      });
    }
    if (reasoningEffort) {
      rows.push({
        id: `tui-thinking:${slug(threadId ?? "detached")}`,
        rowKind: "thinking",
        status: "current",
        label: "Thinking",
        command: "thinking",
        rawInput: "/thinking",
        message: reasoningEffort,
        approvalId: null,
        jobId: null,
        runId: null,
        modelId: modelId ?? selectedModel ?? null,
        routeId,
        reasoningEffort,
        threadId,
        turnId: currentTurnId,
        cursor: lastCursor,
        eventId: lastEventId,
        sequence: null,
        receiptRefs: stringArrayField(modeStatus, "receiptRefs", "receipt_refs"),
        policyDecisionRefs: [],
        reactFlowNodeId: `${modelNodeId}.thinking`,
      });
    }
  }

  mcpRows.forEach((entry, index) => {
    const declaredKind = stringField(entry, "rowKind", "row_kind");
    const rowKind: "mcp_server" | "mcp_tool" | "mcp_resource" | "mcp_prompt" =
      declaredKind === "mcp_tool"
        ? "mcp_tool"
        : declaredKind === "mcp_resource"
          ? "mcp_resource"
          : declaredKind === "mcp_prompt"
            ? "mcp_prompt"
            : "mcp_server";
    const serverId = stringField(entry, "mcpServerId", "mcp_server_id");
    const toolName = stringField(entry, "mcpToolName", "mcp_tool_name");
    const toolCallId = stringField(entry, "mcpToolCallId", "mcp_tool_call_id");
    const resourceUri = stringField(entry, "mcpResourceUri", "mcp_resource_uri");
    const promptName = stringField(entry, "mcpPromptName", "mcp_prompt_name");
    const mcpOperation =
      stringField(entry, "mcpOperation", "mcp_operation") ??
      (toolCallId
        ? "invoke"
        : rowKind === "mcp_tool"
          ? "catalog"
          : rowKind === "mcp_resource"
            ? "resource_catalog"
            : rowKind === "mcp_prompt"
              ? "prompt_catalog"
              : "status");
    const status = tuiControlRowStatus(stringField(entry, "status"));
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    const fallbackNodeId = rowKind === "mcp_tool" && serverId && toolName
      ? `runtime.mcp-tool.${slug(serverId)}.${slug(toolName)}`
      : rowKind === "mcp_resource" && serverId && resourceUri
        ? `runtime.mcp-resource.${slug(serverId)}.${slug(resourceUri)}`
        : rowKind === "mcp_prompt" && serverId && promptName
          ? `runtime.mcp-prompt.${slug(serverId)}.${slug(promptName)}`
          : "runtime.mcp-manager";
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-${rowKind}:${slug([serverId, toolName, resourceUri, promptName, sequence].filter(Boolean).join(":"))}`,
      rowKind,
      status,
      label:
        stringField(entry, "label") ??
        (rowKind === "mcp_tool"
          ? `MCP tool ${[serverId, toolName].filter(Boolean).join(".") || sequence}`
          : rowKind === "mcp_resource"
            ? `MCP resource ${[serverId, resourceUri].filter(Boolean).join(" · ") || sequence}`
            : rowKind === "mcp_prompt"
              ? `MCP prompt ${[serverId, promptName].filter(Boolean).join(".") || sequence}`
          : `MCP server ${serverId ?? sequence}`),
      command: stringField(entry, "command") ?? "mcp",
      rawInput: stringField(entry, "rawInput", "raw_input") ?? "/mcp",
      message:
        stringField(entry, "message", "summary") ??
        ([serverId, toolName, status].filter(Boolean).join(" · ") || null),
      approvalId: null,
      jobId: null,
      runId: null,
      modelId: null,
      mcpServerId: serverId,
      mcpToolName: toolName,
      mcpToolCallId: toolCallId,
      mcpResourceUri: resourceUri,
      mcpPromptName: promptName,
      mcpOperation,
      routeId: null,
      reasoningEffort: null,
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
        fallbackNodeId,
    });
  });

  memoryRows.forEach((entry, index) => {
    const declaredKind = stringField(entry, "rowKind", "row_kind");
    const rowKind: "memory_status" | "memory_policy" | "memory_record" =
      declaredKind === "memory_record"
        ? "memory_record"
        : declaredKind === "memory_policy"
          ? "memory_policy"
          : "memory_status";
    const memoryRecordId = stringField(entry, "memoryRecordId", "memory_record_id");
    const memoryScope = stringField(entry, "memoryScope", "memory_scope");
    const memoryKey = stringField(entry, "memoryKey", "memory_key");
    const memoryOperation =
      stringField(entry, "memoryOperation", "memory_operation") ??
      (rowKind === "memory_record" ? "read" : rowKind === "memory_policy" ? "policy" : "status");
    const status = tuiControlRowStatus(stringField(entry, "status"));
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    const fallbackNodeId = rowKind === "memory_record" && memoryRecordId
      ? `runtime.memory.${slug(memoryRecordId)}`
      : rowKind === "memory_policy"
        ? "runtime.memory-manager.policy"
        : "runtime.memory-manager";
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-${rowKind}:${slug([memoryRecordId, memoryScope, memoryKey, sequence].filter(Boolean).join(":"))}`,
      rowKind,
      status,
      label:
        stringField(entry, "label") ??
        (rowKind === "memory_record"
          ? `Memory record ${memoryRecordId ?? sequence}`
          : rowKind === "memory_policy"
            ? "Memory policy"
            : "Memory status"),
      command: stringField(entry, "command") ?? "memory",
      rawInput: stringField(entry, "rawInput", "raw_input") ?? "/memory status",
      message:
        stringField(entry, "message", "summary") ??
        ([memoryOperation, memoryScope, memoryKey, status].filter(Boolean).join(" · ") || null),
      approvalId: null,
      jobId: null,
      runId: null,
      modelId: null,
      mcpServerId: null,
      mcpToolName: null,
      memoryRecordId,
      memoryScope,
      memoryKey,
      memoryOperation,
      routeId: null,
      reasoningEffort: null,
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
        fallbackNodeId,
    });
  });

  subagentRows.forEach((entry, index) => {
    const subagentId = stringField(entry, "subagentId", "subagent_id");
    const role = stringField(entry, "subagentRole", "subagent_role", "role") ?? "general";
    const operation =
      stringField(entry, "subagentOperation", "subagent_operation") ??
      stringField(entry, "operation") ??
      "list";
    const lifecycleStatus =
      stringField(entry, "subagentLifecycleStatus", "subagent_lifecycle_status") ??
      stringField(entry, "lifecycleStatus", "lifecycle_status") ??
      stringField(entry, "status");
    const outputContractStatus =
      stringField(
        entry,
        "subagentOutputContractStatus",
        "subagent_output_contract_status",
        "outputContractStatus",
        "output_contract_status",
      ) ?? stringField(recordField(entry, "outputContractStatus", "output_contract_status"), "status");
    const cancellationInheritance = stringField(
      entry,
      "subagentCancellationInheritance",
      "subagent_cancellation_inheritance",
      "cancellationInheritance",
      "cancellation_inheritance",
    );
    const mergePolicy = stringField(
      entry,
      "subagentMergePolicy",
      "subagent_merge_policy",
      "mergePolicy",
      "merge_policy",
    );
    const toolPack = stringField(
      entry,
      "subagentToolPack",
      "subagent_tool_pack",
      "toolPack",
      "tool_pack",
    );
    const budgetStatusRecord = recordField(entry, "budgetStatus", "budget_status");
    const usageTelemetryRecord =
      recordField(entry, "usageTelemetry", "usage_telemetry") ??
      recordField(budgetStatusRecord, "usage");
    const subagentBudgetStatus =
      stringField(
        entry,
        "subagentBudgetStatus",
        "subagent_budget_status",
        "budgetStatus",
        "budget_status",
      ) ?? stringField(budgetStatusRecord, "status");
    const subagentCostEstimateUsd =
      numberField(
        entry,
        "subagentCostEstimateUsd",
        "subagent_cost_estimate_usd",
        "costEstimateUsd",
        "cost_estimate_usd",
      ) ??
      numberField(
        usageTelemetryRecord,
        "cumulativeCostEstimateUsd",
        "cumulative_cost_estimate_usd",
        "costEstimateUsd",
        "cost_estimate_usd",
      );
    const subagentTokenEstimate =
      numberField(
        entry,
        "subagentTokenEstimate",
        "subagent_token_estimate",
        "tokenEstimate",
        "token_estimate",
      ) ??
      numberField(
        usageTelemetryRecord,
        "cumulativeTotalTokens",
        "cumulative_total_tokens",
        "totalTokens",
        "total_tokens",
      );
    const subagentRunId =
      stringField(entry, "subagentRunId", "subagent_run_id") ??
      stringField(entry, "runId", "run_id");
    const subagentChildThreadId = stringField(
      entry,
      "subagentChildThreadId",
      "subagent_child_thread_id",
      "childThreadId",
      "child_thread_id",
    );
    const status = tuiControlRowStatus(lifecycleStatus);
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    const fallbackNodeId = `runtime.subagent.${slug(operation)}.${slug(role ?? subagentId ?? String(sequence))}`;
    const rowWorkflowGraphId =
      stringField(entry, "workflowGraphId", "workflow_graph_id") ??
      workflowGraphId;
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-subagent:${slug(subagentId ?? `${role}:${sequence}`)}`,
      rowKind: "subagent",
      status,
      label: subagentId ? `Subagent ${role}` : "Subagent",
      command: stringField(entry, "command") ?? "subagent",
      rawInput:
        stringField(entry, "rawInput", "raw_input") ??
        `/subagent ${operation}`,
      message:
        stringField(entry, "message", "summary") ??
        ([role, operation, outputContractStatus].filter(Boolean).join(" · ") || null),
      approvalId: null,
      jobId: null,
      runId: subagentRunId,
      modelId: null,
      routeId:
        stringField(entry, "modelRouteId", "model_route_id") ??
        stringField(entry, "routeId", "route_id"),
      reasoningEffort: null,
      subagentId,
      subagentRole: role,
      subagentOperation: operation,
      subagentLifecycleStatus: lifecycleStatus ?? null,
      subagentOutputContractStatus: outputContractStatus ?? null,
      subagentCancellationInheritance: cancellationInheritance,
      subagentMergePolicy: mergePolicy,
      subagentToolPack: toolPack,
      subagentBudgetStatus: subagentBudgetStatus ?? null,
      subagentCostEstimateUsd: subagentCostEstimateUsd ?? null,
      subagentTokenEstimate: subagentTokenEstimate ?? null,
      subagentRunId,
      subagentChildThreadId,
      subagentRestartCount: numberField(
        entry,
        "subagentRestartCount",
        "subagent_restart_count",
        "restartCount",
        "restart_count",
      ),
      subagentInputCount: numberField(
        entry,
        "subagentInputCount",
        "subagent_input_count",
        "inputCount",
        "input_count",
      ),
      subagentAssignmentCount: numberField(
        entry,
        "subagentAssignmentCount",
        "subagent_assignment_count",
        "assignmentCount",
        "assignment_count",
      ),
      threadId:
        stringField(entry, "threadId", "thread_id", "parentThreadId", "parent_thread_id") ??
        threadId,
      turnId:
        stringField(entry, "turnId", "turn_id", "parentTurnId", "parent_turn_id") ??
        currentTurnId,
      workflowGraphId: rowWorkflowGraphId,
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
        fallbackNodeId,
    });
  });

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
      jobId: null,
      runId: null,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
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
      jobId: null,
      runId: null,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
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

  jobRows.forEach((entry, index) => {
    const jobId = stringField(entry, "jobId", "job_id");
    const runId = stringField(entry, "runId", "run_id");
    const status = tuiControlRowStatus(stringField(entry, "status"));
    const progress =
      stringField(entry, "progressPercent", "progress_percent") ??
      stringField(recordField(entry, "progress"), "percent");
    const queueName = stringField(entry, "queueName", "queue_name");
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    rows.push({
      id: stringField(entry, "id") ?? `tui-job:${jobId ?? sequence}`,
      rowKind: "job",
      status,
      label: jobId ? `Job ${jobId}` : "Runtime job",
      command: "jobs",
      rawInput: "/jobs",
      message: [runId, queueName, progress ? `${progress}%` : null]
        .filter(Boolean)
        .join(" · ") || null,
      approvalId: null,
      jobId,
      runId,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
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
        "runtime.runtime-job",
    });
  });

  runLifecycleRows.forEach((entry, index) => {
    const runId = stringField(entry, "runId", "run_id");
    const jobId = stringField(entry, "jobId", "job_id");
    const status = tuiControlRowStatus(stringField(entry, "status"));
    const progress =
      stringField(entry, "progressPercent", "progress_percent") ??
      stringField(recordField(entry, "progress"), "percent");
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    rows.push({
      id: stringField(entry, "id") ?? `tui-run-lifecycle:${runId ?? sequence}`,
      rowKind: "run_lifecycle",
      status,
      label: runId ? `Run ${runId}` : "Run lifecycle",
      command: "run",
      rawInput: "/run",
      message: [jobId, progress ? `${progress}%` : null].filter(Boolean).join(" · ") || null,
      approvalId: null,
      jobId,
      runId,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
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
        `runtime.run-lifecycle.${slug(runId ?? String(sequence))}`,
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
      jobId: stringField(entry, "jobId", "job_id"),
      runId: stringField(entry, "runId", "run_id"),
      modelId: stringField(entry, "modelId", "model_id"),
      routeId: stringField(entry, "routeId", "route_id"),
      reasoningEffort: stringField(entry, "reasoningEffort", "reasoning_effort"),
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
      jobId: stringField(entry, "jobId", "job_id"),
      runId: stringField(entry, "runId", "run_id"),
      modelId: stringField(entry, "modelId", "model_id"),
      routeId: stringField(entry, "routeId", "route_id"),
      reasoningEffort: stringField(entry, "reasoningEffort", "reasoning_effort"),
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

  const subagentChildSubflows = subagentChildSubflowsForRows(rows);
  const subagentChildSubflowReactFlowNodes = subagentChildSubflows.flatMap(
    (subflow) =>
      subflow.reactFlowRunNode
        ? [subflow.reactFlowGroupNode, subflow.reactFlowRunNode]
        : [subflow.reactFlowGroupNode],
  );
  const subagentChildSubflowReactFlowEdges = subagentChildSubflows.flatMap(
    (subflow) => subflow.reactFlowEdges,
  );

  return {
    schemaVersion: WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    sourceSchemaVersion: stringField(state, "schemaVersion", "schema_version"),
    surface: stringField(state, "surface") ?? "tui",
    threadId,
    workflowGraphId,
    currentTurnId,
    lastCursor,
    lastEventId,
    commandCount: commandHistory.length,
    validationErrorCount: validationErrors.length,
    approvalCount: approvalRows.length,
    approvalDecisionCount: approvalDecisions.length,
    jobCount: jobRows.length,
    runLifecycleCount: runLifecycleRows.length,
    mcpRowCount: mcpRows.length,
    memoryRowCount: memoryRows.length,
    subagentRowCount: subagentRows.length,
    subagentChildSubflowCount: subagentChildSubflows.length,
    rowCount: rows.length,
    rows,
    subagentChildSubflows,
    subagentChildSubflowReactFlowNodes,
    subagentChildSubflowReactFlowEdges,
  };
}

function subagentChildSubflowsForRows(
  rows: readonly WorkflowRuntimeTuiControlStateRow[],
): WorkflowRuntimeSubagentChildSubflowDescriptor[] {
  const rowsBySubflowKey = new Map<string, WorkflowRuntimeTuiControlStateRow>();
  for (const row of rows) {
    if (row.rowKind !== "subagent" || !row.subagentChildThreadId) continue;
    const subflowKey = [
      row.subagentId ?? "detached",
      row.subagentChildThreadId,
      row.subagentRunId ?? "runless",
    ].join(":");
    rowsBySubflowKey.set(subflowKey, row);
  }

  return Array.from(rowsBySubflowKey.values()).map((row, index) => {
    const childThreadId = row.subagentChildThreadId as string;
    const subagentKey = slug(row.subagentId ?? childThreadId ?? row.id);
    const runKey = row.subagentRunId ? slug(row.subagentRunId) : null;
    const groupNodeId = `runtime.subagent-subflow.${subagentKey}`;
    const runNodeId = runKey ? `${groupNodeId}.run.${runKey}` : null;
    const parentReactFlowNodeId = row.reactFlowNodeId;
    const workflowGraphId = row.workflowGraphId ?? null;
    const label = `Subagent ${row.subagentRole ?? row.subagentId ?? childThreadId}`;
    const baseData: Omit<
      WorkflowRuntimeSubagentChildSubflowNodeData,
      "nodeKind" | "label"
    > = {
      schemaVersion: WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
      collapsed: true,
      status: row.status,
      workflowGraphId,
      workflowNodeId: parentReactFlowNodeId,
      parentReactFlowNodeId,
      parentThreadId: row.threadId,
      parentTurnId: row.turnId,
      rowId: row.id,
      rowReactFlowNodeId: row.reactFlowNodeId,
      subagentId: row.subagentId ?? null,
      subagentRole: row.subagentRole ?? null,
      subagentOperation: row.subagentOperation ?? null,
      subagentLifecycleStatus: row.subagentLifecycleStatus ?? null,
      subagentOutputContractStatus: row.subagentOutputContractStatus ?? null,
      subagentCancellationInheritance: row.subagentCancellationInheritance ?? null,
      subagentMergePolicy: row.subagentMergePolicy ?? null,
      subagentToolPack: row.subagentToolPack ?? null,
      subagentBudgetStatus: row.subagentBudgetStatus ?? null,
      subagentCostEstimateUsd: row.subagentCostEstimateUsd ?? null,
      subagentTokenEstimate: row.subagentTokenEstimate ?? null,
      childThreadId,
      childRunId: row.subagentRunId ?? null,
      receiptRefs: row.receiptRefs,
      policyDecisionRefs: row.policyDecisionRefs,
    };
    const reactFlowGroupNode: WorkflowRuntimeSubagentChildSubflowReactFlowNode = {
      id: groupNodeId,
      type: "runtimeSubagentSubflow",
      parentId: parentReactFlowNodeId,
      parentNode: parentReactFlowNodeId,
      extent: "parent",
      position: {
        x: 28,
        y: 96 + index * 120,
      },
      data: {
        ...baseData,
        nodeKind: "subagent_child_subflow",
        label,
      },
    };
    const reactFlowRunNode: WorkflowRuntimeSubagentChildSubflowReactFlowNode | null =
      runNodeId
        ? {
            id: runNodeId,
            type: "runtimeSubagentRun",
            parentId: groupNodeId,
            parentNode: groupNodeId,
            extent: "parent",
            position: {
              x: 24,
              y: 52,
            },
            data: {
              ...baseData,
              nodeKind: "subagent_child_run",
              label: `Run ${row.subagentRunId}`,
            },
          }
        : null;
    const edgeData: Omit<
      WorkflowRuntimeSubagentChildSubflowEdgeData,
      "edgeKind"
    > = {
      schemaVersion: WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
      workflowGraphId,
      workflowNodeId: parentReactFlowNodeId,
      parentReactFlowNodeId,
      rowId: row.id,
      subagentId: row.subagentId ?? null,
      childThreadId,
      childRunId: row.subagentRunId ?? null,
      receiptRefs: row.receiptRefs,
      policyDecisionRefs: row.policyDecisionRefs,
    };
    const reactFlowEdges: WorkflowRuntimeSubagentChildSubflowReactFlowEdge[] = [
      {
        id: `runtime-subagent-subflow:${slug(`${parentReactFlowNodeId}->${groupNodeId}`)}`,
        source: parentReactFlowNodeId,
        target: groupNodeId,
        type: "runtimeSubagentSubflowEdge",
        data: {
          ...edgeData,
          edgeKind: "subagent_parent_to_subflow",
        },
      },
    ];
    if (runNodeId) {
      reactFlowEdges.push({
        id: `runtime-subagent-subflow:${slug(`${groupNodeId}->${runNodeId}`)}`,
        source: groupNodeId,
        target: runNodeId,
        type: "runtimeSubagentSubflowEdge",
        data: {
          ...edgeData,
          edgeKind: "subagent_subflow_to_run",
        },
      });
    }

    return {
      schemaVersion: WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
      id: groupNodeId,
      kind: "subagent_child_subflow",
      collapsed: true,
      label,
      workflowGraphId,
      workflowNodeId: parentReactFlowNodeId,
      parentReactFlowNodeId,
      parentThreadId: row.threadId,
      parentTurnId: row.turnId,
      rowId: row.id,
      rowReactFlowNodeId: row.reactFlowNodeId,
      subagentId: row.subagentId ?? null,
      subagentRole: row.subagentRole ?? null,
      subagentOperation: row.subagentOperation ?? null,
      subagentLifecycleStatus: row.subagentLifecycleStatus ?? null,
      subagentOutputContractStatus: row.subagentOutputContractStatus ?? null,
      subagentCancellationInheritance: row.subagentCancellationInheritance ?? null,
      subagentMergePolicy: row.subagentMergePolicy ?? null,
      subagentToolPack: row.subagentToolPack ?? null,
      subagentBudgetStatus: row.subagentBudgetStatus ?? null,
      subagentCostEstimateUsd: row.subagentCostEstimateUsd ?? null,
      subagentTokenEstimate: row.subagentTokenEstimate ?? null,
      childThreadId,
      childRunId: row.subagentRunId ?? null,
      childReactFlowNodeId: groupNodeId,
      childRunReactFlowNodeId: runNodeId,
      receiptRefs: row.receiptRefs,
      policyDecisionRefs: row.policyDecisionRefs,
      reactFlowGroupNode,
      reactFlowRunNode,
      reactFlowEdges,
    };
  });
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
  if (event.componentKind === "lsp_diagnostics_repair") return "hook_policy";
  if (event.componentKind === "lsp_diagnostics_repair_retry") return "hook_policy";
  if (event.componentKind === "lsp_diagnostics_operator_override") return "hook_policy";
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
    diagnosticsRepairActions: diagnosticsRepairActionsForEvents(
      events,
      latestEvent,
    ),
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
  if (event.componentKind === "restore_gate") {
    return event.eventKind === "workspace.restore.applied" || event.sourceEventKind === "WorkspaceRestore.Applied"
      ? "Restore apply"
      : "Restore preview";
  }
  if (event.componentKind === "lsp_diagnostics") return "Diagnostics injected";
  if (event.componentKind === "lsp_diagnostics_gate") return "Diagnostics blocking gate";
  if (event.componentKind === "lsp_diagnostics_repair") return "Diagnostics repair decision";
  if (event.componentKind === "lsp_diagnostics_repair_retry") return "Diagnostics repair retry";
  if (event.componentKind === "lsp_diagnostics_operator_override") return "Diagnostics operator override";
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
  ...keys: string[]
): string | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = keys.find((key) => objectValue[key] !== undefined);
  const valueForKey = candidate ? objectValue[candidate] : undefined;
  return typeof valueForKey === "string" && valueForKey.trim()
    ? valueForKey
    : null;
}

function numberField(
  value: unknown,
  ...keys: string[]
): number | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = keys.find((key) => objectValue[key] !== undefined);
  const valueForKey = candidate ? objectValue[candidate] : undefined;
  if (typeof valueForKey === "number" && Number.isFinite(valueForKey)) {
    return valueForKey;
  }
  if (typeof valueForKey === "string" && valueForKey.trim()) {
    const parsed = Number(valueForKey);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function arrayField(
  value: unknown,
  ...keys: string[]
): unknown[] {
  const objectValue = objectField(value);
  if (!objectValue) return [];
  const candidate = keys.find((key) => objectValue[key] !== undefined);
  const valueForKey = candidate ? objectValue[candidate] : undefined;
  return Array.isArray(valueForKey) ? valueForKey : [];
}

function recordField(
  value: unknown,
  ...keys: string[]
): Record<string, unknown> | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = keys.find((key) => objectValue[key] !== undefined);
  return objectField(candidate ? objectValue[candidate] : undefined);
}

function stringArrayField(
  value: unknown,
  ...keys: string[]
): string[] {
  return arrayField(value, ...keys).filter(
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
  if (normalizedStatus === "ready" || normalizedStatus === "configured") {
    return "completed";
  }
  if (normalizedStatus?.includes("waiting")) return "pending";
  if (normalizedStatus?.includes("approved")) return "approved";
  if (normalizedStatus?.includes("rejected") || normalizedStatus?.includes("denied")) {
    return "rejected";
  }
  switch (normalizedStatus) {
    case "current":
    case "queued":
    case "running":
    case "waiting":
    case "completed":
    case "canceled":
    case "interrupted":
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
