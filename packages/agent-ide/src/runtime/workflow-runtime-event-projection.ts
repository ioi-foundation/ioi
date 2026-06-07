import type { WorkflowNodeKind } from "../types/graph";
import {
  workflowCodingToolBudgetRecoveryPolicyFromUnknown,
  type WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor,
} from "./workflow-runtime-coding-tool-budget-recovery-policy";
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
export const WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION =
  "ioi.workflow.coding-tool-budget-recovery.v1" as const;
export const WORKFLOW_RUNTIME_COMPUTER_USE_PROJECTION_SCHEMA_VERSION =
  "ioi.workflow.computer-use-projection.v1" as const;

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
  | "context_budget_evaluated"
  | "compaction_policy_evaluated"
  | "usage_delta"
  | "context_pressure_delta"
  | "context_pressure_alert"
  | "workspace_trust_warning"
  | "workspace_trust_acknowledged"
  | "workflow_edit_proposed"
  | "workflow_edit_applied"
  | "reasoning_delta"
  | "tool_completed"
  | "tool_failed"
  | "approval_required"
  | "approval_decision"
  | "policy_blocked"
  | "receipt_emitted"
  | "model_route_decision"
  | "tool_route_decision"
  | "computer_use_environment_selected"
  | "computer_use_environment_unavailable"
  | "computer_use_lease_acquired"
  | "computer_use_run_state"
  | "computer_use_observation"
  | "computer_use_affordance_graph"
  | "computer_use_browser_discovery"
  | "computer_use_action_proposed"
  | "computer_use_action_executed"
  | "computer_use_verification"
  | "computer_use_commit_gate"
  | "computer_use_trajectory_written"
  | "computer_use_cleanup"
  | "runtime_step";

export type WorkflowRuntimeProjectedStatus =
  | "queued"
  | "running"
  | "waiting"
  | "warning"
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
  toolCallId: string | null;
  approvalId: string | null;
  agentStatus: string | null;
  summary: string | null;
  codingToolBudgetStatus: string | null;
  codingToolBudgetReason: string | null;
  codingToolContextBudgetStatus: string | null;
  codingToolBudgetMode: string | null;
  codingToolBudgetDecisionId: string | null;
  codingToolBudgetCheckCount: number | null;
  codingToolBudgetViolationCount: number | null;
  codingToolBudgetChecks: unknown[];
  codingToolBudgetViolations: unknown[];
  codingToolBudgetUsageTelemetry: Record<string, unknown> | null;
  codingToolMutationBlocked: boolean | null;
  codingToolBudgetRecoveryActions: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor[];
  diagnosticsRepairActions: WorkflowRuntimeDiagnosticsRepairActionDescriptor[];
  contextPressureActions: WorkflowRuntimeContextPressureActionDescriptor[];
  workspaceTrustActions: WorkflowRuntimeWorkspaceTrustActionDescriptor[];
  computerUse: WorkflowRuntimeComputerUseProjection | null;
  tuiDeepLink: WorkflowRuntimeTuiDeepLinkDescriptor;
}

export interface WorkflowRuntimeComputerUseProjection {
  schemaVersion: typeof WORKFLOW_RUNTIME_COMPUTER_USE_PROJECTION_SCHEMA_VERSION;
  step: string | null;
  lane: string | null;
  sessionMode: string | null;
  leaseId: string | null;
  contractIngest: string | null;
  status: WorkflowRuntimeProjectedStatus;
  blocker: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  workflowNodeIds: string[];
  toolRef: string | null;
  authorityScopes: string[];
  failClosedWhenUnavailable: boolean | null;
  observationRef: string | null;
  screenRef: string | null;
  somRef: string | null;
  coordinateSpaceId: string | null;
  targetIndexRef: string | null;
  affordanceGraphRef: string | null;
  browserDiscoveryRef: string | null;
  browserProcessCount: number | null;
  cdpEndpointCount: number | null;
  defaultProfileBlockerCount: number | null;
  controlledRelaunchLaunchRef: string | null;
  controlledRelaunchLaunchStatus: string | null;
  controlledRelaunchProcessRef: string | null;
  controlledRelaunchProfileDirRef: string | null;
  controlledRelaunchEndpointRef: string | null;
  controlledRelaunchApprovalRef: string | null;
  proposalRef: string | null;
  actionRef: string | null;
  actionKind: string | null;
  actionReceiptRef: string | null;
  executionRef: string | null;
  executionStatus: string | null;
  executionAdapterId: string | null;
  executionProviderId: string | null;
  executionPreflightStatus: string | null;
  executionRequiresReobserve: boolean | null;
  targetRef: string | null;
  policyDecisionRef: string | null;
  policyOutcome: string | null;
  policyAuthorityScope: string | null;
  policyApprovalRef: string | null;
  policyExternalEffect: boolean | null;
  policyFailClosed: boolean | null;
  verificationRef: string | null;
  verificationStatus: string | null;
  commitGateRef: string | null;
  commitGateStatus: string | null;
  outcomeRef: string | null;
  humanHandoffRef: string | null;
  trajectoryRef: string | null;
  cleanupRef: string | null;
  cleanupStatus: string | null;
  retentionMode: string | null;
  riskPosture: string | null;
  authorityRequired: string | null;
  targetCount: number | null;
  affordanceCount: number | null;
  detectedPatterns: string[];
  visualTargetRefs: string[];
  visualTargetSummaries: WorkflowRuntimeComputerUseVisualTargetSummary[];
  recoveryPolicy: Record<string, unknown> | null;
  outcomeContract: Record<string, unknown> | null;
  commitGate: Record<string, unknown> | null;
  humanHandoffState: Record<string, unknown> | null;
}

export interface WorkflowRuntimeComputerUseVisualTargetSummary {
  targetRef: string;
  label: string | null;
  role: string | null;
  somId: number | null;
  confidence: number | null;
  bounds: WorkflowRuntimeComputerUseVisualTargetBounds | null;
  boundsSummary: string | null;
  availableActions: string[];
}

export interface WorkflowRuntimeComputerUseVisualTargetBounds {
  x: number;
  y: number;
  width: number;
  height: number;
  coordinateSpaceId: string | null;
}

export type WorkflowRuntimeCodingToolBudgetRecoveryAction =
  | "review_receipt"
  | "request_approval"
  | "approve_override"
  | "reject_override"
  | "retry_approved";

export interface WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor {
  id: string;
  schemaVersion: typeof WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION;
  action: WorkflowRuntimeCodingToolBudgetRecoveryAction;
  label: string;
  summary: string | null;
  status: string;
  executable: boolean;
  runId: string | null;
  threadId: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventId: string;
  sourceEventId: string | null;
  approvalId: string | null;
  approvalRequestEventId: string | null;
  approvalDecisionEventId: string | null;
  targetNodeIds: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
  recoveryPolicy: WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor | null;
}

export type WorkflowRuntimeContextPressureAction =
  | "compact"
  | "stop"
  | "request_approval"
  | "delegate_summary";

export interface WorkflowRuntimeContextPressureActionDescriptor {
  id: string;
  action: WorkflowRuntimeContextPressureAction | string;
  label: string;
  summary: string | null;
  status: string;
  executable: boolean;
  scope: string;
  pressure: number | null;
  pressureStatus: string | null;
  threadId: string;
  turnId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventId: string;
  sourceEventId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export type WorkflowRuntimeWorkspaceTrustAction = "acknowledge";

export interface WorkflowRuntimeWorkspaceTrustActionDescriptor {
  id: string;
  action: WorkflowRuntimeWorkspaceTrustAction;
  label: string;
  summary: string | null;
  status: string;
  executable: boolean;
  warningId: string;
  severity: string | null;
  mode: string | null;
  approvalMode: string | null;
  threadId: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  eventId: string;
  sourceEventId: string | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
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
  | "usage_status"
  | "cost_status"
  | "context_budget"
  | "compaction_policy"
  | "coding_tool"
  | "coding_tool_budget"
  | "workspace_trust_warning"
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
  | "warning"
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
  workspaceTrustRows?: unknown[];
  workspace_trust_rows?: unknown[];
  approvalDecisions?: unknown[];
  approval_decisions?: unknown[];
  jobRows?: unknown[];
  job_rows?: unknown[];
  runLifecycleRows?: unknown[];
  run_lifecycle_rows?: unknown[];
  costRows?: unknown[];
  cost_rows?: unknown[];
  contextRows?: unknown[];
  context_rows?: unknown[];
  codingToolRows?: unknown[];
  coding_tool_rows?: unknown[];
  mcpRows?: unknown[];
  mcp_rows?: unknown[];
  memoryRows?: unknown[];
  memory_rows?: unknown[];
  usageStatus?: unknown;
  usage_status?: unknown;
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
  toolName?: string | null;
  toolCallId?: string | null;
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
  usageScope?: string | null;
  usageTotalTokens?: number | null;
  usageInputTokens?: number | null;
  usageOutputTokens?: number | null;
  usageCostEstimateUsd?: number | null;
  usageContextPressure?: number | null;
  usageContextPressureStatus?: string | null;
  usageRunCount?: number | null;
  usageSubagentCount?: number | null;
  contextBudgetStatus?: string | null;
  contextBudgetMode?: string | null;
  contextBudgetDecisionId?: string | null;
  codingToolBudgetStatus?: string | null;
  codingToolBudgetReason?: string | null;
  codingToolContextBudgetStatus?: string | null;
  codingToolBudgetMode?: string | null;
  codingToolBudgetDecisionId?: string | null;
  codingToolBudgetCheckCount?: number | null;
  codingToolBudgetViolationCount?: number | null;
  codingToolBudgetUsageTotalTokens?: number | null;
  codingToolBudgetUsageCostEstimateUsd?: number | null;
  codingToolBudgetUsageContextPressure?: number | null;
  codingToolMutationBlocked?: boolean | null;
  codingToolShellFallbackUsed?: boolean | null;
  codingToolDryRun?: boolean | null;
  compactionPolicyStatus?: string | null;
  compactionPolicyAction?: string | null;
  compactionPolicyDecisionId?: string | null;
  compactionExecuted?: boolean | null;
  workspaceTrustWarningId?: string | null;
  workspaceTrustStatus?: string | null;
  workspaceTrustSeverity?: string | null;
  workspaceTrustProfile?: string | null;
  workspaceTrustMode?: string | null;
  workspaceTrustApprovalMode?: string | null;
  workspaceTrustDirty?: boolean | null;
  workspaceTrustWarningReasons?: string[];
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
  artifactRefs?: string[];
  policyDecisionRefs: string[];
  rollbackRefs?: string[];
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
  costRowCount: number;
  contextRowCount: number;
  codingToolRowCount: number;
  codingToolBudgetRowCount: number;
  workspaceTrustWarningCount: number;
  mcpRowCount: number;
  memoryRowCount: number;
  usageRowCount: number;
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

interface CodingToolBudgetEvidence {
  isBudgetBlock: boolean;
  toolName: string | null;
  toolCallId: string | null;
  reason: string | null;
  budgetStatus: string | null;
  contextBudgetStatus: string | null;
  budgetMode: string | null;
  budgetDecisionId: string | null;
  checkCount: number | null;
  violationCount: number | null;
  checks: unknown[];
  violations: unknown[];
  usageTelemetry: Record<string, unknown> | null;
  usageTotalTokens: number | null;
  usageCostEstimateUsd: number | null;
  usageContextPressure: number | null;
  mutationBlocked: boolean | null;
  receiptRefs: string[];
  policyDecisionRefs: string[];
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
  const workspaceTrustRows = arrayField(
    state,
    "workspaceTrustRows",
    "workspace_trust_rows",
  );
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
  const costRows = arrayField(state, "costRows", "cost_rows");
  const contextRows = arrayField(state, "contextRows", "context_rows");
  const codingToolRows = arrayField(state, "codingToolRows", "coding_tool_rows");
  const mcpRows = arrayField(state, "mcpRows", "mcp_rows");
  const memoryRows = arrayField(state, "memoryRows", "memory_rows");
  const usageStatus = recordField(state, "usageStatus", "usage_status");
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

  workspaceTrustRows.forEach((entry, index) => {
    const warningId = stringField(entry, "warningId", "warning_id");
    const mode = stringField(entry, "mode", "thread_mode");
    const approvalMode = stringField(entry, "approvalMode", "approval_mode");
    const severity = stringField(entry, "severity") ?? "warning";
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    const status = tuiControlRowStatus(stringField(entry, "status") ?? severity);
    const rowThreadId = stringField(entry, "threadId", "thread_id") ?? threadId;
    const warningReasons = stringArrayField(
      entry,
      "warningReasons",
      "warning_reasons",
    );
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-workspace-trust:${slug(warningId ?? `${rowThreadId ?? "detached"}-${sequence}`)}`,
      rowKind: "workspace_trust_warning",
      status,
      label: "Workspace trust warning",
      command: "mode",
      rawInput: mode ? `/mode ${mode}` : "/mode",
      message:
        stringField(entry, "message", "summary") ??
        [mode, approvalMode, severity, ...warningReasons].filter(Boolean).join(" · "),
      approvalId: null,
      jobId: null,
      runId: null,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
      workspaceTrustWarningId: warningId,
      workspaceTrustStatus: stringField(entry, "status"),
      workspaceTrustSeverity: severity,
      workspaceTrustProfile: stringField(entry, "trustProfile", "trust_profile"),
      workspaceTrustMode: mode,
      workspaceTrustApprovalMode: approvalMode,
      workspaceTrustDirty: booleanField(entry, "dirty", "isDirty", "is_dirty"),
      workspaceTrustWarningReasons: warningReasons,
      threadId: rowThreadId,
      turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
      workflowGraphId:
        stringField(entry, "workflowGraphId", "workflow_graph_id") ??
        workflowGraphId,
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
        "runtime.workspace-trust",
    });
  });

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

  if (usageStatus) {
    rows.push(
      tuiUsageStatusRow({
        usageStatus,
        threadId,
        currentTurnId,
        lastCursor,
        lastEventId,
      }),
    );
  }

  costRows.forEach((entry, index) => {
    rows.push(
      tuiCostStatusRow({
        usageStatus: entry,
        threadId,
        currentTurnId,
        lastCursor,
        lastEventId,
        index,
      }),
    );
  });

  contextRows.forEach((entry, index) => {
    const declaredKind = stringField(entry, "rowKind", "row_kind");
    const rowKind: "context_budget" | "compaction_policy" =
      declaredKind === "compaction_policy" ? "compaction_policy" : "context_budget";
    const status = tuiControlRowStatus(
      stringField(entry, "status") ??
      stringField(entry, "contextBudgetStatus", "context_budget_status") ??
      stringField(entry, "compactionPolicyStatus", "compaction_policy_status"),
    );
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    const contextBudgetStatus = stringField(
      entry,
      "contextBudgetStatus",
      "context_budget_status",
    );
    const compactionPolicyStatus = stringField(
      entry,
      "compactionPolicyStatus",
      "compaction_policy_status",
    );
    const compactionPolicyAction = stringField(
      entry,
      "compactionPolicyAction",
      "compaction_policy_action",
    );
    const nodeId =
      stringField(entry, "workflowNodeId", "workflow_node_id") ??
      (rowKind === "context_budget"
        ? "runtime.context-budget"
        : "runtime.compaction-policy");
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-${rowKind}:${slug([threadId, nodeId, sequence].filter(Boolean).join(":"))}`,
      rowKind,
      status,
      label: rowKind === "context_budget" ? "Context budget" : "Compaction policy",
      command: stringField(entry, "command") ?? "context",
      rawInput: stringField(entry, "rawInput", "raw_input") ?? "/context",
      message:
        stringField(entry, "message", "summary") ??
        ([
          contextBudgetStatus,
          compactionPolicyAction,
          compactionPolicyStatus,
        ].filter(Boolean).join(" · ") || null),
      approvalId: null,
      jobId: null,
      runId: null,
      modelId: null,
      routeId: null,
      reasoningEffort: null,
      usageScope: stringField(entry, "scope", "usageScope", "usage_scope") ?? "thread",
      usageTotalTokens: numberField(
        entry,
        "usageTotalTokens",
        "usage_total_tokens",
      ),
      usageCostEstimateUsd: numberField(
        entry,
        "usageCostEstimateUsd",
        "usage_cost_estimate_usd",
      ),
      usageContextPressure: numberField(
        entry,
        "usageContextPressure",
        "usage_context_pressure",
      ),
      usageContextPressureStatus: stringField(
        entry,
        "usageContextPressureStatus",
        "usage_context_pressure_status",
      ),
      contextBudgetStatus,
      contextBudgetMode: stringField(entry, "contextBudgetMode", "context_budget_mode"),
      contextBudgetDecisionId: stringField(
        entry,
        "contextBudgetDecisionId",
        "context_budget_decision_id",
      ),
      compactionPolicyStatus,
      compactionPolicyAction,
      compactionPolicyDecisionId: stringField(
        entry,
        "compactionPolicyDecisionId",
        "compaction_policy_decision_id",
      ),
      compactionExecuted: booleanField(
        entry,
        "compactionExecuted",
        "compaction_executed",
      ),
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
      reactFlowNodeId: nodeId,
    });
  });

  let codingToolRowCount = 0;
  let codingToolBudgetRowCount = 0;
  codingToolRows.forEach((entry, index) => {
    const evidence = codingToolBudgetEvidenceFromRecord(entry);
    const declaredKind = stringField(entry, "rowKind", "row_kind");
    const toolName =
      evidence.toolName ??
      stringField(entry, "toolName", "tool_name", "toolId", "tool_id");
    const toolCallId =
      evidence.toolCallId ?? stringField(entry, "toolCallId", "tool_call_id");
    const sequence = numberField(entry, "sequence", "seq") ?? index + 1;
    if (
      declaredKind !== "coding_tool_budget" &&
      (declaredKind === "coding_tool" || !evidence.isBudgetBlock)
    ) {
      codingToolRowCount += 1;
      const command =
        stringField(entry, "command") ?? codingToolCommandForToolName(toolName);
      const status = tuiControlRowStatus(stringField(entry, "status") ?? "completed");
      const nodeId =
        stringField(entry, "workflowNodeId", "workflow_node_id") ??
        `runtime.coding-tool.${slug(toolName ?? toolCallId ?? String(sequence))}`;
      const receiptRefs = stringArrayField(entry, "receiptRefs", "receipt_refs");
      const artifactRefs = stringArrayField(entry, "artifactRefs", "artifact_refs");
      const policyDecisionRefs = stringArrayField(
        entry,
        "policyDecisionRefs",
        "policy_decision_refs",
      );
      const rollbackRefs = stringArrayField(entry, "rollbackRefs", "rollback_refs");
      rows.push({
        id:
          stringField(entry, "id") ??
          `tui-coding-tool:${slug(
            [toolName, toolCallId, sequence].filter(Boolean).join(":"),
          )}`,
        rowKind: "coding_tool",
        status,
        label:
          stringField(entry, "label") ??
          `Coding tool${toolName ? `: ${toolName}` : ""}`,
        command,
        rawInput:
          stringField(entry, "rawInput", "raw_input") ??
          (command ? `/${command}` : "/tool"),
        message:
          stringField(entry, "message", "summary") ??
          ([toolName, status].filter(Boolean).join(" · ") || null),
        approvalId: null,
        jobId: null,
        runId: stringField(entry, "runId", "run_id"),
        modelId: null,
        toolName,
        toolCallId,
        routeId: null,
        reasoningEffort: null,
        codingToolMutationBlocked: booleanField(
          entry,
          "mutationBlocked",
          "mutation_blocked",
        ),
        codingToolShellFallbackUsed: booleanField(
          entry,
          "shellFallbackUsed",
          "shell_fallback_used",
        ),
        codingToolDryRun: booleanField(entry, "dryRun", "dry_run"),
        threadId: stringField(entry, "threadId", "thread_id") ?? threadId,
        turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
        workflowGraphId:
          stringField(entry, "workflowGraphId", "workflow_graph_id") ??
          workflowGraphId,
        cursor: stringField(entry, "cursor") ?? lastCursor,
        eventId: stringField(entry, "eventId", "event_id") ?? lastEventId,
        sequence,
        receiptRefs,
        artifactRefs,
        policyDecisionRefs,
        rollbackRefs,
        reactFlowNodeId: nodeId,
      });
      return;
    }
    codingToolBudgetRowCount += 1;
    const budgetStatus =
      evidence.budgetStatus ??
      stringField(entry, "budgetStatus", "budget_status");
    const contextBudgetStatus =
      evidence.contextBudgetStatus ??
      stringField(entry, "contextBudgetStatus", "context_budget_status");
    const status = tuiControlRowStatus(
      stringField(entry, "status") ??
      contextBudgetStatus ??
      budgetStatus ??
      evidence.reason,
    );
    const nodeId =
      stringField(entry, "workflowNodeId", "workflow_node_id") ??
      `runtime.coding-tool-budget.${slug(
        toolName ?? toolCallId ?? String(sequence),
      )}`;
    const receiptRefs = uniqueStrings([
      ...stringArrayField(entry, "receiptRefs", "receipt_refs"),
      ...evidence.receiptRefs,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...stringArrayField(entry, "policyDecisionRefs", "policy_decision_refs"),
      ...evidence.policyDecisionRefs,
    ]);
    rows.push({
      id:
        stringField(entry, "id") ??
        `tui-coding-tool-budget:${slug(
          [toolName, toolCallId, sequence].filter(Boolean).join(":"),
        )}`,
      rowKind: "coding_tool_budget",
      status,
      label:
        stringField(entry, "label") ??
        `Coding tool budget${toolName ? `: ${toolName}` : ""}`,
      command: stringField(entry, "command") ?? "coding-tool",
      rawInput:
        stringField(entry, "rawInput", "raw_input") ??
        "/coding-tool budget",
      message:
        stringField(entry, "message", "summary") ??
        ([
          evidence.reason,
          budgetStatus,
          contextBudgetStatus,
          evidence.violationCount === null
            ? null
            : `${evidence.violationCount} violation(s)`,
        ].filter(Boolean).join(" · ") || null),
      approvalId: null,
      jobId: null,
      runId: null,
      modelId: null,
      toolName,
      toolCallId,
      routeId: null,
      reasoningEffort: null,
      usageScope: stringField(entry, "scope", "usageScope", "usage_scope") ?? "thread",
      usageTotalTokens: evidence.usageTotalTokens,
      usageCostEstimateUsd: evidence.usageCostEstimateUsd,
      usageContextPressure: evidence.usageContextPressure,
      usageContextPressureStatus: contextBudgetStatus,
      codingToolBudgetStatus: budgetStatus,
      codingToolBudgetReason: evidence.reason,
      codingToolContextBudgetStatus: contextBudgetStatus,
      codingToolBudgetMode: evidence.budgetMode,
      codingToolBudgetDecisionId: evidence.budgetDecisionId,
      codingToolBudgetCheckCount: evidence.checkCount,
      codingToolBudgetViolationCount: evidence.violationCount,
      codingToolBudgetUsageTotalTokens: evidence.usageTotalTokens,
      codingToolBudgetUsageCostEstimateUsd: evidence.usageCostEstimateUsd,
      codingToolBudgetUsageContextPressure: evidence.usageContextPressure,
      codingToolMutationBlocked: evidence.mutationBlocked,
      threadId: stringField(entry, "threadId", "thread_id") ?? threadId,
      turnId: stringField(entry, "turnId", "turn_id") ?? currentTurnId,
      workflowGraphId:
        stringField(entry, "workflowGraphId", "workflow_graph_id") ??
        workflowGraphId,
      cursor: stringField(entry, "cursor") ?? lastCursor,
      eventId: stringField(entry, "eventId", "event_id") ?? lastEventId,
      sequence,
      receiptRefs,
      policyDecisionRefs,
      reactFlowNodeId: nodeId,
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
    costRowCount: costRows.length,
    contextRowCount: contextRows.length,
    codingToolRowCount,
    codingToolBudgetRowCount,
    workspaceTrustWarningCount: workspaceTrustRows.length,
    mcpRowCount: mcpRows.length,
    memoryRowCount: memoryRows.length,
    usageRowCount: usageStatus ? 1 : 0,
    subagentRowCount: subagentRows.length,
    subagentChildSubflowCount: subagentChildSubflows.length,
    rowCount: rows.length,
    rows,
    subagentChildSubflows,
    subagentChildSubflowReactFlowNodes,
    subagentChildSubflowReactFlowEdges,
  };
}

function tuiUsageStatusRow({
  usageStatus,
  threadId,
  currentTurnId,
  lastCursor,
  lastEventId,
}: {
  usageStatus: Record<string, unknown>;
  threadId: string | null;
  currentTurnId: string | null;
  lastCursor: string | null;
  lastEventId: string | null;
}): WorkflowRuntimeTuiControlStateRow {
  const scope = stringField(usageStatus, "scope") ?? "thread";
  const totalTokens = numberField(
    usageStatus,
    "usageTotalTokens",
    "usage_total_tokens",
    "totalTokens",
    "total_tokens",
  );
  const inputTokens = numberField(
    usageStatus,
    "usageInputTokens",
    "usage_input_tokens",
    "inputTokens",
    "input_tokens",
  );
  const outputTokens = numberField(
    usageStatus,
    "usageOutputTokens",
    "usage_output_tokens",
    "outputTokens",
    "output_tokens",
  );
  const costUsd = numberField(
    usageStatus,
    "usageCostEstimateUsd",
    "usage_cost_estimate_usd",
    "estimatedCostUsd",
    "estimated_cost_usd",
  );
  const contextPressure = numberField(
    usageStatus,
    "usageContextPressure",
    "usage_context_pressure",
    "contextPressure",
    "context_pressure",
  );
  const contextStatus =
    stringField(
      usageStatus,
      "usageContextPressureStatus",
      "usage_context_pressure_status",
      "contextPressureStatus",
      "context_pressure_status",
      "status",
    ) ?? "nominal";
  const sourceCounts = recordField(usageStatus, "sourceCounts", "source_counts");
  const runCount =
    numberField(usageStatus, "usageRunCount", "usage_run_count") ??
    numberField(sourceCounts, "runs");
  const subagentCount =
    numberField(usageStatus, "usageSubagentCount", "usage_subagent_count") ??
    numberField(sourceCounts, "subagents");
  const usageNodeId =
    stringField(usageStatus, "workflowNodeId", "workflow_node_id") ??
    "runtime.usage-telemetry";
  return {
    id: stringField(usageStatus, "id") ?? `tui-usage-status:${slug(threadId ?? scope)}`,
    rowKind: "usage_status",
    status: contextStatus === "high" ? "blocked" : "current",
    label: "Usage telemetry",
    command: "usage",
    rawInput: "/usage",
    message:
      stringField(usageStatus, "message", "summary") ??
      [
        totalTokens !== null ? `${totalTokens} tokens` : null,
        costUsd !== null ? `$${costUsd}` : null,
        contextPressure !== null ? `context ${contextPressure}` : null,
      ]
        .filter(Boolean)
        .join(" · "),
    approvalId: null,
    jobId: null,
    runId: null,
    modelId: null,
    routeId: null,
    reasoningEffort: null,
    usageScope: scope,
    usageTotalTokens: totalTokens,
    usageInputTokens: inputTokens,
    usageOutputTokens: outputTokens,
    usageCostEstimateUsd: costUsd,
    usageContextPressure: contextPressure,
    usageContextPressureStatus: contextStatus,
    usageRunCount: runCount,
    usageSubagentCount: subagentCount,
    threadId: stringField(usageStatus, "threadId", "thread_id") ?? threadId,
    turnId: stringField(usageStatus, "turnId", "turn_id") ?? currentTurnId,
    cursor: stringField(usageStatus, "cursor") ?? lastCursor,
    eventId: stringField(usageStatus, "eventId", "event_id") ?? lastEventId,
    sequence: numberField(usageStatus, "sequence", "seq"),
    receiptRefs: stringArrayField(usageStatus, "receiptRefs", "receipt_refs"),
    policyDecisionRefs: stringArrayField(
      usageStatus,
      "policyDecisionRefs",
      "policy_decision_refs",
    ),
    reactFlowNodeId: usageNodeId,
  };
}

function tuiCostStatusRow({
  usageStatus,
  threadId,
  currentTurnId,
  lastCursor,
  lastEventId,
  index,
}: {
  usageStatus: unknown;
  threadId: string | null;
  currentTurnId: string | null;
  lastCursor: string | null;
  lastEventId: string | null;
  index: number;
}): WorkflowRuntimeTuiControlStateRow {
  const usageRecord = objectField(usageStatus) ?? {};
  const row = tuiUsageStatusRow({
    usageStatus: usageRecord,
    threadId,
    currentTurnId,
    lastCursor,
    lastEventId,
  });
  return {
    ...row,
    id:
      stringField(usageRecord, "id") ??
      `tui-cost-status:${slug(threadId ?? String(index + 1))}`,
    rowKind: "cost_status",
    label: "Cost telemetry",
    command: "cost",
    rawInput: stringField(usageRecord, "rawInput", "raw_input") ?? "/cost",
    reactFlowNodeId:
      stringField(usageRecord, "workflowNodeId", "workflow_node_id") ??
      row.reactFlowNodeId,
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
  if (isComputerUseRuntimeThreadEvent(event)) {
    const payloadNodeId = stringField(
      event.payload,
      "workflowNodeId",
      "workflow_node_id",
    );
    const authoredNodeId = event.workflowNodeId ?? payloadNodeId;
    const step = computerUseStepForRuntimeThreadEvent(event);
    if (authoredNodeId) {
      return computerUseProjectionNodeId(authoredNodeId, step, event.eventKind);
    }
    return `computer-use.${slug(step ?? event.eventKind)}`;
  }
  if (event.workflowNodeId) return event.workflowNodeId;
  if (isCodingToolBudgetBlockedEvent(event)) {
    const evidence = codingToolBudgetEvidenceForRuntimeThreadEvent(event);
    return `runtime.coding-tool-budget.${slug(
      evidence.toolName ?? evidence.toolCallId ?? event.eventKind,
    )}`;
  }
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
    case "context_budget_evaluated":
      return "runtime.context-budget";
    case "compaction_policy_evaluated":
      return "runtime.compaction-policy";
    case "usage_delta":
      return "runtime.usage-telemetry";
    case "context_pressure_delta":
      return "runtime.context-budget";
    case "context_pressure_alert":
      return "runtime.context-pressure-alert";
    case "workspace_trust_warning":
    case "workspace_trust_acknowledged":
      return "runtime.workspace-trust";
    case "workflow_edit_proposed":
    case "workflow_edit_applied":
      return `runtime.workflow-edit-proposal.${slug(
        stringField(event.payload, "proposalId", "proposal_id") ?? event.id,
      )}`;
    case "reasoning_delta":
      return "runtime.reasoning";
    case "tool_completed":
    case "tool_failed":
      return `runtime.tool-result.${slug(event.toolName ?? event.toolCallId ?? event.eventKind)}`;
    case "approval_required":
    case "approval_decision":
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

function computerUseProjectionNodeId(
  authoredNodeId: string,
  step: string | null,
  eventKind: string,
): string {
  if (authoredNodeId.startsWith("computer-use.")) return authoredNodeId;
  const stepSlug = slug(step ?? eventKind);
  if (!stepSlug) return authoredNodeId;
  return `${authoredNodeId}.${stepSlug}`;
}

export function workflowNodeKindForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): WorkflowNodeKind {
  if (isComputerUseRuntimeThreadEvent(event)) return "gui_harness_validation";
  if (event.componentKind === "workspace_snapshot") return "quality_ledger";
  if (event.componentKind === "restore_gate") return "hook_policy";
  if (event.componentKind === "usage_telemetry") return "runtime_usage_meter";
  if (event.componentKind === "context_pressure") return "runtime_context_budget";
  if (event.componentKind === "context_pressure_alert") return "hook_policy";
  if (event.componentKind === "workspace_trust") return "runtime_workspace_trust_gate";
  if (event.componentKind === "workflow_edit_proposal") return "proposal";
  if (event.componentKind === "approval_gate") return "human_gate";
  if (event.componentKind === "context_budget") return "runtime_context_budget";
  if (event.componentKind === "compaction_policy") return "runtime_compaction_policy";
  if (event.componentKind === "coding_tool_budget_recovery") {
    return "runtime_coding_tool_budget_recovery";
  }
  if (event.componentKind === "coding_tool") return "plugin_tool";
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
    case "context_budget_evaluated":
      return "runtime_context_budget";
    case "compaction_policy_evaluated":
      return "runtime_compaction_policy";
    case "usage_delta":
      return "runtime_usage_meter";
    case "context_pressure_delta":
      return "runtime_context_budget";
    case "context_pressure_alert":
      return "hook_policy";
    case "workspace_trust_warning":
    case "workspace_trust_acknowledged":
      return "hook_policy";
    case "workflow_edit_proposed":
    case "workflow_edit_applied":
      return "proposal";
    case "reasoning_delta":
      return "task_state";
    case "tool_completed":
    case "tool_failed":
      return "plugin_tool";
    case "approval_required":
    case "approval_decision":
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
  const codingToolBudgetEvidence =
    codingToolBudgetEvidenceForRuntimeThreadEvent(latestEvent);
  const computerUse = computerUseProjectionForRuntimeThreadEvent(latestEvent);
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
    toolName: latestEvent.toolName ?? codingToolBudgetEvidence.toolName,
    toolCallId: latestEvent.toolCallId ?? codingToolBudgetEvidence.toolCallId,
    approvalId: latestEvent.approvalId ?? null,
    agentStatus: latestEvent.agentStatus ?? null,
    summary: summaryForRuntimeThreadEvent(latestEvent),
    codingToolBudgetStatus: codingToolBudgetEvidence.budgetStatus,
    codingToolBudgetReason: codingToolBudgetEvidence.reason,
    codingToolContextBudgetStatus:
      codingToolBudgetEvidence.contextBudgetStatus,
    codingToolBudgetMode: codingToolBudgetEvidence.budgetMode,
    codingToolBudgetDecisionId: codingToolBudgetEvidence.budgetDecisionId,
    codingToolBudgetCheckCount: codingToolBudgetEvidence.checkCount,
    codingToolBudgetViolationCount: codingToolBudgetEvidence.violationCount,
    codingToolBudgetChecks: codingToolBudgetEvidence.checks,
    codingToolBudgetViolations: codingToolBudgetEvidence.violations,
    codingToolBudgetUsageTelemetry:
      codingToolBudgetEvidence.usageTelemetry,
    codingToolMutationBlocked: codingToolBudgetEvidence.mutationBlocked,
    codingToolBudgetRecoveryActions: codingToolBudgetRecoveryActionsForEvents(
      events,
      latestEvent,
    ),
    diagnosticsRepairActions: diagnosticsRepairActionsForEvents(
      events,
      latestEvent,
    ),
    contextPressureActions: contextPressureActionsForEvents(events, latestEvent),
    workspaceTrustActions: workspaceTrustActionsForEvents(events, latestEvent),
    computerUse,
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

function contextPressureActionsForEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  latestEvent: WorkflowRuntimeThreadEventLike,
): WorkflowRuntimeContextPressureActionDescriptor[] {
  const alertEvent =
    [...events]
      .reverse()
      .find(
        (event) =>
          event.type === "context_pressure_alert" ||
          event.componentKind === "context_pressure_alert",
      ) ?? null;
  if (!alertEvent) return [];
  const payload = alertEvent.payload ?? {};
  const actionRecords = arrayField(payload, "actions", "recommendedActions");
  const fallbackAction =
    stringField(payload, "recommended_action", "recommendedAction") ?? "compact";
  const records = actionRecords.length > 0
    ? actionRecords
    : [{ action: fallbackAction }];
  const scope = stringField(payload, "scope") ?? "turn";
  const pressure = numberField(payload, "pressure", "usage_context_pressure");
  const pressureStatus =
    stringField(payload, "pressure_status", "pressureStatus") ??
    stringField(payload, "usage_context_pressure_status", "usageContextPressureStatus");
  const sourceEventId = stringField(payload, "source_event_id", "sourceEventId");

  return records.map((record, index) => {
    const action = stringField(record, "action") ?? fallbackAction;
    const workflowNodeId =
      stringField(record, "workflowNodeId", "workflow_node_id") ??
      workflowNodeIdForContextPressureAction(action);
    const label =
      stringField(record, "label") ?? labelForContextPressureAction(action);
    const summary =
      stringField(record, "summary", "message") ??
      summaryForContextPressureAction(action, pressure, scope);
    const executable =
      booleanField(record, "executable") ??
      (action === "compact" ||
        action === "delegate_summary" ||
        action === "request_approval" ||
        (action === "stop" && Boolean(alertEvent.turnId)));
    const status = stringField(record, "status") ?? (executable ? "available" : "advisory");
    const decisionId =
      stringField(record, "decisionId", "decision_id") ??
      latestEvent.policyDecisionRefs[index] ??
      latestEvent.policyDecisionRefs[0] ??
      `context-pressure-${slug(action)}-${index + 1}`;
    return {
      id: `context-pressure:${latestEvent.threadId}:${decisionId}:${slug(action)}`,
      action,
      label,
      summary,
      status,
      executable,
      scope,
      pressure,
      pressureStatus,
      threadId: alertEvent.threadId,
      turnId: alertEvent.turnId,
      workflowGraphId: alertEvent.workflowGraphId,
      workflowNodeId,
      eventId: alertEvent.id,
      sourceEventId,
      receiptRefs: uniqueStrings([
        ...alertEvent.receiptRefs,
        ...stringArrayField(record, "receiptRefs", "receipt_refs"),
      ]),
      policyDecisionRefs: uniqueStrings([
        ...alertEvent.policyDecisionRefs,
        ...stringArrayField(record, "policyDecisionRefs", "policy_decision_refs"),
      ]),
    };
  });
}

function workspaceTrustActionsForEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  latestEvent: WorkflowRuntimeThreadEventLike,
): WorkflowRuntimeWorkspaceTrustActionDescriptor[] {
  const warningEvent =
    [...events]
      .reverse()
      .find(
        (event) =>
          event.type === "workspace_trust_warning" ||
          event.eventKind === "workspace.trust_warning" ||
          event.sourceEventKind === "WorkspaceTrust.Warning",
      ) ?? null;
  if (!warningEvent) return [];
  const warningPayload = warningEvent.payload ?? {};
  const warningId =
    stringField(warningPayload, "warningId", "warning_id") ??
    warningEvent.id;
  const acknowledgementEvent =
    [...events]
      .reverse()
      .find((event) => {
        if (
          event.type !== "workspace_trust_acknowledged" &&
          event.eventKind !== "workspace.trust_acknowledged" &&
          event.sourceEventKind !== "WorkspaceTrust.Acknowledged"
        ) {
          return false;
        }
        const payload = event.payload ?? {};
        return (
          stringField(payload, "warningId", "warning_id") === warningId ||
          stringField(payload, "sourceEventId", "source_event_id") ===
            warningEvent.id
        );
      }) ?? null;
  const severity = stringField(warningPayload, "severity");
  const mode = stringField(warningPayload, "mode", "thread_mode");
  const approvalMode =
    stringField(warningPayload, "approvalMode", "approval_mode");
  const acknowledged = Boolean(acknowledgementEvent);
  return [
    {
      id: `workspace-trust:${latestEvent.threadId}:${warningId}:acknowledge`,
      action: "acknowledge",
      label: acknowledged ? "Acknowledged" : "Acknowledge warning",
      summary:
        stringField(warningPayload, "summary", "message") ??
        (mode
          ? `Acknowledge ${mode} workspace trust warning.`
          : "Acknowledge workspace trust warning."),
      status: acknowledged ? "acknowledged" : "available",
      executable: !acknowledged,
      warningId,
      severity,
      mode,
      approvalMode,
      threadId: warningEvent.threadId,
      workflowGraphId:
        warningEvent.workflowGraphId ?? latestEvent.workflowGraphId,
      workflowNodeId: warningEvent.workflowNodeId ?? "runtime.workspace-trust",
      eventId: warningEvent.id,
      sourceEventId: warningEvent.id,
      receiptRefs: uniqueStrings([
        ...warningEvent.receiptRefs,
        ...(acknowledgementEvent?.receiptRefs ?? []),
      ]),
      policyDecisionRefs: uniqueStrings([
        ...warningEvent.policyDecisionRefs,
        ...(acknowledgementEvent?.policyDecisionRefs ?? []),
      ]),
    },
  ];
}

function codingToolBudgetRecoveryActionsForEvents(
  events: readonly WorkflowRuntimeThreadEventLike[],
  latestEvent: WorkflowRuntimeThreadEventLike,
): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor[] {
  const blockedEvent =
    [...events].reverse().find(isWorkflowRunCodingToolBudgetPreflightBlockedEvent) ??
    null;
  if (!blockedEvent) return [];

  const approvalRequestEvent =
    [...events].reverse().find((event) =>
      isCodingToolBudgetRecoveryApprovalRequest(event, blockedEvent),
    ) ?? null;
  const approvalId =
    stringField(approvalRequestEvent, "approvalId", "approval_id") ??
    stringField(approvalRequestEvent?.payload, "approvalId", "approval_id") ??
    stringField(latestEvent, "approvalId", "approval_id") ??
    stringField(latestEvent.payload, "approvalId", "approval_id");
  const approvalDecisionEvent =
    approvalRequestEvent
      ? [...events].reverse().find((event) =>
          isCodingToolBudgetRecoveryApprovalDecision(
            event,
            approvalRequestEvent,
            approvalId,
          ),
        ) ?? null
      : null;
  const approved =
    approvalDecisionEvent?.eventKind === "approval.approved" ||
    approvalDecisionEvent?.status.toLowerCase().includes("approved") ||
    stringField(approvalDecisionEvent?.payload, "decision") === "approve";
  const rejected =
    approvalDecisionEvent?.eventKind === "approval.rejected" ||
    approvalDecisionEvent?.status.toLowerCase().includes("rejected") ||
    stringField(approvalDecisionEvent?.payload, "decision") === "reject";
  const retryEvent =
    approved && approvalDecisionEvent
      ? [...events].reverse().find((event) =>
          isCodingToolBudgetApprovedRetryEvent(
            event,
            approvalDecisionEvent,
            approvalId,
          ),
        ) ?? null
      : null;
  const sourceEventId =
    stringField(blockedEvent.payload, "sourceEventId", "source_event_id") ??
    blockedEvent.id;
  const runId =
    stringField(blockedEvent.payload, "runId", "run_id") ??
    stringField(blockedEvent.payload, "requestId", "request_id") ??
    stringField(latestEvent.payload, "runId", "run_id") ??
    stringField(latestEvent.payload, "requestId", "request_id");
  const targetNodeIds = uniqueStrings([
    ...stringArrayField(blockedEvent.payload, "targetNodeIds", "target_node_ids"),
    ...stringArrayField(
      approvalRequestEvent?.payload,
      "targetNodeIds",
      "target_node_ids",
    ),
    ...stringArrayField(
      approvalDecisionEvent?.payload,
      "targetNodeIds",
      "target_node_ids",
    ),
    ...stringArrayField(retryEvent?.payload, "targetNodeIds", "target_node_ids"),
    blockedEvent.workflowNodeId ?? latestEvent.workflowNodeId ?? "",
  ]);
  const recoveryPolicy =
    workflowCodingToolBudgetRecoveryPolicyFromUnknown(
      retryEvent?.payload,
      targetNodeIds,
    ) ??
    workflowCodingToolBudgetRecoveryPolicyFromUnknown(
      approvalDecisionEvent?.payload,
      targetNodeIds,
    ) ??
    workflowCodingToolBudgetRecoveryPolicyFromUnknown(
      approvalRequestEvent?.payload,
      targetNodeIds,
    ) ??
    workflowCodingToolBudgetRecoveryPolicyFromUnknown(
      blockedEvent.payload,
      targetNodeIds,
    );
  const recoveryTargetNodeIds =
    recoveryPolicy?.targetNodeIds.length ? recoveryPolicy.targetNodeIds : targetNodeIds;
  const receiptRefs = uniqueStrings([
    ...events.flatMap((event) => event.receiptRefs),
    ...stringArrayField(blockedEvent.payload, "receiptRefs", "receipt_refs"),
    ...stringArrayField(
      approvalRequestEvent?.payload,
      "receiptRefs",
      "receipt_refs",
    ),
    ...stringArrayField(
      approvalDecisionEvent?.payload,
      "receiptRefs",
      "receipt_refs",
    ),
    ...stringArrayField(retryEvent?.payload, "receiptRefs", "receipt_refs"),
  ]);
  const policyDecisionRefs = uniqueStrings([
    ...events.flatMap((event) => event.policyDecisionRefs),
    ...stringArrayField(
      blockedEvent.payload,
      "policyDecisionRefs",
      "policy_decision_refs",
    ),
    ...stringArrayField(
      approvalRequestEvent?.payload,
      "policyDecisionRefs",
      "policy_decision_refs",
    ),
    ...stringArrayField(
      approvalDecisionEvent?.payload,
      "policyDecisionRefs",
      "policy_decision_refs",
    ),
    ...stringArrayField(
      retryEvent?.payload,
      "policyDecisionRefs",
      "policy_decision_refs",
    ),
  ]);
  const base = {
    schemaVersion: WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION,
    runId,
    threadId: blockedEvent.threadId,
    workflowGraphId: blockedEvent.workflowGraphId ?? latestEvent.workflowGraphId,
    workflowNodeId: blockedEvent.workflowNodeId ?? "runtime.coding-tool-budget-preflight",
    eventId: blockedEvent.id,
    sourceEventId,
    approvalId,
    approvalRequestEventId: approvalRequestEvent?.id ?? null,
    approvalDecisionEventId: approvalDecisionEvent?.id ?? null,
    targetNodeIds: recoveryTargetNodeIds,
    receiptRefs,
    policyDecisionRefs,
    recoveryPolicy,
  } satisfies Omit<
    WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
    "id" | "action" | "label" | "summary" | "status" | "executable"
  >;

  return [
    codingToolBudgetRecoveryActionDescriptor(base, latestEvent, {
      action: "review_receipt",
      label: "Review receipt",
      summary: "Review the persisted coding-tool budget receipt before recovery.",
      status: retryEvent ? "completed" : "available",
      executable: false,
    }),
    codingToolBudgetRecoveryActionDescriptor(base, latestEvent, {
      action: "request_approval",
      label: approvalRequestEvent ? "Approval requested" : "Request approval",
      summary: approvalRequestEvent
        ? "Operator approval has been requested for this blocked launch."
        : "Request operator approval before retrying the blocked launch.",
      status: approvalRequestEvent ? "completed" : "available",
      executable: !approvalRequestEvent,
    }),
    codingToolBudgetRecoveryActionDescriptor(base, latestEvent, {
      action: "approve_override",
      label: approved ? "Override approved" : "Approve override",
      summary: approvalRequestEvent
        ? "Approve the coding-tool budget override and enable a recorded retry."
        : "Request approval before approving the override.",
      status: approved ? "completed" : rejected ? "blocked" : approvalRequestEvent ? "available" : "waiting",
      executable: Boolean(approvalRequestEvent && !approvalDecisionEvent),
    }),
    codingToolBudgetRecoveryActionDescriptor(base, latestEvent, {
      action: "reject_override",
      label: rejected ? "Override rejected" : "Reject override",
      summary: approvalRequestEvent
        ? "Reject the coding-tool budget override and keep the launch blocked."
        : "Request approval before rejecting the override.",
      status: rejected ? "completed" : approved ? "blocked" : approvalRequestEvent ? "available" : "waiting",
      executable: Boolean(approvalRequestEvent && !approvalDecisionEvent),
    }),
    codingToolBudgetRecoveryActionDescriptor(base, latestEvent, {
      action: "retry_approved",
      label: retryEvent ? "Retry recorded" : "Retry approved run",
      summary: approved
        ? "Retry the launch through the daemon-recorded approval decision."
        : "Approve the override before retrying the launch.",
      status: retryEvent ? "completed" : approved ? "available" : rejected ? "blocked" : "waiting",
      executable: Boolean(approved && !retryEvent),
    }),
  ];
}

function codingToolBudgetRecoveryActionDescriptor(
  base: Omit<
    WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
    "id" | "action" | "label" | "summary" | "status" | "executable"
  >,
  latestEvent: WorkflowRuntimeThreadEventLike,
  action: Pick<
    WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
    "action" | "label" | "summary" | "status" | "executable"
  >,
): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor {
  return {
    id: `coding-tool-budget-recovery:${latestEvent.threadId}:${base.eventId}:${action.action}`,
    ...base,
    ...action,
  };
}

function isWorkflowRunCodingToolBudgetPreflightBlockedEvent(
  event: WorkflowRuntimeThreadEventLike,
): boolean {
  if (!isCodingToolBudgetBlockedEvent(event)) return false;
  const reason =
    stringField(event.payload, "reason", "blockReason", "block_reason") ??
    codingToolBudgetEvidenceForRuntimeThreadEvent(event).reason;
  return (
    reason === "coding_tool_budget_preflight_blocked" ||
    event.sourceEventKind === "WorkflowRunCodingToolBudgetPreflightBlocked" ||
    stringField(event.payload, "eventKind", "event_kind") ===
      "WorkflowRunCodingToolBudgetPreflightBlocked"
  );
}

function isCodingToolBudgetRecoveryApprovalRequest(
  event: WorkflowRuntimeThreadEventLike,
  blockedEvent: WorkflowRuntimeThreadEventLike,
): boolean {
  if (
    event.seq <= blockedEvent.seq ||
    event.type !== "approval_required" ||
    event.eventKind !== "approval.required"
  ) {
    return false;
  }
  return (
    stringField(event.payload, "reason", "blockReason", "block_reason") ===
      "coding_tool_budget_preflight_blocked" ||
    stringField(event.payload, "sourceEventId", "source_event_id") ===
      blockedEvent.id ||
    event.sourceEventKind === "OperatorApproval.Request"
  );
}

function isCodingToolBudgetRecoveryApprovalDecision(
  event: WorkflowRuntimeThreadEventLike,
  requestEvent: WorkflowRuntimeThreadEventLike,
  approvalId: string | null,
): boolean {
  if (
    event.seq <= requestEvent.seq ||
    (event.type !== "approval_decision" &&
      event.eventKind !== "approval.approved" &&
      event.eventKind !== "approval.rejected")
  ) {
    return false;
  }
  const eventApprovalId =
    stringField(event, "approvalId", "approval_id") ??
    stringField(event.payload, "approvalId", "approval_id");
  return !approvalId || eventApprovalId === approvalId;
}

function isCodingToolBudgetApprovedRetryEvent(
  event: WorkflowRuntimeThreadEventLike,
  decisionEvent: WorkflowRuntimeThreadEventLike,
  approvalId: string | null,
): boolean {
  if (event.seq <= decisionEvent.seq) return false;
  const retryKind =
    event.eventKind === "workflow.run.retry_completed" ||
    event.sourceEventKind === "WorkflowRunCodingToolBudgetApprovedRetry";
  if (event.type !== "tool_completed" && !retryKind) return false;
  const eventApprovalId =
    stringField(event, "approvalId", "approval_id") ??
    stringField(event.payload, "approvalId", "approval_id");
  const decisionEventId = stringField(
    event.payload,
    "approvalDecisionEventId",
    "approval_decision_event_id",
  );
  const approvalSatisfied =
    booleanField(event.payload, "approvalSatisfied", "approval_satisfied") ??
    retryKind;
  return (
    approvalSatisfied &&
    (!approvalId || eventApprovalId === approvalId) &&
    (!decisionEventId || decisionEventId === decisionEvent.id)
  );
}

function workflowNodeIdForContextPressureAction(action: string): string {
  switch (action) {
    case "compact":
      return "runtime.context-compact";
    case "stop":
      return "runtime.operator-interrupt";
    case "request_approval":
      return "runtime.approval.context-pressure";
    case "delegate_summary":
      return "runtime.subagent.delegate-summary";
    default:
      return `runtime.context-pressure-action.${slug(action)}`;
  }
}

function labelForContextPressureAction(action: string): string {
  switch (action) {
    case "compact":
      return "Compact context";
    case "stop":
      return "Stop turn";
    case "request_approval":
      return "Request approval";
    case "delegate_summary":
      return "Delegate summary";
    default:
      return action.replace(/[_-]+/g, " ");
  }
}

function summaryForContextPressureAction(
  action: string,
  pressure: number | null,
  scope: string,
): string {
  const pressureText = pressure === null ? "current pressure" : `pressure ${pressure}`;
  switch (action) {
    case "compact":
      return `Compact ${scope.replace(/_/g, " ")} context at ${pressureText}.`;
    case "stop":
      return `Stop the turn before ${scope.replace(/_/g, " ")} context grows further.`;
    case "request_approval":
      return `Request operator approval to continue at ${pressureText}.`;
    case "delegate_summary":
      return `Delegate a summary for ${scope.replace(/_/g, " ")} context before continuing.`;
    default:
      return `Review ${scope.replace(/_/g, " ")} context at ${pressureText}.`;
  }
}

function isCodingToolBudgetBlockedEvent(
  event: WorkflowRuntimeThreadEventLike,
): boolean {
  if (event.componentKind !== "coding_tool") return false;
  if (
    event.type !== "policy_blocked" &&
    event.eventKind !== "policy.blocked" &&
    event.status !== "blocked"
  ) {
    return false;
  }
  return codingToolBudgetEvidenceForRuntimeThreadEvent(event).isBudgetBlock;
}

function codingToolBudgetEvidenceForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): CodingToolBudgetEvidence {
  return codingToolBudgetEvidenceFromRecord(event.payload, {
    toolName: event.toolName ?? null,
    toolCallId: event.toolCallId ?? null,
    receiptRefs: event.receiptRefs,
    policyDecisionRefs: event.policyDecisionRefs,
  });
}

function codingToolBudgetEvidenceFromRecord(
  record: unknown,
  defaults: {
    toolName?: string | null;
    toolCallId?: string | null;
    receiptRefs?: string[];
    policyDecisionRefs?: string[];
  } = {},
): CodingToolBudgetEvidence {
  const payload = objectField(record) ?? {};
  const result = recordField(payload, "result") ?? {};
  const resultSummary = recordField(payload, "resultSummary", "result_summary") ?? {};
  const error = recordField(payload, "error") ?? recordField(result, "error") ?? {};
  const errorDetails = recordField(error, "details") ?? {};
  const contextBudget =
    recordField(payload, "contextBudget", "context_budget") ??
    recordField(result, "contextBudget", "context_budget") ??
    recordField(errorDetails, "contextBudget", "context_budget") ??
    {};
  const policyDecision =
    recordField(contextBudget, "policyDecision", "policy_decision") ?? {};
  const usageTelemetry =
    recordField(payload, "budgetUsageTelemetry", "budget_usage_telemetry") ??
    recordField(result, "budgetUsageTelemetry", "budget_usage_telemetry") ??
    recordField(errorDetails, "budgetUsageTelemetry", "budget_usage_telemetry") ??
    recordField(contextBudget, "usageTelemetry", "usage_telemetry") ??
    null;
  const usageSummary =
    recordField(contextBudget, "usageSummary", "usage_summary") ??
    recordField(usageTelemetry, "usageSummary", "usage_summary") ??
    usageTelemetry ??
    {};
  const checks = nonEmptyArrayField(contextBudget, "checks")
    ? arrayField(contextBudget, "checks")
    : arrayField(policyDecision, "checks");
  const violations = nonEmptyArrayField(contextBudget, "violations")
    ? arrayField(contextBudget, "violations")
    : arrayField(policyDecision, "violations");
  const reason =
    stringField(payload, "reason", "blockReason", "block_reason") ??
    stringField(resultSummary, "reason") ??
    stringField(errorDetails, "reason", "code") ??
    stringField(error, "code");
  const budgetStatus =
    stringField(payload, "budgetStatus", "budget_status") ??
    stringField(result, "budgetStatus", "budget_status") ??
    stringField(errorDetails, "budgetStatus", "budget_status");
  const contextBudgetStatus =
    stringField(payload, "contextBudgetStatus", "context_budget_status") ??
    stringField(result, "contextBudgetStatus", "context_budget_status") ??
    stringField(errorDetails, "contextBudgetStatus", "context_budget_status") ??
    stringField(contextBudget, "status");
  const isBudgetBlock =
    reason === "coding_tool_budget_exceeded" ||
    reason === "coding_tool_budget_preflight_blocked" ||
    budgetStatus === "exceeded" ||
    contextBudgetStatus === "blocked";
  const resultStatus = stringField(result, "status") ?? stringField(payload, "status");
  const mutationBlocked =
    booleanField(payload, "mutationBlocked", "mutation_blocked") ??
    booleanField(result, "mutationBlocked", "mutation_blocked") ??
    (isBudgetBlock && resultStatus === "blocked" ? true : null);
  const decisionId =
    stringField(
      payload,
      "contextBudgetDecisionId",
      "context_budget_decision_id",
      "budgetDecisionId",
      "budget_decision_id",
      "policyDecisionId",
      "policy_decision_id",
    ) ??
    stringField(contextBudget, "policyDecisionId", "policy_decision_id") ??
    stringField(policyDecision, "policyDecisionId", "policy_decision_id");
  const receiptRefs = uniqueStrings([
    ...(defaults.receiptRefs ?? []),
    ...stringArrayField(payload, "receiptRefs", "receipt_refs"),
    ...stringArrayField(contextBudget, "receiptRefs", "receipt_refs"),
  ]);
  const policyDecisionRefs = uniqueStrings([
    ...(defaults.policyDecisionRefs ?? []),
    ...stringArrayField(payload, "policyDecisionRefs", "policy_decision_refs"),
    ...stringArrayField(contextBudget, "policyDecisionRefs", "policy_decision_refs"),
  ]);

  return {
    isBudgetBlock,
    toolName:
      stringField(payload, "toolName", "tool_name", "toolId", "tool_id") ??
      stringField(result, "toolName", "tool_name", "toolId", "tool_id") ??
      defaults.toolName ??
      null,
    toolCallId:
      stringField(payload, "toolCallId", "tool_call_id") ??
      stringField(result, "toolCallId", "tool_call_id") ??
      defaults.toolCallId ??
      null,
    reason,
    budgetStatus,
    contextBudgetStatus,
    budgetMode:
      stringField(payload, "budgetMode", "budget_mode") ??
      stringField(contextBudget, "mode"),
    budgetDecisionId: decisionId,
    checkCount: checks.length > 0 ? checks.length : null,
    violationCount: violations.length > 0 ? violations.length : null,
    checks,
    violations,
    usageTelemetry,
    usageTotalTokens: numberField(
      usageSummary,
      "total_tokens",
      "totalTokens",
      "cumulativeTotalTokens",
      "cumulative_total_tokens",
    ),
    usageCostEstimateUsd: numberField(
      usageSummary,
      "estimated_cost_usd",
      "estimatedCostUsd",
      "cost_estimate_usd",
      "costEstimateUsd",
      "cumulativeCostEstimateUsd",
      "cumulative_cost_estimate_usd",
    ),
    usageContextPressure: numberField(
      usageSummary,
      "context_pressure",
      "contextPressure",
      "usageContextPressure",
      "usage_context_pressure",
    ),
    mutationBlocked,
    receiptRefs,
    policyDecisionRefs,
  };
}

function isComputerUseRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): boolean {
  return (
    event.componentKind === "computer_use_harness" ||
    event.eventKind.startsWith("computer_use.") ||
    event.sourceEventKind.startsWith("ComputerUse.") ||
    Boolean(computerUseStepForRuntimeThreadEvent(event))
  );
}

function computerUseStepForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string | null {
  const payloadStep = stringField(event.payload, "computer_use_step");
  if (payloadStep) return payloadStep;
  if (event.eventKind.startsWith("computer_use.")) {
    return event.eventKind.slice("computer_use.".length);
  }
  if (event.type.startsWith("computer_use_")) {
    return event.type.slice("computer_use_".length);
  }
  return null;
}

function computerUseProjectionForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): WorkflowRuntimeComputerUseProjection | null {
  if (!isComputerUseRuntimeThreadEvent(event)) return null;
  const payload = event.payload ?? {};
  const lease = recordField(payload, "lease");
  const environmentSelectionReceipt = recordField(
    payload,
    "environment_selection_receipt",
    "environmentSelectionReceipt",
  );
  const runState = recordField(
    payload,
    "computer_use_run_state",
    "computerUseRunState",
  );
  const observationBundle = recordField(
    payload,
    "observation_bundle",
    "observationBundle",
  );
  const targetIndex = recordField(payload, "target_index", "targetIndex");
  const affordanceGraph = recordField(
    payload,
    "affordance_graph",
    "affordanceGraph",
  );
  const browserDiscoveryReport = recordField(
    payload,
    "browser_discovery_report",
  );
  const controlledRelaunchLaunchReceipt = recordField(
    payload,
    "controlled_relaunch_launch_receipt",
    "controlledRelaunchLaunchReceipt",
  );
  const actionProposal = recordField(
    payload,
    "action_proposal",
    "actionProposal",
  );
  const computerAction = recordField(
    payload,
    "computer_action",
    "computerAction",
  );
  const actionReceipt = recordField(
    payload,
    "action_receipt",
    "actionReceipt",
  );
  const executionResult =
    recordField(payload, "computer_use_execution_result", "computerUseExecutionResult") ??
    recordField(actionReceipt, "computer_use_execution_result", "computerUseExecutionResult") ??
    recordField(payload, "native_browser_execution_result", "nativeBrowserExecutionResult");
  const executionReceipt =
    recordField(executionResult, "execution_receipt", "executionReceipt") ??
    recordField(executionResult, "action_result", "actionResult");
  const preflightReceipt = recordField(
    executionResult,
    "preflight_receipt",
    "preflightReceipt",
  );
  const executionAfter = recordField(executionResult, "after");
  const verificationReceipt = recordField(
    payload,
    "verification_receipt",
    "verificationReceipt",
  );
  const outcomeContract = recordField(
    payload,
    "outcome_contract",
    "outcomeContract",
  );
  const commitGate = recordField(
    payload,
    "commit_gate",
    "commitGate",
  );
  const humanHandoffState = recordField(
    payload,
    "human_handoff_state",
    "humanHandoffState",
  );
  const trajectoryBundle = recordField(
    payload,
    "trajectory_bundle",
    "trajectoryBundle",
  );
  const cleanupReceipt = recordField(
    payload,
    "cleanup_receipt",
    "cleanupReceipt",
  );
  const policyDecisionReceipt =
    recordField(payload, "policy_decision_receipt", "policyDecisionReceipt") ??
    recordField(payload, "policy_gate", "policyGate");
  const targetCount = targetIndex ? arrayField(targetIndex, "targets").length : null;
  const affordanceCount = affordanceGraph
    ? arrayField(affordanceGraph, "affordances").length
    : null;
  const visualTargetSummaries = visualTargetSummariesForTargetIndex(targetIndex);

  return {
    schemaVersion: WORKFLOW_RUNTIME_COMPUTER_USE_PROJECTION_SCHEMA_VERSION,
    step: computerUseStepForRuntimeThreadEvent(event),
    lane:
      stringField(payload, "computer_use_lane") ??
      stringField(lease, "lane") ??
      stringField(observationBundle, "lane"),
    sessionMode:
      stringField(payload, "computer_use_session_mode") ??
      stringField(lease, "session_mode", "sessionMode") ??
      stringField(observationBundle, "session_mode", "sessionMode"),
    leaseId:
      stringField(payload, "computer_use_lease_id") ??
      stringField(lease, "lease_id", "leaseId") ??
      stringField(runState, "lease_id", "leaseId"),
    contractIngest: stringField(payload, "computer_use_contract_ingest"),
    status: projectedStatusForRuntimeThreadEvent(event),
    blocker:
      stringField(payload, "computer_use_blocker") ??
      stringField(runState, "blocker_state", "blockerState"),
    workflowGraphId:
      event.workflowGraphId ??
      stringField(payload, "workflow_graph_id", "workflowGraphId"),
    workflowNodeId:
      event.workflowNodeId ??
      stringField(payload, "workflow_node_id", "workflowNodeId"),
    workflowNodeIds: stringArrayField(
      payload,
      "workflow_node_ids",
      "workflowNodeIds",
    ),
    toolRef: stringField(payload, "tool_ref", "toolRef"),
    authorityScopes: stringArrayField(
      payload,
      "authority_scopes",
      "authorityScopes",
    ),
    failClosedWhenUnavailable: booleanField(
      payload,
      "fail_closed_when_unavailable",
      "failClosedWhenUnavailable",
    ),
    observationRef:
      stringField(payload, "computer_use_observation_ref") ??
      stringField(observationBundle, "observation_ref", "observationRef") ??
      stringField(runState, "current_observation_ref", "currentObservationRef"),
    screenRef:
      stringField(payload, "computer_use_screen_ref") ??
      stringField(observationBundle, "screenshot_ref", "screenshotRef"),
    somRef:
      stringField(payload, "computer_use_som_ref") ??
      stringField(observationBundle, "som_ref", "somRef"),
    coordinateSpaceId:
      stringField(
        payload,
        "computer_use_coordinate_space_id",
      ) ??
      stringField(targetIndex, "coordinate_space_id", "coordinateSpaceId") ??
      stringField(computerAction, "coordinate_space_id", "coordinateSpaceId") ??
      stringField(actionReceipt, "coordinate_space_id", "coordinateSpaceId"),
    targetIndexRef:
      stringField(payload, "computer_use_target_index_ref") ??
      stringField(targetIndex, "target_index_ref", "targetIndexRef") ??
      stringField(observationBundle, "target_index_ref", "targetIndexRef") ??
      stringField(runState, "current_target_index_ref", "currentTargetIndexRef"),
    affordanceGraphRef:
      stringField(
        payload,
        "computer_use_affordance_graph_ref",
      ) ?? stringField(affordanceGraph, "graph_ref", "graphRef"),
    browserDiscoveryRef:
      stringField(
        payload,
        "computer_use_browser_discovery_ref",
      ) ??
      stringField(browserDiscoveryReport, "discovery_ref") ??
      stringField(browserDiscoveryReport, "receipt_ref"),
    browserProcessCount: numberField(
      browserDiscoveryReport,
      "browser_process_count",
    ),
    cdpEndpointCount: numberField(
      browserDiscoveryReport,
      "cdp_endpoint_count",
    ),
    defaultProfileBlockerCount: browserDiscoveryReport
      ? arrayField(
          browserDiscoveryReport,
          "default_profile_remote_debugging_blockers",
        ).length
      : null,
    controlledRelaunchLaunchRef:
      stringField(
        payload,
        "computer_use_controlled_relaunch_launch_ref",
      ) ??
      stringField(
        controlledRelaunchLaunchReceipt,
        "launch_ref",
        "launchRef",
      ),
    controlledRelaunchLaunchStatus: stringField(
      controlledRelaunchLaunchReceipt,
      "status",
    ),
    controlledRelaunchProcessRef: stringField(
      controlledRelaunchLaunchReceipt,
      "process_ref",
      "processRef",
    ),
    controlledRelaunchProfileDirRef: stringField(
      controlledRelaunchLaunchReceipt,
      "profile_dir_ref",
      "profileDirRef",
    ),
    controlledRelaunchEndpointRef: stringField(
      controlledRelaunchLaunchReceipt,
      "endpoint_ref",
      "endpointRef",
    ),
    controlledRelaunchApprovalRef: stringField(
      controlledRelaunchLaunchReceipt,
      "approval_ref",
      "approvalRef",
    ),
    proposalRef:
      stringField(payload, "computer_use_proposal_ref") ??
      stringField(actionProposal, "proposal_ref", "proposalRef"),
    actionRef:
      stringField(payload, "computer_use_action_ref") ??
      stringField(computerAction, "action_ref", "actionRef") ??
      stringField(actionReceipt, "action_ref", "actionRef"),
    actionKind: stringField(computerAction, "action_kind", "actionKind"),
    actionReceiptRef: stringField(actionReceipt, "receipt_ref", "receiptRef"),
    executionRef: stringField(executionResult, "executor_ref", "executorRef"),
    executionStatus: stringField(executionResult, "status"),
    executionAdapterId:
      stringField(executionResult, "adapter_id", "adapterId") ??
      stringField(actionReceipt, "adapter_id", "adapterId"),
    executionProviderId:
      stringField(executionResult, "provider_id", "providerId") ??
      stringField(executionReceipt, "provider_id", "providerId"),
    executionPreflightStatus: stringField(preflightReceipt, "status"),
    executionRequiresReobserve: booleanField(
      executionAfter,
      "requires_reobserve",
      "requiresReobserve",
    ),
    targetRef:
      stringField(payload, "computer_use_target_ref") ??
      stringField(actionProposal, "target_ref", "targetRef") ??
      stringField(computerAction, "target_ref", "targetRef"),
    policyDecisionRef:
      stringField(
        payload,
        "computer_use_policy_decision_ref",
      ) ??
      stringField(policyDecisionReceipt, "policy_decision_ref", "policyDecisionRef") ??
      stringField(actionProposal, "policy_decision_ref", "policyDecisionRef") ??
      stringField(recordField(payload, "policy_gate", "policyGate"), "policy_decision_ref", "policyDecisionRef"),
    policyOutcome: stringField(policyDecisionReceipt, "outcome", "decision"),
    policyAuthorityScope: stringField(
      policyDecisionReceipt,
      "authority_scope",
      "authorityScope",
    ),
    policyApprovalRef: stringField(
      policyDecisionReceipt,
      "approval_ref",
      "approvalRef",
    ),
    policyExternalEffect: booleanField(
      policyDecisionReceipt,
      "external_effect",
      "externalEffect",
    ),
    policyFailClosed: booleanField(
      policyDecisionReceipt,
      "fail_closed",
      "failClosed",
    ),
    verificationRef:
      stringField(payload, "computer_use_verification_ref") ??
      stringField(verificationReceipt, "verification_ref", "verificationRef") ??
      stringField(actionReceipt, "verification_ref", "verificationRef"),
    verificationStatus:
      stringField(verificationReceipt, "status") ??
      stringField(runState, "verification_status", "verificationStatus"),
    commitGateRef:
      stringField(payload, "computer_use_commit_gate_ref") ??
      stringField(commitGate, "commit_gate_ref", "commitGateRef"),
    commitGateStatus: stringField(commitGate, "status"),
    outcomeRef: stringField(outcomeContract, "outcome_ref", "outcomeRef"),
    humanHandoffRef: stringField(humanHandoffState, "handoff_ref", "handoffRef"),
    trajectoryRef:
      stringField(payload, "computer_use_trajectory_ref") ??
      stringField(trajectoryBundle, "trajectory_ref", "trajectoryRef"),
    cleanupRef:
      stringField(payload, "computer_use_cleanup_ref") ??
      stringField(cleanupReceipt, "cleanup_ref", "cleanupRef"),
    cleanupStatus: stringField(cleanupReceipt, "status"),
    retentionMode:
      stringField(lease, "retention_mode", "retentionMode") ??
      stringField(observationBundle, "retention_mode", "retentionMode") ??
      stringField(trajectoryBundle, "retention_mode", "retentionMode"),
    riskPosture:
      stringField(environmentSelectionReceipt, "risk_posture", "riskPosture") ??
      stringField(runState, "risk_posture", "riskPosture"),
    authorityRequired:
      stringField(
        environmentSelectionReceipt,
        "authority_required",
        "authorityRequired",
      ) ?? stringField(lease, "authority_scope", "authorityScope"),
    targetCount,
    affordanceCount,
    detectedPatterns: stringArrayField(
      observationBundle,
      "detected_patterns",
      "detectedPatterns",
    ),
    visualTargetRefs: visualTargetSummaries.map((target) => target.targetRef),
    visualTargetSummaries,
    recoveryPolicy: recordField(payload, "recovery_policy", "recoveryPolicy"),
    outcomeContract,
    commitGate,
    humanHandoffState,
  };
}

function visualTargetSummariesForTargetIndex(
  targetIndex: Record<string, unknown> | null,
): WorkflowRuntimeComputerUseVisualTargetSummary[] {
  return arrayField(targetIndex, "targets")
    .map((target) => objectField(target))
    .filter((target): target is Record<string, unknown> => Boolean(target))
    .map((target) => ({
      targetRef: stringField(target, "target_ref", "targetRef") ?? "target",
      label: stringField(target, "label", "name"),
      role: stringField(target, "role"),
      somId: numberField(target, "som_id", "somId"),
      confidence: numberField(target, "confidence"),
      bounds: targetBounds(target),
      boundsSummary: boundsSummaryForTarget(target),
      availableActions: stringArrayField(
        target,
        "available_actions",
        "availableActions",
      ),
    }));
}

function targetBounds(
  target: Record<string, unknown>,
): WorkflowRuntimeComputerUseVisualTargetBounds | null {
  const bounds = recordField(target, "bounds");
  if (!bounds) return null;
  const x = numberField(bounds, "x");
  const y = numberField(bounds, "y");
  const width = numberField(bounds, "width", "w");
  const height = numberField(bounds, "height", "h");
  if (x === null || y === null || width === null || height === null) {
    return null;
  }
  return {
    x,
    y,
    width,
    height,
    coordinateSpaceId: stringField(
      bounds,
      "coordinate_space_id",
      "coordinateSpaceId",
    ),
  };
}

function boundsSummaryForTarget(target: Record<string, unknown>): string | null {
  const bounds = targetBounds(target);
  const coordinateSpaceId = bounds?.coordinateSpaceId ?? null;
  if (!bounds) return coordinateSpaceId;
  return [
    coordinateSpaceId,
    `${Math.round(bounds.x)},${Math.round(bounds.y)} ${Math.round(bounds.width)}x${Math.round(bounds.height)}`,
  ]
    .filter(Boolean)
    .join(" · ");
}

function labelForComputerUseRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string | null {
  const computerUse = computerUseProjectionForRuntimeThreadEvent(event);
  if (!computerUse) return null;
  if (event.eventKind === "computer_use.environment_unavailable" || computerUse.blocker) {
    return "Computer use unavailable";
  }
  switch (computerUse.step) {
    case "select_environment":
    case "environment_selected":
      return "Computer use: select environment";
    case "acquire_lease":
    case "lease_acquired":
      return "Computer use: acquire lease";
    case "plan_next_step":
    case "run_state":
      return "Computer use: run state";
    case "observe":
    case "observation":
      return "Computer use: observe";
    case "build_affordance_graph":
    case "affordance_graph":
      return "Computer use: affordances";
    case "discover_browser":
    case "browser_discovery":
      return "Computer use: browser discovery";
    case "propose_action":
    case "action_proposed":
      return "Computer use: propose action";
    case "execute_action":
    case "action_executed":
      return "Computer use: execute action";
    case "verify_postcondition":
    case "verification":
      return "Computer use: verify";
    case "commit_or_handoff":
    case "commit_gate":
      return "Computer use: commit gate";
    case "write_trajectory":
    case "trajectory_written":
      return "Computer use: trajectory";
    case "cleanup":
      return "Computer use: cleanup";
    default:
      return "Computer use";
  }
}

function summaryForComputerUseProjection(
  computerUse: WorkflowRuntimeComputerUseProjection,
): string {
  const parts = [
    computerUse.lane,
    computerUse.sessionMode,
    computerUse.browserDiscoveryRef
      ? `discovery ${computerUse.browserProcessCount ?? 0} browsers / ${computerUse.cdpEndpointCount ?? 0} CDP`
      : null,
    computerUse.controlledRelaunchLaunchStatus
      ? `launch ${computerUse.controlledRelaunchLaunchStatus}`
      : null,
    computerUse.actionKind,
    computerUse.verificationStatus,
    computerUse.commitGateStatus,
    computerUse.cleanupStatus,
    computerUse.blocker,
  ].filter((part): part is string => Boolean(part));
  return parts.length > 0
    ? parts.join(" · ")
    : "Computer-use harness event projected from canonical runtime truth.";
}

function componentKindForRuntimeThreadEvent(
  event: WorkflowRuntimeThreadEventLike,
): string {
  if (event.componentKind) return event.componentKind;
  if (isComputerUseRuntimeThreadEvent(event)) return "computer_use_harness";
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
    case "context_budget_evaluated":
      return "context_budget";
    case "compaction_policy_evaluated":
      return "compaction_policy";
    case "usage_delta":
      return "usage_telemetry";
    case "context_pressure_delta":
      return "context_pressure";
    case "context_pressure_alert":
      return "context_pressure_alert";
    case "workspace_trust_warning":
    case "workspace_trust_acknowledged":
      return "workspace_trust";
    case "workflow_edit_proposed":
    case "workflow_edit_applied":
      return "workflow_edit_proposal";
    case "reasoning_delta":
      return "reasoning_delta";
    case "tool_completed":
    case "tool_failed":
      return "tool_result";
    case "approval_required":
      return "approval_gate";
    case "approval_decision":
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
  const computerUseLabel = labelForComputerUseRuntimeThreadEvent(event);
  if (computerUseLabel) return computerUseLabel;
  if (isCodingToolBudgetBlockedEvent(event)) {
    const evidence = codingToolBudgetEvidenceForRuntimeThreadEvent(event);
    return `Coding tool budget: ${
      evidence.toolName ?? event.toolName ?? evidence.toolCallId ?? "blocked"
    }`;
  }
  if (event.componentKind === "coding_tool" && event.toolName) return `Coding tool: ${event.toolName}`;
  if (event.componentKind === "workspace_snapshot") return "Workspace snapshot";
  if (event.componentKind === "restore_gate") {
    return event.eventKind === "workspace.restore.applied" || event.sourceEventKind === "WorkspaceRestore.Applied"
      ? "Restore apply"
      : "Restore preview";
  }
  if (event.componentKind === "usage_telemetry") return "Usage telemetry";
  if (event.componentKind === "context_pressure") return "Context pressure";
  if (event.componentKind === "context_pressure_alert") return "Context pressure alert";
  if (event.componentKind === "workspace_trust") {
    return event.type === "workspace_trust_acknowledged" ||
      event.eventKind === "workspace.trust_acknowledged"
      ? "Workspace trust acknowledged"
      : "Workspace trust warning";
  }
  if (event.componentKind === "workflow_edit_proposal") {
    return event.type === "workflow_edit_applied" ||
      event.eventKind === "workflow.edit_applied"
      ? "Workflow edit applied"
      : "Workflow edit proposal";
  }
  if (event.componentKind === "approval_gate") {
    if (event.type === "approval_decision" || event.eventKind.startsWith("approval.")) {
      return event.status.toLowerCase().includes("rejected")
        ? "Approval rejected"
        : "Approval approved";
    }
    return "Approval gate";
  }
  if (event.componentKind === "context_budget") return "Context budget";
  if (event.componentKind === "compaction_policy") return "Compaction policy";
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
    case "context_budget_evaluated":
      return "Context budget";
    case "compaction_policy_evaluated":
      return "Compaction policy";
    case "usage_delta":
      return "Usage telemetry";
    case "context_pressure_delta":
      return "Context pressure";
    case "context_pressure_alert":
      return "Context pressure alert";
    case "workspace_trust_warning":
      return "Workspace trust warning";
    case "workspace_trust_acknowledged":
      return "Workspace trust acknowledged";
    case "workflow_edit_proposed":
      return "Workflow edit proposal";
    case "workflow_edit_applied":
      return "Workflow edit applied";
    case "reasoning_delta":
      return "Reasoning";
    case "tool_completed":
      return "Tool result";
    case "tool_failed":
      return "Tool failed";
    case "approval_required":
      return "Approval gate";
    case "approval_decision":
      return event.status.toLowerCase().includes("rejected")
        ? "Approval rejected"
        : "Approval approved";
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
  if (event.type === "workflow_edit_proposed") return "waiting";
  if (event.type === "workflow_edit_applied") return "completed";
  if (event.type === "policy_blocked") return "blocked";
  if (event.type === "context_pressure_alert") {
    return event.status.toLowerCase().includes("blocked")
      ? "blocked"
      : "warning";
  }
  if (event.type === "tool_failed" || event.type === "turn_failed") return "failed";
  if (event.type === "turn_canceled") return "canceled";
  if (event.type === "turn_interrupted") return "interrupted";

  const normalizedStatus = event.status.toLowerCase();
  if (normalizedStatus.includes("queued")) return "queued";
  if (normalizedStatus.includes("running")) return "running";
  if (normalizedStatus.includes("waiting")) return "waiting";
  if (
    normalizedStatus.includes("warning") ||
    normalizedStatus.includes("warn") ||
    normalizedStatus.includes("elevated")
  ) {
    return "warning";
  }
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
  const computerUse = computerUseProjectionForRuntimeThreadEvent(event);
  if (computerUse) return summaryForComputerUseProjection(computerUse);
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

function booleanField(
  value: unknown,
  ...keys: string[]
): boolean | null {
  const objectValue = objectField(value);
  if (!objectValue) return null;
  const candidate = keys.find((key) => objectValue[key] !== undefined);
  const valueForKey = candidate ? objectValue[candidate] : undefined;
  if (typeof valueForKey === "boolean") return valueForKey;
  if (typeof valueForKey === "string" && valueForKey.trim()) {
    const normalized = valueForKey.toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
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

function nonEmptyArrayField(
  value: unknown,
  ...keys: string[]
): boolean {
  return arrayField(value, ...keys).length > 0;
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

function codingToolCommandForToolName(toolName: string | null): string {
  switch (toolName) {
    case "workspace.status":
      return "status";
    case "git.diff":
      return "diff";
    case "file.inspect":
      return "inspect";
    case "file.apply_patch":
      return "patch";
    case "test.run":
      return "test";
    case "lsp.diagnostics":
      return "diagnostics";
    case "artifact.read":
      return "artifact";
    case "tool.retrieve_result":
      return "retrieve";
    default:
      return "tool";
  }
}

function tuiControlRowStatus(
  status: string | null,
): WorkflowRuntimeTuiControlRowStatus {
  const normalizedStatus = status?.toLowerCase() ?? null;
  if (normalizedStatus === "approve") return "approved";
  if (normalizedStatus === "reject") return "rejected";
  if (normalizedStatus === "ok" || normalizedStatus === "nominal") return "current";
  if (normalizedStatus === "warn" || normalizedStatus === "elevated") return "current";
  if (normalizedStatus === "high") return "blocked";
  if (normalizedStatus === "compact_pending") return "pending";
  if (normalizedStatus === "compacted") return "completed";
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
    case "warning":
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
