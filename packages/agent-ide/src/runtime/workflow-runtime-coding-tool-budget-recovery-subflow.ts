import type { Edge, Node, NodeLogic } from "../types/graph";
import {
  workflowNodeDefaultLaw,
  workflowNodeDefaults,
} from "./workflow-node-registry";
import type { WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor } from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SUBFLOW_SCHEMA_VERSION =
  "ioi.workflow.runtime-coding-tool-budget-recovery-subflow.v1" as const;

const RECOVERY_NODE_TYPE = "runtime_coding_tool_budget_recovery" as const;
const RECOVERY_ENDPOINT = "/v1/runs/{runId}/coding-tool-budget-recovery";

type RecoverySubflowAction =
  | "request_approval"
  | "approve_override"
  | "reject_override"
  | "retry_approved";

export interface WorkflowRuntimeCodingToolBudgetRecoverySubflowOptions {
  idPrefix?: string;
  origin?: { x: number; y: number };
  horizontalSpacing?: number;
  verticalSpacing?: number;
}

export interface WorkflowRuntimeCodingToolBudgetRecoverySubflow {
  schemaVersion: typeof WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SUBFLOW_SCHEMA_VERSION;
  sourceEventId: string;
  blockedEventId: string;
  runId: string | null;
  threadId: string;
  workflowGraphId: string | null;
  sourceWorkflowNodeId: string;
  requestNodeId: string;
  approveNodeId: string;
  rejectNodeId: string;
  retryNodeId: string;
  nodes: Node[];
  edges: Edge[];
}

export function createWorkflowRuntimeCodingToolBudgetRecoverySubflow(
  action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  options: WorkflowRuntimeCodingToolBudgetRecoverySubflowOptions = {},
): WorkflowRuntimeCodingToolBudgetRecoverySubflow {
  const sourceEventId = action.sourceEventId ?? action.eventId;
  const idPrefix =
    cleanId(options.idPrefix) ??
    `coding-budget-recovery-${safeId(sourceEventId)}-${safeId(
      action.runId ?? action.threadId,
    )}`;
  const origin = options.origin ?? { x: 220, y: 220 };
  const horizontalSpacing = options.horizontalSpacing ?? 300;
  const verticalSpacing = options.verticalSpacing ?? 130;
  const approvalId =
    action.approvalId ??
    `approval_workflow_run_coding_tool_budget_${safeId(
      action.runId ?? action.eventId,
    )}_${safeId(sourceEventId)}`;

  const requestNodeId = `${idPrefix}-request`;
  const approveNodeId = `${idPrefix}-approve`;
  const rejectNodeId = `${idPrefix}-reject`;
  const retryNodeId = `${idPrefix}-retry`;

  const nodes = [
    recoveryNode(action, {
      id: requestNodeId,
      label: "Request budget approval",
      recoveryAction: "request_approval",
      approvalId,
      x: origin.x,
      y: origin.y,
    }),
    recoveryNode(action, {
      id: approveNodeId,
      label: "Approve budget override",
      recoveryAction: "approve_override",
      approvalId,
      x: origin.x + horizontalSpacing,
      y: origin.y - verticalSpacing / 2,
    }),
    recoveryNode(action, {
      id: rejectNodeId,
      label: "Reject budget override",
      recoveryAction: "reject_override",
      approvalId,
      x: origin.x + horizontalSpacing,
      y: origin.y + verticalSpacing / 2,
    }),
    recoveryNode(action, {
      id: retryNodeId,
      label: "Retry approved budget run",
      recoveryAction: "retry_approved",
      approvalId,
      x: origin.x + horizontalSpacing * 2,
      y: origin.y - verticalSpacing / 2,
    }),
  ];

  return {
    schemaVersion:
      WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SUBFLOW_SCHEMA_VERSION,
    sourceEventId,
    blockedEventId: action.eventId,
    runId: action.runId,
    threadId: action.threadId,
    workflowGraphId: action.workflowGraphId,
    sourceWorkflowNodeId: action.workflowNodeId,
    requestNodeId,
    approveNodeId,
    rejectNodeId,
    retryNodeId,
    nodes,
    edges: [
      recoveryEdge(idPrefix, requestNodeId, approveNodeId, "approval_path"),
      recoveryEdge(idPrefix, requestNodeId, rejectNodeId, "rejection_path"),
      recoveryEdge(idPrefix, approveNodeId, retryNodeId, "approved_retry"),
    ],
  };
}

function recoveryNode(
  action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  params: {
    id: string;
    label: string;
    recoveryAction: RecoverySubflowAction;
    approvalId: string;
    x: number;
    y: number;
  },
): Node {
  const targetNodeIds =
    action.recoveryPolicy?.targetNodeIds.length
      ? action.recoveryPolicy.targetNodeIds
      : action.targetNodeIds;
  const logic: NodeLogic = {
    runtimeCodingToolBudgetRecoveryEndpoint: RECOVERY_ENDPOINT,
    runtimeCodingToolBudgetRecoveryRunId: action.runId ?? undefined,
    runtimeCodingToolBudgetRecoveryRunIdField: "runId",
    runtimeCodingToolBudgetRecoveryThreadId: action.threadId,
    runtimeCodingToolBudgetRecoveryThreadIdField: "threadId",
    runtimeCodingToolBudgetRecoveryAction: params.recoveryAction,
    runtimeCodingToolBudgetRecoveryActionField: "action",
    runtimeCodingToolBudgetRecoveryApprovalId: params.approvalId,
    runtimeCodingToolBudgetRecoveryApprovalIdField: "approvalId",
    runtimeCodingToolBudgetRecoverySourceEventId:
      action.sourceEventId ?? action.eventId,
    runtimeCodingToolBudgetRecoverySourceEventIdField: "sourceEventId",
    runtimeCodingToolBudgetRecoveryBlockedEventId: action.eventId,
    runtimeCodingToolBudgetRecoveryBlockedEventIdField: "blockedEventId",
    runtimeCodingToolBudgetRecoveryApprovalRequestEventId:
      action.approvalRequestEventId ?? undefined,
    runtimeCodingToolBudgetRecoveryApprovalRequestEventIdField:
      "approvalRequestEventId",
    runtimeCodingToolBudgetRecoveryApprovalDecisionEventId:
      action.approvalDecisionEventId ?? undefined,
    runtimeCodingToolBudgetRecoveryApprovalDecisionEventIdField:
      "approvalDecisionEventId",
    runtimeCodingToolBudgetRecoveryTargetNodeIds: targetNodeIds,
    runtimeCodingToolBudgetRecoveryTargetNodeIdsField: "targetNodeIds",
    runtimeCodingToolBudgetRecoveryPolicy: action.recoveryPolicy ?? {
      source: "react_flow_run_inspector",
      targetNodeIds,
    },
    runtimeCodingToolBudgetRecoveryPolicyInputField: "recoveryPolicy",
    runtimeCodingToolBudgetRecoveryReason: "coding_tool_budget_preflight_blocked",
    runtimeCodingToolBudgetRecoveryReceiptRefsField: "receiptRefs",
    runtimeCodingToolBudgetRecoveryPolicyDecisionRefsField: "policyDecisionRefs",
    runtimeCodingToolBudgetRecoveryWorkflowNodeId: params.id,
    runtimeCodingToolBudgetRecoverySource: "react_flow",
    runtimeCodingToolBudgetRecoveryActor:
      action.recoveryPolicy?.operatorRole ?? "operator",
    redactionProfile: "runtime_coding_tool_budget_recovery_safe",
  };
  return {
    id: params.id,
    type: RECOVERY_NODE_TYPE,
    name: params.label,
    x: params.x,
    y: params.y,
    ...workflowNodeDefaults(RECOVERY_NODE_TYPE),
    config: {
      kind: RECOVERY_NODE_TYPE,
      logic,
      law: workflowNodeDefaultLaw(RECOVERY_NODE_TYPE),
    },
  };
}

function recoveryEdge(
  idPrefix: string,
  from: string,
  to: string,
  path: "approval_path" | "rejection_path" | "approved_retry",
): Edge {
  return {
    id: `${idPrefix}-edge-${path}`,
    from,
    to,
    fromPort: "recovery",
    toPort: "blocked_run",
    type: "control",
    connectionClass: "state",
    data: {
      status: "idle",
      active: false,
      connectionClass: "state",
      createdBy: "coding_tool_budget_recovery_subflow",
      path,
    },
  };
}

function cleanId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function safeId(value: unknown): string {
  return String(value ?? "runtime")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96);
}
