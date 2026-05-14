import type { Node, NodeLogic } from "../types/graph";
import {
  normalizeWorkflowCodingToolBudgetRecoveryPolicy,
  type WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor,
} from "./workflow-runtime-coding-tool-budget-recovery-policy";

export const WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.runtime-coding-tool-budget-recovery-control.v1" as const;
export const RUNTIME_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID =
  "runtime.coding-tool-budget-recovery" as const;
export const RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE =
  "react_flow" as const;
export const RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND =
  "WorkflowRunCodingToolBudgetRecoveryControl" as const;
export const RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND =
  "coding_tool_budget_recovery" as const;
export const RUNTIME_CODING_TOOL_BUDGET_RECOVERY_PAYLOAD_SCHEMA_VERSION =
  "ioi.workflow.coding-tool-budget-recovery.v1" as const;

export type RuntimeCodingToolBudgetRecoveryAction =
  | "request_approval"
  | "approve_override"
  | "reject_override"
  | "retry_approved";

export interface RuntimeCodingToolBudgetRecoveryControlRequestBody {
  source: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE;
  actor: string;
  event_kind: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND;
  eventKind: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND;
  component_kind: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND;
  componentKind: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND;
  payload_schema_version: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_PAYLOAD_SCHEMA_VERSION;
  payloadSchemaVersion: typeof RUNTIME_CODING_TOOL_BUDGET_RECOVERY_PAYLOAD_SCHEMA_VERSION;
  action: RuntimeCodingToolBudgetRecoveryAction;
  recovery_action: RuntimeCodingToolBudgetRecoveryAction;
  recoveryAction: RuntimeCodingToolBudgetRecoveryAction;
  reason: string;
  run_id: string;
  runId: string;
  thread_id: string | null;
  threadId: string | null;
  approval_id: string;
  approvalId: string;
  source_event_id: string | null;
  sourceEventId: string | null;
  blocked_event_id: string | null;
  blockedEventId: string | null;
  approval_request_event_id: string | null;
  approvalRequestEventId: string | null;
  approval_decision_event_id: string | null;
  approvalDecisionEventId: string | null;
  target_node_ids: string[];
  targetNodeIds: string[];
  workflow_graph_id: string | null;
  workflowGraphId: string | null;
  workflow_node_id: string;
  workflowNodeId: string;
  recovery_policy: WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor;
  recoveryPolicy: WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor;
  receipt_refs: string[];
  receiptRefs: string[];
  policy_decision_refs: string[];
  policyDecisionRefs: string[];
}

export interface RuntimeCodingToolBudgetRecoveryControlRequest {
  schemaVersion: typeof WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_CONTROL_SCHEMA_VERSION;
  nodeType: "runtime_coding_tool_budget_recovery";
  nodeId: string | null;
  runId: string;
  threadId: string | null;
  action: RuntimeCodingToolBudgetRecoveryAction;
  endpoint: string;
  method: "POST";
  body: RuntimeCodingToolBudgetRecoveryControlRequestBody;
}

export interface RuntimeCodingToolBudgetRecoveryControlRequestInput {
  nodeId?: string | null;
  input?: unknown;
  runId?: string | null;
  runIdField?: string | null;
  threadId?: string | null;
  threadIdField?: string | null;
  action?: string | null;
  actionField?: string | null;
  approvalId?: string | null;
  approvalIdField?: string | null;
  sourceEventId?: string | null;
  sourceEventIdField?: string | null;
  blockedEventId?: string | null;
  blockedEventIdField?: string | null;
  approvalRequestEventId?: string | null;
  approvalRequestEventIdField?: string | null;
  approvalDecisionEventId?: string | null;
  approvalDecisionEventIdField?: string | null;
  targetNodeIds?: readonly string[] | string | null;
  targetNodeIdsField?: string | null;
  recoveryPolicy?: unknown;
  recoveryPolicyField?: string | null;
  reason?: string | null;
  reasonField?: string | null;
  endpoint?: string | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
  receiptRefs?: readonly string[] | null;
  receiptRefsField?: string | null;
  policyDecisionRefs?: readonly string[] | null;
  policyDecisionRefsField?: string | null;
}

export interface RuntimeCodingToolBudgetRecoveryWorkflowNodeOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

export function createRuntimeCodingToolBudgetRecoveryControlRequest(
  params: RuntimeCodingToolBudgetRecoveryControlRequestInput,
): RuntimeCodingToolBudgetRecoveryControlRequest {
  const action = runtimeCodingToolBudgetRecoveryAction(
    stringAtPath(params.input, params.actionField ?? "") ??
      cleanString(params.action),
  );
  const runId =
    cleanString(params.runId) ??
    stringAtPath(params.input, params.runIdField ?? "runId") ??
    stringAtPath(params.input, "run_id");
  if (!runId) {
    throw new Error(
      "runtime_coding_tool_budget_recovery nodes need a runId input before dispatch.",
    );
  }

  const threadId =
    cleanString(params.threadId) ??
    stringAtPath(params.input, params.threadIdField ?? "threadId") ??
    stringAtPath(params.input, "thread_id");
  const sourceEventId =
    cleanString(params.sourceEventId) ??
    stringAtPath(params.input, params.sourceEventIdField ?? "sourceEventId") ??
    stringAtPath(params.input, "source_event_id");
  const approvalId =
    cleanString(params.approvalId) ??
    stringAtPath(params.input, params.approvalIdField ?? "approvalId") ??
    stringAtPath(params.input, "approval_id") ??
    `approval_workflow_run_coding_tool_budget_${safeId(runId)}_${safeId(
      sourceEventId ?? "source",
    )}`;
  const blockedEventId =
    cleanString(params.blockedEventId) ??
    stringAtPath(params.input, params.blockedEventIdField ?? "blockedEventId") ??
    stringAtPath(params.input, "blocked_event_id");
  const approvalRequestEventId =
    cleanString(params.approvalRequestEventId) ??
    stringAtPath(
      params.input,
      params.approvalRequestEventIdField ?? "approvalRequestEventId",
    ) ??
    stringAtPath(params.input, "approval_request_event_id");
  const approvalDecisionEventId =
    cleanString(params.approvalDecisionEventId) ??
    stringAtPath(
      params.input,
      params.approvalDecisionEventIdField ?? "approvalDecisionEventId",
    ) ??
    stringAtPath(params.input, "approval_decision_event_id");
  const targetNodeIds = uniqueStrings([
    ...stringListOption(params.targetNodeIds),
    ...stringListAtPath(params.input, params.targetNodeIdsField ?? "targetNodeIds"),
    ...stringListAtPath(params.input, "target_node_ids"),
  ]);
  const recoveryPolicy = normalizeWorkflowCodingToolBudgetRecoveryPolicy(
    objectAtPath(params.input, params.recoveryPolicyField ?? "recoveryPolicy") ??
      objectAtPath(params.input, "recovery_policy") ??
      params.recoveryPolicy ??
      {
        source: RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE,
        targetNodeIds,
      },
    targetNodeIds,
  );
  const reason =
    stringAtPath(params.input, params.reasonField ?? "") ??
    cleanString(params.reason) ??
    "coding_tool_budget_preflight_blocked";
  const endpointTemplate =
    cleanString(params.endpoint) ?? "/v1/runs/{runId}/coding-tool-budget-recovery";
  const workflowGraphId = cleanString(params.workflowGraphId);
  const workflowNodeId =
    cleanString(params.workflowNodeId) ??
    RUNTIME_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID;
  const receiptRefs = uniqueStrings([
    ...(params.receiptRefs ?? []),
    ...stringListAtPath(params.input, params.receiptRefsField ?? "receiptRefs"),
    ...stringListAtPath(params.input, "receipt_refs"),
  ]);
  const policyDecisionRefs = uniqueStrings([
    ...(params.policyDecisionRefs ?? []),
    ...stringListAtPath(
      params.input,
      params.policyDecisionRefsField ?? "policyDecisionRefs",
    ),
    ...stringListAtPath(params.input, "policy_decision_refs"),
  ]);

  return {
    schemaVersion:
      WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_CONTROL_SCHEMA_VERSION,
    nodeType: "runtime_coding_tool_budget_recovery",
    nodeId: cleanString(params.nodeId),
    runId,
    threadId,
    action,
    endpoint: endpointFromTemplate(endpointTemplate, {
      runId,
      threadId: threadId ?? "",
      approvalId,
      sourceEventId: sourceEventId ?? "",
    }),
    method: "POST",
    body: {
      source: RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE,
      actor: cleanString(params.actor) ?? recoveryPolicy.operatorRole ?? "operator",
      event_kind: RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND,
      eventKind: RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND,
      component_kind: RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND,
      componentKind: RUNTIME_CODING_TOOL_BUDGET_RECOVERY_COMPONENT_KIND,
      payload_schema_version:
        RUNTIME_CODING_TOOL_BUDGET_RECOVERY_PAYLOAD_SCHEMA_VERSION,
      payloadSchemaVersion:
        RUNTIME_CODING_TOOL_BUDGET_RECOVERY_PAYLOAD_SCHEMA_VERSION,
      action,
      recovery_action: action,
      recoveryAction: action,
      reason,
      run_id: runId,
      runId,
      thread_id: threadId,
      threadId,
      approval_id: approvalId,
      approvalId,
      source_event_id: sourceEventId,
      sourceEventId,
      blocked_event_id: blockedEventId,
      blockedEventId,
      approval_request_event_id: approvalRequestEventId,
      approvalRequestEventId,
      approval_decision_event_id: approvalDecisionEventId,
      approvalDecisionEventId,
      target_node_ids: targetNodeIds,
      targetNodeIds,
      workflow_graph_id: workflowGraphId,
      workflowGraphId,
      workflow_node_id: workflowNodeId,
      workflowNodeId,
      recovery_policy: recoveryPolicy,
      recoveryPolicy,
      receipt_refs: receiptRefs,
      receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      policyDecisionRefs,
    },
  };
}

export function createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
  node: Pick<Node, "id" | "type" | "config">,
  input: unknown = {},
  options: RuntimeCodingToolBudgetRecoveryWorkflowNodeOptions = {},
): RuntimeCodingToolBudgetRecoveryControlRequest {
  const logic = runtimeCodingToolBudgetRecoveryWorkflowNodeLogic(node);
  return createRuntimeCodingToolBudgetRecoveryControlRequest({
    nodeId: node.id,
    input,
    runId: cleanString(logic.runtimeCodingToolBudgetRecoveryRunId),
    runIdField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryRunIdField) ?? "runId",
    threadId: cleanString(logic.runtimeCodingToolBudgetRecoveryThreadId),
    threadIdField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryThreadIdField) ??
      "threadId",
    action: cleanString(logic.runtimeCodingToolBudgetRecoveryAction),
    actionField: cleanString(logic.runtimeCodingToolBudgetRecoveryActionField),
    approvalId: cleanString(logic.runtimeCodingToolBudgetRecoveryApprovalId),
    approvalIdField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryApprovalIdField) ??
      "approvalId",
    sourceEventId: cleanString(logic.runtimeCodingToolBudgetRecoverySourceEventId),
    sourceEventIdField:
      cleanString(logic.runtimeCodingToolBudgetRecoverySourceEventIdField) ??
      "sourceEventId",
    blockedEventId: cleanString(logic.runtimeCodingToolBudgetRecoveryBlockedEventId),
    blockedEventIdField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryBlockedEventIdField) ??
      "blockedEventId",
    approvalRequestEventId: cleanString(
      logic.runtimeCodingToolBudgetRecoveryApprovalRequestEventId,
    ),
    approvalRequestEventIdField:
      cleanString(
        logic.runtimeCodingToolBudgetRecoveryApprovalRequestEventIdField,
      ) ?? "approvalRequestEventId",
    approvalDecisionEventId: cleanString(
      logic.runtimeCodingToolBudgetRecoveryApprovalDecisionEventId,
    ),
    approvalDecisionEventIdField:
      cleanString(
        logic.runtimeCodingToolBudgetRecoveryApprovalDecisionEventIdField,
      ) ?? "approvalDecisionEventId",
    targetNodeIds: logic.runtimeCodingToolBudgetRecoveryTargetNodeIds,
    targetNodeIdsField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryTargetNodeIdsField) ??
      "targetNodeIds",
    recoveryPolicy: logic.runtimeCodingToolBudgetRecoveryPolicy,
    recoveryPolicyField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryPolicyInputField) ??
      "recoveryPolicy",
    reason: cleanString(logic.runtimeCodingToolBudgetRecoveryReason),
    reasonField: cleanString(logic.runtimeCodingToolBudgetRecoveryReasonField),
    endpoint: cleanString(logic.runtimeCodingToolBudgetRecoveryEndpoint),
    workflowGraphId: cleanString(options.workflowGraphId),
    workflowNodeId:
      cleanString(logic.runtimeCodingToolBudgetRecoveryWorkflowNodeId) ??
      RUNTIME_CODING_TOOL_BUDGET_RECOVERY_WORKFLOW_NODE_ID,
    actor:
      cleanString(options.actor) ??
      cleanString(logic.runtimeCodingToolBudgetRecoveryActor),
    receiptRefsField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryReceiptRefsField) ??
      "receiptRefs",
    policyDecisionRefsField:
      cleanString(logic.runtimeCodingToolBudgetRecoveryPolicyDecisionRefsField) ??
      "policyDecisionRefs",
  });
}

function runtimeCodingToolBudgetRecoveryWorkflowNodeLogic(
  node: Pick<Node, "type" | "config">,
): NodeLogic {
  if (node.type !== "runtime_coding_tool_budget_recovery") {
    throw new Error(
      `Expected runtime_coding_tool_budget_recovery node, received ${node.type}.`,
    );
  }
  return node.config?.logic ?? {};
}

function runtimeCodingToolBudgetRecoveryAction(
  value: string | null,
): RuntimeCodingToolBudgetRecoveryAction {
  const normalized = (value ?? "request_approval")
    .trim()
    .toLowerCase()
    .replace(/[-.]/g, "_");
  switch (normalized) {
    case "approve":
    case "approved":
    case "approve_override":
    case "allow":
    case "allowed":
      return "approve_override";
    case "reject":
    case "rejected":
    case "reject_override":
    case "deny":
    case "denied":
      return "reject_override";
    case "retry":
    case "retry_approved":
    case "approved_retry":
      return "retry_approved";
    default:
      return "request_approval";
  }
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function stringAtPath(source: unknown, path: string): string | null {
  const value = valueAtPath(source, path);
  return cleanString(value);
}

function objectAtPath(source: unknown, path: string): Record<string, unknown> | null {
  const value = valueAtPath(source, path);
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringListAtPath(source: unknown, path: string): string[] {
  return stringListOption(valueAtPath(source, path));
}

function stringListOption(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => cleanString(item))
      .filter((item): item is string => Boolean(item));
  }
  const text = cleanString(value);
  if (!text) return [];
  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function valueAtPath(source: unknown, path: string): unknown {
  if (!path || !source || typeof source !== "object" || Array.isArray(source)) {
    return undefined;
  }
  return path.split(".").reduce<unknown>((current, segment) => {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    return (current as Record<string, unknown>)[segment];
  }, source);
}

function uniqueStrings(values: readonly unknown[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const text = cleanString(value);
    if (!text || seen.has(text)) continue;
    seen.add(text);
    result.push(text);
  }
  return result;
}

function endpointFromTemplate(
  template: string,
  values: Record<string, string>,
): string {
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (placeholder, key) => {
    const value = values[key];
    return value === undefined ? placeholder : encodeURIComponent(value);
  });
}

function safeId(value: unknown): string {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
