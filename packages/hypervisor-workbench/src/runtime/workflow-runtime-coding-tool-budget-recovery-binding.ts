import type {
  Node,
  NodeLogic,
  WorkflowFieldMapping,
  WorkflowProject,
  WorkflowValidationIssue,
} from "../types/graph";
import {
  normalizeWorkflowCodingToolBudgetRecoveryPolicy,
  type WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor,
} from "./workflow-runtime-coding-tool-budget-recovery-policy";
import type {
  WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
} from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_BINDING_SCHEMA_VERSION =
  "ioi.workflow.runtime-coding-tool-budget-recovery-binding.v1" as const;

const RECOVERY_NODE_TYPE = "runtime_coding_tool_budget_recovery";
const RECOVERY_ACTION_ORDER = [
  "request_approval",
  "approve_override",
  "reject_override",
  "retry_approved",
  "review_receipt",
] as const;

export interface WorkflowRuntimeCodingToolBudgetRecoveryEvidenceBinding {
  schemaVersion: typeof WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_BINDING_SCHEMA_VERSION;
  source: "react_flow_quick_fix";
  fieldMappingSource: string;
  runId: string;
  threadId: string;
  approvalId: string;
  sourceEventId: string;
  blockedEventId: string;
  approvalRequestEventId: string | null;
  approvalDecisionEventId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string;
  targetNodeIds: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
  recoveryPolicy: WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor;
}

export interface WorkflowRuntimeCodingToolBudgetRecoveryTemplateBindingResult {
  workflow: WorkflowProject;
  nodes: Node[];
  boundNodeIds: string[];
  evidenceBinding: WorkflowRuntimeCodingToolBudgetRecoveryEvidenceBinding | null;
  status: "bound" | "blocked";
  blockers: string[];
}

export type WorkflowRuntimeCodingToolBudgetRecoveryNodeBindingResult = Omit<
  WorkflowRuntimeCodingToolBudgetRecoveryTemplateBindingResult,
  "workflow"
>;

export function workflowRuntimeCodingToolBudgetRecoveryBindingIssue(
  issue: WorkflowValidationIssue | null | undefined,
): boolean {
  return Boolean(
    issue?.code.startsWith("missing_runtime_coding_tool_budget_recovery_") ||
      issue?.repairActionId ===
        "bind-coding-tool-budget-recovery-evidence" ||
      issue?.repairLabel === "Bind recovery input",
  );
}

export function workflowRuntimeCodingToolBudgetRecoveryEvidenceAction(
  actions: readonly WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor[],
): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor | null {
  const candidates = actions.filter((action) => Boolean(action.runId));
  for (const actionName of RECOVERY_ACTION_ORDER) {
    const match = candidates.find((action) => action.action === actionName);
    if (match) return match;
  }
  return candidates[0] ?? null;
}

export function workflowRuntimeCodingToolBudgetRecoveryEvidenceActionsFromProjection(
  projection: {
    reactFlowNodes?: readonly {
      data?: {
        codingToolBudgetRecoveryActions?: readonly WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor[];
      };
    }[];
  } | null | undefined,
): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor[] {
  return [
    ...new Map(
      (projection?.reactFlowNodes ?? [])
        .flatMap((node) => node.data?.codingToolBudgetRecoveryActions ?? [])
        .map((action) => [action.id, action] as const),
    ).values(),
  ];
}

export function bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence(
  workflow: WorkflowProject,
  action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor | null | undefined,
  options: { issue?: WorkflowValidationIssue | null } = {},
): WorkflowRuntimeCodingToolBudgetRecoveryTemplateBindingResult {
  const result = bindWorkflowRuntimeCodingToolBudgetRecoveryNodesToEvidence(
    workflow.nodes,
    action,
    options,
  );
  return {
    ...result,
    workflow: {
      ...workflow,
      metadata: {
        ...workflow.metadata,
        dirty: workflow.metadata.readOnly ? false : true,
        updatedAtMs: Date.now(),
      },
      nodes: result.nodes,
    },
  };
}

export function bindWorkflowRuntimeCodingToolBudgetRecoveryNodesToEvidence(
  nodes: readonly Node[],
  action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor | null | undefined,
  options: { issue?: WorkflowValidationIssue | null } = {},
): WorkflowRuntimeCodingToolBudgetRecoveryNodeBindingResult {
  const evidenceBinding = workflowRuntimeCodingToolBudgetRecoveryEvidenceBinding(
    action,
  );
  const targetNodeIds = recoveryTemplateTargetNodeIds(nodes, options.issue);
  const blockers = [
    ...(evidenceBinding ? [] : ["coding_tool_budget_recovery_evidence_missing"]),
    ...(targetNodeIds.length > 0
      ? []
      : ["coding_tool_budget_recovery_template_node_missing"]),
  ];

  if (!evidenceBinding || targetNodeIds.length === 0) {
    return {
      nodes: [...nodes],
      boundNodeIds: [],
      evidenceBinding,
      status: "blocked",
      blockers,
    };
  }

  const targetSet = new Set(targetNodeIds);
  const boundNodes = nodes.map((node) =>
    targetSet.has(node.id)
      ? bindRecoveryNodeToEvidence(node, evidenceBinding)
      : node,
  );
  return {
    nodes: boundNodes,
    boundNodeIds: targetNodeIds,
    evidenceBinding,
    status: "bound",
    blockers: [],
  };
}

function workflowRuntimeCodingToolBudgetRecoveryEvidenceBinding(
  action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor | null | undefined,
): WorkflowRuntimeCodingToolBudgetRecoveryEvidenceBinding | null {
  if (!action?.runId) return null;
  const sourceEventId = action.sourceEventId ?? action.eventId;
  const targetNodeIds = uniqueStrings([
    ...(action.recoveryPolicy?.targetNodeIds ?? []),
    ...action.targetNodeIds,
    action.workflowNodeId,
  ]);
  const approvalId =
    action.approvalId ??
    `approval_workflow_run_coding_tool_budget_${safeId(
      action.runId,
    )}_${safeId(sourceEventId)}`;
  const recoveryPolicy = normalizeWorkflowCodingToolBudgetRecoveryPolicy(
    action.recoveryPolicy ?? {
      source: "react_flow_quick_fix",
      targetNodeIds,
      sourceNodeIds: targetNodeIds,
    },
    targetNodeIds,
  );
  const fieldMappingSource =
    `{{runtime.codingToolBudgetRecoveryEvidence.${safeId(action.eventId)}}}`;

  return {
    schemaVersion:
      WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_BINDING_SCHEMA_VERSION,
    source: "react_flow_quick_fix",
    fieldMappingSource,
    runId: action.runId,
    threadId: action.threadId,
    approvalId,
    sourceEventId,
    blockedEventId: action.eventId,
    approvalRequestEventId: action.approvalRequestEventId,
    approvalDecisionEventId: action.approvalDecisionEventId,
    workflowGraphId: action.workflowGraphId,
    workflowNodeId: action.workflowNodeId,
    targetNodeIds,
    receiptRefs: uniqueStrings(action.receiptRefs),
    policyDecisionRefs: uniqueStrings(action.policyDecisionRefs),
    recoveryPolicy,
  };
}

function bindRecoveryNodeToEvidence(
  node: Node,
  evidence: WorkflowRuntimeCodingToolBudgetRecoveryEvidenceBinding,
): Node {
  const logic = node.config?.logic ?? {};
  const fieldMappings = recoveryEvidenceFieldMappings(evidence);
  const inputMapping = recoveryEvidenceInputMapping(evidence);
  const nextLogic: NodeLogic = {
    ...logic,
    runtimeCodingToolBudgetRecoveryRunId: evidence.runId,
    runtimeCodingToolBudgetRecoveryThreadId: evidence.threadId,
    runtimeCodingToolBudgetRecoveryApprovalId: evidence.approvalId,
    runtimeCodingToolBudgetRecoverySourceEventId: evidence.sourceEventId,
    runtimeCodingToolBudgetRecoveryBlockedEventId: evidence.blockedEventId,
    runtimeCodingToolBudgetRecoveryApprovalRequestEventId:
      evidence.approvalRequestEventId ?? undefined,
    runtimeCodingToolBudgetRecoveryApprovalDecisionEventId:
      evidence.approvalDecisionEventId ?? undefined,
    runtimeCodingToolBudgetRecoveryTargetNodeIds: evidence.targetNodeIds,
    runtimeCodingToolBudgetRecoveryPolicy: evidence.recoveryPolicy,
    runtimeCodingToolBudgetRecoveryReceiptRefsField: "receiptRefs",
    runtimeCodingToolBudgetRecoveryPolicyDecisionRefsField:
      "policyDecisionRefs",
    inputMapping: {
      ...(logic.inputMapping ?? {}),
      ...inputMapping,
    },
    fieldMappings: {
      ...(logic.fieldMappings ?? {}),
      ...fieldMappings,
    },
    testInput: {
      ...(objectValue(logic.testInput) ?? {}),
      runId: evidence.runId,
      threadId: evidence.threadId,
      approvalId: evidence.approvalId,
      sourceEventId: evidence.sourceEventId,
      blockedEventId: evidence.blockedEventId,
      targetNodeIds: evidence.targetNodeIds,
      recoveryPolicy: evidence.recoveryPolicy,
      receiptRefs: evidence.receiptRefs,
      policyDecisionRefs: evidence.policyDecisionRefs,
    },
    runtimeCodingToolBudgetRecovery: {
      ...(objectValue(logic.runtimeCodingToolBudgetRecovery) ?? {}),
      evidenceBinding: evidence,
    },
  };
  return {
    ...node,
    config: {
      kind: node.type as any,
      ...(node.config ?? {}),
      law: node.config?.law ?? {},
      logic: nextLogic,
    } as NonNullable<Node["config"]>,
  };
}

function recoveryEvidenceFieldMappings(
  evidence: WorkflowRuntimeCodingToolBudgetRecoveryEvidenceBinding,
): Record<string, WorkflowFieldMapping> {
  return {
    runId: {
      source: evidence.fieldMappingSource,
      path: "runId",
      type: "string",
    },
    threadId: {
      source: evidence.fieldMappingSource,
      path: "threadId",
      type: "string",
    },
    approvalId: {
      source: evidence.fieldMappingSource,
      path: "approvalId",
      type: "string",
    },
    targetNodeIds: {
      source: evidence.fieldMappingSource,
      path: "targetNodeIds",
      type: "array",
    },
    recoveryPolicy: {
      source: evidence.fieldMappingSource,
      path: "recoveryPolicy",
      type: "object",
    },
  };
}

function recoveryEvidenceInputMapping(
  evidence: WorkflowRuntimeCodingToolBudgetRecoveryEvidenceBinding,
): Record<string, string> {
  const source = evidence.fieldMappingSource.replace(/\}\}$/, "");
  return {
    runId: `${source}.runId}}`,
    threadId: `${source}.threadId}}`,
    approvalId: `${source}.approvalId}}`,
    targetNodeIds: `${source}.targetNodeIds}}`,
    recoveryPolicy: `${source}.recoveryPolicy}}`,
  };
}

function recoveryTemplateTargetNodeIds(
  nodes: readonly Node[],
  issue: WorkflowValidationIssue | null | undefined,
): string[] {
  const recoveryNodes = nodes.filter((node) => node.type === RECOVERY_NODE_TYPE);
  if (issue?.nodeId) {
    const prefix = recoveryTemplatePrefix(issue.nodeId);
    const groupNodes = recoveryNodes.filter(
      (node) => recoveryTemplatePrefix(node.id) === prefix,
    );
    if (groupNodes.length > 0) return groupNodes.map((node) => node.id);
    return recoveryNodes.some((node) => node.id === issue.nodeId)
      ? [issue.nodeId]
      : [];
  }
  const templateNodes = recoveryNodes.filter((node) => {
    const logic = node.config?.logic ?? {};
    const policy = objectValue(logic.runtimeCodingToolBudgetRecoveryPolicy);
    return (
      stringValue(policy?.source) === "react_flow_template" ||
      !stringValue(logic.runtimeCodingToolBudgetRecoveryRunId)
    );
  });
  return templateNodes.map((node) => node.id);
}

function recoveryTemplatePrefix(nodeId: string): string {
  return nodeId.replace(/-(request|approve|reject|retry)$/, "");
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return [
    ...new Set(
      values
        .flat()
        .map((value) => stringValue(value))
        .filter((value): value is string => Boolean(value)),
    ),
  ];
}

function safeId(value: unknown): string {
  return String(value ?? "runtime")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96);
}
