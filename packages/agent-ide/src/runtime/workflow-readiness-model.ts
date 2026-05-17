import type {
  GraphProductionProfile,
  Node,
  WorkflowConnectionClass,
  WorkflowHarnessDefaultRuntimeDispatchProof,
  WorkflowHarnessSlotSpec,
  WorkflowProject,
  WorkflowSchedulerLaneReadiness,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import { workflowSchedulerLaneReadiness } from "./workflow-scheduler-lane-readiness";
import type { WorkflowRunCodingToolBudgetEvidence } from "./workflow-run-history-model";
import {
  workflowCodingToolBudgetRecoveryPolicyFromWorkflow,
  type WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor,
} from "./workflow-runtime-coding-tool-budget-recovery-policy";
import {
  workflowCapabilityPreflight,
  type WorkflowCapabilityPreflight,
} from "./workflow-capability-preflight";

export type WorkflowReadinessChecklistItem = {
  label: string;
  ready: boolean;
};

export type WorkflowReadinessAttentionIssue = {
  issue: WorkflowValidationIssue;
  status: "blocked" | "warning";
};

export type WorkflowCodingToolBudgetPreflight = {
  sourceKind: "tui_coding_tool_rows";
  status: "blocked" | "warning";
  issue: WorkflowValidationIssue;
  rowCount: number;
  targetNodeIds: string[];
  evidenceWorkflowNodeIds: string[];
  eventIds: string[];
  toolNames: string[];
  toolCallIds: string[];
  budgetStatuses: string[];
  contextBudgetStatuses: string[];
  totalTokens: number | null;
  costEstimateUsd: number | null;
  contextPressure: number | null;
  contextPressureStatus: string | null;
  mutationBlocked: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  recoveryPolicy: WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor;
};

export type WorkflowCodingToolBudgetRunLaunchAnnotation = {
  schemaVersion: "ioi.workflow.coding-tool-budget-preflight.v1";
  sourceKind: "tui_coding_tool_rows";
  status: "blocked" | "warning";
  rowCount: number;
  targetNodeIds: string[];
  evidenceWorkflowNodeIds: string[];
  eventIds: string[];
  toolNames: string[];
  toolCallIds: string[];
  budgetStatuses: string[];
  contextBudgetStatuses: string[];
  totalTokens: number | null;
  costEstimateUsd: number | null;
  contextPressure: number | null;
  contextPressureStatus: string | null;
  mutationBlocked: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  recoveryPolicy: WorkflowRuntimeCodingToolBudgetRecoveryPolicyDescriptor;
  issueCode: string;
  issueMessage: string;
};

export type WorkflowReadinessModelInput = {
  validationResult: WorkflowValidationResult | null;
  readinessResult: WorkflowValidationResult | null;
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  operationalSideEffectNodes: Node[];
  hasErrorOrRetryPath: boolean;
  criticalAiNodeIds: string[];
  productionProfile: GraphProductionProfile;
  coveredNodeIds: Set<string>;
  mcpToolNodes: Node[];
  harnessWorkflow: boolean;
  harnessSlots: WorkflowHarnessSlotSpec[];
  boundHarnessSlotIds: Set<string>;
  harnessActivationReady: boolean;
  harnessDefaultRuntimeDispatchProof?:
    | WorkflowHarnessDefaultRuntimeDispatchProof
    | null;
  harnessAuthorityGateLiveReady: boolean;
  runtimeCodingToolBudgetEvidence?: WorkflowRunCodingToolBudgetEvidence | null;
};

export type WorkflowReadinessModel = {
  result: WorkflowValidationResult | null;
  blockers: WorkflowValidationIssue[];
  readinessWarnings: WorkflowValidationIssue[];
  policyRequiredNodeIds: string[];
  schedulerLaneReadiness: WorkflowSchedulerLaneReadiness[];
  schedulerLaneReadyCount: number;
  capabilityPreflight: WorkflowCapabilityPreflight | null;
  codingToolBudgetPreflight: WorkflowCodingToolBudgetPreflight | null;
  readinessItems: WorkflowReadinessChecklistItem[];
  passedReadinessChecks: number;
  attentionIssues: WorkflowReadinessAttentionIssue[];
};

function workflowHasIncomingConnectionClass(
  workflow: WorkflowProject,
  nodeId: string,
  connectionClass: WorkflowConnectionClass,
): boolean {
  return workflow.edges.some((edge) => {
    if (edge.to !== nodeId) return false;
    const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
    return edgeClass === connectionClass || edge.toPort === connectionClass;
  });
}

export function workflowReadinessModel({
  validationResult,
  readinessResult,
  workflow,
  tests,
  operationalSideEffectNodes,
  hasErrorOrRetryPath,
  criticalAiNodeIds,
  productionProfile,
  coveredNodeIds,
  mcpToolNodes,
  harnessWorkflow,
  harnessSlots,
  boundHarnessSlotIds,
  harnessActivationReady,
  harnessDefaultRuntimeDispatchProof,
  harnessAuthorityGateLiveReady,
  runtimeCodingToolBudgetEvidence = null,
}: WorkflowReadinessModelInput): WorkflowReadinessModel {
  const result = readinessResult ?? validationResult;
  const baseBlockers = result
    ? [
        ...result.errors,
        ...(result.executionReadinessIssues ?? []),
        ...result.missingConfig,
        ...result.connectorBindingIssues,
        ...(result.verificationIssues ?? []),
      ]
    : [];
  const baseReadinessWarnings = result?.warnings ?? [];
  const capabilityPreflight = workflowCapabilityPreflight(workflow);
  const codingToolBudgetPreflight = workflowCodingToolBudgetPreflight({
    workflow,
    evidence: runtimeCodingToolBudgetEvidence,
  });
  const capabilityPreflightIssuePresent = baseBlockers.some(
    (issue) => issue.code === capabilityPreflight?.issue.code,
  );
  const blockers = [
    ...baseBlockers,
    ...(capabilityPreflight && !capabilityPreflightIssuePresent
      ? [capabilityPreflight.issue]
      : []),
    ...(codingToolBudgetPreflight?.status === "blocked"
      ? [codingToolBudgetPreflight.issue]
      : []),
  ];
  const readinessWarnings = [
    ...baseReadinessWarnings,
    ...(codingToolBudgetPreflight?.status === "warning"
      ? [codingToolBudgetPreflight.issue]
      : []),
  ];
  const policyRequiredNodeIds = result?.policyRequiredNodes ?? [];
  const schedulerLaneReadiness =
    result?.schedulerLaneReadiness ?? workflowSchedulerLaneReadiness();
  const schedulerLaneReadyCount = schedulerLaneReadiness.filter(
    (lane) => lane.status === "ready",
  ).length;
  const readinessItems: WorkflowReadinessChecklistItem[] = [
    {
      label: "Trigger or source",
      ready: workflow.nodes.some(
        (node) => node.type === "trigger" || node.type === "source",
      ),
    },
    {
      label: "Model binding",
      ready: !workflow.nodes.some((node) => {
        if (node.type !== "model_call") return false;
        const modelRef = String(node.config?.logic?.modelRef ?? "");
        return (
          !workflow.global_config.modelBindings?.[modelRef]?.modelId &&
          !workflowHasIncomingConnectionClass(workflow, node.id, "model")
        );
      }),
    },
    {
      label: "Mock/live mode explicit",
      ready: !workflow.nodes.some((node) => {
        const logic = node.config?.logic ?? {};
        const binding =
          logic.toolBinding ??
          logic.connectorBinding ??
          logic.modelBinding ??
          logic.parserBinding;
        return binding && typeof binding.mockBinding !== "boolean";
      }),
    },
    {
      label: "Live bindings for activation",
      ready: !workflow.nodes.some((node) => {
        const logic = node.config?.logic ?? {};
        const binding =
          logic.toolBinding ??
          logic.connectorBinding ??
          logic.modelBinding ??
          logic.parserBinding;
        return binding?.mockBinding === true;
      }),
    },
    {
      label: "Error handling",
      ready: operationalSideEffectNodes.length === 0 || hasErrorOrRetryPath,
    },
    {
      label: "Evaluation coverage",
      ready:
        criticalAiNodeIds.length === 0 ||
        Boolean(productionProfile.evaluationSetPath?.trim()) ||
        criticalAiNodeIds.every((nodeId) => coveredNodeIds.has(nodeId)),
    },
    {
      label: "Replay samples",
      ready: !readinessWarnings.some(
        (issue) => issue.code === "missing_replay_fixture",
      ),
    },
    {
      label: "MCP access reviewed",
      ready:
        mcpToolNodes.length === 0 ||
        productionProfile.mcpAccessReviewed === true,
    },
    {
      label: "Value estimate",
      ready: Number(productionProfile.expectedTimeSavedMinutes ?? 0) > 0,
    },
    {
      label: "Outputs defined",
      ready: workflow.nodes.some((node) => node.type === "output"),
    },
    { label: "Tests present", ready: tests.length > 0 },
    {
      label: "Harness slots",
      ready:
        !harnessWorkflow ||
        harnessSlots.every((slot) => boundHarnessSlotIds.has(slot.slotId)),
    },
    {
      label: "Scheduler lanes",
      ready:
        schedulerLaneReadiness.length > 0 &&
        schedulerLaneReadyCount === schedulerLaneReadiness.length,
    },
    { label: "Harness activation", ready: harnessActivationReady },
    {
      label: "Authority gate live",
      ready:
        !harnessWorkflow ||
        !harnessDefaultRuntimeDispatchProof ||
        harnessAuthorityGateLiveReady,
    },
    {
      label: "Capability preflight",
      ready: capabilityPreflight === null,
    },
    {
      label: "Coding budget preflight",
      ready: codingToolBudgetPreflight === null,
    },
    { label: "Readiness checked", ready: readinessResult !== null },
    {
      label: "No blockers",
      ready: blockers.length === 0 && result?.status !== "blocked",
    },
  ];
  const passedReadinessChecks = readinessItems.filter((item) => item.ready)
    .length;
  const attentionIssues: WorkflowReadinessAttentionIssue[] = [
    ...blockers.map((issue) => ({ issue, status: "blocked" as const })),
    ...readinessWarnings.map((issue) => ({
      issue,
      status: "warning" as const,
    })),
  ];

  return {
    result,
    blockers,
    readinessWarnings,
    policyRequiredNodeIds,
    schedulerLaneReadiness,
    schedulerLaneReadyCount,
    capabilityPreflight,
    codingToolBudgetPreflight,
    readinessItems,
    passedReadinessChecks,
    attentionIssues,
  };
}

export function workflowCodingToolBudgetPreflight({
  workflow,
  evidence,
}: {
  workflow: WorkflowProject;
  evidence: WorkflowRunCodingToolBudgetEvidence | null;
}): WorkflowCodingToolBudgetPreflight | null {
  if (!evidence || evidence.rowCount <= 0) return null;
  const targetNodeIds = workflow.nodes
    .filter(workflowNodeIsMutatingCodingTool)
    .map((node) => node.id);
  if (targetNodeIds.length === 0) return null;
  const blocked =
    evidence.mutationBlocked ||
    evidence.status === "blocked" ||
    evidence.budgetStatuses.includes("exceeded") ||
    evidence.contextBudgetStatuses.includes("blocked");
  const status = blocked ? "blocked" : "warning";
  const eventId = evidence.eventIds[0] ?? "event pending";
  const toolCallId = evidence.toolCallIds[0] ?? "tool call pending";
  const sourceNodeId =
    evidence.workflowNodeIds[0] ?? "workflow node pending";
  const policyRef = evidence.policyDecisionRefs[0] ?? "policy pending";
  const toolLabel = evidence.toolNames[0] ?? "coding tool";
  const evidenceVerb = blocked ? "blocked" : "reported";
  const recoveryPolicy = workflowCodingToolBudgetRecoveryPolicyFromWorkflow(
    workflow,
    targetNodeIds,
  );
  return {
    sourceKind: "tui_coding_tool_rows",
    status,
    issue: {
      nodeId: targetNodeIds[0],
      code: "prior_coding_tool_budget_evidence",
      message:
        `Prior ${toolLabel} budget evidence ${eventId} from ${sourceNodeId} ` +
        `${evidenceVerb} ${toolCallId}; review ${policyRef} before invoking another mutating coding tool.`,
      repairLabel: "Review budget evidence",
      configSection: "runtimeTelemetrySummary",
      fieldPath: "tui_coding_tool_rows",
    },
    rowCount: evidence.rowCount,
    targetNodeIds,
    evidenceWorkflowNodeIds: evidence.workflowNodeIds,
    eventIds: evidence.eventIds,
    toolNames: evidence.toolNames,
    toolCallIds: evidence.toolCallIds,
    budgetStatuses: evidence.budgetStatuses,
    contextBudgetStatuses: evidence.contextBudgetStatuses,
    totalTokens: evidence.totalTokens,
    costEstimateUsd: evidence.costEstimateUsd,
    contextPressure: evidence.contextPressure,
    contextPressureStatus: evidence.contextPressureStatus,
    mutationBlocked: evidence.mutationBlocked,
    receiptRefs: evidence.receiptRefs,
    policyDecisionRefs: evidence.policyDecisionRefs,
    recoveryPolicy,
  };
}

export function workflowCodingToolBudgetRunLaunchAnnotation(
  preflight: WorkflowCodingToolBudgetPreflight | null,
): WorkflowCodingToolBudgetRunLaunchAnnotation | null {
  if (!preflight) return null;
  return {
    schemaVersion: "ioi.workflow.coding-tool-budget-preflight.v1",
    sourceKind: preflight.sourceKind,
    status: preflight.status,
    rowCount: preflight.rowCount,
    targetNodeIds: preflight.targetNodeIds,
    evidenceWorkflowNodeIds: preflight.evidenceWorkflowNodeIds,
    eventIds: preflight.eventIds,
    toolNames: preflight.toolNames,
    toolCallIds: preflight.toolCallIds,
    budgetStatuses: preflight.budgetStatuses,
    contextBudgetStatuses: preflight.contextBudgetStatuses,
    totalTokens: preflight.totalTokens,
    costEstimateUsd: preflight.costEstimateUsd,
    contextPressure: preflight.contextPressure,
    contextPressureStatus: preflight.contextPressureStatus,
    mutationBlocked: preflight.mutationBlocked,
    receiptRefs: preflight.receiptRefs,
    policyDecisionRefs: preflight.policyDecisionRefs,
    recoveryPolicy: preflight.recoveryPolicy,
    issueCode: preflight.issue.code,
    issueMessage: preflight.issue.message,
  };
}

function workflowNodeIsMutatingCodingTool(node: Node): boolean {
  if (node.type !== "plugin_tool") return false;
  const binding = node.config?.logic?.toolBinding;
  if (binding?.bindingKind !== "coding_tool_pack") return false;
  const sideEffectClass = String(binding.sideEffectClass ?? "none");
  return !["none", "read"].includes(sideEffectClass);
}
