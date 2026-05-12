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

export type WorkflowReadinessChecklistItem = {
  label: string;
  ready: boolean;
};

export type WorkflowReadinessAttentionIssue = {
  issue: WorkflowValidationIssue;
  status: "blocked" | "warning";
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
};

export type WorkflowReadinessModel = {
  result: WorkflowValidationResult | null;
  blockers: WorkflowValidationIssue[];
  readinessWarnings: WorkflowValidationIssue[];
  policyRequiredNodeIds: string[];
  schedulerLaneReadiness: WorkflowSchedulerLaneReadiness[];
  schedulerLaneReadyCount: number;
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
}: WorkflowReadinessModelInput): WorkflowReadinessModel {
  const result = readinessResult ?? validationResult;
  const blockers = result
    ? [
        ...result.errors,
        ...(result.executionReadinessIssues ?? []),
        ...result.missingConfig,
        ...result.connectorBindingIssues,
        ...(result.verificationIssues ?? []),
      ]
    : [];
  const readinessWarnings = result?.warnings ?? [];
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
    readinessItems,
    passedReadinessChecks,
    attentionIssues,
  };
}
