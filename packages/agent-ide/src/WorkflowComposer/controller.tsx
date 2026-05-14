import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
} from "react";
import {
  Brain,
  Cable,
  CheckCircle2,
  FileOutput,
  FlaskConical,
  GitCompare,
  GitPullRequest,
  Maximize2,
  Minimize2,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Plus,
  Rocket,
  Save,
  Search,
  Settings,
} from "lucide-react";
import type {
  Edge as ReactFlowEdge,
  Node as ReactFlowNode,
} from "@xyflow/react";
import { Canvas } from "../features/Editor/Canvas/Canvas";
import { WorkflowBottomShelf } from "../features/Workflows/WorkflowBottomShelf";
import { WorkflowRailPanel } from "../features/Workflows/WorkflowRailPanel";
import {
  WorkflowNodeConfigModal,
  type WorkflowCompatibleNodeHint,
  type WorkflowUpstreamReference,
} from "../features/Workflows/WorkflowNodeConfigModal";
import {
  ConnectorBindingModal,
  CreateWorkflowModal,
  DeployModal,
  ImportPackageModal,
  ModelBindingModal,
  ProposalPreviewModal,
  TestEditorModal,
} from "../features/Workflows/WorkflowComposerModals";
import type { WorkflowNodeConfigSectionId } from "../features/Workflows/WorkflowNodeConfigTypes";
import { useGraphExecution } from "../hooks/useGraphExecution";
import { useGraphState } from "../hooks/useGraphState";
import type {
  CreateWorkflowProjectRequest,
  CreateWorkflowProposalRequest,
  FirewallPolicy,
  GraphGlobalConfig,
  ImportWorkflowPackageRequest,
  Node,
  NodeLogic,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowBottomPanel,
  WorkflowHarnessActiveRuntimeRollbackApplyProof,
  WorkflowHarnessActivationAuditEvent,
  WorkflowConnectionClass,
  WorkflowHarnessActiveRuntimeRollbackExecutionProof,
  WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof,
  WorkflowHarnessActivationGateActionClickProof,
  WorkflowHarnessActivationGateCollectEvidenceClickProof,
  WorkflowHarnessActivationGateRollbackRestoreClickProof,
  WorkflowHarnessActivationIdGateClickProof,
  WorkflowHarnessPackageImportActivationApplyProof,
  WorkflowHarnessPackageImportActivationHandoffProof,
  WorkflowHarnessPackageImportActivationReplayIntegrityProof,
  WorkflowHarnessPackageImportReviewProof,
  WorkflowHarnessPackageEvidenceGateClickProof,
  WorkflowHarnessPackageEvidenceImportRoundTripProof,
  WorkflowHarnessComponentKind,
  WorkflowHarnessColdStartDeepLinkRestoreProof,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessDeepLinkReplayProof,
  WorkflowHarnessGroupView,
  WorkflowHarnessNodeAttemptRecord,
  WorkflowHarnessPromotionClusterId,
  WorkflowHarnessPromotionTransitionAttempt,
  WorkflowHarnessPromotionTransitionTarget,
  WorkflowHarnessShadowComparison,
  WorkflowHarnessWorkerInvariantNegativeEnforcementProof,
  WorkflowExecutionMode,
  WorkflowKind,
  WorkflowNodeKind,
  WorkflowPortDefinition,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRightPanel,
  WorkflowCheckpoint,
  WorkflowDogfoodRun,
  WorkflowNodeFixture,
  WorkflowNodeRun,
  WorkflowPackageImportReview,
  WorkflowPortablePackage,
  WorkflowResumeRequest,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowRevisionRestoreResult,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowValidationIssue,
  WorkflowValidationResult,
  WorkflowWorkbenchBundle,
  WorkflowWorkbenchTab,
} from "../types/graph";
import {
  actionKindForWorkflowNodeType,
  validateActionEdge,
  validateWorkflowConnection,
} from "../runtime/runtime-projection-adapter";
import {
  createRuntimeApprovalRequestControlRequest,
  createRuntimeContextCompactControlRequest,
  createRuntimeDiagnosticsRepairControlRequest,
  createRuntimeOperatorInterruptControlRequest,
  createRuntimeWorkspaceTrustAcknowledgementControlRequest,
} from "../runtime/workflow-runtime-control-nodes";
import { createRuntimeSubagentControlRequest } from "../runtime/workflow-runtime-subagent-control-nodes";
import type {
  WorkflowRuntimeContextPressureActionDescriptor,
  WorkflowRuntimeDiagnosticsRepairActionDescriptor,
  WorkflowRuntimeThreadEventLike,
  WorkflowRuntimeWorkspaceTrustActionDescriptor,
} from "../runtime/workflow-runtime-event-projection";
import {
  WORKFLOW_RUNTIME_TELEMETRY_POLL_INTERVAL_MS,
  createLiveWorkflowRunTelemetryHydration,
  mergeWorkflowRuntimeThreadEvents,
} from "../runtime/workflow-runtime-live-telemetry";
import {
  WORKFLOW_NODE_DEFINITIONS,
  type WorkflowNodeCreatorDefinition,
  type WorkflowNodeDefinition,
} from "../runtime/workflow-node-registry";
import {
  buildScratchWorkflow,
  type ScratchWorkflowBlueprintId,
} from "../runtime/workflow-scratch-blueprints";
import {
  makeDefaultWorkflow,
  normalizeGlobalConfig,
  slugify,
} from "../runtime/workflow-defaults";
import {
  applyWorkflowHarnessActivationCandidate,
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
  defaultAgentHarnessTests,
  executeWorkflowHarnessActiveRuntimeRollbackApply,
  executeWorkflowHarnessActiveRuntimeRollbackDryRun,
  executeWorkflowHarnessPromotionTransition,
  executeWorkflowHarnessReplayGate,
  executeWorkflowHarnessReplayDrill,
  executeWorkflowHarnessRollbackDrill,
  executeWorkflowHarnessRevisionRollback,
  forkDefaultAgentHarnessWorkflow,
  harnessSlotsForWorkflow,
  makeBlessedHarnessLiveHandoffProof,
  makeHarnessDefaultRuntimeDispatchProof,
  makeHarnessCanaryExecutionBoundaries,
  makeDefaultAgentHarnessWorkflow,
  makeHarnessForkActivationRecord,
  makeHarnessRuntimeSelectorDecision,
  makeWorkflowHarnessWorkerAttachLifecycle,
  makeWorkflowHarnessWorkerBindingRegistryRecord,
  makeWorkflowHarnessWorkerHandoffNodeAttempts,
  makeWorkflowHarnessWorkerLaunchEnvelope,
  makeWorkflowHarnessWorkerSessionRecord,
  recordWorkflowHarnessActivationDryRun,
  recordWorkflowHarnessRollbackTargetSelection,
  resolveWorkflowHarnessWorkerHandoffReceipt,
  runWorkflowHarnessRollbackRestoreCanaryProbe,
  workflowHarnessForkMutationCanaryNodeAttempts,
  workflowHarnessPackageImportActivationApplyProofBlockers,
  workflowHarnessWorkerAttachLifecycleComplete,
  workflowHarnessWorkerBinding,
  type WorkflowHarnessReviewedPackageSnapshotFields,
  workflowIsBlessedHarness,
  workflowIsHarness,
} from "../runtime/harness-workflow";
import {
  compatiblePortPair,
  createBlockedTestResult,
  createSubstrateProjectionProposal,
  createSubstrateProjectionRunSummary,
  createSubstrateProjectionTestResult,
  createWorkflowActionFailure,
  errorMessage,
  nodeFamilyCounts,
  nodeVisualStatus,
  preferredCompatiblePortPair,
  toWorkflowProject,
  workflowCanvasSearchResults,
  workflowNodeCreatorBadge,
} from "../runtime/workflow-composer-model";
import { workflowNodeDeclaredOutputSchema } from "../runtime/workflow-schema";
import {
  createWorkflowHarnessActivationCandidate,
  defaultTestsForWorkflow,
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "../runtime/workflow-validation";
import {
  groupFixturesByNodeId,
  workflowFixtureHashesForNode,
  workflowFixtureValidationForNode,
  workflowFixturesForNode,
} from "../runtime/workflow-fixture-model";
import {
  resolveWorkflowHarnessReplayInspection,
  workflowBindingCheckResult,
  type WorkflowBindingRegistryRow,
  workflowDurationLabel,
  workflowEnvironmentProfile,
  workflowEventLabel,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowLifecycleState,
  workflowNodeRunChildLineage,
  workflowNodeName,
  workflowTimeLabel,
  workflowUniqueReplayFixtureRefs,
} from "../runtime/workflow-rail-model";
import {
  BOTTOM_TABS,
  ACTION_BY_NODE_TYPE,
  EMPTY_CANVAS_START_CREATOR_IDS,
  NODE_GROUP_FILTERS,
  NODE_LIBRARY,
  RIGHT_PANELS,
  SCAFFOLD_GROUPS,
  HARNESS_PROMOTION_LIVE_GUI_SCRIPT,
  SCRATCH_DOGFOOD_SCRIPT,
  SCRATCH_DOGFOOD_WORKFLOW_NAME,
  SCRATCH_HEAVY_BLUEPRINTS,
  WorkflowHeaderAction,
  WorkflowInlineIcon,
  WORKFLOW_SCAFFOLDS,
  workflowActionMetadataLabel,
  workflowCanvasIssuesByNodeId,
  workflowChecksStatusMessage,
  workflowConfigSectionForIssue,
  workflowConfigSectionForNodeKind,
  workflowCreatorItemId,
  workflowIssueCountLabel,
  workflowPatchBoundedTargets,
  workflowValidationBlockingIssueCount,
  workflowValidationStatusMessage,
  type WorkflowNodeGroupFilter,
} from "./support";
import type { WorkflowComposerProps } from "./types";

const HARNESS_GROUP_NODE_PREFIX = "harness.group.";
const HARNESS_WORKBENCH_DEEP_LINK_PREFIX = "#harness-workbench";
const HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS: WorkflowHarnessPromotionClusterId[] =
  ["cognition", "routing_model", "verification_output", "authority_tooling"];

type HarnessWorkbenchDeepLink = {
  panel?: WorkflowRightPanel;
  groupId?: string;
  componentId?: string;
  runId?: string;
  selectorDecisionId?: string;
  dispatchId?: string;
  workerBindingId?: string;
  nodeAttemptId?: string;
  receiptRef?: string;
  replayFixtureRef?: string;
  rollbackTarget?: string;
  revisionBindingKind?: "current" | "candidate" | "rollback" | string;
  revisionBindingRef?: string;
  activationBlockerIndex?: string;
  activationBlockerRef?: string;
  activationAuditEventId?: string;
  activationGateId?: string;
  activationGateEvidenceRef?: string;
  activationGateNodeAttemptId?: string;
  activationGateReceiptRef?: string;
  activationGateReplayFixtureRef?: string;
};

type HarnessWorkbenchDeepLinkProbeCase = {
  id: string;
  link: HarnessWorkbenchDeepLink;
  expectedAttribute: string;
  expectedValue: string;
  selectedRailTestId: string;
  expectedParsedKey?: keyof HarnessWorkbenchDeepLink;
};

const HARNESS_GROUP_BOUNDARY_PORTS: WorkflowPortDefinition[] = [
  {
    id: "input",
    label: "input",
    direction: "input",
    dataType: "payload",
    connectionClass: "data",
    cardinality: "many",
    required: false,
    semanticRole: "input",
  },
  {
    id: "output",
    label: "output",
    direction: "output",
    dataType: "payload",
    connectionClass: "data",
    cardinality: "many",
    required: false,
    semanticRole: "output",
  },
  {
    id: "error",
    label: "error",
    direction: "output",
    dataType: "response",
    connectionClass: "error",
    cardinality: "many",
    required: false,
    semanticRole: "error",
  },
  {
    id: "retry",
    label: "retry",
    direction: "output",
    dataType: "response",
    connectionClass: "retry",
    cardinality: "many",
    required: false,
    semanticRole: "retry",
  },
];

function harnessGroupNodeId(groupId: string): string {
  return `${HARNESS_GROUP_NODE_PREFIX}${groupId}`;
}

function harnessGroupIdFromNodeId(nodeId: string | null): string | null {
  if (!nodeId?.startsWith(HARNESS_GROUP_NODE_PREFIX)) return null;
  return nodeId.slice(HARNESS_GROUP_NODE_PREFIX.length);
}

function uniqueHarnessRefs(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.trim().length > 0,
      ),
    ),
  );
}

const harnessActivationNotValidatedIssue: WorkflowValidationIssue = {
  code: "harness_activation_not_validated",
  message: "Harness fork has not minted an activation id yet.",
};

function workflowOnlyActivationMissingReadiness(
  base: WorkflowValidationResult,
): WorkflowValidationResult {
  return {
    ...base,
    status: "blocked",
    errors: [],
    warnings: [harnessActivationNotValidatedIssue],
    blockedNodes: [],
    missingConfig: [],
    connectorBindingIssues: [],
    executionReadinessIssues: [harnessActivationNotValidatedIssue],
    verificationIssues: [],
  };
}

function harnessPromotionClusterFor(
  workflow: WorkflowProject,
  clusterId: string,
) {
  return (
    workflow.metadata.harness?.promotionClusters?.find(
      (cluster) => String(cluster.clusterId) === String(clusterId),
    ) ?? null
  );
}

function workflowWithHarnessClusterReadiness(
  workflow: WorkflowProject,
  clusterId: string,
  readiness: "live_ready",
): WorkflowProject {
  const cluster = harnessPromotionClusterFor(workflow, clusterId);
  const componentKinds = new Set(cluster?.componentKinds ?? []);
  return {
    ...workflow,
    nodes: workflow.nodes.map((nodeItem) =>
      nodeItem.runtimeBinding?.componentKind &&
      componentKinds.has(nodeItem.runtimeBinding.componentKind)
        ? {
            ...nodeItem,
            runtimeBinding: {
              ...nodeItem.runtimeBinding,
              readiness,
            },
          }
        : nodeItem,
    ),
  };
}

function workflowWithHarnessCanaryBoundaries(
  workflow: WorkflowProject,
): WorkflowProject {
  const harness = workflow.metadata.harness;
  if (!harness) return workflow;
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: {
        ...harness,
        canaryExecutionBoundaries: makeHarnessCanaryExecutionBoundaries(),
      },
    },
  };
}

function workflowWithPassingHarnessReplayGate(
  workflow: WorkflowProject,
  clusterId: string,
  nowMs: number,
): WorkflowProject {
  return executeWorkflowHarnessReplayGate(
    workflow,
    [
      {
        replayFixtureRef: `runtime-evidence:${clusterId}:fixture:live-gui`,
        sourceKind: "harness_group",
        sourceLabel: `${clusterId} live GUI promotion interaction`,
        producerComponent: `ioi.agent-harness.${clusterId}.v1`,
        policyDecision: "accept_live_gui_promotion_replay",
        attemptId: `attempt-${clusterId}-live-gui`,
        receiptRef: `receipt-${clusterId}-live-gui`,
        runId: `run-${clusterId}-live-gui`,
        executionMode: "gated",
        readiness: "live_ready",
        inputHash: `input-${clusterId}-live-gui`,
        outputHash: `output-${clusterId}-live-gui`,
        deterministicEnvelope: true,
        capturesInput: true,
        capturesOutput: true,
        capturesPolicyDecision: true,
        determinism: "deterministic",
        redactionPolicy: "runtime_redacted",
        evidenceRefs: [`evidence-${clusterId}-live-gui`],
      },
    ],
    {
      scopeKind: "harness_group",
      targetId: clusterId,
      nowMs,
    },
  ).workflow;
}

function workflowReadyForHarnessPromotion(
  workflow: WorkflowProject,
  clusterId: string,
  nowMs: number,
): WorkflowProject {
  return workflowWithHarnessClusterReadiness(
    workflowWithHarnessCanaryBoundaries(
      workflowWithPassingHarnessReplayGate(workflow, clusterId, nowMs),
    ),
    clusterId,
    "live_ready",
  );
}

function workflowWithMintableHarnessActivationCandidate(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
  nowMs: number,
): {
  workflow: WorkflowProject;
  candidate: WorkflowHarnessForkActivationCandidate;
} {
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const workerBinding = {
    ...workflow.metadata.workerHarnessBinding,
    harnessWorkflowId: workflowId,
    harnessActivationId: undefined,
    harnessHash:
      workflow.metadata.workerHarnessBinding?.harnessHash ??
      workflow.metadata.harness?.harnessHash ??
      "",
    source: "fork" as const,
  };
  const forkMutationCanary = workflow.metadata.harness?.forkMutationCanary;
  const activationRecord = makeHarnessForkActivationRecord({
    workflowId,
    harnessWorkflowId: workflowId,
    activationState: "blocked",
    activationBlockers: [],
    canaryStatus: "passed",
    rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    rollbackAvailable: true,
    evidenceRefs: uniqueHarnessRefs([
      "canary:passed",
      "rollback:drill",
      ...(forkMutationCanary?.evidenceRefs ?? []),
      ...(forkMutationCanary?.receiptRefs ?? []),
    ]),
    workerBinding,
    forkMutationCanary,
    mintedAtMs: nowMs,
  });
  const stagedWorkflow: WorkflowProject = {
    ...workflow,
    global_config: {
      ...workflow.global_config,
      production: {
        ...(workflow.global_config.production ?? {}),
        mcpAccessReviewed: true,
        requireReplayFixtures: false,
        expectedTimeSavedMinutes:
          workflow.global_config.production?.expectedTimeSavedMinutes ?? 10,
      },
    },
    metadata: {
      ...workflow.metadata,
      harness: workflow.metadata.harness
        ? {
            ...workflow.metadata.harness,
            activationId: undefined,
            activationState: "blocked",
            activationRecord,
          }
        : workflow.metadata.harness,
      workerHarnessBinding: workerBinding,
    },
  };
  const base = validateWorkflowProject(stagedWorkflow, tests);
  const candidate = createWorkflowHarnessActivationCandidate(
    stagedWorkflow,
    tests,
    workflowOnlyActivationMissingReadiness(base),
    [],
    nowMs,
  );
  return { workflow: stagedWorkflow, candidate };
}

function workflowWithBlessedDefaultRuntimeActivationProof(
  workflow: WorkflowProject,
  nowMs: number,
  activationIdGateClickProof: WorkflowHarnessActivationIdGateClickProof,
  packageImportActivationApplyProof: WorkflowHarnessPackageImportActivationApplyProof,
): WorkflowProject {
  const harness = workflow.metadata.harness;
  if (!harness) return workflow;
  const promotionTransitions = harness.promotionTransitions ?? [];
  const canaryBoundaries = harness.canaryExecutionBoundaries ?? [];
  const transitionRefs = uniqueHarnessRefs(
    promotionTransitions.flatMap((attempt) => [
      attempt.transitionId,
      ...attempt.receiptRefs,
      ...attempt.replayFixtureRefs,
      ...attempt.evidenceRefs,
    ]),
  );
  const boundaryAttemptIds = uniqueHarnessRefs(
    canaryBoundaries.flatMap((boundary) => boundary.nodeAttemptIds),
  );
  const boundaryReceiptIds = uniqueHarnessRefs(
    canaryBoundaries.flatMap((boundary) => boundary.receiptIds),
  );
  const boundaryReplayFixtureRefs = uniqueHarnessRefs(
    canaryBoundaries.flatMap((boundary) => boundary.replayFixtureRefs),
  );
  const defaultPromotionEvidenceRefs = uniqueHarnessRefs([
    ...transitionRefs,
    activationIdGateClickProof.mintedActivation.activationId,
    ...activationIdGateClickProof.mintedActivation.receiptRefs,
    ...activationIdGateClickProof.mintedActivation.evidenceRefs,
    packageImportActivationApplyProof.activationResult?.activationId,
    ...(packageImportActivationApplyProof.activationResult?.receiptRefs ?? []),
    ...(packageImportActivationApplyProof.activationResult?.evidenceRefs ?? []),
    ...(packageImportActivationApplyProof.activationResult
      ?.workerHandoffReceiptIds ?? []),
    ...(packageImportActivationApplyProof.activationResult
      ?.workerHandoffNodeAttemptIds ?? []),
    ...(packageImportActivationApplyProof.activationResult
      ?.workerHandoffReplayFixtureRefs ?? []),
  ]);
  const selectorDecisionId = `harness-selector:${workflow.metadata.id || workflow.metadata.slug}:live-gui-default`;
  const defaultRuntimeDispatchProof = makeHarnessDefaultRuntimeDispatchProof({
    selectorDecisionId,
    acceptedClusterIds: HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS,
    sourceBoundaryIds: uniqueHarnessRefs(
      canaryBoundaries.map((boundary) => boundary.boundaryId),
    ),
    acceptedNodeAttemptIds: boundaryAttemptIds,
    receiptIds: boundaryReceiptIds,
    replayFixtureRefs: boundaryReplayFixtureRefs,
    activationIdGateClickProof,
    activationIdGateProofNowMs: nowMs,
    activationIdGateWorkerBindingActivationId:
      harness.activationId ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    packageImportActivationApplyProof,
    packageImportActivationApplyProofNowMs: nowMs,
    evidenceRefs: defaultPromotionEvidenceRefs,
  });
  const livePromotionReadinessProof =
    defaultRuntimeDispatchProof.livePromotionReadinessProof;
  const selectorDecision = makeHarnessRuntimeSelectorDecision({
    decisionId: selectorDecisionId,
    selectedSelector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    canaryEligible: true,
    canaryBlockers: [],
    executionMode: "live",
    actualRuntimeAuthority: "blessed_workflow_activation_default",
    policyDecision: "promote_blessed_workflow_default_for_non_mutating_turn",
    routeReason:
      "Live GUI proof promoted every P0 harness cluster and bound the blessed workflow activation as the default runtime selector.",
    defaultPromotionGateEnabled: true,
    defaultPromotionGateEligible: true,
    defaultPromotionGateAuthorityTransferred: true,
    defaultPromotionGateActivationBlockers: [],
    defaultPromotionGatePolicyDecision:
      "promote_blessed_workflow_default_for_non_mutating_turn",
    livePromotionReadinessProof,
    activationIdGateClickProof,
    activationIdGateProofNowMs: nowMs,
    packageImportActivationApplyProof,
    packageImportActivationApplyProofNowMs: nowMs,
    evidenceRefs: defaultPromotionEvidenceRefs,
  });
  const liveHandoffProof = makeBlessedHarnessLiveHandoffProof({
    selector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    defaultAuthorityTransferred: true,
    runtimeAuthority: "blessed_workflow_activation_default",
    policyDecision: "promote_blessed_workflow_default_for_non_mutating_turn",
    defaultPromotionGateEnabled: true,
    defaultPromotionGateEligible: true,
    defaultPromotionGateActivationBlockers: [],
    defaultPromotionGatePolicyDecision:
      "promote_blessed_workflow_default_for_non_mutating_turn",
    livePromotionReadinessProof,
    gatedClusterIds: HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS,
    executionBoundaryIds: uniqueHarnessRefs(
      canaryBoundaries.map((boundary) => boundary.boundaryId),
    ),
    executionBoundaryClusterIds: HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS,
    nodeTimelineAttemptIds: boundaryAttemptIds,
    receiptIds: boundaryReceiptIds,
    replayFixtureRefs: boundaryReplayFixtureRefs,
    activationBlockers: [],
    activationIdGateClickProof,
    activationIdGateProofNowMs: nowMs,
    packageImportActivationApplyProof,
    packageImportActivationApplyProofNowMs: nowMs,
    evidenceRefs: defaultPromotionEvidenceRefs,
  });
  const workerBinding = {
    ...workflowHarnessWorkerBinding(workflow),
    harnessWorkflowId: harness.harnessWorkflowId || workflow.metadata.id,
    harnessActivationId: harness.activationId,
    harnessHash: harness.harnessHash,
    executionMode: "live" as const,
    source: "default" as const,
    selectorDecisionId: selectorDecision.decisionId,
    defaultDispatchId: defaultRuntimeDispatchProof.dispatchId,
    rollbackTarget: harness.activationId ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    authorityBindingReady: true,
    authorityBindingBlockers: [],
    livePromotionReadinessProofId: livePromotionReadinessProof.proofId,
    policyDecision: selectorDecision.policyDecision,
    requiredInvariantIds:
      defaultRuntimeDispatchProof.defaultLivePromotionInvariantIds,
    invariantBlockers:
      defaultRuntimeDispatchProof.defaultLivePromotionInvariantBlockers,
  };
  const workerBindingRegistryRecord =
    makeWorkflowHarnessWorkerBindingRegistryRecord({
      workflowId: harness.harnessWorkflowId || workflow.metadata.id,
      activationId: harness.activationId ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      activationHash: harness.harnessHash,
      harnessHash: harness.harnessHash,
      reviewedPackageSnapshotHash:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedPackageSnapshotHash,
      reviewedWorkflowContentHash:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedWorkflowContentHash,
      reviewedActivationId:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedActivationId,
      reviewedHarnessWorkflowId:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedHarnessWorkflowId,
      reviewedWorkerBindingActivationId:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedWorkerBindingActivationId,
      reviewedRollbackTarget:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedRollbackTarget,
      reviewedReplayFixtureRefs:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedReplayFixtureRefs,
      reviewedWorkerHandoffNodeAttemptIds:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedWorkerHandoffNodeAttemptIds,
      reviewedWorkerHandoffReceiptIds:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedWorkerHandoffReceiptIds,
      reviewedForkMutationCanaryId:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryId,
      reviewedForkMutationCanaryStatus:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryStatus,
      reviewedForkMutationCanaryDiffHash:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryDiffHash,
      reviewedForkMutationCanaryReceiptRefs:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryReceiptRefs,
      reviewedForkMutationCanaryReplayFixtureRefs:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryReplayFixtureRefs,
      reviewedForkMutationCanaryNodeAttemptIds:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryNodeAttemptIds,
      reviewedForkMutationCanaryRollbackTarget:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedForkMutationCanaryRollbackTarget,
      reviewedPolicyPosture:
        defaultRuntimeDispatchProof.workerBindingRegistryRecord
          ?.reviewedPolicyPosture,
      selectorDecisionId: selectorDecision.decisionId,
      defaultDispatchId: defaultRuntimeDispatchProof.dispatchId,
      componentVersionSet: liveHandoffProof.componentVersionSet,
      rollbackTarget:
        harness.activationId ?? DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      readinessProofId: livePromotionReadinessProof.proofId,
      canaryResultId: "harness-canary-result:default-agent-harness:passed",
      policyDecision: selectorDecision.policyDecision,
      bindingStatus: "bound",
      blockers: [],
      requiredInvariantIds:
        defaultRuntimeDispatchProof.defaultLivePromotionInvariantIds,
      invariantBlockers:
        defaultRuntimeDispatchProof.defaultLivePromotionInvariantBlockers,
      workerBinding,
      createdAtMs: nowMs,
    });
  const boundWorkerBinding = workerBindingRegistryRecord.workerBinding;
  const workerAttachLifecycle = makeWorkflowHarnessWorkerAttachLifecycle(
    workerBindingRegistryRecord,
    { createdAtMs: nowMs },
  );
  const workerAttachReceipt =
    workerAttachLifecycle.find((event) => event.phase === "attach")?.receipt ??
    workerAttachLifecycle[0].receipt;
  const workerAttachResumeReceipt =
    workerAttachLifecycle.find((event) => event.phase === "resume")?.receipt ??
    workerAttachReceipt;
  const workerAttachRollbackReceipt =
    workerAttachLifecycle.find((event) => event.phase === "rollback")
      ?.receipt ?? workerAttachReceipt;
  const workerAttachLifecycleAttemptIds = workerAttachLifecycle.map(
    (event) => event.attemptId,
  );
  const workerAttachLifecycleStatuses = workerAttachLifecycle.map(
    (event) => event.attachStatus,
  );
  const workerAttachLifecycleComplete =
    workflowHarnessWorkerAttachLifecycleComplete(workerAttachLifecycle);
  const workerSessionRecord = makeWorkflowHarnessWorkerSessionRecord(
    workerBindingRegistryRecord,
    workerAttachLifecycle,
    {
      sessionId: workflow.metadata.id || workflow.metadata.slug,
      createdAtMs: nowMs,
    },
  );
  const workerLaunchEnvelopes = (["launch", "resume", "rollback"] as const).map(
    (phase) =>
      makeWorkflowHarnessWorkerLaunchEnvelope(workerSessionRecord, phase, {
        createdAtMs: nowMs,
      }),
  );
  const workerHandoffReceipts = workerLaunchEnvelopes.map((envelope) =>
    resolveWorkflowHarnessWorkerHandoffReceipt(workerSessionRecord, envelope, {
      createdAtMs: nowMs,
    }),
  );
  const workerLaunchEnvelopeIds = workerLaunchEnvelopes.map(
    (envelope) => envelope.envelopeId,
  );
  const workerHandoffReceiptIds = workerHandoffReceipts.map(
    (receipt) => receipt.receiptId,
  );
  const workerHandoffNodeAttempts =
    makeWorkflowHarnessWorkerHandoffNodeAttempts(workerHandoffReceipts, {
      executionMode: "live",
      startedAtMs: nowMs,
    });
  const workerHandoffNodeAttemptIds = workerHandoffNodeAttempts.map(
    (attempt) => attempt.attemptId,
  );
  const workerHandoffReplayFixtureRefs = workerHandoffNodeAttempts
    .map((attempt) => attempt.replay.fixtureRef)
    .filter((fixtureRef): fixtureRef is string => Boolean(fixtureRef));
  const baseDispatchNodeAttemptIds =
    defaultRuntimeDispatchProof.dispatchNodeAttemptIds.filter(
      (attemptId) =>
        !attemptId.startsWith("harness-worker-handoff:attempt:"),
    );
  const baseDispatchNodeAttempts = (
    defaultRuntimeDispatchProof.dispatchNodeAttempts ?? []
  ).filter(
    (attempt) =>
      !attempt.attemptId.startsWith("harness-worker-handoff:attempt:"),
  );
  const baseNodeAttemptIds = defaultRuntimeDispatchProof.nodeAttemptIds.filter(
    (attemptId) => !attemptId.startsWith("harness-worker-handoff:attempt:"),
  );
  const baseReceiptIds = defaultRuntimeDispatchProof.receiptIds.filter(
    (receiptId) =>
      !receiptId.startsWith("harness-worker-handoff-receipt:"),
  );
  const baseReplayFixtureRefs =
    defaultRuntimeDispatchProof.replayFixtureRefs.filter(
      (fixtureRef) =>
        !fixtureRef.startsWith("harness-worker-handoff:fixture:"),
    );
  const defaultRuntimeDispatchProofWithRegistry = {
    ...defaultRuntimeDispatchProof,
    workerBindingRegistryRecord,
    workerAttachReceipt,
    workerAttachResumeReceipt,
    workerAttachRollbackReceipt,
    workerAttachLifecycle,
    workerAttachLifecycleAttemptIds,
    workerAttachLifecycleStatuses,
    workerAttachLifecycleComplete,
    workerSessionRecord,
    workerLaunchEnvelopes,
    workerHandoffReceipts,
    workerLaunchEnvelopeIds,
    workerHandoffReceiptIds,
    workerHandoffNodeAttemptIds,
    workerHandoffNodeAttempts,
    workerHandoffReplayFixtureRefs,
    dispatchNodeAttemptIds: uniqueHarnessRefs([
      ...baseDispatchNodeAttemptIds,
      ...workerAttachLifecycleAttemptIds,
      ...workerHandoffNodeAttemptIds,
    ]),
    dispatchNodeAttempts: [
      ...baseDispatchNodeAttempts,
      ...workerHandoffNodeAttempts,
    ],
    nodeAttemptIds: uniqueHarnessRefs([
      ...baseNodeAttemptIds,
      ...workerHandoffNodeAttemptIds,
    ]),
    receiptIds: uniqueHarnessRefs([...baseReceiptIds, ...workerHandoffReceiptIds]),
    replayFixtureRefs: uniqueHarnessRefs([
      ...baseReplayFixtureRefs,
      ...workerHandoffReplayFixtureRefs,
    ]),
  };
  const activationRecord = makeHarnessForkActivationRecord({
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    harnessWorkflowId: harness.harnessWorkflowId || workflow.metadata.id,
    activationId: harness.activationId,
    activationState: "active",
    activationBlockers: [],
    componentVersionSet: liveHandoffProof.componentVersionSet,
    harnessHash: harness.harnessHash,
    policyPosture: "live",
    canaryStatus: "passed",
    rollbackTarget:
      harness.activationId ??
      "activation:default-agent-harness:blessed-readonly",
    rollbackAvailable: true,
    liveAuthorityTransferred: true,
    evidenceRefs: uniqueHarnessRefs([
      selectorDecision.decisionId,
      liveHandoffProof.executionBoundaryId,
      defaultRuntimeDispatchProof.dispatchId,
      ...transitionRefs,
    ]),
    workerBinding: boundWorkerBinding,
    workerBindingRegistryRecord,
    workerAttachReceipt,
    workerAttachLifecycle,
    workerSessionRecord,
    workerLaunchEnvelopes,
    workerHandoffReceipts,
    workerHandoffNodeAttemptIds,
    workerHandoffNodeAttempts,
    workerHandoffReplayFixtureRefs,
    revisionBinding: harness.revisionBinding,
    rollbackRevisionBinding: harness.revisionBinding,
    mintedAtMs: nowMs,
  });
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      workerHarnessBinding: boundWorkerBinding,
      harness: {
        ...harness,
        executionMode: "live",
        activationState: "active",
        activationRecord,
        runtimeSelectorDecision: selectorDecision,
        liveHandoffProof,
        defaultRuntimeDispatchProof: defaultRuntimeDispatchProofWithRegistry,
        workerBindingRegistryRecord,
        workerAttachReceipt,
        workerAttachLifecycle,
        workerSessionRecord,
        workerLaunchEnvelopes,
        workerHandoffReceipts,
        workerHandoffNodeAttemptIds,
        workerHandoffNodeAttempts,
        workerHandoffReplayFixtureRefs,
      },
      updatedAtMs: nowMs,
    },
  };
}

function harnessComponentKindForNode(
  node: Node,
): WorkflowHarnessComponentKind | null {
  const runtimeKind = node.runtimeBinding?.componentKind;
  if (runtimeKind) return runtimeKind;
  const component = node.config?.logic?.harnessComponent;
  if (
    component &&
    typeof component === "object" &&
    !Array.isArray(component) &&
    typeof (component as { kind?: unknown }).kind === "string"
  ) {
    return (component as { kind: WorkflowHarnessComponentKind }).kind;
  }
  return null;
}

function harnessGroupRollupStatus(
  group: WorkflowHarnessGroupView,
): Node["status"] {
  if (
    group.statusRollup.blockedCount > 0 ||
    group.statusRollup.divergenceCount > 0 ||
    ["blocked", "failed"].includes(group.statusRollup.replayGateStatus)
  ) {
    return "blocked";
  }
  if (group.statusRollup.liveReadyCount === group.innerNodeIds.length) {
    return "success";
  }
  return "idle";
}

function encodeHarnessWorkbenchDeepLink(
  link: HarnessWorkbenchDeepLink,
): string {
  const params = new URLSearchParams();
  const setParam = (key: keyof HarnessWorkbenchDeepLink) => {
    const value = link[key];
    if (value) {
      params.set(key, value);
    }
  };
  setParam("panel");
  setParam("groupId");
  setParam("componentId");
  setParam("runId");
  setParam("selectorDecisionId");
  setParam("dispatchId");
  setParam("workerBindingId");
  setParam("nodeAttemptId");
  setParam("receiptRef");
  setParam("replayFixtureRef");
  setParam("rollbackTarget");
  setParam("revisionBindingKind");
  setParam("revisionBindingRef");
  setParam("activationBlockerIndex");
  setParam("activationBlockerRef");
  setParam("activationAuditEventId");
  setParam("activationGateId");
  setParam("activationGateEvidenceRef");
  setParam("activationGateNodeAttemptId");
  setParam("activationGateReceiptRef");
  setParam("activationGateReplayFixtureRef");
  const query = params.toString();
  return query
    ? `${HARNESS_WORKBENCH_DEEP_LINK_PREFIX}?${query}`
    : HARNESS_WORKBENCH_DEEP_LINK_PREFIX;
}

function parseHarnessWorkbenchDeepLink(
  hash: string,
): HarnessWorkbenchDeepLink | null {
  if (!hash.startsWith(HARNESS_WORKBENCH_DEEP_LINK_PREFIX)) return null;
  const params = new URLSearchParams(
    hash.slice(HARNESS_WORKBENCH_DEEP_LINK_PREFIX.length).replace(/^\?/, ""),
  );
  const panel = params.get("panel");
  const link: HarnessWorkbenchDeepLink = {};
  if (panel && RIGHT_PANELS.some((candidate) => candidate.id === panel)) {
    link.panel = panel as WorkflowRightPanel;
  }
  link.groupId = params.get("groupId") ?? undefined;
  link.componentId = params.get("componentId") ?? undefined;
  link.runId = params.get("runId") ?? undefined;
  link.selectorDecisionId = params.get("selectorDecisionId") ?? undefined;
  link.dispatchId = params.get("dispatchId") ?? undefined;
  link.workerBindingId = params.get("workerBindingId") ?? undefined;
  link.nodeAttemptId = params.get("nodeAttemptId") ?? undefined;
  link.receiptRef = params.get("receiptRef") ?? undefined;
  link.replayFixtureRef = params.get("replayFixtureRef") ?? undefined;
  link.rollbackTarget = params.get("rollbackTarget") ?? undefined;
  link.revisionBindingKind = params.get("revisionBindingKind") ?? undefined;
  link.revisionBindingRef = params.get("revisionBindingRef") ?? undefined;
  link.activationBlockerIndex =
    params.get("activationBlockerIndex") ?? undefined;
  link.activationBlockerRef = params.get("activationBlockerRef") ?? undefined;
  link.activationAuditEventId =
    params.get("activationAuditEventId") ?? undefined;
  link.activationGateId = params.get("activationGateId") ?? undefined;
  link.activationGateEvidenceRef =
    params.get("activationGateEvidenceRef") ?? undefined;
  link.activationGateNodeAttemptId =
    params.get("activationGateNodeAttemptId") ?? undefined;
  link.activationGateReceiptRef =
    params.get("activationGateReceiptRef") ?? undefined;
  link.activationGateReplayFixtureRef =
    params.get("activationGateReplayFixtureRef") ?? undefined;
  return link;
}

function readHarnessWorkbenchDeepLink(): HarnessWorkbenchDeepLink | null {
  if (typeof window === "undefined") return null;
  return parseHarnessWorkbenchDeepLink(window.location.hash);
}

function harnessWorkbenchDeepLinkHref(hash: string): string {
  if (typeof window === "undefined") return hash;
  const url = new URL(window.location.href);
  url.hash = hash;
  return url.toString();
}

function writeHarnessWorkbenchDeepLink(hash: string): void {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href);
  url.hash = hash;
  const nextHref = url.toString();
  if (nextHref !== window.location.href) {
    try {
      window.history.replaceState(null, "", nextHref);
    } catch {
      window.location.replace(nextHref);
    }
  }
}

function nextHarnessWorkbenchFrame(): Promise<void> {
  if (typeof requestAnimationFrame === "undefined") {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}

function readHarnessRailSelectedState(testId: string): Record<string, string> {
  if (typeof document === "undefined") return {};
  const target = document.querySelector(`[data-testid="${testId}"]`);
  if (!target) return {};
  const selectedAttributes = [
    "data-selected-selector-decision-id",
    "data-selected-default-dispatch-id",
    "data-selected-worker-binding-id",
    "data-selected-rollback-target",
    "data-selected-receipt-ref",
    "data-selected-replay-fixture-ref",
    "data-selected-revision-binding-kind",
    "data-selected-revision-binding-ref",
    "data-selected-activation-blocker-index",
    "data-selected-activation-blocker-ref",
    "data-selected-activation-audit-event-id",
    "data-selected-activation-gate-id",
    "data-selected-activation-gate-evidence-ref",
    "data-selected-node-attempt-id",
    "data-selected-activation-gate-node-attempt-id",
    "data-selected-activation-gate-receipt-ref",
    "data-selected-activation-gate-replay-fixture-ref",
    "data-selected-canary-boundary-id",
    "data-selected-rollback-drill-id",
    "data-selected-rollback-restore-canary-id",
    "data-selected-rollback-restore-receipt-ref",
    "data-rollback-proof-bound",
    "data-rollback-proof-blockers",
    "data-rollback-readiness-proof-id",
    "data-rollback-live-shadow-gate-id",
    "data-rollback-live-shadow-gate-ready",
    "data-rollback-activation-id",
    "data-rollback-harness-hash",
    "data-rollback-policy-decision",
    "data-rollback-launch-envelope-id",
    "data-rollback-handoff-receipt-id",
    "data-rollback-node-attempt-id",
    "data-rollback-replay-fixture-ref",
    "data-rollback-execution-dry-run-status",
    "data-rollback-execution-canary-result-id",
    "data-rollback-execution-canary-status",
    "data-rollback-execution-canary-hash-verified",
    "data-rollback-execution-apply-readiness",
    "data-rollback-execution-apply-disabled",
    "data-rollback-execution-apply-policy-decision",
    "data-rollback-execution-blockers",
    "data-rollback-apply-execution-status",
    "data-rollback-apply-execution-id",
    "data-rollback-apply-receipt-id",
    "data-rollback-apply-audit-event-id",
    "data-rollback-apply-target-verified",
    "data-rollback-apply-hash-verified",
    "data-rollback-apply-policy-decision",
    "data-rollback-apply-blockers",
    "data-node-attempt-id",
    "data-node-attempt-source-kind",
    "data-workflow-node-id",
    "data-component-kind",
    "data-component-id",
    "data-harness-workflow-id",
    "data-harness-activation-id",
    "data-harness-hash",
    "data-execution-mode",
    "data-readiness",
    "data-status",
    "data-policy-decision",
    "data-receipt-refs",
    "data-replay-fixture-ref",
    "data-replay-determinism",
    "data-input-hash",
    "data-output-hash",
    "data-mutation-diff-hash",
    "data-rollback-target",
    "data-shadow-comparison-live-attempt-id",
    "data-shadow-comparison-shadow-attempt-id",
    "data-shadow-comparison-divergence",
    "data-shadow-comparison-blocking",
    "data-live-attempt-id",
    "data-shadow-attempt-id",
    "data-divergence",
    "data-blocking",
    "data-summary",
    "data-live-receipt-refs",
    "data-shadow-receipt-refs",
    "data-live-replay-fixture-ref",
    "data-shadow-replay-fixture-ref",
    "data-live-input-hash",
    "data-shadow-input-hash",
    "data-live-output-hash",
    "data-shadow-output-hash",
    "data-gate-source-kind",
    "data-gate-status",
    "data-evidence-ref-count",
    "data-node-attempt-ref-count",
    "data-receipt-ref-count",
    "data-replay-fixture-ref-count",
    "data-required-invariant-ids",
    "data-invariant-blockers",
    "data-invariant-blocker-count",
    "data-gate-action-id",
    "data-gate-action-kind",
    "data-gate-action-impact",
    "data-gate-action-command",
    "data-gate-action-disabled",
  ];
  return Object.fromEntries(
    selectedAttributes.map((attribute) => [
      attribute,
      target.getAttribute(attribute) ?? "",
    ]),
  );
}

function splitHarnessRailBlockers(value: string | null | undefined): string[] {
  return uniqueHarnessRefs(
    String(value ?? "")
      .split(/[|,]/)
      .map((entry) => entry.trim()),
  );
}

function readHarnessPackageEvidenceReviewState(): Record<string, string> {
  if (typeof document === "undefined") return {};
  const target = document.querySelector(
    '[data-testid="workflow-harness-package-evidence-review"]',
  );
  if (!target) return {};
  const attributes = [
    "data-harness-package-manifest-present",
    "data-harness-package-schema-version",
    "data-harness-package-evidence-ready",
    "data-harness-package-evidence-blocker-count",
    "data-harness-package-evidence-ref-count",
    "data-harness-package-receipt-ref-count",
    "data-harness-package-replay-fixture-ref-count",
    "data-harness-package-rollback-restore-ref-count",
    "data-harness-package-fork-mutation-receipt-count",
    "data-harness-package-fork-mutation-replay-count",
    "data-harness-package-fork-mutation-attempt-count",
    "data-harness-package-worker-handoff-attempt-count",
    "data-harness-package-worker-handoff-receipt-count",
    "data-harness-package-deep-link-count",
  ];
  return Object.fromEntries(
    attributes.map((attribute) => [
      attribute,
      target.getAttribute(attribute) ?? "",
    ]),
  );
}

function readHarnessPackageEvidenceRowStatuses(): Record<string, string> {
  if (typeof document === "undefined") return {};
  const rows = Array.from(
    document.querySelectorAll<HTMLElement>("[data-package-evidence-row-id]"),
  );
  return Object.fromEntries(
    rows.map((row) => [
      row.getAttribute("data-package-evidence-row-id") ?? "unknown",
      row.getAttribute("data-package-evidence-row-status") ?? "",
    ]),
  );
}

function readHarnessPackageEvidenceMissingRows(): string[] {
  const rowStatuses = readHarnessPackageEvidenceRowStatuses();
  return Object.entries(rowStatuses)
    .filter(([, status]) => status === "blocked")
    .map(([rowId]) => rowId);
}

function readHarnessPackageImportReviewState(): Record<string, string> {
  if (typeof document === "undefined") return {};
  const review = document.querySelector<HTMLElement>(
    '[data-testid="workflow-harness-package-import-review"]',
  );
  if (!review) return {};
  return Object.fromEntries(
    [
      "data-package-import-review-open",
      "data-package-import-source-workflow-path",
      "data-package-import-source-workflow-id",
      "data-package-import-source-activation-id",
      "data-package-import-source-workflow-content-hash",
      "data-package-import-source-harness-hash",
      "data-package-import-source-worker-binding-id",
      "data-package-import-source-policy-posture",
      "data-package-import-source-mutation-canary-id",
      "data-package-import-source-mutation-canary-status",
      "data-package-import-source-mutation-canary-diff-hash",
      "data-package-import-source-mutation-canary-receipt-ref",
      "data-package-import-source-mutation-canary-replay-fixture-ref",
      "data-package-import-source-mutation-canary-node-attempt-id",
      "data-package-import-source-mutation-canary-rollback-target",
      "data-package-import-source-replay-fixture-count",
      "data-package-import-imported-workflow-path",
      "data-package-import-imported-workflow-id",
      "data-package-import-readiness-status",
      "data-package-import-evidence-ready",
      "data-package-import-evidence-blocker-count",
      "data-package-import-activation-enabled",
      "data-package-import-replay-integrity-blocker-count",
      "data-package-import-replay-integrity-blockers",
    ].map((name) => [name, review.getAttribute(name) ?? ""]),
  );
}

function readHarnessPackageImportHandoffState(): Record<string, string> {
  if (typeof document === "undefined") return {};
  const handoff = document.querySelector<HTMLElement>(
    '[data-testid="workflow-harness-package-import-handoff"]',
  );
  if (!handoff) return {};
  return Object.fromEntries(
    [
      "data-package-import-handoff-open",
      "data-package-import-handoff-decision",
      "data-package-import-handoff-activation-id",
      "data-package-import-handoff-canary-status",
      "data-package-import-handoff-mutation-canary-id",
      "data-package-import-handoff-mutation-canary-status",
      "data-package-import-handoff-mutation-canary-diff-hash",
      "data-package-import-handoff-mutation-canary-receipt-ref",
      "data-package-import-handoff-mutation-canary-replay-fixture-ref",
      "data-package-import-handoff-mutation-canary-node-attempt-id",
      "data-package-import-handoff-mutation-canary-rollback-target",
      "data-package-import-handoff-rollback-target",
      "data-package-import-handoff-rollback-available",
      "data-package-import-handoff-worker-binding-id",
      "data-package-import-handoff-worker-workflow-id",
      "data-package-import-handoff-worker-hash",
      "data-package-import-handoff-workflow-content-hash",
      "data-package-import-handoff-policy-posture",
      "data-package-import-handoff-replay-fixture-count",
      "data-package-import-handoff-mintable",
      "data-package-import-handoff-replay-integrity-blocker-count",
      "data-package-import-handoff-replay-integrity-blockers",
      "data-package-import-handoff-blocker-count",
      "data-package-import-handoff-package-evidence-ready",
      "data-package-import-handoff-activation-enabled",
    ].map((name) => [name, handoff.getAttribute(name) ?? ""]),
  );
}

function workflowPackageImportMissingRows(options: {
  manifestPresent: boolean;
  receiptRefCount: number;
  replayFixtureRefCount: number;
  rollbackRestoreReceiptRefCount: number;
  forkMutationCanaryReceiptRefCount?: number;
  forkMutationCanaryReplayFixtureRefCount?: number;
  forkMutationCanaryNodeAttemptCount?: number;
  workerHandoffNodeAttemptCount: number;
  workerHandoffReceiptCount: number;
  deepLinkCount: number;
}): string[] {
  const missing: string[] = [];
  if (!options.manifestPresent) missing.push("manifest");
  if (options.receiptRefCount <= 0) missing.push("receipts");
  if (options.replayFixtureRefCount <= 0) missing.push("replay-fixtures");
  if (options.rollbackRestoreReceiptRefCount <= 0) {
    missing.push("rollback-restore");
  }
  if (
    (options.forkMutationCanaryReceiptRefCount ?? 0) <= 0 ||
    (options.forkMutationCanaryReplayFixtureRefCount ?? 0) <= 0 ||
    (options.forkMutationCanaryNodeAttemptCount ?? 0) <= 0
  ) {
    missing.push("fork-mutation-canary");
  }
  if (options.workerHandoffNodeAttemptCount <= 0) {
    missing.push("worker-handoff-attempts");
  }
  if (options.workerHandoffReceiptCount <= 0) {
    missing.push("worker-handoff-receipts");
  }
  if (options.deepLinkCount <= 0) missing.push("deep-links");
  return missing;
}

function createWorkflowPackageImportActivationCandidate(options: {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  readiness: WorkflowValidationResult;
  proposals: WorkflowProposal[];
  createdAtMs: number;
  rollbackRestoreResult?: WorkflowRevisionRestoreResult | null;
  rollbackRestoreBlockers?: string[];
  packageEvidenceReady: boolean;
}): WorkflowHarnessForkActivationCandidate {
  const candidate = createWorkflowHarnessActivationCandidate(
    options.workflow,
    options.tests,
    options.readiness,
    options.proposals,
    options.createdAtMs,
    {
      rollbackRestoreResult: options.rollbackRestoreResult,
      rollbackRestoreBlockers: options.rollbackRestoreBlockers ?? [],
    },
  );
  const activationRecord = options.workflow.metadata.harness?.activationRecord;
  const preservedActivationId =
    activationRecord?.activationId ??
    options.workflow.metadata.harness?.activationId ??
    null;
  const preservedWorkerBinding =
    activationRecord?.workerBinding ??
    options.workflow.metadata.workerHarnessBinding ??
    candidate.workerBindingPreview;
  if (
    !options.packageEvidenceReady ||
    !activationRecord ||
    activationRecord.activationState !== "validated" ||
    activationRecord.canaryStatus !== "passed" ||
    !preservedActivationId ||
    !preservedWorkerBinding
  ) {
    return candidate;
  }
  const workerBindingPreview = {
    ...preservedWorkerBinding,
    harnessWorkflowId:
      preservedWorkerBinding.harnessWorkflowId ||
      candidate.harnessWorkflowId ||
      options.workflow.metadata.id ||
      options.workflow.metadata.slug,
    harnessActivationId: preservedActivationId,
    harnessHash:
      preservedWorkerBinding.harnessHash ||
      activationRecord.harnessHash ||
      candidate.harnessHash,
    executionMode:
      preservedWorkerBinding.executionMode ?? candidate.workerBindingPreview.executionMode,
    source: "fork" as const,
    rollbackTarget:
      preservedWorkerBinding.rollbackTarget ||
      activationRecord.rollbackTarget ||
      candidate.rollbackTarget,
  };
  const gateResults = candidate.gateResults.map((gate) => {
    if (gate.gateId === "activation-id") {
      return {
        ...gate,
        status: "passed" as const,
        value: preservedActivationId,
        detail:
          "Portable package preserved a validated activation id for reviewed import handoff.",
        evidenceRefs: uniqueHarnessRefs([
          ...gate.evidenceRefs,
          preservedActivationId,
        ]),
      };
    }
    if (
      [
	        "package-evidence",
	        "mutation-canary",
	        "canary",
        "rollback-restore",
        "rollback",
        "worker-binding",
      ].includes(gate.gateId)
    ) {
      return {
        ...gate,
        status: "passed" as const,
        evidenceRefs: uniqueHarnessRefs([
          ...gate.evidenceRefs,
          preservedActivationId,
          activationRecord.rollbackTarget,
          workerBindingPreview.harnessActivationId,
        ]),
      };
    }
    return {
      ...gate,
      status: "passed" as const,
      detail: `${gate.detail} Preserved package activation evidence satisfies this reviewed import handoff gate.`,
    };
  });
  return {
    ...candidate,
    candidateId: `candidate:${candidate.workflowId}:package-import-handoff:${options.createdAtMs}`,
    decision: "mintable",
    activationId: preservedActivationId,
    activationIdPreview: preservedActivationId,
    activationBlockers: [],
    blockerCodes: [],
    gateResults,
    componentVersionSet:
      activationRecord.componentVersionSet ?? candidate.componentVersionSet,
    policyPosture: activationRecord.policyPosture ?? candidate.policyPosture,
    canaryStatus: "passed",
    rollbackTarget: activationRecord.rollbackTarget || candidate.rollbackTarget,
    rollbackAvailable:
      activationRecord.rollbackAvailable === true || candidate.rollbackAvailable,
	    rollbackRestoreCanary:
	      activationRecord.rollbackRestoreCanary ?? candidate.rollbackRestoreCanary,
	    forkMutationCanary:
	      activationRecord.forkMutationCanary ?? candidate.forkMutationCanary,
	    workerBindingPreview,
    revisionBindingPreview:
      activationRecord.revisionBinding ?? candidate.revisionBindingPreview,
    evidenceRefs: uniqueHarnessRefs([
      ...candidate.evidenceRefs,
      ...activationRecord.evidenceRefs,
      preservedActivationId,
      activationRecord.rollbackTarget,
      workerBindingPreview.harnessActivationId,
    ]),
  };
}

function createWorkflowPackageImportReview(options: {
  bundle: WorkflowWorkbenchBundle;
  packagePath: string;
  projectRoot: string;
  readinessStatus: WorkflowValidationResult["status"] | null;
  importedAtMs: number;
  activationCandidate?: WorkflowHarnessForkActivationCandidate | null;
}): WorkflowPackageImportReview {
  const portableManifest = options.bundle.importedPackage?.manifest ?? null;
  const harnessPackageManifest =
    portableManifest?.harnessPackageManifest ??
    options.bundle.workflow.metadata.harness?.packageManifest ??
    options.bundle.workflow.metadata.harness?.activationRecord?.packageManifest ??
    null;
  const activationRecord =
    options.bundle.workflow.metadata.harness?.activationRecord ??
    portableManifest?.harness?.activationRecord ??
    null;
  const evidenceRefCount = harnessPackageManifest?.evidenceRefs?.length ?? 0;
  const receiptRefCount = harnessPackageManifest?.receiptRefs?.length ?? 0;
  const replayFixtureRefCount =
    harnessPackageManifest?.replayFixtureRefs?.length ?? 0;
  const rollbackRestoreReceiptRefCount =
    harnessPackageManifest?.rollbackRestoreReceiptRefs?.length ?? 0;
  const forkMutationCanary =
    harnessPackageManifest?.forkMutationCanary ??
    options.bundle.workflow.metadata.harness?.forkMutationCanary ??
    activationRecord?.forkMutationCanary ??
    options.activationCandidate?.forkMutationCanary ??
    null;
  const forkMutationCanaryReceiptRefs = uniqueHarnessRefs([
    ...(harnessPackageManifest?.forkMutationCanaryReceiptRefs ?? []),
    ...(forkMutationCanary?.receiptRefs ?? []),
  ]);
  const forkMutationCanaryReplayFixtureRefs = uniqueHarnessRefs([
    ...(harnessPackageManifest?.forkMutationCanaryReplayFixtureRefs ?? []),
    ...(forkMutationCanary?.replayFixtureRefs ?? []),
  ]);
  const forkMutationCanaryNodeAttemptIds = uniqueHarnessRefs([
    ...(harnessPackageManifest?.forkMutationCanaryNodeAttemptIds ?? []),
    ...(forkMutationCanary?.nodeAttempts?.map((attempt) => attempt.attemptId) ??
      []),
    ...(forkMutationCanary?.nodeAttemptIds ?? []),
  ]);
  const forkMutationCanaryReceiptRefCount =
    forkMutationCanaryReceiptRefs.length;
  const forkMutationCanaryReplayFixtureRefCount =
    forkMutationCanaryReplayFixtureRefs.length;
  const forkMutationCanaryNodeAttemptCount =
    forkMutationCanaryNodeAttemptIds.length;
  const workerHandoffNodeAttemptCount =
    harnessPackageManifest?.workerHandoffNodeAttemptIds?.length ?? 0;
  const workerHandoffReceiptCount =
    harnessPackageManifest?.workerHandoffReceiptIds?.length ?? 0;
  const deepLinkCount = harnessPackageManifest?.deepLinks?.length ?? 0;
  const packageWorkerBinding =
    options.bundle.workflow.metadata.workerHarnessBinding ??
    portableManifest?.workerHarnessBinding ??
    activationRecord?.workerBinding ??
    null;
  const packagePolicyPosture =
    harnessPackageManifest?.policyPosture ??
    activationRecord?.policyPosture ??
    null;
  const reviewedPackageSnapshotHash =
    harnessPackageManifest?.reviewedPackageSnapshotHash ??
    activationRecord?.workerBindingRegistryRecord?.reviewedPackageSnapshotHash ??
    options.bundle.workflow.metadata.harness?.workerBindingRegistryRecord
      ?.reviewedPackageSnapshotHash ??
    null;
  const importedWorkflowChromeLocale =
    typeof options.bundle.workflow.global_config.workflowChromeLocale === "string"
      ? options.bundle.workflow.global_config.workflowChromeLocale
      : null;
  const sourceWorkflowChromeLocale =
    typeof portableManifest?.workflowChromeLocale === "string"
      ? portableManifest.workflowChromeLocale
      : importedWorkflowChromeLocale;
  const manifestPresent =
    harnessPackageManifest?.schemaVersion ===
    "workflow.harness.package-evidence-manifest.v1";
  const missingRows = workflowPackageImportMissingRows({
    manifestPresent,
    receiptRefCount,
    replayFixtureRefCount,
    rollbackRestoreReceiptRefCount,
    forkMutationCanaryReceiptRefCount,
    forkMutationCanaryReplayFixtureRefCount,
    forkMutationCanaryNodeAttemptCount,
    workerHandoffNodeAttemptCount,
    workerHandoffReceiptCount,
    deepLinkCount,
  });
  const review: WorkflowPackageImportReview = {
    schemaVersion: "workflow.package-import-review.v1",
    packagePath: options.bundle.importedPackage?.packagePath ?? options.packagePath,
    manifestPath: options.bundle.importedPackage?.manifestPath ?? null,
    importedAtMs: options.importedAtMs,
    source: {
      workflowName:
        portableManifest?.workflowName ?? harnessPackageManifest?.packageName ?? null,
      workflowSlug: portableManifest?.workflowSlug ?? null,
      workflowId: harnessPackageManifest?.workflowId ?? null,
      sourceWorkflowPath: portableManifest?.sourceWorkflowPath ?? null,
      workflowContentHash: harnessPackageManifest?.workflowContentHash ?? null,
      activationId: harnessPackageManifest?.activationId ?? null,
      harnessWorkflowId: harnessPackageManifest?.harnessWorkflowId ?? null,
      harnessHash: harnessPackageManifest?.harnessHash ?? null,
      reviewedPackageSnapshotHash,
      workerBindingActivationId:
        packageWorkerBinding?.harnessActivationId ??
        harnessPackageManifest?.activationId ??
        null,
      workerBindingWorkflowId:
        packageWorkerBinding?.harnessWorkflowId ??
        harnessPackageManifest?.harnessWorkflowId ??
        null,
      policyPosture: packagePolicyPosture,
      rollbackTarget: harnessPackageManifest?.rollbackTarget ?? null,
      workflowChromeLocale: sourceWorkflowChromeLocale,
      forkMutationCanaryId: forkMutationCanary?.canaryId ?? null,
      forkMutationCanaryStatus: forkMutationCanary?.status ?? null,
      forkMutationCanaryDiffHash: forkMutationCanary?.diffHash ?? null,
      forkMutationCanaryReceiptRefs,
      forkMutationCanaryReplayFixtureRefs,
      forkMutationCanaryNodeAttemptIds,
      forkMutationCanaryRollbackTarget:
        forkMutationCanary?.rollbackTarget ??
        harnessPackageManifest?.rollbackTarget ??
        null,
      replayFixtureRefs: harnessPackageManifest?.replayFixtureRefs ?? [],
      workerHandoffNodeAttemptIds:
        harnessPackageManifest?.workerHandoffNodeAttemptIds ?? [],
      workerHandoffReceiptIds:
        harnessPackageManifest?.workerHandoffReceiptIds ?? [],
      portable: portableManifest?.portable ?? missingRows.length === 0,
      readinessStatus: portableManifest?.readinessStatus ?? null,
      fileCount: portableManifest?.files?.length ?? 0,
      blockerCount: portableManifest?.blockers?.length ?? 0,
    },
    imported: {
      workflowId: options.bundle.workflow.metadata.id,
      workflowName: options.bundle.workflow.metadata.name,
      workflowSlug: options.bundle.workflow.metadata.slug,
      workflowPath: options.bundle.workflowPath,
      testsPath: options.bundle.testsPath,
      projectRoot: options.projectRoot,
      activationReadinessStatus: options.readinessStatus,
      workflowChromeLocale: importedWorkflowChromeLocale,
    },
    evidence: {
      harnessPackageManifestPresent: manifestPresent,
      packageEvidenceReady: missingRows.length === 0,
      workflowChromeLocalePreserved:
        !sourceWorkflowChromeLocale ||
        sourceWorkflowChromeLocale === importedWorkflowChromeLocale,
      blockerCount: missingRows.length,
      evidenceRefCount,
      receiptRefCount,
      replayFixtureRefCount,
      rollbackRestoreReceiptRefCount,
      forkMutationCanaryReceiptRefCount,
      forkMutationCanaryReplayFixtureRefCount,
      forkMutationCanaryNodeAttemptCount,
      workerHandoffNodeAttemptCount,
      workerHandoffReceiptCount,
      deepLinkCount,
      missingRows,
    },
  };
  const candidate = options.activationCandidate ?? null;
  if (candidate) {
    const passedGateCount = candidate.gateResults.filter(
      (gate) => gate.status === "passed",
    ).length;
    const workerBindingId =
      candidate.workerBindingPreview.harnessActivationId ??
      candidate.workerBindingPreview.harnessWorkflowId ??
      null;
    const packageEvidenceGate = candidate.gateResults.find(
      (gate) => gate.gateId === "package-evidence",
    );
    const packageEvidenceReady =
      missingRows.length === 0 && packageEvidenceGate?.status === "passed";
    review.activationHandoff = {
      schemaVersion: "workflow.package-import-activation-handoff.v1",
      candidateId: candidate.candidateId,
      decision: candidate.decision,
      activationIdPreview: candidate.activationIdPreview ?? null,
	      canaryStatus: candidate.canaryStatus,
	      rollbackTarget: candidate.rollbackTarget || null,
	      rollbackAvailable: candidate.rollbackAvailable,
	      rollbackRestoreCanaryStatus: candidate.rollbackRestoreCanary.status,
		      forkMutationCanaryId: candidate.forkMutationCanary.canaryId,
		      forkMutationCanaryStatus: candidate.forkMutationCanary.status,
		      forkMutationCanaryDiffHash: candidate.forkMutationCanary.diffHash,
          forkMutationCanaryReceiptRefs,
          forkMutationCanaryReplayFixtureRefs,
          forkMutationCanaryNodeAttemptIds,
          forkMutationCanaryRollbackTarget:
            candidate.forkMutationCanary.rollbackTarget ??
            candidate.rollbackTarget ??
            null,
		      workerBinding: candidate.workerBindingPreview,
      workflowContentHash: harnessPackageManifest?.workflowContentHash ?? null,
      reviewedPackageSnapshotHash,
      policyPosture: candidate.policyPosture ?? packagePolicyPosture,
      replayFixtureRefs: harnessPackageManifest?.replayFixtureRefs ?? [],
      workerHandoffNodeAttemptIds:
        harnessPackageManifest?.workerHandoffNodeAttemptIds ?? [],
      workerHandoffReceiptIds:
        harnessPackageManifest?.workerHandoffReceiptIds ?? [],
      gateCount: candidate.gateResults.length,
      passedGateCount,
      blockerCount: candidate.activationBlockers.length,
      blockerCodes: candidate.blockerCodes,
      packageEvidenceReady,
      mintable:
        candidate.decision === "mintable" &&
        packageEvidenceReady &&
        candidate.activationBlockers.length === 0,
      deepLinkTargets: {
	        activationId: candidate.activationIdPreview ?? null,
	        canary: candidate.canaryStatus === "passed" ? "canary" : null,
	        mutationCanary:
	          candidate.forkMutationCanary.status === "passed"
	            ? candidate.forkMutationCanary.canaryId
	            : null,
	        rollbackRestore: candidate.rollbackRestoreCanary.canaryId,
        rollbackTarget: candidate.rollbackTarget || null,
        workerBindingId,
      },
    };
  }
  return review;
}

function reviewedPackageSnapshotFromPackageImportSource(
  source: WorkflowPackageImportReview["source"] | null | undefined,
): WorkflowHarnessReviewedPackageSnapshotFields | null {
  if (!source) return null;
  return {
    reviewedPackageSnapshotHash: source.reviewedPackageSnapshotHash,
    reviewedWorkflowContentHash: source.workflowContentHash,
    reviewedActivationId: source.activationId,
    reviewedHarnessWorkflowId: source.harnessWorkflowId,
    reviewedWorkerBindingActivationId: source.workerBindingActivationId,
    reviewedRollbackTarget: source.rollbackTarget,
    reviewedReplayFixtureRefs: source.replayFixtureRefs,
    reviewedWorkerHandoffNodeAttemptIds: source.workerHandoffNodeAttemptIds,
    reviewedWorkerHandoffReceiptIds: source.workerHandoffReceiptIds,
    reviewedForkMutationCanaryId: source.forkMutationCanaryId,
    reviewedForkMutationCanaryStatus: source.forkMutationCanaryStatus,
    reviewedForkMutationCanaryDiffHash: source.forkMutationCanaryDiffHash,
    reviewedForkMutationCanaryReceiptRefs: source.forkMutationCanaryReceiptRefs,
    reviewedForkMutationCanaryReplayFixtureRefs:
      source.forkMutationCanaryReplayFixtureRefs,
    reviewedForkMutationCanaryNodeAttemptIds:
      source.forkMutationCanaryNodeAttemptIds,
    reviewedForkMutationCanaryRollbackTarget:
      source.forkMutationCanaryRollbackTarget,
    reviewedPolicyPosture: source.policyPosture,
    rollbackTarget: source.rollbackTarget,
  };
}

function readWorkflowRightRailTestId(): string | null {
  if (typeof document === "undefined") return null;
  return (
    document
      .querySelector('[data-testid^="workflow-right-rail-"]')
      ?.getAttribute("data-testid") ?? null
  );
}

function readWorkflowStatusMessage(): string | null {
  if (typeof document === "undefined") return null;
  return (
    document
      .querySelector('[data-testid="workflow-status-message"]')
      ?.textContent?.trim() || null
  );
}

type HarnessReplayGateClickResult = {
  gateId: string;
  gateStatus: string;
  activationGateImpact: string;
  scopeKind: string;
  targetId: string;
  totalFixtures: number;
  replayFixtureRefs: string[];
  receiptRefs: string[];
  evidenceRefs: string[];
  replayGateCount: number;
  replayDrillCount: number;
  statusMessage: string;
};

function readHarnessReplayGateClickResult(): HarnessReplayGateClickResult | null {
  if (typeof window === "undefined") return null;
  const result = (window as any).__AUTOPILOT_HARNESS_REPLAY_GATE_CLICK_RESULT;
  return result && typeof result === "object"
    ? (result as HarnessReplayGateClickResult)
    : null;
}

type HarnessActivationDryRunClickResult = {
  candidateId: string;
  decision: string;
  activationBlockerCount: number;
  workflowActivationId: string | null;
  workflowActivationState: string | null;
  workerBindingActivationId: string | null;
  rollbackRestoreCanaryId: string;
  rollbackRestoreStatus: string;
  rollbackRestoreRevisionSource: string;
  rollbackRestoreStrategy: string;
  rollbackRestoreHashVerified: boolean;
  rollbackRestoreReceiptBindingRef: string | null;
  rollbackRestoreEvidenceRefs: string[];
  rollbackRestoreBlockers: string[];
  rollbackRestoreGateStatus: string | null;
  activationAuditEventCount: number;
  latestAuditEventId: string | null;
  latestAuditEventType: string | null;
  latestAuditStatus: string | null;
  statusMessage: string;
};

function readHarnessActivationDryRunClickResult(): HarnessActivationDryRunClickResult | null {
  if (typeof window === "undefined") return null;
  const result = (window as any)
    .__AUTOPILOT_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT;
  return result && typeof result === "object"
    ? (result as HarnessActivationDryRunClickResult)
    : null;
}

type HarnessActivationMintClickResult = {
  applied: boolean;
  activationId: string | null;
  blockers: string[];
  workflowActivationId: string | null;
  workflowActivationState: string | null;
  workerBindingActivationId: string | null;
  activationRecordWorkerBindingActivationId: string | null;
  rollbackTarget: string | null;
  revisionBindingActivationId: string | null;
  activationRecordRevisionBindingHash: string | null;
  rollbackRevisionBindingHash: string | null;
  activationAuditEventCount: number;
  latestAuditEventId: string | null;
  latestAuditEventType: string | null;
  latestAuditStatus: string | null;
  receiptRefs: string[];
  evidenceRefs: string[];
  workerHandoffReceiptIds: string[];
  workerHandoffNodeAttemptIds: string[];
  workerHandoffReplayFixtureRefs: string[];
  reviewedPackageSnapshotHash: string | null;
  reviewedWorkflowContentHash: string | null;
  reviewedActivationId: string | null;
  reviewedHarnessWorkflowId: string | null;
  reviewedWorkerBindingActivationId: string | null;
  reviewedRollbackTarget: string | null;
	  reviewedReplayFixtureRefs: string[];
	  reviewedWorkerHandoffNodeAttemptIds: string[];
	  reviewedWorkerHandoffReceiptIds: string[];
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: string[];
  reviewedForkMutationCanaryReplayFixtureRefs?: string[];
  reviewedForkMutationCanaryNodeAttemptIds?: string[];
  reviewedForkMutationCanaryRollbackTarget?: string | null;
	  reviewedPolicyPosture: string | null;
  statusMessage: string;
};

function readHarnessActivationMintClickResult(): HarnessActivationMintClickResult | null {
  if (typeof window === "undefined") return null;
  const result = (window as any)
    .__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT;
  return result && typeof result === "object"
    ? (result as HarnessActivationMintClickResult)
    : null;
}

type HarnessActiveRuntimeRollbackDryRunClickResult = {
  passed: boolean;
  blockers: string[];
  rollbackTarget: string;
  readinessProofId: string;
  liveShadowComparisonGateId: string;
  activationId: string;
  harnessHash: string;
  dryRunStatus: string;
  canaryResultId: string | null;
  canaryStatus: string;
  canaryHashVerified: boolean;
  applyReadiness: string;
  applyDisabled: boolean;
  statusMessage: string;
};

type HarnessActiveRuntimeRollbackApplyClickResult = {
  passed: boolean;
  applied: boolean;
  blockers: string[];
  rollbackTarget: string;
  readinessProofId: string;
  liveShadowComparisonGateId: string;
  activationId: string;
  harnessHash: string;
  executionId: string;
  rollbackReceiptId: string;
  auditEventId: string;
  applyStatus: string;
  rollbackTargetVerified: boolean;
  hashVerified: boolean;
  policyDecision: string;
  receiptRefs: string[];
  replayFixtureRefs: string[];
  statusMessage: string;
};

function readHarnessActiveRuntimeRollbackDryRunClickResult(): HarnessActiveRuntimeRollbackDryRunClickResult | null {
  if (typeof window === "undefined") return null;
  const result = (window as any)
    .__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_DRY_RUN_RESULT;
  return result && typeof result === "object"
    ? (result as HarnessActiveRuntimeRollbackDryRunClickResult)
    : null;
}

function readHarnessActiveRuntimeRollbackApplyClickResult(): HarnessActiveRuntimeRollbackApplyClickResult | null {
  if (typeof window === "undefined") return null;
  const result = (window as any)
    .__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_APPLY_RESULT;
  return result && typeof result === "object"
    ? (result as HarnessActiveRuntimeRollbackApplyClickResult)
    : null;
}

function harnessDeepLinkProbeCasesForWorkflow(
  workflow: WorkflowProject,
): HarnessWorkbenchDeepLinkProbeCase[] {
  const selector = workflow.metadata.harness?.runtimeSelectorDecision ?? null;
  const dispatch =
    workflow.metadata.harness?.defaultRuntimeDispatchProof ?? null;
  const workerBinding = workflow.metadata.workerHarnessBinding ?? null;
  const revisionBinding =
    workflow.metadata.harness?.revisionBinding ??
    workflow.metadata.harness?.activationRecord?.revisionBinding ??
    null;
  const revisionBindingRef =
    revisionBinding?.activatedRevision ??
    revisionBinding?.workflowContentHash ??
    revisionBinding?.activationId ??
    null;
  const activationBlockerRef =
    workflow.metadata.harness?.activationRecord?.activationBlockers?.[0] ??
    null;
  const activationAuditEventId =
    workflow.metadata.harness?.activationAudit?.find((event) => event.eventId)
      ?.eventId ?? null;
  const isHarnessFork = Boolean(workflow.metadata.harness?.forkedFrom);
  const activationGateId = isHarnessFork ? "slots" : null;
  const hasLiveWorkerInvariantGate =
    workflowIsBlessedHarness(workflow) ||
    Boolean(workflow.metadata.harness?.defaultRuntimeDispatchProof);
  const activationGateEvidenceRef = activationGateId
    ? (harnessSlotsForWorkflow(workflow).find((slot) => slot.required)
        ?.slotId ?? null)
    : null;
  const activationGateReferenceBoundary = isHarnessFork
    ? ((workflow.metadata.harness?.canaryExecutionBoundaries ?? []).find(
        (boundary) =>
          boundary.receiptIds.length > 0 ||
          boundary.replayFixtureRefs.length > 0,
      ) ?? null)
    : null;
  const activationGateReceiptRef =
    activationGateReferenceBoundary?.receiptIds[0] ?? null;
  const activationGateReplayFixtureRef = isHarnessFork
    ? (activationGateReferenceBoundary?.replayFixtureRefs[0] ??
      (workflow.metadata.harness?.replayGates ?? []).flatMap(
        (gate) => gate.replayFixtureRefs,
      )[0] ??
      null)
    : null;
  const activationGateReferenceGateId = activationGateReferenceBoundary
    ? "canary"
    : activationGateReplayFixtureRef
      ? "replay-fixtures"
      : null;
  const activationGateCanaryBoundaryId =
    activationGateReferenceBoundary?.boundaryId ?? null;
  const activationGateCanaryRollbackDrillId =
    activationGateReferenceBoundary?.rollbackDrill?.drillId ?? null;
  const activationGateWorkerHandoffAttemptId = isHarnessFork
    ? (workflow.metadata.harness?.activationRecord
        ?.workerHandoffNodeAttemptIds?.[0] ?? null)
    : null;
  const activationGateWorkerHandoffReceiptRef = isHarnessFork
    ? (workflow.metadata.harness?.activationRecord?.workerHandoffReceipts?.[0]
        ?.receiptId ?? null)
    : null;
  const activationGateWorkerHandoffReplayFixtureRef = isHarnessFork
    ? (workflow.metadata.harness?.activationRecord
        ?.workerHandoffReplayFixtureRefs?.[0] ?? null)
    : null;
  const activationGateMutationCanary = isHarnessFork
    ? (workflow.metadata.harness?.activationRecord?.forkMutationCanary ??
      workflow.metadata.harness?.forkMutationCanary ??
      null)
    : null;
  const activationGateMutationCanaryAttemptId =
    workflowHarnessForkMutationCanaryNodeAttempts(
      activationGateMutationCanary,
    )[0]?.attemptId ??
    activationGateMutationCanary?.nodeAttemptIds?.[0] ??
    null;
  const activationGateMutationCanaryReceiptRef =
    activationGateMutationCanary?.receiptRefs?.[0] ?? null;
  const activationGateMutationCanaryReplayFixtureRef =
    activationGateMutationCanary?.replayFixtureRefs?.[0] ?? null;
  const cases: Array<HarnessWorkbenchDeepLinkProbeCase | null> = [
    selector?.decisionId
      ? {
          id: "selector",
          link: {
            panel: "settings" as WorkflowRightPanel,
            selectorDecisionId: selector.decisionId,
          },
          expectedAttribute: "data-selected-selector-decision-id",
          expectedValue: selector.decisionId,
          selectedRailTestId: "workflow-harness-active-runtime-binding",
        }
      : null,
    dispatch?.dispatchId
      ? {
          id: "dispatch",
          link: {
            panel: "settings" as WorkflowRightPanel,
            dispatchId: dispatch.dispatchId,
          },
          expectedAttribute: "data-selected-default-dispatch-id",
          expectedValue: dispatch.dispatchId,
          selectedRailTestId: "workflow-harness-active-runtime-binding",
        }
      : null,
    workerBinding?.harnessActivationId
      ? {
          id: "worker",
          link: {
            panel: "settings" as WorkflowRightPanel,
            workerBindingId: workerBinding.harnessActivationId,
          },
          expectedAttribute: "data-selected-worker-binding-id",
          expectedValue: workerBinding.harnessActivationId,
          selectedRailTestId: "workflow-harness-active-runtime-binding",
        }
      : null,
    dispatch?.rollbackTarget
      ? {
          id: "rollback",
          link: {
            panel: "settings" as WorkflowRightPanel,
            rollbackTarget: dispatch.rollbackTarget,
          },
          expectedAttribute: "data-selected-rollback-target",
          expectedValue: dispatch.rollbackTarget,
          selectedRailTestId: "workflow-harness-active-runtime-binding",
        }
      : null,
    dispatch?.receiptIds[0]
      ? {
          id: "receipt",
          link: {
            panel: "outputs" as WorkflowRightPanel,
            receiptRef: dispatch.receiptIds[0],
          },
          expectedAttribute: "data-selected-receipt-ref",
          expectedValue: dispatch.receiptIds[0],
          selectedRailTestId: "workflow-harness-deep-link-state",
        }
      : null,
    dispatch?.replayFixtureRefs[0]
      ? {
          id: "replay",
          link: {
            panel: "outputs" as WorkflowRightPanel,
            replayFixtureRef: dispatch.replayFixtureRefs[0],
          },
          expectedAttribute: "data-selected-replay-fixture-ref",
          expectedValue: dispatch.replayFixtureRefs[0],
          selectedRailTestId: "workflow-harness-deep-link-state",
        }
      : null,
    revisionBindingRef
      ? {
          id: "revision",
          link: {
            panel: "settings" as WorkflowRightPanel,
            revisionBindingKind: "current",
            revisionBindingRef,
          },
          expectedAttribute: "data-selected-revision-binding-ref",
          expectedValue: revisionBindingRef,
          selectedRailTestId: "workflow-harness-revision-binding",
          expectedParsedKey: "revisionBindingRef",
        }
      : null,
    activationBlockerRef
      ? {
          id: "activation-blocker",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationBlockerIndex: "0",
            activationBlockerRef,
          },
          expectedAttribute: "data-selected-activation-blocker-ref",
          expectedValue: activationBlockerRef,
          selectedRailTestId: "workflow-harness-activation-blockers",
          expectedParsedKey: "activationBlockerRef",
        }
      : null,
    activationAuditEventId
      ? {
          id: "activation-audit",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationAuditEventId,
          },
          expectedAttribute: "data-selected-activation-audit-event-id",
          expectedValue: activationAuditEventId,
          selectedRailTestId: "workflow-harness-activation-audit",
          expectedParsedKey: "activationAuditEventId",
        }
      : null,
    activationGateId
      ? {
          id: "activation-gate",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId,
          },
          expectedAttribute: "data-selected-activation-gate-id",
          expectedValue: activationGateId,
          selectedRailTestId: "workflow-harness-activation-gate-inspector",
          expectedParsedKey: "activationGateId",
        }
      : null,
    hasLiveWorkerInvariantGate
      ? {
          id: "activation-gate-worker-invariant",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: "worker-invariant",
          },
          expectedAttribute: "data-selected-activation-gate-id",
          expectedValue: "worker-invariant",
          selectedRailTestId: "workflow-harness-activation-gate-inspector",
          expectedParsedKey: "activationGateId",
        }
      : null,
    activationGateId && activationGateEvidenceRef
      ? {
          id: "activation-gate-evidence",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId,
            activationGateEvidenceRef,
          },
          expectedAttribute: "data-selected-activation-gate-evidence-ref",
          expectedValue: activationGateEvidenceRef,
          selectedRailTestId: "workflow-harness-activation-gate-inspector",
          expectedParsedKey: "activationGateEvidenceRef",
        }
      : null,
    activationGateReferenceGateId && activationGateReceiptRef
      ? {
          id: "activation-gate-receipt",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: activationGateReferenceGateId,
            activationGateReceiptRef,
            receiptRef: activationGateReceiptRef,
          },
          expectedAttribute: "data-selected-activation-gate-receipt-ref",
          expectedValue: activationGateReceiptRef,
          selectedRailTestId: "workflow-harness-activation-gate-inspector",
          expectedParsedKey: "activationGateReceiptRef",
        }
      : null,
    activationGateReferenceGateId && activationGateReplayFixtureRef
      ? {
          id: "activation-gate-replay",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: activationGateReferenceGateId,
            activationGateReplayFixtureRef,
            replayFixtureRef: activationGateReplayFixtureRef,
          },
          expectedAttribute: "data-selected-activation-gate-replay-fixture-ref",
          expectedValue: activationGateReplayFixtureRef,
          selectedRailTestId: "workflow-harness-activation-gate-inspector",
          expectedParsedKey: "activationGateReplayFixtureRef",
        }
      : null,
    activationGateCanaryBoundaryId && activationGateReceiptRef
      ? {
          id: "activation-gate-canary-boundary",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: "canary",
            activationGateEvidenceRef: activationGateCanaryBoundaryId,
            activationGateReceiptRef,
            receiptRef: activationGateReceiptRef,
            activationGateReplayFixtureRef:
              activationGateReplayFixtureRef ?? undefined,
            replayFixtureRef: activationGateReplayFixtureRef ?? undefined,
          },
          expectedAttribute: "data-selected-canary-boundary-id",
          expectedValue: activationGateCanaryBoundaryId,
          selectedRailTestId: "workflow-harness-canary-execution-boundaries",
          expectedParsedKey: "activationGateEvidenceRef",
        }
      : null,
    activationGateCanaryRollbackDrillId && activationGateReceiptRef
      ? {
          id: "activation-gate-canary-rollback-drill",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: "canary",
            activationGateEvidenceRef: activationGateCanaryRollbackDrillId,
            activationGateReceiptRef,
            receiptRef: activationGateReceiptRef,
            activationGateReplayFixtureRef:
              activationGateReplayFixtureRef ?? undefined,
            replayFixtureRef: activationGateReplayFixtureRef ?? undefined,
          },
          expectedAttribute: "data-selected-rollback-drill-id",
          expectedValue: activationGateCanaryRollbackDrillId,
          selectedRailTestId: "workflow-harness-canary-execution-boundaries",
          expectedParsedKey: "activationGateEvidenceRef",
        }
      : null,
	    activationGateWorkerHandoffAttemptId
	      ? {
	          id: "activation-gate-node-attempt",
          link: {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: "worker-handoff",
            activationGateNodeAttemptId: activationGateWorkerHandoffAttemptId,
            nodeAttemptId: activationGateWorkerHandoffAttemptId,
            activationGateReceiptRef:
              activationGateWorkerHandoffReceiptRef ?? undefined,
            receiptRef: activationGateWorkerHandoffReceiptRef ?? undefined,
            activationGateReplayFixtureRef:
              activationGateWorkerHandoffReplayFixtureRef ?? undefined,
            replayFixtureRef:
              activationGateWorkerHandoffReplayFixtureRef ?? undefined,
          },
          expectedAttribute:
            "data-selected-activation-gate-node-attempt-id",
          expectedValue: activationGateWorkerHandoffAttemptId,
          selectedRailTestId: "workflow-harness-activation-gate-inspector",
	          expectedParsedKey: "activationGateNodeAttemptId",
	        }
	      : null,
    activationGateMutationCanary && activationGateMutationCanaryAttemptId
      ? {
          id: "activation-gate-mutation-canary-node-attempt",
          link: {
            panel: "outputs" as WorkflowRightPanel,
            activationGateId: "mutation-canary",
            activationGateEvidenceRef: activationGateMutationCanary.canaryId,
            activationGateNodeAttemptId: activationGateMutationCanaryAttemptId,
            nodeAttemptId: activationGateMutationCanaryAttemptId,
            activationGateReceiptRef:
              activationGateMutationCanaryReceiptRef ?? undefined,
            receiptRef: activationGateMutationCanaryReceiptRef ?? undefined,
            activationGateReplayFixtureRef:
              activationGateMutationCanaryReplayFixtureRef ?? undefined,
            replayFixtureRef:
              activationGateMutationCanaryReplayFixtureRef ?? undefined,
          },
          expectedAttribute: "data-node-attempt-id",
          expectedValue: activationGateMutationCanaryAttemptId,
          selectedRailTestId: "workflow-harness-node-attempt-inspector",
          expectedParsedKey: "nodeAttemptId",
        }
      : null,
	  ];
  return cases.filter(
    (item): item is HarnessWorkbenchDeepLinkProbeCase => item !== null,
  );
}

function harnessLiveTurnNodeInspectorAttemptForWorkflow(
  workflow: WorkflowProject,
): WorkflowHarnessNodeAttemptRecord | null {
  const dispatch =
    workflow.metadata.harness?.defaultRuntimeDispatchProof ?? null;
  if (!dispatch) return null;
  const adapterAttempts = [
    ...(dispatch.cognitionExecutionAdapterResults ?? []),
    ...(dispatch.cognitionExecutionShadowAdapterResults ?? []),
    ...(dispatch.cognitionExecutionGateAdapterResults ?? []),
    ...(dispatch.routingModelAdapterResults ?? []),
    ...(dispatch.routingModelShadowAdapterResults ?? []),
    ...(dispatch.verificationOutputAdapterResults ?? []),
    ...(dispatch.verificationOutputShadowAdapterResults ?? []),
    ...(dispatch.authorityToolingAdapterResults ?? []),
    ...(dispatch.authorityToolingShadowAdapterResults ?? []),
  ].map((result) => result.nodeAttempt);
  const attempts = [
    ...adapterAttempts,
    ...(dispatch.dispatchNodeAttempts ?? []),
  ].filter(
    (attempt): attempt is WorkflowHarnessNodeAttemptRecord =>
      Boolean(attempt),
  );
  const inspectable = (attempt: WorkflowHarnessNodeAttemptRecord) =>
    attempt.attemptId.length > 0 &&
    attempt.workflowNodeId.length > 0 &&
    attempt.componentId.length > 0 &&
    attempt.receiptIds.length > 0 &&
    Boolean(attempt.replay.fixtureRef) &&
    Boolean(attempt.inputHash) &&
    Boolean(attempt.outputHash) &&
    Boolean(attempt.policyDecision);
  return (
    attempts.find(
      (attempt) =>
        attempt.executionMode === "live" &&
        attempt.readiness === "live_ready" &&
        attempt.status === "live" &&
        inspectable(attempt),
    ) ??
    attempts.find(
      (attempt) => attempt.executionMode === "live" && inspectable(attempt),
    ) ??
    attempts.find(inspectable) ??
    null
  );
}

function harnessLiveShadowComparisonForWorkflow(
  workflow: WorkflowProject,
): {
  comparison: WorkflowHarnessShadowComparison;
  liveAttempt: WorkflowHarnessNodeAttemptRecord;
  shadowAttempt: WorkflowHarnessNodeAttemptRecord;
} | null {
  const dispatch =
    workflow.metadata.harness?.defaultRuntimeDispatchProof ?? null;
  const comparison = dispatch?.liveShadowComparisons?.[0] ?? null;
  if (!dispatch || !comparison) return null;
  const attempts = [
    ...(dispatch.cognitionExecutionAdapterResults ?? []),
    ...(dispatch.cognitionExecutionShadowAdapterResults ?? []),
    ...(dispatch.cognitionExecutionGateAdapterResults ?? []),
    ...(dispatch.routingModelAdapterResults ?? []),
    ...(dispatch.routingModelShadowAdapterResults ?? []),
    ...(dispatch.verificationOutputAdapterResults ?? []),
    ...(dispatch.verificationOutputShadowAdapterResults ?? []),
    ...(dispatch.authorityToolingAdapterResults ?? []),
    ...(dispatch.authorityToolingShadowAdapterResults ?? []),
  ]
    .map((result) => result.nodeAttempt)
    .filter(
      (attempt): attempt is WorkflowHarnessNodeAttemptRecord =>
        Boolean(attempt),
    );
  const liveAttempt =
    attempts.find((attempt) => attempt.attemptId === comparison.liveAttemptId) ??
    null;
  const shadowAttempt =
    attempts.find(
      (attempt) => attempt.attemptId === comparison.shadowAttemptId,
    ) ?? null;
  return liveAttempt && shadowAttempt
    ? { comparison, liveAttempt, shadowAttempt }
    : null;
}

type HarnessGroupCanvasView = WorkflowHarnessGroupView & {
  groupNodeId: string;
  position: { x: number; y: number };
};

export function useWorkflowComposerController({
  runtime,
  currentProject,
  initialFile,
  onInitialFileLoaded,
}: WorkflowComposerProps) {
  const defaultWorkflow = useMemo(() => makeDefaultWorkflow(), []);
  const {
    nodes,
    edges,
    setNodes,
    setEdges,
    onNodesChange,
    onEdgesChange,
    onConnect,
    handleCanvasDrop,
    selectedNodeId,
    handleNodeSelect,
    fitView,
    zoomIn,
    zoomOut,
    replaceGraph,
    addNode,
  } = useGraphState(defaultWorkflow.nodes, defaultWorkflow.edges);
  const execution = useGraphExecution(
    runtime,
    nodes,
    edges,
    setNodes,
    setEdges,
  );
  const [workflow, setWorkflow] = useState<WorkflowProject>(defaultWorkflow);
  const [workflowPath, setWorkflowPath] = useState(
    currentProject?.rootPath
      ? `${currentProject.rootPath}/.agents/workflows/${defaultWorkflow.metadata.slug}.workflow.json`
      : defaultWorkflow.metadata.gitLocation ||
          ".agents/workflows/agent-workflow.workflow.json",
  );
  const [testsPath, setTestsPath] = useState(
    workflowPath.replace(/\.workflow\.json$/, ".tests.json"),
  );
  const [tests, setTests] = useState<WorkflowTestCase[]>([]);
  const [proposals, setProposals] = useState<WorkflowProposal[]>([]);
  const [runs, setRuns] = useState<WorkflowRunSummary[]>([]);
  const [activeTab, setActiveTab] = useState<WorkflowWorkbenchTab>("graph");
  const [rightPanel, setRightPanel] = useState<WorkflowRightPanel>("outputs");
  const [bottomPanel, setBottomPanel] =
    useState<WorkflowBottomPanel>("selection");
  const [rightRailCollapsed, setRightRailCollapsed] = useState(false);
  const [rightRailWidth, setRightRailWidth] = useState(336);
  const [leftDrawerOpen, setLeftDrawerOpen] = useState(false);
  const [nodeSearch, setNodeSearch] = useState("");
  const [canvasSearchOpen, setCanvasSearchOpen] = useState(false);
  const [canvasSearchQuery, setCanvasSearchQuery] = useState("");
  const [collapsedHarnessGroupIds, setCollapsedHarnessGroupIds] = useState<
    Record<string, boolean>
  >({});
  const [selectedHarnessGroupId, setSelectedHarnessGroupId] = useState<
    string | null
  >(null);
  const [selectedHarnessReceiptRef, setSelectedHarnessReceiptRef] = useState<
    string | null
  >(null);
  const [selectedHarnessReplayFixtureRef, setSelectedHarnessReplayFixtureRef] =
    useState<string | null>(null);
  const [selectedHarnessRollbackTarget, setSelectedHarnessRollbackTarget] =
    useState<string | null>(null);
  const [
    selectedHarnessSelectorDecisionId,
    setSelectedHarnessSelectorDecisionId,
  ] = useState<string | null>(null);
  const [
    selectedHarnessDefaultDispatchId,
    setSelectedHarnessDefaultDispatchId,
  ] = useState<string | null>(null);
  const [selectedHarnessWorkerBindingId, setSelectedHarnessWorkerBindingId] =
    useState<string | null>(null);
  const [selectedHarnessNodeAttemptId, setSelectedHarnessNodeAttemptId] =
    useState<string | null>(null);
  const [
    selectedHarnessRevisionBindingKind,
    setSelectedHarnessRevisionBindingKind,
  ] = useState<string | null>(null);
  const [
    selectedHarnessRevisionBindingRef,
    setSelectedHarnessRevisionBindingRef,
  ] = useState<string | null>(null);
  const [
    selectedHarnessActivationBlockerIndex,
    setSelectedHarnessActivationBlockerIndex,
  ] = useState<string | null>(null);
  const [
    selectedHarnessActivationBlockerRef,
    setSelectedHarnessActivationBlockerRef,
  ] = useState<string | null>(null);
  const [
    selectedHarnessActivationAuditEventId,
    setSelectedHarnessActivationAuditEventId,
  ] = useState<string | null>(null);
  const [selectedHarnessActivationGateId, setSelectedHarnessActivationGateId] =
    useState<string | null>(null);
  const [
    selectedHarnessActivationGateEvidenceRef,
    setSelectedHarnessActivationGateEvidenceRef,
  ] = useState<string | null>(null);
  const [
    selectedHarnessActivationGateReceiptRef,
    setSelectedHarnessActivationGateReceiptRef,
  ] = useState<string | null>(null);
  const [
    selectedHarnessActivationGateNodeAttemptId,
    setSelectedHarnessActivationGateNodeAttemptId,
  ] = useState<string | null>(null);
  const [
    selectedHarnessActivationGateReplayFixtureRef,
    setSelectedHarnessActivationGateReplayFixtureRef,
  ] = useState<string | null>(null);
  const [harnessActivationCandidate, setHarnessActivationCandidate] =
    useState<WorkflowHarnessForkActivationCandidate | null>(null);
  const restoredHarnessDeepLinkWorkflowRef = useRef<string | null>(null);
  const [nodeConfigOpen, setNodeConfigOpen] = useState(false);
  const [nodeConfigInitialSection, setNodeConfigInitialSection] =
    useState<WorkflowNodeConfigSectionId>("settings");
  const [compatiblePortFocus, setCompatiblePortFocus] = useState<{
    nodeId: string;
    portId: string;
    direction: "downstream" | "attachment";
  } | null>(null);
  const [modelBindingOpen, setModelBindingOpen] = useState(false);
  const [connectorBindingOpen, setConnectorBindingOpen] = useState(false);
  const [testEditorOpen, setTestEditorOpen] = useState(false);
  const [deployOpen, setDeployOpen] = useState(false);
  const [proposalToReview, setProposalToReview] =
    useState<WorkflowProposal | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [nodeGroupFilter, setNodeGroupFilter] =
    useState<WorkflowNodeGroupFilter>("All");
  const [recentNodeTypes, setRecentNodeTypes] = useState<string[]>([]);
  const [createName, setCreateName] = useState("New blank workflow");
  const [createKind, setCreateKind] = useState<WorkflowKind>("agent_workflow");
  const [createMode, setCreateMode] = useState<WorkflowExecutionMode>("local");
  const [newTestName, setNewTestName] = useState("Selected node exists");
  const [newTestTargets, setNewTestTargets] = useState("");
  const [newTestKind, setNewTestKind] =
    useState<WorkflowTestCase["assertion"]["kind"]>("node_exists");
  const [newTestExpected, setNewTestExpected] = useState("");
  const [newTestExpression, setNewTestExpression] = useState("");
  const [statusMessage, setStatusMessage] = useState("Ready");
  const [testResult, setTestResult] = useState<WorkflowTestRunResult | null>(
    null,
  );
  const [validationResult, setValidationResult] =
    useState<WorkflowValidationResult | null>(null);
  const [readinessResult, setReadinessResult] =
    useState<WorkflowValidationResult | null>(null);
  const [lastRunResult, setLastRunResult] = useState<WorkflowRunResult | null>(
    null,
  );
  const [runDetailLoading, setRunDetailLoading] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [compareRunResult, setCompareRunResult] =
    useState<WorkflowRunResult | null>(null);
  const [compareRunId, setCompareRunId] = useState<string | null>(null);
  const [functionDryRunResult, setFunctionDryRunResult] =
    useState<WorkflowRunResult | null>(null);
  const [dogfoodRun, setDogfoodRun] = useState<WorkflowDogfoodRun | null>(null);
  const [portablePackage, setPortablePackage] =
    useState<WorkflowPortablePackage | null>(null);
  const [packageImportReview, setPackageImportReview] =
    useState<WorkflowPackageImportReview | null>(null);
  const [bindingManifest, setBindingManifest] =
    useState<WorkflowBindingManifest | null>(null);
  const [importPackageOpen, setImportPackageOpen] = useState(false);
  const [importPackagePath, setImportPackagePath] = useState("");
  const [importPackageName, setImportPackageName] = useState("");
  const [connectFromNodeId, setConnectFromNodeId] = useState<string | null>(
    null,
  );
  const [runEvents, setRunEvents] = useState<WorkflowStreamEvent[]>([]);
  const [runtimeThreadEvents, setRuntimeThreadEvents] = useState<
    WorkflowRuntimeThreadEventLike[]
  >([]);
  const [checkpoints, setCheckpoints] = useState<WorkflowCheckpoint[]>([]);
  const [nodeRunStatusById, setNodeRunStatusById] = useState<
    Record<string, WorkflowNodeRun>
  >({});
  const [nodeFixturesById, setNodeFixturesById] = useState<
    Record<string, WorkflowNodeFixture[]>
  >({});
  const dogfoodAutomationStarted = useRef(false);
  const liveTelemetryRunIdRef = useRef<string | null>(null);
  const [globalConfig, setGlobalConfig] = useState<GraphGlobalConfig>(
    defaultWorkflow.global_config,
  );
  const openLeftDrawer = useCallback(() => {
    setCanvasSearchOpen(false);
    setLeftDrawerOpen(true);
  }, []);
  const closeLeftDrawer = useCallback(() => {
    setLeftDrawerOpen(false);
    setNodeSearch("");
    setNodeGroupFilter("All");
    setCompatiblePortFocus(null);
  }, []);
  const toggleLeftDrawer = useCallback(() => {
    setLeftDrawerOpen((open) => {
      const nextOpen = !open;
      if (nextOpen) {
        setCanvasSearchOpen(false);
      }
      return nextOpen;
    });
  }, []);
  const closeCanvasSearch = useCallback(() => {
    setCanvasSearchOpen(false);
  }, []);
  const toggleCanvasSearch = useCallback(() => {
    setCanvasSearchOpen((open) => {
      const nextOpen = !open;
      if (nextOpen) {
        setLeftDrawerOpen(false);
      }
      return nextOpen;
    });
  }, []);

  const selectedNode =
    (nodes.find((node) => node.id === selectedNodeId)?.data as
      | Node
      | undefined) ?? null;
  const selectedDefinition = selectedNode
    ? WORKFLOW_NODE_DEFINITIONS.find(
        (definition) => definition.type === selectedNode.type,
      )
    : null;
  const selectedOutputClasses = new Set(
    (selectedNode?.ports ?? [])
      .filter((port) => port.direction === "output")
      .map((port) => port.connectionClass),
  );
  const isSearchingNodeLibrary = nodeSearch.trim().length > 0;
  const searchedNodeLibrary = useMemo(() => {
    const query = nodeSearch.trim().toLowerCase();
    return NODE_LIBRARY.filter((item) => {
      const scaffold = WORKFLOW_SCAFFOLDS.find(
        (entry) => entry.nodeType === item.type,
      );
      const action = ACTION_BY_NODE_TYPE.get(item.type);
      const haystack = [
        item.label,
        item.group,
        item.familyLabel,
        item.metricLabel,
        "creatorDescription" in item ? item.creatorDescription : "",
        action?.description,
        action?.requiredBinding,
        action?.sideEffectClass,
        action?.requiresApproval ? "approval" : "",
        action?.supportsMockBinding ? "mock live credential" : "",
        action?.schemaRequired ? "schema typed contract" : "",
        ...(scaffold?.keywords ?? []),
        ...(scaffold?.connectionClasses ?? []),
        ...(action?.keywords ?? []),
        ...(action?.connectionClasses ?? []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return !query || haystack.includes(query);
    });
  }, [nodeSearch]);
  const compatibleNodeHints = useMemo<WorkflowCompatibleNodeHint[]>(() => {
    if (!selectedNode) return [];
    const selectedActionKind = actionKindForWorkflowNodeType(selectedNode.type);
    const selectedOutputPorts = (selectedNode.ports ?? []).filter(
      (port) => port.direction === "output",
    );
    const selectedInputPorts = (selectedNode.ports ?? []).filter(
      (port) => port.direction === "input",
    );
    const selectedScaffold = WORKFLOW_SCAFFOLDS.find(
      (entry) => entry.nodeType === selectedNode.type,
    );
    const hints = NODE_LIBRARY.flatMap((definition) => {
      const targetActionKind = actionKindForWorkflowNodeType(definition.type);
      const downstreamHints: WorkflowCompatibleNodeHint[] = [];
      for (const sourcePort of selectedOutputPorts) {
        for (const targetPort of definition.portDefinitions.filter(
          (port) => port.direction === "input",
        )) {
          const issue = validateWorkflowConnection(
            selectedActionKind,
            targetActionKind,
            sourcePort,
            targetPort,
          );
          if (!issue) {
            downstreamHints.push({
              definition,
              sourcePort,
              targetPort,
              connectionClass: sourcePort.connectionClass,
              direction: "downstream",
              recommended: Boolean(
                selectedScaffold?.relatedNodeTypes?.includes(
                  definition.type as WorkflowNodeKind,
                ),
              ),
            });
            break;
          }
        }
      }
      const sourceActionKind = targetActionKind;
      const attachmentHints: WorkflowCompatibleNodeHint[] = [];
      for (const sourcePort of definition.portDefinitions.filter(
        (port) => port.direction === "output",
      )) {
        for (const targetPort of selectedInputPorts) {
          const issue = validateWorkflowConnection(
            sourceActionKind,
            selectedActionKind,
            sourcePort,
            targetPort,
          );
          if (!issue) {
            attachmentHints.push({
              definition,
              sourcePort,
              targetPort,
              connectionClass: sourcePort.connectionClass,
              direction: "attachment",
              recommended:
                targetPort.semanticRole !== "input" ||
                Boolean(
                  selectedScaffold?.relatedNodeTypes?.includes(
                    definition.type as WorkflowNodeKind,
                  ),
                ),
            });
            break;
          }
        }
      }
      return [...downstreamHints, ...attachmentHints];
    });
    const scopedHints =
      compatiblePortFocus?.nodeId === selectedNode.id
        ? hints.filter((hint) =>
            compatiblePortFocus.direction === "downstream"
              ? hint.direction === "downstream" &&
                hint.sourcePort.id === compatiblePortFocus.portId
              : hint.direction === "attachment" &&
                hint.targetPort.id === compatiblePortFocus.portId,
          )
        : hints;
    return scopedHints.sort((left, right) => {
      if (left.direction !== right.direction)
        return left.direction === "attachment" ? -1 : 1;
      if (left.recommended !== right.recommended)
        return left.recommended ? -1 : 1;
      return (
        left.definition.group.localeCompare(right.definition.group) ||
        left.definition.label.localeCompare(right.definition.label)
      );
    });
  }, [compatiblePortFocus, selectedNode, selectedOutputClasses]);
  const compatiblePortFocusLabel = useMemo(() => {
    if (!selectedNode || compatiblePortFocus?.nodeId !== selectedNode.id)
      return null;
    const port = (selectedNode.ports ?? []).find(
      (candidate) => candidate.id === compatiblePortFocus.portId,
    );
    if (!port) return null;
    return `${selectedNode.name} · ${port.label}`;
  }, [compatiblePortFocus, selectedNode]);
  const compatibleCreatorIds = useMemo(
    () =>
      new Set(
        compatibleNodeHints.map((hint) =>
          workflowCreatorItemId(hint.definition),
        ),
      ),
    [compatibleNodeHints],
  );
  const searchedCreatorIds = useMemo(
    () => new Set(searchedNodeLibrary.map(workflowCreatorItemId)),
    [searchedNodeLibrary],
  );
  const filteredNodeLibrary = useMemo(
    () =>
      searchedNodeLibrary.filter((item) => {
        if (nodeGroupFilter === "All") return true;
        if (nodeGroupFilter === "Compatible")
          return compatibleCreatorIds.has(workflowCreatorItemId(item));
        return item.group === nodeGroupFilter;
      }),
    [compatibleCreatorIds, nodeGroupFilter, searchedNodeLibrary],
  );
  const visibleCompatibleNodeHints = useMemo(
    () =>
      compatibleNodeHints.filter((hint) => {
        const itemId = workflowCreatorItemId(hint.definition);
        if (!searchedCreatorIds.has(itemId)) return false;
        if (nodeGroupFilter === "All" || nodeGroupFilter === "Compatible")
          return true;
        return hint.definition.group === nodeGroupFilter;
      }),
    [compatibleNodeHints, nodeGroupFilter, searchedCreatorIds],
  );
  const recentNodeLibrary = useMemo(
    () =>
      recentNodeTypes
        .map((creatorId) =>
          filteredNodeLibrary.find(
            (item) => workflowCreatorItemId(item) === creatorId,
          ),
        )
        .filter((item): item is WorkflowNodeCreatorDefinition => Boolean(item)),
    [filteredNodeLibrary, recentNodeTypes],
  );
  const nodeGroupCounts = useMemo(() => {
    const counts = new Map<WorkflowNodeGroupFilter, number>();
    counts.set("All", searchedNodeLibrary.length);
    counts.set(
      "Compatible",
      searchedNodeLibrary.filter((item) =>
        compatibleCreatorIds.has(workflowCreatorItemId(item)),
      ).length,
    );
    for (const group of SCAFFOLD_GROUPS) {
      counts.set(
        group,
        searchedNodeLibrary.filter((item) => item.group === group).length,
      );
    }
    return counts;
  }, [compatibleCreatorIds, searchedNodeLibrary]);
  const emptyCanvasStartItems = useMemo(
    () =>
      EMPTY_CANVAS_START_CREATOR_IDS.map((creatorId) =>
        NODE_LIBRARY.find((item) => workflowCreatorItemId(item) === creatorId),
      ).filter((item): item is WorkflowNodeCreatorDefinition => Boolean(item)),
    [],
  );
  const selectedUpstreamReferences = useMemo<
    WorkflowUpstreamReference[]
  >(() => {
    if (!selectedNode) return [];
    return edges
      .filter((edge) => edge.target === selectedNode.id)
      .map((edge) => {
        const source = nodes.find((flowNode) => flowNode.id === edge.source);
        const sourceData = source?.data as Node | undefined;
        if (!sourceData) return null;
        const portId = edge.sourceHandle ?? "output";
        const sourcePort = sourceData.ports?.find(
          (port) => port.id === portId && port.direction === "output",
        );
        const latestOutput = nodeRunStatusById[sourceData.id]?.output;
        return {
          nodeId: sourceData.id,
          nodeName: sourceData.name,
          nodeType: sourceData.type,
          portId,
          connectionClass:
            sourcePort?.connectionClass ??
            (edge.data?.connectionClass as
              | WorkflowConnectionClass
              | undefined) ??
            "data",
          expression: `{{nodes.${sourceData.id}.${portId}}}`,
          schema: workflowNodeDeclaredOutputSchema(sourceData, latestOutput),
          latestOutput,
        };
      })
      .filter((item): item is WorkflowUpstreamReference => Boolean(item));
  }, [edges, nodeRunStatusById, nodes, selectedNode]);
  const selectedFixtures = useMemo(
    () => workflowFixturesForNode(selectedNode, nodeFixturesById),
    [nodeFixturesById, selectedNode],
  );
  const canvasSearchResults = useMemo(() => {
    return workflowCanvasSearchResults(
      nodes,
      nodeRunStatusById,
      canvasSearchQuery,
    );
  }, [canvasSearchQuery, nodeRunStatusById, nodes]);
  const counts = nodeFamilyCounts(nodes);
  const missingReasoningBinding = useMemo(
    () =>
      nodes.some((flowNode) => {
        const nodeItem = flowNode.data as Node | undefined;
        if (!nodeItem || nodeItem.type !== "model_call") return false;
        const logic = nodeItem.config?.logic ?? {};
        const modelRef = String(logic.modelRef ?? "reasoning");
        const hasInlineBinding = Boolean(logic.modelBinding?.modelRef);
        const hasGlobalBinding = Boolean(
          globalConfig.modelBindings[modelRef]?.modelId,
        );
        const hasAttachedModelBinding = edges.some((edge) => {
          if (edge.target !== nodeItem.id) return false;
          const connectionClass =
            (edge.data?.connectionClass as
              | WorkflowConnectionClass
              | undefined) ??
            (
              edge.data as
                | { connectionClass?: WorkflowConnectionClass }
                | undefined
            )?.connectionClass;
          return edge.targetHandle === "model" || connectionClass === "model";
        });
        return (
          !hasInlineBinding && !hasGlobalBinding && !hasAttachedModelBinding
        );
      }),
    [edges, globalConfig.modelBindings, nodes],
  );
  const canvasIssuesByNodeId = useMemo(
    () => workflowCanvasIssuesByNodeId(validationResult, readinessResult),
    [readinessResult, validationResult],
  );
  const canvasEdgeIssues = useMemo(() => {
    const nodeById = new Map(nodes.map((flowNode) => [flowNode.id, flowNode]));
    const issueByEdge = new Map<
      string,
      Pick<WorkflowValidationIssue, "code" | "message">
    >();
    edges.forEach((edge) => {
      const sourceNode = nodeById.get(edge.source);
      const targetNode = nodeById.get(edge.target);
      if (!sourceNode || !targetNode) {
        issueByEdge.set(edge.id, {
          code: "missing_edge_endpoint",
          message: "This connection references a missing node.",
        });
        return;
      }
      const sourceData = sourceNode.data as Node | undefined;
      const targetData = targetNode.data as Node | undefined;
      const sourceType = String(sourceData?.type ?? sourceNode.type ?? "");
      const targetType = String(targetData?.type ?? targetNode.type ?? "");
      const sourcePort = sourceData?.ports?.find(
        (port) =>
          port.direction === "output" &&
          port.id === (edge.sourceHandle || "output"),
      );
      const targetPort = targetData?.ports?.find(
        (port) =>
          port.direction === "input" &&
          port.id === (edge.targetHandle || "input"),
      );
      const edgeIssue = validateActionEdge(
        edge.source,
        actionKindForWorkflowNodeType(sourceType),
        edge.target,
        actionKindForWorkflowNodeType(targetType),
        sourcePort ?? null,
        targetPort ?? null,
      );
      if (edgeIssue) {
        issueByEdge.set(edge.id, edgeIssue);
      }
    });
    return issueByEdge;
  }, [edges, nodes]);
  const handleShowCompatibleNodesForPort = useCallback(
    (request: {
      nodeId: string;
      portId: string;
      direction: "downstream" | "attachment";
    }) => {
      const nodeItem = nodes.find((flowNode) => flowNode.id === request.nodeId)
        ?.data as Node | undefined;
      const port = (nodeItem?.ports ?? []).find(
        (candidate) => candidate.id === request.portId,
      );
      handleNodeSelect(request.nodeId);
      setCompatiblePortFocus(request);
      setNodeGroupFilter("Compatible");
      setNodeSearch("");
      openLeftDrawer();
      setStatusMessage(
        port
          ? `Showing compatible nodes for ${nodeItem?.name ?? request.nodeId} · ${port.label}`
          : `Showing compatible nodes for ${nodeItem?.name ?? request.nodeId}`,
      );
    },
    [handleNodeSelect, nodes, openLeftDrawer],
  );
  const loadWorkflowProject = useCallback(
    (next: WorkflowProject) => {
      setWorkflow(next);
      setGlobalConfig(normalizeGlobalConfig(next.global_config));
      setCollapsedHarnessGroupIds({});
      setSelectedHarnessGroupId(null);
      setSelectedHarnessReceiptRef(null);
      setSelectedHarnessReplayFixtureRef(null);
      setSelectedHarnessRollbackTarget(null);
      setSelectedHarnessSelectorDecisionId(null);
      setSelectedHarnessDefaultDispatchId(null);
      setSelectedHarnessWorkerBindingId(null);
      setSelectedHarnessNodeAttemptId(null);
      setSelectedHarnessRevisionBindingKind(null);
      setSelectedHarnessRevisionBindingRef(null);
      setSelectedHarnessActivationBlockerIndex(null);
      setSelectedHarnessActivationBlockerRef(null);
      setSelectedHarnessActivationAuditEventId(null);
      setSelectedHarnessActivationGateId(null);
      setSelectedHarnessActivationGateEvidenceRef(null);
      setSelectedHarnessActivationGateNodeAttemptId(null);
      setSelectedHarnessActivationGateReceiptRef(null);
      setSelectedHarnessActivationGateReplayFixtureRef(null);
      setHarnessActivationCandidate(null);
      setPackageImportReview(null);
      restoredHarnessDeepLinkWorkflowRef.current = null;
      replaceGraph(next);
      requestAnimationFrame(() => fitView({ padding: 0.22 }));
    },
    [fitView, replaceGraph],
  );

  useEffect(() => {
    if (!initialFile) return;
    const next = {
      ...makeDefaultWorkflow(
        initialFile.global_config?.meta?.name || "Generated workflow",
      ),
      ...initialFile,
      metadata: initialFile.metadata ?? makeDefaultWorkflow().metadata,
      global_config: normalizeGlobalConfig(initialFile.global_config),
    } as WorkflowProject;
    loadWorkflowProject(next);
    onInitialFileLoaded?.();
  }, [initialFile, loadWorkflowProject, onInitialFileLoaded]);

  const currentProjectFile = useMemo(
    () => toWorkflowProject(nodes, edges, globalConfig, workflow),
    [nodes, edges, globalConfig, workflow],
  );
  const isReadOnlyWorkflow = currentProjectFile.metadata.readOnly === true;
  const isHarnessWorkflow = workflowIsHarness(currentProjectFile);
  const isBlessedHarnessWorkflow = workflowIsBlessedHarness(currentProjectFile);
  const harnessWorkerBinding = isHarnessWorkflow
    ? workflowHarnessWorkerBinding(currentProjectFile)
    : null;
  const handleToggleHarnessGroup = useCallback(
    (groupId: string) => {
      setCollapsedHarnessGroupIds((current) => {
        const currentlyCollapsed = current[groupId] ?? true;
        const nextCollapsed = !currentlyCollapsed;
        setStatusMessage(
          `${nextCollapsed ? "Collapsed" : "Expanded"} harness group ${groupId}`,
        );
        return { ...current, [groupId]: nextCollapsed };
      });
      requestAnimationFrame(() => fitView({ padding: 0.2 }));
    },
    [fitView],
  );
  const handleExpandHarnessGroup = useCallback(
    (groupId: string) => {
      setCollapsedHarnessGroupIds((current) => ({
        ...current,
        [groupId]: false,
      }));
      setStatusMessage(`Expanded harness group ${groupId}`);
      requestAnimationFrame(() => fitView({ padding: 0.2 }));
    },
    [fitView],
  );
  const handleCollapseHarnessGroups = useCallback(() => {
    const groupIds =
      currentProjectFile.metadata.harness?.promotionClusters?.map(
        (cluster) => cluster.clusterId,
      ) ?? [];
    setCollapsedHarnessGroupIds(
      Object.fromEntries(groupIds.map((groupId) => [groupId, true])),
    );
    setStatusMessage("Collapsed harness promotion groups");
    requestAnimationFrame(() => fitView({ padding: 0.2 }));
  }, [currentProjectFile.metadata.harness?.promotionClusters, fitView]);
  const handleExpandHarnessGroups = useCallback(() => {
    const groupIds =
      currentProjectFile.metadata.harness?.promotionClusters?.map(
        (cluster) => cluster.clusterId,
      ) ?? [];
    setCollapsedHarnessGroupIds(
      Object.fromEntries(groupIds.map((groupId) => [groupId, false])),
    );
    setStatusMessage("Expanded harness promotion groups");
    requestAnimationFrame(() => fitView({ padding: 0.2 }));
  }, [currentProjectFile.metadata.harness?.promotionClusters, fitView]);
  const harnessGroupViews = useMemo<HarnessGroupCanvasView[]>(() => {
    const harness = currentProjectFile.metadata.harness;
    const clusters = harness?.promotionClusters ?? [];
    if (!isHarnessWorkflow || clusters.length === 0) return [];

    const nodesByComponentKind = new Map<
      WorkflowHarnessComponentKind,
      { flowNode: ReactFlowNode; nodeData: Node }
    >();
    nodes.forEach((flowNode) => {
      const nodeData = flowNode.data as Node | undefined;
      if (!nodeData) return;
      const kind = harnessComponentKindForNode(nodeData);
      if (kind && !nodesByComponentKind.has(kind)) {
        nodesByComponentKind.set(kind, { flowNode, nodeData });
      }
    });

    const attemptsByNodeId = new Map(
      (lastRunResult?.harnessAttempts ?? []).map((attempt) => [
        attempt.workflowNodeId,
        attempt,
      ]),
    );
    const comparisonsByNodeId = new Map(
      (lastRunResult?.harnessShadowComparisons ?? []).map((comparison) => [
        comparison.workflowNodeId,
        comparison,
      ]),
    );
    const gatedRunsByClusterId = new Map(
      (lastRunResult?.harnessGatedClusterRuns ?? []).map((run) => [
        run.clusterId,
        run,
      ]),
    );

    return clusters.flatMap((cluster) => {
      const inner = cluster.componentKinds
        .map((kind) => nodesByComponentKind.get(kind))
        .filter((item): item is { flowNode: ReactFlowNode; nodeData: Node } =>
          Boolean(item),
        );
      if (inner.length === 0) return [];

      const minX = Math.min(...inner.map((item) => item.flowNode.position.x));
      const minY = Math.min(...inner.map((item) => item.flowNode.position.y));
      const componentIds = inner.map(
        (item) => item.nodeData.runtimeBinding?.componentId ?? item.nodeData.id,
      );
      const readinessValues = inner.map(
        (item) =>
          item.nodeData.runtimeBinding?.readiness ??
          (item.nodeData.runtimeBinding?.componentId
            ? harness?.componentReadiness?.[
                item.nodeData.runtimeBinding.componentId
              ]
            : undefined) ??
          "projection_only",
      );
      const firstReadiness = readinessValues[0] ?? "projection_only";
      const readiness = readinessValues.every(
        (value) => value === firstReadiness,
      )
        ? firstReadiness
        : "mixed";
      const replayGateProof = cluster.replayGateProof;
      const attempts = inner
        .map((item) => attemptsByNodeId.get(item.nodeData.id))
        .filter((attempt): attempt is NonNullable<typeof attempt> =>
          Boolean(attempt),
        );
      const comparisons = inner
        .map((item) => comparisonsByNodeId.get(item.nodeData.id))
        .filter((comparison): comparison is NonNullable<typeof comparison> =>
          Boolean(comparison),
        );
      const gatedRun = gatedRunsByClusterId.get(cluster.clusterId);
      const receiptRefs = Array.from(
        new Set([
          ...inner.flatMap(
            (item) => item.nodeData.runtimeBinding?.receiptKinds ?? [],
          ),
          ...attempts.flatMap((attempt) => attempt.receiptIds),
        ]),
      );
      const replayFixtureRefs = Array.from(
        new Set([
          ...attempts.flatMap((attempt) =>
            attempt.evidenceRefs.filter((ref) => ref.includes("replay")),
          ),
          ...inner.map((item) => {
            const envelope = item.nodeData.runtimeBinding?.replayEnvelope;
            const determinism = envelope?.determinism ?? "unknown";
            return `replay:${item.nodeData.id}:${determinism}`;
          }),
        ]),
      );
      const divergenceCount = comparisons.filter(
        (comparison) => comparison.blocking || comparison.divergence !== "none",
      ).length;
      const blockedCount =
        (gatedRun?.promotionBlocked ? 1 : 0) +
        comparisons.filter((comparison) => comparison.blocking).length;
      const nonLiveReadyCount = readinessValues.filter(
        (value) => value !== "live_ready",
      ).length;
      const group: HarnessGroupCanvasView = {
        groupId: cluster.clusterId,
        groupNodeId: harnessGroupNodeId(cluster.clusterId),
        label: cluster.label,
        collapsed: collapsedHarnessGroupIds[cluster.clusterId] ?? true,
        innerNodeIds: inner.map((item) => item.nodeData.id),
        componentKinds: cluster.componentKinds,
        boundaryPorts: HARNESS_GROUP_BOUNDARY_PORTS,
        position: {
          x: Math.max(40, minX - 24),
          y: Math.max(40, minY - 32),
        },
        statusRollup: {
          executionMode:
            harness?.executionMode ?? cluster.requiredExecutionMode,
          readiness,
          liveReadyCount: readinessValues.filter(
            (value) => value === "live_ready",
          ).length,
          shadowReadyCount: readinessValues.filter(
            (value) => value === "shadow_ready",
          ).length,
          simulatedCount: readinessValues.filter(
            (value) => value === "simulated",
          ).length,
          projectionOnlyCount: readinessValues.filter(
            (value) => value === "projection_only",
          ).length,
          blockedCount,
          warningCount: nonLiveReadyCount + divergenceCount,
          receiptKindCount: receiptRefs.length,
          replayFixtureCount: replayFixtureRefs.length,
          replayGateStatus: replayGateProof?.gateStatus ?? "not_run",
          replayGateImpact: replayGateProof?.activationGateImpact ?? "pending",
          replayGateTotalFixtures: replayGateProof?.totalFixtures ?? 0,
          replayGateBlockingFixtureCount:
            replayGateProof?.blockingReplayFixtureRefs.length ?? 0,
          replayGateId: replayGateProof?.gateId,
          divergenceCount,
          activationState: harness?.activationState,
        },
        deepLinks: {
          groupId: cluster.clusterId,
          componentIds,
          receiptRefs,
          replayFixtureRefs,
          runId: lastRunResult?.summary.id,
        },
      };
      return [group];
    });
  }, [
    collapsedHarnessGroupIds,
    currentProjectFile.metadata.harness,
    isHarnessWorkflow,
    lastRunResult,
    nodes,
  ]);
  const collapsedHarnessGroupByNodeId = useMemo(() => {
    const groupByNodeId = new Map<string, HarnessGroupCanvasView>();
    harnessGroupViews.forEach((group) => {
      if (!group.collapsed) return;
      group.innerNodeIds.forEach((nodeId) => groupByNodeId.set(nodeId, group));
    });
    return groupByNodeId;
  }, [harnessGroupViews]);
  const harnessGroupSummary = useMemo(
    () => ({
      total: harnessGroupViews.length,
      collapsed: harnessGroupViews.filter((group) => group.collapsed).length,
      expanded: harnessGroupViews.filter((group) => !group.collapsed).length,
    }),
    [harnessGroupViews],
  );
  const selectedHarnessGroup = useMemo(
    () =>
      selectedHarnessGroupId
        ? (harnessGroupViews.find(
            (group) => String(group.groupId) === selectedHarnessGroupId,
          ) ?? null)
        : null,
    [harnessGroupViews, selectedHarnessGroupId],
  );
  const selectedHarnessComponentId = useMemo(() => {
    if (!isHarnessWorkflow || !selectedNode) return null;
    if (
      !selectedNode.runtimeBinding &&
      !harnessComponentKindForNode(selectedNode)
    ) {
      return null;
    }
    return selectedNode.runtimeBinding?.componentId ?? selectedNode.id;
  }, [isHarnessWorkflow, selectedNode]);
  const harnessWorkbenchDeepLink =
    useMemo<HarnessWorkbenchDeepLink | null>(() => {
      if (!isHarnessWorkflow) return null;
      const groupId = selectedHarnessGroup
        ? String(selectedHarnessGroup.groupId)
        : undefined;
      const componentId = selectedHarnessComponentId ?? undefined;
      const runId =
        selectedRunId ??
        selectedHarnessGroup?.deepLinks.runId ??
        lastRunResult?.summary.id;
      const hasDeepLinkScope =
        groupId ||
        componentId ||
        runId ||
        selectedHarnessSelectorDecisionId ||
        selectedHarnessDefaultDispatchId ||
        selectedHarnessWorkerBindingId ||
        selectedHarnessNodeAttemptId ||
        selectedHarnessReceiptRef ||
        selectedHarnessReplayFixtureRef ||
        selectedHarnessRollbackTarget ||
        selectedHarnessRevisionBindingKind ||
        selectedHarnessRevisionBindingRef ||
        selectedHarnessActivationBlockerIndex ||
        selectedHarnessActivationBlockerRef ||
        selectedHarnessActivationAuditEventId ||
        selectedHarnessActivationGateId ||
        selectedHarnessActivationGateEvidenceRef ||
        selectedHarnessActivationGateNodeAttemptId ||
        selectedHarnessActivationGateReceiptRef ||
        selectedHarnessActivationGateReplayFixtureRef;
      if (!hasDeepLinkScope) return null;
      return {
        panel: rightPanel,
        groupId,
        componentId,
        runId,
        selectorDecisionId: selectedHarnessSelectorDecisionId ?? undefined,
        dispatchId: selectedHarnessDefaultDispatchId ?? undefined,
        workerBindingId: selectedHarnessWorkerBindingId ?? undefined,
        nodeAttemptId: selectedHarnessNodeAttemptId ?? undefined,
        receiptRef: selectedHarnessReceiptRef ?? undefined,
        replayFixtureRef: selectedHarnessReplayFixtureRef ?? undefined,
        rollbackTarget: selectedHarnessRollbackTarget ?? undefined,
        revisionBindingKind: selectedHarnessRevisionBindingKind ?? undefined,
        revisionBindingRef: selectedHarnessRevisionBindingRef ?? undefined,
        activationBlockerIndex:
          selectedHarnessActivationBlockerIndex ?? undefined,
        activationBlockerRef: selectedHarnessActivationBlockerRef ?? undefined,
        activationAuditEventId:
          selectedHarnessActivationAuditEventId ?? undefined,
        activationGateId: selectedHarnessActivationGateId ?? undefined,
        activationGateEvidenceRef:
          selectedHarnessActivationGateEvidenceRef ?? undefined,
        activationGateNodeAttemptId:
          selectedHarnessActivationGateNodeAttemptId ?? undefined,
        activationGateReceiptRef:
          selectedHarnessActivationGateReceiptRef ?? undefined,
        activationGateReplayFixtureRef:
          selectedHarnessActivationGateReplayFixtureRef ?? undefined,
      };
    }, [
      isHarnessWorkflow,
      lastRunResult?.summary.id,
      rightPanel,
      selectedHarnessDefaultDispatchId,
      selectedHarnessComponentId,
      selectedHarnessGroup,
      selectedHarnessNodeAttemptId,
      selectedHarnessReceiptRef,
      selectedHarnessReplayFixtureRef,
      selectedHarnessRollbackTarget,
      selectedHarnessActivationBlockerIndex,
      selectedHarnessActivationBlockerRef,
      selectedHarnessActivationAuditEventId,
      selectedHarnessActivationGateId,
      selectedHarnessActivationGateEvidenceRef,
      selectedHarnessActivationGateNodeAttemptId,
      selectedHarnessActivationGateReceiptRef,
      selectedHarnessActivationGateReplayFixtureRef,
      selectedHarnessRevisionBindingKind,
      selectedHarnessRevisionBindingRef,
      selectedHarnessSelectorDecisionId,
      selectedHarnessWorkerBindingId,
      selectedRunId,
    ]);
  const harnessWorkbenchDeepLinkHash = useMemo(
    () =>
      harnessWorkbenchDeepLink
        ? encodeHarnessWorkbenchDeepLink(harnessWorkbenchDeepLink)
        : null,
    [harnessWorkbenchDeepLink],
  );
  const harnessWorkbenchDeepLinkUrl = useMemo(
    () =>
      harnessWorkbenchDeepLinkHash
        ? harnessWorkbenchDeepLinkHref(harnessWorkbenchDeepLinkHash)
        : null,
    [harnessWorkbenchDeepLinkHash],
  );
  const applyHarnessWorkbenchDeepLink = useCallback(
    (link: HarnessWorkbenchDeepLink) => {
      if (link.panel) {
        setRightPanel(link.panel);
      }
      if (link.runId) {
        setSelectedRunId(link.runId);
      }
      setSelectedHarnessReceiptRef(link.receiptRef ?? null);
      setSelectedHarnessReplayFixtureRef(link.replayFixtureRef ?? null);
      setSelectedHarnessRollbackTarget(link.rollbackTarget ?? null);
      setSelectedHarnessSelectorDecisionId(link.selectorDecisionId ?? null);
      setSelectedHarnessDefaultDispatchId(link.dispatchId ?? null);
      setSelectedHarnessWorkerBindingId(link.workerBindingId ?? null);
      setSelectedHarnessNodeAttemptId(link.nodeAttemptId ?? null);
      setSelectedHarnessRevisionBindingKind(link.revisionBindingKind ?? null);
      setSelectedHarnessRevisionBindingRef(link.revisionBindingRef ?? null);
      setSelectedHarnessActivationBlockerIndex(
        link.activationBlockerIndex ?? null,
      );
      setSelectedHarnessActivationBlockerRef(link.activationBlockerRef ?? null);
      setSelectedHarnessActivationAuditEventId(
        link.activationAuditEventId ?? null,
      );
      setSelectedHarnessActivationGateId(link.activationGateId ?? null);
      setSelectedHarnessActivationGateEvidenceRef(
        link.activationGateEvidenceRef ?? null,
      );
      setSelectedHarnessActivationGateNodeAttemptId(
        link.activationGateNodeAttemptId ?? null,
      );
      setSelectedHarnessActivationGateReceiptRef(
        link.activationGateReceiptRef ?? null,
      );
      setSelectedHarnessActivationGateReplayFixtureRef(
        link.activationGateReplayFixtureRef ?? null,
      );

      const componentNode = link.componentId
        ? nodes.find((flowNode) => {
            const nodeItem = flowNode.data as Node | undefined;
            if (!nodeItem) return false;
            return (
              nodeItem.id === link.componentId ||
              nodeItem.runtimeBinding?.componentId === link.componentId ||
              harnessComponentKindForNode(nodeItem) === link.componentId
            );
          })
        : null;
      const componentNodeData = componentNode?.data as Node | undefined;
      if (componentNodeData) {
        const parentGroup = harnessGroupViews.find((group) =>
          group.innerNodeIds.includes(componentNodeData.id),
        );
        if (parentGroup) {
          setCollapsedHarnessGroupIds((current) => ({
            ...current,
            [String(parentGroup.groupId)]: false,
          }));
        }
        setSelectedHarnessGroupId(null);
        handleNodeSelect(componentNodeData.id);
        setRightPanel(link.panel ?? "outputs");
        setBottomPanel("selection");
        setActiveTab("graph");
        setStatusMessage(`Opened harness component ${link.componentId}`);
        requestAnimationFrame(() => fitView({ padding: 0.2 }));
        return;
      }

      const group = link.groupId
        ? harnessGroupViews.find(
            (candidate) => String(candidate.groupId) === link.groupId,
          )
        : null;
      if (group) {
        setSelectedHarnessGroupId(String(group.groupId));
        handleNodeSelect(null);
        setRightPanel(link.panel ?? "outputs");
        setBottomPanel("selection");
        setActiveTab("graph");
        setStatusMessage(`Restored harness group ${group.groupId}`);
        return;
      }

      const activeBindingTarget =
        link.selectorDecisionId ??
        link.dispatchId ??
        link.workerBindingId ??
        link.nodeAttemptId ??
        link.rollbackTarget ??
        link.receiptRef ??
        link.replayFixtureRef ??
        link.revisionBindingRef ??
        link.revisionBindingKind ??
        link.activationBlockerRef ??
        link.activationBlockerIndex ??
        link.activationAuditEventId ??
        link.activationGateId ??
        link.activationGateEvidenceRef ??
        link.activationGateNodeAttemptId ??
        link.activationGateReceiptRef ??
        link.activationGateReplayFixtureRef ??
        null;
      if (activeBindingTarget) {
        setSelectedHarnessGroupId(null);
        handleNodeSelect(null);
        setRightPanel(
          link.panel ??
            (link.receiptRef || link.replayFixtureRef ? "outputs" : "settings"),
        );
        setBottomPanel("selection");
        setActiveTab("graph");
        setStatusMessage(`Restored harness target ${activeBindingTarget}`);
      }
    },
    [fitView, handleNodeSelect, harnessGroupViews, nodes],
  );
  useEffect(() => {
    if (!isHarnessWorkflow || harnessGroupViews.length === 0) return;
    const workflowKey =
      currentProjectFile.metadata.slug ??
      currentProjectFile.metadata.name ??
      workflowPath;
    if (restoredHarnessDeepLinkWorkflowRef.current === workflowKey) return;
    restoredHarnessDeepLinkWorkflowRef.current = workflowKey;
    const link = readHarnessWorkbenchDeepLink();
    if (link) {
      applyHarnessWorkbenchDeepLink(link);
    }
  }, [
    applyHarnessWorkbenchDeepLink,
    currentProjectFile.metadata.name,
    currentProjectFile.metadata.slug,
    harnessGroupViews.length,
    isHarnessWorkflow,
    workflowPath,
  ]);
  useEffect(() => {
    if (harnessWorkbenchDeepLinkHash) {
      writeHarnessWorkbenchDeepLink(harnessWorkbenchDeepLinkHash);
    }
  }, [harnessWorkbenchDeepLinkHash]);
  const runHarnessDeepLinkReplayProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessDeepLinkReplayProof> => {
      const replayCases = harnessDeepLinkProbeCasesForWorkflow(workflow);
      const cases = [];
      for (const replayCase of replayCases) {
        const hash = encodeHarnessWorkbenchDeepLink(replayCase.link);
        const parsed = parseHarnessWorkbenchDeepLink(hash);
        if (parsed) {
          writeHarnessWorkbenchDeepLink(hash);
          applyHarnessWorkbenchDeepLink(parsed);
        }
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
        const observedSelectedState = readHarnessRailSelectedState(
          replayCase.selectedRailTestId,
        );
        const observedValue =
          observedSelectedState[replayCase.expectedAttribute] ?? null;
        cases.push({
          id: replayCase.id,
          hash,
          expectedPanel: replayCase.link.panel ?? "outputs",
          expectedAttribute: replayCase.expectedAttribute,
          expectedValue: replayCase.expectedValue,
          selectedRailTestId: replayCase.selectedRailTestId,
          openedHash: typeof window === "undefined" ? "" : window.location.hash,
          parsedMatches:
            parsed?.[
              replayCase.expectedParsedKey ??
                (Object.keys(replayCase.link).find(
                  (key) => key !== "panel",
                ) as keyof HarnessWorkbenchDeepLink)
            ] === replayCase.expectedValue,
          historyMatches:
            typeof window !== "undefined" && window.location.hash === hash,
          observedValue,
          observedSelectedState,
          passed:
            Boolean(parsed) &&
            observedValue === replayCase.expectedValue &&
            (typeof window === "undefined" || window.location.hash === hash),
        });
      }
      const requiredCaseIds = [
        "selector",
        "dispatch",
        "worker",
        "rollback",
        "receipt",
        "replay",
        "revision",
        "activation-audit",
      ];
      const presentCaseIds = new Set(cases.map((replayCase) => replayCase.id));
      const blockers = [
        ...requiredCaseIds
          .filter((caseId) => !presentCaseIds.has(caseId))
          .map((caseId) => `missing_${caseId}_deep_link_replay`),
        ...cases
          .filter((replayCase) => !replayCase.passed)
          .map((replayCase) => `${replayCase.id}_deep_link_replay_failed`),
      ];
      return {
        schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
        method:
          "same-session Workflows bridge writes each harness hash, parses it, applies workbench state, waits for the rail, and reads data-selected attributes",
        generatedAtMs,
        cases,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessLiveTurnNodeInspectorDeepLinkProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessDeepLinkReplayProof> => {
      const attempt = harnessLiveTurnNodeInspectorAttemptForWorkflow(workflow);
      if (!attempt) {
        return {
          schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
          method:
            "same-session Workflows bridge opens a live default dispatch node attempt deep link and reads the node-attempt inspector rail",
          generatedAtMs,
          cases: [],
          passed: false,
          blockers: ["missing_live_turn_node_inspector_attempt"],
        };
      }
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const receiptRef = attempt.receiptIds[0] ?? null;
      const replayFixtureRef = attempt.replay.fixtureRef ?? null;
      const link: HarnessWorkbenchDeepLink = {
        panel: "outputs" as WorkflowRightPanel,
        nodeAttemptId: attempt.attemptId,
        receiptRef: receiptRef ?? undefined,
        replayFixtureRef: replayFixtureRef ?? undefined,
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      let observedSelectedState: Record<string, string> = {};
      let openedHash = "";
      try {
        if (parsed) {
          writeHarnessWorkbenchDeepLink(hash);
          applyHarnessWorkbenchDeepLink(parsed);
        }
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
        openedHash =
          typeof window === "undefined" ? hash : window.location.hash;
        observedSelectedState = readHarnessRailSelectedState(
          "workflow-harness-node-attempt-inspector",
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      const receiptRefs = String(
        observedSelectedState["data-receipt-refs"] ?? "",
      )
        .split(/[|,]/)
        .map((value) => value.trim())
        .filter(Boolean);
      const requiredAttributeChecks = [
        [
          "data-node-attempt-id",
          attempt.attemptId,
          observedSelectedState["data-node-attempt-id"],
        ],
        [
          "data-workflow-node-id",
          attempt.workflowNodeId,
          observedSelectedState["data-workflow-node-id"],
        ],
        [
          "data-component-kind",
          attempt.componentKind,
          observedSelectedState["data-component-kind"],
        ],
        [
          "data-component-id",
          attempt.componentId,
          observedSelectedState["data-component-id"],
        ],
        [
          "data-harness-workflow-id",
          attempt.harnessWorkflowId,
          observedSelectedState["data-harness-workflow-id"],
        ],
        [
          "data-harness-activation-id",
          attempt.harnessActivationId,
          observedSelectedState["data-harness-activation-id"],
        ],
        [
          "data-harness-hash",
          attempt.harnessHash,
          observedSelectedState["data-harness-hash"],
        ],
        [
          "data-execution-mode",
          attempt.executionMode,
          observedSelectedState["data-execution-mode"],
        ],
        [
          "data-readiness",
          attempt.readiness,
          observedSelectedState["data-readiness"],
        ],
        [
          "data-status",
          attempt.status,
          observedSelectedState["data-status"],
        ],
        [
          "data-policy-decision",
          attempt.policyDecision ?? "",
          observedSelectedState["data-policy-decision"],
        ],
        [
          "data-replay-fixture-ref",
          replayFixtureRef ?? "",
          observedSelectedState["data-replay-fixture-ref"],
        ],
        [
          "data-input-hash",
          attempt.inputHash ?? "",
          observedSelectedState["data-input-hash"],
        ],
        [
          "data-output-hash",
          attempt.outputHash ?? "",
          observedSelectedState["data-output-hash"],
        ],
      ] as const;
      const attributeBlockers = requiredAttributeChecks
        .filter(([, expected, observed]) => observed !== expected)
        .map(([attribute]) => `${attribute}_mismatch`);
      const blockers = [
        ...(parsed ? [] : ["live_turn_node_inspector_hash_parse_failed"]),
        ...(parsed?.nodeAttemptId === attempt.attemptId
          ? []
          : ["live_turn_node_inspector_node_attempt_parse_mismatch"]),
        ...(openedHash === hash
          ? []
          : ["live_turn_node_inspector_history_mismatch"]),
        ...(receiptRef && receiptRefs.includes(receiptRef)
          ? []
          : ["live_turn_node_inspector_receipt_refs_mismatch"]),
        ...attributeBlockers,
      ];
      const observedValue =
        observedSelectedState["data-node-attempt-id"] ?? null;
      const casePassed =
        blockers.length === 0 &&
        observedValue === attempt.attemptId &&
        Boolean(parsed) &&
        parsed?.nodeAttemptId === attempt.attemptId;
      return {
        schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
        method:
          "same-session Workflows bridge opens a live default dispatch node attempt deep link and reads the node-attempt inspector rail",
        generatedAtMs,
        cases: [
          {
            id: "live-turn-node-inspector",
            hash,
            expectedPanel: "outputs",
            expectedAttribute: "data-node-attempt-id",
            expectedValue: attempt.attemptId,
            selectedRailTestId: "workflow-harness-node-attempt-inspector",
            openedHash,
            parsedMatches: parsed?.nodeAttemptId === attempt.attemptId,
            historyMatches: openedHash === hash,
            observedValue,
            observedSelectedState,
            passed: casePassed,
          },
        ],
        passed: casePassed,
        blockers: casePassed ? [] : blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessLiveShadowComparisonDeepLinkProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessDeepLinkReplayProof> => {
      const comparisonBundle = harnessLiveShadowComparisonForWorkflow(workflow);
      if (!comparisonBundle) {
        return {
          schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
          method:
            "same-session Workflows bridge opens a live-vs-shadow comparison through the node-attempt inspector rail",
          generatedAtMs,
          cases: [],
          passed: false,
          blockers: ["missing_live_shadow_comparison"],
        };
      }
      const { comparison, liveAttempt, shadowAttempt } = comparisonBundle;
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const receiptRef = liveAttempt.receiptIds[0] ?? null;
      const replayFixtureRef = liveAttempt.replay.fixtureRef ?? null;
      const link: HarnessWorkbenchDeepLink = {
        panel: "outputs" as WorkflowRightPanel,
        nodeAttemptId: comparison.liveAttemptId,
        receiptRef: receiptRef ?? undefined,
        replayFixtureRef: replayFixtureRef ?? undefined,
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      let observedSelectedState: Record<string, string> = {};
      let openedHash = "";
      try {
        if (parsed) {
          writeHarnessWorkbenchDeepLink(hash);
          applyHarnessWorkbenchDeepLink(parsed);
        }
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
        openedHash =
          typeof window === "undefined" ? hash : window.location.hash;
        observedSelectedState = readHarnessRailSelectedState(
          "workflow-harness-live-shadow-comparison-inspector",
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      const liveReceiptRefs = String(
        observedSelectedState["data-live-receipt-refs"] ?? "",
      )
        .split(/[|,]/)
        .map((value) => value.trim())
        .filter(Boolean);
      const shadowReceiptRefs = String(
        observedSelectedState["data-shadow-receipt-refs"] ?? "",
      )
        .split(/[|,]/)
        .map((value) => value.trim())
        .filter(Boolean);
      const requiredAttributeChecks = [
        [
          "data-live-attempt-id",
          comparison.liveAttemptId,
          observedSelectedState["data-live-attempt-id"],
        ],
        [
          "data-shadow-attempt-id",
          comparison.shadowAttemptId,
          observedSelectedState["data-shadow-attempt-id"],
        ],
        [
          "data-workflow-node-id",
          comparison.workflowNodeId,
          observedSelectedState["data-workflow-node-id"],
        ],
        [
          "data-component-kind",
          comparison.componentKind,
          observedSelectedState["data-component-kind"],
        ],
        [
          "data-divergence",
          comparison.divergence,
          observedSelectedState["data-divergence"],
        ],
        [
          "data-blocking",
          comparison.blocking ? "true" : "false",
          observedSelectedState["data-blocking"],
        ],
        [
          "data-live-replay-fixture-ref",
          liveAttempt.replay.fixtureRef ?? "",
          observedSelectedState["data-live-replay-fixture-ref"],
        ],
        [
          "data-shadow-replay-fixture-ref",
          shadowAttempt.replay.fixtureRef ?? "",
          observedSelectedState["data-shadow-replay-fixture-ref"],
        ],
        [
          "data-live-input-hash",
          liveAttempt.inputHash ?? "",
          observedSelectedState["data-live-input-hash"],
        ],
        [
          "data-shadow-input-hash",
          shadowAttempt.inputHash ?? "",
          observedSelectedState["data-shadow-input-hash"],
        ],
        [
          "data-live-output-hash",
          liveAttempt.outputHash ?? "",
          observedSelectedState["data-live-output-hash"],
        ],
        [
          "data-shadow-output-hash",
          shadowAttempt.outputHash ?? "",
          observedSelectedState["data-shadow-output-hash"],
        ],
      ] as const;
      const attributeBlockers = requiredAttributeChecks
        .filter(([, expected, observed]) => observed !== expected)
        .map(([attribute]) => `${attribute}_mismatch`);
      const blockers = [
        ...(parsed ? [] : ["live_shadow_comparison_hash_parse_failed"]),
        ...(parsed?.nodeAttemptId === comparison.liveAttemptId
          ? []
          : ["live_shadow_comparison_node_attempt_parse_mismatch"]),
        ...(openedHash === hash
          ? []
          : ["live_shadow_comparison_history_mismatch"]),
        ...(receiptRef && liveReceiptRefs.includes(receiptRef)
          ? []
          : ["live_shadow_comparison_live_receipt_mismatch"]),
        ...(shadowAttempt.receiptIds[0] &&
        shadowReceiptRefs.includes(shadowAttempt.receiptIds[0])
          ? []
          : ["live_shadow_comparison_shadow_receipt_mismatch"]),
        ...attributeBlockers,
      ];
      const observedValue =
        observedSelectedState["data-live-attempt-id"] ?? null;
      const casePassed =
        blockers.length === 0 &&
        observedValue === comparison.liveAttemptId &&
        Boolean(parsed) &&
        parsed?.nodeAttemptId === comparison.liveAttemptId;
      return {
        schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
        method:
          "same-session Workflows bridge opens a live-vs-shadow comparison through the node-attempt inspector rail",
        generatedAtMs,
        cases: [
          {
            id: "live-shadow-comparison",
            hash,
            expectedPanel: "outputs",
            expectedAttribute: "data-live-attempt-id",
            expectedValue: comparison.liveAttemptId,
            selectedRailTestId:
              "workflow-harness-live-shadow-comparison-inspector",
            openedHash,
            parsedMatches: parsed?.nodeAttemptId === comparison.liveAttemptId,
            historyMatches: openedHash === hash,
            observedValue,
            observedSelectedState,
            passed: casePassed,
          },
        ],
        passed: casePassed,
        blockers: casePassed ? [] : blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActiveRuntimeRollbackProofProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessDeepLinkReplayProof> => {
      const defaultDispatch =
        workflow.metadata.harness?.defaultRuntimeDispatchProof ?? null;
      const selector =
        workflow.metadata.harness?.runtimeSelectorDecision ?? null;
      const workerLaunchEnvelopes =
        defaultDispatch?.workerLaunchEnvelopes ??
        workflow.metadata.harness?.workerLaunchEnvelopes ??
        workflow.metadata.harness?.activationRecord?.workerLaunchEnvelopes ??
        [];
      const workerHandoffReceipts =
        defaultDispatch?.workerHandoffReceipts ??
        workflow.metadata.harness?.workerHandoffReceipts ??
        workflow.metadata.harness?.activationRecord?.workerHandoffReceipts ??
        [];
      const workerHandoffNodeAttempts =
        defaultDispatch?.workerHandoffNodeAttempts ?? [];
      const rollbackLaunchEnvelope =
        workerLaunchEnvelopes.find(
          (envelope) => envelope.phase === "rollback",
        ) ?? null;
      const rollbackHandoffReceipt =
        workerHandoffReceipts.find((receipt) => receipt.phase === "rollback") ??
        null;
      const rollbackNodeAttempt =
        workerHandoffNodeAttempts.find(
          (attempt) =>
            Boolean(rollbackHandoffReceipt?.receiptId) &&
            attempt.receiptIds.includes(rollbackHandoffReceipt?.receiptId ?? ""),
        ) ??
        workerHandoffNodeAttempts.find((attempt) =>
          attempt.attemptId.includes(":rollback:"),
        ) ??
        null;
      const rollbackReplayFixtureRef =
        rollbackNodeAttempt?.replay.fixtureRef ??
        (defaultDispatch?.workerHandoffReplayFixtureRefs ?? []).find(
          (fixtureRef) => fixtureRef.includes(":rollback:"),
        ) ??
        "";
      const readinessProofId =
        rollbackHandoffReceipt?.rollbackReadinessProofId ??
        rollbackLaunchEnvelope?.rollbackReadinessProofId ??
        selector?.livePromotionReadinessProof?.proofId ??
        defaultDispatch?.livePromotionReadinessProof?.proofId ??
        "";
      const liveShadowGateId =
        rollbackHandoffReceipt?.rollbackLiveShadowComparisonGateId ??
        rollbackLaunchEnvelope?.rollbackLiveShadowComparisonGateId ??
        defaultDispatch?.liveShadowComparisonGate?.gateId ??
        defaultDispatch?.livePromotionReadinessProof?.liveShadowComparisonGate
          ?.gateId ??
        "";
      const rollbackTarget =
        defaultDispatch?.rollbackTarget ??
        selector?.rollbackTarget ??
        workflow.metadata.harness?.activationId ??
        "";
      if (
        !defaultDispatch ||
        !rollbackTarget ||
        !rollbackLaunchEnvelope ||
        !rollbackHandoffReceipt ||
        !rollbackNodeAttempt ||
        !rollbackReplayFixtureRef
      ) {
        return {
          schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
          method:
            "same-session Workflows bridge opens active runtime rollback proof deep links and reads the rollback workbench rail",
          generatedAtMs,
          cases: [],
          passed: false,
          blockers: [
            ...(!defaultDispatch
              ? ["missing_default_runtime_dispatch"]
              : []),
            ...(!rollbackTarget ? ["missing_rollback_target"] : []),
            ...(!rollbackLaunchEnvelope
              ? ["missing_rollback_launch_envelope"]
              : []),
            ...(!rollbackHandoffReceipt
              ? ["missing_rollback_handoff_receipt"]
              : []),
            ...(!rollbackNodeAttempt
              ? ["missing_rollback_node_attempt"]
              : []),
            ...(!rollbackReplayFixtureRef
              ? ["missing_rollback_replay_fixture"]
              : []),
          ],
        };
      }
      const replayCases: Array<{
        id: string;
        link: HarnessWorkbenchDeepLink;
        expectedAttribute: string;
        expectedValue: string;
        expectedParsedKey?: keyof HarnessWorkbenchDeepLink;
      }> = [
        {
          id: "active-runtime-rollback-target",
          link: {
            panel: "settings" as WorkflowRightPanel,
            rollbackTarget,
          },
          expectedAttribute: "data-selected-rollback-target",
          expectedValue: rollbackTarget,
          expectedParsedKey: "rollbackTarget",
        },
        {
          id: "active-runtime-rollback-launch-envelope",
          link: {
            panel: "settings" as WorkflowRightPanel,
            receiptRef: rollbackLaunchEnvelope.envelopeId,
          },
          expectedAttribute: "data-selected-receipt-ref",
          expectedValue: rollbackLaunchEnvelope.envelopeId,
          expectedParsedKey: "receiptRef",
        },
        {
          id: "active-runtime-rollback-handoff-receipt",
          link: {
            panel: "settings" as WorkflowRightPanel,
            receiptRef: rollbackHandoffReceipt.receiptId,
          },
          expectedAttribute: "data-selected-receipt-ref",
          expectedValue: rollbackHandoffReceipt.receiptId,
          expectedParsedKey: "receiptRef",
        },
        {
          id: "active-runtime-rollback-node-attempt",
          link: {
            panel: "settings" as WorkflowRightPanel,
            nodeAttemptId: rollbackNodeAttempt.attemptId,
            receiptRef: rollbackHandoffReceipt.receiptId,
            replayFixtureRef: rollbackReplayFixtureRef,
          },
          expectedAttribute: "data-selected-node-attempt-id",
          expectedValue: rollbackNodeAttempt.attemptId,
          expectedParsedKey: "nodeAttemptId",
        },
        {
          id: "active-runtime-rollback-replay",
          link: {
            panel: "settings" as WorkflowRightPanel,
            replayFixtureRef: rollbackReplayFixtureRef,
          },
          expectedAttribute: "data-selected-replay-fixture-ref",
          expectedValue: rollbackReplayFixtureRef,
          expectedParsedKey: "replayFixtureRef",
        },
      ];
      const cases = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      try {
        for (const replayCase of replayCases) {
          const hash = encodeHarnessWorkbenchDeepLink(replayCase.link);
          const parsed = parseHarnessWorkbenchDeepLink(hash);
          if (parsed) {
            writeHarnessWorkbenchDeepLink(hash);
            applyHarnessWorkbenchDeepLink(parsed);
          }
          await nextHarnessWorkbenchFrame();
          writeHarnessWorkbenchDeepLink(hash);
          await nextHarnessWorkbenchFrame();
          const observedSelectedState = readHarnessRailSelectedState(
            "workflow-harness-active-runtime-binding",
          );
          const observedValue =
            observedSelectedState[replayCase.expectedAttribute] ?? null;
          const proofBound =
            observedSelectedState["data-rollback-proof-bound"] === "true";
          const proofAttributesMatch =
            proofBound &&
            observedSelectedState["data-rollback-readiness-proof-id"] ===
              readinessProofId &&
            observedSelectedState["data-rollback-live-shadow-gate-id"] ===
              liveShadowGateId &&
            observedSelectedState["data-rollback-live-shadow-gate-ready"] ===
              "true" &&
            observedSelectedState["data-rollback-activation-id"] ===
              rollbackHandoffReceipt.rollbackActivationId &&
            observedSelectedState["data-rollback-harness-hash"] ===
              rollbackHandoffReceipt.rollbackHarnessHash &&
            observedSelectedState["data-rollback-policy-decision"] ===
              rollbackHandoffReceipt.rollbackPolicyDecision &&
            observedSelectedState["data-rollback-launch-envelope-id"] ===
              rollbackLaunchEnvelope.envelopeId &&
            observedSelectedState["data-rollback-handoff-receipt-id"] ===
              rollbackHandoffReceipt.receiptId &&
            observedSelectedState["data-rollback-node-attempt-id"] ===
              rollbackNodeAttempt.attemptId &&
            observedSelectedState["data-rollback-replay-fixture-ref"] ===
              rollbackReplayFixtureRef;
          cases.push({
            id: replayCase.id,
            hash,
            expectedPanel: replayCase.link.panel ?? "outputs",
            expectedAttribute: replayCase.expectedAttribute,
            expectedValue: replayCase.expectedValue,
            selectedRailTestId: "workflow-harness-active-runtime-binding",
            openedHash:
              typeof window === "undefined" ? "" : window.location.hash,
            parsedMatches:
              parsed?.[replayCase.expectedParsedKey ?? "rollbackTarget"] ===
              replayCase.expectedValue,
            historyMatches:
              typeof window !== "undefined" && window.location.hash === hash,
            observedValue,
            observedSelectedState,
            rollbackProofAttributesMatch: proofAttributesMatch,
            passed:
              Boolean(parsed) &&
              observedValue === replayCase.expectedValue &&
              (typeof window === "undefined" ||
                window.location.hash === hash) &&
              proofAttributesMatch,
          });
        }
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      const requiredCaseIds = replayCases.map((replayCase) => replayCase.id);
      const presentCaseIds = new Set(cases.map((replayCase) => replayCase.id));
      const blockers = [
        ...requiredCaseIds
          .filter((caseId) => !presentCaseIds.has(caseId))
          .map((caseId) => `missing_${caseId.replace(/-/g, "_")}`),
        ...cases
          .filter((replayCase) => !replayCase.passed)
          .map((replayCase) => `${replayCase.id}_deep_link_replay_failed`),
      ];
      return {
        schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
        method:
          "same-session Workflows bridge opens active runtime rollback proof deep links and reads the rollback workbench rail",
        generatedAtMs,
        cases,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActiveRuntimeRollbackExecutionWorkbenchProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<{
      executionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof;
      applyProof: WorkflowHarnessActiveRuntimeRollbackApplyProof;
      auditEvent: WorkflowHarnessActivationAuditEvent;
    }> => {
      const defaultDispatch =
        workflow.metadata.harness?.defaultRuntimeDispatchProof ?? null;
      const workerHandoffReceipts =
        defaultDispatch?.workerHandoffReceipts ??
        workflow.metadata.harness?.workerHandoffReceipts ??
        [];
      const workerHandoffNodeAttempts =
        defaultDispatch?.workerHandoffNodeAttempts ??
        workflow.metadata.harness?.workerHandoffNodeAttempts ??
        [];
      const rollbackHandoffReceipt =
        workerHandoffReceipts.find((receipt) => receipt.phase === "rollback") ??
        null;
      const rollbackNodeAttempt =
        workerHandoffNodeAttempts.find(
          (attempt) =>
            Boolean(rollbackHandoffReceipt?.receiptId) &&
            attempt.receiptIds.includes(rollbackHandoffReceipt?.receiptId ?? ""),
        ) ??
        workerHandoffNodeAttempts.find((attempt) =>
          attempt.attemptId.includes(":rollback:"),
        ) ??
        null;
      const rollbackReplayFixtureRef =
        rollbackNodeAttempt?.replay.fixtureRef ??
        (defaultDispatch?.workerHandoffReplayFixtureRefs ?? []).find(
          (fixtureRef) => fixtureRef.includes(":rollback:"),
        ) ??
        "";
      const rollbackTarget =
        defaultDispatch?.rollbackTarget ??
        workflow.metadata.harness?.runtimeSelectorDecision?.rollbackTarget ??
        workflow.metadata.harness?.activationId ??
        "";
      const link: HarnessWorkbenchDeepLink = {
        panel: "settings" as WorkflowRightPanel,
        rollbackTarget,
        nodeAttemptId: rollbackNodeAttempt?.attemptId,
        receiptRef: rollbackHandoffReceipt?.receiptId,
        replayFixtureRef: rollbackReplayFixtureRef || undefined,
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      let beforeState: Record<string, string> = {};
      let afterState: Record<string, string> = {};
      let finalState: Record<string, string> = {};
      let dryRunResult: HarnessActiveRuntimeRollbackDryRunClickResult | null =
        null;
      let applyResult: HarnessActiveRuntimeRollbackApplyClickResult | null =
        null;
      let clicked = false;
      let applyClicked = false;
      let applyDisabledBefore = true;
      let applyDisabledAfter = true;
      try {
        if (typeof window !== "undefined") {
          (window as any)
            .__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_DRY_RUN_RESULT =
            null;
          (window as any)
            .__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_APPLY_RESULT = null;
        }
        if (!parsed) {
          blockers.push("active_runtime_rollback_execution_hash_parse_failed");
        } else {
          writeHarnessWorkbenchDeepLink(hash);
          applyHarnessWorkbenchDeepLink(parsed);
        }
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
        beforeState = readHarnessRailSelectedState(
          "workflow-harness-active-runtime-binding",
        );
        const dryRunButton = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-active-runtime-rollback-dry-run"]',
        );
        const applyButtonBefore = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-active-runtime-rollback-apply"]',
        );
        applyDisabledBefore =
          applyButtonBefore?.disabled ??
          beforeState["data-rollback-execution-apply-disabled"] !== "false";
        if (!dryRunButton) {
          blockers.push("active_runtime_rollback_dry_run_button_missing");
        } else if (dryRunButton.disabled) {
          blockers.push("active_runtime_rollback_dry_run_button_disabled");
        } else {
          dryRunButton.click();
          clicked = true;
          for (let attempt = 0; attempt < 80; attempt += 1) {
            await nextHarnessWorkbenchFrame();
            dryRunResult =
              readHarnessActiveRuntimeRollbackDryRunClickResult();
            if (dryRunResult?.canaryResultId || dryRunResult?.blockers.length) {
              break;
            }
          }
          if (parsed) {
            applyHarnessWorkbenchDeepLink(parsed);
            writeHarnessWorkbenchDeepLink(hash);
            await nextHarnessWorkbenchFrame();
            await nextHarnessWorkbenchFrame();
            afterState = readHarnessRailSelectedState(
              "workflow-harness-active-runtime-binding",
            );
            const applyButtonAfter =
              document.querySelector<HTMLButtonElement>(
                '[data-testid="workflow-harness-active-runtime-rollback-apply"]',
              );
            applyDisabledAfter =
              applyButtonAfter?.disabled ??
              afterState["data-rollback-execution-apply-disabled"] !== "false";
            if (!applyButtonAfter) {
              blockers.push("active_runtime_rollback_apply_button_missing");
            } else if (applyButtonAfter.disabled) {
              blockers.push("active_runtime_rollback_apply_button_disabled");
            } else {
              applyButtonAfter.click();
              applyClicked = true;
              for (let attempt = 0; attempt < 80; attempt += 1) {
                await nextHarnessWorkbenchFrame();
                applyResult =
                  readHarnessActiveRuntimeRollbackApplyClickResult();
                if (applyResult?.executionId || applyResult?.blockers.length) {
                  break;
                }
              }
              applyHarnessWorkbenchDeepLink(parsed);
              writeHarnessWorkbenchDeepLink(hash);
              await nextHarnessWorkbenchFrame();
              await nextHarnessWorkbenchFrame();
              finalState = readHarnessRailSelectedState(
                "workflow-harness-active-runtime-binding",
              );
            }
          }
        }
      } catch (error) {
        blockers.push(
          `active_runtime_rollback_execution_probe_failed:${errorMessage(error)}`,
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      if (Object.keys(finalState).length === 0) {
        finalState = afterState;
      }
      if (!rollbackTarget) {
        blockers.push("active_runtime_rollback_target_missing");
      }
      if (!rollbackHandoffReceipt) {
        blockers.push("active_runtime_rollback_handoff_receipt_missing");
      }
      if (!rollbackNodeAttempt) {
        blockers.push("active_runtime_rollback_node_attempt_missing");
      }
      if (!rollbackReplayFixtureRef) {
        blockers.push("active_runtime_rollback_replay_fixture_missing");
      }
      if (beforeState["data-rollback-proof-bound"] !== "true") {
        blockers.push("active_runtime_rollback_before_proof_not_bound");
      }
      if (!applyDisabledBefore) {
        blockers.push("active_runtime_rollback_apply_enabled_before_dry_run");
      }
      if (!clicked) {
        blockers.push("active_runtime_rollback_dry_run_not_clicked");
      }
      if (dryRunResult?.passed !== true) {
        blockers.push("active_runtime_rollback_dry_run_not_passed");
      }
      if (dryRunResult?.canaryStatus !== "passed") {
        blockers.push("active_runtime_rollback_canary_not_passed");
      }
      if (dryRunResult?.canaryHashVerified !== true) {
        blockers.push("active_runtime_rollback_canary_hash_not_verified");
      }
      if (afterState["data-rollback-proof-bound"] !== "true") {
        blockers.push("active_runtime_rollback_after_proof_not_bound");
      }
      if (afterState["data-rollback-execution-dry-run-status"] !== "passed") {
        blockers.push("active_runtime_rollback_dry_run_status_not_visible");
      }
      if (
        afterState["data-rollback-execution-canary-result-id"] !==
        dryRunResult?.canaryResultId
      ) {
        blockers.push("active_runtime_rollback_canary_id_not_visible");
      }
      if (afterState["data-rollback-execution-apply-readiness"] !== "ready") {
        blockers.push("active_runtime_rollback_apply_not_ready_after_dry_run");
      }
      if (applyDisabledAfter) {
        blockers.push("active_runtime_rollback_apply_still_disabled");
      }
      if (!applyClicked) {
        blockers.push("active_runtime_rollback_apply_not_clicked");
      }
      if (applyResult?.passed !== true || applyResult?.applied !== true) {
        blockers.push("active_runtime_rollback_apply_not_applied");
      }
      if (applyResult?.rollbackTargetVerified !== true) {
        blockers.push("active_runtime_rollback_apply_target_not_verified");
      }
      if (applyResult?.hashVerified !== true) {
        blockers.push("active_runtime_rollback_apply_hash_not_verified");
      }
      if (!applyResult?.rollbackReceiptId) {
        blockers.push("active_runtime_rollback_apply_receipt_missing");
      }
      if (!applyResult?.auditEventId) {
        blockers.push("active_runtime_rollback_apply_audit_event_missing");
      }
      if (
        finalState["data-rollback-apply-execution-status"] !== "applied" ||
        finalState["data-rollback-apply-execution-id"] !==
          applyResult?.executionId ||
        finalState["data-rollback-apply-receipt-id"] !==
          applyResult?.rollbackReceiptId ||
        finalState["data-rollback-apply-audit-event-id"] !==
          applyResult?.auditEventId
      ) {
        blockers.push("active_runtime_rollback_apply_state_not_visible");
      }
      const proof: WorkflowHarnessActiveRuntimeRollbackExecutionProof = {
        schemaVersion:
          "workflow.harness.active-runtime-rollback-execution-proof.v1",
        method:
          "same-session Workflows bridge opens the active runtime rollback proof, clicks dry-run, verifies inline canary state, and restores the route before checking apply readiness",
        generatedAtMs,
        workflowId:
          defaultDispatch?.workflowId ??
          workflow.metadata.harness?.harnessWorkflowId ??
          workflow.metadata.id,
        activationId:
          afterState["data-rollback-activation-id"] ||
          dryRunResult?.activationId ||
          defaultDispatch?.activationId ||
          "",
        rollbackTarget,
        readinessProofId:
          afterState["data-rollback-readiness-proof-id"] ||
          dryRunResult?.readinessProofId ||
          "",
        liveShadowComparisonGateId:
          afterState["data-rollback-live-shadow-gate-id"] ||
          dryRunResult?.liveShadowComparisonGateId ||
          "",
        liveShadowComparisonGateReady:
          afterState["data-rollback-live-shadow-gate-ready"] === "true",
        harnessHash:
          afterState["data-rollback-harness-hash"] ||
          dryRunResult?.harnessHash ||
          defaultDispatch?.harnessHash ||
          "",
        policyDecision:
          afterState["data-rollback-policy-decision"] ||
          "allow_default_harness_worker_rollback_from_live_shadow_gate",
        launchEnvelopeId:
          afterState["data-rollback-launch-envelope-id"] || null,
        handoffReceiptId:
          afterState["data-rollback-handoff-receipt-id"] ||
          rollbackHandoffReceipt?.receiptId ||
          null,
        nodeAttemptId:
          afterState["data-rollback-node-attempt-id"] ||
          rollbackNodeAttempt?.attemptId ||
          null,
        replayFixtureRef:
          afterState["data-rollback-replay-fixture-ref"] ||
          rollbackReplayFixtureRef ||
          null,
        dryRun: {
          clicked,
          passed: dryRunResult?.passed === true,
          canaryResultId: dryRunResult?.canaryResultId ?? null,
          canaryStatus: dryRunResult?.canaryStatus ?? "blocked",
          canaryHashVerified: dryRunResult?.canaryHashVerified === true,
          policyDecision: dryRunResult?.passed
            ? "allow_default_live_rollback_dry_run_from_bound_proof"
            : "block_default_live_rollback_dry_run",
          receiptRefs: [
            rollbackHandoffReceipt?.receiptId ?? "",
            rollbackNodeAttempt?.receiptIds?.[0] ?? "",
          ].filter(Boolean),
          replayFixtureRefs: [rollbackReplayFixtureRef].filter(Boolean),
          blockers: dryRunResult?.blockers ?? [],
        },
        apply: {
          attempted: applyClicked,
          disabled: applyDisabledAfter,
          readiness: applyResult?.applied ? "applied" : "ready",
          applied: applyResult?.applied === true,
          policyDecision:
            applyResult?.policyDecision ??
            (applyDisabledAfter
              ? "block_default_live_rollback_apply_until_dry_run_passes"
              : "allow_default_live_rollback_apply_after_bound_dry_run"),
          executionId: applyResult?.executionId ?? null,
          rollbackReceiptId: applyResult?.rollbackReceiptId ?? null,
          auditEventId: applyResult?.auditEventId ?? null,
          rollbackTargetVerified:
            applyResult?.rollbackTargetVerified === true,
          hashVerified: applyResult?.hashVerified === true,
          receiptRefs: applyResult?.receiptRefs ?? [],
          evidenceRefs: [
            applyResult?.executionId ?? "",
            applyResult?.rollbackReceiptId ?? "",
            applyResult?.auditEventId ?? "",
            dryRunResult?.canaryResultId ?? "",
          ].filter(Boolean),
          replayFixtureRefs: applyResult?.replayFixtureRefs ?? [],
          appliedAtMs: applyResult?.applied ? generatedAtMs : null,
          blockers: applyResult?.blockers ?? [],
        },
        routeRestore: {
          hash,
          selectedRailTestId: "workflow-harness-active-runtime-binding",
          rollbackProofBound:
            finalState["data-rollback-proof-bound"] === "true",
          dryRunStatus:
            finalState["data-rollback-execution-dry-run-status"] || null,
          applyDisabled:
            finalState["data-rollback-execution-apply-disabled"] !== "false",
          canaryResultId:
            finalState["data-rollback-execution-canary-result-id"] || null,
          observedSelectedState: finalState,
        },
        passed: blockers.length === 0,
        blockers,
      };
      const applyProof: WorkflowHarnessActiveRuntimeRollbackApplyProof = {
        schemaVersion: "workflow.harness.active-runtime-rollback-apply-proof.v1",
        method:
          "same-session Workflows bridge clicks active runtime rollback apply after a bound dry run and verifies rollback receipt plus audit state in the rail",
        generatedAtMs,
        workflowId: proof.workflowId,
        activationId: proof.activationId,
        previousActivationId: proof.activationId,
        nextActivationId: applyResult?.rollbackTarget ?? proof.rollbackTarget,
        rollbackTarget: proof.rollbackTarget,
        readinessProofId: proof.readinessProofId,
        liveShadowComparisonGateId: proof.liveShadowComparisonGateId,
        liveShadowComparisonGateReady: proof.liveShadowComparisonGateReady,
        harnessHash: proof.harnessHash,
        launchEnvelopeId: proof.launchEnvelopeId,
        handoffReceiptId: proof.handoffReceiptId,
        nodeAttemptId: proof.nodeAttemptId,
        replayFixtureRef: proof.replayFixtureRef,
        dryRunCanaryResultId: proof.dryRun.canaryResultId,
        executionId: applyResult?.executionId ?? "",
        rollbackReceiptId: applyResult?.rollbackReceiptId ?? "",
        auditEventId: applyResult?.auditEventId ?? "",
        applyStatus: applyResult?.applyStatus ?? "blocked",
        rollbackApplied: applyResult?.applied === true,
        rollbackTargetVerified:
          applyResult?.rollbackTargetVerified === true,
        hashVerified: applyResult?.hashVerified === true,
        policyDecision:
          applyResult?.policyDecision ??
          "active_runtime_rollback_apply_blocked",
        receiptRefs: applyResult?.receiptRefs ?? [],
        evidenceRefs: proof.apply.evidenceRefs ?? [],
        replayFixtureRefs: applyResult?.replayFixtureRefs ?? [],
        staleProofBlocked: false,
        detachedProofBlocked: false,
        blockers,
        passed: blockers.length === 0 && applyResult?.passed === true,
      };
      const auditEventIdParts = applyProof.auditEventId.split(":");
      const auditEventCreatedAtMs =
        Number(auditEventIdParts[auditEventIdParts.length - 1]) ||
        generatedAtMs;
      const auditEvent: WorkflowHarnessActivationAuditEvent = {
        schemaVersion: "workflow.harness.activation-audit.v1",
        eventId: applyProof.auditEventId,
        eventType: applyProof.rollbackApplied
          ? "active_runtime_rollback_applied"
          : "active_runtime_rollback_apply_blocked",
        status: applyProof.rollbackApplied ? "applied" : "blocked",
        workflowId: applyProof.workflowId,
        activationId: applyProof.activationId,
        previousActivationId: applyProof.previousActivationId ?? undefined,
        nextActivationId: applyProof.nextActivationId ?? undefined,
        rollbackTarget: applyProof.rollbackTarget,
        rollbackExecuted: applyProof.rollbackApplied,
        blockers: applyProof.blockers,
        evidenceRefs: applyProof.evidenceRefs,
        receiptRefs: applyProof.receiptRefs,
        summary: applyProof.rollbackApplied
          ? `Active runtime rollback applied to ${applyProof.rollbackTarget}`
          : `Active runtime rollback apply blocked by ${applyProof.blockers.length} blockers`,
        createdAtMs: auditEventCreatedAtMs,
      };
      return { executionProof: proof, applyProof, auditEvent };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActiveRuntimeRollbackNegativeApplyProbe = useCallback(
    async (
      workflow: WorkflowProject,
      executionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof> => {
      type DefaultRuntimeDispatchProof = NonNullable<
        NonNullable<
          WorkflowProject["metadata"]["harness"]
        >["defaultRuntimeDispatchProof"]
      >;
      type NegativeApplyCaseConfig = {
        caseId: string;
        mutationKind: "stale_proof" | "detached_proof";
        expectedBlockers: string[];
        workflow: WorkflowProject;
        executionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof;
        staleProofBlocked: boolean;
        detachedProofBlocked: boolean;
      };
      const resetExecutionProofForNegativeApply = (
        proof: WorkflowHarnessActiveRuntimeRollbackExecutionProof,
        method: string,
      ): WorkflowHarnessActiveRuntimeRollbackExecutionProof => ({
        ...proof,
        method,
        apply: {
          ...proof.apply,
          attempted: false,
          disabled: false,
          readiness: "ready",
          applied: false,
          executionId: null,
          rollbackReceiptId: null,
          auditEventId: null,
          rollbackTargetVerified: false,
          hashVerified: false,
          receiptRefs: [],
          evidenceRefs: [],
          replayFixtureRefs: [],
          appliedAtMs: null,
          blockers: [],
        },
        routeRestore: undefined,
        passed: true,
        blockers: [],
      });
      const buildNegativeWorkflow = (
        nextExecutionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof,
        mutateDispatch?: (
          dispatch: DefaultRuntimeDispatchProof,
        ) => DefaultRuntimeDispatchProof,
      ): WorkflowProject => {
        const harness = workflow.metadata.harness;
        const defaultDispatch = harness?.defaultRuntimeDispatchProof ?? null;
        const nextDefaultDispatch =
          defaultDispatch && mutateDispatch
            ? mutateDispatch(defaultDispatch)
            : defaultDispatch;
        return {
          ...workflow,
          metadata: {
            ...workflow.metadata,
            harness: harness
              ? {
                  ...harness,
                  defaultRuntimeDispatchProof:
                    nextDefaultDispatch ?? undefined,
                  workerLaunchEnvelopes:
                    nextDefaultDispatch?.workerLaunchEnvelopes ??
                    harness.workerLaunchEnvelopes,
                  workerHandoffReceipts:
                    nextDefaultDispatch?.workerHandoffReceipts ??
                    harness.workerHandoffReceipts,
                  workerHandoffNodeAttemptIds:
                    nextDefaultDispatch?.workerHandoffNodeAttemptIds ??
                    harness.workerHandoffNodeAttemptIds,
                  workerHandoffNodeAttempts:
                    nextDefaultDispatch?.workerHandoffNodeAttempts ??
                    harness.workerHandoffNodeAttempts,
                  workerHandoffReplayFixtureRefs:
                    nextDefaultDispatch?.workerHandoffReplayFixtureRefs ??
                    harness.workerHandoffReplayFixtureRefs,
                  activationRecord:
                    harness.activationRecord && nextDefaultDispatch
                      ? {
                          ...harness.activationRecord,
                          workerLaunchEnvelopes:
                            nextDefaultDispatch.workerLaunchEnvelopes,
                          workerHandoffReceipts:
                            nextDefaultDispatch.workerHandoffReceipts,
                          workerHandoffNodeAttemptIds:
                            nextDefaultDispatch.workerHandoffNodeAttemptIds,
                          workerHandoffNodeAttempts:
                            nextDefaultDispatch.workerHandoffNodeAttempts,
                          workerHandoffReplayFixtureRefs:
                            nextDefaultDispatch.workerHandoffReplayFixtureRefs,
                        }
                      : harness.activationRecord,
                  activeRuntimeRollbackExecutionProof: nextExecutionProof,
                  activeRuntimeRollbackApplyProof: undefined,
                }
              : harness,
          },
        };
      };
      const resetMethod =
        "negative apply fixture reuses the bound dry-run proof but removes or orphans one live rollback binding dependency before Apply";
      const staleExecutionProof: WorkflowHarnessActiveRuntimeRollbackExecutionProof =
        {
          ...resetExecutionProofForNegativeApply(
            executionProof,
            "negative apply fixture mutates the bound rollback hash, node attempt, and replay fixture after dry-run to prove stale proof blocking",
          ),
          harnessHash: `${executionProof.harnessHash}:stale-negative`,
          nodeAttemptId: executionProof.nodeAttemptId
            ? `${executionProof.nodeAttemptId}:stale-negative`
            : "stale-negative-node-attempt",
          replayFixtureRef: executionProof.replayFixtureRef
            ? `${executionProof.replayFixtureRef}:stale-negative`
            : "stale-negative-replay-fixture",
        };
      const detachedExecutionProof = () =>
        resetExecutionProofForNegativeApply(executionProof, resetMethod);
      const withoutRollbackNodeAttempt = (
        dispatch: DefaultRuntimeDispatchProof,
      ): DefaultRuntimeDispatchProof => {
        const nextWorkerHandoffNodeAttempts =
          dispatch.workerHandoffNodeAttempts.filter(
            (attempt) => attempt.attemptId !== executionProof.nodeAttemptId,
          );
        const nextWorkerHandoffNodeAttemptIds =
          dispatch.workerHandoffNodeAttemptIds.filter(
            (attemptId) => attemptId !== executionProof.nodeAttemptId,
          );
        return {
          ...dispatch,
          workerHandoffNodeAttempts: nextWorkerHandoffNodeAttempts,
          workerHandoffNodeAttemptIds: nextWorkerHandoffNodeAttemptIds,
          dispatchNodeAttempts: dispatch.dispatchNodeAttempts?.filter(
            (attempt) => attempt.attemptId !== executionProof.nodeAttemptId,
          ),
          dispatchNodeAttemptIds: dispatch.dispatchNodeAttemptIds.filter(
            (attemptId) => attemptId !== executionProof.nodeAttemptId,
          ),
          acceptedNodeAttemptIds: dispatch.acceptedNodeAttemptIds.filter(
            (attemptId) => attemptId !== executionProof.nodeAttemptId,
          ),
          nodeAttemptIds: dispatch.nodeAttemptIds.filter(
            (attemptId) => attemptId !== executionProof.nodeAttemptId,
          ),
        };
      };
      const orphanRollbackNodeAttempt = (
        dispatch: DefaultRuntimeDispatchProof,
      ): DefaultRuntimeDispatchProof => ({
        ...dispatch,
        workerHandoffNodeAttempts: dispatch.workerHandoffNodeAttempts.map(
          (attempt) =>
            attempt.attemptId === executionProof.nodeAttemptId
              ? {
                  ...attempt,
                  receiptIds: uniqueHarnessRefs([
                    ...attempt.receiptIds.filter(
                      (receiptId) =>
                        receiptId !== executionProof.handoffReceiptId,
                    ),
                    executionProof.handoffReceiptId
                      ? `${executionProof.handoffReceiptId}:orphaned`
                      : "rollback-handoff-receipt:orphaned",
                  ]),
                }
              : attempt,
        ),
      });
      const clearRollbackReplayFixture = (
        dispatch: DefaultRuntimeDispatchProof,
      ): DefaultRuntimeDispatchProof => {
        const nextWorkerHandoffNodeAttempts =
          dispatch.workerHandoffNodeAttempts.map((attempt) =>
            attempt.attemptId === executionProof.nodeAttemptId
              ? {
                  ...attempt,
                  replay: {
                    ...attempt.replay,
                    fixtureRef: "",
                  },
                }
              : attempt,
          );
        const nextReplayFixtureRefs = dispatch.replayFixtureRefs.filter(
          (fixtureRef) => fixtureRef !== executionProof.replayFixtureRef,
        );
        return {
          ...dispatch,
          workerHandoffNodeAttempts: nextWorkerHandoffNodeAttempts,
          workerHandoffReplayFixtureRefs:
            dispatch.workerHandoffReplayFixtureRefs.filter(
              (fixtureRef) => fixtureRef !== executionProof.replayFixtureRef,
            ),
          replayFixtureRefs: nextReplayFixtureRefs,
        };
      };
      const negativeCaseConfigs: NegativeApplyCaseConfig[] = [
        {
          caseId: "stale-hash-node-replay",
          mutationKind: "stale_proof",
          expectedBlockers: [
            "rollback_harness_hash_stale",
            "rollback_node_attempt_stale",
            "rollback_replay_fixture_stale",
            "rollback_apply_hash_not_verified",
          ],
          workflow: buildNegativeWorkflow(staleExecutionProof),
          executionProof: staleExecutionProof,
          staleProofBlocked: true,
          detachedProofBlocked: false,
        },
        {
          caseId: "detached-launch-envelope-missing",
          mutationKind: "detached_proof",
          expectedBlockers: [
            "rollback_launch_envelope_missing",
            "rollback_launch_envelope_stale",
          ],
          workflow: buildNegativeWorkflow(detachedExecutionProof(), (dispatch) => ({
            ...dispatch,
            workerLaunchEnvelopes: dispatch.workerLaunchEnvelopes.filter(
              (envelope) => envelope.phase !== "rollback",
            ),
            workerLaunchEnvelopeIds: dispatch.workerLaunchEnvelopeIds.filter(
              (envelopeId) => envelopeId !== executionProof.launchEnvelopeId,
            ),
          })),
          executionProof: detachedExecutionProof(),
          staleProofBlocked: true,
          detachedProofBlocked: true,
        },
        {
          caseId: "detached-handoff-receipt-missing",
          mutationKind: "detached_proof",
          expectedBlockers: [
            "rollback_handoff_receipt_missing",
            "rollback_handoff_receipt_stale",
          ],
          workflow: buildNegativeWorkflow(detachedExecutionProof(), (dispatch) => ({
            ...dispatch,
            workerHandoffReceipts: dispatch.workerHandoffReceipts.filter(
              (receipt) => receipt.phase !== "rollback",
            ),
            workerHandoffReceiptIds: dispatch.workerHandoffReceiptIds.filter(
              (receiptId) => receiptId !== executionProof.handoffReceiptId,
            ),
            receiptIds: dispatch.receiptIds.filter(
              (receiptId) => receiptId !== executionProof.handoffReceiptId,
            ),
          })),
          executionProof: detachedExecutionProof(),
          staleProofBlocked: true,
          detachedProofBlocked: true,
        },
        {
          caseId: "detached-node-attempt-missing",
          mutationKind: "detached_proof",
          expectedBlockers: [
            "rollback_node_attempt_missing",
            "rollback_node_attempt_stale",
          ],
          workflow: buildNegativeWorkflow(
            detachedExecutionProof(),
            withoutRollbackNodeAttempt,
          ),
          executionProof: detachedExecutionProof(),
          staleProofBlocked: true,
          detachedProofBlocked: true,
        },
        {
          caseId: "detached-node-attempt-orphaned",
          mutationKind: "detached_proof",
          expectedBlockers: ["rollback_node_attempt_orphaned"],
          workflow: buildNegativeWorkflow(
            detachedExecutionProof(),
            orphanRollbackNodeAttempt,
          ),
          executionProof: detachedExecutionProof(),
          staleProofBlocked: false,
          detachedProofBlocked: true,
        },
        {
          caseId: "detached-replay-fixture-missing",
          mutationKind: "detached_proof",
          expectedBlockers: [
            "rollback_replay_fixture_missing",
            "rollback_replay_fixture_stale",
          ],
          workflow: buildNegativeWorkflow(
            detachedExecutionProof(),
            clearRollbackReplayFixture,
          ),
          executionProof: detachedExecutionProof(),
          staleProofBlocked: true,
          detachedProofBlocked: true,
        },
      ];
      const runNegativeCase = async (
        negativeConfig: NegativeApplyCaseConfig,
        index: number,
      ) => {
        const runtimeResult = executeWorkflowHarnessActiveRuntimeRollbackApply(
          negativeConfig.workflow,
          { nowMs: generatedAtMs + index + 1 },
        );
        const link: HarnessWorkbenchDeepLink = {
          panel: "settings" as WorkflowRightPanel,
          rollbackTarget: negativeConfig.executionProof.rollbackTarget,
          nodeAttemptId:
            negativeConfig.executionProof.nodeAttemptId ?? undefined,
          receiptRef:
            negativeConfig.executionProof.handoffReceiptId ?? undefined,
          replayFixtureRef:
            negativeConfig.executionProof.replayFixtureRef ?? undefined,
        };
        const hash = encodeHarnessWorkbenchDeepLink(link);
        const parsed = parseHarnessWorkbenchDeepLink(hash);
        const blockers: string[] = [];
        let observedState: Record<string, string> = {};
        let applyButtonDisabled = true;
        try {
          loadWorkflowProject(negativeConfig.workflow);
          setWorkflow(negativeConfig.workflow);
          setRightPanel("settings");
          setBottomPanel("selection");
          if (!parsed) {
            blockers.push(
              "active_runtime_rollback_negative_hash_parse_failed",
            );
          } else {
            applyHarnessWorkbenchDeepLink(parsed);
          }
          await nextHarnessWorkbenchFrame();
          await nextHarnessWorkbenchFrame();
          observedState = readHarnessRailSelectedState(
            "workflow-harness-active-runtime-binding",
          );
          const applyButton = document.querySelector<HTMLButtonElement>(
            '[data-testid="workflow-harness-active-runtime-rollback-apply"]',
          );
          applyButtonDisabled =
            applyButton?.disabled ??
            observedState["data-rollback-execution-apply-disabled"] !== "false";
        } catch (error) {
          blockers.push(
            `active_runtime_rollback_negative_apply_probe_failed:${errorMessage(
              error,
            )}`,
          );
        } finally {
          loadWorkflowProject(workflow);
          setWorkflow(workflow);
          setRightPanel("outputs");
          setBottomPanel("selection");
          await nextHarnessWorkbenchFrame();
        }
        const observedRailBlockers = uniqueHarnessRefs([
          ...splitHarnessRailBlockers(
            observedState["data-rollback-execution-blockers"],
          ),
          ...splitHarnessRailBlockers(
            observedState["data-rollback-apply-blockers"],
          ),
        ]);
        const runtimeBlockers = runtimeResult.proof.blockers ?? [];
        const missingRailBlockers = negativeConfig.expectedBlockers.filter(
          (blocker) => !observedRailBlockers.includes(blocker),
        );
        const missingRuntimeBlockers = negativeConfig.expectedBlockers.filter(
          (blocker) => !runtimeBlockers.includes(blocker),
        );
        const caseBlockers = uniqueHarnessRefs([
          ...blockers,
          ...(applyButtonDisabled
            ? []
            : ["active_runtime_rollback_negative_apply_button_enabled"]),
          ...(runtimeResult.applied
            ? ["active_runtime_rollback_negative_apply_unexpectedly_applied"]
            : []),
          ...(runtimeResult.proof.applyStatus === "blocked"
            ? []
            : ["active_runtime_rollback_negative_apply_status_not_blocked"]),
          ...(runtimeResult.proof.staleProofBlocked ===
          negativeConfig.staleProofBlocked
            ? []
            : [
                negativeConfig.staleProofBlocked
                  ? "active_runtime_rollback_negative_stale_flag_missing"
                  : "active_runtime_rollback_negative_stale_flag_unexpected",
              ]),
          ...(runtimeResult.proof.detachedProofBlocked ===
          negativeConfig.detachedProofBlocked
            ? []
            : [
                negativeConfig.detachedProofBlocked
                  ? "active_runtime_rollback_negative_detached_flag_missing"
                  : "active_runtime_rollback_negative_detached_flag_unexpected",
              ]),
          ...missingRailBlockers.map(
            (blocker) => `missing_rail_blocker:${blocker}`,
          ),
          ...missingRuntimeBlockers.map(
            (blocker) => `missing_runtime_blocker:${blocker}`,
          ),
        ]);
        return {
          caseBlockers,
          negativeCase: {
            caseId: negativeConfig.caseId,
            mutationKind: negativeConfig.mutationKind,
            expectedBlockers: negativeConfig.expectedBlockers,
            observedRailBlockers,
            runtimeBlockers,
            selectedRailTestId: "workflow-harness-active-runtime-binding",
            applyButtonDisabled,
            applyStatus: runtimeResult.proof.applyStatus,
            staleProofBlocked: runtimeResult.proof.staleProofBlocked,
            detachedProofBlocked: runtimeResult.proof.detachedProofBlocked,
            rollbackApplied: runtimeResult.proof.rollbackApplied,
            rollbackTargetVerified: runtimeResult.proof.rollbackTargetVerified,
            hashVerified: runtimeResult.proof.hashVerified,
            rollbackReceiptId: runtimeResult.proof.rollbackReceiptId,
            auditEventId: runtimeResult.proof.auditEventId,
            passed: caseBlockers.length === 0,
          },
        };
      };
      const caseResults = [];
      for (const [index, negativeConfig] of negativeCaseConfigs.entries()) {
        caseResults.push(await runNegativeCase(negativeConfig, index));
      }
      const negativeCases = caseResults.map((result) => result.negativeCase);
      const proofBlockers = uniqueHarnessRefs(
        caseResults.flatMap((result) =>
          result.caseBlockers.map(
            (blocker) => `${result.negativeCase.caseId}:${blocker}`,
          ),
        ),
      );
      return {
        schemaVersion:
          "workflow.harness.active-runtime-rollback-negative-apply-proof.v1",
        method:
          "same-session Workflows bridge renders stale and detached rollback proof fixtures and confirms Apply stays disabled while the runtime helper blocks with matching proof blocker codes",
        generatedAtMs,
        workflowId:
          workflow.metadata.harness?.harnessWorkflowId ?? workflow.metadata.id,
        cases: negativeCases,
        passed: proofBlockers.length === 0,
        blockers: proofBlockers,
      };
    },
    [applyHarnessWorkbenchDeepLink, loadWorkflowProject],
  );
  const runHarnessColdStartDeepLinkRestoreProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessColdStartDeepLinkRestoreProof> => {
      const replayCases = harnessDeepLinkProbeCasesForWorkflow(workflow);
      const cases = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      try {
        setSelectedHarnessGroupId(null);
        setSelectedHarnessReceiptRef(null);
        setSelectedHarnessReplayFixtureRef(null);
        setSelectedHarnessRollbackTarget(null);
        setSelectedHarnessSelectorDecisionId(null);
        setSelectedHarnessDefaultDispatchId(null);
        setSelectedHarnessWorkerBindingId(null);
        setSelectedHarnessNodeAttemptId(null);
        setSelectedHarnessRevisionBindingKind(null);
        setSelectedHarnessRevisionBindingRef(null);
        setSelectedHarnessActivationBlockerIndex(null);
        setSelectedHarnessActivationBlockerRef(null);
        setSelectedHarnessActivationAuditEventId(null);
        setSelectedHarnessActivationGateId(null);
        setSelectedHarnessActivationGateEvidenceRef(null);
        setSelectedHarnessActivationGateNodeAttemptId(null);
        setSelectedHarnessActivationGateReceiptRef(null);
        setSelectedHarnessActivationGateReplayFixtureRef(null);
        handleNodeSelect(null);
        await nextHarnessWorkbenchFrame();
        for (const [index, replayCase] of replayCases.entries()) {
          const hash = encodeHarnessWorkbenchDeepLink(replayCase.link);
          const parsed = parseHarnessWorkbenchDeepLink(hash);
          writeHarnessWorkbenchDeepLink(hash);
          loadWorkflowProject({
            ...workflow,
            metadata: {
              ...workflow.metadata,
              updatedAtMs: generatedAtMs + index,
            },
          });
          await nextHarnessWorkbenchFrame();
          await nextHarnessWorkbenchFrame();
          await nextHarnessWorkbenchFrame();
          await nextHarnessWorkbenchFrame();
          await nextHarnessWorkbenchFrame();
          const observedSelectedState = readHarnessRailSelectedState(
            replayCase.selectedRailTestId,
          );
          const observedValue =
            observedSelectedState[replayCase.expectedAttribute] ?? null;
          const restoredFromInitialHash =
            typeof window === "undefined" || window.location.hash === hash;
          cases.push({
            id: replayCase.id,
            hash,
            initialHash: hash,
            expectedPanel: replayCase.link.panel ?? "outputs",
            expectedAttribute: replayCase.expectedAttribute,
            expectedValue: replayCase.expectedValue,
            selectedRailTestId: replayCase.selectedRailTestId,
            openedHash:
              typeof window === "undefined" ? "" : window.location.hash,
            parsedMatches:
              parsed?.[
                replayCase.expectedParsedKey ??
                  (Object.keys(replayCase.link).find(
                    (key) => key !== "panel",
                  ) as keyof HarnessWorkbenchDeepLink)
              ] === replayCase.expectedValue,
            historyMatches: restoredFromInitialHash,
            workflowReloaded: true,
            restoredFromInitialHash,
            observedValue,
            observedSelectedState,
            passed:
              Boolean(parsed) &&
              restoredFromInitialHash &&
              observedValue === replayCase.expectedValue,
          });
        }
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      const requiredCaseIds = [
        "selector",
        "dispatch",
        "worker",
        "rollback",
        "receipt",
        "replay",
        "revision",
        "activation-audit",
      ];
      const presentCaseIds = new Set(cases.map((replayCase) => replayCase.id));
      const blockers = [
        ...requiredCaseIds
          .filter((caseId) => !presentCaseIds.has(caseId))
          .map((caseId) => `missing_${caseId}_cold_start_deep_link_restore`),
        ...cases
          .filter((replayCase) => !replayCase.passed)
          .map(
            (replayCase) =>
              `${replayCase.id}_cold_start_deep_link_restore_failed`,
          ),
      ];
      return {
        schemaVersion: "workflow.harness.cold-start-deep-link-restore-proof.v1",
        method:
          "Workflows bridge writes each harness hash before loading the workflow, waits for startup restoration, and reads right-rail data-selected attributes",
        generatedAtMs,
        cases,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [handleNodeSelect, loadWorkflowProject],
  );
  const runHarnessActivationBlockerDeepLinkProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessDeepLinkReplayProof> => {
      const replayCases = harnessDeepLinkProbeCasesForWorkflow(workflow).filter(
        (replayCase) => replayCase.id === "activation-blocker",
      );
      const cases = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      try {
        for (const replayCase of replayCases) {
          const hash = encodeHarnessWorkbenchDeepLink(replayCase.link);
          const parsed = parseHarnessWorkbenchDeepLink(hash);
          if (parsed) {
            writeHarnessWorkbenchDeepLink(hash);
            applyHarnessWorkbenchDeepLink(parsed);
          }
          await nextHarnessWorkbenchFrame();
          writeHarnessWorkbenchDeepLink(hash);
          await nextHarnessWorkbenchFrame();
          const observedSelectedState = readHarnessRailSelectedState(
            replayCase.selectedRailTestId,
          );
          const observedValue =
            observedSelectedState[replayCase.expectedAttribute] ?? null;
          cases.push({
            id: replayCase.id,
            hash,
            expectedPanel: replayCase.link.panel ?? "outputs",
            expectedAttribute: replayCase.expectedAttribute,
            expectedValue: replayCase.expectedValue,
            selectedRailTestId: replayCase.selectedRailTestId,
            openedHash:
              typeof window === "undefined" ? "" : window.location.hash,
            parsedMatches:
              parsed?.[
                replayCase.expectedParsedKey ??
                  (Object.keys(replayCase.link).find(
                    (key) => key !== "panel",
                  ) as keyof HarnessWorkbenchDeepLink)
              ] === replayCase.expectedValue,
            historyMatches:
              typeof window !== "undefined" && window.location.hash === hash,
            observedValue,
            observedSelectedState,
            passed:
              Boolean(parsed) &&
              observedValue === replayCase.expectedValue &&
              (typeof window === "undefined" || window.location.hash === hash),
          });
        }
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      const presentCaseIds = new Set(cases.map((replayCase) => replayCase.id));
      const blockers = [
        ...(!presentCaseIds.has("activation-blocker")
          ? ["missing_activation_blocker_deep_link_replay"]
          : []),
        ...cases
          .filter((replayCase) => !replayCase.passed)
          .map((replayCase) => `${replayCase.id}_deep_link_replay_failed`),
      ];
      return {
        schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
        method:
          "same-session Workflows bridge restores a blocked fork activation blocker hash into right-rail selected state",
        generatedAtMs,
        cases,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActivationGateDeepLinkProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
      options: { requiredCaseIds?: string[] } = {},
    ): Promise<WorkflowHarnessDeepLinkReplayProof> => {
      const replayCases = harnessDeepLinkProbeCasesForWorkflow(workflow).filter(
        (replayCase) => replayCase.id.startsWith("activation-gate"),
      );
      const cases = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      try {
        for (const replayCase of replayCases) {
          const hash = encodeHarnessWorkbenchDeepLink(replayCase.link);
          const parsed = parseHarnessWorkbenchDeepLink(hash);
          if (parsed) {
            writeHarnessWorkbenchDeepLink(hash);
            applyHarnessWorkbenchDeepLink(parsed);
          }
          await nextHarnessWorkbenchFrame();
          writeHarnessWorkbenchDeepLink(hash);
          await nextHarnessWorkbenchFrame();
          const observedSelectedState = readHarnessRailSelectedState(
            replayCase.selectedRailTestId,
          );
          const observedValue =
            observedSelectedState[replayCase.expectedAttribute] ?? null;
          const requiredInvariantIds = (
            observedSelectedState["data-required-invariant-ids"] ?? ""
          )
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean);
          const workerInvariantSelected =
            replayCase.id === "activation-gate-worker-invariant";
          const workerInvariantGateRestored =
            !workerInvariantSelected ||
            (requiredInvariantIds.includes(
              DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
            ) &&
              (observedSelectedState["data-invariant-blockers"] ?? "") ===
                "" &&
              observedSelectedState["data-invariant-blocker-count"] === "0" &&
              observedSelectedState["data-gate-status"] === "passed" &&
              (observedSelectedState["data-gate-action-id"] ?? "").startsWith(
                "activation-gate-action:worker-invariant:",
              ) &&
              observedSelectedState["data-gate-action-command"] ===
                "workflow-harness-gate-action-worker-invariant");
          cases.push({
            id: replayCase.id,
            hash,
            expectedPanel: replayCase.link.panel ?? "outputs",
            expectedAttribute: replayCase.expectedAttribute,
            expectedValue: replayCase.expectedValue,
            selectedRailTestId: replayCase.selectedRailTestId,
            openedHash:
              typeof window === "undefined" ? "" : window.location.hash,
            parsedMatches:
              parsed?.[
                replayCase.expectedParsedKey ??
                  (Object.keys(replayCase.link).find(
                    (key) => key !== "panel",
                  ) as keyof HarnessWorkbenchDeepLink)
              ] === replayCase.expectedValue,
            historyMatches:
              typeof window !== "undefined" && window.location.hash === hash,
            observedValue,
            observedSelectedState,
            workerInvariantGateRestored,
            passed:
              Boolean(parsed) &&
              observedValue === replayCase.expectedValue &&
              (typeof window === "undefined" ||
                window.location.hash === hash) &&
              workerInvariantGateRestored,
          });
        }
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      const presentCaseIds = new Set(cases.map((replayCase) => replayCase.id));
      const requiredCaseIds = options.requiredCaseIds ?? [
        "activation-gate",
        "activation-gate-evidence",
        "activation-gate-canary-boundary",
        "activation-gate-canary-rollback-drill",
        "activation-gate-receipt",
	        "activation-gate-replay",
	        "activation-gate-mutation-canary-node-attempt",
	      ];
      const blockers = [
        ...requiredCaseIds
          .filter((caseId) => !presentCaseIds.has(caseId))
          .map(
            (caseId) => `missing_${caseId.replace(/-/g, "_")}_deep_link_replay`,
          ),
        ...cases
          .filter((replayCase) => !replayCase.passed)
          .map((replayCase) => `${replayCase.id}_deep_link_replay_failed`),
      ];
      return {
        schemaVersion: "workflow.harness.deep-link-replay-proof.v1",
        method:
          "same-session Workflows bridge restores a fork activation wizard gate hash into right-rail selected state",
        generatedAtMs,
        cases,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActivationGateActionClickProbe = useCallback(
    async (
      workflow: WorkflowProject,
      generatedAtMs: number,
    ): Promise<WorkflowHarnessActivationGateActionClickProof> => {
      const replayCase =
        harnessDeepLinkProbeCasesForWorkflow(workflow).find(
          (candidate) => candidate.id === "activation-gate",
        ) ?? null;
      const selectedRailTestId =
        replayCase?.selectedRailTestId ??
        "workflow-harness-activation-gate-inspector";
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      let beforeSelectedState: Record<string, string> = {};
      let beforeHash: string | null = null;
      let gateId: string | null = null;
      let actionId: string | null = null;
      let actionKind: string | null = null;
      let actionImpact: string | null = null;
      let actionCommand: string | null = null;
      let actionDisabled = false;
      let clicked = false;
      let afterRailTestId: string | null = null;
      let afterStatusMessage: string | null = null;
      let readinessPanelVisible = false;
      let readinessSummaryVisible = false;
      try {
        if (!replayCase) {
          blockers.push("missing_activation_gate_action_click_replay_case");
        } else {
          const hash = encodeHarnessWorkbenchDeepLink(replayCase.link);
          const parsed = parseHarnessWorkbenchDeepLink(hash);
          beforeHash = hash;
          if (!parsed) {
            blockers.push("activation_gate_action_click_hash_parse_failed");
          } else {
            writeHarnessWorkbenchDeepLink(hash);
            applyHarnessWorkbenchDeepLink(parsed);
          }
          await nextHarnessWorkbenchFrame();
          writeHarnessWorkbenchDeepLink(hash);
          await nextHarnessWorkbenchFrame();
          beforeSelectedState =
            readHarnessRailSelectedState(selectedRailTestId);
          gateId =
            beforeSelectedState["data-selected-activation-gate-id"] || null;
          actionId = beforeSelectedState["data-gate-action-id"] || null;
          actionKind = beforeSelectedState["data-gate-action-kind"] || null;
          actionImpact = beforeSelectedState["data-gate-action-impact"] || null;
          actionCommand =
            beforeSelectedState["data-gate-action-command"] || null;
          actionDisabled =
            beforeSelectedState["data-gate-action-disabled"] === "true";
          const actionButton = document.querySelector<HTMLButtonElement>(
            '[data-testid="workflow-harness-activation-gate-action"]',
          );
          if (!actionButton) {
            blockers.push("activation_gate_action_button_missing");
          } else if (actionButton.disabled || actionDisabled) {
            blockers.push("activation_gate_action_button_disabled");
          } else {
            actionButton.click();
            clicked = true;
            for (let attempt = 0; attempt < 30; attempt += 1) {
              await nextHarnessWorkbenchFrame();
              readinessSummaryVisible = Boolean(
                document.querySelector(
                  '[data-testid="workflow-readiness-summary"]',
                ),
              );
              afterRailTestId = readWorkflowRightRailTestId();
              if (
                readinessSummaryVisible &&
                afterRailTestId === "workflow-right-rail-readiness"
              ) {
                break;
              }
            }
          }
        }
      } catch (error) {
        blockers.push(
          `activation_gate_action_click_failed:${errorMessage(error)}`,
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      afterRailTestId = afterRailTestId ?? readWorkflowRightRailTestId();
      afterStatusMessage = readWorkflowStatusMessage();
      readinessPanelVisible =
        afterRailTestId === "workflow-right-rail-readiness";
      readinessSummaryVisible =
        readinessSummaryVisible ||
        Boolean(
          document.querySelector('[data-testid="workflow-readiness-summary"]'),
        );
      if (!gateId)
        blockers.push("activation_gate_action_click_gate_not_selected");
      if (!actionId?.startsWith("activation-gate-action:")) {
        blockers.push("activation_gate_action_click_action_id_missing");
      }
      if (!actionKind)
        blockers.push("activation_gate_action_click_kind_missing");
      if (!actionCommand?.startsWith("workflow-harness-gate-action-")) {
        blockers.push("activation_gate_action_click_command_missing");
      }
      if (!clicked)
        blockers.push("activation_gate_action_click_not_dispatched");
      if (!readinessPanelVisible) {
        blockers.push(
          "activation_gate_action_click_readiness_panel_not_opened",
        );
      }
      if (!readinessSummaryVisible) {
        blockers.push("activation_gate_action_click_readiness_summary_missing");
      }
      return {
        schemaVersion: "workflow.harness.activation-gate-action-click-proof.v1",
        method:
          "same-session Workflows bridge restores an activation gate, clicks the rendered gate action button, then requires the readiness rail and summary to appear",
        generatedAtMs,
        gateId,
        action: {
          id: actionId,
          kind: actionKind,
          impact: actionImpact,
          command: actionCommand,
          disabled: actionDisabled,
        },
        before: {
          hash: beforeHash,
          railTestId: selectedRailTestId,
          selectedState: beforeSelectedState,
        },
        after: {
          railTestId: afterRailTestId,
          statusMessage: afterStatusMessage,
          readinessPanelVisible,
          readinessSummaryVisible,
        },
        clicked,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessPackageEvidenceGateClickProbe = useCallback(
    async (
      generatedAtMs: number,
    ): Promise<WorkflowHarnessPackageEvidenceGateClickProof> => {
      const selectedRailTestId = "workflow-harness-activation-gate-inspector";
      const projectRoot = currentProject?.rootPath || ".";
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const link = {
        panel: "settings" as WorkflowRightPanel,
        activationGateId: "package-evidence",
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      let gateId: string | null = null;
      let beforeSelectedState: Record<string, string> = {};
      let packageReviewState: Record<string, string> = {};
      let evidenceState: Record<string, string> = {};
      let receiptState: Record<string, string> = {};
      let replayState: Record<string, string> = {};
      let nodeAttemptState: Record<string, string> = {};
      let mutationCanaryState: Record<string, string> = {};
      let mutationCanaryNodeAttemptState: Record<string, string> = {};
      let mutationCanaryTimelineAttemptId: string | null = null;
      let packageDeepLinkState: Record<string, string> = {};
      let clicked = false;
      let validatedWorkflow: WorkflowProject | null = null;

      const readCount = (state: Record<string, string>, key: string) => {
        const value = Number(state[key] ?? 0);
        return Number.isFinite(value) ? value : 0;
      };
      const clickPackageEvidenceRef = async (
        testId: string,
        missingBlocker: string,
      ) => {
        const button = document.querySelector<HTMLButtonElement>(
          `[data-testid="${testId}"]`,
        );
        if (!button) {
          blockers.push(missingBlocker);
          return false;
        }
        if (button.disabled) {
          blockers.push(`${missingBlocker}:disabled`);
          return false;
        }
        button.click();
        clicked = true;
        await nextHarnessWorkbenchFrame();
        await nextHarnessWorkbenchFrame();
        return true;
      };
      const restorePackageGate = async () => {
        if (!parsed) {
          blockers.push("package_evidence_gate_hash_parse_failed");
          return;
        }
        writeHarnessWorkbenchDeepLink(hash);
        applyHarnessWorkbenchDeepLink(parsed);
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
      };

      try {
        const packageFork = forkDefaultAgentHarnessWorkflow(
          "Package Evidence Gate GUI Fork",
          generatedAtMs + 10,
        );
        let packageWorkflow = packageFork.workflow;
        HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS.forEach((clusterId, index) => {
          packageWorkflow = workflowReadyForHarnessPromotion(
            packageWorkflow,
            clusterId,
            generatedAtMs + 20 + index,
          );
        });
        const { workflow: stagedWorkflow, candidate } =
          workflowWithMintableHarnessActivationCandidate(
            packageWorkflow,
            packageFork.tests,
            generatedAtMs + 40,
          );
        if (candidate.decision !== "mintable") {
          blockers.push("package_evidence_candidate_not_mintable");
        }
        const activationResult = applyWorkflowHarnessActivationCandidate(
          stagedWorkflow,
          candidate,
          {
            rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            nowMs: generatedAtMs + 50,
          },
        );
        if (!activationResult.applied) {
          blockers.push(
            `package_evidence_activation_not_applied:${activationResult.blockers.join(",")}`,
          );
        }
        validatedWorkflow = activationResult.workflow;
        const nextWorkflowPath = `${projectRoot}/.agents/workflows/${validatedWorkflow.metadata.slug}.workflow.json`;
        const nextValidation = validateWorkflowProject(
          validatedWorkflow,
          packageFork.tests,
        );
        setWorkflowPath(nextWorkflowPath);
        setTestsPath(
          nextWorkflowPath.replace(/\.workflow\.json$/, ".tests.json"),
        );
        setTests(packageFork.tests);
        setProposals([]);
        setRuns([]);
        loadWorkflowProject(validatedWorkflow);
        setHarnessActivationCandidate(null);
        setValidationResult(nextValidation);
        setReadinessResult(
          evaluateWorkflowActivationReadiness(
            validatedWorkflow,
            packageFork.tests,
            nextValidation,
            [],
            [],
          ),
        );
        setRightPanel("settings");
        setBottomPanel("selection");
        await nextHarnessWorkbenchFrame();
        await restorePackageGate();
        beforeSelectedState = readHarnessRailSelectedState(selectedRailTestId);
        packageReviewState = readHarnessPackageEvidenceReviewState();
        gateId =
          beforeSelectedState["data-selected-activation-gate-id"] || null;

        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-manifest-0",
            "package_evidence_manifest_ref_button_missing",
          )
        ) {
          evidenceState = readHarnessRailSelectedState(selectedRailTestId);
        }
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-receipts-0",
            "package_evidence_receipt_ref_button_missing",
          )
        ) {
          receiptState = readHarnessRailSelectedState(selectedRailTestId);
        }
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-replay-fixtures-0",
            "package_evidence_replay_ref_button_missing",
          )
        ) {
          replayState = readHarnessRailSelectedState(selectedRailTestId);
        }
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-worker-handoff-attempts-0",
            "package_evidence_node_attempt_ref_button_missing",
          )
        ) {
          nodeAttemptState = readHarnessRailSelectedState(selectedRailTestId);
        }
        await restorePackageGate();
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-fork-mutation-canary-0",
            "package_evidence_mutation_canary_ref_button_missing",
          )
        ) {
          mutationCanaryState = readHarnessRailSelectedState(selectedRailTestId);
          const mutationAttemptId =
            mutationCanaryState[
              "data-selected-activation-gate-node-attempt-id"
            ] ||
            mutationCanaryState["data-node-attempt-id"] ||
            "";
          const selectedTimelineAttempt =
            mutationAttemptId.length > 0
              ? document.querySelector<HTMLElement>(
                  `[data-testid="workflow-harness-activation-gate-node-timeline-${mutationAttemptId}"]`,
                )
              : null;
          mutationCanaryTimelineAttemptId =
            selectedTimelineAttempt?.dataset.nodeAttemptId ?? null;
        }
        await restorePackageGate();
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-deep-links-0",
            "package_evidence_deep_link_ref_button_missing",
          )
        ) {
          packageDeepLinkState = readHarnessRailSelectedState(selectedRailTestId);
        }
      } catch (error) {
        blockers.push(`package_evidence_gate_click_failed:${errorMessage(error)}`);
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }

      const manifest =
        validatedWorkflow?.metadata.harness?.packageManifest ??
        validatedWorkflow?.metadata.harness?.activationRecord?.packageManifest ??
        null;
      const selectedEvidenceRef =
        manifest?.workflowId ?? manifest?.activationId ?? null;
      const selectedReceiptRef = manifest?.receiptRefs?.[0] ?? null;
      const selectedReplayFixtureRef = manifest?.replayFixtureRefs?.[0] ?? null;
      const selectedNodeAttemptId =
        manifest?.workerHandoffNodeAttemptIds?.[0] ?? null;
      const selectedMutationCanary = manifest?.forkMutationCanary ?? null;
      const selectedMutationCanaryAttemptId =
        selectedMutationCanary?.nodeAttempts?.[0]?.attemptId ??
        manifest?.forkMutationCanaryNodeAttemptIds?.[0] ??
        selectedMutationCanary?.nodeAttemptIds?.[0] ??
        null;
      const selectedMutationCanaryReceiptRef =
        manifest?.forkMutationCanaryReceiptRefs?.[0] ??
        selectedMutationCanary?.receiptRefs?.[0] ??
        null;
      const selectedMutationCanaryReplayFixtureRef =
        manifest?.forkMutationCanaryReplayFixtureRefs?.[0] ??
        selectedMutationCanary?.replayFixtureRefs?.[0] ??
        null;
      const selectedPackageDeepLink =
        manifest?.deepLinks?.find((link) => link.kind !== "activation") ??
        manifest?.deepLinks?.[0] ??
        null;
      if (
        selectedMutationCanaryAttemptId &&
        mutationCanaryNodeAttemptState["data-node-attempt-id"] !==
          selectedMutationCanaryAttemptId
      ) {
        const nodeInspectorLink = {
          panel: "outputs" as WorkflowRightPanel,
          activationGateId: "mutation-canary",
          activationGateEvidenceRef:
            selectedMutationCanary?.canaryId ?? undefined,
          activationGateNodeAttemptId: selectedMutationCanaryAttemptId,
          nodeAttemptId: selectedMutationCanaryAttemptId,
          activationGateReceiptRef:
            selectedMutationCanaryReceiptRef ?? undefined,
          receiptRef: selectedMutationCanaryReceiptRef ?? undefined,
          activationGateReplayFixtureRef:
            selectedMutationCanaryReplayFixtureRef ?? undefined,
          replayFixtureRef: selectedMutationCanaryReplayFixtureRef ?? undefined,
        };
        const nodeInspectorHash =
          encodeHarnessWorkbenchDeepLink(nodeInspectorLink);
        const nodeInspectorParsed =
          parseHarnessWorkbenchDeepLink(nodeInspectorHash);
        if (nodeInspectorParsed) {
          writeHarnessWorkbenchDeepLink(nodeInspectorHash);
          applyHarnessWorkbenchDeepLink(nodeInspectorParsed);
          await nextHarnessWorkbenchFrame();
          writeHarnessWorkbenchDeepLink(nodeInspectorHash);
          await nextHarnessWorkbenchFrame();
          mutationCanaryNodeAttemptState = readHarnessRailSelectedState(
            "workflow-harness-node-attempt-inspector",
          );
        }
      }
      if (gateId !== "package-evidence") {
        blockers.push("package_evidence_gate_not_selected");
      }
      if (packageReviewState["data-harness-package-manifest-present"] !== "true") {
        blockers.push("package_evidence_manifest_not_visible");
      }
      if (packageReviewState["data-harness-package-evidence-ready"] !== "true") {
        blockers.push("package_evidence_not_ready");
      }
      [
        ["data-harness-package-receipt-ref-count", "package_evidence_receipts_missing"],
        [
          "data-harness-package-replay-fixture-ref-count",
          "package_evidence_replay_fixtures_missing",
        ],
        [
          "data-harness-package-rollback-restore-ref-count",
          "package_evidence_rollback_restore_refs_missing",
        ],
        [
          "data-harness-package-fork-mutation-receipt-count",
          "package_evidence_fork_mutation_receipts_missing",
        ],
        [
          "data-harness-package-fork-mutation-replay-count",
          "package_evidence_fork_mutation_replay_fixtures_missing",
        ],
        [
          "data-harness-package-fork-mutation-attempt-count",
          "package_evidence_fork_mutation_node_attempts_missing",
        ],
        [
          "data-harness-package-worker-handoff-attempt-count",
          "package_evidence_worker_handoff_attempts_missing",
        ],
        [
          "data-harness-package-worker-handoff-receipt-count",
          "package_evidence_worker_handoff_receipts_missing",
        ],
        ["data-harness-package-deep-link-count", "package_evidence_deep_links_missing"],
      ].forEach(([key, blocker]) => {
        if (readCount(packageReviewState, key) <= 0) blockers.push(blocker);
      });
      if (
        selectedEvidenceRef &&
        evidenceState["data-selected-activation-gate-evidence-ref"] !==
          selectedEvidenceRef
      ) {
        blockers.push("package_evidence_evidence_ref_not_restored");
      }
      if (
        selectedReceiptRef &&
        receiptState["data-selected-activation-gate-receipt-ref"] !==
          selectedReceiptRef
      ) {
        blockers.push("package_evidence_receipt_ref_not_restored");
      }
      if (
        selectedReplayFixtureRef &&
        replayState["data-selected-activation-gate-replay-fixture-ref"] !==
          selectedReplayFixtureRef
      ) {
        blockers.push("package_evidence_replay_ref_not_restored");
      }
      if (
        selectedNodeAttemptId &&
        nodeAttemptState["data-selected-activation-gate-node-attempt-id"] !==
          selectedNodeAttemptId
      ) {
        blockers.push("package_evidence_node_attempt_not_restored");
      }
      if (
        selectedMutationCanary &&
        mutationCanaryState["data-selected-activation-gate-id"] !==
          "mutation-canary"
      ) {
        blockers.push("package_evidence_mutation_canary_gate_not_restored");
      }
      if (
        selectedMutationCanary?.canaryId &&
        mutationCanaryState["data-selected-activation-gate-evidence-ref"] !==
          selectedMutationCanary.canaryId
      ) {
        blockers.push("package_evidence_mutation_canary_ref_not_restored");
      }
      if (
        selectedMutationCanaryAttemptId &&
        mutationCanaryState["data-selected-activation-gate-node-attempt-id"] !==
          selectedMutationCanaryAttemptId
      ) {
        blockers.push("package_evidence_mutation_canary_attempt_not_restored");
      }
      if (
        selectedMutationCanaryAttemptId &&
        mutationCanaryNodeAttemptState["data-node-attempt-id"] !==
          selectedMutationCanaryAttemptId
      ) {
        blockers.push(
          "package_evidence_mutation_canary_node_inspector_not_restored",
        );
      }
      if (
        selectedMutationCanaryAttemptId &&
        mutationCanaryTimelineAttemptId !== selectedMutationCanaryAttemptId
      ) {
        blockers.push("package_evidence_mutation_canary_timeline_not_restored");
      }
      if (
        selectedMutationCanaryReceiptRef &&
        !String(
          mutationCanaryNodeAttemptState["data-receipt-refs"] ?? "",
        ).includes(selectedMutationCanaryReceiptRef)
      ) {
        blockers.push("package_evidence_mutation_canary_receipt_missing");
      }
      if (
        selectedMutationCanaryReplayFixtureRef &&
        mutationCanaryNodeAttemptState["data-replay-fixture-ref"] !==
          selectedMutationCanaryReplayFixtureRef
      ) {
        blockers.push("package_evidence_mutation_canary_replay_missing");
      }
      if (
        selectedMutationCanary?.diffHash &&
        mutationCanaryNodeAttemptState["data-mutation-diff-hash"] !==
          selectedMutationCanary.diffHash
      ) {
        blockers.push("package_evidence_mutation_canary_diff_missing");
      }
      if (
        selectedMutationCanary?.rollbackTarget &&
        mutationCanaryNodeAttemptState["data-rollback-target"] !==
          selectedMutationCanary.rollbackTarget
      ) {
        blockers.push("package_evidence_mutation_canary_rollback_missing");
      }
      if (
        selectedPackageDeepLink &&
        !(
          packageDeepLinkState["data-selected-activation-gate-id"] ||
          packageDeepLinkState["data-selected-worker-binding-id"]
        )
      ) {
        blockers.push("package_evidence_deep_link_not_restored");
      }

      return {
        schemaVersion:
          "workflow.harness.package-evidence-gate-click-proof.v1",
        method:
          "same-session Workflows bridge stages a validated fork package, opens the package-evidence activation gate, and clicks preserved manifest receipt, replay, node-attempt, and deep-link refs",
        generatedAtMs,
        gateId,
        manifest: {
          present: Boolean(manifest),
          schemaVersion: manifest?.schemaVersion ?? null,
          status:
            packageReviewState["data-harness-package-evidence-ready"] || null,
          evidenceRefCount: readCount(
            packageReviewState,
            "data-harness-package-evidence-ref-count",
          ),
          receiptRefCount: readCount(
            packageReviewState,
            "data-harness-package-receipt-ref-count",
          ),
          replayFixtureRefCount: readCount(
            packageReviewState,
            "data-harness-package-replay-fixture-ref-count",
          ),
          rollbackRestoreReceiptRefCount: readCount(
            packageReviewState,
            "data-harness-package-rollback-restore-ref-count",
          ),
          forkMutationCanaryReceiptRefCount: readCount(
            packageReviewState,
            "data-harness-package-fork-mutation-receipt-count",
          ),
          forkMutationCanaryReplayFixtureRefCount: readCount(
            packageReviewState,
            "data-harness-package-fork-mutation-replay-count",
          ),
          forkMutationCanaryNodeAttemptCount: readCount(
            packageReviewState,
            "data-harness-package-fork-mutation-attempt-count",
          ),
          workerHandoffNodeAttemptCount: readCount(
            packageReviewState,
            "data-harness-package-worker-handoff-attempt-count",
          ),
          workerHandoffReceiptCount: readCount(
            packageReviewState,
            "data-harness-package-worker-handoff-receipt-count",
          ),
          deepLinkCount: readCount(
            packageReviewState,
            "data-harness-package-deep-link-count",
          ),
          blockerCount: readCount(
            packageReviewState,
            "data-harness-package-evidence-blocker-count",
          ),
        },
	        selectedRefs: {
	          evidenceRef: selectedEvidenceRef,
	          receiptRef: selectedReceiptRef,
	          replayFixtureRef: selectedReplayFixtureRef,
	          nodeAttemptId: selectedNodeAttemptId,
	          mutationCanaryId: selectedMutationCanary?.canaryId ?? null,
	          mutationCanaryReceiptRef: selectedMutationCanaryReceiptRef,
	          mutationCanaryReplayFixtureRef:
	            selectedMutationCanaryReplayFixtureRef,
	          mutationCanaryNodeAttemptId: selectedMutationCanaryAttemptId,
	          mutationCanaryDiffHash: selectedMutationCanary?.diffHash ?? null,
	          mutationCanaryRollbackTarget:
	            selectedMutationCanary?.rollbackTarget ?? null,
	          packageDeepLinkRef: selectedPackageDeepLink?.ref ?? null,
	          packageDeepLinkHash: selectedPackageDeepLink?.hash ?? null,
	        },
        before: {
          hash,
          railTestId: selectedRailTestId,
          selectedState: beforeSelectedState,
        },
        restored: {
          evidenceState,
          receiptState,
          replayState,
          nodeAttemptState,
          mutationCanaryState,
          mutationCanaryNodeAttemptState,
          mutationCanaryTimelineAttemptId,
          packageDeepLinkState,
        },
        clicked,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink, currentProject?.rootPath, loadWorkflowProject],
  );
  const runHarnessPackageEvidenceImportRoundTripProbe = useCallback(
    async (
      generatedAtMs: number,
    ): Promise<{
      packageEvidenceImportRoundTripProof: WorkflowHarnessPackageEvidenceImportRoundTripProof;
      packageImportReviewProof: WorkflowHarnessPackageImportReviewProof;
      packageImportActivationHandoffProof: WorkflowHarnessPackageImportActivationHandoffProof;
      packageImportActivationApplyProof: WorkflowHarnessPackageImportActivationApplyProof;
      packageImportActivationReplayIntegrityProof: WorkflowHarnessPackageImportActivationReplayIntegrityProof;
    }> => {
      const selectedRailTestId = "workflow-harness-activation-gate-inspector";
      const projectRoot = currentProject?.rootPath || ".";
      const sourceRoot = `${projectRoot}/target/harness-package-roundtrip-source-${generatedAtMs}`;
      const importRoot = `${projectRoot}/target/harness-package-roundtrip-import-${generatedAtMs}`;
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const link = {
        panel: "settings" as WorkflowRightPanel,
        activationGateId: "package-evidence",
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      const emptyManifest = {
        present: false,
        schemaVersion: null,
        status: null,
        evidenceRefCount: 0,
        receiptRefCount: 0,
        replayFixtureRefCount: 0,
        rollbackRestoreReceiptRefCount: 0,
        forkMutationCanaryReceiptRefCount: 0,
        forkMutationCanaryReplayFixtureRefCount: 0,
        forkMutationCanaryNodeAttemptCount: 0,
        workerHandoffNodeAttemptCount: 0,
        workerHandoffReceiptCount: 0,
        deepLinkCount: 0,
        blockerCount: 0,
      };
      const emptyRestored = {
        evidenceState: {},
        receiptState: {},
        replayState: {},
        nodeAttemptState: {},
        packageDeepLinkState: {},
      };
      let exportedPackagePath: string | null = null;
      let exportedManifestPath: string | null = null;
      let importedWorkflowPath: string | null = null;
      let packageImportReviewProof: WorkflowHarnessPackageImportReviewProof = {
        schemaVersion: "workflow.harness.package-import-review-proof.v1",
        method:
          "same-session Workflows bridge imports a portable harness package and opens source/import package evidence review before activation",
        generatedAtMs,
        review: null,
        railState: {},
        gateId: null,
        activationAction: {
          valid: {
            present: false,
            disabled: true,
            evidenceReady: false,
            blockerCount: 0,
          },
          incomplete: {
            present: false,
            disabled: true,
            evidenceReady: false,
            blockerCount: 0,
          },
        },
        sourceWorkflowPath: null,
        importedWorkflowPath: null,
        passed: false,
        blockers: ["package_import_review_not_exercised"],
      };
      const emptyHandoffAction = {
        present: false,
        disabled: true,
        evidenceReady: false,
        blockerCount: 0,
        handoffPresent: false,
        handoffDecision: null,
        activationIdPreview: null,
        canaryStatus: null,
        rollbackTarget: null,
        workerBindingId: null,
        mintable: false,
      };
      let packageImportActivationHandoffProof: WorkflowHarnessPackageImportActivationHandoffProof =
        {
          schemaVersion:
            "workflow.harness.package-import-activation-handoff-proof.v1",
          method:
            "same-session Workflows bridge imports a reviewed harness package and proves the activation handoff exposes candidate, canary, rollback, and worker binding routes",
          generatedAtMs,
          review: null,
          railState: {},
          activationAction: {
            valid: emptyHandoffAction,
            incomplete: emptyHandoffAction,
          },
          deepLinks: {
            activationId: {},
            canary: {},
            rollbackRestore: {},
            workerBinding: {},
          },
          passed: false,
          blockers: ["package_import_activation_handoff_not_exercised"],
        };
      const emptyPackageImportActivationAction = {
        present: false,
        disabled: true,
        evidenceReady: false,
        blockerCount: 0,
        handoffPresent: false,
        handoffDecision: null,
        activationIdPreview: null,
        canaryStatus: null,
        rollbackTarget: null,
        workerBindingId: null,
        mintable: false,
      };
      let packageImportActivationApplyProof: WorkflowHarnessPackageImportActivationApplyProof =
        {
          schemaVersion:
            "workflow.harness.package-import-activation-apply-proof.v1",
          method:
            "same-session Workflows bridge clicks Activate reviewed import and proves activation id, worker binding, rollback, audit, and handoff receipts are committed",
          generatedAtMs,
          review: null,
          clicked: false,
          beforeState: {},
          afterState: {},
          activationAction: emptyPackageImportActivationAction,
          activationResult: null,
          workerHandoff: {
            deepLinkHash: null,
            selectedState: {},
            timelineVisible: false,
            selectedAttemptId: null,
          },
          incompleteAction: emptyPackageImportActivationAction,
          passed: false,
          blockers: ["package_import_activation_apply_not_exercised"],
        };
      let packageImportActivationReplayIntegrityProof: WorkflowHarnessPackageImportActivationReplayIntegrityProof =
        {
          schemaVersion:
            "workflow.harness.package-import-activation-replay-integrity-proof.v1",
          method:
            "same-session Workflows bridge mutates reviewed package import identity fields and proves rail/runtime activation is blocked",
          generatedAtMs,
          sourceWorkflowPath: null,
          importedWorkflowPath: null,
          cases: [],
          passed: false,
          blockers: [
            "package_import_activation_replay_integrity_not_exercised",
          ],
        };
      let validImport: WorkflowHarnessPackageEvidenceImportRoundTripProof["validImport"] =
        {
          workflowId: null,
          workflowSlug: null,
          gateId: null,
          activationReadinessStatus: null,
          manifest: emptyManifest,
          rowStatuses: {},
          selectedRefs: {
            evidenceRef: null,
            receiptRef: null,
            replayFixtureRef: null,
            nodeAttemptId: null,
            packageDeepLinkRef: null,
            packageDeepLinkHash: null,
          },
          restored: emptyRestored,
          clicked: false,
        };
      let incompleteImport: WorkflowHarnessPackageEvidenceImportRoundTripProof["incompleteImport"] =
        {
          workflowId: null,
          gateId: null,
          activationReadinessStatus: null,
          readinessBlockerCodes: [],
          manifest: emptyManifest,
          rowStatuses: {},
          missingRows: [],
        };

      const readCount = (state: Record<string, string>, key: string) => {
        const value = Number(state[key] ?? 0);
        return Number.isFinite(value) ? value : 0;
      };
      const manifestCounts = (
        manifest:
          | WorkflowHarnessPackageEvidenceGateClickProof["selectedRefs"]
          | unknown,
        reviewState: Record<string, string>,
      ) => {
        const packageManifest = manifest as
          | NonNullable<WorkflowProject["metadata"]["harness"]>["packageManifest"]
          | null
          | undefined;
        return {
          present: Boolean(packageManifest),
          schemaVersion: packageManifest?.schemaVersion ?? null,
          status: reviewState["data-harness-package-evidence-ready"] || null,
          evidenceRefCount: readCount(
            reviewState,
            "data-harness-package-evidence-ref-count",
          ),
          receiptRefCount: readCount(
            reviewState,
            "data-harness-package-receipt-ref-count",
          ),
          replayFixtureRefCount: readCount(
            reviewState,
            "data-harness-package-replay-fixture-ref-count",
          ),
          rollbackRestoreReceiptRefCount: readCount(
            reviewState,
            "data-harness-package-rollback-restore-ref-count",
          ),
          forkMutationCanaryReceiptRefCount: readCount(
            reviewState,
            "data-harness-package-fork-mutation-receipt-count",
          ),
          forkMutationCanaryReplayFixtureRefCount: readCount(
            reviewState,
            "data-harness-package-fork-mutation-replay-count",
          ),
          forkMutationCanaryNodeAttemptCount: readCount(
            reviewState,
            "data-harness-package-fork-mutation-attempt-count",
          ),
          workerHandoffNodeAttemptCount: readCount(
            reviewState,
            "data-harness-package-worker-handoff-attempt-count",
          ),
          workerHandoffReceiptCount: readCount(
            reviewState,
            "data-harness-package-worker-handoff-receipt-count",
          ),
          deepLinkCount: readCount(
            reviewState,
            "data-harness-package-deep-link-count",
          ),
          blockerCount: readCount(
            reviewState,
            "data-harness-package-evidence-blocker-count",
          ),
        };
      };
      const selectedRefsFor = (
        manifest:
          | NonNullable<WorkflowProject["metadata"]["harness"]>["packageManifest"]
          | null
          | undefined,
      ) => {
        const selectedPackageDeepLink =
          manifest?.deepLinks?.find((packageLink) => packageLink.kind !== "activation") ??
          manifest?.deepLinks?.[0] ??
          null;
        return {
          evidenceRef: manifest?.workflowId ?? manifest?.activationId ?? null,
          receiptRef: manifest?.receiptRefs?.[0] ?? null,
          replayFixtureRef: manifest?.replayFixtureRefs?.[0] ?? null,
          nodeAttemptId: manifest?.workerHandoffNodeAttemptIds?.[0] ?? null,
          packageDeepLinkRef: selectedPackageDeepLink?.ref ?? null,
          packageDeepLinkHash: selectedPackageDeepLink?.hash ?? null,
        };
      };
      const restorePackageGate = async () => {
        if (!parsed) {
          blockers.push("package_evidence_import_gate_hash_parse_failed");
          return;
        }
        writeHarnessWorkbenchDeepLink(hash);
        applyHarnessWorkbenchDeepLink(parsed);
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
      };
      const clickPackageEvidenceRef = async (
        testId: string,
        missingBlocker: string,
      ) => {
        const button = document.querySelector<HTMLButtonElement>(
          `[data-testid="${testId}"]`,
        );
        if (!button) {
          blockers.push(missingBlocker);
          return false;
        }
        if (button.disabled) {
          blockers.push(`${missingBlocker}:disabled`);
          return false;
        }
        button.click();
        await nextHarnessWorkbenchFrame();
        await nextHarnessWorkbenchFrame();
        return true;
      };
      const clickPackageImportHandoffLink = async (
        testId: string,
        missingBlocker: string,
      ) => {
        await restorePackageGate();
        const button = document.querySelector<HTMLButtonElement>(
          `[data-testid="${testId}"]`,
        );
        if (!button) {
          blockers.push(missingBlocker);
          return {};
        }
        if (button.disabled) {
          blockers.push(`${missingBlocker}:disabled`);
          return {};
        }
        button.click();
        await nextHarnessWorkbenchFrame();
        await nextHarnessWorkbenchFrame();
        const selectedState = readHarnessRailSelectedState(selectedRailTestId);
        const deepLinkState = readHarnessRailSelectedState(
          "workflow-harness-deep-link-state",
        );
        const parsedHash =
          typeof window === "undefined"
            ? null
            : parseHarnessWorkbenchDeepLink(window.location.hash);
        const hashState: Record<string, string> = parsedHash
          ? {
              "data-selected-activation-gate-id":
                parsedHash.activationGateId ?? "",
              "data-selected-activation-gate-evidence-ref":
                parsedHash.activationGateEvidenceRef ?? "",
              "data-selected-worker-binding-id":
                parsedHash.workerBindingId ?? "",
              "data-selected-rollback-target": parsedHash.rollbackTarget ?? "",
            }
          : {};
        return {
          ...hashState,
          ...deepLinkState,
          ...Object.fromEntries(
            Object.entries(selectedState).filter(([, value]) => value),
          ),
        };
      };
      const readImportActivationAction = (
        review: WorkflowPackageImportReview | null,
      ) => {
        const button = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-package-import-activate"]',
        );
        const handoffState = readHarnessPackageImportHandoffState();
        return {
          present: Boolean(button),
          disabled: button?.disabled ?? true,
          evidenceReady: review?.evidence.packageEvidenceReady ?? false,
          blockerCount: review?.evidence.blockerCount ?? 0,
          integrityBlockerCount: readCount(
            {
              ...readHarnessPackageImportReviewState(),
              ...handoffState,
            },
            "data-package-import-replay-integrity-blocker-count",
          ),
          integrityBlockers: (
            readHarnessPackageImportReviewState()[
              "data-package-import-replay-integrity-blockers"
            ] ||
            handoffState[
              "data-package-import-handoff-replay-integrity-blockers"
            ] ||
            ""
          )
            .split(",")
            .filter(Boolean),
          handoffPresent:
            handoffState["data-package-import-handoff-open"] === "true",
          handoffDecision:
            handoffState["data-package-import-handoff-decision"] || null,
          activationIdPreview:
            handoffState["data-package-import-handoff-activation-id"] || null,
	          canaryStatus:
	            handoffState["data-package-import-handoff-canary-status"] || null,
          mutationCanaryId:
            handoffState[
              "data-package-import-handoff-mutation-canary-id"
            ] || null,
          mutationCanaryStatus:
            handoffState[
              "data-package-import-handoff-mutation-canary-status"
            ] || null,
          mutationCanaryDiffHash:
            handoffState[
              "data-package-import-handoff-mutation-canary-diff-hash"
            ] || null,
          mutationCanaryReceiptRef:
            handoffState[
              "data-package-import-handoff-mutation-canary-receipt-ref"
            ] || null,
          mutationCanaryReplayFixtureRef:
            handoffState[
              "data-package-import-handoff-mutation-canary-replay-fixture-ref"
            ] || null,
          mutationCanaryNodeAttemptId:
            handoffState[
              "data-package-import-handoff-mutation-canary-node-attempt-id"
            ] || null,
          mutationCanaryRollbackTarget:
            handoffState[
              "data-package-import-handoff-mutation-canary-rollback-target"
            ] || null,
	          rollbackTarget:
	            handoffState["data-package-import-handoff-rollback-target"] ||
	            null,
          workerBindingId:
            handoffState["data-package-import-handoff-worker-binding-id"] ||
            null,
          mintable:
            handoffState["data-package-import-handoff-mintable"] === "true",
        };
      };
      const clickPackageImportActivationApply = async () => {
        const applyBlockers: string[] = [];
        let clicked = false;
        let mintResult: HarnessActivationMintClickResult | null = null;
        let workerHandoffDeepLinkHash: string | null = null;
        let workerHandoffState: Record<string, string> = {};
        let workerHandoffTimelineVisible = false;
        let workerHandoffTimelineAttemptId: string | null = null;
        let mutationCanaryDeepLinkHash: string | null = null;
        let mutationCanaryState: Record<string, string> = {};
        let mutationCanaryNodeAttemptState: Record<string, string> = {};
        let mutationCanaryTimelineVisible = false;
        let mutationCanaryTimelineAttemptId: string | null = null;
        await restorePackageGate();
        const beforeState = {
          ...readHarnessPackageImportReviewState(),
          ...readHarnessPackageImportHandoffState(),
        };
        if (typeof window !== "undefined") {
          (window as any).__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT =
            null;
        }
        const button = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-package-import-activate"]',
        );
        if (!button) {
          applyBlockers.push("package_import_activation_apply_button_missing");
        } else if (button.disabled) {
          applyBlockers.push("package_import_activation_apply_button_disabled");
        } else {
          button.click();
          clicked = true;
          for (let attempt = 0; attempt < 80; attempt += 1) {
            await nextHarnessWorkbenchFrame();
            mintResult = readHarnessActivationMintClickResult();
            if (mintResult && typeof mintResult.applied === "boolean") break;
          }
        }
        await nextHarnessWorkbenchFrame();
        const afterState = {
          ...readHarnessPackageImportReviewState(),
          ...readHarnessPackageImportHandoffState(),
        };
        const workerHandoffNodeAttemptId =
          mintResult?.workerHandoffNodeAttemptIds[0] ?? null;
        if (workerHandoffNodeAttemptId) {
          const workerHandoffLink = {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: "worker-handoff",
            activationGateNodeAttemptId: workerHandoffNodeAttemptId,
            nodeAttemptId: workerHandoffNodeAttemptId,
            activationGateReceiptRef:
              mintResult?.workerHandoffReceiptIds[0] ?? undefined,
            receiptRef: mintResult?.workerHandoffReceiptIds[0] ?? undefined,
            activationGateReplayFixtureRef:
              mintResult?.workerHandoffReplayFixtureRefs[0] ?? undefined,
            replayFixtureRef:
              mintResult?.workerHandoffReplayFixtureRefs[0] ?? undefined,
          };
          workerHandoffDeepLinkHash =
            encodeHarnessWorkbenchDeepLink(workerHandoffLink);
          const workerHandoffParsed = parseHarnessWorkbenchDeepLink(
            workerHandoffDeepLinkHash,
          );
          if (workerHandoffParsed) {
            writeHarnessWorkbenchDeepLink(workerHandoffDeepLinkHash);
            applyHarnessWorkbenchDeepLink(workerHandoffParsed);
            await nextHarnessWorkbenchFrame();
            writeHarnessWorkbenchDeepLink(workerHandoffDeepLinkHash);
            await nextHarnessWorkbenchFrame();
            workerHandoffState = readHarnessRailSelectedState(selectedRailTestId);
            const timeline = document.querySelector<HTMLElement>(
              '[data-testid="workflow-harness-activation-gate-node-timeline"]',
            );
            const selectedTimelineAttempt =
              document.querySelector<HTMLElement>(
                `[data-node-attempt-id="${workerHandoffNodeAttemptId}"]`,
              );
            workerHandoffTimelineVisible = Boolean(timeline);
            workerHandoffTimelineAttemptId =
              selectedTimelineAttempt?.dataset.nodeAttemptId ?? null;
          } else {
            applyBlockers.push(
              "package_import_activation_apply_worker_handoff_link_parse_failed",
            );
          }
        }
        const mutationCanaryNodeAttemptId =
          mintResult?.reviewedForkMutationCanaryNodeAttemptIds?.[0] ?? null;
        if (mutationCanaryNodeAttemptId) {
          const mutationCanaryGateLink = {
            panel: "settings" as WorkflowRightPanel,
            activationGateId: "mutation-canary",
            activationGateEvidenceRef:
              mintResult?.reviewedForkMutationCanaryId ?? undefined,
            activationGateNodeAttemptId: mutationCanaryNodeAttemptId,
            nodeAttemptId: mutationCanaryNodeAttemptId,
            activationGateReceiptRef:
              mintResult?.reviewedForkMutationCanaryReceiptRefs?.[0] ??
              undefined,
            receiptRef:
              mintResult?.reviewedForkMutationCanaryReceiptRefs?.[0] ??
              undefined,
            activationGateReplayFixtureRef:
              mintResult?.reviewedForkMutationCanaryReplayFixtureRefs?.[0] ??
              undefined,
            replayFixtureRef:
              mintResult?.reviewedForkMutationCanaryReplayFixtureRefs?.[0] ??
              undefined,
          };
          mutationCanaryDeepLinkHash =
            encodeHarnessWorkbenchDeepLink(mutationCanaryGateLink);
          const mutationCanaryParsed = parseHarnessWorkbenchDeepLink(
            mutationCanaryDeepLinkHash,
          );
          if (mutationCanaryParsed) {
            writeHarnessWorkbenchDeepLink(mutationCanaryDeepLinkHash);
            applyHarnessWorkbenchDeepLink(mutationCanaryParsed);
            await nextHarnessWorkbenchFrame();
            writeHarnessWorkbenchDeepLink(mutationCanaryDeepLinkHash);
            await nextHarnessWorkbenchFrame();
            mutationCanaryState =
              readHarnessRailSelectedState(selectedRailTestId);
            mutationCanaryNodeAttemptState = readHarnessRailSelectedState(
              "workflow-harness-node-attempt-inspector",
            );
            const timeline = document.querySelector<HTMLElement>(
              '[data-testid="workflow-harness-activation-gate-node-timeline"]',
            );
            const selectedTimelineAttempt =
              document.querySelector<HTMLElement>(
                `[data-node-attempt-id="${mutationCanaryNodeAttemptId}"]`,
              );
            mutationCanaryTimelineVisible = Boolean(timeline);
            mutationCanaryTimelineAttemptId =
              selectedTimelineAttempt?.dataset.nodeAttemptId ?? null;
          } else {
            applyBlockers.push(
              "package_import_activation_apply_mutation_canary_link_parse_failed",
            );
          }
          const mutationCanaryInspectorLink = {
            ...mutationCanaryGateLink,
            panel: "outputs" as WorkflowRightPanel,
          };
          const mutationCanaryInspectorHash = encodeHarnessWorkbenchDeepLink(
            mutationCanaryInspectorLink,
          );
          const mutationCanaryInspectorParsed =
            parseHarnessWorkbenchDeepLink(mutationCanaryInspectorHash);
          if (mutationCanaryInspectorParsed) {
            writeHarnessWorkbenchDeepLink(mutationCanaryInspectorHash);
            applyHarnessWorkbenchDeepLink(mutationCanaryInspectorParsed);
            await nextHarnessWorkbenchFrame();
            writeHarnessWorkbenchDeepLink(mutationCanaryInspectorHash);
            await nextHarnessWorkbenchFrame();
            mutationCanaryNodeAttemptState = readHarnessRailSelectedState(
              "workflow-harness-node-attempt-inspector",
            );
          } else {
            applyBlockers.push(
              "package_import_activation_apply_mutation_canary_inspector_link_parse_failed",
            );
          }
        }
        return {
          clicked,
          beforeState,
          afterState,
          mintResult,
          workerHandoff: {
            deepLinkHash: workerHandoffDeepLinkHash,
            selectedState: workerHandoffState,
            timelineVisible: workerHandoffTimelineVisible,
            selectedAttemptId: workerHandoffTimelineAttemptId,
          },
          mutationCanary: {
            deepLinkHash: mutationCanaryDeepLinkHash,
            selectedState: mutationCanaryState,
            nodeAttemptState: mutationCanaryNodeAttemptState,
            timelineVisible: mutationCanaryTimelineVisible,
            selectedAttemptId: mutationCanaryTimelineAttemptId,
          },
          blockers: applyBlockers,
        };
      };
      const exercisePackageEvidenceReview = async (
        manifest:
          | NonNullable<WorkflowProject["metadata"]["harness"]>["packageManifest"]
          | null
          | undefined,
        blockerPrefix: string,
      ) => {
        let evidenceState: Record<string, string> = {};
        let receiptState: Record<string, string> = {};
        let replayState: Record<string, string> = {};
        let nodeAttemptState: Record<string, string> = {};
        let packageDeepLinkState: Record<string, string> = {};
        let clicked = false;
        await restorePackageGate();
        const selectedState = readHarnessRailSelectedState(selectedRailTestId);
        const reviewState = readHarnessPackageEvidenceReviewState();
        const rowStatuses = readHarnessPackageEvidenceRowStatuses();
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-manifest-0",
            `${blockerPrefix}_manifest_ref_button_missing`,
          )
        ) {
          clicked = true;
          evidenceState = readHarnessRailSelectedState(selectedRailTestId);
        }
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-receipts-0",
            `${blockerPrefix}_receipt_ref_button_missing`,
          )
        ) {
          clicked = true;
          receiptState = readHarnessRailSelectedState(selectedRailTestId);
        }
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-replay-fixtures-0",
            `${blockerPrefix}_replay_ref_button_missing`,
          )
        ) {
          clicked = true;
          replayState = readHarnessRailSelectedState(selectedRailTestId);
        }
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-worker-handoff-attempts-0",
            `${blockerPrefix}_node_attempt_ref_button_missing`,
          )
        ) {
          clicked = true;
          nodeAttemptState = readHarnessRailSelectedState(selectedRailTestId);
        }
        await restorePackageGate();
        if (
          await clickPackageEvidenceRef(
            "workflow-harness-package-evidence-row-ref-deep-links-0",
            `${blockerPrefix}_deep_link_ref_button_missing`,
          )
        ) {
          clicked = true;
          packageDeepLinkState = readHarnessRailSelectedState(selectedRailTestId);
        }
        return {
          gateId: selectedState["data-selected-activation-gate-id"] || null,
          manifest: manifestCounts(manifest, reviewState),
          rowStatuses,
          selectedRefs: selectedRefsFor(manifest),
          restored: {
            evidenceState,
            receiptState,
            replayState,
            nodeAttemptState,
            packageDeepLinkState,
          },
          clicked,
        };
      };

      try {
        if (!runtime.exportWorkflowPackage) {
          blockers.push("package_evidence_roundtrip_export_unavailable");
        }
        if (!runtime.importWorkflowPackage) {
          blockers.push("package_evidence_roundtrip_import_unavailable");
        }
        if (!runtime.saveWorkflowTests) {
          blockers.push("package_evidence_roundtrip_save_tests_unavailable");
        }
        if (!runtime.exportWorkflowPackage || !runtime.importWorkflowPackage) {
          throw new Error("Package export/import APIs unavailable");
        }

        const packageFork = forkDefaultAgentHarnessWorkflow(
          "Package Evidence Import Roundtrip Fork",
          generatedAtMs + 10,
        );
        let packageWorkflow = packageFork.workflow;
        HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS.forEach((clusterId, index) => {
          packageWorkflow = workflowReadyForHarnessPromotion(
            packageWorkflow,
            clusterId,
            generatedAtMs + 20 + index,
          );
        });
        const { workflow: stagedWorkflow, candidate } =
          workflowWithMintableHarnessActivationCandidate(
            packageWorkflow,
            packageFork.tests,
            generatedAtMs + 40,
          );
        if (candidate.decision !== "mintable") {
          blockers.push("package_evidence_roundtrip_candidate_not_mintable");
        }
        const activationResult = applyWorkflowHarnessActivationCandidate(
          stagedWorkflow,
          candidate,
          {
            rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            nowMs: generatedAtMs + 50,
          },
        );
        if (!activationResult.applied) {
          blockers.push(
            `package_evidence_roundtrip_activation_not_applied:${activationResult.blockers.join(",")}`,
          );
        }
        const validatedWorkflow = activationResult.workflow;
        const sourceWorkflowPath = `${sourceRoot}/.agents/workflows/${validatedWorkflow.metadata.slug}.workflow.json`;
        await (runtime.saveWorkflowProject
          ? runtime.saveWorkflowProject(sourceWorkflowPath, validatedWorkflow)
          : runtime.saveProject(sourceWorkflowPath, validatedWorkflow));
        if (runtime.saveWorkflowTests) {
          await runtime.saveWorkflowTests(sourceWorkflowPath, packageFork.tests);
        }
        const exported = await runtime.exportWorkflowPackage(
          sourceWorkflowPath,
          `${sourceRoot}/package`,
        );
        exportedPackagePath = exported.packagePath;
        exportedManifestPath = exported.manifestPath;
        if (exported.manifest.harnessPackageManifest?.schemaVersion !==
          "workflow.harness.package-evidence-manifest.v1") {
          blockers.push("package_evidence_roundtrip_export_manifest_missing");
        }
        if (!exported.manifest.portable) {
          blockers.push("package_evidence_roundtrip_export_not_portable");
        }

        const importedBundle = await runtime.importWorkflowPackage({
          packagePath: exported.packagePath,
          projectRoot: importRoot,
          name: "Imported Package Evidence Roundtrip Fork",
        });
        importedWorkflowPath = importedBundle.workflowPath;
        const importedValidation = validateWorkflowProject(
          importedBundle.workflow,
          importedBundle.tests,
        );
        const importedReadiness = evaluateWorkflowActivationReadiness(
          importedBundle.workflow,
          importedBundle.tests,
          importedValidation,
          importedBundle.proposals,
          [],
        );
        const importedRollbackRevisionBinding =
          importedBundle.workflow.metadata.harness?.activationRecord
            ?.rollbackRevisionBinding ??
          importedBundle.workflow.metadata.harness?.activationRollbackProof
            ?.restoredRevisionBinding ??
          null;
        const {
          rollbackRestoreResult: importedRollbackRestoreResult,
          rollbackRestoreBlockers: importedRollbackRestoreBlockers,
        } = await runWorkflowHarnessRollbackRestoreCanaryProbe({
          runtime,
          workflowPath: importedBundle.workflowPath,
          rollbackRevisionBinding: importedRollbackRevisionBinding,
        });
        const preflightValidImportReview = createWorkflowPackageImportReview({
          bundle: importedBundle,
          packagePath: exported.packagePath,
          projectRoot: importRoot,
          readinessStatus: importedReadiness.status,
          importedAtMs: generatedAtMs + 59,
        });
        const importedActivationCandidate =
          createWorkflowPackageImportActivationCandidate({
            workflow: importedBundle.workflow,
            tests: importedBundle.tests,
            readiness: importedReadiness,
            proposals: importedBundle.proposals,
            createdAtMs: generatedAtMs + 58,
            rollbackRestoreResult: importedRollbackRestoreResult,
            rollbackRestoreBlockers: importedRollbackRestoreBlockers,
            packageEvidenceReady:
              preflightValidImportReview.evidence.packageEvidenceReady,
          });
        setWorkflowPath(importedBundle.workflowPath);
        setTestsPath(importedBundle.testsPath);
        setTests(importedBundle.tests);
        setProposals(importedBundle.proposals);
        setRuns(importedBundle.runs);
        loadWorkflowProject(importedBundle.workflow);
        setValidationResult(importedValidation);
        setReadinessResult(importedReadiness);
        setPortablePackage(importedBundle.importedPackage ?? null);
        const validImportReview = createWorkflowPackageImportReview({
          bundle: importedBundle,
          packagePath: exported.packagePath,
          projectRoot: importRoot,
          readinessStatus: importedReadiness.status,
          importedAtMs: generatedAtMs + 60,
          activationCandidate: importedActivationCandidate,
        });
        setPackageImportReview(validImportReview);
        setHarnessActivationCandidate(importedActivationCandidate);
        setRightPanel("settings");
        setBottomPanel("selection");
        await nextHarnessWorkbenchFrame();
        const importedManifest =
          importedBundle.workflow.metadata.harness?.packageManifest ??
          importedBundle.workflow.metadata.harness?.activationRecord
            ?.packageManifest ??
          null;
        const validReview = await exercisePackageEvidenceReview(
          importedManifest,
          "package_evidence_roundtrip_valid_import",
        );
        validImport = {
          workflowId: importedBundle.workflow.metadata.id,
          workflowSlug: importedBundle.workflow.metadata.slug,
          activationReadinessStatus: importedReadiness.status,
          ...validReview,
        };
        await restorePackageGate();
        const validImportReviewState = readHarnessPackageImportReviewState();
        const validImportActivationAction =
          readImportActivationAction(validImportReview);
        const validImportHandoffState = readHarnessPackageImportHandoffState();
        const activationHandoffLinkState =
          await clickPackageImportHandoffLink(
            "workflow-harness-package-import-handoff-activation-link",
            "package_import_handoff_activation_link_missing",
          );
        const canaryHandoffLinkState = await clickPackageImportHandoffLink(
          "workflow-harness-package-import-handoff-canary-link",
          "package_import_handoff_canary_link_missing",
        );
        const mutationCanaryHandoffLinkState =
          await clickPackageImportHandoffLink(
            "workflow-harness-package-import-handoff-mutation-canary-link",
            "package_import_handoff_mutation_canary_link_missing",
          );
        const rollbackHandoffLinkState = await clickPackageImportHandoffLink(
          "workflow-harness-package-import-handoff-rollback-link",
          "package_import_handoff_rollback_link_missing",
        );
        const workerHandoffLinkState = await clickPackageImportHandoffLink(
          "workflow-harness-package-import-handoff-worker-link",
          "package_import_handoff_worker_link_missing",
        );
        await restorePackageGate();
        const validImportActivationApply =
          await clickPackageImportActivationApply();

        const incompleteWorkflow: WorkflowProject = JSON.parse(
          JSON.stringify(importedBundle.workflow),
        ) as WorkflowProject;
        const incompleteManifest = importedManifest
          ? {
              ...importedManifest,
	              receiptRefs: [],
	              replayFixtureRefs: [],
	              rollbackRestoreReceiptRefs: [],
	              forkMutationCanaryReceiptRefs: [],
	              forkMutationCanaryReplayFixtureRefs: [],
	              forkMutationCanaryNodeAttemptIds: [],
	              workerHandoffNodeAttemptIds: [],
              workerHandoffReceiptIds: [],
              deepLinks: [],
            }
          : null;
        if (incompleteWorkflow.metadata.harness && incompleteManifest) {
          incompleteWorkflow.metadata.harness = {
            ...incompleteWorkflow.metadata.harness,
            packageManifest: incompleteManifest,
            activationRecord: incompleteWorkflow.metadata.harness
              .activationRecord
              ? {
                  ...incompleteWorkflow.metadata.harness.activationRecord,
                  packageManifest: incompleteManifest,
                }
              : incompleteWorkflow.metadata.harness.activationRecord,
          };
        }
        const incompleteValidation = validateWorkflowProject(
          incompleteWorkflow,
          importedBundle.tests,
        );
        const incompleteReadiness = evaluateWorkflowActivationReadiness(
          incompleteWorkflow,
          importedBundle.tests,
          incompleteValidation,
          importedBundle.proposals,
          [],
        );
        const incompleteRollbackRevisionBinding =
          incompleteWorkflow.metadata.harness?.activationRecord
            ?.rollbackRevisionBinding ??
          incompleteWorkflow.metadata.harness?.activationRollbackProof
            ?.restoredRevisionBinding ??
          null;
        const {
          rollbackRestoreResult: incompleteRollbackRestoreResult,
          rollbackRestoreBlockers: incompleteRollbackRestoreBlockers,
        } = await runWorkflowHarnessRollbackRestoreCanaryProbe({
          runtime,
          workflowPath: importedBundle.workflowPath,
          rollbackRevisionBinding: incompleteRollbackRevisionBinding,
        });
        const incompleteBundle = {
          ...importedBundle,
          workflow: incompleteWorkflow,
          importedPackage: importedBundle.importedPackage
            ? {
                ...importedBundle.importedPackage,
                manifest: {
                  ...importedBundle.importedPackage.manifest,
                  harnessPackageManifest: incompleteManifest ?? undefined,
                },
              }
            : importedBundle.importedPackage,
        };
        const preflightIncompleteImportReview = createWorkflowPackageImportReview({
          bundle: incompleteBundle,
          packagePath: exported.packagePath,
          projectRoot: importRoot,
          readinessStatus: incompleteReadiness.status,
          importedAtMs: generatedAtMs + 69,
        });
        const incompleteActivationCandidate =
          createWorkflowPackageImportActivationCandidate({
            workflow: incompleteWorkflow,
            tests: importedBundle.tests,
            readiness: incompleteReadiness,
            proposals: importedBundle.proposals,
            createdAtMs: generatedAtMs + 68,
            rollbackRestoreResult: incompleteRollbackRestoreResult,
            rollbackRestoreBlockers: incompleteRollbackRestoreBlockers,
            packageEvidenceReady:
              preflightIncompleteImportReview.evidence.packageEvidenceReady,
          });
        const incompleteImportReview = createWorkflowPackageImportReview({
          bundle: incompleteBundle,
          packagePath: exported.packagePath,
          projectRoot: importRoot,
          readinessStatus: incompleteReadiness.status,
          importedAtMs: generatedAtMs + 70,
          activationCandidate: incompleteActivationCandidate,
        });
        loadWorkflowProject(incompleteWorkflow);
        setValidationResult(incompleteValidation);
        setReadinessResult(incompleteReadiness);
        setPackageImportReview(incompleteImportReview);
        setHarnessActivationCandidate(incompleteActivationCandidate);
        setRightPanel("settings");
        setBottomPanel("selection");
        await nextHarnessWorkbenchFrame();
        await restorePackageGate();
        const incompleteImportActivationAction =
          readImportActivationAction(incompleteImportReview);
        const incompleteImportHandoffState =
          readHarnessPackageImportHandoffState();
        const incompleteReviewState = readHarnessPackageEvidenceReviewState();
        const incompleteRowStatuses = readHarnessPackageEvidenceRowStatuses();
        const readinessBlockerCodes = [
          ...incompleteReadiness.errors,
          ...incompleteReadiness.warnings,
          ...(incompleteReadiness.executionReadinessIssues ?? []),
        ].map((issue) => issue.code);
        incompleteImport = {
          workflowId: incompleteWorkflow.metadata.id,
          gateId:
            readHarnessRailSelectedState(selectedRailTestId)[
              "data-selected-activation-gate-id"
            ] || null,
          activationReadinessStatus: incompleteReadiness.status,
          readinessBlockerCodes,
          manifest: manifestCounts(incompleteManifest, incompleteReviewState),
          rowStatuses: incompleteRowStatuses,
          missingRows: readHarnessPackageEvidenceMissingRows(),
        };
        const packageImportReviewBlockers: string[] = [];
        if (
          validImportReviewState["data-package-import-review-open"] !== "true"
        ) {
          packageImportReviewBlockers.push("package_import_review_not_open");
        }
        if (
          validImportReviewState["data-package-import-source-workflow-path"] !==
          (validImportReview.source.sourceWorkflowPath ?? "")
        ) {
          packageImportReviewBlockers.push("package_import_source_path_mismatch");
        }
        if (
          validImportReviewState["data-package-import-imported-workflow-path"] !==
          validImportReview.imported.workflowPath
        ) {
          packageImportReviewBlockers.push(
            "package_import_imported_path_mismatch",
          );
        }
        if (!validImportReview.evidence.packageEvidenceReady) {
          packageImportReviewBlockers.push(
            "package_import_valid_evidence_not_ready",
          );
        }
        if (validImportActivationAction.disabled) {
          packageImportReviewBlockers.push(
            "package_import_valid_activation_disabled",
          );
        }
        if (!incompleteImportActivationAction.disabled) {
          packageImportReviewBlockers.push(
            "package_import_incomplete_activation_enabled",
          );
        }
        if (incompleteImportReview.evidence.packageEvidenceReady) {
          packageImportReviewBlockers.push(
            "package_import_incomplete_evidence_ready",
          );
        }
        const packageImportActivationHandoffBlockers: string[] = [];
        if (!validImportActivationAction.handoffPresent) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_not_present",
          );
        }
        if (validImportActivationAction.handoffDecision !== "mintable") {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_not_mintable",
          );
        }
        if (!validImportActivationAction.activationIdPreview) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_activation_id_missing",
          );
        }
        if (validImportActivationAction.canaryStatus !== "passed") {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_canary_not_passed",
          );
        }
        if (!validImportActivationAction.rollbackTarget) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_rollback_target_missing",
          );
        }
        if (!validImportActivationAction.workerBindingId) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_worker_binding_missing",
          );
        }
        if (validImportHandoffState["data-package-import-handoff-open"] !== "true") {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_rail_not_open",
          );
        }
        if (
          validImportHandoffState[
            "data-package-import-handoff-activation-id"
          ] !== validImportActivationAction.activationIdPreview
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_activation_id_mismatch",
          );
        }
        if (
          activationHandoffLinkState["data-selected-activation-gate-id"] !==
          "activation-id"
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_activation_link_not_restored",
          );
        }
        if (
          canaryHandoffLinkState["data-selected-activation-gate-id"] !==
          "canary"
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_canary_link_not_restored",
          );
        }
        if (
          mutationCanaryHandoffLinkState["data-selected-activation-gate-id"] !==
            "mutation-canary" ||
          mutationCanaryHandoffLinkState[
            "data-selected-activation-gate-node-attempt-id"
          ] !== validImportActivationAction.mutationCanaryNodeAttemptId
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_mutation_canary_link_not_restored",
          );
        }
        if (
          rollbackHandoffLinkState["data-selected-activation-gate-id"] !==
          "rollback-restore"
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_rollback_link_not_restored",
          );
        }
        if (
          workerHandoffLinkState["data-selected-worker-binding-id"] !==
          validImportActivationAction.workerBindingId
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_handoff_worker_link_not_restored",
          );
        }
        if (!incompleteImportActivationAction.handoffPresent) {
          packageImportActivationHandoffBlockers.push(
            "package_import_incomplete_handoff_not_present",
          );
        }
        if (!incompleteImportActivationAction.disabled) {
          packageImportActivationHandoffBlockers.push(
            "package_import_incomplete_handoff_activation_enabled",
          );
        }
        if (incompleteImportActivationAction.mintable) {
          packageImportActivationHandoffBlockers.push(
            "package_import_incomplete_handoff_mintable",
          );
        }
        if (
          incompleteImportHandoffState[
            "data-package-import-handoff-package-evidence-ready"
          ] !== "false"
        ) {
          packageImportActivationHandoffBlockers.push(
            "package_import_incomplete_handoff_evidence_ready",
          );
        }
        const packageImportActivationApplyBlockers = [
          ...validImportActivationApply.blockers,
        ];
        const applyResult = validImportActivationApply.mintResult;
        if (!validImportActivationApply.clicked) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_not_clicked",
          );
        }
        if (applyResult?.applied !== true) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_not_applied",
          );
        }
        if (
          applyResult?.activationId !==
          validImportActivationAction.activationIdPreview
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_activation_id_mismatch",
          );
        }
        if (applyResult?.workflowActivationId !== applyResult?.activationId) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_workflow_activation_mismatch",
          );
        }
        if (applyResult?.workflowActivationState !== "validated") {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_state_not_validated",
          );
        }
        if (
          applyResult?.workerBindingActivationId !== applyResult?.activationId
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_worker_binding_mismatch",
          );
        }
        if (
          applyResult?.activationRecordWorkerBindingActivationId !==
          applyResult?.activationId
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_record_worker_binding_mismatch",
          );
        }
        if (applyResult?.rollbackTarget !== validImportActivationAction.rollbackTarget) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_rollback_target_mismatch",
          );
        }
        if (
          validImportReview.source.reviewedPackageSnapshotHash &&
          applyResult?.reviewedPackageSnapshotHash !==
            validImportReview.source.reviewedPackageSnapshotHash
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_replay_integrity_snapshot_hash_mismatch",
          );
        }
        if (
          applyResult?.revisionBindingActivationId !== applyResult?.activationId
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_revision_binding_mismatch",
          );
        }
        if (!applyResult?.activationRecordRevisionBindingHash) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_revision_hash_missing",
          );
        }
        if (!applyResult?.rollbackRevisionBindingHash) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_rollback_hash_missing",
          );
        }
        if (applyResult?.latestAuditEventType !== "activation_minted") {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_audit_type_mismatch",
          );
        }
        if (applyResult?.latestAuditStatus !== "applied") {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_audit_status_mismatch",
          );
        }
        if ((applyResult?.receiptRefs.length ?? 0) <= 0) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_receipts_missing",
          );
        }
        if ((applyResult?.evidenceRefs.length ?? 0) <= 0) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_evidence_missing",
          );
        }
        if ((applyResult?.workerHandoffReceiptIds.length ?? 0) <= 0) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_worker_handoff_receipts_missing",
          );
        }
        if ((applyResult?.workerHandoffNodeAttemptIds.length ?? 0) <= 0) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_worker_handoff_attempts_missing",
          );
        }
        if ((applyResult?.workerHandoffReplayFixtureRefs.length ?? 0) <= 0) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_worker_handoff_replay_missing",
          );
        }
        if (!applyResult?.reviewedForkMutationCanaryId) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_missing",
          );
        }
        if (applyResult?.reviewedForkMutationCanaryStatus !== "passed") {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_not_passed",
          );
        }
        if (!applyResult?.reviewedForkMutationCanaryDiffHash) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_diff_missing",
          );
        }
        if (
          (applyResult?.reviewedForkMutationCanaryReceiptRefs?.length ?? 0) <= 0
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_receipt_missing",
          );
        }
        if (
          (applyResult?.reviewedForkMutationCanaryReplayFixtureRefs?.length ??
            0) <= 0
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_replay_missing",
          );
        }
        if (
          (applyResult?.reviewedForkMutationCanaryNodeAttemptIds?.length ?? 0) <=
          0
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_attempt_missing",
          );
        }
        if (!applyResult?.reviewedForkMutationCanaryRollbackTarget) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_fork_mutation_canary_rollback_missing",
          );
        }
        const expectedApplyHandoffAttempt =
          applyResult?.workerHandoffNodeAttemptIds[0] ?? null;
        if (
          expectedApplyHandoffAttempt &&
          !validImportActivationApply.workerHandoff.deepLinkHash?.includes(
            "activationGateNodeAttemptId=",
          )
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_handoff_node_link_missing",
          );
        }
        if (
          expectedApplyHandoffAttempt &&
          validImportActivationApply.workerHandoff.selectedState[
            "data-selected-activation-gate-id"
          ] !== "worker-handoff"
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_handoff_gate_not_restored",
          );
        }
        if (
          expectedApplyHandoffAttempt &&
          validImportActivationApply.workerHandoff.selectedState[
            "data-selected-activation-gate-node-attempt-id"
          ] !== expectedApplyHandoffAttempt
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_handoff_attempt_not_restored",
          );
        }
        if (
          expectedApplyHandoffAttempt &&
          !validImportActivationApply.workerHandoff.timelineVisible
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_handoff_timeline_missing",
          );
        }
        if (
          expectedApplyHandoffAttempt &&
          validImportActivationApply.workerHandoff.selectedAttemptId !==
            expectedApplyHandoffAttempt
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_handoff_timeline_attempt_missing",
          );
        }
        const expectedApplyMutationCanaryAttempt =
          applyResult?.reviewedForkMutationCanaryNodeAttemptIds?.[0] ?? null;
        if (
          expectedApplyMutationCanaryAttempt &&
          !validImportActivationApply.mutationCanary.deepLinkHash?.includes(
            "activationGateNodeAttemptId=",
          )
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_mutation_canary_node_link_missing",
          );
        }
        if (
          expectedApplyMutationCanaryAttempt &&
          validImportActivationApply.mutationCanary.selectedState[
            "data-selected-activation-gate-id"
          ] !== "mutation-canary"
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_mutation_canary_gate_not_restored",
          );
        }
        if (
          expectedApplyMutationCanaryAttempt &&
          validImportActivationApply.mutationCanary.selectedState[
            "data-selected-activation-gate-node-attempt-id"
          ] !== expectedApplyMutationCanaryAttempt
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_mutation_canary_attempt_not_restored",
          );
        }
        if (
          expectedApplyMutationCanaryAttempt &&
          validImportActivationApply.mutationCanary.nodeAttemptState[
            "data-node-attempt-id"
          ] !== expectedApplyMutationCanaryAttempt
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_mutation_canary_node_inspector_missing",
          );
        }
        if (
          expectedApplyMutationCanaryAttempt &&
          !validImportActivationApply.mutationCanary.timelineVisible
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_mutation_canary_timeline_missing",
          );
        }
        if (
          expectedApplyMutationCanaryAttempt &&
          validImportActivationApply.mutationCanary.selectedAttemptId !==
            expectedApplyMutationCanaryAttempt
        ) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_mutation_canary_timeline_attempt_missing",
          );
        }
        if (!incompleteImportActivationAction.disabled) {
          packageImportActivationApplyBlockers.push(
            "package_import_activation_apply_incomplete_action_enabled",
          );
        }
        packageImportReviewProof = {
          schemaVersion: "workflow.harness.package-import-review-proof.v1",
          method:
            "same-session Workflows bridge imports a portable harness package, opens source/import package evidence review, and proves activation is gated by package evidence",
          generatedAtMs,
          review: validImportReview,
          railState: validImportReviewState,
          gateId: validReview.gateId,
          activationAction: {
            valid: validImportActivationAction,
            incomplete: incompleteImportActivationAction,
          },
          sourceWorkflowPath: validImportReview.source.sourceWorkflowPath,
          importedWorkflowPath: validImportReview.imported.workflowPath,
          passed: packageImportReviewBlockers.length === 0,
          blockers: packageImportReviewBlockers,
        };
        packageImportActivationHandoffProof = {
          schemaVersion:
            "workflow.harness.package-import-activation-handoff-proof.v1",
          method:
            "same-session Workflows bridge imports a reviewed harness package and proves the activation handoff exposes candidate, canary, rollback, and worker binding routes",
          generatedAtMs,
          review: validImportReview,
          railState: validImportHandoffState,
          activationAction: {
            valid: validImportActivationAction,
            incomplete: incompleteImportActivationAction,
          },
	          deepLinks: {
	            activationId: activationHandoffLinkState,
	            canary: canaryHandoffLinkState,
            mutationCanary: mutationCanaryHandoffLinkState,
	            rollbackRestore: rollbackHandoffLinkState,
	            workerBinding: workerHandoffLinkState,
	          },
          passed: packageImportActivationHandoffBlockers.length === 0,
          blockers: packageImportActivationHandoffBlockers,
        };
        packageImportActivationApplyProof = {
          schemaVersion:
            "workflow.harness.package-import-activation-apply-proof.v1",
          method:
            "same-session Workflows bridge clicks Activate reviewed import and proves activation id, worker binding, rollback, audit, and handoff receipts are committed",
          generatedAtMs,
          review: validImportReview,
          clicked: validImportActivationApply.clicked,
          beforeState: validImportActivationApply.beforeState,
          afterState: validImportActivationApply.afterState,
	          activationAction: validImportActivationAction,
	          activationResult: applyResult,
	          workerHandoff: validImportActivationApply.workerHandoff,
          mutationCanary: validImportActivationApply.mutationCanary,
	          incompleteAction: incompleteImportActivationAction,
          passed: packageImportActivationApplyBlockers.length === 0,
          blockers: packageImportActivationApplyBlockers,
        };
        const replayIntegrityCaseSpecs = [
          {
            caseId: "snapshot-hash-mismatch",
            mutationKind: "snapshot_hash_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_snapshot_hash_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.reviewedPackageSnapshotHash = `${review.source.reviewedPackageSnapshotHash ?? "stable-fnv1a32:missing"}:mismatch`;
            },
          },
          {
            caseId: "workflow-hash-mismatch",
            mutationKind: "workflow_hash_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_workflow_hash_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.workflowContentHash = `${review.source.workflowContentHash ?? "stable-fnv1a32:missing"}:mismatch`;
            },
          },
          {
            caseId: "activation-id-mismatch",
            mutationKind: "activation_id_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_activation_id_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.activationId = `${review.source.activationId ?? "activation:missing"}:mismatch`;
            },
          },
          {
            caseId: "worker-binding-mismatch",
            mutationKind: "worker_binding_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_worker_binding_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.workerBindingActivationId = "activation:mismatch";
            },
          },
          {
            caseId: "rollback-target-mismatch",
            mutationKind: "rollback_target_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_rollback_target_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.rollbackTarget = "activation:mismatch";
            },
          },
	          {
	            caseId: "replay-fixture-mismatch",
	            mutationKind: "replay_fixture_mismatch",
	            expectedBlocker:
	              "package_import_activation_replay_integrity_replay_fixture_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.replayFixtureRefs = [
                "harness-worker-handoff:fixture:mismatch",
	              ];
	            },
	          },
          {
            caseId: "fork-mutation-canary-mismatch",
            mutationKind: "fork_mutation_canary_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_fork_mutation_canary_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.forkMutationCanaryId = `${
                review.source.forkMutationCanaryId ??
                "harness-fork-mutation-canary:missing"
              }:mismatch`;
            },
          },
	          {
	            caseId: "policy-posture-mismatch",
            mutationKind: "policy_posture_mismatch",
            expectedBlocker:
              "package_import_activation_replay_integrity_policy_posture_mismatch",
            mutateReview: (review: WorkflowPackageImportReview) => {
              review.source.policyPosture =
                review.activationHandoff?.policyPosture === "live"
                  ? "proposal_only"
                  : "live";
            },
          },
        ] satisfies Array<{
          caseId: string;
          mutationKind:
            WorkflowHarnessPackageImportActivationReplayIntegrityProof["cases"][number]["mutationKind"];
          expectedBlocker: string;
          mutateReview: (review: WorkflowPackageImportReview) => void;
        }>;
        const replayIntegrityCases: WorkflowHarnessPackageImportActivationReplayIntegrityProof["cases"] =
          [];
        const replayIntegrityBlockers: string[] = [];
        for (const spec of replayIntegrityCaseSpecs) {
          const mismatchedReview = JSON.parse(
            JSON.stringify(validImportReview),
          ) as WorkflowPackageImportReview;
          spec.mutateReview(mismatchedReview);
          loadWorkflowProject(importedBundle.workflow);
          setValidationResult(importedValidation);
          setReadinessResult(importedReadiness);
          setPackageImportReview(mismatchedReview);
          setHarnessActivationCandidate(importedActivationCandidate);
          setRightPanel("settings");
          setBottomPanel("selection");
          await nextHarnessWorkbenchFrame();
          await restorePackageGate();
          const railState = {
            ...readHarnessPackageImportReviewState(),
            ...readHarnessPackageImportHandoffState(),
          };
          const action = readImportActivationAction(mismatchedReview);
          const mutatedProof: WorkflowHarnessPackageImportActivationApplyProof =
            {
              ...packageImportActivationApplyProof,
              review: mismatchedReview,
            };
          const runtimeBlockers =
            workflowHarnessPackageImportActivationApplyProofBlockers(
              mutatedProof,
              { nowMs: generatedAtMs },
            );
          const defaultLivePromotionBlockers =
            makeHarnessDefaultRuntimeDispatchProof({
              requireActivationIdGateClickProof: false,
              packageImportActivationApplyProof: mutatedProof,
              packageImportActivationApplyProofNowMs: generatedAtMs,
            }).defaultLivePromotionInvariantBlockers;
          const passed =
            action.present === true &&
            action.disabled === true &&
            action.integrityBlockerCount > 0 &&
            railState["data-package-import-activation-enabled"] === "false" &&
            runtimeBlockers.includes(spec.expectedBlocker) &&
            defaultLivePromotionBlockers.includes(spec.expectedBlocker);
          if (!passed) {
            replayIntegrityBlockers.push(
              `package_import_activation_replay_integrity_case_failed:${spec.caseId}`,
            );
          }
          replayIntegrityCases.push({
            caseId: spec.caseId,
            mutationKind: spec.mutationKind,
            expectedBlocker: spec.expectedBlocker,
            railState,
            action: {
              present: action.present,
              disabled: action.disabled,
              evidenceReady: action.evidenceReady,
              blockerCount: action.blockerCount,
              integrityBlockerCount: action.integrityBlockerCount,
              handoffPresent: action.handoffPresent,
              handoffDecision: action.handoffDecision,
	              activationIdPreview: action.activationIdPreview,
	              canaryStatus: action.canaryStatus,
              mutationCanaryId: action.mutationCanaryId,
              mutationCanaryStatus: action.mutationCanaryStatus,
              mutationCanaryDiffHash: action.mutationCanaryDiffHash,
              mutationCanaryReceiptRef: action.mutationCanaryReceiptRef,
              mutationCanaryReplayFixtureRef:
                action.mutationCanaryReplayFixtureRef,
              mutationCanaryNodeAttemptId:
                action.mutationCanaryNodeAttemptId,
              mutationCanaryRollbackTarget:
                action.mutationCanaryRollbackTarget,
	              rollbackTarget: action.rollbackTarget,
              workerBindingId: action.workerBindingId,
              mintable: action.mintable,
            },
            runtimeBlockers,
            defaultLivePromotionBlockers,
            passed,
          });
        }
        loadWorkflowProject(importedBundle.workflow);
        setValidationResult(importedValidation);
        setReadinessResult(importedReadiness);
        setPackageImportReview(validImportReview);
        setHarnessActivationCandidate(importedActivationCandidate);
        packageImportActivationReplayIntegrityProof = {
          schemaVersion:
            "workflow.harness.package-import-activation-replay-integrity-proof.v1",
          method:
            "same-session Workflows bridge mutates reviewed package import identity fields and proves rail/runtime activation is blocked",
          generatedAtMs,
          sourceWorkflowPath: validImportReview.source.sourceWorkflowPath,
          importedWorkflowPath: validImportReview.imported.workflowPath,
          cases: replayIntegrityCases,
          passed: replayIntegrityBlockers.length === 0,
          blockers: replayIntegrityBlockers,
        };
      } catch (error) {
        blockers.push(
          `package_evidence_import_roundtrip_failed:${errorMessage(error)}`,
        );
        packageImportReviewProof = {
          ...packageImportReviewProof,
          blockers: [
            ...packageImportReviewProof.blockers,
            `package_import_review_failed:${errorMessage(error)}`,
          ],
        };
        packageImportActivationHandoffProof = {
          ...packageImportActivationHandoffProof,
          blockers: [
            ...packageImportActivationHandoffProof.blockers,
            `package_import_activation_handoff_failed:${errorMessage(error)}`,
          ],
        };
        packageImportActivationApplyProof = {
          ...packageImportActivationApplyProof,
          blockers: [
            ...packageImportActivationApplyProof.blockers,
            `package_import_activation_apply_failed:${errorMessage(error)}`,
          ],
        };
        packageImportActivationReplayIntegrityProof = {
          ...packageImportActivationReplayIntegrityProof,
          blockers: [
            ...packageImportActivationReplayIntegrityProof.blockers,
            `package_import_activation_replay_integrity_failed:${errorMessage(error)}`,
          ],
        };
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }

      const selectedRefs = validImport.selectedRefs;
      if (validImport.gateId !== "package-evidence") {
        blockers.push("package_evidence_roundtrip_valid_gate_not_selected");
      }
      if (
        validImport.manifest.schemaVersion !==
        "workflow.harness.package-evidence-manifest.v1"
      ) {
        blockers.push("package_evidence_roundtrip_valid_schema_missing");
      }
      if (validImport.manifest.status !== "true") {
        blockers.push("package_evidence_roundtrip_valid_not_ready");
      }
      if (validImport.manifest.blockerCount !== 0) {
        blockers.push("package_evidence_roundtrip_valid_blockers_present");
      }
      if (
        validImport.manifest.receiptRefCount <= 0 ||
        validImport.manifest.replayFixtureRefCount <= 0 ||
        validImport.manifest.rollbackRestoreReceiptRefCount <= 0 ||
        validImport.manifest.forkMutationCanaryReceiptRefCount <= 0 ||
        validImport.manifest.forkMutationCanaryReplayFixtureRefCount <= 0 ||
        validImport.manifest.forkMutationCanaryNodeAttemptCount <= 0 ||
        validImport.manifest.workerHandoffNodeAttemptCount <= 0 ||
        validImport.manifest.workerHandoffReceiptCount <= 0 ||
        validImport.manifest.deepLinkCount <= 0
      ) {
        blockers.push("package_evidence_roundtrip_valid_refs_missing");
      }
      if (
        selectedRefs.receiptRef &&
        validImport.restored.receiptState[
          "data-selected-activation-gate-receipt-ref"
        ] !== selectedRefs.receiptRef
      ) {
        blockers.push("package_evidence_roundtrip_receipt_ref_not_restored");
      }
      if (
        selectedRefs.replayFixtureRef &&
        validImport.restored.replayState[
          "data-selected-activation-gate-replay-fixture-ref"
        ] !== selectedRefs.replayFixtureRef
      ) {
        blockers.push("package_evidence_roundtrip_replay_ref_not_restored");
      }
      if (
        selectedRefs.nodeAttemptId &&
        validImport.restored.nodeAttemptState[
          "data-selected-activation-gate-node-attempt-id"
        ] !== selectedRefs.nodeAttemptId
      ) {
        blockers.push("package_evidence_roundtrip_node_attempt_not_restored");
      }
      if (
        selectedRefs.packageDeepLinkHash &&
        !(
          validImport.restored.packageDeepLinkState[
            "data-selected-activation-gate-id"
          ] ||
          validImport.restored.packageDeepLinkState[
            "data-selected-worker-binding-id"
          ]
        )
      ) {
        blockers.push("package_evidence_roundtrip_deep_link_not_restored");
      }
      if (incompleteImport.gateId !== "package-evidence") {
        blockers.push("package_evidence_roundtrip_incomplete_gate_not_selected");
      }
      if (incompleteImport.manifest.status !== "false") {
        blockers.push("package_evidence_roundtrip_incomplete_not_blocked");
      }
      if (incompleteImport.manifest.blockerCount <= 0) {
        blockers.push("package_evidence_roundtrip_incomplete_blockers_missing");
      }
      if (
        !incompleteImport.readinessBlockerCodes.includes(
          "harness_package_manifest_incomplete",
        )
      ) {
        blockers.push(
          "package_evidence_roundtrip_incomplete_readiness_blocker_missing",
        );
      }
      [
        "receipts",
        "replay-fixtures",
        "rollback-restore",
        "fork-mutation-canary",
        "worker-handoff-attempts",
        "worker-handoff-receipts",
        "deep-links",
      ].forEach((rowId) => {
        if (!incompleteImport.missingRows.includes(rowId)) {
          blockers.push(`package_evidence_roundtrip_missing_row_absent:${rowId}`);
        }
      });

      return {
        packageEvidenceImportRoundTripProof: {
          schemaVersion:
            "workflow.harness.package-evidence-import-roundtrip-proof.v1",
          method:
            "same-session Workflows bridge saves a validated harness fork, exports a portable package, imports it into a fresh target root, clicks package-evidence refs, and verifies incomplete imported package blockers",
          generatedAtMs,
          exportedPackagePath,
          exportedManifestPath,
          importedWorkflowPath,
          validImport,
          incompleteImport,
          passed: blockers.length === 0,
          blockers,
        },
        packageImportReviewProof,
        packageImportActivationHandoffProof,
        packageImportActivationApplyProof,
        packageImportActivationReplayIntegrityProof,
      };
    },
    [
      applyHarnessWorkbenchDeepLink,
      currentProject?.rootPath,
      loadWorkflowProject,
      runtime,
    ],
  );
  const runHarnessActivationGateCollectEvidenceClickProbe = useCallback(
    async (
      generatedAtMs: number,
    ): Promise<WorkflowHarnessActivationGateCollectEvidenceClickProof> => {
      const selectedRailTestId = "workflow-harness-activation-gate-inspector";
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const link = {
        panel: "settings" as WorkflowRightPanel,
        activationGateId: "replay-fixtures",
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      let beforeSelectedState: Record<string, string> = {};
      let gateId: string | null = null;
      let actionId: string | null = null;
      let actionKind: string | null = null;
      let actionImpact: string | null = null;
      let actionCommand: string | null = null;
      let actionDisabled = false;
      let clicked = false;
      let replayGateResult: HarnessReplayGateClickResult | null = null;
      let afterRailTestId: string | null = null;
      let afterStatusMessage: string | null = null;
      let afterInspectorState: Record<string, string> = {};
      try {
        if (typeof window !== "undefined") {
          (window as any).__AUTOPILOT_HARNESS_REPLAY_GATE_CLICK_RESULT = null;
        }
        if (!parsed) {
          blockers.push("activation_gate_collect_evidence_hash_parse_failed");
        } else {
          writeHarnessWorkbenchDeepLink(hash);
          applyHarnessWorkbenchDeepLink(parsed);
        }
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
        beforeSelectedState = readHarnessRailSelectedState(selectedRailTestId);
        gateId =
          beforeSelectedState["data-selected-activation-gate-id"] || null;
        actionId = beforeSelectedState["data-gate-action-id"] || null;
        actionKind = beforeSelectedState["data-gate-action-kind"] || null;
        actionImpact = beforeSelectedState["data-gate-action-impact"] || null;
        actionCommand = beforeSelectedState["data-gate-action-command"] || null;
        actionDisabled =
          beforeSelectedState["data-gate-action-disabled"] === "true";
        const actionButton = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-activation-gate-action"]',
        );
        if (!actionButton) {
          blockers.push("activation_gate_collect_evidence_button_missing");
        } else if (actionButton.disabled || actionDisabled) {
          blockers.push("activation_gate_collect_evidence_button_disabled");
        } else {
          actionButton.click();
          clicked = true;
          for (let attempt = 0; attempt < 40; attempt += 1) {
            await nextHarnessWorkbenchFrame();
            replayGateResult = readHarnessReplayGateClickResult();
            if (replayGateResult?.gateId) break;
          }
          if (parsed) {
            applyHarnessWorkbenchDeepLink(parsed);
            writeHarnessWorkbenchDeepLink(hash);
            await nextHarnessWorkbenchFrame();
            await nextHarnessWorkbenchFrame();
            afterInspectorState =
              readHarnessRailSelectedState(selectedRailTestId);
          }
        }
      } catch (error) {
        blockers.push(
          `activation_gate_collect_evidence_click_failed:${errorMessage(error)}`,
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      afterRailTestId = readWorkflowRightRailTestId();
      afterStatusMessage = readWorkflowStatusMessage();
      if (gateId !== "replay-fixtures") {
        blockers.push("activation_gate_collect_evidence_gate_not_selected");
      }
      if (!actionId?.startsWith("activation-gate-action:replay-fixtures:")) {
        blockers.push("activation_gate_collect_evidence_action_id_missing");
      }
      if (actionKind !== "run_replay_gate") {
        blockers.push("activation_gate_collect_evidence_kind_not_replay_gate");
      }
      if (actionImpact !== "collect_evidence") {
        blockers.push("activation_gate_collect_evidence_impact_not_collect");
      }
      if (actionCommand !== "workflow-harness-gate-action-replay-fixtures") {
        blockers.push("activation_gate_collect_evidence_command_mismatch");
      }
      if (!clicked)
        blockers.push("activation_gate_collect_evidence_not_dispatched");
      if (!replayGateResult?.gateId) {
        blockers.push("activation_gate_collect_evidence_result_missing");
      }
      if ((replayGateResult?.totalFixtures ?? 0) <= 0) {
        blockers.push("activation_gate_collect_evidence_no_fixtures");
      }
      if ((replayGateResult?.replayGateCount ?? 0) <= 0) {
        blockers.push("activation_gate_collect_evidence_not_persisted");
      }
      if (
        afterInspectorState["data-selected-activation-gate-id"] !==
        "replay-fixtures"
      ) {
        blockers.push(
          "activation_gate_collect_evidence_inspector_not_restored",
        );
      }
      if (Number(afterInspectorState["data-evidence-ref-count"] ?? 0) <= 0) {
        blockers.push("activation_gate_collect_evidence_refs_not_visible");
      }
      return {
        schemaVersion:
          "workflow.harness.activation-gate-collect-evidence-click-proof.v1",
        method:
          "same-session Workflows bridge restores the replay fixtures activation gate, clicks its replay gate action, and verifies persisted replay gate evidence plus restored inspector metadata",
        generatedAtMs,
        gateId,
        action: {
          id: actionId,
          kind: actionKind,
          impact: actionImpact,
          command: actionCommand,
          disabled: actionDisabled,
        },
        before: {
          hash,
          railTestId: selectedRailTestId,
          selectedState: beforeSelectedState,
        },
        replayGate: {
          gateId: replayGateResult?.gateId ?? null,
          gateStatus: replayGateResult?.gateStatus ?? null,
          activationGateImpact: replayGateResult?.activationGateImpact ?? null,
          scopeKind: replayGateResult?.scopeKind ?? null,
          targetId: replayGateResult?.targetId ?? null,
          totalFixtures: replayGateResult?.totalFixtures ?? 0,
          replayFixtureRefs: replayGateResult?.replayFixtureRefs ?? [],
          receiptRefs: replayGateResult?.receiptRefs ?? [],
          evidenceRefs: replayGateResult?.evidenceRefs ?? [],
          persistedReplayGateCount: replayGateResult?.replayGateCount ?? 0,
          persistedReplayDrillCount: replayGateResult?.replayDrillCount ?? 0,
        },
        after: {
          railTestId: afterRailTestId,
          statusMessage: afterStatusMessage,
          inspectorState: afterInspectorState,
        },
        clicked,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActivationGateRollbackRestoreClickProbe = useCallback(
    async (
      generatedAtMs: number,
    ): Promise<WorkflowHarnessActivationGateRollbackRestoreClickProof> => {
      const selectedRailTestId = "workflow-harness-activation-gate-inspector";
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const link = {
        panel: "settings" as WorkflowRightPanel,
        activationGateId: "rollback-restore",
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      let beforeSelectedState: Record<string, string> = {};
      let gateId: string | null = null;
      let actionId: string | null = null;
      let actionKind: string | null = null;
      let actionImpact: string | null = null;
      let actionCommand: string | null = null;
      let actionDisabled = false;
      let clicked = false;
      let dryRunResult: HarnessActivationDryRunClickResult | null = null;
      let afterRailTestId: string | null = null;
      let afterStatusMessage: string | null = null;
      let afterInspectorState: Record<string, string> = {};
      let rollbackRestoreDeepLinkHash: string | null = null;
      let rollbackRestoreDeepLinkState: Record<string, string> = {};
      try {
        if (typeof window !== "undefined") {
          (window as any).__AUTOPILOT_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT =
            null;
        }
        if (!parsed) {
          blockers.push("activation_gate_rollback_restore_hash_parse_failed");
        } else {
          writeHarnessWorkbenchDeepLink(hash);
          applyHarnessWorkbenchDeepLink(parsed);
        }
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
        beforeSelectedState = readHarnessRailSelectedState(selectedRailTestId);
        gateId =
          beforeSelectedState["data-selected-activation-gate-id"] || null;
        actionId = beforeSelectedState["data-gate-action-id"] || null;
        actionKind = beforeSelectedState["data-gate-action-kind"] || null;
        actionImpact = beforeSelectedState["data-gate-action-impact"] || null;
        actionCommand = beforeSelectedState["data-gate-action-command"] || null;
        actionDisabled =
          beforeSelectedState["data-gate-action-disabled"] === "true";
        const actionButton = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-activation-gate-action"]',
        );
        if (!actionButton) {
          blockers.push("activation_gate_rollback_restore_button_missing");
        } else if (actionButton.disabled || actionDisabled) {
          blockers.push("activation_gate_rollback_restore_button_disabled");
        } else {
          actionButton.click();
          clicked = true;
          for (let attempt = 0; attempt < 80; attempt += 1) {
            await nextHarnessWorkbenchFrame();
            dryRunResult = readHarnessActivationDryRunClickResult();
            if (dryRunResult?.candidateId) break;
          }
          if (parsed) {
            applyHarnessWorkbenchDeepLink(parsed);
            writeHarnessWorkbenchDeepLink(hash);
            await nextHarnessWorkbenchFrame();
            await nextHarnessWorkbenchFrame();
            afterInspectorState =
              readHarnessRailSelectedState(selectedRailTestId);
            const rollbackRestoreReceiptRef =
              dryRunResult?.rollbackRestoreReceiptBindingRef ?? null;
            const rollbackRestoreCanaryId =
              dryRunResult?.rollbackRestoreCanaryId ?? null;
            if (rollbackRestoreReceiptRef && rollbackRestoreCanaryId) {
              const rollbackRestoreLink = {
                panel: "settings" as WorkflowRightPanel,
                activationGateId: "rollback-restore",
                activationGateEvidenceRef: rollbackRestoreCanaryId,
                activationGateReceiptRef: rollbackRestoreReceiptRef,
                receiptRef: rollbackRestoreReceiptRef,
              };
              rollbackRestoreDeepLinkHash = encodeHarnessWorkbenchDeepLink(
                rollbackRestoreLink,
              );
              const rollbackRestoreParsed = parseHarnessWorkbenchDeepLink(
                rollbackRestoreDeepLinkHash,
              );
              if (!rollbackRestoreParsed) {
                blockers.push(
                  "activation_gate_rollback_restore_deep_link_parse_failed",
                );
              } else {
                writeHarnessWorkbenchDeepLink(rollbackRestoreDeepLinkHash);
                applyHarnessWorkbenchDeepLink(rollbackRestoreParsed);
                await nextHarnessWorkbenchFrame();
                writeHarnessWorkbenchDeepLink(rollbackRestoreDeepLinkHash);
                await nextHarnessWorkbenchFrame();
                rollbackRestoreDeepLinkState =
                  readHarnessRailSelectedState(selectedRailTestId);
              }
            }
          }
        }
      } catch (error) {
        blockers.push(
          `activation_gate_rollback_restore_click_failed:${errorMessage(error)}`,
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }
      afterRailTestId = readWorkflowRightRailTestId();
      afterStatusMessage = readWorkflowStatusMessage();
      if (gateId !== "rollback-restore") {
        blockers.push("activation_gate_rollback_restore_gate_not_selected");
      }
      if (!actionId?.startsWith("activation-gate-action:rollback-restore:")) {
        blockers.push("activation_gate_rollback_restore_action_id_missing");
      }
      if (actionKind !== "run_activation_dry_run") {
        blockers.push("activation_gate_rollback_restore_kind_not_dry_run");
      }
      if (actionImpact !== "collect_evidence") {
        blockers.push("activation_gate_rollback_restore_impact_not_collect");
      }
      if (actionCommand !== "workflow-harness-gate-action-rollback-restore") {
        blockers.push("activation_gate_rollback_restore_command_mismatch");
      }
      if (!clicked)
        blockers.push("activation_gate_rollback_restore_not_dispatched");
      if (!dryRunResult?.candidateId) {
        blockers.push("activation_gate_rollback_restore_result_missing");
      }
      if (
        !["passed", "not_required"].includes(
          dryRunResult?.rollbackRestoreStatus ?? "",
        )
      ) {
        blockers.push("activation_gate_rollback_restore_canary_not_ready");
      }
      if (dryRunResult?.rollbackRestoreHashVerified !== true) {
        blockers.push("activation_gate_rollback_restore_hash_not_verified");
      }
      if (
        !dryRunResult?.rollbackRestoreReceiptBindingRef?.startsWith(
          "workflow_restore_canary:",
        )
      ) {
        blockers.push("activation_gate_rollback_restore_receipt_missing");
      }
      if ((dryRunResult?.rollbackRestoreEvidenceRefs.length ?? 0) <= 0) {
        blockers.push("activation_gate_rollback_restore_evidence_missing");
      }
      if ((dryRunResult?.activationAuditEventCount ?? 0) <= 0) {
        blockers.push("activation_gate_rollback_restore_audit_not_persisted");
      }
      if (dryRunResult?.rollbackRestoreGateStatus !== "passed") {
        blockers.push("activation_gate_rollback_restore_gate_not_passed");
      }
      if (
        afterInspectorState["data-selected-activation-gate-id"] !==
        "rollback-restore"
      ) {
        blockers.push(
          "activation_gate_rollback_restore_inspector_not_restored",
        );
      }
      if (Number(afterInspectorState["data-evidence-ref-count"] ?? 0) <= 0) {
        blockers.push("activation_gate_rollback_restore_refs_not_visible");
      }
      if (Number(afterInspectorState["data-receipt-ref-count"] ?? 0) <= 0) {
        blockers.push(
          "activation_gate_rollback_restore_receipt_refs_not_visible",
        );
      }
      if (!rollbackRestoreDeepLinkHash) {
        blockers.push("activation_gate_rollback_restore_deep_link_missing");
      }
      if (
        dryRunResult?.rollbackRestoreCanaryId &&
        rollbackRestoreDeepLinkState[
          "data-selected-rollback-restore-canary-id"
        ] !== dryRunResult.rollbackRestoreCanaryId
      ) {
        blockers.push(
          "activation_gate_rollback_restore_canary_deep_link_not_restored",
        );
      }
      if (
        dryRunResult?.rollbackRestoreReceiptBindingRef &&
        rollbackRestoreDeepLinkState[
          "data-selected-rollback-restore-receipt-ref"
        ] !== dryRunResult.rollbackRestoreReceiptBindingRef
      ) {
        blockers.push(
          "activation_gate_rollback_restore_receipt_deep_link_not_restored",
        );
      }
      return {
        schemaVersion:
          "workflow.harness.activation-gate-rollback-restore-click-proof.v1",
        method:
          "same-session Workflows bridge restores the rollback restore activation gate, clicks its dry-run action, and verifies rollback restore canary evidence, receipt binding, and activation audit persistence",
        generatedAtMs,
        gateId,
        action: {
          id: actionId,
          kind: actionKind,
          impact: actionImpact,
          command: actionCommand,
          disabled: actionDisabled,
        },
        before: {
          hash,
          railTestId: selectedRailTestId,
          selectedState: beforeSelectedState,
        },
        dryRun: {
          candidateId: dryRunResult?.candidateId ?? null,
          decision: dryRunResult?.decision ?? null,
          activationBlockerCount: dryRunResult?.activationBlockerCount ?? 0,
          rollbackRestoreCanaryId:
            dryRunResult?.rollbackRestoreCanaryId ?? null,
          rollbackRestoreStatus: dryRunResult?.rollbackRestoreStatus ?? null,
          rollbackRestoreRevisionSource:
            dryRunResult?.rollbackRestoreRevisionSource ?? null,
          rollbackRestoreStrategy:
            dryRunResult?.rollbackRestoreStrategy ?? null,
          rollbackRestoreHashVerified:
            dryRunResult?.rollbackRestoreHashVerified === true,
          rollbackRestoreReceiptBindingRef:
            dryRunResult?.rollbackRestoreReceiptBindingRef ?? null,
          rollbackRestoreEvidenceRefs:
            dryRunResult?.rollbackRestoreEvidenceRefs ?? [],
          rollbackRestoreBlockers: dryRunResult?.rollbackRestoreBlockers ?? [],
          rollbackRestoreGateStatus:
            dryRunResult?.rollbackRestoreGateStatus ?? null,
          persistedActivationAuditEventCount:
            dryRunResult?.activationAuditEventCount ?? 0,
          latestAuditEventId: dryRunResult?.latestAuditEventId ?? null,
          latestAuditEventType: dryRunResult?.latestAuditEventType ?? null,
          latestAuditStatus: dryRunResult?.latestAuditStatus ?? null,
        },
        after: {
          railTestId: afterRailTestId,
          statusMessage: afterStatusMessage,
          inspectorState: afterInspectorState,
        },
        rollbackRestoreDeepLink: rollbackRestoreDeepLinkHash,
        rollbackRestoreDeepLinkState,
        clicked,
        passed: blockers.length === 0,
        blockers,
      };
    },
    [applyHarnessWorkbenchDeepLink],
  );
  const runHarnessActivationIdGateClickProbe = useCallback(
    async (
      blockedWorkflow: WorkflowProject,
      blockedTests: WorkflowTestCase[],
      blockedProposals: WorkflowProposal[],
      generatedAtMs: number,
    ): Promise<WorkflowHarnessActivationIdGateClickProof> => {
      const selectedRailTestId = "workflow-harness-activation-gate-inspector";
      const projectRoot = currentProject?.rootPath || ".";
      const blockers: string[] = [];
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const link = {
        panel: "settings" as WorkflowRightPanel,
        activationGateId: "activation-id",
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      const emptyAction = () => ({
        id: null as string | null,
        kind: null as string | null,
        impact: null as string | null,
        command: null as string | null,
        disabled: false,
      });
      const readAction = (state: Record<string, string>) => ({
        id: state["data-gate-action-id"] || null,
        kind: state["data-gate-action-kind"] || null,
        impact: state["data-gate-action-impact"] || null,
        command: state["data-gate-action-command"] || null,
        disabled: state["data-gate-action-disabled"] === "true",
      });
      const stageWorkflow = async (
        nextWorkflow: WorkflowProject,
        nextTests: WorkflowTestCase[],
        nextProposals: WorkflowProposal[],
        candidate: WorkflowHarnessForkActivationCandidate | null,
      ) => {
        const nextWorkflowPath = `${projectRoot}/.agents/workflows/${nextWorkflow.metadata.slug}.workflow.json`;
        const nextValidation = validateWorkflowProject(nextWorkflow, nextTests);
        setWorkflowPath(nextWorkflowPath);
        setTestsPath(
          nextWorkflowPath.replace(/\.workflow\.json$/, ".tests.json"),
        );
        setTests(nextTests);
        setProposals(nextProposals);
        setRuns([]);
        loadWorkflowProject(nextWorkflow);
        setHarnessActivationCandidate(candidate);
        setSelectedHarnessRollbackTarget(null);
        setValidationResult(nextValidation);
        setReadinessResult(
          evaluateWorkflowActivationReadiness(
            nextWorkflow,
            nextTests,
            nextValidation,
            nextProposals,
            [],
          ),
        );
        setRightPanel("settings");
        setBottomPanel("selection");
        await nextHarnessWorkbenchFrame();
        await nextHarnessWorkbenchFrame();
      };
      const applyActivationIdDeepLink = async () => {
        if (!parsed) {
          blockers.push("activation_id_gate_hash_parse_failed");
          return;
        }
        writeHarnessWorkbenchDeepLink(hash);
        applyHarnessWorkbenchDeepLink(parsed);
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
      };

      let blockedBeforeState: Record<string, string> = {};
      let blockedAfterState: Record<string, string> = {};
      let blockedGateId: string | null = null;
      let blockedAction = emptyAction();
      let blockedClicked = false;
      let blockedDryRunResult: HarnessActivationDryRunClickResult | null = null;
      let mintedBeforeState: Record<string, string> = {};
      let mintedAfterState: Record<string, string> = {};
      let mintedGateId: string | null = null;
      let mintedAction = emptyAction();
      let mintedClicked = false;
      let mintResult: HarnessActivationMintClickResult | null = null;
      let mintedHandoffDeepLinkHash: string | null = null;
      let mintedHandoffState: Record<string, string> = {};
      let mintedHandoffTimelineVisible = false;
      let mintedHandoffTimelineAttemptId: string | null = null;

      try {
        if (typeof window !== "undefined") {
          (window as any).__AUTOPILOT_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT =
            null;
          (window as any).__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT =
            null;
        }
        await stageWorkflow(
          blockedWorkflow,
          blockedTests,
          blockedProposals,
          null,
        );
        await applyActivationIdDeepLink();
        blockedBeforeState = readHarnessRailSelectedState(selectedRailTestId);
        blockedGateId =
          blockedBeforeState["data-selected-activation-gate-id"] || null;
        blockedAction = readAction(blockedBeforeState);
        const blockedActionButton = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-activation-gate-action"]',
        );
        if (!blockedActionButton) {
          blockers.push("activation_id_gate_dry_run_button_missing");
        } else if (blockedActionButton.disabled || blockedAction.disabled) {
          blockers.push("activation_id_gate_dry_run_button_disabled");
        } else {
          blockedActionButton.click();
          blockedClicked = true;
          for (let attempt = 0; attempt < 80; attempt += 1) {
            await nextHarnessWorkbenchFrame();
            blockedDryRunResult = readHarnessActivationDryRunClickResult();
            if (blockedDryRunResult?.candidateId) break;
          }
          await applyActivationIdDeepLink();
          blockedAfterState = readHarnessRailSelectedState(selectedRailTestId);
        }

        const mintableFork = forkDefaultAgentHarnessWorkflow(
          "Activation Mint GUI Fork",
          generatedAtMs + 10,
        );
        let mintableWorkflow = mintableFork.workflow;
        HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS.forEach((clusterId, index) => {
          mintableWorkflow = workflowReadyForHarnessPromotion(
            mintableWorkflow,
            clusterId,
            generatedAtMs + 20 + index,
          );
        });
        const {
          workflow: stagedMintableWorkflow,
          candidate: mintableCandidate,
        } = workflowWithMintableHarnessActivationCandidate(
          mintableWorkflow,
          mintableFork.tests,
          generatedAtMs + 40,
        );
        if (mintableCandidate.decision !== "mintable") {
          blockers.push("activation_id_gate_candidate_not_mintable");
        }
        if (typeof window !== "undefined") {
          (window as any).__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT =
            null;
        }
        await stageWorkflow(
          stagedMintableWorkflow,
          mintableFork.tests,
          [],
          mintableCandidate,
        );
        await applyActivationIdDeepLink();
        mintedBeforeState = readHarnessRailSelectedState(selectedRailTestId);
        mintedGateId =
          mintedBeforeState["data-selected-activation-gate-id"] || null;
        mintedAction = readAction(mintedBeforeState);
        const mintActionButton = document.querySelector<HTMLButtonElement>(
          '[data-testid="workflow-harness-activation-gate-action"]',
        );
        if (!mintActionButton) {
          blockers.push("activation_id_gate_mint_button_missing");
        } else if (mintActionButton.disabled || mintedAction.disabled) {
          blockers.push("activation_id_gate_mint_button_disabled");
        } else {
          mintActionButton.click();
          mintedClicked = true;
          for (let attempt = 0; attempt < 80; attempt += 1) {
            await nextHarnessWorkbenchFrame();
            mintResult = readHarnessActivationMintClickResult();
            if (mintResult && typeof mintResult.applied === "boolean") break;
          }
          await applyActivationIdDeepLink();
          mintedAfterState = readHarnessRailSelectedState(selectedRailTestId);
          const workerHandoffNodeAttemptId =
            mintResult?.workerHandoffNodeAttemptIds[0] ?? null;
          if (workerHandoffNodeAttemptId) {
            const workerHandoffLink = {
              panel: "settings" as WorkflowRightPanel,
              activationGateId: "worker-handoff",
              activationGateNodeAttemptId: workerHandoffNodeAttemptId,
              nodeAttemptId: workerHandoffNodeAttemptId,
              activationGateReceiptRef:
                mintResult?.workerHandoffReceiptIds[0] ?? undefined,
              receiptRef: mintResult?.workerHandoffReceiptIds[0] ?? undefined,
              activationGateReplayFixtureRef:
                mintResult?.workerHandoffReplayFixtureRefs[0] ?? undefined,
              replayFixtureRef:
                mintResult?.workerHandoffReplayFixtureRefs[0] ?? undefined,
            };
            mintedHandoffDeepLinkHash =
              encodeHarnessWorkbenchDeepLink(workerHandoffLink);
            const workerHandoffParsed = parseHarnessWorkbenchDeepLink(
              mintedHandoffDeepLinkHash,
            );
            if (workerHandoffParsed) {
              writeHarnessWorkbenchDeepLink(mintedHandoffDeepLinkHash);
              applyHarnessWorkbenchDeepLink(workerHandoffParsed);
              await nextHarnessWorkbenchFrame();
              writeHarnessWorkbenchDeepLink(mintedHandoffDeepLinkHash);
              await nextHarnessWorkbenchFrame();
              mintedHandoffState =
                readHarnessRailSelectedState(selectedRailTestId);
              const timeline =
                document.querySelector<HTMLElement>(
                  '[data-testid="workflow-harness-activation-gate-node-timeline"]',
                );
              const selectedTimelineAttempt =
                document.querySelector<HTMLElement>(
                  `[data-node-attempt-id="${workerHandoffNodeAttemptId}"]`,
                );
              mintedHandoffTimelineVisible = Boolean(timeline);
              mintedHandoffTimelineAttemptId =
                selectedTimelineAttempt?.dataset.nodeAttemptId ?? null;
            }
          }
        }
      } catch (error) {
        blockers.push(`activation_id_gate_click_failed:${errorMessage(error)}`);
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }

      if (blockedGateId !== "activation-id") {
        blockers.push("activation_id_gate_dry_run_gate_not_selected");
      }
      if (
        blockedAction.id !== "activation-gate-action:activation-id:run-dry-run"
      ) {
        blockers.push("activation_id_gate_dry_run_action_id_mismatch");
      }
      if (blockedAction.kind !== "run_activation_dry_run") {
        blockers.push("activation_id_gate_dry_run_kind_mismatch");
      }
      if (blockedAction.impact !== "collect_evidence") {
        blockers.push("activation_id_gate_dry_run_impact_mismatch");
      }
      if (
        blockedAction.command !== "workflow-harness-gate-action-activation-id"
      ) {
        blockers.push("activation_id_gate_dry_run_command_mismatch");
      }
      if (!blockedClicked)
        blockers.push("activation_id_gate_dry_run_not_dispatched");
      if (!blockedDryRunResult?.candidateId) {
        blockers.push("activation_id_gate_dry_run_result_missing");
      }
      if (blockedDryRunResult?.decision !== "blocked") {
        blockers.push("activation_id_gate_dry_run_not_blocked");
      }
      if ((blockedDryRunResult?.activationBlockerCount ?? 0) <= 0) {
        blockers.push("activation_id_gate_dry_run_no_blockers");
      }
      if (blockedDryRunResult?.workflowActivationId) {
        blockers.push("activation_id_gate_dry_run_minted_activation_id");
      }
      if (blockedDryRunResult?.workflowActivationState !== "blocked") {
        blockers.push("activation_id_gate_dry_run_activation_state_mismatch");
      }
      if (blockedDryRunResult?.latestAuditEventType !== "dry_run_blocked") {
        blockers.push("activation_id_gate_dry_run_audit_type_mismatch");
      }
      if (
        blockedAfterState["data-selected-activation-gate-id"] !==
        "activation-id"
      ) {
        blockers.push("activation_id_gate_dry_run_inspector_not_restored");
      }
      if (blockedAfterState["data-gate-status"] !== "blocked") {
        blockers.push("activation_id_gate_dry_run_gate_status_not_blocked");
      }

      if (mintedGateId !== "activation-id") {
        blockers.push("activation_id_gate_mint_gate_not_selected");
      }
      if (mintedAction.id !== "activation-gate-action:activation-id:mint") {
        blockers.push("activation_id_gate_mint_action_id_mismatch");
      }
      if (mintedAction.kind !== "mint_activation") {
        blockers.push("activation_id_gate_mint_kind_mismatch");
      }
      if (mintedAction.impact !== "mint_activation") {
        blockers.push("activation_id_gate_mint_impact_mismatch");
      }
      if (
        mintedAction.command !== "workflow-harness-gate-action-activation-id"
      ) {
        blockers.push("activation_id_gate_mint_command_mismatch");
      }
      if (!mintedClicked)
        blockers.push("activation_id_gate_mint_not_dispatched");
      if (mintResult?.applied !== true) {
        blockers.push("activation_id_gate_mint_not_applied");
      }
      if (!mintResult?.activationId?.startsWith("activation:")) {
        blockers.push("activation_id_gate_mint_activation_id_missing");
      }
      if (mintResult?.workflowActivationId !== mintResult?.activationId) {
        blockers.push("activation_id_gate_mint_workflow_activation_mismatch");
      }
      if (mintResult?.workflowActivationState !== "validated") {
        blockers.push("activation_id_gate_mint_activation_state_mismatch");
      }
      if (mintResult?.workerBindingActivationId !== mintResult?.activationId) {
        blockers.push("activation_id_gate_mint_worker_binding_mismatch");
      }
      if (
        mintResult?.activationRecordWorkerBindingActivationId !==
        mintResult?.activationId
      ) {
        blockers.push(
          "activation_id_gate_mint_activation_record_binding_mismatch",
        );
      }
      if (mintResult?.rollbackTarget !== DEFAULT_AGENT_HARNESS_ACTIVATION_ID) {
        blockers.push("activation_id_gate_mint_rollback_target_mismatch");
      }
      if (
        mintResult?.revisionBindingActivationId !== mintResult?.activationId
      ) {
        blockers.push("activation_id_gate_mint_revision_binding_mismatch");
      }
      if (!mintResult?.activationRecordRevisionBindingHash) {
        blockers.push("activation_id_gate_mint_revision_hash_missing");
      }
      if (!mintResult?.rollbackRevisionBindingHash) {
        blockers.push("activation_id_gate_mint_rollback_hash_missing");
      }
      if (mintResult?.latestAuditEventType !== "activation_minted") {
        blockers.push("activation_id_gate_mint_audit_type_mismatch");
      }
      if (mintResult?.latestAuditStatus !== "applied") {
        blockers.push("activation_id_gate_mint_audit_status_mismatch");
      }
      if ((mintResult?.receiptRefs.length ?? 0) <= 0) {
        blockers.push("activation_id_gate_mint_receipts_missing");
      }
      if ((mintResult?.evidenceRefs.length ?? 0) <= 0) {
        blockers.push("activation_id_gate_mint_evidence_missing");
      }
      if ((mintResult?.workerHandoffReceiptIds.length ?? 0) <= 0) {
        blockers.push("activation_id_gate_mint_worker_handoff_receipts_missing");
      }
      if ((mintResult?.workerHandoffNodeAttemptIds.length ?? 0) <= 0) {
        blockers.push("activation_id_gate_mint_worker_handoff_attempts_missing");
      }
      if ((mintResult?.workerHandoffReplayFixtureRefs.length ?? 0) <= 0) {
        blockers.push("activation_id_gate_mint_worker_handoff_replay_missing");
      }
      const expectedHandoffAttempt =
        mintResult?.workerHandoffNodeAttemptIds[0] ?? null;
      if (
        expectedHandoffAttempt &&
        !mintedHandoffDeepLinkHash?.includes("activationGateNodeAttemptId=")
      ) {
        blockers.push("activation_id_gate_mint_handoff_node_link_missing");
      }
      if (
        expectedHandoffAttempt &&
        mintedHandoffState["data-selected-activation-gate-id"] !==
          "worker-handoff"
      ) {
        blockers.push("activation_id_gate_mint_handoff_gate_not_restored");
      }
      if (
        expectedHandoffAttempt &&
        mintedHandoffState["data-selected-activation-gate-node-attempt-id"] !==
          expectedHandoffAttempt
      ) {
        blockers.push("activation_id_gate_mint_handoff_attempt_not_selected");
      }
      if (
        expectedHandoffAttempt &&
        mintedHandoffState["data-selected-node-attempt-id"] !==
          expectedHandoffAttempt
      ) {
        blockers.push("activation_id_gate_mint_global_attempt_not_selected");
      }
      if (
        expectedHandoffAttempt &&
        Number(mintedHandoffState["data-node-attempt-ref-count"] ?? 0) <= 0
      ) {
        blockers.push("activation_id_gate_mint_handoff_attempt_refs_missing");
      }
      if (expectedHandoffAttempt && !mintedHandoffTimelineVisible) {
        blockers.push("activation_id_gate_mint_handoff_timeline_missing");
      }
      if (
        expectedHandoffAttempt &&
        mintedHandoffTimelineAttemptId !== expectedHandoffAttempt
      ) {
        blockers.push("activation_id_gate_mint_handoff_timeline_attempt_missing");
      }
      if (
        mintedAfterState["data-selected-activation-gate-id"] !== "activation-id"
      ) {
        blockers.push("activation_id_gate_mint_inspector_not_restored");
      }
      if (mintedAfterState["data-gate-status"] !== "passed") {
        blockers.push("activation_id_gate_mint_gate_status_not_passed");
      }

      return {
        schemaVersion: "workflow.harness.activation-id-gate-click-proof.v1",
        method:
          "same-session Workflows bridge clicks the activation-id gate first as a blocked dry run, then stages a mintable fork and clicks the same gate to mint a validated activation id with worker, revision, receipt, audit, and rollback bindings",
        generatedAtMs,
        blockedDryRun: {
          gateId: blockedGateId,
          action: blockedAction,
          beforeState: blockedBeforeState,
          afterState: blockedAfterState,
          clicked: blockedClicked,
          candidateId: blockedDryRunResult?.candidateId ?? null,
          decision: blockedDryRunResult?.decision ?? null,
          activationBlockerCount:
            blockedDryRunResult?.activationBlockerCount ?? 0,
          workflowActivationId:
            blockedDryRunResult?.workflowActivationId ?? null,
          workflowActivationState:
            blockedDryRunResult?.workflowActivationState ?? null,
          latestAuditEventType:
            blockedDryRunResult?.latestAuditEventType ?? null,
          latestAuditStatus: blockedDryRunResult?.latestAuditStatus ?? null,
        },
        mintedActivation: {
          gateId: mintedGateId,
          action: mintedAction,
          beforeState: mintedBeforeState,
          afterState: mintedAfterState,
          clicked: mintedClicked,
          applied: mintResult?.applied === true,
          activationId: mintResult?.activationId ?? null,
          workflowActivationId: mintResult?.workflowActivationId ?? null,
          workflowActivationState: mintResult?.workflowActivationState ?? null,
          workerBindingActivationId:
            mintResult?.workerBindingActivationId ?? null,
          activationRecordWorkerBindingActivationId:
            mintResult?.activationRecordWorkerBindingActivationId ?? null,
          rollbackTarget: mintResult?.rollbackTarget ?? null,
          revisionBindingActivationId:
            mintResult?.revisionBindingActivationId ?? null,
          activationRecordRevisionBindingHash:
            mintResult?.activationRecordRevisionBindingHash ?? null,
          rollbackRevisionBindingHash:
            mintResult?.rollbackRevisionBindingHash ?? null,
          latestAuditEventType: mintResult?.latestAuditEventType ?? null,
          latestAuditStatus: mintResult?.latestAuditStatus ?? null,
          receiptRefs: mintResult?.receiptRefs ?? [],
          evidenceRefs: mintResult?.evidenceRefs ?? [],
          workerHandoffReceiptIds: mintResult?.workerHandoffReceiptIds ?? [],
          workerHandoffNodeAttemptIds:
            mintResult?.workerHandoffNodeAttemptIds ?? [],
          workerHandoffReplayFixtureRefs:
            mintResult?.workerHandoffReplayFixtureRefs ?? [],
          workerHandoffDeepLink: mintedHandoffDeepLinkHash,
          workerHandoffDeepLinkState: mintedHandoffState,
          workerHandoffTimelineVisible: mintedHandoffTimelineVisible,
          workerHandoffTimelineAttemptId: mintedHandoffTimelineAttemptId,
        },
        passed: blockers.length === 0,
        blockers,
      };
    },
    [
      applyHarnessWorkbenchDeepLink,
      currentProject?.rootPath,
      loadWorkflowProject,
    ],
  );
  const runHarnessWorkerInvariantNegativeEnforcementProbe = useCallback(
    async (
      generatedAtMs: number,
    ): Promise<WorkflowHarnessWorkerInvariantNegativeEnforcementProof> => {
      const selectedRailTestId = "workflow-harness-activation-gate-inspector";
      const projectRoot = currentProject?.rootPath || ".";
      const blockers: string[] = [];
      const invalidActivationBlocker =
        "worker_launch_reviewed_import_activation_apply_invariant_missing";
      const expectedInspectorBlocker =
        "worker_launch_reviewed_import_activation_invariant_not_bound";
      const originalHash =
        typeof window === "undefined" ? "" : window.location.hash;
      const link = {
        panel: "settings" as WorkflowRightPanel,
        activationGateId: "worker-invariant",
      };
      const hash = encodeHarnessWorkbenchDeepLink(link);
      const parsed = parseHarnessWorkbenchDeepLink(hash);
      const emptyAction = () => ({
        id: null as string | null,
        kind: null as string | null,
        impact: null as string | null,
        command: null as string | null,
        disabled: false,
      });
      const readAction = (state: Record<string, string>) => ({
        id: state["data-gate-action-id"] || null,
        kind: state["data-gate-action-kind"] || null,
        impact: state["data-gate-action-impact"] || null,
        command: state["data-gate-action-command"] || null,
        disabled: state["data-gate-action-disabled"] === "true",
      });
      const stageWorkflow = async (
        nextWorkflow: WorkflowProject,
        nextTests: WorkflowTestCase[],
        candidate: WorkflowHarnessForkActivationCandidate | null,
      ) => {
        const nextWorkflowPath = `${projectRoot}/.agents/workflows/${nextWorkflow.metadata.slug}.workflow.json`;
        const nextValidation = validateWorkflowProject(nextWorkflow, nextTests);
        setWorkflowPath(nextWorkflowPath);
        setTestsPath(
          nextWorkflowPath.replace(/\.workflow\.json$/, ".tests.json"),
        );
        setTests(nextTests);
        setProposals([]);
        setRuns([]);
        loadWorkflowProject(nextWorkflow);
        setHarnessActivationCandidate(candidate);
        setSelectedHarnessRollbackTarget(null);
        setValidationResult(nextValidation);
        setReadinessResult(
          evaluateWorkflowActivationReadiness(
            nextWorkflow,
            nextTests,
            nextValidation,
            [],
            [],
          ),
        );
        setRightPanel("settings");
        setBottomPanel("selection");
        await nextHarnessWorkbenchFrame();
        await nextHarnessWorkbenchFrame();
      };
      const applyWorkerInvariantDeepLink = async () => {
        if (!parsed) {
          blockers.push("worker_invariant_negative_hash_parse_failed");
          return;
        }
        writeHarnessWorkbenchDeepLink(hash);
        applyHarnessWorkbenchDeepLink(parsed);
        await nextHarnessWorkbenchFrame();
        writeHarnessWorkbenchDeepLink(hash);
        await nextHarnessWorkbenchFrame();
      };

      let forkWorkflowId = "";
      let invalidCandidate: WorkflowHarnessForkActivationCandidate | null =
        null;
      let inspectorState: Record<string, string> = {};
      let action = emptyAction();
      let activationApply: ReturnType<
        typeof applyWorkflowHarnessActivationCandidate
      > | null = null;

      try {
        const fork = forkDefaultAgentHarnessWorkflow(
          "Worker Invariant Negative Fork",
          generatedAtMs,
        );
        let mintableWorkflow = fork.workflow;
        HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS.forEach((clusterId, index) => {
          mintableWorkflow = workflowReadyForHarnessPromotion(
            mintableWorkflow,
            clusterId,
            generatedAtMs + 10 + index,
          );
        });
        const { workflow: stagedWorkflow, candidate } =
          workflowWithMintableHarnessActivationCandidate(
            mintableWorkflow,
            fork.tests,
            generatedAtMs + 20,
          );
        forkWorkflowId = stagedWorkflow.metadata.id || stagedWorkflow.metadata.slug;
        invalidCandidate = {
          ...candidate,
          decision: "blocked",
          activationId: undefined,
          activationBlockers: Array.from(
            new Set([...candidate.activationBlockers, invalidActivationBlocker]),
          ),
          blockerCodes: Array.from(
            new Set([...candidate.blockerCodes, invalidActivationBlocker]),
          ),
        };

        await stageWorkflow(stagedWorkflow, fork.tests, invalidCandidate);
        await applyWorkerInvariantDeepLink();
        inspectorState = readHarnessRailSelectedState(selectedRailTestId);
        action = readAction(inspectorState);
        activationApply = applyWorkflowHarnessActivationCandidate(
          stagedWorkflow,
          invalidCandidate,
          {
            rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
            nowMs: generatedAtMs + 30,
          },
        );
      } catch (error) {
        blockers.push(
          `worker_invariant_negative_probe_failed:${errorMessage(error)}`,
        );
      } finally {
        writeHarnessWorkbenchDeepLink(originalHash);
      }

      const gateId =
        inspectorState["data-selected-activation-gate-id"] || null;
      const status = inspectorState["data-gate-status"] || null;
      const requiredInvariantIds = String(
        inspectorState["data-required-invariant-ids"] ?? "",
      )
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      const invariantBlockers = String(
        inspectorState["data-invariant-blockers"] ?? "",
      )
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      const invariantBlockerCount = Number(
        inspectorState["data-invariant-blocker-count"] ?? 0,
      );
      const appliedWorkflow = activationApply?.workflow ?? null;
      const appliedHarness = appliedWorkflow?.metadata.harness ?? null;
      const latestAudit =
        appliedHarness?.activationAudit?.[
          (appliedHarness.activationAudit?.length ?? 0) - 1
        ] ?? null;
      const workerSessionLive =
        appliedHarness?.workerSessionRecord?.accepted === true ||
        appliedHarness?.activationRecord?.workerSessionRecord?.accepted ===
          true;
      const workerLaunchEnvelopeCount =
        (appliedHarness?.workerLaunchEnvelopes?.length ?? 0) +
        (appliedHarness?.activationRecord?.workerLaunchEnvelopes?.length ?? 0);
      const workerHandoffReceiptCount =
        (appliedHarness?.workerHandoffReceipts?.length ?? 0) +
        (appliedHarness?.activationRecord?.workerHandoffReceipts?.length ?? 0);
      const workerHandoffNodeAttemptCount =
        (appliedHarness?.workerHandoffNodeAttemptIds?.length ?? 0) +
        (appliedHarness?.activationRecord?.workerHandoffNodeAttemptIds
          ?.length ?? 0);

      if (gateId !== "worker-invariant") {
        blockers.push("worker_invariant_negative_gate_not_selected");
      }
      if (status !== "blocked") {
        blockers.push("worker_invariant_negative_gate_not_blocked");
      }
      if (invariantBlockerCount <= 0 || invariantBlockers.length <= 0) {
        blockers.push("worker_invariant_negative_blockers_missing");
      }
      if (!invariantBlockers.includes(expectedInspectorBlocker)) {
        blockers.push("worker_invariant_negative_expected_blocker_missing");
      }
      if (
        requiredInvariantIds.includes(
          DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT,
        ) &&
        !invariantBlockers.includes(expectedInspectorBlocker)
      ) {
        blockers.push("worker_invariant_negative_required_id_bound");
      }
      if (
        action.id !== "activation-gate-action:worker-invariant:check-readiness"
      ) {
        blockers.push("worker_invariant_negative_action_id_mismatch");
      }
      if (action.kind !== "check_readiness") {
        blockers.push("worker_invariant_negative_action_kind_mismatch");
      }
      if (action.impact !== "inspect") {
        blockers.push("worker_invariant_negative_action_impact_mismatch");
      }
      if (action.command !== "workflow-harness-gate-action-worker-invariant") {
        blockers.push("worker_invariant_negative_action_command_mismatch");
      }
      if (!invalidCandidate) {
        blockers.push("worker_invariant_negative_candidate_missing");
      }
      if (invalidCandidate?.decision !== "blocked") {
        blockers.push("worker_invariant_negative_candidate_not_blocked");
      }
      if (
        !invalidCandidate?.activationBlockers.includes(invalidActivationBlocker)
      ) {
        blockers.push("worker_invariant_negative_candidate_blocker_missing");
      }
      if (activationApply?.applied !== false) {
        blockers.push("worker_invariant_negative_apply_not_refused");
      }
      if (!activationApply?.blockers.includes(invalidActivationBlocker)) {
        blockers.push("worker_invariant_negative_apply_blocker_missing");
      }
      if (!activationApply?.blockers.includes("candidate_not_mintable")) {
        blockers.push("worker_invariant_negative_apply_mintable");
      }
      if (activationApply?.activationId) {
        blockers.push("worker_invariant_negative_activation_id_minted");
      }
      if (appliedHarness?.activationId) {
        blockers.push("worker_invariant_negative_workflow_activation_minted");
      }
      if (appliedHarness?.activationState !== "blocked") {
        blockers.push("worker_invariant_negative_activation_state_mismatch");
      }
      if (
        appliedWorkflow?.metadata.workerHarnessBinding?.authorityBindingReady ===
        true
      ) {
        blockers.push("worker_invariant_negative_authority_bound");
      }
      if (workerSessionLive) {
        blockers.push("worker_invariant_negative_worker_session_live");
      }
      if (workerLaunchEnvelopeCount > 0) {
        blockers.push("worker_invariant_negative_worker_launch_created");
      }
      if (workerHandoffReceiptCount > 0) {
        blockers.push("worker_invariant_negative_worker_handoff_created");
      }
      if (workerHandoffNodeAttemptCount > 0) {
        blockers.push("worker_invariant_negative_worker_attempt_created");
      }
      if (latestAudit?.eventType !== "activation_mint_blocked") {
        blockers.push("worker_invariant_negative_audit_type_mismatch");
      }
      if (latestAudit?.status !== "blocked") {
        blockers.push("worker_invariant_negative_audit_status_mismatch");
      }

      return {
        schemaVersion:
          "workflow.harness.worker-invariant-negative-enforcement-proof.v1",
        method:
          "stage a promoted fork with the reviewed-import activation apply worker invariant not bound, deep-link the worker-invariant activation gate, then attempt activation apply and require refusal without worker session, launch, handoff, or activation id state",
        generatedAtMs,
        forkWorkflowId,
        invalidCandidate: {
          candidateId: invalidCandidate?.candidateId ?? null,
          decision: invalidCandidate?.decision ?? null,
          activationIdPreview:
            invalidCandidate?.activationIdPreview ??
            invalidCandidate?.activationId ??
            null,
          activationBlockers: invalidCandidate?.activationBlockers ?? [],
        },
        deepLink: {
          hash,
          selectedRailTestId,
          gateId,
          status,
          requiredInvariantIds,
          invariantBlockers,
          invariantBlockerCount,
          action,
          inspectorState,
        },
        activationApply: {
          attempted: Boolean(invalidCandidate),
          applied: activationApply?.applied === true,
          activationId: activationApply?.activationId ?? null,
          blockers: activationApply?.blockers ?? [],
          workflowActivationId: appliedHarness?.activationId ?? null,
          workflowActivationState: appliedHarness?.activationState ?? null,
          workerBindingAuthorityReady:
            appliedWorkflow?.metadata.workerHarnessBinding
              ?.authorityBindingReady === true,
          workerSessionLive,
          workerLaunchEnvelopeCount,
          workerHandoffReceiptCount,
          workerHandoffNodeAttemptCount,
          latestAuditEventType: latestAudit?.eventType ?? null,
          latestAuditStatus: latestAudit?.status ?? null,
        },
        passed: blockers.length === 0,
        blockers,
      };
    },
    [
      applyHarnessWorkbenchDeepLink,
      currentProject?.rootPath,
      loadWorkflowProject,
    ],
  );
  const displayEdges = useMemo(() => {
    const edgeWithIssueData = (edge: ReactFlowEdge, sourceEdgeId: string) => {
      const issue = canvasEdgeIssues.get(sourceEdgeId);
      return {
        ...edge,
        data: {
          ...(edge.data ?? {}),
          ...(issue
            ? {
                issueCount: 1,
                issueStatus: "blocked",
                issueTitle: workflowIssueTitle(issue),
                issueMessage: issue.message,
              }
            : {
                issueCount: 0,
                issueStatus: null,
                issueTitle: null,
                issueMessage: null,
              }),
        },
      };
    };
    if (collapsedHarnessGroupByNodeId.size === 0) {
      return edges.map((edge) => edgeWithIssueData(edge, edge.id));
    }

    const routedEdges = new Map<string, ReactFlowEdge>();
    edges.forEach((edge) => {
      const sourceGroup = collapsedHarnessGroupByNodeId.get(edge.source);
      const targetGroup = collapsedHarnessGroupByNodeId.get(edge.target);
      const source = sourceGroup?.groupNodeId ?? edge.source;
      const target = targetGroup?.groupNodeId ?? edge.target;
      if (source === target) return;

      if (!sourceGroup && !targetGroup) {
        routedEdges.set(edge.id, edgeWithIssueData(edge, edge.id));
        return;
      }

      const connectionClass = String(
        edge.data?.connectionClass ??
          edge.sourceHandle ??
          edge.targetHandle ??
          "data",
      );
      const routedId = [
        "harness.group.edge",
        source,
        target,
        connectionClass,
      ].join(".");
      const existing = routedEdges.get(routedId);
      if (existing) {
        routedEdges.set(routedId, {
          ...existing,
          data: {
            ...(existing.data ?? {}),
            collapsedGroupEdge: true,
            collapsedEdgeCount:
              Number(existing.data?.collapsedEdgeCount ?? 1) + 1,
          },
        });
        return;
      }

      routedEdges.set(
        routedId,
        edgeWithIssueData(
          {
            ...edge,
            id: routedId,
            source,
            target,
            sourceHandle: sourceGroup ? "output" : edge.sourceHandle,
            targetHandle: targetGroup ? "input" : edge.targetHandle,
            type: "semantic",
            animated: false,
            data: {
              ...(edge.data ?? {}),
              label:
                sourceGroup || targetGroup
                  ? "group boundary"
                  : edge.data?.label,
              connectionClass:
                edge.data?.connectionClass ??
                (edge.sourceHandle === "error" || edge.targetHandle === "error"
                  ? "error"
                  : "data"),
              collapsedGroupEdge: true,
              collapsedEdgeCount: 1,
              innerSource: edge.source,
              innerTarget: edge.target,
              sourceGroupId: sourceGroup?.groupId,
              targetGroupId: targetGroup?.groupId,
            },
          },
          edge.id,
        ),
      );
    });
    return Array.from(routedEdges.values());
  }, [canvasEdgeIssues, collapsedHarnessGroupByNodeId, edges]);
  const activeRightPanelMeta = RIGHT_PANELS.find(
    (panel) => panel.id === rightPanel,
  ) ?? {
    id: "outputs" as WorkflowRightPanel,
    label: "Outputs",
    description: "Inspect selected nodes and workflow outputs.",
    icon: FileOutput,
  };
  const rightPanelBadgeCounts = useMemo<
    Record<WorkflowRightPanel, number>
  >(() => {
    const activeValidation = readinessResult ?? validationResult;
    const readinessIssueCount = activeValidation
      ? workflowValidationBlockingIssueCount(activeValidation) +
        activeValidation.warnings.length
      : 0;
    return {
      outputs: currentProjectFile.nodes.filter(
        (nodeItem) => nodeItem.type === "output",
      ).length,
      unit_tests: tests.length,
      sources: currentProjectFile.nodes.filter(
        (nodeItem) => nodeItem.type === "source" || nodeItem.type === "trigger",
      ).length,
      search: 0,
      changes: proposals.filter((proposal) => proposal.status === "open")
        .length,
      runs: runs.length,
      readiness: readinessIssueCount,
      schedules: currentProjectFile.nodes.filter(
        (nodeItem) => nodeItem.type === "trigger",
      ).length,
      files: 0,
      settings: 0,
    };
  }, [
    currentProjectFile.nodes,
    proposals,
    readinessResult,
    runs,
    tests,
    validationResult,
  ]);

  const loadRuntimeSidecars = useCallback(
    async (path: string) => {
      if (runtime.listWorkflowRuns) {
        setRuns(await runtime.listWorkflowRuns(path));
      }
      if (runtime.listWorkflowNodeFixtures) {
        setNodeFixturesById(
          groupFixturesByNodeId(await runtime.listWorkflowNodeFixtures(path)),
        );
      }
      if (runtime.loadWorkflowBindingManifest) {
        setBindingManifest(await runtime.loadWorkflowBindingManifest(path));
      }
    },
    [runtime],
  );

  const handleCheckWorkflowBinding = useCallback(
    async (
      row: WorkflowBindingRegistryRow,
    ): Promise<WorkflowBindingCheckResult> => {
      const localResult = workflowBindingCheckResult(
        row,
        workflowEnvironmentProfile(currentProjectFile),
      );
      if (!runtime.checkWorkflowBinding) {
        return localResult;
      }
      try {
        const result = await runtime.checkWorkflowBinding(
          workflowPath,
          row.nodeItem.id,
          row.id,
        );
        await loadRuntimeSidecars(workflowPath);
        return result;
      } catch (error) {
        return {
          ...localResult,
          status: "blocked",
          summary: "Binding check could not run",
          detail: error instanceof Error ? error.message : String(error),
        };
      }
    },
    [currentProjectFile, loadRuntimeSidecars, runtime, workflowPath],
  );

  const clearRunState = useCallback(() => {
    setLastRunResult(null);
    setSelectedRunId(null);
    setCompareRunResult(null);
    setCompareRunId(null);
    setFunctionDryRunResult(null);
    setReadinessResult(null);
    setBindingManifest(null);
    setRunDetailLoading(false);
    setRunEvents([]);
    setRuntimeThreadEvents([]);
    setCheckpoints([]);
    setNodeRunStatusById({});
    setNodeFixturesById({});
    liveTelemetryRunIdRef.current = null;
  }, []);

  const loadRuntimeThreadEvents = useCallback(
    async (threadId: string): Promise<WorkflowRuntimeThreadEventLike[]> => {
      if (!runtime.loadWorkflowRuntimeThreadEvents) return [];
      try {
        return await runtime.loadWorkflowRuntimeThreadEvents<WorkflowRuntimeThreadEventLike>(
          threadId,
          { limit: 500 },
        );
      } catch {
        return [];
      }
    },
    [runtime],
  );

  const startRuntimeThreadEventHydration = useCallback(
    (threadId: string): (() => void) => {
      if (!runtime.loadWorkflowRuntimeThreadEvents) return () => {};
      let cancelled = false;
      let timer: ReturnType<typeof setTimeout> | null = null;

      const poll = () => {
        void loadRuntimeThreadEvents(threadId)
          .then((events) => {
            if (cancelled || events.length === 0) return;
            setRuntimeThreadEvents((current) =>
              mergeWorkflowRuntimeThreadEvents(current, events),
            );
          })
          .finally(() => {
            if (cancelled) return;
            timer = setTimeout(
              poll,
              WORKFLOW_RUNTIME_TELEMETRY_POLL_INTERVAL_MS,
            );
          });
      };

      poll();
      return () => {
        cancelled = true;
        if (timer) {
          clearTimeout(timer);
        }
      };
    },
    [loadRuntimeThreadEvents, runtime.loadWorkflowRuntimeThreadEvents],
  );

  const prepareLiveRuntimeTelemetryHydration = useCallback(async () => {
    if (
      !runtime.createWorkflowThread ||
      !runtime.loadWorkflowRuntimeThreadEvents
    ) {
      return null;
    }

    const thread = await runtime.createWorkflowThread(workflowPath);
    const liveRun = createLiveWorkflowRunTelemetryHydration({
      workflow: currentProjectFile,
      thread,
    });
    liveTelemetryRunIdRef.current = liveRun.summary.id;
    setLastRunResult(liveRun);
    setSelectedRunId(liveRun.summary.id);
    setRunEvents(liveRun.events);
    setRuntimeThreadEvents([]);
    setCheckpoints([]);
    setNodeRunStatusById({});
    setRuns((current) => [
      liveRun.summary,
      ...current.filter((run) => run.id !== liveRun.summary.id),
    ]);
    setStatusMessage("Run streaming runtime telemetry");

    return {
      threadId: thread.id,
      stop: startRuntimeThreadEventHydration(thread.id),
    };
  }, [
    currentProjectFile,
    runtime,
    startRuntimeThreadEventHydration,
    workflowPath,
  ]);

  const applyRunResult = useCallback(
    async (result: WorkflowRunResult) => {
      const liveTelemetryRunId = liveTelemetryRunIdRef.current;
      liveTelemetryRunIdRef.current = null;
      setLastRunResult(result);
      setSelectedRunId(result.summary.id);
      setRunEvents(result.events);
      setRuntimeThreadEvents(await loadRuntimeThreadEvents(result.thread.id));
      setRuns((current) => [
        result.summary,
        ...current.filter(
          (run) =>
            run.id !== result.summary.id && run.id !== liveTelemetryRunId,
        ),
      ]);
      const runStatusEntries = new Map(
        result.nodeRuns.map((run) => [run.nodeId, run]),
      );
      result.finalState.completedNodeIds.forEach((nodeId) => {
        if (runStatusEntries.has(nodeId)) return;
        const nodeData = nodes.find((node) => node.id === nodeId)?.data as
          | Node
          | undefined;
        runStatusEntries.set(nodeId, {
          nodeId,
          nodeType: String(nodeData?.type ?? "function"),
          status: "success",
          startedAtMs: result.summary.startedAtMs,
          finishedAtMs: result.summary.finishedAtMs,
          attempt: 1,
        });
      });
      setNodeRunStatusById(Object.fromEntries(runStatusEntries));
      if (runtime.listWorkflowCheckpoints) {
        setCheckpoints(
          await runtime.listWorkflowCheckpoints(workflowPath, result.thread.id),
        );
      } else {
        setCheckpoints(result.checkpoints);
      }
      setRightPanel(
        result.summary.status === "interrupted" ? "runs" : rightPanel,
      );
      setStatusMessage(`Run ${result.summary.status}`);
    },
    [loadRuntimeThreadEvents, nodes, rightPanel, runtime, workflowPath],
  );

  const handleExecuteRuntimeDiagnosticsRepair = useCallback(
    async (action: WorkflowRuntimeDiagnosticsRepairActionDescriptor) => {
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!action.executable) {
        setStatusMessage(`Diagnostics repair ${action.label} is unavailable`);
        return;
      }
      if (!runtime.executeWorkflowRuntimeControlRequest) {
        setStatusMessage(
          "Diagnostics repair actions require a daemon runtime control executor.",
        );
        return;
      }
      const request = createRuntimeDiagnosticsRepairControlRequest({
        nodeId: action.id,
        threadId: action.threadId,
        decisionId: action.decisionId,
        action: action.action,
        message:
          action.summary ??
          `${action.label} diagnostics repair requested from React Flow run inspector.`,
        approvalGranted: action.approvalGranted,
        allowConflicts: action.allowConflicts,
        workflowGraphId: action.workflowGraphId ?? currentProjectFile.metadata.id,
        workflowNodeId: action.workflowNodeId,
        actor: "operator",
      });
      try {
        await runtime.executeWorkflowRuntimeControlRequest(request);
        setRuntimeThreadEvents(await loadRuntimeThreadEvents(action.threadId));
        setStatusMessage(`Diagnostics repair ${action.label} requested`);
      } catch (error) {
        setStatusMessage(
          `Diagnostics repair ${action.label} blocked: ${errorMessage(error)}`,
        );
      }
    },
    [currentProjectFile.metadata.id, loadRuntimeThreadEvents, runtime],
  );

  const handleExecuteRuntimeContextPressureAction = useCallback(
    async (action: WorkflowRuntimeContextPressureActionDescriptor) => {
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!action.executable) {
        setStatusMessage(`Context pressure action ${action.label} is advisory`);
        return;
      }
      if (!["compact", "stop", "request_approval", "delegate_summary"].includes(action.action)) {
        setStatusMessage(
          `Context pressure action ${action.label} is not executable yet`,
        );
        return;
      }
      if (action.action === "stop" && !action.turnId) {
        setStatusMessage("Context pressure stop action requires an active turn.");
        return;
      }
      if (!runtime.executeWorkflowRuntimeControlRequest) {
        setStatusMessage(
          "Context pressure actions require a daemon runtime control executor.",
        );
        return;
      }
      const reason =
        action.summary ??
        `${action.label} requested from React Flow run inspector.`;
      const workflowGraphId =
        action.workflowGraphId ?? currentProjectFile.metadata.id;
      const request =
        action.action === "compact"
          ? createRuntimeContextCompactControlRequest({
              nodeId: action.id,
              threadId: action.threadId,
              turnId: action.turnId,
              reason,
              scope: action.scope,
              workflowGraphId,
              workflowNodeId: action.workflowNodeId,
              actor: "operator",
            })
          : action.action === "request_approval"
            ? createRuntimeApprovalRequestControlRequest({
                nodeId: action.id,
                threadId: action.threadId,
                turnId: action.turnId,
                approvalId: action.id,
                reason,
                scope: action.scope,
                pressure: action.pressure,
                pressureStatus: action.pressureStatus,
                alertId: action.eventId,
                sourceEventId: action.sourceEventId ?? action.eventId,
                receiptRefs: action.receiptRefs,
                policyDecisionRefs: action.policyDecisionRefs,
                workflowGraphId,
                workflowNodeId: action.workflowNodeId,
                actor: "operator",
              })
            : action.action === "delegate_summary"
              ? createRuntimeSubagentControlRequest({
                  nodeId: action.id,
                  operation: "spawn",
                  threadId: action.threadId,
                  parentTurnId: action.turnId,
                  role: "review",
                  prompt: [
                    `Summarize the current ${action.scope.replace(/_/g, " ")} context before the parent turn continues.`,
                    action.pressureStatus || action.pressure !== null
                      ? `Context pressure: ${action.pressureStatus ?? "unknown"}${action.pressure !== null ? ` at ${action.pressure}` : ""}.`
                      : null,
                    action.summary ? `Alert: ${action.summary}` : null,
                    "Return SUMMARY, EVIDENCE, RISKS, BLOCKERS, and RECEIPTS.",
                  ]
                    .filter(Boolean)
                    .join("\n"),
                  forkContext: true,
                  toolPack: "coding",
                  outputContract: [
                    "SUMMARY",
                    "EVIDENCE",
                    "RISKS",
                    "BLOCKERS",
                    "RECEIPTS",
                  ],
                  mergePolicy: "evidence_only",
                  cancellationInheritance: "isolate",
                  contextPressureAction: action.action,
                  pressure: action.pressure,
                  pressureStatus: action.pressureStatus,
                  alertId: action.eventId,
                  sourceEventId: action.sourceEventId ?? action.eventId,
                  receiptRefs: action.receiptRefs,
                  policyDecisionRefs: action.policyDecisionRefs,
                  workflowGraphId,
                  workflowNodeId: action.workflowNodeId,
                  actor: "operator",
                })
            : createRuntimeOperatorInterruptControlRequest({
                nodeId: action.id,
                threadId: action.threadId,
                turnId: action.turnId,
                reason,
                workflowGraphId,
                workflowNodeId: action.workflowNodeId,
                actor: "operator",
              });
      try {
        await runtime.executeWorkflowRuntimeControlRequest(request);
        setRuntimeThreadEvents(await loadRuntimeThreadEvents(action.threadId));
        setStatusMessage(`Context pressure action ${action.label} requested`);
      } catch (error) {
        setStatusMessage(
          `Context pressure action ${action.label} blocked: ${errorMessage(error)}`,
        );
      }
    },
    [currentProjectFile.metadata.id, loadRuntimeThreadEvents, runtime],
  );

  const handleExecuteRuntimeWorkspaceTrustAction = useCallback(
    async (action: WorkflowRuntimeWorkspaceTrustActionDescriptor) => {
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!action.executable) {
        setStatusMessage(`Workspace trust action ${action.label} is already recorded`);
        return;
      }
      if (action.action !== "acknowledge") {
        setStatusMessage(`Workspace trust action ${action.label} is not executable yet`);
        return;
      }
      if (!runtime.executeWorkflowRuntimeControlRequest) {
        setStatusMessage(
          "Workspace trust actions require a daemon runtime control executor.",
        );
        return;
      }
      const request = createRuntimeWorkspaceTrustAcknowledgementControlRequest({
        nodeId: action.id,
        threadId: action.threadId,
        warningId: action.warningId,
        sourceEventId: action.sourceEventId ?? action.eventId,
        reason:
          action.summary ??
          `${action.label} requested from React Flow run inspector.`,
        workflowGraphId: action.workflowGraphId ?? currentProjectFile.metadata.id,
        workflowNodeId: action.workflowNodeId,
        actor: "operator",
      });
      try {
        await runtime.executeWorkflowRuntimeControlRequest(request);
        setRuntimeThreadEvents(await loadRuntimeThreadEvents(action.threadId));
        setStatusMessage(`Workspace trust action ${action.label} recorded`);
      } catch (error) {
        setStatusMessage(
          `Workspace trust action ${action.label} blocked: ${errorMessage(error)}`,
        );
      }
    },
    [currentProjectFile.metadata.id, loadRuntimeThreadEvents, runtime],
  );

  const handleSelectRun = useCallback(
    async (run: WorkflowRunSummary) => {
      setSelectedRunId(run.id);
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!runtime.loadWorkflowRun) {
        setStatusMessage(`Selected run ${run.status}`);
        return;
      }
      setRunDetailLoading(true);
      try {
        const result = await runtime.loadWorkflowRun(workflowPath, run.id);
        await applyRunResult(result);
        setStatusMessage(`Loaded run ${result.summary.status}`);
      } catch (error) {
        setStatusMessage(`Run detail unavailable: ${errorMessage(error)}`);
      } finally {
        setRunDetailLoading(false);
      }
    },
    [applyRunResult, runtime, workflowPath],
  );

  useLayoutEffect(() => {
    if (!runtime.loadWorkflowRun || runs.length === 0) return;
    if (runDetailLoading) return;
    const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0];
    if (lastRunResult?.summary.id === selectedRun.id) return;

    let cancelled = false;
    setRunDetailLoading(true);
    runtime
      .loadWorkflowRun(workflowPath, selectedRun.id)
      .then((result) => {
        if (!cancelled) {
          void applyRunResult(result);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedRunId(selectedRun.id);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setRunDetailLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [
    applyRunResult,
    lastRunResult?.summary.id,
    runtime,
    runDetailLoading,
    runs,
    selectedRunId,
    workflowPath,
  ]);

  const handleCompareRun = useCallback(
    async (run: WorkflowRunSummary) => {
      if (!lastRunResult || run.id === lastRunResult.summary.id) {
        setStatusMessage("Select a different run to compare.");
        return;
      }
      setCompareRunId(run.id);
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (!runtime.loadWorkflowRun) {
        setStatusMessage("Run comparison needs durable run detail loading.");
        return;
      }
      try {
        const result = await runtime.loadWorkflowRun(workflowPath, run.id);
        setCompareRunResult(result);
        setStatusMessage(`Comparing with ${result.summary.status} run`);
      } catch (error) {
        setStatusMessage(`Run comparison unavailable: ${errorMessage(error)}`);
      }
    },
    [lastRunResult, runtime, workflowPath],
  );

  const handleDragStart = (event: DragEvent, type: string, label: string) => {
    event.dataTransfer.setData("nodeType", type);
    event.dataTransfer.setData("nodeName", label);
  };

  const markWorkflowDirty = useCallback(() => {
    if (isReadOnlyWorkflow) {
      setStatusMessage(
        "Read-only harness graph cannot be edited. Fork it first.",
      );
      return;
    }
    setReadinessResult(null);
    setWorkflow((current) => ({
      ...current,
      metadata: { ...current.metadata, dirty: true },
    }));
  }, [isReadOnlyWorkflow]);

  const guardedOnNodesChange = useCallback(
    (...args: Parameters<typeof onNodesChange>) => {
      if (isReadOnlyWorkflow) return;
      onNodesChange(...args);
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, onNodesChange],
  );
  const guardedOnEdgesChange = useCallback(
    (...args: Parameters<typeof onEdgesChange>) => {
      if (isReadOnlyWorkflow) return;
      onEdgesChange(...args);
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, onEdgesChange],
  );
  const guardedOnConnect = useCallback(
    (...args: Parameters<typeof onConnect>) => {
      if (isReadOnlyWorkflow) return;
      onConnect(...args);
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, onConnect],
  );
  const guardedCanvasDrop = useCallback(
    (...args: Parameters<typeof handleCanvasDrop>) => {
      if (isReadOnlyWorkflow) return;
      handleCanvasDrop(...args);
      markWorkflowDirty();
    },
    [handleCanvasDrop, isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleUpdateProductionProfile = useCallback(
    (updates: NonNullable<GraphGlobalConfig["production"]>) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage(
          "Read-only harness graph cannot be edited. Fork it first.",
        );
        return;
      }
      setGlobalConfig((current) =>
        normalizeGlobalConfig({
          ...current,
          production: {
            ...(current.production ?? {}),
            ...updates,
          },
        }),
      );
      markWorkflowDirty();
      setStatusMessage("Production checklist updated");
    },
    [isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleUpdateEnvironmentProfile = useCallback(
    (
      updates: Partial<NonNullable<GraphGlobalConfig["environmentProfile"]>>,
    ) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage(
          "Read-only harness graph cannot be edited. Fork it first.",
        );
        return;
      }
      setGlobalConfig((current) =>
        normalizeGlobalConfig({
          ...current,
          environmentProfile: {
            ...(current.environmentProfile ?? {
              target: "local",
              credentialScope: "local",
              mockBindingPolicy: "block",
            }),
            ...updates,
          },
        }),
      );
      markWorkflowDirty();
      setStatusMessage("Environment profile updated");
    },
    [isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleUpdateWorkflowChromeLocale = useCallback(
    (workflowChromeLocale: string) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage(
          "Read-only harness graph cannot be edited. Fork it first.",
        );
        return;
      }
      setGlobalConfig((current) =>
        normalizeGlobalConfig({
          ...current,
          workflowChromeLocale,
        }),
      );
      markWorkflowDirty();
      setStatusMessage(`Workflow chrome locale set to ${workflowChromeLocale}`);
    },
    [isReadOnlyWorkflow, markWorkflowDirty],
  );

  const handleAddNodeFromLibrary = useCallback(
    (
      type: string,
      label: string,
      preferredId?: string,
      options: {
        openConfig?: boolean;
        closeDrawer?: boolean;
        creatorId?: string;
        defaultLogic?: NodeLogic;
        defaultLaw?: FirewallPolicy;
        metricLabel?: string;
        metricValue?: string;
      } = {},
    ): string => {
      if (isReadOnlyWorkflow) {
        setStatusMessage(
          "Read-only harness graph cannot be edited. Fork it first.",
        );
        return selectedNodeId ?? "";
      }
      const nodeId = addNode(type, label, preferredId);
      const definition =
        (options.creatorId
          ? NODE_LIBRARY.find(
              (item) => workflowCreatorItemId(item) === options.creatorId,
            )
          : null) ?? NODE_LIBRARY.find((item) => item.type === type);
      if (definition) {
        const creatorId = workflowCreatorItemId(definition);
        setRecentNodeTypes((current) =>
          [creatorId, ...current.filter((item) => item !== creatorId)].slice(
            0,
            5,
          ),
        );
      }
      if (
        options.defaultLogic ||
        options.defaultLaw ||
        options.metricLabel ||
        options.metricValue
      ) {
        setNodes((currentNodes) =>
          currentNodes.map((flowNode) => {
            if (flowNode.id !== nodeId) return flowNode;
            const data = flowNode.data as Node;
            const currentConfig = data.config ?? {
              kind: type as WorkflowNodeKind,
              logic: {},
              law: {},
            };
            return {
              ...flowNode,
              data: {
                ...data,
                metricLabel: options.metricLabel ?? data.metricLabel,
                metricValue: options.metricValue ?? data.metricValue,
                config: {
                  ...currentConfig,
                  kind: type as WorkflowNodeKind,
                  logic: options.defaultLogic
                    ? { ...options.defaultLogic }
                    : currentConfig.logic,
                  law: options.defaultLaw
                    ? { ...options.defaultLaw }
                    : currentConfig.law,
                },
              },
            };
          }),
        );
      }
      markWorkflowDirty();
      if (options.openConfig) {
        handleNodeSelect(nodeId);
        setBottomPanel("selection");
        closeCanvasSearch();
        setNodeConfigInitialSection(workflowConfigSectionForNodeKind(type));
        setNodeConfigOpen(true);
      }
      if (options.closeDrawer) {
        closeLeftDrawer();
      }
      setStatusMessage(`${label} node added`);
      return nodeId;
    },
    [
      addNode,
      closeCanvasSearch,
      closeLeftDrawer,
      handleNodeSelect,
      isReadOnlyWorkflow,
      markWorkflowDirty,
      selectedNodeId,
      setNodes,
    ],
  );

  const connectWorkflowNodes = useCallback(
    (sourceNodeId: string, targetNodeId: string): boolean => {
      if (sourceNodeId === targetNodeId) return false;
      const sourceNode = nodes.find((flowNode) => flowNode.id === sourceNodeId);
      const targetNode = nodes.find((flowNode) => flowNode.id === targetNodeId);
      const sourceType = String(
        sourceNode?.type ?? (sourceNode?.data as Node | undefined)?.type ?? "",
      );
      const targetType = String(
        targetNode?.type ?? (targetNode?.data as Node | undefined)?.type ?? "",
      );
      const { sourcePort, targetPort, connectionClass } = compatiblePortPair(
        sourceNode,
        targetNode,
      );
      const edgeIssue = validateActionEdge(
        sourceNodeId,
        actionKindForWorkflowNodeType(sourceType),
        targetNodeId,
        actionKindForWorkflowNodeType(targetType),
        sourcePort,
        targetPort,
      );
      if (edgeIssue) {
        setStatusMessage(edgeIssue.message);
        return false;
      }
      const edgeId = `edge-${sourceNodeId}-${targetNodeId}-${Date.now()}`;
      setEdges((currentEdges) => {
        if (
          currentEdges.some(
            (edge) =>
              edge.source === sourceNodeId && edge.target === targetNodeId,
          )
        ) {
          return currentEdges;
        }
        return [
          ...currentEdges,
          {
            id: edgeId,
            source: sourceNodeId,
            target: targetNodeId,
            sourceHandle: sourcePort?.id ?? "output",
            targetHandle: targetPort?.id ?? "input",
            type: "semantic",
            animated: false,
            data: { status: "idle", active: false, connectionClass },
          },
        ];
      });
      markWorkflowDirty();
      setStatusMessage("Nodes connected");
      return true;
    },
    [markWorkflowDirty, nodes, setEdges],
  );

  const handleAddCompatibleNode = useCallback(
    (
      sourceNode: Node,
      item: WorkflowNodeDefinition | WorkflowNodeCreatorDefinition,
      portPath?: Pick<
        WorkflowCompatibleNodeHint,
        "sourcePort" | "targetPort" | "connectionClass" | "direction"
      >,
    ) => {
      const direction = portPath?.direction ?? "downstream";
      const fallbackPair =
        direction === "attachment"
          ? preferredCompatiblePortPair(
              item.portDefinitions.filter(
                (port) => port.direction === "output",
              ),
              (sourceNode.ports ?? []).filter(
                (port) => port.direction === "input",
              ),
            )
          : preferredCompatiblePortPair(
              (sourceNode.ports ?? []).filter(
                (port) => port.direction === "output",
              ),
              item.portDefinitions.filter((port) => port.direction === "input"),
            );
      const sourcePort = portPath?.sourcePort ?? fallbackPair.sourcePort;
      const targetPort = portPath?.targetPort ?? fallbackPair.targetPort;
      const connectionClass =
        portPath?.connectionClass ?? fallbackPair.connectionClass;
      const prospectiveNodeId = `new-${item.type}`;
      const prospectiveEdgeSourceId =
        direction === "attachment" ? prospectiveNodeId : sourceNode.id;
      const prospectiveEdgeTargetId =
        direction === "attachment" ? sourceNode.id : prospectiveNodeId;
      const edgeSourceType =
        direction === "attachment" ? item.type : sourceNode.type;
      const edgeTargetType =
        direction === "attachment" ? sourceNode.type : item.type;
      const edgeIssue = validateActionEdge(
        prospectiveEdgeSourceId,
        actionKindForWorkflowNodeType(edgeSourceType),
        prospectiveEdgeTargetId,
        actionKindForWorkflowNodeType(edgeTargetType),
        sourcePort,
        targetPort,
      );
      if (edgeIssue) {
        setStatusMessage(edgeIssue.message);
        return;
      }
      const nodeId = handleAddNodeFromLibrary(
        item.type,
        item.label,
        undefined,
        {
          creatorId: workflowCreatorItemId(item),
          defaultLogic: item.defaultLogic,
          defaultLaw: item.defaultLaw,
          metricLabel: item.metricLabel,
          metricValue: item.metricValue,
        },
      );
      const edgeSourceId = direction === "attachment" ? nodeId : sourceNode.id;
      const edgeTargetId = direction === "attachment" ? sourceNode.id : nodeId;
      setEdges((currentEdges) => [
        ...currentEdges,
        {
          id: `edge-${edgeSourceId}-${edgeTargetId}-${Date.now()}`,
          source: edgeSourceId,
          target: edgeTargetId,
          sourceHandle: sourcePort?.id ?? "output",
          targetHandle: targetPort?.id ?? "input",
          type: "semantic",
          animated: false,
          data: {
            status: "idle",
            active: false,
            connectionClass,
            createdBy: "compatible_node_picker",
            direction,
          },
        },
      ]);
      markWorkflowDirty();
      handleNodeSelect(nodeId);
      closeLeftDrawer();
      closeCanvasSearch();
      setBottomPanel("selection");
      setNodeConfigInitialSection(workflowConfigSectionForNodeKind(item.type));
      setNodeConfigOpen(true);
      setStatusMessage(
        direction === "attachment"
          ? `${item.label} attached to ${sourceNode.name}`
          : `${item.label} added and connected after ${sourceNode.name}`,
      );
    },
    [
      handleAddNodeFromLibrary,
      handleNodeSelect,
      closeCanvasSearch,
      closeLeftDrawer,
      markWorkflowDirty,
      setEdges,
      setBottomPanel,
      setNodeConfigOpen,
    ],
  );

  const handleInsertAgentLoopMacro = useCallback(() => {
    const macroId = `agent-loop-${Date.now()}`;
    const selectedData = selectedNode;
    const baseX = Number(selectedData?.x ?? 120);
    const baseY = Number(selectedData?.y ?? 180);
    const selectedHasDataOutput = selectedData?.ports?.some(
      (port) =>
        port.direction === "output" &&
        port.connectionClass === "data" &&
        port.id === "output",
    );
    const shouldCreateInput = !selectedData || !selectedHasDataOutput;
    const inputId = shouldCreateInput
      ? handleAddNodeFromLibrary("source", "Agent input", `${macroId}-input`)
      : selectedData.id;
    const memoryId = handleAddNodeFromLibrary(
      "state",
      "Agent memory",
      `${macroId}-memory`,
    );
    const toolId = handleAddNodeFromLibrary(
      "plugin_tool",
      "Agent tool",
      `${macroId}-tool`,
    );
    const modelId = handleAddNodeFromLibrary(
      "model_call",
      "Agent reasoning",
      `${macroId}-model`,
    );
    const decisionId = handleAddNodeFromLibrary(
      "decision",
      "Route result",
      `${macroId}-decision`,
    );
    const outputId = handleAddNodeFromLibrary(
      "output",
      "Agent output",
      `${macroId}-output`,
    );
    const positions: Record<string, { x: number; y: number }> = {
      [memoryId]: { x: baseX + 280, y: baseY + 150 },
      [toolId]: { x: baseX + 280, y: baseY + 300 },
      [modelId]: { x: baseX + 280, y: baseY },
      [decisionId]: { x: baseX + 560, y: baseY },
      [outputId]: { x: baseX + 840, y: baseY },
    };
    const macroRoles: Record<
      string,
      NonNullable<NodeLogic["viewMacro"]>["role"]
    > = {
      [inputId]: "input",
      [memoryId]: "memory",
      [toolId]: "tool",
      [modelId]: "model",
      [decisionId]: "decision",
      [outputId]: "output",
    };
    if (shouldCreateInput) {
      positions[inputId] = { x: baseX, y: baseY };
    }

    setNodes((currentNodes) =>
      currentNodes.map((flowNode) => {
        const nodeData = flowNode.data as Node;
        const position = positions[flowNode.id];
        const macroRole = macroRoles[flowNode.id];
        if (!position && !macroRole) return flowNode;
        let logic = nodeData.config?.logic ?? {};
        let law = nodeData.config?.law ?? {};
        if (flowNode.id === inputId && shouldCreateInput) {
          logic = {
            payload: { message: "Describe the request for this agent run." },
          };
        } else if (flowNode.id === memoryId) {
          logic = {
            stateKey: "agent_memory",
            stateOperation: "merge",
            reducer: "merge",
            initialValue: {},
          };
        } else if (flowNode.id === toolId) {
          logic = {
            toolBinding: {
              toolRef: "codex_plugin",
              bindingKind: "plugin_tool",
              mockBinding: true,
              capabilityScope: ["read", "analyze"],
              sideEffectClass: "read",
              requiresApproval: false,
              arguments: {},
            },
          };
        } else if (flowNode.id === modelId) {
          logic = {
            modelRef: "reasoning",
            prompt:
              "Use the input, memory, and tool attachment to produce the next workflow result.",
          };
        } else if (flowNode.id === decisionId) {
          logic = {
            routes: ["left", "right"],
            defaultRoute: "left",
          };
        }
        if (macroRole) {
          logic = {
            ...logic,
            viewMacro: {
              macroId,
              macroLabel: "Agent loop",
              role: macroRole,
              expandedFrom: "agent_loop_macro",
            },
          };
        }
        return {
          ...flowNode,
          position: position ?? flowNode.position,
          data: {
            ...nodeData,
            x: position?.x ?? nodeData.x,
            y: position?.y ?? nodeData.y,
            config: {
              kind: nodeData.type,
              logic,
              law,
            },
          },
        };
      }),
    );
    setEdges((currentEdges) => {
      const macroEdges = [
        {
          id: `edge-${inputId}-${modelId}-${macroId}`,
          source: inputId,
          target: modelId,
          sourceHandle: "output",
          targetHandle: "input",
          data: {
            status: "idle",
            active: false,
            connectionClass: "data",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${memoryId}-${modelId}-${macroId}`,
          source: memoryId,
          target: modelId,
          sourceHandle: "memory",
          targetHandle: "memory",
          data: {
            status: "idle",
            active: false,
            connectionClass: "memory",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${toolId}-${modelId}-${macroId}`,
          source: toolId,
          target: modelId,
          sourceHandle: "tool",
          targetHandle: "tool",
          data: {
            status: "idle",
            active: false,
            connectionClass: "tool",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${modelId}-${decisionId}-${macroId}`,
          source: modelId,
          target: decisionId,
          sourceHandle: "output",
          targetHandle: "input",
          data: {
            status: "idle",
            active: false,
            connectionClass: "data",
            createdBy: "agent_loop_macro",
          },
        },
        {
          id: `edge-${decisionId}-${outputId}-${macroId}`,
          source: decisionId,
          target: outputId,
          sourceHandle: "left",
          targetHandle: "input",
          data: {
            status: "idle",
            active: false,
            connectionClass: "data",
            createdBy: "agent_loop_macro",
          },
        },
      ];
      const dedupedEdges = macroEdges.filter(
        (edge) =>
          !currentEdges.some(
            (current) =>
              current.source === edge.source &&
              current.target === edge.target &&
              current.targetHandle === edge.targetHandle,
          ),
      );
      return [
        ...currentEdges,
        ...dedupedEdges.map((edge) => ({
          ...edge,
          type: "semantic",
          animated: false,
        })),
      ];
    });
    handleNodeSelect(modelId);
    markWorkflowDirty();
    setStatusMessage("Agent loop expanded into explicit workflow primitives");
  }, [
    handleAddNodeFromLibrary,
    handleNodeSelect,
    markWorkflowDirty,
    selectedNode,
    setEdges,
    setNodes,
  ]);

  const handleConnectSelectedNodes = useCallback(() => {
    if (!connectFromNodeId || !selectedNode) return;
    if (connectWorkflowNodes(connectFromNodeId, selectedNode.id)) {
      setConnectFromNodeId(null);
    }
  }, [connectFromNodeId, connectWorkflowNodes, selectedNode]);

  const handleWorkflowNodeSelect = useCallback(
    (nodeId: string | null) => {
      const harnessGroupId = harnessGroupIdFromNodeId(nodeId);
      if (harnessGroupId) {
        setSelectedHarnessGroupId(harnessGroupId);
        setSelectedHarnessReceiptRef(null);
        setSelectedHarnessReplayFixtureRef(null);
        setSelectedHarnessRollbackTarget(null);
        setSelectedHarnessSelectorDecisionId(null);
        setSelectedHarnessDefaultDispatchId(null);
        setSelectedHarnessWorkerBindingId(null);
        setSelectedHarnessNodeAttemptId(null);
        setSelectedHarnessRevisionBindingKind(null);
        setSelectedHarnessRevisionBindingRef(null);
        setSelectedHarnessActivationBlockerIndex(null);
        setSelectedHarnessActivationBlockerRef(null);
        setSelectedHarnessActivationAuditEventId(null);
        setSelectedHarnessActivationGateId(null);
        setSelectedHarnessActivationGateEvidenceRef(null);
        setSelectedHarnessActivationGateNodeAttemptId(null);
        setSelectedHarnessActivationGateReceiptRef(null);
        setSelectedHarnessActivationGateReplayFixtureRef(null);
        handleNodeSelect(null);
        setRightPanel("outputs");
        setBottomPanel("selection");
        setStatusMessage(`Inspecting harness group ${harnessGroupId}`);
        return;
      }
      setSelectedHarnessGroupId(null);
      setSelectedHarnessReceiptRef(null);
      setSelectedHarnessReplayFixtureRef(null);
      setSelectedHarnessRollbackTarget(null);
      setSelectedHarnessSelectorDecisionId(null);
      setSelectedHarnessDefaultDispatchId(null);
      setSelectedHarnessWorkerBindingId(null);
      setSelectedHarnessNodeAttemptId(null);
      setSelectedHarnessRevisionBindingKind(null);
      setSelectedHarnessRevisionBindingRef(null);
      setSelectedHarnessActivationBlockerIndex(null);
      setSelectedHarnessActivationBlockerRef(null);
      setSelectedHarnessActivationAuditEventId(null);
      setSelectedHarnessActivationGateId(null);
      setSelectedHarnessActivationGateEvidenceRef(null);
      setSelectedHarnessActivationGateNodeAttemptId(null);
      setSelectedHarnessActivationGateReceiptRef(null);
      setSelectedHarnessActivationGateReplayFixtureRef(null);
      if (nodeId && connectFromNodeId && connectFromNodeId !== nodeId) {
        if (connectWorkflowNodes(connectFromNodeId, nodeId)) {
          setConnectFromNodeId(null);
        }
      }
      handleNodeSelect(nodeId);
    },
    [connectFromNodeId, connectWorkflowNodes, handleNodeSelect],
  );

  const handleInspectHarnessGroupNode = useCallback(
    (groupId: string, nodeId: string) => {
      setCollapsedHarnessGroupIds((current) => ({
        ...current,
        [groupId]: false,
      }));
      setSelectedHarnessGroupId(null);
      setSelectedHarnessReceiptRef(null);
      setSelectedHarnessReplayFixtureRef(null);
      setSelectedHarnessRollbackTarget(null);
      setSelectedHarnessSelectorDecisionId(null);
      setSelectedHarnessDefaultDispatchId(null);
      setSelectedHarnessWorkerBindingId(null);
      setSelectedHarnessNodeAttemptId(null);
      setSelectedHarnessRevisionBindingKind(null);
      setSelectedHarnessRevisionBindingRef(null);
      setSelectedHarnessActivationBlockerIndex(null);
      setSelectedHarnessActivationBlockerRef(null);
      setSelectedHarnessActivationAuditEventId(null);
      setSelectedHarnessActivationGateId(null);
      setSelectedHarnessActivationGateEvidenceRef(null);
      setSelectedHarnessActivationGateNodeAttemptId(null);
      setSelectedHarnessActivationGateReceiptRef(null);
      setSelectedHarnessActivationGateReplayFixtureRef(null);
      handleNodeSelect(nodeId);
      setRightPanel("outputs");
      setBottomPanel("selection");
      setStatusMessage(`Opened ${nodeId} from harness group ${groupId}`);
      requestAnimationFrame(() => fitView({ padding: 0.2 }));
    },
    [fitView, handleNodeSelect],
  );
  const handleSelectHarnessReceiptRef = useCallback((receiptRef: string) => {
    setSelectedHarnessReceiptRef(receiptRef);
    setSelectedHarnessSelectorDecisionId(null);
    setSelectedHarnessDefaultDispatchId(null);
    setSelectedHarnessWorkerBindingId(null);
    setSelectedHarnessNodeAttemptId(null);
    setSelectedHarnessRevisionBindingKind(null);
    setSelectedHarnessRevisionBindingRef(null);
    setSelectedHarnessActivationBlockerIndex(null);
    setSelectedHarnessActivationBlockerRef(null);
    setSelectedHarnessActivationAuditEventId(null);
    setSelectedHarnessActivationGateId(null);
    setSelectedHarnessActivationGateEvidenceRef(null);
    setSelectedHarnessActivationGateNodeAttemptId(null);
    setSelectedHarnessActivationGateReceiptRef(null);
    setSelectedHarnessActivationGateReplayFixtureRef(null);
    setRightPanel("outputs");
    setStatusMessage(`Pinned harness receipt ${receiptRef}`);
  }, []);
  const handleSelectHarnessReplayFixtureRef = useCallback(
    (replayFixtureRef: string) => {
      setSelectedHarnessReplayFixtureRef(replayFixtureRef);
      setSelectedHarnessSelectorDecisionId(null);
      setSelectedHarnessDefaultDispatchId(null);
      setSelectedHarnessWorkerBindingId(null);
      setSelectedHarnessNodeAttemptId(null);
      setSelectedHarnessRevisionBindingKind(null);
      setSelectedHarnessRevisionBindingRef(null);
      setSelectedHarnessActivationBlockerIndex(null);
      setSelectedHarnessActivationBlockerRef(null);
      setSelectedHarnessActivationAuditEventId(null);
      setSelectedHarnessActivationGateId(null);
      setSelectedHarnessActivationGateEvidenceRef(null);
      setSelectedHarnessActivationGateNodeAttemptId(null);
      setSelectedHarnessActivationGateReceiptRef(null);
      setSelectedHarnessActivationGateReplayFixtureRef(null);
      setRightPanel("outputs");
      setStatusMessage(`Pinned replay fixture ${replayFixtureRef}`);
    },
    [],
  );
  const handleRunHarnessReplayDrill = useCallback(() => {
    const harnessDefaultRuntimeDispatchProof =
      currentProjectFile.metadata.harness?.defaultRuntimeDispatchProof;
    const replayInspection = resolveWorkflowHarnessReplayInspection({
      replayFixtureRef: selectedHarnessReplayFixtureRef,
      workflow: currentProjectFile,
      lastRunResult,
      selectedRunId,
      selectedHarnessGroup,
      readOnlyRoutingReady:
        harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReady ===
          true &&
        harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSelected ===
          true &&
        harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingNoMutationReady ===
          true,
      authorityToolingProof:
        harnessDefaultRuntimeDispatchProof?.authorityToolingProof ?? null,
    });
    const result = executeWorkflowHarnessReplayDrill(
      currentProjectFile,
      replayInspection,
    );
    setWorkflow(result.workflow);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("outputs");
    setBottomPanel("selection");
    setStatusMessage(
      result.executed
        ? `Replay drill passed: ${result.drill?.replayFixtureRef ?? selectedHarnessReplayFixtureRef}`
        : `Replay drill blocked by ${result.blockers.length} blocker${
            result.blockers.length === 1 ? "" : "s"
          }`,
    );
  }, [
    currentProjectFile,
    lastRunResult,
    nodeFixturesById,
    proposals,
    selectedHarnessGroup,
    selectedHarnessReplayFixtureRef,
    selectedRunId,
    tests,
  ]);
  const handleRunHarnessReplayGate = useCallback(() => {
    const harnessDefaultRuntimeDispatchProof =
      currentProjectFile.metadata.harness?.defaultRuntimeDispatchProof;
    const activationGateReplayFixtureRefs =
      selectedHarnessActivationGateId === "replay-fixtures"
        ? workflowUniqueReplayFixtureRefs([
            ...(currentProjectFile.metadata.harness?.replayDrills ?? []).map(
              (drill) => drill.replayFixtureRef,
            ),
            ...(currentProjectFile.metadata.harness?.replayGates ?? []).flatMap(
              (gate) => gate.replayFixtureRefs,
            ),
            ...(
              currentProjectFile.metadata.harness?.promotionClusters ?? []
            ).flatMap(
              (cluster) => cluster.replayGateProof?.replayFixtureRefs ?? [],
            ),
            ...(harnessDefaultRuntimeDispatchProof?.replayFixtureRefs ?? []),
            selectedHarnessActivationGateReplayFixtureRef,
          ])
        : [];
    const harnessGroupReplayFixtureRefs =
      selectedHarnessGroup?.deepLinks.replayFixtureRefs ?? [];
    const fallbackReplayFixtureRefs = [
      ...(harnessDefaultRuntimeDispatchProof?.replayFixtureRefs ?? []),
      ...currentProjectFile.nodes.flatMap((node) =>
        node.runtimeBinding?.replayEnvelope?.fixtureRef
          ? [node.runtimeBinding.replayEnvelope.fixtureRef]
          : [],
      ),
      ...(selectedHarnessReplayFixtureRef
        ? [selectedHarnessReplayFixtureRef]
        : []),
    ];
    const replayFixtureRefs = Array.from(
      new Set(
        (activationGateReplayFixtureRefs.length
          ? activationGateReplayFixtureRefs
          : harnessGroupReplayFixtureRefs.length
            ? harnessGroupReplayFixtureRefs
            : fallbackReplayFixtureRefs
        ).filter(
          (ref): ref is string => typeof ref === "string" && ref.length > 0,
        ),
      ),
    );
    const readOnlyRoutingReady =
      harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReady ===
        true &&
      harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSelected ===
        true &&
      harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingNoMutationReady ===
        true;
    const replayInspections = replayFixtureRefs.map((replayFixtureRef) =>
      resolveWorkflowHarnessReplayInspection({
        replayFixtureRef,
        workflow: currentProjectFile,
        lastRunResult,
        selectedRunId,
        selectedHarnessGroup,
        readOnlyRoutingReady,
        authorityToolingProof:
          harnessDefaultRuntimeDispatchProof?.authorityToolingProof ?? null,
      }),
    );
    const replayGateScopeKind = activationGateReplayFixtureRefs.length
      ? "activation_candidate"
      : selectedHarnessGroup
        ? "harness_group"
        : "activation_candidate";
    const replayGateTargetId = activationGateReplayFixtureRefs.length
      ? (currentProjectFile.metadata.harness?.activationId ??
        currentProjectFile.metadata.id)
      : selectedHarnessGroup
        ? String(selectedHarnessGroup.groupId)
        : (currentProjectFile.metadata.harness?.activationId ??
          currentProjectFile.metadata.id);
    const result = executeWorkflowHarnessReplayGate(
      currentProjectFile,
      replayInspections,
      {
        scopeKind: replayGateScopeKind,
        targetId: replayGateTargetId,
      },
    );
    setWorkflow(result.workflow);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("outputs");
    setBottomPanel("selection");
    const replayGateStatusMessage = result.executed
      ? `Replay gate passed: ${result.gate.totalFixtures} fixtures`
      : `Replay gate blocked by ${result.gate.blockingReplayFixtureRefs.length} fixture${
          result.gate.blockingReplayFixtureRefs.length === 1 ? "" : "s"
        }`;
    if (HARNESS_PROMOTION_LIVE_GUI_SCRIPT && typeof window !== "undefined") {
      (window as any).__AUTOPILOT_HARNESS_REPLAY_GATE_CLICK_RESULT = {
        gateId: result.gate.gateId,
        gateStatus: result.gate.gateStatus,
        activationGateImpact: result.gate.activationGateImpact,
        scopeKind: result.gate.scopeKind,
        targetId: result.gate.targetId,
        totalFixtures: result.gate.totalFixtures,
        replayFixtureRefs: result.gate.replayFixtureRefs,
        receiptRefs: result.gate.receiptRefs,
        evidenceRefs: result.gate.evidenceRefs,
        replayGateCount:
          result.workflow.metadata.harness?.replayGates?.length ?? 0,
        replayDrillCount:
          result.workflow.metadata.harness?.replayDrills?.length ?? 0,
        statusMessage: replayGateStatusMessage,
      } satisfies HarnessReplayGateClickResult;
    }
    setStatusMessage(replayGateStatusMessage);
  }, [
    currentProjectFile,
    lastRunResult,
    nodeFixturesById,
    proposals,
    selectedHarnessActivationGateId,
    selectedHarnessActivationGateReplayFixtureRef,
    selectedHarnessGroup,
    selectedHarnessReplayFixtureRef,
    selectedRunId,
    tests,
  ]);
  const handleRunHarnessPromotionTransition = useCallback(
    (targetExecutionMode: WorkflowHarnessPromotionTransitionTarget) => {
      if (!selectedHarnessGroup) {
        setStatusMessage(
          "Select a harness promotion group before promoting it.",
        );
        return;
      }
      const result = executeWorkflowHarnessPromotionTransition(
        currentProjectFile,
        String(selectedHarnessGroup.groupId),
        targetExecutionMode,
      );
      setWorkflow(result.workflow);
      const validation = validateWorkflowProject(result.workflow, tests);
      const readiness = evaluateWorkflowActivationReadiness(
        result.workflow,
        tests,
        validation,
        proposals,
        Object.values(nodeFixturesById).flat(),
      );
      setValidationResult(validation);
      setReadinessResult(readiness);
      setRightPanel("outputs");
      setBottomPanel("selection");
      setStatusMessage(
        result.promoted
          ? `${result.attempt.clusterLabel} promoted to ${targetExecutionMode}`
          : `${result.attempt.clusterLabel} promotion blocked by ${result.blockers.length} gate${
              result.blockers.length === 1 ? "" : "s"
            }`,
      );
    },
    [
      currentProjectFile,
      nodeFixturesById,
      proposals,
      selectedHarnessGroup,
      tests,
    ],
  );
  const handleSelectHarnessRollbackTarget = useCallback(
    (rollbackTarget: string) => {
      setSelectedHarnessRollbackTarget(rollbackTarget);
      setSelectedHarnessSelectorDecisionId(null);
      setSelectedHarnessDefaultDispatchId(null);
      setSelectedHarnessWorkerBindingId(null);
      setSelectedHarnessNodeAttemptId(null);
      setSelectedHarnessRevisionBindingKind(null);
      setSelectedHarnessRevisionBindingRef(null);
      setSelectedHarnessActivationBlockerIndex(null);
      setSelectedHarnessActivationBlockerRef(null);
      setSelectedHarnessActivationAuditEventId(null);
      setSelectedHarnessActivationGateId(null);
      setSelectedHarnessActivationGateEvidenceRef(null);
      setSelectedHarnessActivationGateNodeAttemptId(null);
      setSelectedHarnessActivationGateReceiptRef(null);
      setSelectedHarnessActivationGateReplayFixtureRef(null);
      if (!isReadOnlyWorkflow) {
        setWorkflow(
          recordWorkflowHarnessRollbackTargetSelection(
            currentProjectFile,
            rollbackTarget,
          ),
        );
      }
      setRightPanel("settings");
      setStatusMessage(`Rollback target selected: ${rollbackTarget}`);
    },
    [currentProjectFile, isReadOnlyWorkflow],
  );
  const handleCopyHarnessDeepLink = useCallback(
    (target?: HarnessWorkbenchDeepLink) => {
      const link = target
        ? {
            panel: target.panel ?? rightPanel,
            ...target,
          }
        : harnessWorkbenchDeepLink;
      const linkUrl = link
        ? harnessWorkbenchDeepLinkHref(encodeHarnessWorkbenchDeepLink(link))
        : harnessWorkbenchDeepLinkUrl;
      if (!link || !linkUrl) {
        setStatusMessage(
          "Select a harness group, component, run, receipt, or replay fixture first.",
        );
        return;
      }
      applyHarnessWorkbenchDeepLink(link);
      writeHarnessWorkbenchDeepLink(encodeHarnessWorkbenchDeepLink(link));
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        void navigator.clipboard
          .writeText(linkUrl)
          .then(() => setStatusMessage("Copied harness workbench deep link"))
          .catch(() => {
            setStatusMessage(`Harness workbench link: ${linkUrl}`);
          });
        return;
      }
      setStatusMessage(`Harness workbench link: ${linkUrl}`);
    },
    [
      applyHarnessWorkbenchDeepLink,
      harnessWorkbenchDeepLink,
      harnessWorkbenchDeepLinkUrl,
      rightPanel,
    ],
  );

  const handleInspectExecutionNode = useCallback(
    (nodeId: string) => {
      handleWorkflowNodeSelect(nodeId);
      setActiveTab("graph");
      setRightPanel("runs");
      setBottomPanel("selection");
    },
    [handleWorkflowNodeSelect],
  );

  const handleResolveWorkflowIssue = useCallback(
    (issue: WorkflowValidationIssue) => {
      if (issue.nodeId) {
        handleWorkflowNodeSelect(issue.nodeId);
        setNodeConfigInitialSection(workflowConfigSectionForIssue(issue));
        setBottomPanel(
          issue.code === "missing_replay_fixture" ? "fixtures" : "selection",
        );
        setNodeConfigOpen(true);
        setStatusMessage(workflowIssueActionLabel(issue));
        return;
      }

      setCompatiblePortFocus(null);
      setCanvasSearchOpen(false);
      setActiveTab("graph");

      if (issue.code === "missing_output_node") {
        setNodeGroupFilter("Outputs");
        setNodeSearch("");
        openLeftDrawer();
        setStatusMessage("Add an Output primitive");
        return;
      }

      if (
        issue.code === "missing_start_node" ||
        issue.code === "missing_scheduled_trigger" ||
        issue.code === "missing_event_trigger"
      ) {
        setNodeGroupFilter("Start");
        setNodeSearch(
          issue.code === "missing_scheduled_trigger"
            ? "scheduled"
            : issue.code === "missing_event_trigger"
              ? "event"
              : "",
        );
        openLeftDrawer();
        setStatusMessage("Add a start primitive");
        return;
      }

      if (issue.code === "missing_unit_tests") {
        const firstTarget =
          selectedNode?.id ??
          ((nodes[0]?.data as Node | undefined)?.id || nodes[0]?.id || "");
        setRightPanel("unit_tests");
        setBottomPanel("test_output");
        setNewTestName(
          firstTarget ? "Selected node exists" : "Workflow smoke test",
        );
        setNewTestTargets(firstTarget);
        setNewTestKind("node_exists");
        setNewTestExpected("");
        setNewTestExpression("");
        setTestEditorOpen(true);
        setStatusMessage("Create a unit test");
        return;
      }

      if (issue.code === "missing_error_handling_path") {
        setNodeGroupFilter("Flow");
        setNodeSearch("error");
        openLeftDrawer();
        setStatusMessage("Add an error or retry path");
        return;
      }

      if (issue.code === "mock_binding_active") {
        setRightPanel("settings");
        setStatusMessage("Review binding mode");
        return;
      }

      setRightPanel("settings");
      setStatusMessage(workflowIssueActionLabel(issue));
    },
    [handleWorkflowNodeSelect, nodes, openLeftDrawer, selectedNode],
  );
  const displayNodes = useMemo(() => {
    const componentNodes = nodes
      .filter((flowNode) => !collapsedHarnessGroupByNodeId.has(flowNode.id))
      .map((flowNode) => {
        const run = nodeRunStatusById[flowNode.id];
        const data = flowNode.data as Node;
        const issueSummary = canvasIssuesByNodeId.get(flowNode.id);
        return {
          ...flowNode,
          data: {
            ...data,
            onRequestCompatibleNodes: handleShowCompatibleNodesForPort,
            onResolveCanvasIssue: handleResolveWorkflowIssue,
            validationIssueSummary: issueSummary
              ? {
                  blockerCount: issueSummary.blockers.length,
                  warningCount: issueSummary.warnings.length,
                  issueCount:
                    issueSummary.blockers.length + issueSummary.warnings.length,
                  title: workflowIssueTitle(issueSummary.primaryIssue),
                  message: issueSummary.primaryIssue.message,
                  actionLabel: workflowIssueActionLabel(
                    issueSummary.primaryIssue,
                  ),
                  primaryIssue: issueSummary.primaryIssue,
                }
              : null,
            ...(run
              ? {
                  status: nodeVisualStatus(run.status),
                  metricLabel: "Run",
                  metricValue: run.status,
                }
              : {}),
          },
        };
      });
    const groupNodes = harnessGroupViews
      .filter((group) => group.collapsed)
      .map(
        (group): ReactFlowNode => ({
          id: group.groupNodeId,
          type: "subgraph",
          position: group.position,
          draggable: false,
          selectable: true,
          data: {
            id: group.groupNodeId,
            type: "subgraph",
            name: group.label,
            x: group.position.x,
            y: group.position.y,
            status: harnessGroupRollupStatus(group),
            metricLabel: "Harness group",
            metricValue: `${group.innerNodeIds.length} nodes`,
            inputs: ["input"],
            outputs: ["output", "error", "retry"],
            ports: HARNESS_GROUP_BOUNDARY_PORTS,
            ioTypes: {
              in: "boundary",
              out: "boundary",
            },
            config: {
              kind: "subgraph",
              logic: {
                harnessGroup: group,
              },
              law: {},
            },
            onToggleHarnessGroup: () =>
              handleToggleHarnessGroup(String(group.groupId)),
            onOpenHarnessGroup: () =>
              handleExpandHarnessGroup(String(group.groupId)),
          },
        }),
      );
    return [...componentNodes, ...groupNodes];
  }, [
    canvasIssuesByNodeId,
    collapsedHarnessGroupByNodeId,
    handleExpandHarnessGroup,
    handleResolveWorkflowIssue,
    handleShowCompatibleNodesForPort,
    handleToggleHarnessGroup,
    harnessGroupViews,
    nodeRunStatusById,
    nodes,
  ]);

  const updateNode = useCallback(
    (nodeId: string, updates: Partial<Node>) => {
      if (isReadOnlyWorkflow) {
        setStatusMessage(
          "Read-only harness graph cannot be edited. Fork it first.",
        );
        return;
      }
      setNodes((currentNodes) =>
        currentNodes.map((flowNode) =>
          flowNode.id === nodeId
            ? {
                ...flowNode,
                data: {
                  ...flowNode.data,
                  ...updates,
                  config: updates.config ?? (flowNode.data as Node).config,
                },
              }
            : flowNode,
        ),
      );
      markWorkflowDirty();
    },
    [isReadOnlyWorkflow, markWorkflowDirty, setNodes],
  );

  const handleCreateWorkflow = async () => {
    const request: CreateWorkflowProjectRequest = {
      projectRoot: currentProject?.rootPath || ".",
      name: createName,
      workflowKind: createKind,
      executionMode: createMode,
    };
    if (runtime.createWorkflowProject) {
      const bundle = await runtime.createWorkflowProject(request);
      setWorkflowPath(bundle.workflowPath);
      setTestsPath(bundle.testsPath);
      setTests(bundle.tests);
      setProposals(bundle.proposals);
      setRuns(bundle.runs);
      clearRunState();
      loadWorkflowProject(bundle.workflow);
      await loadRuntimeSidecars(bundle.workflowPath);
      setStatusMessage("Blank workflow created");
    } else {
      const next = makeDefaultWorkflow(createName);
      next.metadata.workflowKind = createKind;
      next.metadata.executionMode = createMode;
      setTests(defaultTestsForWorkflow(next));
      setRuns([]);
      clearRunState();
      loadWorkflowProject(next);
      setStatusMessage("Blank workflow initialized locally");
    }
    setCreateOpen(false);
  };

  const handleOpenDefaultHarness = useCallback(() => {
    const next = makeDefaultAgentHarnessWorkflow();
    const projectRoot = currentProject?.rootPath || ".";
    setWorkflowPath(
      `${projectRoot}/.agents/workflows/${next.metadata.slug}.workflow.json`,
    );
    setTestsPath(
      `${projectRoot}/.agents/workflows/${next.metadata.slug}.tests.json`,
    );
    setTests(defaultAgentHarnessTests(next));
    setProposals([]);
    setRuns([]);
    clearRunState();
    loadWorkflowProject(next);
    setValidationResult(
      validateWorkflowProject(next, defaultAgentHarnessTests(next)),
    );
    setRightPanel("settings");
    setBottomPanel("selection");
    setStatusMessage("Default Agent Harness opened as a read-only graph");
  }, [clearRunState, currentProject?.rootPath, loadWorkflowProject]);

  const handleForkDefaultHarness = useCallback(() => {
    const fork = forkDefaultAgentHarnessWorkflow();
    const projectRoot = currentProject?.rootPath || ".";
    const nextPath = `${projectRoot}/.agents/workflows/${fork.workflow.metadata.slug}.workflow.json`;
    setWorkflowPath(nextPath);
    setTestsPath(nextPath.replace(/\.workflow\.json$/, ".tests.json"));
    setTests(fork.tests);
    setProposals(fork.proposals);
    setRuns([]);
    clearRunState();
    loadWorkflowProject(fork.workflow);
    const base = validateWorkflowProject(fork.workflow, fork.tests);
    setValidationResult(base);
    setReadinessResult(
      evaluateWorkflowActivationReadiness(
        fork.workflow,
        fork.tests,
        base,
        fork.proposals,
      ),
    );
    setRightPanel("settings");
    setBottomPanel("selection");
    setStatusMessage(
      "Harness fork created with activation wizard and blockers",
    );
  }, [clearRunState, currentProject?.rootPath, loadWorkflowProject]);

  const handleSave = async () => {
    if (isReadOnlyWorkflow) {
      setStatusMessage(
        "Read-only harness graph cannot be saved. Fork it first.",
      );
      return;
    }
    const next = toWorkflowProject(nodes, edges, globalConfig, workflow);
    if (runtime.saveWorkflowProject) {
      await runtime.saveWorkflowProject(workflowPath, next);
    } else {
      await runtime.saveProject(workflowPath, next);
    }
    if (runtime.saveWorkflowTests) {
      await runtime.saveWorkflowTests(workflowPath, tests);
    }
    setWorkflow({ ...next, metadata: { ...next.metadata, dirty: false } });
    setValidationResult(validateWorkflowProject(next, tests));
    await loadRuntimeSidecars(workflowPath);
    setStatusMessage("Saved");
  };

  const handleGenerateBindingManifest = async () => {
    if (!runtime.generateWorkflowBindingManifest) {
      setStatusMessage("Binding manifest unavailable");
      return;
    }
    await handleSave();
    const manifest =
      await runtime.generateWorkflowBindingManifest(workflowPath);
    setBindingManifest(manifest);
    await loadRuntimeSidecars(workflowPath);
    setRightPanel("settings");
    setStatusMessage(
      `Binding manifest ready: ${manifest.summary.ready}/${manifest.summary.total}`,
    );
  };

  const handleValidate = async () => {
    let result: WorkflowValidationResult;
    try {
      result = runtime.validateWorkflowBundle
        ? await runtime.validateWorkflowBundle(workflowPath)
        : validateWorkflowProject(currentProjectFile, tests);
    } catch (error) {
      result = createWorkflowActionFailure(
        "workflow_bundle_unavailable",
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setValidationResult(result);
    setBottomPanel("warnings");
    setStatusMessage(workflowValidationStatusMessage("Validation", result));
  };

  const handleCheckReadiness = async (): Promise<WorkflowValidationResult> => {
    let result: WorkflowValidationResult;
    try {
      const runtimeReadinessAvailable = Boolean(
        runtime.validateWorkflowExecutionReadiness,
      );
      const runtimeResult = runtime.validateWorkflowExecutionReadiness
        ? await runtime.validateWorkflowExecutionReadiness(workflowPath)
        : validateWorkflowProject(currentProjectFile, tests);
      result = evaluateWorkflowActivationReadiness(
        currentProjectFile,
        tests,
        runtimeResult,
        proposals,
        runtimeReadinessAvailable
          ? null
          : Object.values(nodeFixturesById).flat(),
      );
    } catch (error) {
      result = createWorkflowActionFailure(
        "workflow_bundle_unavailable",
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setReadinessResult(result);
    setRightPanel("readiness");
    setStatusMessage(workflowValidationStatusMessage("Readiness", result));
    return result;
  };

  const handleRunHarnessActivationDryRun = useCallback(async () => {
    const base = validateWorkflowProject(currentProjectFile, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      currentProjectFile,
      tests,
      base,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    const rollbackRevisionBinding =
      currentProjectFile.metadata.harness?.activationRecord
        ?.rollbackRevisionBinding ??
      currentProjectFile.metadata.harness?.activationRollbackProof
        ?.restoredRevisionBinding ??
      null;
    const { rollbackRestoreResult, rollbackRestoreBlockers } =
      await runWorkflowHarnessRollbackRestoreCanaryProbe({
        runtime,
        workflowPath,
        rollbackRevisionBinding,
      });
    const candidate = createWorkflowHarnessActivationCandidate(
      currentProjectFile,
      tests,
      readiness,
      proposals,
      Date.now(),
      {
        rollbackRestoreResult,
        rollbackRestoreBlockers,
      },
    );
    const workflowWithDryRun = recordWorkflowHarnessActivationDryRun(
      currentProjectFile,
      candidate,
    );
    setValidationResult(base);
    setReadinessResult(readiness);
    setHarnessActivationCandidate(candidate);
    setWorkflow(workflowWithDryRun);
    setRightPanel("settings");
    setBottomPanel("selection");
    const dryRunStatusMessage =
      candidate.decision === "mintable"
        ? `Activation dry run mintable: ${candidate.activationIdPreview}`
        : `Activation dry run blocked by ${candidate.activationBlockers.length} blocker${
            candidate.activationBlockers.length === 1 ? "" : "s"
          }`;
    if (HARNESS_PROMOTION_LIVE_GUI_SCRIPT && typeof window !== "undefined") {
      const activationAudit =
        workflowWithDryRun.metadata.harness?.activationAudit ?? [];
      const latestAuditEvent =
        activationAudit.length > 0
          ? activationAudit[activationAudit.length - 1]
          : null;
      const rollbackRestoreGate =
        candidate.gateResults.find(
          (gate) => gate.gateId === "rollback-restore",
        ) ?? null;
      (window as any).__AUTOPILOT_HARNESS_ACTIVATION_DRY_RUN_CLICK_RESULT = {
        candidateId: candidate.candidateId,
        decision: candidate.decision,
        activationBlockerCount: candidate.activationBlockers.length,
        workflowActivationId:
          workflowWithDryRun.metadata.harness?.activationId ?? null,
        workflowActivationState:
          workflowWithDryRun.metadata.harness?.activationState ?? null,
        workerBindingActivationId:
          workflowWithDryRun.metadata.workerHarnessBinding
            ?.harnessActivationId ?? null,
        rollbackRestoreCanaryId: candidate.rollbackRestoreCanary.canaryId,
        rollbackRestoreStatus: candidate.rollbackRestoreCanary.status,
        rollbackRestoreRevisionSource:
          candidate.rollbackRestoreCanary.revisionSource,
        rollbackRestoreStrategy:
          candidate.rollbackRestoreCanary.restoreStrategy,
        rollbackRestoreHashVerified:
          candidate.rollbackRestoreCanary.hashVerified,
        rollbackRestoreReceiptBindingRef:
          candidate.rollbackRestoreCanary.receiptBindingRef ?? null,
        rollbackRestoreEvidenceRefs:
          candidate.rollbackRestoreCanary.evidenceRefs,
        rollbackRestoreBlockers: candidate.rollbackRestoreCanary.blockers,
        rollbackRestoreGateStatus: rollbackRestoreGate?.status ?? null,
        activationAuditEventCount: activationAudit.length,
        latestAuditEventId: latestAuditEvent?.eventId ?? null,
        latestAuditEventType: latestAuditEvent?.eventType ?? null,
        latestAuditStatus: latestAuditEvent?.status ?? null,
        statusMessage: dryRunStatusMessage,
      } satisfies HarnessActivationDryRunClickResult;
    }
    setStatusMessage(dryRunStatusMessage);
  }, [
    currentProjectFile,
    nodeFixturesById,
    proposals,
    runtime,
    tests,
    workflowPath,
  ]);

  const handleApplyHarnessActivationCandidate = useCallback(async () => {
    const reviewedPackageSource = packageImportReview?.source ?? null;
    const reviewedPackageSnapshot =
      reviewedPackageSnapshotFromPackageImportSource(reviewedPackageSource);
    const candidate =
      harnessActivationCandidate ??
      createWorkflowHarnessActivationCandidate(
        currentProjectFile,
        tests,
        evaluateWorkflowActivationReadiness(
          currentProjectFile,
          tests,
          validateWorkflowProject(currentProjectFile, tests),
          proposals,
          Object.values(nodeFixturesById).flat(),
        ),
        proposals,
      );
    const result = applyWorkflowHarnessActivationCandidate(
      currentProjectFile,
      candidate,
      {
        rollbackTarget: selectedHarnessRollbackTarget,
        reviewedPackageSnapshot,
      },
    );
    if (!result.applied) {
      setWorkflow(result.workflow);
      setHarnessActivationCandidate(candidate);
      setRightPanel("settings");
      setBottomPanel("selection");
      const blockedStatusMessage = `Activation mint blocked by ${result.blockers.length} blocker${
        result.blockers.length === 1 ? "" : "s"
      }`;
      if (HARNESS_PROMOTION_LIVE_GUI_SCRIPT && typeof window !== "undefined") {
        const activationAudit =
          result.workflow.metadata.harness?.activationAudit ?? [];
        const latestAuditEvent =
          activationAudit.length > 0
            ? activationAudit[activationAudit.length - 1]
            : null;
        (window as any).__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT = {
          applied: false,
          activationId: result.activationId ?? null,
          blockers: result.blockers,
          workflowActivationId:
            result.workflow.metadata.harness?.activationId ?? null,
          workflowActivationState:
            result.workflow.metadata.harness?.activationState ?? null,
          workerBindingActivationId:
            result.workflow.metadata.workerHarnessBinding
              ?.harnessActivationId ?? null,
          activationRecordWorkerBindingActivationId:
            result.workflow.metadata.harness?.activationRecord?.workerBinding
              ?.harnessActivationId ?? null,
          rollbackTarget: result.rollbackTarget ?? null,
          revisionBindingActivationId:
            result.workflow.metadata.harness?.revisionBinding?.activationId ??
            null,
          activationRecordRevisionBindingHash:
            result.workflow.metadata.harness?.activationRecord?.revisionBinding
              ?.workflowContentHash ?? null,
          rollbackRevisionBindingHash:
            result.workflow.metadata.harness?.activationRecord
              ?.rollbackRevisionBinding?.workflowContentHash ?? null,
          activationAuditEventCount: activationAudit.length,
          latestAuditEventId: latestAuditEvent?.eventId ?? null,
          latestAuditEventType: latestAuditEvent?.eventType ?? null,
          latestAuditStatus: latestAuditEvent?.status ?? null,
          receiptRefs: latestAuditEvent?.receiptRefs ?? [],
          evidenceRefs: latestAuditEvent?.evidenceRefs ?? [],
        workerHandoffReceiptIds: [],
        workerHandoffNodeAttemptIds: [],
        workerHandoffReplayFixtureRefs: [],
        reviewedPackageSnapshotHash:
          reviewedPackageSource?.reviewedPackageSnapshotHash ?? null,
        reviewedWorkflowContentHash:
          reviewedPackageSource?.workflowContentHash ?? null,
          reviewedActivationId: reviewedPackageSource?.activationId ?? null,
          reviewedHarnessWorkflowId:
            reviewedPackageSource?.harnessWorkflowId ?? null,
          reviewedWorkerBindingActivationId:
            reviewedPackageSource?.workerBindingActivationId ?? null,
          reviewedRollbackTarget: reviewedPackageSource?.rollbackTarget ?? null,
          reviewedReplayFixtureRefs:
            reviewedPackageSource?.replayFixtureRefs ?? [],
          reviewedWorkerHandoffNodeAttemptIds:
            reviewedPackageSource?.workerHandoffNodeAttemptIds ?? [],
	          reviewedWorkerHandoffReceiptIds:
	            reviewedPackageSource?.workerHandoffReceiptIds ?? [],
          reviewedForkMutationCanaryId:
            reviewedPackageSource?.forkMutationCanaryId ?? null,
          reviewedForkMutationCanaryStatus:
            reviewedPackageSource?.forkMutationCanaryStatus ?? null,
          reviewedForkMutationCanaryDiffHash:
            reviewedPackageSource?.forkMutationCanaryDiffHash ?? null,
          reviewedForkMutationCanaryReceiptRefs:
            reviewedPackageSource?.forkMutationCanaryReceiptRefs ?? [],
          reviewedForkMutationCanaryReplayFixtureRefs:
            reviewedPackageSource?.forkMutationCanaryReplayFixtureRefs ?? [],
          reviewedForkMutationCanaryNodeAttemptIds:
            reviewedPackageSource?.forkMutationCanaryNodeAttemptIds ?? [],
          reviewedForkMutationCanaryRollbackTarget:
            reviewedPackageSource?.forkMutationCanaryRollbackTarget ?? null,
	          reviewedPolicyPosture: reviewedPackageSource?.policyPosture ?? null,
          statusMessage: blockedStatusMessage,
        } satisfies HarnessActivationMintClickResult;
      }
      setStatusMessage(blockedStatusMessage);
      return;
    }
    setWorkflow(result.workflow);
    setHarnessActivationCandidate(null);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("settings");
    setBottomPanel("selection");
    const mintedStatusMessage = `Activation minted: ${result.activationId} · rollback ${result.rollbackTarget}`;
    if (HARNESS_PROMOTION_LIVE_GUI_SCRIPT && typeof window !== "undefined") {
      const activationAudit =
        result.workflow.metadata.harness?.activationAudit ?? [];
      const workerBindingRegistryRecord =
        result.workflow.metadata.harness?.activationRecord
          ?.workerBindingRegistryRecord ??
        result.workflow.metadata.harness?.workerBindingRegistryRecord ??
        null;
      const latestAuditEvent =
        activationAudit.length > 0
          ? activationAudit[activationAudit.length - 1]
          : null;
      (window as any).__AUTOPILOT_HARNESS_ACTIVATION_MINT_CLICK_RESULT = {
        applied: true,
        activationId: result.activationId ?? null,
        blockers: result.blockers,
        workflowActivationId:
          result.workflow.metadata.harness?.activationId ?? null,
        workflowActivationState:
          result.workflow.metadata.harness?.activationState ?? null,
        workerBindingActivationId:
          result.workflow.metadata.workerHarnessBinding?.harnessActivationId ??
          null,
        activationRecordWorkerBindingActivationId:
          result.workflow.metadata.harness?.activationRecord?.workerBinding
            ?.harnessActivationId ?? null,
        rollbackTarget: result.rollbackTarget ?? null,
        revisionBindingActivationId:
          result.workflow.metadata.harness?.revisionBinding?.activationId ??
          null,
        activationRecordRevisionBindingHash:
          result.workflow.metadata.harness?.activationRecord?.revisionBinding
            ?.workflowContentHash ?? null,
        rollbackRevisionBindingHash:
          result.workflow.metadata.harness?.activationRecord
            ?.rollbackRevisionBinding?.workflowContentHash ?? null,
        activationAuditEventCount: activationAudit.length,
        latestAuditEventId: latestAuditEvent?.eventId ?? null,
        latestAuditEventType: latestAuditEvent?.eventType ?? null,
        latestAuditStatus: latestAuditEvent?.status ?? null,
        receiptRefs: latestAuditEvent?.receiptRefs ?? [],
        evidenceRefs: latestAuditEvent?.evidenceRefs ?? [],
        workerHandoffReceiptIds:
          result.workflow.metadata.harness?.activationRecord?.workerHandoffReceipts?.map(
            (receipt) => receipt.receiptId,
          ) ?? [],
        workerHandoffNodeAttemptIds:
          result.workflow.metadata.harness?.activationRecord
            ?.workerHandoffNodeAttemptIds ?? [],
        workerHandoffReplayFixtureRefs:
          result.workflow.metadata.harness?.activationRecord
            ?.workerHandoffReplayFixtureRefs ?? [],
        reviewedPackageSnapshotHash:
          workerBindingRegistryRecord?.reviewedPackageSnapshotHash ??
          reviewedPackageSource?.reviewedPackageSnapshotHash ??
          null,
        reviewedWorkflowContentHash:
          workerBindingRegistryRecord?.reviewedWorkflowContentHash ??
          reviewedPackageSource?.workflowContentHash ??
          null,
        reviewedActivationId:
          workerBindingRegistryRecord?.reviewedActivationId ??
          reviewedPackageSource?.activationId ??
          null,
        reviewedHarnessWorkflowId:
          workerBindingRegistryRecord?.reviewedHarnessWorkflowId ??
          reviewedPackageSource?.harnessWorkflowId ??
          null,
        reviewedWorkerBindingActivationId:
          workerBindingRegistryRecord?.reviewedWorkerBindingActivationId ??
          reviewedPackageSource?.workerBindingActivationId ??
          null,
        reviewedRollbackTarget:
          workerBindingRegistryRecord?.reviewedRollbackTarget ??
          reviewedPackageSource?.rollbackTarget ??
          null,
        reviewedReplayFixtureRefs:
          workerBindingRegistryRecord?.reviewedReplayFixtureRefs ??
          reviewedPackageSource?.replayFixtureRefs ??
          [],
        reviewedWorkerHandoffNodeAttemptIds:
          workerBindingRegistryRecord?.reviewedWorkerHandoffNodeAttemptIds ??
          reviewedPackageSource?.workerHandoffNodeAttemptIds ??
          [],
	        reviewedWorkerHandoffReceiptIds:
	          workerBindingRegistryRecord?.reviewedWorkerHandoffReceiptIds ??
	          reviewedPackageSource?.workerHandoffReceiptIds ??
	          [],
        reviewedForkMutationCanaryId:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryId ??
          reviewedPackageSource?.forkMutationCanaryId ??
          null,
        reviewedForkMutationCanaryStatus:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryStatus ??
          reviewedPackageSource?.forkMutationCanaryStatus ??
          null,
        reviewedForkMutationCanaryDiffHash:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryDiffHash ??
          reviewedPackageSource?.forkMutationCanaryDiffHash ??
          null,
        reviewedForkMutationCanaryReceiptRefs:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryReceiptRefs ??
          reviewedPackageSource?.forkMutationCanaryReceiptRefs ??
          [],
        reviewedForkMutationCanaryReplayFixtureRefs:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryReplayFixtureRefs ??
          reviewedPackageSource?.forkMutationCanaryReplayFixtureRefs ??
          [],
        reviewedForkMutationCanaryNodeAttemptIds:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryNodeAttemptIds ??
          reviewedPackageSource?.forkMutationCanaryNodeAttemptIds ??
          [],
        reviewedForkMutationCanaryRollbackTarget:
          workerBindingRegistryRecord?.reviewedForkMutationCanaryRollbackTarget ??
          reviewedPackageSource?.forkMutationCanaryRollbackTarget ??
          null,
	        reviewedPolicyPosture:
	          workerBindingRegistryRecord?.reviewedPolicyPosture ??
          reviewedPackageSource?.policyPosture ??
          null,
        statusMessage: mintedStatusMessage,
      } satisfies HarnessActivationMintClickResult;
    }
    setStatusMessage(mintedStatusMessage);
  }, [
    currentProjectFile,
    harnessActivationCandidate,
    nodeFixturesById,
    packageImportReview,
    proposals,
    selectedHarnessRollbackTarget,
    tests,
  ]);

  const handleRunHarnessRollbackDrill = useCallback(async () => {
    const result = executeWorkflowHarnessRollbackDrill(currentProjectFile, {
      rollbackTarget: selectedHarnessRollbackTarget,
    });
    setWorkflow(result.workflow);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("settings");
    setBottomPanel("selection");
    setStatusMessage(
      result.executed
        ? `Rollback drill passed: ${result.rollbackTarget}`
        : `Rollback drill blocked by ${result.blockers.length} blocker${
            result.blockers.length === 1 ? "" : "s"
          }`,
    );
  }, [
    currentProjectFile,
    nodeFixturesById,
    proposals,
    selectedHarnessRollbackTarget,
    tests,
  ]);

  const handleRunActiveRuntimeRollbackDryRun = useCallback(() => {
    const result = executeWorkflowHarnessActiveRuntimeRollbackDryRun(
      currentProjectFile,
    );
    setWorkflow(result.workflow);
    loadWorkflowProject(result.workflow);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("settings");
    setBottomPanel("selection");
    const statusMessage = result.passed
      ? `Active runtime rollback dry run passed: ${result.proof.rollbackTarget}`
      : `Active runtime rollback dry run blocked by ${result.blockers.length} blocker${
          result.blockers.length === 1 ? "" : "s"
        }`;
    if (typeof window !== "undefined") {
      (window as any)
        .__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_DRY_RUN_RESULT = {
        passed: result.passed,
        blockers: result.blockers,
        rollbackTarget: result.proof.rollbackTarget,
        readinessProofId: result.proof.readinessProofId,
        liveShadowComparisonGateId: result.proof.liveShadowComparisonGateId,
        activationId: result.proof.activationId,
        harnessHash: result.proof.harnessHash,
        dryRunStatus: result.proof.dryRun.canaryStatus,
        canaryResultId: result.proof.dryRun.canaryResultId ?? null,
        canaryStatus: result.proof.dryRun.canaryStatus,
        canaryHashVerified: result.proof.dryRun.canaryHashVerified,
        applyReadiness: result.proof.apply.readiness,
        applyDisabled: result.proof.apply.disabled,
        statusMessage,
      } satisfies HarnessActiveRuntimeRollbackDryRunClickResult;
    }
    setStatusMessage(statusMessage);
  }, [currentProjectFile, loadWorkflowProject, nodeFixturesById, proposals, tests]);

  const handleApplyActiveRuntimeRollback = useCallback(() => {
    const result = executeWorkflowHarnessActiveRuntimeRollbackApply(
      currentProjectFile,
    );
    setWorkflow(result.workflow);
    loadWorkflowProject(result.workflow);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("settings");
    setBottomPanel("selection");
    const statusMessage = result.applied
      ? `Active runtime rollback applied: ${result.proof.rollbackTarget}`
      : `Active runtime rollback apply blocked by ${result.blockers.length} blocker${
          result.blockers.length === 1 ? "" : "s"
        }`;
    if (typeof window !== "undefined") {
      (window as any).__AUTOPILOT_HARNESS_ACTIVE_RUNTIME_ROLLBACK_APPLY_RESULT =
        {
          passed: result.proof.passed,
          applied: result.applied,
          blockers: result.blockers,
          rollbackTarget: result.proof.rollbackTarget,
          readinessProofId: result.proof.readinessProofId,
          liveShadowComparisonGateId: result.proof.liveShadowComparisonGateId,
          activationId: result.proof.activationId,
          harnessHash: result.proof.harnessHash,
          executionId: result.proof.executionId,
          rollbackReceiptId: result.proof.rollbackReceiptId,
          auditEventId: result.proof.auditEventId,
          applyStatus: result.proof.applyStatus,
          rollbackTargetVerified: result.proof.rollbackTargetVerified,
          hashVerified: result.proof.hashVerified,
          policyDecision: result.proof.policyDecision,
          receiptRefs: result.proof.receiptRefs,
          replayFixtureRefs: result.proof.replayFixtureRefs,
          statusMessage,
        } satisfies HarnessActiveRuntimeRollbackApplyClickResult;
    }
    setStatusMessage(statusMessage);
  }, [
    currentProjectFile,
    loadWorkflowProject,
    nodeFixturesById,
    proposals,
    tests,
  ]);

  const handleExecuteHarnessRollback = useCallback(async () => {
    const rollbackRevisionBinding =
      currentProjectFile.metadata.harness?.activationRecord
        ?.rollbackRevisionBinding ??
      currentProjectFile.metadata.harness?.activationRollbackProof
        ?.restoredRevisionBinding ??
      null;
    let restoredWorkflow: WorkflowProject | null = null;
    let restoreResult: WorkflowRevisionRestoreResult | null = null;
    let restoreBlockers: string[] = [];
    if (rollbackRevisionBinding?.revisionSource === "git") {
      if (!runtime.restoreWorkflowRevision) {
        restoreBlockers = ["restore_api_unavailable"];
      } else {
        try {
          restoreResult = await runtime.restoreWorkflowRevision({
            workflowPath,
            revisionBinding: rollbackRevisionBinding,
            expectedWorkflowContentHash:
              rollbackRevisionBinding.workflowContentHash,
          });
        } catch (error) {
          restoreBlockers = ["restore_command_failed", errorMessage(error)];
        }
      }
      if (restoreResult?.restored && restoreResult.bundle?.workflow) {
        restoredWorkflow = restoreResult.bundle.workflow;
      } else if (restoreResult?.restored) {
        restoreBlockers = ["restore_workflow_bundle_missing"];
      } else if (restoreResult) {
        restoreBlockers = restoreResult.blockers;
      }
    }
    const result = executeWorkflowHarnessRevisionRollback(currentProjectFile, {
      rollbackTarget: selectedHarnessRollbackTarget,
      restoredWorkflow,
      restoreResult,
      restoreBlockers,
    });
    setWorkflow(result.workflow);
    const validation = validateWorkflowProject(result.workflow, tests);
    const readiness = evaluateWorkflowActivationReadiness(
      result.workflow,
      tests,
      validation,
      proposals,
      Object.values(nodeFixturesById).flat(),
    );
    setValidationResult(validation);
    setReadinessResult(readiness);
    setRightPanel("settings");
    setBottomPanel("selection");
    if (!result.executed) {
      setStatusMessage(
        `Rollback execution blocked by ${result.blockers.length} blocker${
          result.blockers.length === 1 ? "" : "s"
        }`,
      );
      return;
    }
    try {
      if (runtime.saveWorkflowProject) {
        await runtime.saveWorkflowProject(workflowPath, result.workflow);
        await loadRuntimeSidecars(workflowPath);
      }
      setStatusMessage(`Rollback executed: ${result.rollbackTarget}`);
    } catch (error) {
      setStatusMessage(
        `Rollback executed but save failed: ${errorMessage(error)}`,
      );
    }
  }, [
    currentProjectFile,
    loadRuntimeSidecars,
    nodeFixturesById,
    proposals,
    runtime,
    selectedHarnessRollbackTarget,
    tests,
    workflowPath,
  ]);

  const handleOpenDeploy = async () => {
    await handleCheckReadiness();
    setDeployOpen(true);
  };

  const handleExportPortablePackage = async () => {
    await handleSave();
    const readiness = await handleCheckReadiness();
    if (!runtime.exportWorkflowPackage) {
      setStatusMessage("Package export unavailable");
      return;
    }
    const exported = await runtime.exportWorkflowPackage(workflowPath);
    setPortablePackage(exported);
    setRightPanel("readiness");
    setStatusMessage(
      exported.manifest.portable
        ? "Portable package exported"
        : `Package exported with ${readiness.status} blockers`,
    );
    await loadRuntimeSidecars(workflowPath);
  };

  const handleImportPortablePackage = async () => {
    const packagePath = importPackagePath.trim();
    if (!packagePath) {
      setStatusMessage("Choose a package directory to import");
      return;
    }
    if (!runtime.importWorkflowPackage) {
      setStatusMessage("Package import unavailable");
      return;
    }
    const request: ImportWorkflowPackageRequest = {
      packagePath,
      projectRoot: currentProject?.rootPath || ".",
      name: importPackageName.trim() || undefined,
    };
    try {
      const bundle = await runtime.importWorkflowPackage(request);
      const importedFixtures = runtime.listWorkflowNodeFixtures
        ? await runtime.listWorkflowNodeFixtures(bundle.workflowPath)
        : [];
      const validation = validateWorkflowProject(bundle.workflow, bundle.tests);
      const readiness = evaluateWorkflowActivationReadiness(
        bundle.workflow,
        bundle.tests,
        validation,
        bundle.proposals,
        importedFixtures,
      );
      const rollbackRevisionBinding =
        bundle.workflow.metadata.harness?.activationRecord
          ?.rollbackRevisionBinding ??
        bundle.workflow.metadata.harness?.activationRollbackProof
          ?.restoredRevisionBinding ??
        null;
      const { rollbackRestoreResult, rollbackRestoreBlockers } =
        await runWorkflowHarnessRollbackRestoreCanaryProbe({
          runtime,
          workflowPath: bundle.workflowPath,
          rollbackRevisionBinding,
        });
      const importedAtMs = Date.now();
      const preflightReview = createWorkflowPackageImportReview({
        bundle,
        packagePath,
        projectRoot: request.projectRoot,
        readinessStatus: readiness.status,
        importedAtMs,
      });
      const activationCandidate = createWorkflowPackageImportActivationCandidate(
        {
          workflow: bundle.workflow,
          tests: bundle.tests,
          readiness,
          proposals: bundle.proposals,
          createdAtMs: importedAtMs,
          rollbackRestoreResult,
          rollbackRestoreBlockers,
          packageEvidenceReady: preflightReview.evidence.packageEvidenceReady,
        },
      );
      const review = createWorkflowPackageImportReview({
        bundle,
        packagePath,
        projectRoot: request.projectRoot,
        readinessStatus: readiness.status,
        importedAtMs,
        activationCandidate,
      });
      setWorkflowPath(bundle.workflowPath);
      setTestsPath(bundle.testsPath);
      setTests(bundle.tests);
      setProposals(bundle.proposals);
      setRuns(bundle.runs);
      clearRunState();
      loadWorkflowProject(bundle.workflow);
      setValidationResult(validation);
      setReadinessResult(readiness);
      setNodeFixturesById(groupFixturesByNodeId(importedFixtures));
      setPortablePackage(bundle.importedPackage ?? null);
      setPackageImportReview(review);
      setHarnessActivationCandidate(activationCandidate);
      await loadRuntimeSidecars(bundle.workflowPath);
      setSelectedHarnessActivationGateId("package-evidence");
      setSelectedHarnessActivationGateEvidenceRef(null);
      setSelectedHarnessActivationGateNodeAttemptId(null);
      setSelectedHarnessActivationGateReceiptRef(null);
      setSelectedHarnessActivationGateReplayFixtureRef(null);
      setRightPanel("settings");
      setBottomPanel("selection");
      setImportPackageOpen(false);
      setStatusMessage(
        review.evidence.packageEvidenceReady
          ? "Package imported for activation review"
          : `Package imported with ${review.evidence.blockerCount} package evidence blocker${
              review.evidence.blockerCount === 1 ? "" : "s"
            }`,
      );
    } catch (error) {
      setStatusMessage(`Package import failed: ${errorMessage(error)}`);
    }
  };

  const handleRunTests = async () => {
    let result: WorkflowTestRunResult;
    try {
      result = runtime.runWorkflowTests
        ? await runtime.runWorkflowTests(workflowPath)
        : createSubstrateProjectionTestResult(tests, nodes);
    } catch (error) {
      result = createBlockedTestResult(
        tests,
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setTestResult(result);
    setTests((current) =>
      current.map((test) => {
        const run = result.results.find((item) => item.testId === test.id);
        return run
          ? { ...test, status: run.status, lastMessage: run.message }
          : test;
      }),
    );
    setRightPanel(
      result.failed > 0 || result.blocked > 0 ? "unit_tests" : rightPanel,
    );
    setBottomPanel("test_output");
    setStatusMessage(
      `Tests: ${result.passed} passed, ${result.failed} failed, ${result.blocked} blocked`,
    );
  };

  const handleRun = async () => {
    let validation: WorkflowValidationResult;
    try {
      validation = runtime.validateWorkflowBundle
        ? await runtime.validateWorkflowBundle(workflowPath)
        : validateWorkflowProject(currentProjectFile, tests);
    } catch (error) {
      validation = createWorkflowActionFailure(
        "workflow_bundle_unavailable",
        `Saved workflow bundle is unavailable. ${errorMessage(error)}`,
      );
    }
    setValidationResult(validation);
    setRightPanel("runs");
    setBottomPanel("run_output");
    if (runtime.runWorkflowProject) {
      let liveTelemetryHydration:
        | { threadId: string; stop: () => void }
        | null = null;
      try {
        try {
          liveTelemetryHydration = await prepareLiveRuntimeTelemetryHydration();
        } catch (error) {
          setStatusMessage(
            `Run starting without live telemetry hydration: ${errorMessage(error)}`,
          );
        }
        const result = await runtime.runWorkflowProject(
          workflowPath,
          liveTelemetryHydration
            ? {
                threadId: liveTelemetryHydration.threadId,
                liveTelemetryHydration: true,
              }
            : undefined,
        );
        liveTelemetryHydration?.stop();
        await applyRunResult(result);
        setRightPanel("runs");
      } catch (error) {
        liveTelemetryHydration?.stop();
        const liveTelemetryRunId = liveTelemetryRunIdRef.current;
        liveTelemetryRunIdRef.current = null;
        if (liveTelemetryRunId) {
          setLastRunResult((current) =>
            current?.summary.id === liveTelemetryRunId ? null : current,
          );
          setSelectedRunId((current) =>
            current === liveTelemetryRunId ? null : current,
          );
          setRuns((current) =>
            current.filter((run) => run.id !== liveTelemetryRunId),
          );
        }
        setRightPanel("runs");
        setStatusMessage(
          `Run blocked by runtime substrate: ${errorMessage(error)}`,
        );
      }
    } else if (validation.status === "passed") {
      await execution.runGraph(globalConfig);
      setRuns((current) => [
        createSubstrateProjectionRunSummary(currentProjectFile, validation),
        ...current,
      ]);
      setStatusMessage("Run completed");
    } else {
      setRuns((current) => [
        createSubstrateProjectionRunSummary(currentProjectFile, validation),
        ...current,
      ]);
      setRightPanel("runs");
      setStatusMessage(`Run ${validation.status}`);
    }
    setBottomPanel("run_output");
  };

  const handleResumeRun = async (outcome: WorkflowResumeRequest["outcome"]) => {
    if (!lastRunResult?.interrupt || !runtime.resumeWorkflowRun) return;
    const result = await runtime.resumeWorkflowRun(workflowPath, {
      runId: lastRunResult.summary.id,
      threadId: lastRunResult.thread.id,
      interruptId: lastRunResult.interrupt.id,
      checkpointId: lastRunResult.thread.latestCheckpointId,
      outcome,
    });
    await applyRunResult(result);
    setRightPanel("runs");
    setBottomPanel("run_output");
  };

  const handleDryRunFunction = async (node: Node) => {
    if (node.type !== "function" || !runtime.dryRunWorkflowFunction) return;
    const result = await runtime.dryRunWorkflowFunction(
      workflowPath,
      node.id,
      node.config?.logic.functionBinding?.testInput ??
        node.config?.logic.testInput ?? { payload: "sample" },
    );
    setFunctionDryRunResult(result);
    setBottomPanel("run_output");
    setStatusMessage(`Function dry run ${result.summary.status}`);
  };

  const handleCaptureNodeFixture = useCallback(
    async (node: Node) => {
      const run = nodeRunStatusById[node.id];
      const logic = node.config?.logic ?? {};
      const input =
        run?.input ??
        logic.functionBinding?.testInput ??
        logic.testInput ??
        logic.payload ??
        null;
      const hashes = workflowFixtureHashesForNode(node);
      const fixture: WorkflowNodeFixture = {
        id: `fixture-${node.id}-${Date.now()}`,
        nodeId: node.id,
        name: `${node.name} fixture`,
        input,
        output: run?.output ?? null,
        schemaHash: hashes.schemaHash,
        nodeConfigHash: hashes.nodeConfigHash,
        ...workflowFixtureValidationForNode(node, run?.output ?? null),
        sourceRunId: lastRunResult?.summary.id,
        pinned: true,
        stale: false,
        createdAtMs: Date.now(),
      };
      if (runtime.saveWorkflowNodeFixture) {
        const savedFixtures = await runtime.saveWorkflowNodeFixture(
          workflowPath,
          fixture,
        );
        setNodeFixturesById(groupFixturesByNodeId(savedFixtures));
      } else {
        setNodeFixturesById((current) => ({
          ...current,
          [node.id]: [fixture, ...(current[node.id] ?? [])].slice(0, 8),
        }));
      }
      setBottomPanel("fixtures");
      setStatusMessage(`Fixture captured for ${node.name}`);
    },
    [lastRunResult?.summary.id, nodeRunStatusById, runtime, workflowPath],
  );

  const handleImportNodeFixture = useCallback(
    async (node: Node, rawText: string) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawText);
      } catch (error) {
        setStatusMessage(`Fixture import blocked: ${errorMessage(error)}`);
        return;
      }
      const record =
        parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : null;
      const logic = node.config?.logic ?? {};
      const hashes = workflowFixtureHashesForNode(node);
      const fixture: WorkflowNodeFixture = {
        id: `fixture-${node.id}-import-${Date.now()}`,
        nodeId: node.id,
        name: String(record?.name ?? `${node.name} imported sample`),
        input:
          record && "input" in record
            ? record.input
            : (logic.functionBinding?.testInput ??
              logic.testInput ??
              logic.payload ??
              null),
        output: record && "output" in record ? record.output : parsed,
        schemaHash: hashes.schemaHash,
        nodeConfigHash: hashes.nodeConfigHash,
        ...workflowFixtureValidationForNode(
          node,
          record && "output" in record ? record.output : parsed,
        ),
        pinned: true,
        stale: false,
        createdAtMs: Date.now(),
      };
      if (runtime.saveWorkflowNodeFixture) {
        const savedFixtures = await runtime.saveWorkflowNodeFixture(
          workflowPath,
          fixture,
        );
        setNodeFixturesById(groupFixturesByNodeId(savedFixtures));
      } else {
        setNodeFixturesById((current) => ({
          ...current,
          [node.id]: [fixture, ...(current[node.id] ?? [])].slice(0, 8),
        }));
      }
      setBottomPanel("fixtures");
      setStatusMessage(`Fixture imported for ${node.name}`);
    },
    [runtime, workflowPath],
  );

  const handlePinNodeFixture = useCallback(
    async (node: Node, fixture: WorkflowNodeFixture) => {
      const pinnedFixture: WorkflowNodeFixture = {
        ...fixture,
        pinned: true,
        stale: fixture.stale ?? false,
      };
      if (runtime.saveWorkflowNodeFixture) {
        const savedFixtures = await runtime.saveWorkflowNodeFixture(
          workflowPath,
          pinnedFixture,
        );
        setNodeFixturesById(groupFixturesByNodeId(savedFixtures));
      } else {
        setNodeFixturesById((current) => ({
          ...current,
          [node.id]: (current[node.id] ?? []).map((item) => ({
            ...item,
            pinned: item.id === fixture.id,
          })),
        }));
      }
      setBottomPanel("fixtures");
      setStatusMessage(`Fixture pinned for ${node.name}`);
    },
    [runtime, workflowPath],
  );

  const handleDryRunNodeFromFixture = useCallback(
    async (node: Node, fixture?: WorkflowNodeFixture) => {
      const input = fixture?.input ??
        node.config?.logic?.functionBinding?.testInput ??
        node.config?.logic?.testInput ??
        node.config?.logic?.payload ?? { payload: "sample" };
      if (runtime.dryRunWorkflowNode) {
        const result = await runtime.dryRunWorkflowNode(
          workflowPath,
          node.id,
          input,
        );
        if (node.type === "function") {
          setFunctionDryRunResult(result);
        }
        await applyRunResult(result);
        setBottomPanel("run_output");
        setStatusMessage(`Dry run ${result.summary.status}`);
        return;
      }
      if (node.type === "function" && runtime.dryRunWorkflowFunction) {
        const result = await runtime.dryRunWorkflowFunction(
          workflowPath,
          node.id,
          input,
        );
        setFunctionDryRunResult(result);
        setBottomPanel("run_output");
        setStatusMessage(`Function dry run ${result.summary.status}`);
        return;
      }
      setStatusMessage(
        "Dry run is unavailable for this node until the runtime binding is saved.",
      );
    },
    [applyRunResult, runtime, workflowPath],
  );

  const handleRunWorkflowNode = useCallback(
    async (node: Node, fixture?: WorkflowNodeFixture) => {
      const run = nodeRunStatusById[node.id];
      const logic = node.config?.logic ?? {};
      const input = fixture?.input ??
        run?.input ??
        logic.functionBinding?.testInput ??
        logic.testInput ??
        logic.payload ?? { payload: "sample" };
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (runtime.runWorkflowNode) {
        try {
          const result = await runtime.runWorkflowNode(
            workflowPath,
            node.id,
            input,
            { source: "inspector" },
          );
          await applyRunResult(result);
          setStatusMessage(`Node run ${result.summary.status}`);
        } catch (error) {
          const blocked = createSubstrateProjectionRunSummary(
            currentProjectFile,
            createWorkflowActionFailure(
              "workflow_node_run_unavailable",
              `Node run is unavailable. ${errorMessage(error)}`,
            ),
          );
          setRuns((current) => [blocked, ...current]);
          setStatusMessage("Node run blocked");
        }
        return;
      }
      await handleDryRunNodeFromFixture(node, fixture);
    },
    [
      applyRunResult,
      currentProjectFile,
      handleDryRunNodeFromFixture,
      nodeRunStatusById,
      runtime,
      workflowPath,
    ],
  );

  const handleRunWorkflowUpstream = useCallback(
    async (node: Node) => {
      setRightPanel("runs");
      setBottomPanel("run_output");
      if (runtime.runWorkflowProject) {
        try {
          const result = await runtime.runWorkflowProject(workflowPath, {
            stopAtNodeId: node.id,
            source: "inspector-upstream",
          });
          await applyRunResult(result);
          setStatusMessage(`Upstream run ${result.summary.status}`);
        } catch (error) {
          const blocked = createSubstrateProjectionRunSummary(
            currentProjectFile,
            createWorkflowActionFailure(
              "workflow_upstream_run_unavailable",
              `Upstream run is unavailable. ${errorMessage(error)}`,
            ),
          );
          setRuns((current) => [blocked, ...current]);
          setStatusMessage("Upstream run blocked");
        }
        return;
      }
      await handleRunWorkflowNode(node);
    },
    [
      applyRunResult,
      currentProjectFile,
      handleRunWorkflowNode,
      runtime,
      workflowPath,
    ],
  );

  const handleAddTestFromOutput = useCallback(
    (node: Node) => {
      const output = nodeRunStatusById[node.id]?.output;
      setNewTestName(`${node.name} output is valid`);
      setNewTestTargets(node.id);
      setNewTestKind("schema_matches");
      setNewTestExpression(`nodes.${node.id}.output`);
      setNewTestExpected(
        output === undefined ? "" : JSON.stringify(output, null, 2),
      );
      setTestEditorOpen(true);
      setRightPanel("unit_tests");
      setBottomPanel("test_output");
      setStatusMessage(`Adding test from ${node.name} output`);
    },
    [nodeRunStatusById],
  );

  const handleBuildScratchBlueprint = useCallback(
    async (blueprintId: ScratchWorkflowBlueprintId) => {
      setActiveTab("graph");
      setRightPanel("runs");
      setBottomPanel("run_output");
      setStatusMessage(`Building ${blueprintId}`);
      const projectRoot = currentProject?.rootPath || ".";
      const requestedName =
        blueprintId === "repo-test-engineer"
          ? SCRATCH_DOGFOOD_WORKFLOW_NAME
          : `Scratch ${blueprintId.replace(/-/g, " ")}`;
      const bundle = runtime.createWorkflowProject
        ? await runtime.createWorkflowProject({
            projectRoot,
            name: requestedName,
            workflowKind: "agent_workflow",
            executionMode: "local",
          })
        : {
            workflowPath: `${projectRoot}/.agents/workflows/${slugify(requestedName)}.workflow.json`,
            testsPath: `${projectRoot}/.agents/workflows/${slugify(requestedName)}.tests.json`,
            proposalsDir: `${projectRoot}/.agents/workflows/${slugify(requestedName)}.proposals`,
            workflow: makeDefaultWorkflow(requestedName),
            tests: [],
            proposals: [],
            runs: [],
          };
      const scratch = buildScratchWorkflow(bundle.workflow, blueprintId);

      const blankWorkflow = {
        ...bundle.workflow,
        metadata: {
          ...bundle.workflow.metadata,
          name: scratch.workflow.metadata.name,
          slug: scratch.workflow.metadata.slug,
          dirty: true,
          updatedAtMs: Date.now(),
        },
        global_config: scratch.workflow.global_config,
        nodes: [],
        edges: [],
      };
      setWorkflowPath(bundle.workflowPath);
      setTestsPath(bundle.testsPath);
      setTests([]);
      setProposals(bundle.proposals);
      setRuns(bundle.runs);
      clearRunState();
      loadWorkflowProject(blankWorkflow);
      setStatusMessage(
        `Composing ${scratch.workflow.metadata.name} from blank canvas`,
      );

      scratch.workflow.nodes.forEach((nodeItem) => {
        handleAddNodeFromLibrary(nodeItem.type, nodeItem.name, nodeItem.id);
        setNodes((currentNodes) =>
          currentNodes.map((flowNode) =>
            flowNode.id === nodeItem.id
              ? {
                  ...flowNode,
                  type: nodeItem.type,
                  position: { x: nodeItem.x, y: nodeItem.y },
                  data: { ...nodeItem },
                }
              : flowNode,
          ),
        );
      });
      const scratchNodeById = new Map(
        scratch.workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]),
      );
      setEdges(() =>
        scratch.workflow.edges.flatMap((edge) => {
          const sourceNode = scratchNodeById.get(edge.from);
          const targetNode = scratchNodeById.get(edge.to);
          const edgeIssue = validateActionEdge(
            edge.from,
            actionKindForWorkflowNodeType(sourceNode?.type ?? ""),
            edge.to,
            actionKindForWorkflowNodeType(targetNode?.type ?? ""),
          );
          if (edgeIssue) return [];
          return [
            {
              id: edge.id,
              source: edge.from,
              target: edge.to,
              sourceHandle: edge.fromPort || "output",
              targetHandle: edge.toPort || "input",
              type: "semantic",
              animated: false,
              data: {
                status: "idle",
                active: false,
                compositionMode: "manual_canvas_primitives",
              },
            },
          ];
        }),
      );
      setWorkflow(scratch.workflow);
      setGlobalConfig(normalizeGlobalConfig(scratch.workflow.global_config));
      handleNodeSelect(scratch.workflow.nodes[0]?.id ?? null);
      await new Promise<void>((resolve) =>
        requestAnimationFrame(() => resolve()),
      );

      if (runtime.saveWorkflowProject) {
        await runtime.saveWorkflowProject(
          bundle.workflowPath,
          scratch.workflow,
        );
      }
      if (runtime.saveWorkflowTests) {
        await runtime.saveWorkflowTests(bundle.workflowPath, scratch.tests);
      }
      setTests(scratch.tests);
      await loadRuntimeSidecars(bundle.workflowPath);

      let bindingCheckCount = 0;
      if (runtime.checkWorkflowBinding) {
        const bindingNodeIds = scratch.workflow.nodes
          .filter((nodeItem) =>
            [
              "model_call",
              "model_binding",
              "adapter",
              "plugin_tool",
              "parser",
            ].includes(nodeItem.type),
          )
          .map((nodeItem) => nodeItem.id);
        for (const nodeId of bindingNodeIds) {
          try {
            await runtime.checkWorkflowBinding(bundle.workflowPath, nodeId);
            bindingCheckCount += 1;
          } catch {
            // The visible dogfood result is driven by validation/run status;
            // binding-check failures are still captured through readiness.
          }
        }
        await loadRuntimeSidecars(bundle.workflowPath);
      }
      if (runtime.generateWorkflowBindingManifest) {
        try {
          setBindingManifest(
            await runtime.generateWorkflowBindingManifest(bundle.workflowPath),
          );
          await loadRuntimeSidecars(bundle.workflowPath);
        } catch {
          // Validation/readiness will expose binding blockers; manifest refresh
          // stays a sidecar concern for dogfood evidence.
        }
      }

      const validation = runtime.validateWorkflowBundle
        ? await runtime.validateWorkflowBundle(bundle.workflowPath)
        : validateWorkflowProject(scratch.workflow, scratch.tests);
      setValidationResult(validation);
      const activationReadiness = runtime.validateWorkflowExecutionReadiness
        ? await runtime.validateWorkflowExecutionReadiness(bundle.workflowPath)
        : evaluateWorkflowActivationReadiness(
            scratch.workflow,
            scratch.tests,
            validation,
            [],
            Object.values(nodeFixturesById).flat(),
          );
      setReadinessResult(activationReadiness);

      const testsResult = runtime.runWorkflowTests
        ? await runtime.runWorkflowTests(bundle.workflowPath)
        : createSubstrateProjectionTestResult(
            scratch.tests,
            scratch.workflow.nodes.map((node) => ({
              id: node.id,
              type: node.type,
              data: node,
            })),
          );
      setTestResult(testsResult);
      setTests((current) =>
        current.map((test) => {
          const run = testsResult.results.find(
            (item) => item.testId === test.id,
          );
          return run
            ? { ...test, status: run.status, lastMessage: run.message }
            : test;
        }),
      );

      let finalRun: WorkflowRunResult | null = null;
      let checkpointResumePassed = false;
      if (runtime.runWorkflowProject) {
        finalRun = await runtime.runWorkflowProject(bundle.workflowPath);
        if (
          blueprintId === "failed-function-resume" &&
          finalRun.summary.status === "failed" &&
          runtime.saveWorkflowProject &&
          runtime.resumeWorkflowRun
        ) {
          const repairedWorkflow: WorkflowProject = {
            ...scratch.workflow,
            nodes: scratch.workflow.nodes.map((nodeItem) => {
              if (nodeItem.id !== "resume-function") return nodeItem;
              const logic = {
                ...(nodeItem.config?.logic ?? {}),
              } as Record<string, unknown>;
              const functionBinding = {
                ...((logic.functionBinding as Record<string, unknown>) ?? {}),
                code: "return { repaired: true, result: input };",
              };
              return {
                ...nodeItem,
                config: {
                  ...nodeItem.config,
                  logic: {
                    ...logic,
                    code: "return { repaired: true, result: input };",
                    functionBinding,
                  },
                },
              };
            }) as WorkflowProject["nodes"],
          };
          await runtime.saveWorkflowProject(
            bundle.workflowPath,
            repairedWorkflow,
          );
          setWorkflow(repairedWorkflow);
          loadWorkflowProject(repairedWorkflow);
          finalRun = await runtime.resumeWorkflowRun(bundle.workflowPath, {
            runId: finalRun.summary.id,
            threadId: finalRun.thread.id,
            nodeId: "resume-function",
            checkpointId: finalRun.thread.latestCheckpointId,
            outcome: "repair",
          });
          checkpointResumePassed = finalRun.summary.status === "passed";
        }
        for (let approvals = 0; approvals < 8; approvals += 1) {
          if (
            finalRun.summary.status !== "interrupted" ||
            !finalRun.interrupt ||
            !runtime.resumeWorkflowRun
          ) {
            break;
          }
          finalRun = await runtime.resumeWorkflowRun(bundle.workflowPath, {
            runId: finalRun.summary.id,
            threadId: finalRun.thread.id,
            interruptId: finalRun.interrupt.id,
            checkpointId: finalRun.thread.latestCheckpointId,
            outcome: "approve",
          });
        }
      }

      if (finalRun) {
        setLastRunResult(finalRun);
        setSelectedRunId(finalRun.summary.id);
        setRunEvents(finalRun.events);
        setRuns((current) => [
          finalRun.summary,
          ...current.filter((run) => run.id !== finalRun?.summary.id),
        ]);
        setCheckpoints(finalRun.checkpoints);
        setNodeRunStatusById(
          Object.fromEntries(finalRun.nodeRuns.map((run) => [run.nodeId, run])),
        );
        if (runtime.saveWorkflowNodeFixture) {
          const nodeById = new Map(
            scratch.workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]),
          );
          const fixtureNodeRun =
            finalRun.nodeRuns.find(
              (run) =>
                nodeById.get(run.nodeId)?.type === "output" && run.output,
            ) ?? finalRun.nodeRuns.find((run) => run.output);
          const fixtureNode = fixtureNodeRun
            ? nodeById.get(fixtureNodeRun.nodeId)
            : null;
          if (fixtureNode && fixtureNodeRun) {
            const hashes = workflowFixtureHashesForNode(fixtureNode);
            const fixture: WorkflowNodeFixture = {
              id: `fixture-${fixtureNode.id}-${Date.now()}`,
              nodeId: fixtureNode.id,
              name: `${fixtureNode.name} fixture`,
              input:
                fixtureNodeRun.input ??
                fixtureNode.config?.logic.functionBinding?.testInput ??
                fixtureNode.config?.logic.testInput ??
                fixtureNode.config?.logic.payload ??
                null,
              output: fixtureNodeRun.output ?? null,
              schemaHash: hashes.schemaHash,
              nodeConfigHash: hashes.nodeConfigHash,
              ...workflowFixtureValidationForNode(
                fixtureNode,
                fixtureNodeRun.output ?? null,
              ),
              sourceRunId: finalRun.summary.id,
              pinned: true,
              stale: false,
              createdAtMs: Date.now(),
            };
            setNodeFixturesById(
              groupFixturesByNodeId(
                await runtime.saveWorkflowNodeFixture(
                  bundle.workflowPath,
                  fixture,
                ),
              ),
            );
          }
        }
      }

      const proposalRequest: CreateWorkflowProposalRequest = {
        title: `Bounded ${scratch.workflow.metadata.name} review`,
        summary:
          "Review the scratch-built workflow before applying any graph, code, or test mutations.",
        boundedTargets: workflowPatchBoundedTargets(scratch.workflow),
        workflowPatch: scratch.workflow,
        codeDiff:
          "No files are mutated by this workflow run. Future repair remains proposal-only.",
      };
      if (runtime.createWorkflowProposal) {
        try {
          const proposalBundle = await runtime.createWorkflowProposal(
            bundle.workflowPath,
            proposalRequest,
          );
          setProposals(proposalBundle.proposals);
          setProposalToReview(
            proposalBundle.proposals.find(
              (proposal) => proposal.status === "open",
            ) ?? null,
          );
        } catch (error) {
          setProposalToReview(null);
          setStatusMessage(
            `Proposal blocked by runtime substrate: ${errorMessage(error)}`,
          );
        }
      } else {
        const proposal = createSubstrateProjectionProposal(proposalRequest);
        setProposals((current) => [proposal, ...current]);
        setProposalToReview(proposal);
      }

      let packagePath: string | null = null;
      if (runtime.exportWorkflowPackage) {
        const exported = await runtime.exportWorkflowPackage(
          bundle.workflowPath,
        );
        setPortablePackage(exported);
        packagePath = exported.packagePath;
      }

      const status =
        validation.status === "passed" &&
        testsResult.status === "passed" &&
        (!finalRun || finalRun.summary.status === "passed")
          ? "passed"
          : "blocked";
      const validationWarningCount =
        validation.warnings.length + activationReadiness.warnings.length;
      const validationBlockingIssueCount =
        workflowValidationBlockingIssueCount(validation) +
        workflowValidationBlockingIssueCount(activationReadiness);
      setRightPanel(status === "passed" ? "runs" : "unit_tests");
      setBottomPanel(status === "passed" ? "run_output" : "warnings");
      setStatusMessage(
        status === "passed" && validationWarningCount > 0
          ? `${scratch.workflow.metadata.name} passed with ${workflowIssueCountLabel(
              validationWarningCount,
              "warning",
            )}`
          : `${scratch.workflow.metadata.name} ${status}`,
      );
      return {
        blueprintId,
        status,
        workflowPath: bundle.workflowPath,
        testsPath: bundle.testsPath,
        packagePath,
        bindingCheckCount,
        validationStatus: validation.status,
        readinessStatus: activationReadiness.status,
        readinessNeedsAttention:
          activationReadiness.status !== "passed" ||
          activationReadiness.warnings.length > 0,
        validationWarningCount,
        validationBlockingIssueCount,
        testStatus: testsResult.status,
        runStatus: finalRun?.summary.status ?? "not-run",
        checkpointResumePassed,
      };
    },
    [
      clearRunState,
      currentProject?.rootPath,
      handleAddNodeFromLibrary,
      handleNodeSelect,
      loadRuntimeSidecars,
      loadWorkflowProject,
      runtime,
      setEdges,
      setNodes,
    ],
  );

  const handleBuildRepoTestEngineerScratch = useCallback(
    () => handleBuildScratchBlueprint("repo-test-engineer"),
    [handleBuildScratchBlueprint],
  );

  const handleBuildScratchHeavySuite = useCallback(async () => {
    const results = [];
    for (const blueprintId of SCRATCH_HEAVY_BLUEPRINTS) {
      results.push(await handleBuildScratchBlueprint(blueprintId));
    }
    const status = results.every((result) => result.status === "passed")
      ? "passed"
      : "blocked";
    setStatusMessage(
      workflowChecksStatusMessage(status, {
        warningCount: results.reduce(
          (count, result) => count + result.validationWarningCount,
          0,
        ),
        blockedWorkflowCount: results.filter(
          (result) => result.status !== "passed",
        ).length,
        readinessAttentionWorkflowCount: results.filter(
          (result) => result.readinessNeedsAttention,
        ).length,
      }),
    );
    return { status, results };
  }, [handleBuildScratchBlueprint]);

  const handleDogfoodSuite = useCallback(async () => {
    if (!runtime.runWorkflowDogfoodSuite) return;
    const result = await runtime.runWorkflowDogfoodSuite(
      currentProject?.rootPath || ".",
      "heavy-agent-workflows",
    );
    setDogfoodRun(result);
    setRightPanel("runs");
    setBottomPanel("run_output");
    setStatusMessage(workflowChecksStatusMessage(result.status));
  }, [currentProject?.rootPath, runtime]);

  const handleCreateProposal = async () => {
    const targetIds = selectedNode
      ? workflowPatchBoundedTargets(currentProjectFile, {
          selectedNodeId: selectedNode.id,
        })
      : workflowPatchBoundedTargets(currentProjectFile);
    const request: CreateWorkflowProposalRequest = {
      title: selectedNode
        ? `Review ${selectedNode.name}`
        : "Review workflow improvement",
      summary:
        "Bounded workflow change staged for explicit review before apply.",
      boundedTargets: targetIds,
      workflowPatch: currentProjectFile,
      codeDiff: "Workflow graph metadata and node configuration only.",
    };
    if (runtime.createWorkflowProposal) {
      try {
        const bundle = await runtime.createWorkflowProposal(
          workflowPath,
          request,
        );
        setProposals(bundle.proposals);
        setRuns(bundle.runs);
        setTests(bundle.tests);
        setProposalToReview(
          bundle.proposals.find((proposal) => proposal.status === "open") ??
            null,
        );
      } catch (error) {
        setProposalToReview(null);
        setStatusMessage(
          `Proposal blocked by runtime substrate: ${errorMessage(error)}`,
        );
        return;
      }
    } else {
      const proposal = createSubstrateProjectionProposal(request);
      setProposals((current) => [proposal, ...current]);
      setProposalToReview(proposal);
    }
    setActiveTab("proposals");
    setRightPanel("changes");
    setStatusMessage("Proposal staged");
  };

  const handleApplyProposal = async (proposalId: string) => {
    if (!runtime.applyWorkflowProposal) return;
    const bundle = await runtime.applyWorkflowProposal(
      workflowPath,
      proposalId,
    );
    setProposals(bundle.proposals);
    setRuns(bundle.runs);
    setTests(bundle.tests);
    loadWorkflowProject(bundle.workflow);
    await loadRuntimeSidecars(workflowPath);
    setProposalToReview(null);
    setStatusMessage("Proposal applied");
  };

  const handleAddTest = () => {
    const targets = newTestTargets
      .split(",")
      .map((target) => target.trim())
      .filter(Boolean);
    const fallbackTargets = selectedNode
      ? [selectedNode.id]
      : nodes.slice(0, 1).map((node) => node.id);
    const targetNodeIds = targets.length > 0 ? targets : fallbackTargets;
    const testId = `test-${slugify(newTestName)}-${Date.now()}`;
    let expected: unknown = undefined;
    if (newTestExpected.trim()) {
      try {
        expected = JSON.parse(newTestExpected);
      } catch {
        expected = newTestExpected;
      }
    }
    setTests((current) => [
      ...current,
      {
        id: testId,
        name: newTestName,
        targetNodeIds,
        assertion: {
          kind: newTestKind,
          expected,
          expression: newTestExpression.trim() || undefined,
        },
        status: "idle",
      },
    ]);
    setTestEditorOpen(false);
    setRightPanel("unit_tests");
    setStatusMessage("Unit test added");
  };

  const handleHarnessPromotionLiveGuiProbe = useCallback(async () => {
    const clusterIds = HARNESS_PROMOTION_LIVE_GUI_CLUSTER_IDS;
    const primaryClusterId = clusterIds[0];
    const nowMs = Date.now();
    const projectRoot = currentProject?.rootPath || ".";
    const proofWorkflowPath = `${projectRoot}/.agents/workflows/default-agent-harness-live-gui-promotion-proof.workflow.json`;
    let lastProbePhase = "open_default_harness";
    let latestProbeWorkflow: WorkflowProject | null = null;
    const publishLiveGuiProbeState = (payload: Record<string, unknown>) => {
      if (typeof payload.phase === "string") {
        lastProbePhase = payload.phase;
      }
      (window as any).__AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI_RESULT = {
        ...(window as any).__AUTOPILOT_HARNESS_PROMOTION_LIVE_GUI_RESULT,
        ...payload,
        proofWorkflowPath,
        updatedAtMs: Date.now(),
      };
    };

    publishLiveGuiProbeState({
      status: "running",
      phase: "open_default_harness",
      clusterId: primaryClusterId,
      clusterIds,
    });
    setActiveTab("graph");
    setRightPanel("outputs");
    setBottomPanel("selection");
    setSelectedHarnessGroupId(primaryClusterId);
    setSelectedHarnessReceiptRef(null);
    setSelectedHarnessReplayFixtureRef(null);
    setSelectedHarnessRollbackTarget(null);
    setSelectedHarnessActivationBlockerIndex(null);
    setSelectedHarnessActivationBlockerRef(null);
    setSelectedHarnessActivationAuditEventId(null);
    setSelectedHarnessActivationGateId(null);
    setSelectedHarnessActivationGateEvidenceRef(null);
    setSelectedHarnessActivationGateNodeAttemptId(null);
    setSelectedHarnessActivationGateReceiptRef(null);
    setSelectedHarnessActivationGateReplayFixtureRef(null);
    setStatusMessage("Harness promotion live GUI proof running");

    try {
      let workflow = makeDefaultAgentHarnessWorkflow(nowMs);
      latestProbeWorkflow = workflow;
      publishLiveGuiProbeState({
        status: "running",
        phase: "build_default_workflow",
      });
      const blockedAttempts: WorkflowHarnessPromotionTransitionAttempt[] = [];
      const gatedAttempts: WorkflowHarnessPromotionTransitionAttempt[] = [];
      const liveAttempts: WorkflowHarnessPromotionTransitionAttempt[] = [];
      clusterIds.forEach((clusterId, index) => {
        const blocked = executeWorkflowHarnessPromotionTransition(
          workflow,
          clusterId,
          "gated",
          { nowMs: nowMs + 10 + index },
        );
        workflow = blocked.workflow;
        blockedAttempts.push(blocked.attempt);
      });
      clusterIds.forEach((clusterId, index) => {
        workflow = workflowReadyForHarnessPromotion(
          workflow,
          clusterId,
          nowMs + 30 + index,
        );
        const gated = executeWorkflowHarnessPromotionTransition(
          workflow,
          clusterId,
          "gated",
          { nowMs: nowMs + 50 + index },
        );
        workflow = gated.workflow;
        gatedAttempts.push(gated.attempt);
      });
      clusterIds.forEach((clusterId, index) => {
        const live = executeWorkflowHarnessPromotionTransition(
          workflow,
          clusterId,
          "live",
          { nowMs: nowMs + 70 + index },
        );
        workflow = live.workflow;
        liveAttempts.push(live.attempt);
      });
      latestProbeWorkflow = workflow;
      publishLiveGuiProbeState({
        status: "running",
        phase: "promotion_transitions_ready",
        blockedAttemptStatuses: blockedAttempts.map(
          (attempt) => attempt.attemptStatus,
        ),
        gatedAttemptStatuses: gatedAttempts.map(
          (attempt) => attempt.attemptStatus,
        ),
        liveAttemptStatuses: liveAttempts.map(
          (attempt) => attempt.attemptStatus,
        ),
      });
      const activationBlockerFork = forkDefaultAgentHarnessWorkflow(
        "Activation Blocker Deep Link Fork",
        nowMs + 115,
      );
      let activationGateProofWorkflow = activationBlockerFork.workflow;
      clusterIds.forEach((clusterId, index) => {
        activationGateProofWorkflow = workflowReadyForHarnessPromotion(
          activationGateProofWorkflow,
          clusterId,
          nowMs + 116 + index,
        );
      });
      latestProbeWorkflow = activationGateProofWorkflow;
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_gate_probe_workflow_staged",
      });
      setWorkflowPath(
        `${projectRoot}/.agents/workflows/${activationGateProofWorkflow.metadata.slug}.workflow.json`,
      );
      setTestsPath(
        `${projectRoot}/.agents/workflows/${activationGateProofWorkflow.metadata.slug}.tests.json`,
      );
      setTests(activationBlockerFork.tests);
      setProposals(activationBlockerFork.proposals);
      loadWorkflowProject(activationGateProofWorkflow);
      setValidationResult(
        validateWorkflowProject(
          activationGateProofWorkflow,
          activationBlockerFork.tests,
        ),
      );
      setReadinessResult(
        evaluateWorkflowActivationReadiness(
          activationGateProofWorkflow,
          activationBlockerFork.tests,
          validateWorkflowProject(
            activationGateProofWorkflow,
            activationBlockerFork.tests,
          ),
          activationBlockerFork.proposals,
          [],
        ),
      );
      await nextHarnessWorkbenchFrame();
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_blocker_deep_link_probe",
      });
      const activationBlockerDeepLinkProof =
        await runHarnessActivationBlockerDeepLinkProbe(
          activationGateProofWorkflow,
          nowMs + 120,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_gate_deep_link_probe",
      });
      const activationGateDeepLinkProof =
        await runHarnessActivationGateDeepLinkProbe(
          activationGateProofWorkflow,
          nowMs + 125,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_gate_action_click_probe",
      });
      const activationGateActionClickProof =
        await runHarnessActivationGateActionClickProbe(
          activationGateProofWorkflow,
          nowMs + 130,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "package_evidence_gate_click_probe",
      });
      const packageEvidenceGateClickProof =
        await runHarnessPackageEvidenceGateClickProbe(nowMs + 132);
      publishLiveGuiProbeState({
        status: "running",
        phase: "package_evidence_import_roundtrip_probe",
      });
      const {
        packageEvidenceImportRoundTripProof,
        packageImportReviewProof,
        packageImportActivationHandoffProof,
        packageImportActivationApplyProof,
        packageImportActivationReplayIntegrityProof,
      } =
        await runHarnessPackageEvidenceImportRoundTripProbe(nowMs + 134);
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_gate_collect_evidence_probe",
      });
      const activationGateCollectEvidenceClickProof =
        await runHarnessActivationGateCollectEvidenceClickProbe(nowMs + 135);
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_gate_rollback_restore_probe",
      });
      const activationGateRollbackRestoreClickProof =
        await runHarnessActivationGateRollbackRestoreClickProbe(nowMs + 140);
      publishLiveGuiProbeState({
        status: "running",
        phase: "activation_id_gate_click_probe",
      });
      const activationIdGateClickProof =
        await runHarnessActivationIdGateClickProbe(
          activationGateProofWorkflow,
          activationBlockerFork.tests,
          activationBlockerFork.proposals,
          nowMs + 145,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "worker_invariant_negative_probe",
      });
      const workerInvariantNegativeEnforcementProof =
        await runHarnessWorkerInvariantNegativeEnforcementProbe(nowMs + 148);
      publishLiveGuiProbeState({
        status: "running",
        phase: "bind_blessed_default_runtime_activation",
      });
      workflow = workflowWithBlessedDefaultRuntimeActivationProof(
        workflow,
        nowMs + 150,
        activationIdGateClickProof,
        packageImportActivationApplyProof,
      );
      latestProbeWorkflow = workflow;
      const nextTests = defaultAgentHarnessTests(workflow);
      setWorkflowPath(proofWorkflowPath);
      setTestsPath(
        proofWorkflowPath.replace(/\.workflow\.json$/, ".tests.json"),
      );
      setTests(nextTests);
      setProposals([]);
      setRuns([]);
      clearRunState();
      loadWorkflowProject(workflow);
      setValidationResult(validateWorkflowProject(workflow, nextTests));
      setReadinessResult(
        evaluateWorkflowActivationReadiness(
          workflow,
          nextTests,
          validateWorkflowProject(workflow, nextTests),
          [],
          [],
        ),
      );
      setSelectedHarnessGroupId(primaryClusterId);
      setRightPanel("outputs");
      setBottomPanel("selection");
      setStatusMessage("Blessed harness activation promoted to live default");
      await nextHarnessWorkbenchFrame();
      publishLiveGuiProbeState({
        status: "running",
        phase: "live_activation_gate_deep_link_probe",
      });
      const liveActivationGateDeepLinkProof =
        await runHarnessActivationGateDeepLinkProbe(
          workflow,
          nowMs + 154,
          {
            requiredCaseIds: ["activation-gate-worker-invariant"],
          },
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "deep_link_replay_probe",
      });
      const deepLinkReplayProof = await runHarnessDeepLinkReplayProbe(
        workflow,
        nowMs + 155,
      );
      publishLiveGuiProbeState({
        status: "running",
        phase: "live_turn_node_inspector_probe",
      });
      const liveTurnNodeInspectorDeepLinkProof =
        await runHarnessLiveTurnNodeInspectorDeepLinkProbe(
          workflow,
          nowMs + 157,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "live_shadow_comparison_probe",
      });
      const liveShadowComparisonDeepLinkProof =
        await runHarnessLiveShadowComparisonDeepLinkProbe(
          workflow,
          nowMs + 158,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "active_runtime_rollback_proof_probe",
      });
      const activeRuntimeRollbackProofWorkbenchProof =
        await runHarnessActiveRuntimeRollbackProofProbe(workflow, nowMs + 159);
      publishLiveGuiProbeState({
        status: "running",
        phase: "active_runtime_rollback_execution_probe",
      });
      const {
        executionProof: activeRuntimeRollbackExecutionProof,
        applyProof: activeRuntimeRollbackApplyProof,
        auditEvent: activeRuntimeRollbackApplyAuditEvent,
      } =
        await runHarnessActiveRuntimeRollbackExecutionWorkbenchProbe(
          workflow,
          nowMs + 160,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "active_runtime_rollback_negative_apply_probe",
      });
      const activeRuntimeRollbackNegativeApplyProof =
        await runHarnessActiveRuntimeRollbackNegativeApplyProbe(
          workflow,
          activeRuntimeRollbackExecutionProof,
          nowMs + 161,
        );
      publishLiveGuiProbeState({
        status: "running",
        phase: "cold_start_deep_link_restore_probe",
      });
      const coldStartDeepLinkRestoreProof =
        await runHarnessColdStartDeepLinkRestoreProbe(workflow, nowMs + 162);
      const harnessMetadata = workflow.metadata.harness;
      if (!harnessMetadata) {
        throw new Error(
          "Harness deep-link replay proof requires harness metadata.",
        );
      }
      workflow = {
        ...workflow,
        metadata: {
          ...workflow.metadata,
          harness: {
            ...harnessMetadata,
            deepLinkReplayProof,
            coldStartDeepLinkRestoreProof,
            activationBlockerDeepLinkProof,
            activationGateDeepLinkProof,
            liveActivationGateDeepLinkProof,
            liveTurnNodeInspectorDeepLinkProof,
            liveShadowComparisonDeepLinkProof,
            activeRuntimeRollbackProofWorkbenchProof,
            activeRuntimeRollbackExecutionProof,
            activeRuntimeRollbackApplyProof,
            activeRuntimeRollbackNegativeApplyProof,
            activationAudit: [
              ...(harnessMetadata.activationAudit ?? []),
              activeRuntimeRollbackApplyAuditEvent,
            ],
            activationGateActionClickProof,
            packageEvidenceGateClickProof,
            packageEvidenceImportRoundTripProof,
            packageImportReviewProof,
            packageImportActivationHandoffProof,
            packageImportActivationApplyProof,
            packageImportActivationReplayIntegrityProof,
            activationGateCollectEvidenceClickProof,
            activationGateRollbackRestoreClickProof,
            activationIdGateClickProof,
            workerInvariantNegativeEnforcementProof,
          },
          updatedAtMs: Date.now(),
        },
      };
      latestProbeWorkflow = workflow;
      publishLiveGuiProbeState({
        status: "running",
        phase: "save_live_gui_proof_workflow",
      });
      setWorkflowPath(proofWorkflowPath);
      setTestsPath(
        proofWorkflowPath.replace(/\.workflow\.json$/, ".tests.json"),
      );
      setTests(nextTests);
      setProposals([]);
      loadWorkflowProject(workflow);
      setWorkflow(workflow);
      if (runtime.saveWorkflowProject) {
        await runtime.saveWorkflowProject(proofWorkflowPath, workflow);
      }
      publishLiveGuiProbeState({
        status: "passed",
        phase: "complete",
        blockedAttemptStatuses: blockedAttempts.map(
          (attempt) => attempt.attemptStatus,
        ),
        gatedAttemptStatuses: gatedAttempts.map(
          (attempt) => attempt.attemptStatus,
        ),
        liveAttemptStatuses: liveAttempts.map(
          (attempt) => attempt.attemptStatus,
        ),
        targetExecutionMode: "live",
        deepLinkReplayPassed: deepLinkReplayProof.passed,
        deepLinkReplayCaseIds: deepLinkReplayProof.cases.map(
          (replayCase) => replayCase.id,
        ),
        coldStartDeepLinkRestorePassed: coldStartDeepLinkRestoreProof.passed,
        coldStartDeepLinkRestoreCaseIds:
          coldStartDeepLinkRestoreProof.cases.map(
            (restoreCase) => restoreCase.id,
          ),
        activationBlockerDeepLinkPassed: activationBlockerDeepLinkProof.passed,
        activationBlockerDeepLinkCaseIds:
          activationBlockerDeepLinkProof.cases.map(
            (restoreCase) => restoreCase.id,
          ),
        activationGateDeepLinkPassed: activationGateDeepLinkProof.passed,
        activationGateDeepLinkCaseIds: activationGateDeepLinkProof.cases.map(
          (restoreCase) => restoreCase.id,
        ),
        liveActivationGateDeepLinkPassed:
          liveActivationGateDeepLinkProof.passed,
        liveActivationGateDeepLinkCaseIds:
          liveActivationGateDeepLinkProof.cases.map(
            (restoreCase) => restoreCase.id,
          ),
        liveTurnNodeInspectorDeepLinkPassed:
          liveTurnNodeInspectorDeepLinkProof.passed,
        liveTurnNodeInspectorDeepLinkCaseIds:
          liveTurnNodeInspectorDeepLinkProof.cases.map(
            (restoreCase) => restoreCase.id,
          ),
        liveShadowComparisonDeepLinkPassed:
          liveShadowComparisonDeepLinkProof.passed,
        liveShadowComparisonDeepLinkCaseIds:
          liveShadowComparisonDeepLinkProof.cases.map(
            (restoreCase) => restoreCase.id,
          ),
        activeRuntimeRollbackProofWorkbenchPassed:
          activeRuntimeRollbackProofWorkbenchProof.passed,
        activeRuntimeRollbackProofWorkbenchCaseIds:
          activeRuntimeRollbackProofWorkbenchProof.cases.map(
            (restoreCase) => restoreCase.id,
          ),
        activeRuntimeRollbackExecutionPassed:
          activeRuntimeRollbackExecutionProof.passed,
        activeRuntimeRollbackExecutionCanaryResultId:
          activeRuntimeRollbackExecutionProof.dryRun.canaryResultId,
        activeRuntimeRollbackApplyPassed:
          activeRuntimeRollbackApplyProof.passed,
        activeRuntimeRollbackApplyExecutionId:
          activeRuntimeRollbackApplyProof.executionId,
        activeRuntimeRollbackApplyReceiptId:
          activeRuntimeRollbackApplyProof.rollbackReceiptId,
        activeRuntimeRollbackNegativeApplyPassed:
          activeRuntimeRollbackNegativeApplyProof.passed,
        activeRuntimeRollbackNegativeApplyCaseIds:
          activeRuntimeRollbackNegativeApplyProof.cases.map(
            (negativeCase) => negativeCase.caseId,
          ),
        activationGateActionClickPassed: activationGateActionClickProof.passed,
        activationGateActionCommand:
          activationGateActionClickProof.action.command,
        packageEvidenceGateClickPassed:
          packageEvidenceGateClickProof.passed,
        packageEvidenceGateReceiptRefCount:
          packageEvidenceGateClickProof.manifest.receiptRefCount,
        packageEvidenceGateDeepLinkCount:
          packageEvidenceGateClickProof.manifest.deepLinkCount,
        packageEvidenceImportRoundTripPassed:
          packageEvidenceImportRoundTripProof.passed,
        packageEvidenceImportRoundTripMissingRows:
          packageEvidenceImportRoundTripProof.incompleteImport.missingRows,
        packageImportReviewPassed: packageImportReviewProof.passed,
        packageImportReviewSourcePath:
          packageImportReviewProof.sourceWorkflowPath,
        packageImportReviewImportedPath:
          packageImportReviewProof.importedWorkflowPath,
        packageImportReviewActivationDisabledWhenIncomplete:
          packageImportReviewProof.activationAction.incomplete.disabled,
        packageImportActivationHandoffPassed:
          packageImportActivationHandoffProof.passed,
        packageImportActivationHandoffDecision:
          packageImportActivationHandoffProof.activationAction.valid
            .handoffDecision,
        packageImportActivationHandoffWorker:
          packageImportActivationHandoffProof.activationAction.valid
            .workerBindingId,
        packageImportActivationApplyPassed:
          packageImportActivationApplyProof.passed,
        packageImportActivationApplyActivationId:
          packageImportActivationApplyProof.activationResult?.activationId ??
          null,
        packageImportActivationApplyAudit:
          packageImportActivationApplyProof.activationResult
            ?.latestAuditEventType ?? null,
        packageImportActivationReplayIntegrityPassed:
          packageImportActivationReplayIntegrityProof.passed,
        packageImportActivationReplayIntegrityCaseIds:
          packageImportActivationReplayIntegrityProof.cases.map(
            (replayCase) => replayCase.caseId,
          ),
        activationGateCollectEvidenceClickPassed:
          activationGateCollectEvidenceClickProof.passed,
        activationGateCollectEvidenceCommand:
          activationGateCollectEvidenceClickProof.action.command,
        activationGateCollectEvidenceReplayGateId:
          activationGateCollectEvidenceClickProof.replayGate.gateId,
        activationGateRollbackRestoreClickPassed:
          activationGateRollbackRestoreClickProof.passed,
        activationGateRollbackRestoreCommand:
          activationGateRollbackRestoreClickProof.action.command,
        activationGateRollbackRestoreCanaryStatus:
          activationGateRollbackRestoreClickProof.dryRun.rollbackRestoreStatus,
        activationGateRollbackRestoreReceiptBindingRef:
          activationGateRollbackRestoreClickProof.dryRun
            .rollbackRestoreReceiptBindingRef,
        activationIdGateClickPassed: activationIdGateClickProof.passed,
        activationIdBlockedDryRunDecision:
          activationIdGateClickProof.blockedDryRun.decision,
        activationIdMintedActivationId:
          activationIdGateClickProof.mintedActivation.activationId,
        workerInvariantNegativeEnforcementPassed:
          workerInvariantNegativeEnforcementProof.passed,
        workerInvariantNegativeEnforcementBlockers:
          workerInvariantNegativeEnforcementProof.blockers,
        workerInvariantNegativeEnforcementApplyRefused:
          workerInvariantNegativeEnforcementProof.activationApply.applied ===
          false,
        selectedSelector:
          workflow.metadata.harness?.runtimeSelectorDecision?.selectedSelector,
        defaultAuthorityTransferred:
          workflow.metadata.harness?.liveHandoffProof
            ?.defaultAuthorityTransferred,
      });
    } catch (error) {
      const message = errorMessage(error);
      if (HARNESS_PROMOTION_LIVE_GUI_SCRIPT) {
        console.error("[HarnessPromotionLiveGuiProbe]", message);
      }
      setStatusMessage(`Harness promotion live GUI proof blocked: ${message}`);
      try {
        const diagnosticWorkflow =
          latestProbeWorkflow ?? makeDefaultAgentHarnessWorkflow(nowMs);
        const diagnosticHarness = diagnosticWorkflow.metadata.harness ?? {};
        const workflowWithDiagnostic: WorkflowProject = {
          ...diagnosticWorkflow,
          metadata: {
            ...diagnosticWorkflow.metadata,
            harness: {
              ...diagnosticHarness,
              liveGuiProbeDiagnostics: {
                schemaVersion:
                  "workflow.harness.live-gui-probe-diagnostics.v1",
                status: "blocked",
                phase: lastProbePhase,
                error: message,
                proofWorkflowPath,
                generatedAtMs: Date.now(),
              },
            } as WorkflowProject["metadata"]["harness"],
            updatedAtMs: Date.now(),
          },
        };
        if (runtime.saveWorkflowProject) {
          await runtime.saveWorkflowProject(
            proofWorkflowPath,
            workflowWithDiagnostic,
          );
        }
      } catch (diagnosticError) {
        publishLiveGuiProbeState({
          status: "blocked",
          phase: "error",
          diagnosticSaveError: errorMessage(diagnosticError),
        });
      }
      publishLiveGuiProbeState({
        status: "blocked",
        phase: "error",
        blockedPhase: lastProbePhase,
        error: message,
      });
    }
  }, [
    clearRunState,
    currentProject?.rootPath,
    loadWorkflowProject,
    runHarnessActivationBlockerDeepLinkProbe,
    runHarnessActivationGateActionClickProbe,
    runHarnessPackageEvidenceGateClickProbe,
    runHarnessPackageEvidenceImportRoundTripProbe,
    runHarnessActivationGateCollectEvidenceClickProbe,
    runHarnessActivationIdGateClickProbe,
    runHarnessWorkerInvariantNegativeEnforcementProbe,
    runHarnessActivationGateRollbackRestoreClickProbe,
    runHarnessActivationGateDeepLinkProbe,
    runHarnessColdStartDeepLinkRestoreProbe,
    runHarnessDeepLinkReplayProbe,
    runHarnessActiveRuntimeRollbackExecutionWorkbenchProbe,
    runHarnessActiveRuntimeRollbackNegativeApplyProbe,
    runHarnessActiveRuntimeRollbackProofProbe,
    runHarnessLiveShadowComparisonDeepLinkProbe,
    runHarnessLiveTurnNodeInspectorDeepLinkProbe,
    runtime,
  ]);

  useEffect(() => {
    if (!HARNESS_PROMOTION_LIVE_GUI_SCRIPT) return;
    if (dogfoodAutomationStarted.current) return;
    dogfoodAutomationStarted.current = true;
    void handleHarnessPromotionLiveGuiProbe();
  }, [handleHarnessPromotionLiveGuiProbe]);

  useEffect(() => {
    if (
      SCRATCH_DOGFOOD_SCRIPT !== "scratch-heavy" &&
      SCRATCH_DOGFOOD_SCRIPT !== "manual-repo-test-engineer"
    )
      return;
    if (dogfoodAutomationStarted.current) return;
    dogfoodAutomationStarted.current = true;

    const publishDogfoodState = (payload: Record<string, unknown>) => {
      (window as any).__AUTOPILOT_WORKFLOW_DOGFOOD_RESULT = {
        ...(window as any).__AUTOPILOT_WORKFLOW_DOGFOOD_RESULT,
        ...payload,
        updatedAtMs: Date.now(),
      };
    };

    const runScratchDogfood = async () => {
      const isHeavySuite = SCRATCH_DOGFOOD_SCRIPT === "scratch-heavy";
      publishDogfoodState({
        status: "running",
        phase: isHeavySuite
          ? "build_scratch_heavy_suite"
          : "build_repo_test_engineer",
      });
      setActiveTab("graph");
      setBottomPanel("run_output");
      setStatusMessage("Run checks running");
      try {
        const result = isHeavySuite
          ? await handleBuildScratchHeavySuite()
          : await handleBuildRepoTestEngineerScratch();
        publishDogfoodState({
          ...result,
          phase: "complete",
        });
      } catch (error) {
        const message = errorMessage(error);
        setStatusMessage("Run checks blocked");
        setRightPanel("runs");
        setBottomPanel("run_output");
        publishDogfoodState({
          status: "blocked",
          phase: "error",
          error: message,
        });
      }
    };

    void runScratchDogfood();
  }, [handleBuildRepoTestEngineerScratch, handleBuildScratchHeavySuite]);

  useEffect(() => {
    if (SCRATCH_DOGFOOD_SCRIPT !== "heavy-agent-suite") return;
    if (dogfoodAutomationStarted.current) return;
    dogfoodAutomationStarted.current = true;
    void handleDogfoodSuite();
  }, [handleDogfoodSuite]);

  const proposalStatusCounts = proposals.reduce(
    (counts, proposal) => ({
      ...counts,
      [proposal.status]: counts[proposal.status] + 1,
    }),
    { open: 0, applied: 0, rejected: 0 },
  );
  const proposalBoundedTargetCount = proposals.reduce(
    (total, proposal) => total + proposal.boundedTargets.length,
    0,
  );
  const executionStatusCounts = runs.reduce<Record<string, number>>(
    (counts, run) => {
      counts[run.status] = (counts[run.status] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const selectedExecutionRun =
    runs.find((run) => run.id === selectedRunId) ??
    (lastRunResult ? lastRunResult.summary : null) ??
    runs[0] ??
    null;
  const selectedExecutionRunResult =
    lastRunResult && selectedExecutionRun?.id === lastRunResult.summary.id
      ? lastRunResult
      : null;
  const executionCheckpointCount = runs.reduce(
    (total, run) => total + (run.checkpointCount ?? 0),
    0,
  );
  const executionCompareRun = selectedExecutionRun
    ? (runs.find((run) => run.id !== selectedExecutionRun.id) ?? null)
    : null;
  const lifecycleState = workflowLifecycleState(
    currentProjectFile,
    readinessResult,
    validationResult,
  );

  return {
    activeRightPanelMeta,
    activeTab,
    bindingManifest,
    BOTTOM_TABS,
    bottomPanel,
    Brain,
    Cable,
    CheckCircle2,
    GitCompare,
    Canvas,
    canvasSearchOpen,
    canvasSearchQuery,
    canvasSearchResults,
    checkpoints,
    closeCanvasSearch,
    closeLeftDrawer,
    compareRunId,
    compareRunResult,
    compatibleNodeHints,
    compatiblePortFocusLabel,
    connectFromNodeId,
    ConnectorBindingModal,
    connectorBindingOpen,
    counts,
    createKind,
    createMode,
    createName,
    createOpen,
    CreateWorkflowModal,
    currentProject,
    currentProjectFile,
    DeployModal,
    deployOpen,
    displayEdges,
    displayNodes,
    dogfoodRun,
    emptyCanvasStartItems,
    execution,
    executionCheckpointCount,
    executionCompareRun,
    executionStatusCounts,
    filteredNodeLibrary,
    fitView,
    FlaskConical,
    functionDryRunResult,
    GitPullRequest,
    globalConfig,
    guardedCanvasDrop,
    guardedOnConnect,
    guardedOnEdgesChange,
    guardedOnNodesChange,
    handleAddCompatibleNode,
    handleAddNodeFromLibrary,
    handleAddTest,
    handleAddTestFromOutput,
    handleApplyHarnessActivationCandidate,
    handleApplyProposal,
    handleCaptureNodeFixture,
    handleCheckReadiness,
    handleCheckWorkflowBinding,
    handleCollapseHarnessGroups,
    handleCompareRun,
    handleConnectSelectedNodes,
    handleCopyHarnessDeepLink,
    handleCreateProposal,
    handleCreateWorkflow,
    handleDragStart,
    handleDryRunFunction,
    handleDryRunNodeFromFixture,
    handleApplyActiveRuntimeRollback,
    handleExecuteRuntimeDiagnosticsRepair,
    handleExecuteRuntimeContextPressureAction,
    handleExecuteRuntimeWorkspaceTrustAction,
    handleExecuteHarnessRollback,
    handleExpandHarnessGroups,
    handleExportPortablePackage,
    handleForkDefaultHarness,
    handleGenerateBindingManifest,
    handleImportNodeFixture,
    handleImportPortablePackage,
    handleInsertAgentLoopMacro,
    handleInspectExecutionNode,
    handleInspectHarnessGroupNode,
    handleOpenDefaultHarness,
    handleOpenDeploy,
    handlePinNodeFixture,
    handleResolveWorkflowIssue,
    handleResumeRun,
    handleRun,
    handleRunHarnessActivationDryRun,
    handleRunHarnessPromotionTransition,
    handleRunHarnessReplayDrill,
    handleRunHarnessReplayGate,
    handleRunHarnessRollbackDrill,
    handleRunActiveRuntimeRollbackDryRun,
    handleRunTests,
    handleRunWorkflowNode,
    handleRunWorkflowUpstream,
    handleSave,
    handleSelectHarnessReceiptRef,
    handleSelectHarnessReplayFixtureRef,
    handleSelectHarnessRollbackTarget,
    handleSelectRun,
    handleUpdateEnvironmentProfile,
    handleUpdateWorkflowChromeLocale,
    handleUpdateProductionProfile,
    handleValidate,
    handleWorkflowNodeSelect,
    harnessActivationCandidate,
    harnessGroupSummary,
    harnessGroupViews,
    harnessWorkbenchDeepLinkUrl,
    harnessWorkerBinding,
    ImportPackageModal,
    importPackageName,
    importPackageOpen,
    importPackagePath,
    isBlessedHarnessWorkflow,
    isReadOnlyWorkflow,
    isSearchingNodeLibrary,
    lastRunResult,
    leftDrawerOpen,
    lifecycleState,
    Maximize2,
    Minimize2,
    missingReasoningBinding,
    ModelBindingModal,
    modelBindingOpen,
    newTestExpected,
    newTestExpression,
    newTestKind,
    newTestName,
    newTestTargets,
    NODE_GROUP_FILTERS,
    nodeConfigInitialSection,
    nodeConfigOpen,
    nodeGroupCounts,
    nodeGroupFilter,
    nodeRunStatusById,
    nodes,
    nodeSearch,
    openLeftDrawer,
    PanelLeftOpen,
    PanelRightClose,
    PanelRightOpen,
    Play,
    Plus,
    packageImportReview,
    portablePackage,
    proposalBoundedTargetCount,
    ProposalPreviewModal,
    proposals,
    proposalStatusCounts,
    proposalToReview,
    readinessResult,
    recentNodeLibrary,
    RIGHT_PANELS,
    rightPanel,
    rightPanelBadgeCounts,
    rightRailCollapsed,
    rightRailWidth,
    Rocket,
    Search,
    selectedHarnessActivationAuditEventId,
    selectedHarnessActivationBlockerIndex,
    selectedHarnessActivationBlockerRef,
    selectedHarnessActivationGateEvidenceRef,
    selectedHarnessActivationGateId,
    selectedHarnessActivationGateNodeAttemptId,
    selectedHarnessActivationGateReceiptRef,
    selectedHarnessActivationGateReplayFixtureRef,
    selectedHarnessDefaultDispatchId,
    selectedHarnessGroup,
    selectedHarnessNodeAttemptId,
    selectedHarnessReceiptRef,
    selectedHarnessReplayFixtureRef,
    selectedHarnessRevisionBindingKind,
    selectedHarnessRevisionBindingRef,
    selectedHarnessRollbackTarget,
    selectedHarnessSelectorDecisionId,
    selectedHarnessWorkerBindingId,
    Settings,
    runDetailLoading,
    runEvents,
    runtimeThreadEvents,
    runs,
    Save,
    SCAFFOLD_GROUPS,
    WORKFLOW_SCAFFOLDS,
    selectedDefinition,
    selectedExecutionRun,
    selectedExecutionRunResult,
    selectedFixtures,
    selectedNode,
    selectedNodeId,
    selectedRunId,
    selectedUpstreamReferences,
    setActiveTab,
    setBottomPanel,
    setCanvasSearchQuery,
    setCompatiblePortFocus,
    setConnectFromNodeId,
    setConnectorBindingOpen,
    setCreateKind,
    setCreateMode,
    setCreateName,
    setCreateOpen,
    setDeployOpen,
    setGlobalConfig,
    setImportPackageName,
    setImportPackageOpen,
    setImportPackagePath,
    setModelBindingOpen,
    setNewTestExpected,
    setNewTestExpression,
    setNewTestKind,
    setNewTestName,
    setNewTestTargets,
    setNodeConfigInitialSection,
    setNodeConfigOpen,
    setNodeGroupFilter,
    setNodeSearch,
    setProposalToReview,
    setRightPanel,
    setRightRailCollapsed,
    setRightRailWidth,
    setStatusMessage,
    setTestEditorOpen,
    slugify,
    statusMessage,
    TestEditorModal,
    testEditorOpen,
    testResult,
    tests,
    testsPath,
    toggleCanvasSearch,
    toggleLeftDrawer,
    updateNode,
    validationResult,
    visibleCompatibleNodeHints,
    workflow,
    workflowActionMetadataLabel,
    WorkflowBottomShelf,
    workflowConfigSectionForNodeKind,
    workflowCreatorItemId,
    workflowDurationLabel,
    workflowEventLabel,
    WorkflowHeaderAction,
    WorkflowInlineIcon,
    WorkflowNodeConfigModal,
    workflowNodeCreatorBadge,
    workflowNodeName,
    workflowNodeRunChildLineage,
    workflowPath,
    WorkflowRailPanel,
    workflowTimeLabel,
    zoomIn,
    zoomOut,
  } as const;
}
