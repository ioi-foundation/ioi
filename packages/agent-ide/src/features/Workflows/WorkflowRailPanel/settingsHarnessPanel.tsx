import type {
  WorkflowHarnessActivationAuditEvent,
  WorkflowHarnessActivationCandidateGateResult,
  WorkflowHarnessActivationRollbackExecution,
  WorkflowHarnessActivationRollbackProof,
  WorkflowHarnessActiveRuntimeRollbackApplyProof,
  WorkflowHarnessActiveRuntimeRollbackExecutionProof,
  WorkflowHarnessAuthorityToolingNodeAuthorityGate,
  WorkflowHarnessCanaryExecutionBoundary,
  WorkflowHarnessCognitionNodeAuthorityGate,
  WorkflowHarnessComponentKind,
  WorkflowHarnessDefaultRuntimeDispatchProof,
  WorkflowHarnessForkActivationCandidate,
  WorkflowHarnessForkActivationRecord,
  WorkflowHarnessForkMutationCanary,
  WorkflowHarnessLiveHandoffProof,
  WorkflowHarnessLivePromotionReadinessProof,
  WorkflowHarnessNodeAttemptRecord,
  WorkflowHarnessPackageEvidenceLink,
  WorkflowHarnessPackageEvidenceManifest,
  WorkflowHarnessPromotionCluster,
  WorkflowHarnessRoutingModelNodeAuthorityGate,
  WorkflowHarnessRuntimeSelectorDecision,
  WorkflowHarnessSlotSpec,
  WorkflowHarnessVerificationOutputNodeAuthorityGate,
  WorkflowHarnessWorkerAttachLifecycleEvent,
  WorkflowHarnessWorkerAttachReceipt,
  WorkflowHarnessWorkerBinding,
  WorkflowHarnessWorkerBindingRegistryRecord,
  WorkflowHarnessWorkerHandoffReceipt,
  WorkflowHarnessWorkerLaunchEnvelope,
  WorkflowHarnessWorkerSessionRecord,
  WorkflowPackageImportActivationHandoff,
  WorkflowPackageImportReview,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRevisionBinding,
  WorkflowValidationIssue,
} from "../../../types/graph";
import { WorkflowSettingsHarnessActivationPanel } from "./settingsHarnessActivationPanel";
import { WorkflowSettingsHarnessWorkerBindingPanel } from "./settingsHarnessWorkerBindingPanel";
import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import type { WorkflowSettingsHarnessModel } from "../../../runtime/workflow-settings-harness-model";
import {
  workflowProofString,
} from "./statusPrimitives";
import type {
  WorkflowHarnessActivationGateAction,
  WorkflowHarnessActivationWizardStep,
  WorkflowHarnessAuthorityGateProofView,
  WorkflowHarnessWorkbenchDeepLinkTarget,
} from "./types";

type Nullable<T> = T | null | undefined;

export interface WorkflowSettingsHarnessRollbackProofBinding {
  bound: boolean;
  blockers: string[];
  readinessProofId: string;
  liveShadowComparisonGateId: string;
  liveShadowComparisonGateReady: boolean;
  expectedLiveShadowComparisonGateId: string;
  activationId: string;
  harnessHash: string;
  policyDecision: string;
  launchEnvelope: WorkflowHarnessWorkerLaunchEnvelope | null;
  handoffReceipt: WorkflowHarnessWorkerHandoffReceipt | null;
  nodeAttempt: WorkflowHarnessNodeAttemptRecord | null;
  replayFixtureRef: string;
}

export interface WorkflowSettingsHarnessActiveRuntimeBinding {
  workflowId: string;
  activationId: string;
  harnessHash: string;
  selectorDecisionId: string;
  defaultDispatchId: string;
  workerBindingId: string;
  selectedSelector: string;
  productionDefaultSelector: string;
  executionMode: string;
  runtimeAuthority: string;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  workerBinding: Nullable<WorkflowHarnessWorkerBinding>;
  bindingMatched: boolean;
  selectorDecisionLinksDispatch: boolean;
  drivesRuntimeDecision: boolean;
  selectorLivePromotionReadinessReady: boolean;
  liveHandoffLivePromotionReadinessReady: boolean;
  dispatchLivePromotionReadinessReady: boolean;
  selectorLivePromotionReadinessProofId: string;
  liveHandoffLivePromotionReadinessProofId: string;
  dispatchLivePromotionReadinessProofId: string;
  livePromotionReadinessProofIdsMatch: boolean;
  invalidForkLiveActivationBlocked: boolean;
  workerBindingAuthorityReady: boolean;
  workerBindingAuthorityBlockers: string[];
  workerLaunchReviewedImportInvariantBound: boolean;
  workerRegistryReviewedPackageBound: boolean;
  workerBindingRequiredInvariantIds: string[];
  workerBindingInvariantBlockers: string[];
  workerRegistryRequiredInvariantIds: string[];
  workerRegistryInvariantBlockers: string[];
  workerAttachRequiredInvariantIds: string[];
  workerAttachInvariantBlockers: string[];
  workerAttachLifecycleRequiredInvariantIds: string[];
  workerAttachLifecycleInvariantBlockers: string[];
  workerSessionRequiredInvariantIds: string[];
  workerSessionInvariantBlockers: string[];
  workerSessionLaunchAuthorityInvariantIds: string[];
  workerSessionLaunchAuthorityInvariantBlockers: string[];
  workerLaunchEnvelopeInvariantIds: string[];
  workerLaunchEnvelopeInvariantBlockers: string[];
  workerHandoffReceiptInvariantIds: string[];
  workerHandoffReceiptInvariantBlockers: string[];
  workerInvariantBlockers: string[];
  workerBindingRegistryRecord: Nullable<WorkflowHarnessWorkerBindingRegistryRecord>;
  workerBindingRegistryBound: boolean;
  workerBindingRegistryStatus: string;
  workerBindingRegistryBlockers: string[];
  workerAttachReceipt: Nullable<WorkflowHarnessWorkerAttachReceipt>;
  workerAttachResumeReceipt: Nullable<WorkflowHarnessWorkerAttachReceipt>;
  workerAttachRollbackReceipt: Nullable<WorkflowHarnessWorkerAttachReceipt>;
  workerAttachLifecycle: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerAttachLifecycleComplete: boolean;
  workerAttachLifecycleStatuses: string[];
  workerAttachLifecycleAttemptIds: string[];
  workerSessionRecord: Nullable<WorkflowHarnessWorkerSessionRecord>;
  workerSessionAccepted: boolean;
  workerSessionStatus: string;
  workerSessionRecordId: string;
  workerSessionBlockers: string[];
  workerLaunchEnvelopes: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts: WorkflowHarnessWorkerHandoffReceipt[];
  workerLaunchEnvelopeIds: string[];
  workerHandoffReceiptIds: string[];
  workerHandoffNodeAttempts: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffNodeAttemptIds: string[];
  workerHandoffReplayFixtureRefs: string[];
  workerHandoffNodeTimelineBound: boolean;
  workerRollbackProof: WorkflowSettingsHarnessRollbackProofBinding;
  workerLaunchEnvelopesAccepted: boolean;
  workerHandoffReceiptsAccepted: boolean;
  workerAttachAccepted: boolean;
  workerAttachStatus: string;
  workerAttachBlockers: string[];
  receiptRefs: string[];
  replayFixtureRefs: string[];
  blockers: string[];
}

export interface WorkflowSettingsHarnessPackageEvidenceReviewRow {
  id: string;
  label: string;
  ready: boolean;
  value: string;
  detail: string;
  refs: string[];
  kind: string;
}

export interface WorkflowSettingsHarnessActivationGateInspection
  extends WorkflowHarnessActivationCandidateGateResult {
  sourceKind: "activation_candidate" | "wizard_step";
  nodeAttemptIds: string[];
  receiptRefs: string[];
  replayFixtureRefs: string[];
  requiredInvariantIds: string[];
  invariantBlockers: string[];
  gateAction: WorkflowHarnessActivationGateAction | null;
}

export interface WorkflowSettingsHarnessReadOnlyRoutingProof {
  mode?: string;
  scenario?: string;
  sideEffectsExecuted?: boolean;
  mutationExecuted?: boolean;
  rollbackAvailable?: boolean;
  requiredScenarioSet?: string[];
}

export interface WorkflowSettingsHarnessForkComponentDiffRow {
  componentId: string;
  nodeId: string | null;
  label: string;
  kind: string;
  blessedVersion: string;
  forkVersion: string;
  blessedReadiness: string;
  forkReadiness: string;
  status: string;
}

export interface WorkflowSettingsHarnessActivationProps {
  activationGateProposal: WorkflowProposal | undefined;
  blessedHarnessWorkflow: boolean;
  boundHarnessSlotIds: Set<string>;
  firstHarnessActivationBlocker: WorkflowValidationIssue | null;
  harnessActivationAudit: WorkflowHarnessActivationAuditEvent[];
  harnessActivationAuditReceiptRefs: string[];
  harnessActivationBlockers: WorkflowValidationIssue[];
  harnessActivationCandidate: Nullable<WorkflowHarnessForkActivationCandidate>;
  harnessActivationGateActions: Record<string, WorkflowHarnessActivationGateAction>;
  harnessActivationGateNodeAttempts: WorkflowHarnessNodeAttemptRecord[];
  harnessActivationReady: boolean;
  harnessActivationRecord: Nullable<WorkflowHarnessForkActivationRecord>;
  harnessActivationRollbackExecution: Nullable<WorkflowHarnessActivationRollbackExecution>;
  harnessActivationRollbackProof: Nullable<WorkflowHarnessActivationRollbackProof>;
  harnessActivationWizardSteps: WorkflowHarnessActivationWizardStep[];
  harnessActivationWorkerHandoffNodeAttemptIds: string[];
  harnessActivationWorkerHandoffNodeAttempts: WorkflowHarnessNodeAttemptRecord[];
  harnessActivationWorkerHandoffReplayFixtureRefs: string[];
  harnessActivationWorkerHandoffTimelineReady: boolean;
  harnessActivationWorkerInvariantBlockers: string[];
  harnessActivationWorkerInvariantReady: boolean;
  harnessActivationWorkerRequiredInvariantIds: string[];
  latestHarnessActivationAudit: Nullable<WorkflowHarnessActivationAuditEvent>;
  latestHarnessActivationAuditReceiptRefs: string[];
  packageImportActivationEnabled: boolean;
  packageImportActivationHandoff: Nullable<WorkflowPackageImportActivationHandoff>;
  packageImportHandoffWorkerBindingId: string;
  packageImportReplayIntegrityBlockers: string[];
  packageImportReview: WorkflowPackageImportReview | null;
  selectedHarnessActivationAuditEventId: string | null | undefined;
  selectedHarnessActivationBlockerIndex: string | null | undefined;
  selectedHarnessActivationBlockerRef: string | null | undefined;
  selectedHarnessActivationGateEvidenceRef: string | null | undefined;
  selectedHarnessActivationGateId: string | null | undefined;
  selectedHarnessActivationGateInspection: WorkflowSettingsHarnessActivationGateInspection | null;
  selectedHarnessActivationGateMutationCanary: WorkflowHarnessForkMutationCanary | null;
  selectedHarnessActivationGateNodeAttempt: WorkflowHarnessNodeAttemptRecord | null;
  selectedHarnessActivationGateNodeAttemptId: string | null | undefined;
  selectedHarnessActivationGateReceiptRef: string | null | undefined;
  selectedHarnessActivationGateReplayFixtureRef: string | null | undefined;
}

export interface WorkflowSettingsHarnessPackageRestoreProps {
  harnessPackageDeepLinks: WorkflowHarnessPackageEvidenceLink[];
  harnessPackageEvidenceBlockerCount: number;
  harnessPackageEvidenceReady: boolean;
  harnessPackageEvidenceRefValues: string[];
  harnessPackageEvidenceReviewRows: WorkflowSettingsHarnessPackageEvidenceReviewRow[];
  harnessPackageForkMutationCanary: Nullable<WorkflowHarnessForkMutationCanary>;
  harnessPackageForkMutationCanaryNodeAttemptIds: string[];
  harnessPackageForkMutationCanaryReceiptRefs: string[];
  harnessPackageForkMutationCanaryReplayFixtureRefs: string[];
  harnessPackageManifest: WorkflowHarnessPackageEvidenceManifest | null;
  harnessPackageReceiptRefValues: string[];
  harnessPackageReplayFixtureRefValues: string[];
  harnessPackageRollbackRestoreReceiptRefs: string[];
  harnessPackageWorkerHandoffNodeAttemptIds: string[];
  harnessPackageWorkerHandoffReceiptIds: string[];
}

export interface WorkflowSettingsHarnessRollbackProps {
  harnessActiveRuntimeBinding: WorkflowSettingsHarnessActiveRuntimeBinding | null;
  harnessActiveRuntimeRollbackApplyBlockers: string[];
  harnessActiveRuntimeRollbackApplyDisabled: boolean;
  harnessActiveRuntimeRollbackApplyProof: Nullable<WorkflowHarnessActiveRuntimeRollbackApplyProof>;
  harnessActiveRuntimeRollbackDryRunPassed: boolean;
  harnessActiveRuntimeRollbackExecutionProof: Nullable<WorkflowHarnessActiveRuntimeRollbackExecutionProof>;
  harnessActiveRuntimeRollbackProofBindingBlockers: string[];
  harnessActiveRuntimeRollbackProofStillBound: boolean;
  harnessBindingRollbackAvailable: boolean;
  harnessBindingRollbackHash: string;
  harnessBindingRollbackTargets: string[];
  harnessCanaryExecutionBoundaries: WorkflowHarnessCanaryExecutionBoundary[];
  harnessRollbackDrillReceiptRefs: string[];
  harnessRollbackExecutionReceiptRefs: string[];
  harnessRollbackRevisionBinding: Nullable<WorkflowRevisionBinding>;
  harnessRollbackRevisionBindingRef: string | null;
  harnessSelectedRollbackTarget: string;
  rollbackReady: boolean;
  selectedHarnessCanaryBoundary: WorkflowHarnessCanaryExecutionBoundary | null;
  selectedHarnessRollbackDrillId: string | null | undefined;
  selectedHarnessRollbackRestoreCanaryId: string | null | undefined;
  selectedHarnessRollbackRestoreReceiptRef: string | null | undefined;
  selectedHarnessRollbackTarget: string | null | undefined;
}

export interface WorkflowSettingsHarnessWorkerBindingProps {
  harnessBindingInspectorStatus: string;
  harnessBindingVersionEntries: Array<[string, string]>;
  harnessCandidateRevisionBinding: Nullable<WorkflowRevisionBinding>;
  harnessCandidateRevisionBindingRef: string | null;
  harnessCandidateWorkerBinding: Nullable<WorkflowHarnessWorkerBinding>;
  harnessCurrentWorkerBinding: Nullable<WorkflowHarnessWorkerBinding>;
  harnessDefaultRuntimeDispatchProof: Nullable<WorkflowHarnessDefaultRuntimeDispatchProof>;
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers: string[];
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds: string[];
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers: string[];
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds: string[];
  harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound: boolean;
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers: string[];
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds: string[];
  harnessRevisionBinding: Nullable<WorkflowRevisionBinding>;
  harnessRevisionBindingRef: string | null;
  harnessWorkerBinding: Nullable<WorkflowHarnessWorkerBinding>;
  selectedHarnessDefaultDispatchId: string | null | undefined;
  selectedHarnessNodeAttemptId: string | null | undefined;
  selectedHarnessReceiptRef: string | null | undefined;
  selectedHarnessReplayFixtureRef: string | null | undefined;
  selectedHarnessRevisionBindingKind: string | null | undefined;
  selectedHarnessRevisionBindingRef: string | null | undefined;
  selectedHarnessSelectorDecisionId: string | null | undefined;
  selectedHarnessWorkerBindingId: string | null | undefined;
}

export interface WorkflowSettingsHarnessPromotionProps {
  harnessAuthorityGateLiveProofs: WorkflowHarnessAuthorityGateProofView[];
  harnessAuthorityGateLiveReady: boolean;
  harnessAuthorityGateReadyCount: number;
  harnessAuthorityToolingNodeAuthorityGate: Nullable<WorkflowHarnessAuthorityToolingNodeAuthorityGate>;
  harnessAuthorityToolingProof: Nullable<Record<string, unknown>>;
  harnessCognitionNodeAuthorityGate: Nullable<WorkflowHarnessCognitionNodeAuthorityGate>;
  harnessForkComponentDiffRows: WorkflowSettingsHarnessForkComponentDiffRow[];
  harnessForkComponentDiffStats: Record<string, number>;
  harnessForkMutationCanary: Nullable<WorkflowHarnessForkMutationCanary>;
  harnessForkMutationCanaryNodeAttemptIds: string[];
  harnessForkWorkflow: boolean;
  harnessLiveHandoffProof: Nullable<WorkflowHarnessLiveHandoffProof>;
  harnessPromotionClusters: WorkflowHarnessPromotionCluster[];
  harnessReadOnlyRoutingNodeKinds: WorkflowHarnessComponentKind[];
  harnessReadOnlyRoutingProof: WorkflowSettingsHarnessReadOnlyRoutingProof | null;
  harnessReadOnlyRoutingReady: boolean;
  harnessReadOnlyRoutingRequiredScenarios: string[];
  harnessRoutingModelNodeAuthorityGate: Nullable<WorkflowHarnessRoutingModelNodeAuthorityGate>;
  harnessRuntimeSelectorDecision: Nullable<WorkflowHarnessRuntimeSelectorDecision>;
  harnessSelectorLivePromotionReadinessBlockers: string[];
  harnessSelectorLivePromotionReadinessProof: Nullable<WorkflowHarnessLivePromotionReadinessProof>;
  harnessSelectorLivePromotionReadinessReady: boolean;
  harnessSlots: WorkflowHarnessSlotSpec[];
  harnessVerificationOutputNodeAuthorityGate: Nullable<WorkflowHarnessVerificationOutputNodeAuthorityGate>;
}

export interface WorkflowSettingsHarnessCallbacks {
  onApplyActiveRuntimeRollback?: () => void;
  onApplyHarnessActivationCandidate?: () => void;
  onCheckActivationReadiness?: () => void;
  onCopyHarnessDeepLink?: (
    target?: WorkflowHarnessWorkbenchDeepLinkTarget,
  ) => void;
  onExecuteHarnessRollback?: () => void;
  onInspectNode: (nodeId: string) => void;
  onResolveIssue: (issue: WorkflowValidationIssue) => void;
  onRunActiveRuntimeRollbackDryRun?: () => void;
  onRunHarnessActivationDryRun?: () => void;
  onRunHarnessRollbackDrill?: () => void;
  onSelectHarnessReceiptRef?: (receiptRef: string) => void;
  onSelectHarnessReplayFixtureRef?: (replayFixtureRef: string) => void;
  onSelectHarnessRollbackTarget?: (rollbackTarget: string) => void;
  onSelectProposal: (proposal: WorkflowProposal) => void;
}

export interface WorkflowSettingsHarnessPanelProps
  extends WorkflowSettingsHarnessActivationProps,
    WorkflowSettingsHarnessPackageRestoreProps,
    WorkflowSettingsHarnessRollbackProps,
    WorkflowSettingsHarnessWorkerBindingProps,
    WorkflowSettingsHarnessPromotionProps,
    WorkflowSettingsHarnessCallbacks {
  model: WorkflowSettingsHarnessModel;
  harnessWorkflow: boolean;
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessPanel({
  model,
  activationGateProposal,
  blessedHarnessWorkflow,
  boundHarnessSlotIds,
  firstHarnessActivationBlocker,
  harnessActivationAudit,
  harnessActivationAuditReceiptRefs,
  harnessActivationBlockers,
  harnessActivationCandidate,
  harnessActivationGateActions,
  harnessActivationGateNodeAttempts,
  harnessActivationReady,
  harnessActivationRecord,
  harnessActivationRollbackExecution,
  harnessActivationRollbackProof,
  harnessActivationWizardSteps,
  harnessActivationWorkerHandoffNodeAttemptIds,
  harnessActivationWorkerHandoffNodeAttempts,
  harnessActivationWorkerHandoffReplayFixtureRefs,
  harnessActivationWorkerHandoffTimelineReady,
  harnessActivationWorkerInvariantBlockers,
  harnessActivationWorkerInvariantReady,
  harnessActivationWorkerRequiredInvariantIds,
  harnessActiveRuntimeBinding,
  harnessActiveRuntimeRollbackApplyBlockers,
  harnessActiveRuntimeRollbackApplyDisabled,
  harnessActiveRuntimeRollbackApplyProof,
  harnessActiveRuntimeRollbackDryRunPassed,
  harnessActiveRuntimeRollbackExecutionProof,
  harnessActiveRuntimeRollbackProofBindingBlockers,
  harnessActiveRuntimeRollbackProofStillBound,
  harnessAuthorityGateLiveProofs,
  harnessAuthorityGateLiveReady,
  harnessAuthorityGateReadyCount,
  harnessAuthorityToolingNodeAuthorityGate,
  harnessAuthorityToolingProof,
  harnessBindingInspectorStatus,
  harnessBindingRollbackAvailable,
  harnessBindingRollbackHash,
  harnessBindingRollbackTargets,
  harnessBindingVersionEntries,
  harnessCanaryExecutionBoundaries,
  harnessCandidateRevisionBinding,
  harnessCandidateRevisionBindingRef,
  harnessCandidateWorkerBinding,
  harnessCognitionNodeAuthorityGate,
  harnessCurrentWorkerBinding,
  harnessDefaultRuntimeDispatchProof,
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds,
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds,
  harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound,
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds,
  harnessForkComponentDiffRows,
  harnessForkComponentDiffStats,
  harnessForkMutationCanary,
  harnessForkMutationCanaryNodeAttemptIds,
  harnessForkWorkflow,
  harnessLiveHandoffProof,
  harnessPackageDeepLinks,
  harnessPackageEvidenceBlockerCount,
  harnessPackageEvidenceReady,
  harnessPackageEvidenceRefValues,
  harnessPackageEvidenceReviewRows,
  harnessPackageForkMutationCanary,
  harnessPackageForkMutationCanaryNodeAttemptIds,
  harnessPackageForkMutationCanaryReceiptRefs,
  harnessPackageForkMutationCanaryReplayFixtureRefs,
  harnessPackageManifest,
  harnessPackageReceiptRefValues,
  harnessPackageReplayFixtureRefValues,
  harnessPackageRollbackRestoreReceiptRefs,
  harnessPackageWorkerHandoffNodeAttemptIds,
  harnessPackageWorkerHandoffReceiptIds,
  harnessPromotionClusters,
  harnessReadOnlyRoutingNodeKinds,
  harnessReadOnlyRoutingProof,
  harnessReadOnlyRoutingReady,
  harnessReadOnlyRoutingRequiredScenarios,
  harnessRevisionBinding,
  harnessRevisionBindingRef,
  harnessRollbackDrillReceiptRefs,
  harnessRollbackExecutionReceiptRefs,
  harnessRollbackRevisionBinding,
  harnessRollbackRevisionBindingRef,
  harnessRoutingModelNodeAuthorityGate,
  harnessRuntimeSelectorDecision,
  harnessSelectedRollbackTarget,
  harnessSelectorLivePromotionReadinessBlockers,
  harnessSelectorLivePromotionReadinessProof,
  harnessSelectorLivePromotionReadinessReady,
  harnessSlots,
  harnessVerificationOutputNodeAuthorityGate,
  harnessWorkerBinding,
  harnessWorkflow,
  latestHarnessActivationAudit,
  latestHarnessActivationAuditReceiptRefs,
  onApplyActiveRuntimeRollback,
  onApplyHarnessActivationCandidate,
  onCheckActivationReadiness,
  onCopyHarnessDeepLink,
  onExecuteHarnessRollback,
  onInspectNode,
  onResolveIssue,
  onRunActiveRuntimeRollbackDryRun,
  onRunHarnessActivationDryRun,
  onRunHarnessRollbackDrill,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onSelectHarnessRollbackTarget,
  onSelectProposal,
  packageImportActivationEnabled,
  packageImportActivationHandoff,
  packageImportHandoffWorkerBindingId,
  packageImportReplayIntegrityBlockers,
  packageImportReview,
  rollbackReady,
  selectedHarnessActivationAuditEventId,
  selectedHarnessActivationBlockerIndex,
  selectedHarnessActivationBlockerRef,
  selectedHarnessActivationGateEvidenceRef,
  selectedHarnessActivationGateId,
  selectedHarnessActivationGateInspection,
  selectedHarnessActivationGateMutationCanary,
  selectedHarnessActivationGateNodeAttempt,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  selectedHarnessCanaryBoundary,
  selectedHarnessDefaultDispatchId,
  selectedHarnessNodeAttemptId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  selectedHarnessRevisionBindingKind,
  selectedHarnessRevisionBindingRef,
  selectedHarnessRollbackDrillId,
  selectedHarnessRollbackRestoreCanaryId,
  selectedHarnessRollbackRestoreReceiptRef,
  selectedHarnessRollbackTarget,
  selectedHarnessSelectorDecisionId,
  selectedHarnessWorkerBindingId,
  workflow,
}: WorkflowSettingsHarnessPanelProps) {
  const renderHarnessAuthorityGateProofRows = (
    gates: WorkflowHarnessAuthorityGateProofView[],
    options: {
      listTestId: string;
      gateTestIdPrefix: string;
    },
  ) => (
    <div
      className="workflow-rail-list workflow-harness-authority-gate-list"
      data-testid={options.listTestId}
    >
      {gates.map((gate) => {
        const receiptRef = gate.receiptIds[0] ?? null;
        const replayFixtureRef = gate.replayFixtureRefs[0] ?? null;
        return (
          <article
            key={gate.id}
            className={`workflow-test-row workflow-harness-authority-gate-row is-${
              gate.ready ? "passed" : "blocked"
            }`}
            data-testid={`${options.gateTestIdPrefix}-${gate.id}`}
            data-component-kind={gate.componentKind}
            data-authority-gate-status={gate.status}
          >
            <strong>{gate.label}</strong>
            <span>
              {gate.componentKind} · {gate.status} · {gate.attemptIds.length}{" "}
              attempts
            </span>
            <small>{gate.policyDecision}</small>
            <small
              data-testid={`${options.gateTestIdPrefix}-deep-links-${gate.id}`}
            >
              component {gate.componentId} · run {gate.runId} · replay{" "}
              {replayFixtureRef ?? "pending"} · panel {gate.selectedPanel}
            </small>
            <small>blocker {gate.blockerState}</small>
            <div className="workflow-harness-authority-gate-actions">
              <button
                type="button"
                className="workflow-harness-ref-button"
                data-testid={`${options.gateTestIdPrefix}-component-${gate.id}`}
                disabled={!gate.node}
                onClick={() => gate.node && onInspectNode(gate.node.id)}
              >
                <code>{gate.componentId}</code>
              </button>
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  receiptRef && selectedHarnessReceiptRef === receiptRef
                    ? "is-active"
                    : ""
                }`}
                data-testid={`${options.gateTestIdPrefix}-receipt-${gate.id}`}
                disabled={!receiptRef}
                onClick={() =>
                  receiptRef && onSelectHarnessReceiptRef?.(receiptRef)
                }
              >
                <code>{receiptRef ?? "receipt pending"}</code>
              </button>
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  replayFixtureRef &&
                  selectedHarnessReplayFixtureRef === replayFixtureRef
                    ? "is-active"
                    : ""
                }`}
                data-testid={`${options.gateTestIdPrefix}-replay-${gate.id}`}
                disabled={!replayFixtureRef}
                onClick={() =>
                  replayFixtureRef &&
                  onSelectHarnessReplayFixtureRef?.(replayFixtureRef)
                }
              >
                <code>{replayFixtureRef ?? "replay pending"}</code>
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );

  return harnessWorkflow ? (
          <section
            className="workflow-rail-section"
            data-testid="workflow-settings-harness-summary"
          >
            <h4>Harness</h4>
            <dl className="workflow-rail-stats">
              <div>
                <dt>Template</dt>
                <dd>{model.templateLabel}</dd>
              </div>
              <div>
                <dt>Activation</dt>
                <dd>
                  {model.activationLabel}
                </dd>
              </div>
              <div>
                <dt>Mode</dt>
                <dd>
                  {model.modeLabel}
                </dd>
              </div>
              <div>
                <dt>Components</dt>
                <dd>{model.componentCount}</dd>
              </div>
              <div>
                <dt>Live-ready</dt>
                <dd>
                  {model.liveReadyLabel}
                </dd>
              </div>
              <div>
                <dt>Gated clusters</dt>
                <dd>{model.gatedClustersLabel}</dd>
              </div>
              <div data-testid="workflow-harness-authority-gate-status">
                <dt>Authority gates</dt>
                <dd>
                  {harnessAuthorityGateReadyCount}/
                  {harnessAuthorityGateLiveProofs.length}
                </dd>
              </div>
              <div>
                <dt>Slots</dt>
                <dd>
                  {
                    harnessSlots.filter((slot) =>
                      boundHarnessSlotIds.has(slot.slotId),
                    ).length
                  }
                  /{harnessSlots.length}
                </dd>
              </div>
            </dl>
            <WorkflowSettingsHarnessWorkerBindingPanel
              harnessActivationAudit={harnessActivationAudit}
              harnessActivationAuditReceiptRefs={harnessActivationAuditReceiptRefs}
              harnessActivationCandidate={harnessActivationCandidate}
              harnessActivationRecord={harnessActivationRecord}
              harnessActivationRollbackExecution={harnessActivationRollbackExecution}
              harnessActivationRollbackProof={harnessActivationRollbackProof}
              latestHarnessActivationAudit={latestHarnessActivationAudit}
              latestHarnessActivationAuditReceiptRefs={latestHarnessActivationAuditReceiptRefs}
              selectedHarnessActivationAuditEventId={selectedHarnessActivationAuditEventId}
              harnessActiveRuntimeBinding={harnessActiveRuntimeBinding}
              harnessActiveRuntimeRollbackApplyBlockers={harnessActiveRuntimeRollbackApplyBlockers}
              harnessActiveRuntimeRollbackApplyDisabled={harnessActiveRuntimeRollbackApplyDisabled}
              harnessActiveRuntimeRollbackApplyProof={harnessActiveRuntimeRollbackApplyProof}
              harnessActiveRuntimeRollbackDryRunPassed={harnessActiveRuntimeRollbackDryRunPassed}
              harnessActiveRuntimeRollbackExecutionProof={harnessActiveRuntimeRollbackExecutionProof}
              harnessActiveRuntimeRollbackProofBindingBlockers={harnessActiveRuntimeRollbackProofBindingBlockers}
              harnessActiveRuntimeRollbackProofStillBound={harnessActiveRuntimeRollbackProofStillBound}
              harnessBindingRollbackAvailable={harnessBindingRollbackAvailable}
              harnessBindingRollbackHash={harnessBindingRollbackHash}
              harnessBindingRollbackTargets={harnessBindingRollbackTargets}
              harnessRollbackDrillReceiptRefs={harnessRollbackDrillReceiptRefs}
              harnessRollbackExecutionReceiptRefs={harnessRollbackExecutionReceiptRefs}
              harnessRollbackRevisionBinding={harnessRollbackRevisionBinding}
              harnessRollbackRevisionBindingRef={harnessRollbackRevisionBindingRef}
              harnessSelectedRollbackTarget={harnessSelectedRollbackTarget}
              selectedHarnessRollbackTarget={selectedHarnessRollbackTarget}
              harnessBindingInspectorStatus={harnessBindingInspectorStatus}
              harnessBindingVersionEntries={harnessBindingVersionEntries}
              harnessCandidateRevisionBinding={harnessCandidateRevisionBinding}
              harnessCandidateRevisionBindingRef={harnessCandidateRevisionBindingRef}
              harnessCandidateWorkerBinding={harnessCandidateWorkerBinding}
              harnessCurrentWorkerBinding={harnessCurrentWorkerBinding}
              harnessRevisionBinding={harnessRevisionBinding}
              harnessRevisionBindingRef={harnessRevisionBindingRef}
              harnessWorkerBinding={harnessWorkerBinding}
              selectedHarnessDefaultDispatchId={selectedHarnessDefaultDispatchId}
              selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
              selectedHarnessReceiptRef={selectedHarnessReceiptRef}
              selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
              selectedHarnessRevisionBindingKind={selectedHarnessRevisionBindingKind}
              selectedHarnessRevisionBindingRef={selectedHarnessRevisionBindingRef}
              selectedHarnessSelectorDecisionId={selectedHarnessSelectorDecisionId}
              selectedHarnessWorkerBindingId={selectedHarnessWorkerBindingId}
              harnessForkWorkflow={harnessForkWorkflow}
              onApplyActiveRuntimeRollback={onApplyActiveRuntimeRollback}
              onApplyHarnessActivationCandidate={onApplyHarnessActivationCandidate}
              onCheckActivationReadiness={onCheckActivationReadiness}
              onCopyHarnessDeepLink={onCopyHarnessDeepLink}
              onExecuteHarnessRollback={onExecuteHarnessRollback}
              onRunActiveRuntimeRollbackDryRun={onRunActiveRuntimeRollbackDryRun}
              onRunHarnessActivationDryRun={onRunHarnessActivationDryRun}
              onRunHarnessRollbackDrill={onRunHarnessRollbackDrill}
              onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
              onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
              onSelectHarnessRollbackTarget={onSelectHarnessRollbackTarget}
              workflow={workflow}
            />
            <WorkflowSettingsHarnessActivationPanel
              activationGateProposal={activationGateProposal}
              blessedHarnessWorkflow={blessedHarnessWorkflow}
              firstHarnessActivationBlocker={firstHarnessActivationBlocker}
              harnessActivationBlockers={harnessActivationBlockers}
              harnessActivationCandidate={harnessActivationCandidate}
              harnessActivationGateActions={harnessActivationGateActions}
              harnessActivationGateNodeAttempts={harnessActivationGateNodeAttempts}
              harnessActivationReady={harnessActivationReady}
              harnessActivationRecord={harnessActivationRecord}
              harnessActivationWizardSteps={harnessActivationWizardSteps}
              harnessActivationWorkerHandoffNodeAttemptIds={harnessActivationWorkerHandoffNodeAttemptIds}
              harnessActivationWorkerHandoffNodeAttempts={harnessActivationWorkerHandoffNodeAttempts}
              harnessActivationWorkerHandoffReplayFixtureRefs={harnessActivationWorkerHandoffReplayFixtureRefs}
              harnessActivationWorkerHandoffTimelineReady={harnessActivationWorkerHandoffTimelineReady}
              harnessActivationWorkerInvariantBlockers={harnessActivationWorkerInvariantBlockers}
              harnessActivationWorkerInvariantReady={harnessActivationWorkerInvariantReady}
              harnessActivationWorkerRequiredInvariantIds={harnessActivationWorkerRequiredInvariantIds}
              packageImportActivationEnabled={packageImportActivationEnabled}
              packageImportActivationHandoff={packageImportActivationHandoff}
              packageImportHandoffWorkerBindingId={packageImportHandoffWorkerBindingId}
              packageImportReplayIntegrityBlockers={packageImportReplayIntegrityBlockers}
              packageImportReview={packageImportReview}
              selectedHarnessActivationGateEvidenceRef={selectedHarnessActivationGateEvidenceRef}
              selectedHarnessActivationGateId={selectedHarnessActivationGateId}
              selectedHarnessActivationGateInspection={selectedHarnessActivationGateInspection}
              selectedHarnessActivationGateMutationCanary={selectedHarnessActivationGateMutationCanary}
              selectedHarnessActivationGateNodeAttempt={selectedHarnessActivationGateNodeAttempt}
              selectedHarnessActivationGateNodeAttemptId={selectedHarnessActivationGateNodeAttemptId}
              selectedHarnessActivationGateReceiptRef={selectedHarnessActivationGateReceiptRef}
              selectedHarnessActivationGateReplayFixtureRef={selectedHarnessActivationGateReplayFixtureRef}
              harnessPackageDeepLinks={harnessPackageDeepLinks}
              harnessPackageEvidenceBlockerCount={harnessPackageEvidenceBlockerCount}
              harnessPackageEvidenceReady={harnessPackageEvidenceReady}
              harnessPackageEvidenceRefValues={harnessPackageEvidenceRefValues}
              harnessPackageEvidenceReviewRows={harnessPackageEvidenceReviewRows}
              harnessPackageForkMutationCanary={harnessPackageForkMutationCanary}
              harnessPackageForkMutationCanaryNodeAttemptIds={harnessPackageForkMutationCanaryNodeAttemptIds}
              harnessPackageForkMutationCanaryReceiptRefs={harnessPackageForkMutationCanaryReceiptRefs}
              harnessPackageForkMutationCanaryReplayFixtureRefs={harnessPackageForkMutationCanaryReplayFixtureRefs}
              harnessPackageManifest={harnessPackageManifest}
              harnessPackageReceiptRefValues={harnessPackageReceiptRefValues}
              harnessPackageReplayFixtureRefValues={harnessPackageReplayFixtureRefValues}
              harnessPackageRollbackRestoreReceiptRefs={harnessPackageRollbackRestoreReceiptRefs}
              harnessPackageWorkerHandoffNodeAttemptIds={harnessPackageWorkerHandoffNodeAttemptIds}
              harnessPackageWorkerHandoffReceiptIds={harnessPackageWorkerHandoffReceiptIds}
              rollbackReady={rollbackReady}
              selectedHarnessCanaryBoundary={selectedHarnessCanaryBoundary}
              selectedHarnessRollbackDrillId={selectedHarnessRollbackDrillId}
              selectedHarnessRollbackRestoreCanaryId={selectedHarnessRollbackRestoreCanaryId}
              selectedHarnessRollbackRestoreReceiptRef={selectedHarnessRollbackRestoreReceiptRef}
              harnessWorkerBinding={harnessWorkerBinding}
              selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
              selectedHarnessReceiptRef={selectedHarnessReceiptRef}
              selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
              harnessForkMutationCanary={harnessForkMutationCanary}
              harnessForkMutationCanaryNodeAttemptIds={harnessForkMutationCanaryNodeAttemptIds}
              harnessForkWorkflow={harnessForkWorkflow}
              onApplyHarnessActivationCandidate={onApplyHarnessActivationCandidate}
              onCheckActivationReadiness={onCheckActivationReadiness}
              onCopyHarnessDeepLink={onCopyHarnessDeepLink}
              onResolveIssue={onResolveIssue}
              onRunHarnessActivationDryRun={onRunHarnessActivationDryRun}
              onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
              onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
              onSelectProposal={onSelectProposal}
              workflow={workflow}
            />
            {harnessLiveHandoffProof ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-live-handoff"
              >
                <strong>{harnessLiveHandoffProof.selector}</strong>
                <span>
                  canary {harnessLiveHandoffProof.canaryStatus} · rollback{" "}
                  {harnessLiveHandoffProof.rollbackAvailable
                    ? "ready"
                    : "blocked"}
                </span>
                <small>
                  default {harnessLiveHandoffProof.productionDefaultSelector} ·{" "}
                  {harnessLiveHandoffProof.runtimeAuthority}
                </small>
              </article>
            ) : null}
            {harnessRuntimeSelectorDecision ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-runtime-selector"
              >
                <strong>
                  {harnessRuntimeSelectorDecision.selectedSelector}
                </strong>
                <span>
                  default{" "}
                  {harnessRuntimeSelectorDecision.productionDefaultSelector} ·{" "}
                  {harnessRuntimeSelectorDecision.executionMode}
                </span>
                <small>{harnessRuntimeSelectorDecision.policyDecision}</small>
              </article>
            ) : null}
            {harnessSelectorLivePromotionReadinessProof ? (
              <article
                className={`workflow-output-row is-${
                  harnessSelectorLivePromotionReadinessReady
                    ? "ready"
                    : "blocked"
                }`}
                data-testid="workflow-harness-selector-live-promotion-readiness"
                data-readiness={
                  harnessSelectorLivePromotionReadinessReady
                    ? "live_ready"
                    : "blocked"
                }
              >
                <strong>
                  selector readiness{" "}
                  {harnessSelectorLivePromotionReadinessReady
                    ? "ready"
                    : "blocked"}
                </strong>
                <span>
                  {
                    harnessSelectorLivePromotionReadinessProof.clusterReadiness
                      .length
                  }{" "}
                  clusters · rollback{" "}
                  {harnessSelectorLivePromotionReadinessProof.rollbackAvailable
                    ? "ready"
                    : "blocked"}
                </span>
                <small>
                  {harnessSelectorLivePromotionReadinessBlockers.length}{" "}
                  blockers ·{" "}
                  {harnessRuntimeSelectorDecision?.livePromotionReadinessPolicyDecision ??
                    harnessSelectorLivePromotionReadinessProof.policyDecision}
                </small>
              </article>
            ) : null}
            {harnessDefaultRuntimeDispatchProof ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-default-runtime-dispatch"
                data-cognition-node-authority-mode={
                  harnessCognitionNodeAuthorityGate?.authorityMode ?? ""
                }
                data-cognition-node-authority-authoritative={
                  harnessCognitionNodeAuthorityGate?.authoritative
                    ? "true"
                    : "false"
                }
                data-cognition-node-authority-policy-decision={
                  harnessCognitionNodeAuthorityGate?.policyDecision ?? ""
                }
                data-cognition-node-authority-blockers={(
                  harnessCognitionNodeAuthorityGate?.blockers ?? []
                ).join(",")}
                data-cognition-node-authority-component-kinds={(
                  harnessCognitionNodeAuthorityGate?.componentKinds ?? []
                ).join(",")}
                data-cognition-node-authority-action-frame-ids={(
                  harnessCognitionNodeAuthorityGate?.actionFrameIds ?? []
                ).join(",")}
                data-cognition-node-authority-attempt-ids={(
                  harnessCognitionNodeAuthorityGate?.attemptIds ?? []
                ).join(",")}
                data-cognition-node-authority-receipt-ids={(
                  harnessCognitionNodeAuthorityGate?.receiptIds ?? []
                ).join(",")}
                data-cognition-node-authority-replay-fixture-refs={(
                  harnessCognitionNodeAuthorityGate?.replayFixtureRefs ?? []
                ).join(",")}
                data-routing-model-node-authority-mode={
                  harnessRoutingModelNodeAuthorityGate?.authorityMode ?? ""
                }
                data-routing-model-node-authority-authoritative={
                  harnessRoutingModelNodeAuthorityGate?.authoritative
                    ? "true"
                    : "false"
                }
                data-routing-model-node-authority-policy-decision={
                  harnessRoutingModelNodeAuthorityGate?.policyDecision ?? ""
                }
                data-routing-model-node-authority-visible-output-authority={
                  harnessRoutingModelNodeAuthorityGate?.visibleOutputAuthority ??
                  ""
                }
                data-routing-model-node-authority-blockers={(
                  harnessRoutingModelNodeAuthorityGate?.blockers ?? []
                ).join(",")}
                data-routing-model-node-authority-component-kinds={(
                  harnessRoutingModelNodeAuthorityGate?.componentKinds ?? []
                ).join(",")}
                data-routing-model-node-authority-action-frame-ids={(
                  harnessRoutingModelNodeAuthorityGate?.actionFrameIds ?? []
                ).join(",")}
                data-routing-model-node-authority-attempt-ids={(
                  harnessRoutingModelNodeAuthorityGate?.attemptIds ?? []
                ).join(",")}
                data-routing-model-node-authority-receipt-ids={(
                  harnessRoutingModelNodeAuthorityGate?.receiptIds ?? []
                ).join(",")}
                data-routing-model-node-authority-replay-fixture-refs={(
                  harnessRoutingModelNodeAuthorityGate?.replayFixtureRefs ?? []
                ).join(",")}
                data-verification-output-node-authority-mode={
                  harnessVerificationOutputNodeAuthorityGate?.authorityMode ??
                  ""
                }
                data-verification-output-node-authority-authoritative={
                  harnessVerificationOutputNodeAuthorityGate?.authoritative
                    ? "true"
                    : "false"
                }
                data-verification-output-node-authority-policy-decision={
                  harnessVerificationOutputNodeAuthorityGate?.policyDecision ??
                  ""
                }
                data-verification-output-node-authority-visible-write-committed={
                  harnessVerificationOutputNodeAuthorityGate?.outputWriterVisibleWriteCommitted
                    ? "true"
                    : "false"
                }
                data-verification-output-node-authority-blockers={(
                  harnessVerificationOutputNodeAuthorityGate?.blockers ?? []
                ).join(",")}
                data-verification-output-node-authority-component-kinds={(
                  harnessVerificationOutputNodeAuthorityGate?.componentKinds ??
                  []
                ).join(",")}
                data-verification-output-node-authority-action-frame-ids={(
                  harnessVerificationOutputNodeAuthorityGate?.actionFrameIds ??
                  []
                ).join(",")}
                data-verification-output-node-authority-attempt-ids={(
                  harnessVerificationOutputNodeAuthorityGate?.attemptIds ?? []
                ).join(",")}
                data-verification-output-node-authority-receipt-ids={(
                  harnessVerificationOutputNodeAuthorityGate?.receiptIds ?? []
                ).join(",")}
                data-verification-output-node-authority-replay-fixture-refs={(
                  harnessVerificationOutputNodeAuthorityGate?.replayFixtureRefs ??
                  []
                ).join(",")}
                data-authority-tooling-node-authority-mode={
                  harnessAuthorityToolingNodeAuthorityGate?.authorityMode ?? ""
                }
                data-authority-tooling-node-authority-authoritative={
                  harnessAuthorityToolingNodeAuthorityGate?.authoritative
                    ? "true"
                    : "false"
                }
                data-authority-tooling-node-authority-policy-decision={
                  harnessAuthorityToolingNodeAuthorityGate?.policyDecision ?? ""
                }
                data-authority-tooling-node-authority-read-only-route-accepted={
                  harnessAuthorityToolingNodeAuthorityGate?.readOnlyRouteAccepted
                    ? "true"
                    : "false"
                }
                data-authority-tooling-node-authority-destructive-route-denied={
                  harnessAuthorityToolingNodeAuthorityGate?.destructiveRouteDenied
                    ? "true"
                    : "false"
                }
                data-authority-tooling-node-authority-side-effects-executed={
                  harnessAuthorityToolingNodeAuthorityGate?.sideEffectsExecuted
                    ? "true"
                    : "false"
                }
                data-authority-tooling-node-authority-blockers={(
                  harnessAuthorityToolingNodeAuthorityGate?.blockers ?? []
                ).join(",")}
                data-authority-tooling-node-authority-component-kinds={(
                  harnessAuthorityToolingNodeAuthorityGate?.componentKinds ?? []
                ).join(",")}
                data-authority-tooling-node-authority-action-frame-ids={(
                  harnessAuthorityToolingNodeAuthorityGate?.actionFrameIds ?? []
                ).join(",")}
                data-authority-tooling-node-authority-attempt-ids={(
                  harnessAuthorityToolingNodeAuthorityGate?.attemptIds ?? []
                ).join(",")}
                data-authority-tooling-node-authority-receipt-ids={(
                  harnessAuthorityToolingNodeAuthorityGate?.receiptIds ?? []
                ).join(",")}
                data-authority-tooling-node-authority-replay-fixture-refs={(
                  harnessAuthorityToolingNodeAuthorityGate?.replayFixtureRefs ??
                  []
                ).join(",")}
                data-worker-attach-lifecycle-complete={
                  harnessDefaultRuntimeDispatchProof.workerAttachLifecycleComplete
                    ? "true"
                    : "false"
                }
                data-worker-attach-lifecycle-statuses={(
                  harnessDefaultRuntimeDispatchProof.workerAttachLifecycleStatuses ??
                  []
                ).join(",")}
                data-worker-session-record-id={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.sessionRecordId ?? ""
                }
                data-worker-session-status={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.currentStatus ?? ""
                }
                data-worker-session-persistence-key={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.persistenceKey ?? ""
                }
                data-worker-session-record-persistence-key={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.recordPersistenceKey ?? ""
                }
                data-worker-session-persisted={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.persistedInRuntimeCheckpoint
                    ? "true"
                    : "false"
                }
                data-worker-session-restored={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.restoredFromPersistedSession
                    ? "true"
                    : "false"
                }
                data-worker-session-checkpoint-source={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.runtimeCheckpointSource ?? ""
                }
                data-worker-session-launch-authority-ready={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.launchAuthorityReady
                    ? "true"
                    : "false"
                }
                data-worker-session-launch-authority-source={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.launchAuthoritySource ?? ""
                }
                data-worker-launch-reviewed-import-invariant-bound={
                  harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound
                    ? "true"
                    : "false"
                }
                data-worker-session-launch-authority-invariant-ids={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds.join(
                  ",",
                )}
                data-worker-session-launch-authority-invariant-blockers={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers.join(
                  ",",
                )}
                data-worker-session-rollback-handoff-ready={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.rollbackHandoffReady
                    ? "true"
                    : "false"
                }
                data-worker-session-rollback-handoff-target={
                  harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.rollbackHandoffTarget ?? ""
                }
                data-worker-launch-envelope-count={
                  (
                    harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopes ??
                    []
                  ).length
                }
                data-worker-launch-envelope-ids={(
                  harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopeIds ??
                  []
                ).join(",")}
                data-worker-launch-envelope-invariant-ids={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds.join(
                  ",",
                )}
                data-worker-launch-envelope-invariant-blockers={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers.join(
                  ",",
                )}
                data-worker-handoff-receipt-count={
                  (
                    harnessDefaultRuntimeDispatchProof.workerHandoffReceipts ??
                    []
                  ).length
                }
                data-worker-handoff-receipt-ids={(
                  harnessDefaultRuntimeDispatchProof.workerHandoffReceiptIds ??
                  []
                ).join(",")}
                data-worker-handoff-receipt-invariant-ids={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds.join(
                  ",",
                )}
                data-worker-handoff-receipt-invariant-blockers={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers.join(
                  ",",
                )}
                data-worker-rollback-handoff-receipt-status={
                  harnessDefaultRuntimeDispatchProof.workerHandoffReceipts?.find(
                    (receipt) => receipt.phase === "rollback",
                  )?.handoffStatus ?? ""
                }
              >
                <strong>
                  {harnessDefaultRuntimeDispatchProof.selectedSelector}
                </strong>
                <span>
                  {harnessDefaultRuntimeDispatchProof.executionMode} ·{" "}
                  {harnessDefaultRuntimeDispatchProof.outputWriterStatus}
                </span>
                <small>
                  {harnessDefaultRuntimeDispatchProof.acceptedClusterIds.length}{" "}
                  clusters ·{" "}
                  {
                    harnessDefaultRuntimeDispatchProof.dispatchNodeAttemptIds
                      .length
                  }{" "}
                  attempts
                </small>
                <small>
                  cognition{" "}
                  {harnessCognitionNodeAuthorityGate?.authoritative
                    ? "node authoritative"
                    : "authority blocked"}{" "}
                  ·{" "}
                  {harnessCognitionNodeAuthorityGate?.componentKinds.length ??
                    0}{" "}
                  nodes
                </small>
                <small>
                  routing/model{" "}
                  {harnessRoutingModelNodeAuthorityGate?.authoritative
                    ? "gated node authority"
                    : "authority blocked"}{" "}
                  ·{" "}
                  {harnessRoutingModelNodeAuthorityGate?.componentKinds.length ??
                    0}{" "}
                  nodes
                </small>
                <small>
                  verification/output{" "}
                  {harnessVerificationOutputNodeAuthorityGate?.authoritative
                    ? "gated node authority"
                    : "authority blocked"}{" "}
                  ·{" "}
                  {harnessVerificationOutputNodeAuthorityGate?.componentKinds
                    .length ?? 0}{" "}
                  nodes
                </small>
                <small>
                  authority/tooling{" "}
                  {harnessAuthorityToolingNodeAuthorityGate?.authoritative
                    ? "gated node authority"
                    : "authority blocked"}{" "}
                  ·{" "}
                  {harnessAuthorityToolingNodeAuthorityGate?.componentKinds
                    .length ?? 0}{" "}
                  nodes
                </small>
                <small>
                  worker lifecycle{" "}
                  {(
                    harnessDefaultRuntimeDispatchProof.workerAttachLifecycleStatuses ??
                    []
                  ).join(" / ") || "missing"}
                </small>
                <small>
                  worker session{" "}
                  {harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.currentStatus ?? "missing"}
                </small>
                <small>
                  worker checkpoint{" "}
                  {harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.persistedInRuntimeCheckpoint
                    ? "persisted"
                    : "missing"}{" "}
                  /{" "}
                  {harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.restoredFromPersistedSession
                    ? "restored"
                    : "not restored"}
                </small>
                <small>
                  launch{" "}
                  {harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.launchAuthorityReady
                    ? "authoritative"
                    : "blocked"}{" "}
                  / rollback{" "}
                  {harnessDefaultRuntimeDispatchProof.workerSessionRecord
                    ?.rollbackHandoffReady
                    ? "handoff ready"
                    : "handoff blocked"}
                </small>
                <small>
                  launch invariant{" "}
                  {
                    DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT
                  }{" "}
                  ·{" "}
                  {harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound
                    ? "bound"
                    : "blocked"}
                </small>
                <small>
                  envelopes{" "}
                  {
                    (
                      harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopes ??
                      []
                    ).length
                  }{" "}
                  · handoff receipts{" "}
                  {
                    (
                      harnessDefaultRuntimeDispatchProof.workerHandoffReceipts ??
                      []
                    ).length
                  }
                </small>
              </article>
            ) : null}
            {harnessDefaultRuntimeDispatchProof ? (
              <section
                className="workflow-rail-section workflow-harness-authority-gates"
                data-testid="workflow-harness-authority-gate-live"
              >
                <h4>Authority tooling gates</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-authority-gate-summary"
                >
                  <div>
                    <dt>Ready</dt>
                    <dd>
                      {harnessAuthorityGateReadyCount}/
                      {harnessAuthorityGateLiveProofs.length}
                    </dd>
                  </div>
                  <div>
                    <dt>Receipts</dt>
                    <dd>
                      {
                        harnessDefaultRuntimeDispatchProof
                          .authorityToolingGateLiveReceiptIds.length
                      }
                    </dd>
                  </div>
                  <div>
                    <dt>Replay</dt>
                    <dd>
                      {
                        harnessDefaultRuntimeDispatchProof
                          .authorityToolingGateLiveReplayFixtureRefs.length
                      }
                    </dd>
                  </div>
                  <div>
                    <dt>Status</dt>
                    <dd>
                      {harnessAuthorityGateLiveReady ? "live" : "blocked"}
                    </dd>
                  </div>
                </dl>
                <article
                  className={`workflow-output-row is-${
                    harnessAuthorityGateLiveReady ? "ready" : "blocked"
                  }`}
                  data-testid="workflow-harness-authority-gate-rollup"
                >
                  <strong>
                    {workflowProofString(
                      harnessAuthorityToolingProof,
                      "policyDecision",
                      "authority gate proof pending",
                    )}
                  </strong>
                  <span>
                    destructive denied{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveRouteDenied
                      ? "yes"
                      : "review"}{" "}
                    · approvals blocked{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingMutatingToolCallsBlocked
                      ? "yes"
                      : "review"}
                  </span>
                  <small>
                    side effects{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingSideEffectsExecuted
                      ? "executed"
                      : "not executed"}{" "}
                    · rollback{" "}
                    {harnessDefaultRuntimeDispatchProof.authorityToolingRollbackAvailable
                      ? "ready"
                      : "blocked"}
                  </small>
                </article>
                {renderHarnessAuthorityGateProofRows(
                  harnessAuthorityGateLiveProofs,
                  {
                    listTestId: "workflow-harness-authority-gate-list",
                    gateTestIdPrefix: "workflow-harness-authority-gate",
                  },
                )}
              </section>
            ) : null}
            {harnessReadOnlyRoutingProof ? (
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-read-only-routing-proof"
              >
                <h4>Read-only routing</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-read-only-routing-summary"
                >
                  <div>
                    <dt>Mode</dt>
                    <dd>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingMode ??
                        String(harnessReadOnlyRoutingProof.mode ?? "unknown")}
                    </dd>
                  </div>
                  <div>
                    <dt>Scenario</dt>
                    <dd>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenario ??
                        String(
                          harnessReadOnlyRoutingProof.scenario ?? "pending",
                        )}
                    </dd>
                  </div>
                  <div>
                    <dt>Nodes</dt>
                    <dd>{harnessReadOnlyRoutingNodeKinds.length}</dd>
                  </div>
                  <div>
                    <dt>Mutation</dt>
                    <dd>
                      {harnessReadOnlyRoutingReady ? "blocked" : "review"}
                    </dd>
                  </div>
                </dl>
                <article
                  className="workflow-output-row"
                  data-testid="workflow-harness-read-only-routing-no-mutation"
                >
                  <strong>
                    {harnessReadOnlyRoutingReady
                      ? "No mutation proof ready"
                      : "No mutation proof incomplete"}
                  </strong>
                  <span>
                    side effects{" "}
                    {harnessReadOnlyRoutingProof.sideEffectsExecuted === false
                      ? "not executed"
                      : "review"}{" "}
                    · mutation{" "}
                    {harnessReadOnlyRoutingProof.mutationExecuted === false
                      ? "not executed"
                      : "review"}
                  </span>
                  <small>
                    source material{" "}
                    {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSourceMaterialReady
                      ? "ready"
                      : "pending"}{" "}
                    · rollback{" "}
                    {harnessReadOnlyRoutingProof.rollbackAvailable
                      ? "ready"
                      : "blocked"}
                  </small>
                </article>
                <div
                  className="workflow-rail-list"
                  data-testid="workflow-harness-read-only-routing-node-kinds"
                >
                  {harnessReadOnlyRoutingNodeKinds.map((kind) => {
                    const nodeItem = workflow.nodes.find(
                      (candidate) =>
                        candidate.runtimeBinding?.componentKind === kind,
                    );
                    return (
                      <button
                        key={kind}
                        type="button"
                        className="workflow-search-result is-ready"
                        data-testid={`workflow-harness-read-only-routing-node-${kind}`}
                        disabled={!nodeItem}
                        onClick={() => nodeItem && onInspectNode(nodeItem.id)}
                      >
                        <strong>{nodeItem?.name ?? kind}</strong>
                        <span>{kind} · workflow-owned</span>
                        <small>
                          {nodeItem?.runtimeBinding?.readiness ??
                            "binding pending"}
                        </small>
                      </button>
                    );
                  })}
                </div>
                <div
                  className="workflow-rail-list"
                  data-testid="workflow-harness-read-only-routing-receipts"
                >
                  <article className="workflow-output-row">
                    <strong>Attempts</strong>
                    <span>
                      {harnessDefaultRuntimeDispatchProof
                        ?.readOnlyCapabilityRoutingAttemptIds.length ?? 0}{" "}
                      node attempts
                    </span>
                    <small>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingAttemptIds
                        .slice(0, 2)
                        .join(", ") ?? "pending"}
                    </small>
                  </article>
                  <article className="workflow-output-row">
                    <strong>Receipts</strong>
                    <span>
                      {harnessDefaultRuntimeDispatchProof
                        ?.readOnlyCapabilityRoutingReceiptIds.length ?? 0}{" "}
                      receipt refs
                    </span>
                    <small>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReceiptIds
                        .slice(0, 2)
                        .join(", ") ?? "pending"}
                    </small>
                  </article>
                  <article className="workflow-output-row">
                    <strong>Replay fixtures</strong>
                    <span>
                      {harnessDefaultRuntimeDispatchProof
                        ?.readOnlyCapabilityRoutingReplayFixtureRefs.length ??
                        0}{" "}
                      fixture refs
                    </span>
                    <small>
                      {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReplayFixtureRefs
                        .slice(0, 2)
                        .join(", ") ?? "pending"}
                    </small>
                  </article>
                </div>
                {harnessReadOnlyRoutingRequiredScenarios.length > 0 ? (
                  <div
                    className="workflow-rail-list"
                    data-testid="workflow-harness-read-only-routing-scenarios"
                  >
                    {harnessReadOnlyRoutingRequiredScenarios.map((scenario) => (
                      <article
                        key={scenario}
                        className={`workflow-test-row is-${
                          scenario ===
                          harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey
                            ? "passed"
                            : "idle"
                        }`}
                      >
                        <strong>{scenario}</strong>
                        <span>
                          {scenario ===
                          harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey
                            ? "current coverage key"
                            : "retained requirement"}
                        </span>
                      </article>
                    ))}
                  </div>
                ) : null}
              </section>
            ) : null}
            {harnessCanaryExecutionBoundaries.length > 0 ? (
              <div
                className="workflow-rail-list"
                data-testid="workflow-harness-canary-execution-boundaries"
                data-selected-canary-boundary-id={
                  selectedHarnessCanaryBoundary?.boundaryId ?? ""
                }
                data-selected-rollback-drill-id={selectedHarnessRollbackDrillId}
                data-selected-canary-receipt-ref={
                  selectedHarnessActivationGateReceiptRef ??
                  selectedHarnessReceiptRef ??
                  ""
                }
                data-selected-canary-replay-fixture-ref={
                  selectedHarnessActivationGateReplayFixtureRef ??
                  selectedHarnessReplayFixtureRef ??
                  ""
                }
                data-canary-boundary-count={
                  harnessCanaryExecutionBoundaries.length
                }
                data-rollback-drill-count={
                  harnessCanaryExecutionBoundaries.filter(
                    (boundary) => boundary.rollbackDrill.drillStatus,
                  ).length
                }
              >
                {harnessCanaryExecutionBoundaries.map((boundary) => (
                  <article
                    key={boundary.boundaryId}
                    className={`workflow-output-row ${
                      selectedHarnessCanaryBoundary?.boundaryId ===
                      boundary.boundaryId
                        ? "is-active"
                        : ""
                    }`}
                    data-testid="workflow-harness-canary-execution-boundary"
                    data-canary-boundary-id={boundary.boundaryId}
                    data-rollback-drill-id={boundary.rollbackDrill.drillId}
                    data-receipt-refs={boundary.receiptIds.join("|")}
                    data-replay-fixture-refs={boundary.replayFixtureRefs.join(
                      "|",
                    )}
                    data-rollback-target={boundary.rollbackTarget}
                    data-canary-status={boundary.status}
                    data-rollback-drill-status={
                      boundary.rollbackDrill.drillStatus
                    }
                    data-canary-eligible={
                      boundary.canaryEligible ? "true" : "false"
                    }
                  >
                    <strong>{boundary.clusterLabel}</strong>
                    <span>
                      {boundary.status} · {boundary.executorKind}
                    </span>
                    <small>
                      rollback drill {boundary.rollbackDrill.drillStatus} ·{" "}
                      {boundary.executedComponentKinds.length} nodes
                    </small>
                    {onCopyHarnessDeepLink ? (
                      <div className="workflow-harness-authority-gate-actions">
                        <button
                          type="button"
                          data-testid={`workflow-harness-canary-boundary-link-${boundary.clusterId}`}
                          onClick={() =>
                            onCopyHarnessDeepLink({
                              panel: "settings",
                              activationGateId: "canary",
                              activationGateEvidenceRef: boundary.boundaryId,
                              activationGateReceiptRef: boundary.receiptIds[0],
                              receiptRef: boundary.receiptIds[0],
                              activationGateReplayFixtureRef:
                                boundary.replayFixtureRefs[0],
                              replayFixtureRef: boundary.replayFixtureRefs[0],
                            })
                          }
                        >
                          Boundary
                        </button>
                        <button
                          type="button"
                          data-testid={`workflow-harness-canary-rollback-drill-link-${boundary.clusterId}`}
                          onClick={() =>
                            onCopyHarnessDeepLink({
                              panel: "settings",
                              activationGateId: "canary",
                              activationGateEvidenceRef:
                                boundary.rollbackDrill.drillId,
                              activationGateReceiptRef: boundary.receiptIds[0],
                              receiptRef: boundary.receiptIds[0],
                              activationGateReplayFixtureRef:
                                boundary.replayFixtureRefs[0],
                              replayFixtureRef: boundary.replayFixtureRefs[0],
                            })
                          }
                        >
                          Drill
                        </button>
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>
            ) : null}
            {workflow.metadata.harness?.forkedFrom ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-lineage"
              >
                <strong>Fork lineage</strong>
                <span>
                  {workflow.metadata.harness.forkedFrom.harnessWorkflowId}
                </span>
                <small>
                  {workflow.metadata.harness.forkedFrom.harnessHash}
                </small>
              </article>
            ) : null}
            {workflow.metadata.harness?.forkedFrom ? (
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-fork-component-diff"
              >
                <h4>Blessed vs fork components</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-fork-component-diff-summary"
                >
                  <div>
                    <dt>Unchanged</dt>
                    <dd>{harnessForkComponentDiffStats.unchanged ?? 0}</dd>
                  </div>
                  <div>
                    <dt>Changed</dt>
                    <dd>{harnessForkComponentDiffStats.changed ?? 0}</dd>
                  </div>
                  <div>
                    <dt>Missing</dt>
                    <dd>
                      {harnessForkComponentDiffStats.missing_from_fork ?? 0}
                    </dd>
                  </div>
                  <div>
                    <dt>Fork-only</dt>
                    <dd>{harnessForkComponentDiffStats.fork_only ?? 0}</dd>
                  </div>
                </dl>
                <div
                  className="workflow-rail-list"
                  data-testid="workflow-harness-fork-component-diff-list"
                >
                  {harnessForkComponentDiffRows.map((row) => (
                    <button
                      key={row.componentId}
                      type="button"
                      className={`workflow-search-result is-${
                        row.status === "unchanged" ? "ready" : "blocked"
                      }`}
                      data-testid={`workflow-harness-fork-component-diff-row-${row.componentId}`}
                      data-component-diff-status={row.status}
                      disabled={!row.nodeId}
                      onClick={() => row.nodeId && onInspectNode(row.nodeId)}
                    >
                      <strong>{row.label}</strong>
                      <span>
                        {row.status} · {row.kind}
                      </span>
                      <small>
                        blessed {row.blessedVersion} ({row.blessedReadiness}) ·
                        fork {row.forkVersion} ({row.forkReadiness})
                      </small>
                    </button>
                  ))}
                </div>
              </section>
            ) : null}
            <div
              className="workflow-rail-list"
              data-testid="workflow-harness-slots"
            >
              {harnessSlots.map((slot) => {
                const ready = boundHarnessSlotIds.has(slot.slotId);
                return (
                  <article
                    key={slot.slotId}
                    className={`workflow-test-row is-${ready ? "passed" : "blocked"}`}
                  >
                    <strong>{slot.label}</strong>
                    <span>
                      {ready ? "bound" : "unbound"} · {slot.kind}
                    </span>
                    <small>{slot.description}</small>
                  </article>
                );
              })}
            </div>
            <div
              className="workflow-rail-list"
              data-testid="workflow-harness-promotion-clusters"
            >
              {harnessPromotionClusters.map((cluster) => {
                const replayGateProof = cluster.replayGateProof;
                const replayGateStatus =
                  replayGateProof?.gateStatus ?? "not_run";
                const replayGateReady =
                  replayGateStatus === "passed" &&
                  replayGateProof?.activationGateImpact === "passed";
                return (
                  <article
                    key={cluster.clusterId}
                    className={`workflow-test-row is-${
                      replayGateReady
                        ? "passed"
                        : replayGateStatus === "blocked" ||
                            replayGateStatus === "failed"
                          ? "blocked"
                          : "idle"
                    }`}
                    data-testid={`workflow-harness-promotion-cluster-replay-gate-${cluster.clusterId}`}
                    data-replay-gate-status={replayGateStatus}
                    data-activation-gate-impact={
                      replayGateProof?.activationGateImpact ?? "pending"
                    }
                    data-replay-gate-id={replayGateProof?.gateId ?? ""}
                  >
                    <strong>{cluster.label}</strong>
                    <span>
                      {cluster.requiredExecutionMode} · replay gate{" "}
                      {replayGateStatus}
                    </span>
                    <small>
                      {cluster.componentKinds.length} components ·{" "}
                      {replayGateProof?.totalFixtures ?? 0} fixtures · rollback{" "}
                      {cluster.rollbackTarget}
                    </small>
                  </article>
                );
              })}
            </div>
            {harnessForkWorkflow ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-activation-blockers"
                data-activation-blockers={(
                  harnessActivationRecord?.activationBlockers ?? []
                ).join("|")}
                data-selected-activation-blocker-index={
                  selectedHarnessActivationBlockerIndex ?? ""
                }
                data-selected-activation-blocker-ref={
                  selectedHarnessActivationBlockerRef ?? ""
                }
              >
                <strong>Activation blockers</strong>
                <span>
                  {(harnessActivationRecord?.activationBlockers ?? []).length >
                  0
                    ? harnessActivationRecord?.activationBlockers.join(", ")
                    : "None"}
                </span>
                <small>
                  {workflow.metadata.harness?.activationState ?? "blocked"}
                </small>
                {(harnessActivationRecord?.activationBlockers ?? []).length >
                0 ? (
                  <div className="workflow-harness-authority-gate-actions">
                    {(harnessActivationRecord?.activationBlockers ?? [])
                      .slice(0, 5)
                      .map((blocker, index: number) => (
                        <button
                          key={`${blocker}-${index}`}
                          type="button"
                          className={`workflow-harness-ref-button ${
                            selectedHarnessActivationBlockerRef === blocker
                              ? "is-active"
                              : ""
                          }`}
                          data-testid={`workflow-harness-activation-blocker-link-${index}`}
                          data-activation-blocker-index={String(index)}
                          data-activation-blocker-ref={blocker}
                          disabled={!onCopyHarnessDeepLink}
                          onClick={() =>
                            onCopyHarnessDeepLink?.({
                              panel: "settings",
                              activationBlockerIndex: String(index),
                              activationBlockerRef: blocker,
                            })
                          }
                        >
                          <code>{blocker}</code>
                        </button>
                      ))}
                  </div>
                ) : null}
              </article>
            ) : null}
          </section>
  ) : null;
}
