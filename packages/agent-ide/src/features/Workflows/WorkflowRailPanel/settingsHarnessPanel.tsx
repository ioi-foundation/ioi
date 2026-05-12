import type { ReactNode } from "react";
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
import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import type { WorkflowSettingsHarnessModel } from "../../../runtime/workflow-settings-harness-model";
import {
  workflowIssueTitle,
  workflowNodeName,
  workflowUniqueReceiptRefs,
} from "../../../runtime/workflow-rail-model";
import {
  workflowHarnessPackageDeepLinkTarget,
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
  const renderHarnessActivationGateAction = (
    action: WorkflowHarnessActivationGateAction | null | undefined,
    testId: string,
  ): ReactNode =>
    action ? (
      <button
        type="button"
        className="workflow-harness-ref-button"
        data-testid={testId}
        data-gate-action-id={action.actionId}
        data-gate-action-kind={action.kind}
        data-gate-action-impact={action.impact}
        data-gate-action-command={action.commandTestId}
        data-gate-action-disabled={action.disabled ? "true" : "false"}
        data-gate-action-disabled-reason={action.disabledReason ?? ""}
        disabled={action.disabled}
        onClick={() => action.onRun?.()}
      >
        <strong>{action.label}</strong>
        <span>{action.detail}</span>
      </button>
    ) : null;

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
            {harnessWorkerBinding ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-worker-identity"
              >
                <strong>{harnessWorkerBinding.harnessWorkflowId}</strong>
                <span>
                  {harnessWorkerBinding.harnessActivationId ??
                    "activation blocked"}
                </span>
                <small>
                  {harnessWorkerBinding.executionMode ?? "projection"} ·{" "}
                  {harnessWorkerBinding.harnessHash}
                </small>
              </article>
            ) : null}
            {harnessActivationRecord ? (
              <article
                className="workflow-output-row"
                data-testid="workflow-harness-activation-record"
              >
                <strong>
                  {harnessActivationRecord.activationId ??
                    "activation not minted"}
                </strong>
                <span>
                  {harnessActivationRecord.activationState} · canary{" "}
                  {harnessActivationRecord.canaryStatus}
                </span>
                <small>
                  rollback{" "}
                  {harnessActivationRecord.rollbackAvailable
                    ? "ready"
                    : "blocked"}{" "}
                  · {harnessActivationRecord.rollbackTarget}
                </small>
              </article>
            ) : null}
            {harnessActiveRuntimeBinding ? (
              <section
                className="workflow-rail-section workflow-harness-active-runtime-binding"
                data-testid="workflow-harness-active-runtime-binding"
                data-binding-matched={
                  harnessActiveRuntimeBinding.bindingMatched ? "true" : "false"
                }
                data-workflow-id={harnessActiveRuntimeBinding.workflowId}
                data-activation-id={harnessActiveRuntimeBinding.activationId}
                data-harness-hash={harnessActiveRuntimeBinding.harnessHash}
                data-selector-decision-id={
                  harnessActiveRuntimeBinding.selectorDecisionId
                }
                data-default-dispatch-id={
                  harnessActiveRuntimeBinding.defaultDispatchId
                }
                data-worker-binding-id={
                  harnessActiveRuntimeBinding.workerBindingId
                }
                data-rollback-target={
                  harnessActiveRuntimeBinding.rollbackTarget
                }
                data-worker-binding-authority-ready={
                  harnessActiveRuntimeBinding.workerBindingAuthorityReady
                    ? "true"
                    : "false"
                }
                data-worker-launch-reviewed-import-invariant-bound={
                  harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
                    ? "true"
                    : "false"
                }
                data-worker-required-invariant-ids={harnessActiveRuntimeBinding.workerBindingRequiredInvariantIds.join(
                  ",",
                )}
                data-worker-invariant-blockers={harnessActiveRuntimeBinding.workerInvariantBlockers.join(
                  ",",
                )}
                data-worker-binding-registry-bound={
                  harnessActiveRuntimeBinding.workerBindingRegistryBound
                    ? "true"
                    : "false"
                }
                data-worker-binding-registry-status={
                  harnessActiveRuntimeBinding.workerBindingRegistryStatus
                }
                data-worker-attach-status={
                  harnessActiveRuntimeBinding.workerAttachStatus
                }
                data-worker-attach-accepted={
                  harnessActiveRuntimeBinding.workerAttachAccepted
                    ? "true"
                    : "false"
                }
                data-live-promotion-readiness-proof-id={
                  harnessActiveRuntimeBinding.selectorLivePromotionReadinessProofId
                }
                data-live-promotion-readiness-proof-match={
                  harnessActiveRuntimeBinding.livePromotionReadinessProofIdsMatch
                    ? "true"
                    : "false"
                }
                data-selected-selector-decision-id={
                  selectedHarnessSelectorDecisionId ?? ""
                }
                data-selected-default-dispatch-id={
                  selectedHarnessDefaultDispatchId ?? ""
                }
                data-selected-worker-binding-id={
                  selectedHarnessWorkerBindingId ?? ""
                }
                data-selected-rollback-target={
                  selectedHarnessRollbackTarget ?? ""
                }
                data-selected-receipt-ref={selectedHarnessReceiptRef ?? ""}
                data-selected-replay-fixture-ref={
                  selectedHarnessReplayFixtureRef ?? ""
                }
                data-selected-node-attempt-id={
                  selectedHarnessNodeAttemptId ?? ""
                }
                data-rollback-proof-bound={
                  harnessActiveRuntimeBinding.workerRollbackProof.bound
                    ? "true"
                    : "false"
                }
                data-rollback-proof-blockers={harnessActiveRuntimeBinding.workerRollbackProof.blockers.join(
                  ",",
                )}
                data-rollback-readiness-proof-id={
                  harnessActiveRuntimeBinding.workerRollbackProof
                    .readinessProofId
                }
                data-rollback-live-shadow-gate-id={
                  harnessActiveRuntimeBinding.workerRollbackProof
                    .liveShadowComparisonGateId
                }
                data-rollback-live-shadow-gate-ready={
                  harnessActiveRuntimeBinding.workerRollbackProof
                    .liveShadowComparisonGateReady
                    ? "true"
                    : "false"
                }
                data-rollback-activation-id={
                  harnessActiveRuntimeBinding.workerRollbackProof.activationId
                }
                data-rollback-harness-hash={
                  harnessActiveRuntimeBinding.workerRollbackProof.harnessHash
                }
                data-rollback-policy-decision={
                  harnessActiveRuntimeBinding.workerRollbackProof.policyDecision
                }
                data-rollback-launch-envelope-id={
                  harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
                    ?.envelopeId ?? ""
                }
                data-rollback-handoff-receipt-id={
                  harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
                    ?.receiptId ?? ""
                }
                data-rollback-node-attempt-id={
                  harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
                    ?.attemptId ?? ""
                }
                data-rollback-replay-fixture-ref={
                  harnessActiveRuntimeBinding.workerRollbackProof
                    .replayFixtureRef
                }
                data-rollback-execution-dry-run-status={
                  harnessActiveRuntimeRollbackExecutionProof?.dryRun
                    .canaryStatus ?? "not_run"
                }
                data-rollback-execution-canary-result-id={
                  harnessActiveRuntimeRollbackExecutionProof?.dryRun
                    .canaryResultId ?? ""
                }
                data-rollback-execution-canary-status={
                  harnessActiveRuntimeRollbackExecutionProof?.dryRun
                    .canaryStatus ?? "not_run"
                }
                data-rollback-execution-canary-hash-verified={
                  harnessActiveRuntimeRollbackExecutionProof?.dryRun
                    .canaryHashVerified
                    ? "true"
                    : "false"
                }
                data-rollback-execution-apply-readiness={
                  harnessActiveRuntimeRollbackProofStillBound &&
                  harnessActiveRuntimeRollbackDryRunPassed
                    ? "ready"
                    : "blocked"
                }
                data-rollback-execution-apply-disabled={
                  harnessActiveRuntimeRollbackApplyDisabled ? "true" : "false"
                }
                data-rollback-execution-apply-policy-decision={
                  harnessActiveRuntimeRollbackExecutionProof?.apply
                    .policyDecision ?? ""
                }
                data-rollback-apply-execution-status={
                  harnessActiveRuntimeRollbackApplyProof?.applyStatus ??
                  "not_run"
                }
                data-rollback-apply-execution-id={
                  harnessActiveRuntimeRollbackApplyProof?.executionId ?? ""
                }
                data-rollback-apply-receipt-id={
                  harnessActiveRuntimeRollbackApplyProof?.rollbackReceiptId ?? ""
                }
                data-rollback-apply-audit-event-id={
                  harnessActiveRuntimeRollbackApplyProof?.auditEventId ?? ""
                }
                data-rollback-apply-target-verified={
                  harnessActiveRuntimeRollbackApplyProof?.rollbackTargetVerified
                    ? "true"
                    : "false"
                }
                data-rollback-apply-hash-verified={
                  harnessActiveRuntimeRollbackApplyProof?.hashVerified
                    ? "true"
                    : "false"
                }
                data-rollback-apply-policy-decision={
                  harnessActiveRuntimeRollbackApplyProof?.policyDecision ?? ""
                }
                data-rollback-apply-blockers={harnessActiveRuntimeRollbackApplyBlockers.join(
                  ",",
                )}
                data-rollback-execution-blockers={[
                  ...(harnessActiveRuntimeRollbackExecutionProof?.blockers ??
                    []),
                  ...(harnessActiveRuntimeRollbackExecutionProof?.dryRun
                    .blockers ?? []),
                  ...harnessActiveRuntimeRollbackProofBindingBlockers,
                ].join(",")}
              >
                <h4>Active runtime binding</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-active-runtime-binding-summary"
                >
                  <div>
                    <dt>Mode</dt>
                    <dd>{harnessActiveRuntimeBinding.executionMode}</dd>
                  </div>
                  <div>
                    <dt>Status</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.bindingMatched
                        ? "matched"
                        : "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Receipts</dt>
                    <dd>{harnessActiveRuntimeBinding.receiptRefs.length}</dd>
                  </div>
                  <div>
                    <dt>Replay</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.replayFixtureRefs.length}
                    </dd>
                  </div>
                  <div>
                    <dt>Authority</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.workerBindingAuthorityReady
                        ? "ready"
                        : "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Invariant</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
                        ? "bound"
                        : "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Package</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.workerRegistryReviewedPackageBound
                        ? "bound"
                        : "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Registry</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.workerBindingRegistryStatus}
                    </dd>
                  </div>
                  <div>
                    <dt>Attach</dt>
                    <dd>{harnessActiveRuntimeBinding.workerAttachStatus}</dd>
                  </div>
                  <div>
                    <dt>Lifecycle</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.workerAttachLifecycleComplete
                        ? "complete"
                        : "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Worker</dt>
                    <dd>{harnessActiveRuntimeBinding.workerSessionStatus}</dd>
                  </div>
                  <div>
                    <dt>Handoff</dt>
                    <dd>
                      {harnessActiveRuntimeBinding.workerHandoffNodeTimelineBound
                        ? "timeline"
                        : "blocked"}
                    </dd>
                  </div>
                </dl>
                <article
                  className={`workflow-output-row is-${
                    harnessActiveRuntimeBinding.bindingMatched
                      ? "ready"
                      : "blocked"
                  }`}
                  data-testid="workflow-harness-active-runtime-binding-rollup"
                  data-runtime-authority={
                    harnessActiveRuntimeBinding.runtimeAuthority
                  }
                  data-selected-selector={
                    harnessActiveRuntimeBinding.selectedSelector
                  }
                  data-production-default-selector={
                    harnessActiveRuntimeBinding.productionDefaultSelector
                  }
                  data-selector-live-promotion-readiness-ready={
                    harnessActiveRuntimeBinding.selectorLivePromotionReadinessReady
                      ? "true"
                      : "false"
                  }
                  data-dispatch-live-promotion-readiness-ready={
                    harnessActiveRuntimeBinding.dispatchLivePromotionReadinessReady
                      ? "true"
                      : "false"
                  }
                  data-invalid-fork-live-activation-blocked={
                    harnessActiveRuntimeBinding.invalidForkLiveActivationBlocked
                      ? "true"
                      : "false"
                  }
                  data-worker-launch-reviewed-import-invariant-bound={
                    harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
                      ? "true"
                      : "false"
                  }
                  data-worker-registry-reviewed-package-bound={
                    harnessActiveRuntimeBinding.workerRegistryReviewedPackageBound
                      ? "true"
                      : "false"
                  }
                  data-worker-registry-reviewed-package-snapshot-hash={
                    harnessActiveRuntimeBinding.workerBindingRegistryRecord
                      ?.reviewedPackageSnapshotHash ?? ""
                  }
                  data-worker-registry-reviewed-package-workflow-hash={
                    harnessActiveRuntimeBinding.workerBindingRegistryRecord
                      ?.reviewedWorkflowContentHash ?? ""
                  }
                  data-worker-registry-reviewed-package-replay-fixtures={(
                    harnessActiveRuntimeBinding.workerBindingRegistryRecord
                      ?.reviewedReplayFixtureRefs ?? []
                  ).join(",")}
                  data-worker-binding-required-invariant-ids={harnessActiveRuntimeBinding.workerBindingRequiredInvariantIds.join(
                    ",",
                  )}
                  data-worker-binding-invariant-blockers={harnessActiveRuntimeBinding.workerBindingInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-registry-required-invariant-ids={harnessActiveRuntimeBinding.workerRegistryRequiredInvariantIds.join(
                    ",",
                  )}
                  data-worker-registry-invariant-blockers={harnessActiveRuntimeBinding.workerRegistryInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-attach-required-invariant-ids={harnessActiveRuntimeBinding.workerAttachRequiredInvariantIds.join(
                    ",",
                  )}
                  data-worker-attach-invariant-blockers={harnessActiveRuntimeBinding.workerAttachInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-attach-lifecycle-required-invariant-ids={harnessActiveRuntimeBinding.workerAttachLifecycleRequiredInvariantIds.join(
                    ",",
                  )}
                  data-worker-attach-lifecycle-invariant-blockers={harnessActiveRuntimeBinding.workerAttachLifecycleInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-session-required-invariant-ids={harnessActiveRuntimeBinding.workerSessionRequiredInvariantIds.join(
                    ",",
                  )}
                  data-worker-session-invariant-blockers={harnessActiveRuntimeBinding.workerSessionInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-session-launch-authority-invariant-ids={harnessActiveRuntimeBinding.workerSessionLaunchAuthorityInvariantIds.join(
                    ",",
                  )}
                  data-worker-session-launch-authority-invariant-blockers={harnessActiveRuntimeBinding.workerSessionLaunchAuthorityInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-launch-envelope-invariant-ids={harnessActiveRuntimeBinding.workerLaunchEnvelopeInvariantIds.join(
                    ",",
                  )}
                  data-worker-launch-envelope-invariant-blockers={harnessActiveRuntimeBinding.workerLaunchEnvelopeInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-handoff-receipt-invariant-ids={harnessActiveRuntimeBinding.workerHandoffReceiptInvariantIds.join(
                    ",",
                  )}
                  data-worker-handoff-receipt-invariant-blockers={harnessActiveRuntimeBinding.workerHandoffReceiptInvariantBlockers.join(
                    ",",
                  )}
                  data-worker-binding-registry-record-id={
                    harnessActiveRuntimeBinding.workerBindingRegistryRecord
                      ?.registryRecordId ?? ""
                  }
                  data-worker-attach-receipt-id={
                    harnessActiveRuntimeBinding.workerAttachReceipt
                      ?.receiptId ?? ""
                  }
                  data-worker-attach-resume-receipt-id={
                    harnessActiveRuntimeBinding.workerAttachResumeReceipt
                      ?.receiptId ?? ""
                  }
                  data-worker-attach-rollback-receipt-id={
                    harnessActiveRuntimeBinding.workerAttachRollbackReceipt
                      ?.receiptId ?? ""
                  }
                  data-worker-attach-lifecycle-complete={
                    harnessActiveRuntimeBinding.workerAttachLifecycleComplete
                      ? "true"
                      : "false"
                  }
                  data-worker-attach-lifecycle-statuses={harnessActiveRuntimeBinding.workerAttachLifecycleStatuses.join(
                    ",",
                  )}
                  data-worker-attach-lifecycle-attempt-ids={harnessActiveRuntimeBinding.workerAttachLifecycleAttemptIds.join(
                    ",",
                  )}
                  data-worker-session-record-id={
                    harnessActiveRuntimeBinding.workerSessionRecordId
                  }
                  data-worker-session-status={
                    harnessActiveRuntimeBinding.workerSessionStatus
                  }
                  data-worker-session-accepted={
                    harnessActiveRuntimeBinding.workerSessionAccepted
                      ? "true"
                      : "false"
                  }
                  data-worker-session-worker-id={
                    harnessActiveRuntimeBinding.workerSessionRecord?.workerId ??
                    ""
                  }
                  data-worker-session-rollback-target={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.rollbackTarget ?? ""
                  }
                  data-worker-session-current-attempt-id={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.currentAttemptId ?? ""
                  }
                  data-worker-session-persistence-key={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.persistenceKey ?? ""
                  }
                  data-worker-session-record-persistence-key={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.recordPersistenceKey ?? ""
                  }
                  data-worker-session-persisted={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.persistedInRuntimeCheckpoint
                      ? "true"
                      : "false"
                  }
                  data-worker-session-restored={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.restoredFromPersistedSession
                      ? "true"
                      : "false"
                  }
                  data-worker-session-checkpoint-source={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.runtimeCheckpointSource ?? ""
                  }
                  data-worker-session-launch-authority-ready={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.launchAuthorityReady
                      ? "true"
                      : "false"
                  }
                  data-worker-session-launch-authority-source={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.launchAuthoritySource ?? ""
                  }
                  data-worker-session-rollback-handoff-ready={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.rollbackHandoffReady
                      ? "true"
                      : "false"
                  }
                  data-worker-session-rollback-handoff-target={
                    harnessActiveRuntimeBinding.workerSessionRecord
                      ?.rollbackHandoffTarget ?? ""
                  }
                  data-worker-launch-envelope-count={
                    harnessActiveRuntimeBinding.workerLaunchEnvelopes.length
                  }
                  data-worker-launch-envelope-ids={harnessActiveRuntimeBinding.workerLaunchEnvelopeIds.join(
                    ",",
                  )}
                  data-worker-launch-envelopes-accepted={
                    harnessActiveRuntimeBinding.workerLaunchEnvelopesAccepted
                      ? "true"
                      : "false"
                  }
                  data-worker-handoff-receipt-count={
                    harnessActiveRuntimeBinding.workerHandoffReceipts.length
                  }
                  data-worker-handoff-receipt-ids={harnessActiveRuntimeBinding.workerHandoffReceiptIds.join(
                    ",",
                  )}
                  data-worker-handoff-receipts-accepted={
                    harnessActiveRuntimeBinding.workerHandoffReceiptsAccepted
                      ? "true"
                      : "false"
                  }
                  data-worker-handoff-node-attempt-count={
                    harnessActiveRuntimeBinding.workerHandoffNodeAttempts.length
                  }
                  data-worker-handoff-node-attempt-ids={harnessActiveRuntimeBinding.workerHandoffNodeAttemptIds.join(
                    ",",
                  )}
                  data-worker-handoff-replay-fixture-refs={harnessActiveRuntimeBinding.workerHandoffReplayFixtureRefs.join(
                    ",",
                  )}
                  data-worker-handoff-node-timeline-bound={
                    harnessActiveRuntimeBinding.workerHandoffNodeTimelineBound
                      ? "true"
                      : "false"
                  }
                  data-worker-rollback-handoff-receipt-status={
                    harnessActiveRuntimeBinding.workerHandoffReceipts.find(
                      (receipt) => receipt.phase === "rollback",
                    )?.handoffStatus ?? ""
                  }
                >
                  <strong>{harnessActiveRuntimeBinding.activationId}</strong>
                  <span>
                    {harnessActiveRuntimeBinding.workflowId} ·{" "}
                    {harnessActiveRuntimeBinding.executionMode}
                  </span>
                  <small>
                    {harnessActiveRuntimeBinding.runtimeAuthority} · rollback{" "}
                    {harnessActiveRuntimeBinding.rollbackAvailable
                      ? harnessActiveRuntimeBinding.rollbackTarget
                      : "blocked"}
                  </small>
                  <small>
                    proof{" "}
                    {
                      harnessActiveRuntimeBinding.selectorLivePromotionReadinessProofId
                    }
                  </small>
                  <small>
                    registry{" "}
                    {harnessActiveRuntimeBinding.workerBindingRegistryRecord
                      ?.registryRecordId ?? "missing"}
                  </small>
                  <small>
                    package snapshot{" "}
                    {harnessActiveRuntimeBinding.workerBindingRegistryRecord
                      ?.reviewedPackageSnapshotHash ?? "missing"}
                  </small>
                  <small>
                    attach{" "}
                    {harnessActiveRuntimeBinding.workerAttachReceipt
                      ?.receiptId ?? "missing"}
                  </small>
                  <small>
                    lifecycle{" "}
                    {harnessActiveRuntimeBinding.workerAttachLifecycleStatuses.join(
                      " / ",
                    ) || "missing"}
                  </small>
                  <small>
                    worker session{" "}
                    {harnessActiveRuntimeBinding.workerSessionRecord
                      ?.sessionRecordId ?? "missing"}
                  </small>
                  <small>
                    checkpoint{" "}
                    {harnessActiveRuntimeBinding.workerSessionRecord
                      ?.persistedInRuntimeCheckpoint
                      ? "persisted"
                      : "missing"}{" "}
                    /{" "}
                    {harnessActiveRuntimeBinding.workerSessionRecord
                      ?.restoredFromPersistedSession
                      ? "restored"
                      : "not restored"}
                  </small>
                  <small>
                    launch{" "}
                    {harnessActiveRuntimeBinding.workerSessionRecord
                      ?.launchAuthorityReady
                      ? "authoritative"
                      : "blocked"}{" "}
                    / rollback{" "}
                    {harnessActiveRuntimeBinding.workerSessionRecord
                      ?.rollbackHandoffReady
                      ? "handoff ready"
                      : "handoff blocked"}
                  </small>
                  <small>
                    invariant{" "}
                    {
                      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT
                    }{" "}
                    ·{" "}
                    {harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
                      ? "bound"
                      : "blocked"}
                  </small>
                  {harnessActiveRuntimeBinding.workerInvariantBlockers.length >
                  0 ? (
                    <small>
                      invariant blockers{" "}
                      {harnessActiveRuntimeBinding.workerInvariantBlockers.join(
                        ", ",
                      )}
                    </small>
                  ) : null}
                  <small>
                    envelopes{" "}
                    {harnessActiveRuntimeBinding.workerLaunchEnvelopes.length} ·
                    handoff receipts{" "}
                    {harnessActiveRuntimeBinding.workerHandoffReceipts.length}
                  </small>
                  <small>
                    handoff attempts{" "}
                    {
                      harnessActiveRuntimeBinding.workerHandoffNodeAttempts
                        .length
                    }{" "}
                    · replay fixtures{" "}
                    {
                      harnessActiveRuntimeBinding.workerHandoffReplayFixtureRefs
                        .length
                    }
                  </small>
                </article>
                <article
                  className={`workflow-output-row is-${
                    harnessActiveRuntimeBinding.workerRollbackProof.bound
                      ? "ready"
                      : "blocked"
                  }`}
                  data-testid="workflow-harness-active-runtime-rollback-proof"
                  data-rollback-proof-bound={
                    harnessActiveRuntimeBinding.workerRollbackProof.bound
                      ? "true"
                      : "false"
                  }
                  data-rollback-proof-blockers={harnessActiveRuntimeBinding.workerRollbackProof.blockers.join(
                    ",",
                  )}
                  data-rollback-readiness-proof-id={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .readinessProofId
                  }
                  data-rollback-live-shadow-gate-id={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .liveShadowComparisonGateId
                  }
                  data-rollback-live-shadow-gate-ready={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .liveShadowComparisonGateReady
                      ? "true"
                      : "false"
                  }
                  data-rollback-activation-id={
                    harnessActiveRuntimeBinding.workerRollbackProof.activationId
                  }
                  data-rollback-harness-hash={
                    harnessActiveRuntimeBinding.workerRollbackProof.harnessHash
                  }
                  data-rollback-policy-decision={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .policyDecision
                  }
                  data-rollback-launch-envelope-id={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .launchEnvelope?.envelopeId ?? ""
                  }
                  data-rollback-handoff-receipt-id={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .handoffReceipt?.receiptId ?? ""
                  }
                  data-rollback-node-attempt-id={
                    harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
                      ?.attemptId ?? ""
                  }
                  data-rollback-replay-fixture-ref={
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .replayFixtureRef
                  }
                  data-rollback-execution-dry-run-status={
                    harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .canaryStatus ?? "not_run"
                  }
                  data-rollback-execution-canary-result-id={
                    harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .canaryResultId ?? ""
                  }
                  data-rollback-execution-canary-status={
                    harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .canaryStatus ?? "not_run"
                  }
                  data-rollback-execution-canary-hash-verified={
                    harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .canaryHashVerified
                      ? "true"
                      : "false"
                  }
                  data-rollback-execution-apply-readiness={
                    harnessActiveRuntimeRollbackProofStillBound &&
                    harnessActiveRuntimeRollbackDryRunPassed
                      ? "ready"
                      : "blocked"
                  }
                  data-rollback-execution-apply-disabled={
                    harnessActiveRuntimeRollbackApplyDisabled
                      ? "true"
                      : "false"
                  }
                  data-rollback-execution-apply-policy-decision={
                    harnessActiveRuntimeRollbackExecutionProof?.apply
                      .policyDecision ?? ""
                  }
                  data-rollback-apply-execution-status={
                    harnessActiveRuntimeRollbackApplyProof?.applyStatus ??
                    "not_run"
                  }
                  data-rollback-apply-execution-id={
                    harnessActiveRuntimeRollbackApplyProof?.executionId ?? ""
                  }
                  data-rollback-apply-receipt-id={
                    harnessActiveRuntimeRollbackApplyProof?.rollbackReceiptId ??
                    ""
                  }
                  data-rollback-apply-audit-event-id={
                    harnessActiveRuntimeRollbackApplyProof?.auditEventId ?? ""
                  }
                  data-rollback-apply-target-verified={
                    harnessActiveRuntimeRollbackApplyProof?.rollbackTargetVerified
                      ? "true"
                      : "false"
                  }
                  data-rollback-apply-hash-verified={
                    harnessActiveRuntimeRollbackApplyProof?.hashVerified
                      ? "true"
                      : "false"
                  }
                  data-rollback-apply-policy-decision={
                    harnessActiveRuntimeRollbackApplyProof?.policyDecision ?? ""
                  }
                  data-rollback-apply-blockers={harnessActiveRuntimeRollbackApplyBlockers.join(
                    ",",
                  )}
                  data-rollback-execution-blockers={[
                    ...(harnessActiveRuntimeRollbackExecutionProof?.blockers ??
                      []),
                    ...(harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .blockers ?? []),
                    ...harnessActiveRuntimeRollbackProofBindingBlockers,
                  ].join(",")}
                >
                  <strong>Rollback proof</strong>
                  <span>
                    {harnessActiveRuntimeBinding.workerRollbackProof.bound
                      ? "bound to live-shadow gate"
                      : "blocked"}
                  </span>
                  <small>
                    readiness{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .readinessProofId || "missing"}
                  </small>
                  <small>
                    gate{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .liveShadowComparisonGateId || "missing"}{" "}
                    ·{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .liveShadowComparisonGateReady
                      ? "ready"
                      : "blocked"}
                  </small>
                  <small>
                    policy{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .policyDecision || "missing"}
                  </small>
                  <small>
                    envelope{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .launchEnvelope?.envelopeId ?? "missing"}
                  </small>
                  <small>
                    handoff{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .handoffReceipt?.receiptId ?? "missing"}
                  </small>
                  <small>
                    attempt{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
                      ?.attemptId ?? "missing"}
                  </small>
                  <small>
                    replay{" "}
                    {harnessActiveRuntimeBinding.workerRollbackProof
                      .replayFixtureRef || "missing"}
                  </small>
                  <small>
                    dry run{" "}
                    {harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .canaryStatus ?? "not run"}{" "}
                    · canary{" "}
                    {harnessActiveRuntimeRollbackExecutionProof?.dryRun
                      .canaryResultId ?? "pending"}
                  </small>
                  <small>
                    apply{" "}
                    {harnessActiveRuntimeRollbackApplyDisabled
                      ? "blocked"
                      : "ready"}{" "}
                    · proof{" "}
                    {harnessActiveRuntimeRollbackProofStillBound
                      ? "bound"
                      : "not restored"}
                  </small>
                  <small>
                    rollback apply{" "}
                    {harnessActiveRuntimeRollbackApplyProof?.applyStatus ??
                      "not run"}{" "}
                    · receipt{" "}
                    {harnessActiveRuntimeRollbackApplyProof?.rollbackReceiptId ??
                      "pending"}
                  </small>
                  {harnessActiveRuntimeBinding.workerRollbackProof.blockers
                    .length > 0 ? (
                    <small>
                      blockers{" "}
                      {harnessActiveRuntimeBinding.workerRollbackProof.blockers.join(
                        ", ",
                      )}
                    </small>
                  ) : null}
                  <div className="workflow-harness-authority-gate-actions">
                    <button
                      type="button"
                      data-testid="workflow-harness-active-runtime-rollback-dry-run"
                      data-rollback-action-kind="dry_run"
                      disabled={
                        !onRunActiveRuntimeRollbackDryRun ||
                        !harnessActiveRuntimeBinding.workerRollbackProof.bound
                      }
                      onClick={onRunActiveRuntimeRollbackDryRun}
                    >
                      Rollback dry run
                    </button>
                    <button
                      type="button"
                      data-testid="workflow-harness-active-runtime-rollback-apply"
                      data-rollback-action-kind="apply"
                      data-rollback-apply-disabled={
                        harnessActiveRuntimeRollbackApplyDisabled
                          ? "true"
                          : "false"
                      }
                      disabled={harnessActiveRuntimeRollbackApplyDisabled}
                      onClick={onApplyActiveRuntimeRollback}
                    >
                      Apply rollback
                    </button>
                  </div>
                </article>
                <div
                  className="workflow-harness-authority-gate-actions"
                  data-testid="workflow-harness-active-runtime-binding-deep-links"
                >
                  <button
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessSelectorDecisionId ===
                      harnessActiveRuntimeBinding.selectorDecisionId
                        ? "is-active"
                        : ""
                    }`}
                    data-testid="workflow-harness-active-runtime-binding-selector-link"
                    data-deep-link-kind="selector_decision"
                    data-deep-link-target={
                      harnessActiveRuntimeBinding.selectorDecisionId
                    }
                    disabled={!onCopyHarnessDeepLink}
                    onClick={() =>
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        selectorDecisionId:
                          harnessActiveRuntimeBinding.selectorDecisionId,
                      })
                    }
                  >
                    <code>
                      {harnessActiveRuntimeBinding.selectorDecisionId}
                    </code>
                  </button>
                  <button
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessDefaultDispatchId ===
                      harnessActiveRuntimeBinding.defaultDispatchId
                        ? "is-active"
                        : ""
                    }`}
                    data-testid="workflow-harness-active-runtime-binding-dispatch-link"
                    data-deep-link-kind="default_dispatch"
                    data-deep-link-target={
                      harnessActiveRuntimeBinding.defaultDispatchId
                    }
                    disabled={!onCopyHarnessDeepLink}
                    onClick={() =>
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        dispatchId:
                          harnessActiveRuntimeBinding.defaultDispatchId,
                      })
                    }
                  >
                    <code>{harnessActiveRuntimeBinding.defaultDispatchId}</code>
                  </button>
                  <button
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessWorkerBindingId ===
                      harnessActiveRuntimeBinding.workerBindingId
                        ? "is-active"
                        : ""
                    }`}
                    data-testid="workflow-harness-active-runtime-binding-worker-link"
                    data-deep-link-kind="worker_binding"
                    data-deep-link-target={
                      harnessActiveRuntimeBinding.workerBindingId
                    }
                    disabled={!onCopyHarnessDeepLink}
                    onClick={() =>
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        workerBindingId:
                          harnessActiveRuntimeBinding.workerBindingId,
                      })
                    }
                  >
                    <code>
                      {harnessActiveRuntimeBinding.workerBinding?.source ??
                        "worker"}
                      {" · "}
                      {harnessActiveRuntimeBinding.workerBindingId}
                    </code>
                  </button>
                  <button
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessRollbackTarget ===
                      harnessActiveRuntimeBinding.rollbackTarget
                        ? "is-active"
                        : ""
                    }`}
                    data-testid="workflow-harness-active-runtime-binding-rollback-link"
                    data-deep-link-kind="rollback_target"
                    data-deep-link-target={
                      harnessActiveRuntimeBinding.rollbackTarget
                    }
                    data-rollback-target={
                      harnessActiveRuntimeBinding.rollbackTarget
                    }
                    onClick={() => {
                      onSelectHarnessRollbackTarget?.(
                        harnessActiveRuntimeBinding.rollbackTarget,
                      );
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        rollbackTarget:
                          harnessActiveRuntimeBinding.rollbackTarget,
                      });
                    }}
                  >
                    <code>{harnessActiveRuntimeBinding.rollbackTarget}</code>
                  </button>
                  {harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope ? (
                    <button
                      type="button"
                      className={`workflow-harness-ref-button ${
                        selectedHarnessReceiptRef ===
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .launchEnvelope.envelopeId
                          ? "is-active"
                          : ""
                      }`}
                      data-testid="workflow-harness-active-runtime-rollback-proof-launch-envelope-link"
                      data-deep-link-kind="rollback_launch_envelope"
                      data-receipt-ref={
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .launchEnvelope.envelopeId
                      }
                      onClick={() => {
                        const envelopeId =
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .launchEnvelope?.envelopeId;
                        if (!envelopeId) return;
                        onSelectHarnessReceiptRef?.(envelopeId);
                        onCopyHarnessDeepLink?.({
                          panel: "outputs",
                          receiptRef: envelopeId,
                        });
                      }}
                    >
                      <code>
                        {
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .launchEnvelope.envelopeId
                        }
                      </code>
                    </button>
                  ) : null}
                  {harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt ? (
                    <button
                      type="button"
                      className={`workflow-harness-ref-button ${
                        selectedHarnessReceiptRef ===
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .handoffReceipt.receiptId
                          ? "is-active"
                          : ""
                      }`}
                      data-testid="workflow-harness-active-runtime-rollback-proof-handoff-receipt-link"
                      data-deep-link-kind="rollback_handoff_receipt"
                      data-receipt-ref={
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .handoffReceipt.receiptId
                      }
                      onClick={() => {
                        const receiptId =
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .handoffReceipt?.receiptId;
                        if (!receiptId) return;
                        onSelectHarnessReceiptRef?.(receiptId);
                        onCopyHarnessDeepLink?.({
                          panel: "outputs",
                          receiptRef: receiptId,
                        });
                      }}
                    >
                      <code>
                        {
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .handoffReceipt.receiptId
                        }
                      </code>
                    </button>
                  ) : null}
                  {harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt ? (
                    <button
                      type="button"
                      className={`workflow-harness-ref-button ${
                        selectedHarnessNodeAttemptId ===
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .nodeAttempt.attemptId
                          ? "is-active"
                          : ""
                      }`}
                      data-testid="workflow-harness-active-runtime-rollback-proof-node-attempt-link"
                      data-deep-link-kind="rollback_node_attempt"
                      data-node-attempt-id={
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .nodeAttempt.attemptId
                      }
                      onClick={() => {
                        const rollbackAttempt =
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .nodeAttempt;
                        if (!rollbackAttempt) return;
                        onCopyHarnessDeepLink?.({
                          panel: "outputs",
                          nodeAttemptId: rollbackAttempt.attemptId,
                          receiptRef:
                            harnessActiveRuntimeBinding.workerRollbackProof
                              .handoffReceipt?.receiptId,
                          replayFixtureRef:
                            harnessActiveRuntimeBinding.workerRollbackProof
                              .replayFixtureRef || undefined,
                        });
                      }}
                    >
                      <code>
                        {
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .nodeAttempt.attemptId
                        }
                      </code>
                    </button>
                  ) : null}
                  {harnessActiveRuntimeBinding.workerRollbackProof
                    .replayFixtureRef ? (
                    <button
                      type="button"
                      className={`workflow-harness-ref-button ${
                        selectedHarnessReplayFixtureRef ===
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .replayFixtureRef
                          ? "is-active"
                          : ""
                      }`}
                      data-testid="workflow-harness-active-runtime-rollback-proof-replay-link"
                      data-deep-link-kind="rollback_replay_fixture"
                      data-replay-fixture-ref={
                        harnessActiveRuntimeBinding.workerRollbackProof
                          .replayFixtureRef
                      }
                      onClick={() => {
                        const replayFixtureRef =
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .replayFixtureRef;
                        if (!replayFixtureRef) return;
                        onSelectHarnessReplayFixtureRef?.(replayFixtureRef);
                        onCopyHarnessDeepLink?.({
                          panel: "outputs",
                          replayFixtureRef,
                        });
                      }}
                    >
                      <code>
                        {
                          harnessActiveRuntimeBinding.workerRollbackProof
                            .replayFixtureRef
                        }
                      </code>
                    </button>
                  ) : null}
                  {harnessActiveRuntimeBinding.receiptRefs
                    .slice(0, 4)
                    .map((receiptRef, index: number) => (
                      <button
                        key={receiptRef}
                        type="button"
                        className={`workflow-harness-ref-button ${
                          selectedHarnessReceiptRef === receiptRef
                            ? "is-active"
                            : ""
                        }`}
                        data-testid={`workflow-harness-active-runtime-binding-receipt-${index}`}
                        data-deep-link-kind="receipt"
                        data-receipt-ref={receiptRef}
                        onClick={() => {
                          onSelectHarnessReceiptRef?.(receiptRef);
                          onCopyHarnessDeepLink?.({
                            panel: "outputs",
                            receiptRef,
                          });
                        }}
                      >
                        <code>{receiptRef}</code>
                      </button>
                    ))}
                  {harnessActiveRuntimeBinding.replayFixtureRefs
                    .slice(0, 4)
                    .map((replayFixtureRef, index: number) => (
                      <button
                        key={replayFixtureRef}
                        type="button"
                        className={`workflow-harness-ref-button ${
                          selectedHarnessReplayFixtureRef === replayFixtureRef
                            ? "is-active"
                            : ""
                        }`}
                        data-testid={`workflow-harness-active-runtime-binding-replay-${index}`}
                        data-deep-link-kind="replay_fixture"
                        data-replay-fixture-ref={replayFixtureRef}
                        onClick={() => {
                          onSelectHarnessReplayFixtureRef?.(replayFixtureRef);
                          onCopyHarnessDeepLink?.({
                            panel: "outputs",
                            replayFixtureRef,
                          });
                        }}
                      >
                        <code>{replayFixtureRef}</code>
                      </button>
                    ))}
                </div>
                {harnessActiveRuntimeBinding.blockers.length > 0 ? (
                  <div
                    className="workflow-rail-list"
                    data-testid="workflow-harness-active-runtime-binding-blockers"
                    data-activation-blockers={harnessActiveRuntimeBinding.blockers.join(
                      "|",
                    )}
                  >
                    {harnessActiveRuntimeBinding.blockers.map((blocker) => (
                      <article
                        key={blocker}
                        className="workflow-test-row is-blocked"
                      >
                        <strong>Blocked</strong>
                        <span>{blocker}</span>
                      </article>
                    ))}
                  </div>
                ) : null}
              </section>
            ) : null}
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-worker-binding-inspector"
              data-binding-status={harnessBindingInspectorStatus}
              data-component-version-count={harnessBindingVersionEntries.length}
            >
              <h4>Worker binding inspector</h4>
              <dl
                className="workflow-rail-stats"
                data-testid="workflow-harness-worker-binding-summary"
              >
                <div>
                  <dt>Current</dt>
                  <dd>
                    {harnessCurrentWorkerBinding?.harnessActivationId ??
                      workflow.metadata.harness?.activationId ??
                      "blocked"}
                  </dd>
                </div>
                <div>
                  <dt>Candidate</dt>
                  <dd>
                    {harnessActivationCandidate?.activationIdPreview ??
                      harnessActivationCandidate?.decision ??
                      "none"}
                  </dd>
                </div>
                <div>
                  <dt>Versions</dt>
                  <dd>{harnessBindingVersionEntries.length}</dd>
                </div>
                <div>
                  <dt>Rollback</dt>
                  <dd>
                    {harnessBindingRollbackAvailable ? "ready" : "blocked"}
                  </dd>
                </div>
                <div>
                  <dt>History</dt>
                  <dd>{harnessActivationAudit.length}</dd>
                </div>
                <div>
                  <dt>Drill</dt>
                  <dd>
                    {harnessActivationRollbackProof?.drillStatus ?? "not_run"}
                  </dd>
                </div>
                <div>
                  <dt>Revision</dt>
                  <dd>{harnessRevisionBinding?.revisionSource ?? "unbound"}</dd>
                </div>
              </dl>
              <div
                className="workflow-rail-list"
                data-testid="workflow-harness-worker-binding-picker"
              >
                <article
                  className={`workflow-output-row is-${
                    harnessCurrentWorkerBinding ? "ready" : "blocked"
                  }`}
                  data-testid="workflow-harness-worker-binding-option-current"
                  data-binding-source={
                    harnessCurrentWorkerBinding?.source ?? "unbound"
                  }
                >
                  <strong>
                    {harnessCurrentWorkerBinding?.harnessWorkflowId ??
                      workflow.metadata.harness?.harnessWorkflowId ??
                      "unbound"}
                  </strong>
                  <span>
                    current ·{" "}
                    {harnessCurrentWorkerBinding?.harnessActivationId ??
                      workflow.metadata.harness?.activationId ??
                      "activation blocked"}
                  </span>
                  <small>
                    {harnessCurrentWorkerBinding?.executionMode ??
                      workflow.metadata.harness?.executionMode ??
                      "projection"}{" "}
                    ·{" "}
                    {harnessCurrentWorkerBinding?.harnessHash ??
                      workflow.metadata.harness?.harnessHash ??
                      "hash pending"}
                  </small>
                </article>
                <article
                  className={`workflow-output-row is-${
                    harnessActivationCandidate?.decision === "mintable"
                      ? "ready"
                      : "blocked"
                  }`}
                  data-testid="workflow-harness-worker-binding-option-candidate"
                  data-candidate-decision={
                    harnessActivationCandidate?.decision ?? "not_generated"
                  }
                >
                  <strong>
                    {harnessCandidateWorkerBinding?.harnessWorkflowId ??
                      workflow.metadata.harness?.packageName ??
                      "candidate pending"}
                  </strong>
                  <span>
                    candidate ·{" "}
                    {harnessCandidateWorkerBinding?.harnessActivationId ??
                      harnessActivationCandidate?.activationIdPreview ??
                      "activation blocked"}
                  </span>
                  <small>
                    {harnessCandidateWorkerBinding?.source ?? "fork"} ·{" "}
                    {harnessCandidateWorkerBinding?.harnessHash ??
                      workflow.metadata.harness?.harnessHash ??
                      "hash pending"}
                  </small>
                </article>
                <article
                  className={`workflow-output-row is-${
                    harnessBindingRollbackAvailable ? "ready" : "blocked"
                  }`}
                  data-testid="workflow-harness-worker-binding-option-rollback"
                  data-rollback-available={
                    harnessBindingRollbackAvailable ? "true" : "false"
                  }
                >
                  <strong>{harnessSelectedRollbackTarget}</strong>
                  <span>
                    rollback ·{" "}
                    {harnessActivationRecord?.canaryStatus ??
                      workflow.metadata.harness?.activationState ??
                      "not_run"}
                  </span>
                  <small>{harnessBindingRollbackHash}</small>
                </article>
              </div>
              <div
                className="workflow-harness-authority-gate-actions"
                data-testid="workflow-harness-worker-binding-rollback-targets"
              >
                {harnessBindingRollbackTargets.map((rollbackTarget, index: number) => (
                  <button
                    key={rollbackTarget}
                    type="button"
                    className={`workflow-harness-ref-button ${
                      rollbackTarget === harnessSelectedRollbackTarget
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-worker-binding-rollback-target-${index}`}
                    data-rollback-target={rollbackTarget}
                    onClick={() =>
                      onSelectHarnessRollbackTarget?.(rollbackTarget)
                    }
                  >
                    <code>{rollbackTarget}</code>
                  </button>
                ))}
              </div>
              <div
                className="workflow-rail-list"
                data-testid="workflow-harness-worker-binding-version-set"
              >
                {harnessBindingVersionEntries
                  .slice(0, 8)
                  .map(([componentId, version]) => (
                    <article
                      key={componentId}
                      className="workflow-test-row"
                      data-testid={`workflow-harness-worker-binding-version-${componentId}`}
                    >
                      <strong>{componentId}</strong>
                      <span>{version}</span>
                    </article>
                  ))}
                {harnessBindingVersionEntries.length > 8 ? (
                  <article className="workflow-output-row">
                    <strong>
                      {harnessBindingVersionEntries.length - 8} more component
                      versions
                    </strong>
                    <span>
                      Full version set remains bound in activation metadata.
                    </span>
                  </article>
                ) : null}
              </div>
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-revision-binding"
                data-revision-source={
                  harnessRevisionBinding?.revisionSource ?? "unbound"
                }
                data-current-revision-binding-ref={
                  harnessRevisionBindingRef ?? ""
                }
                data-candidate-revision-binding-ref={
                  harnessCandidateRevisionBindingRef ?? ""
                }
                data-rollback-revision-binding-ref={
                  harnessRollbackRevisionBindingRef ?? ""
                }
                data-selected-revision-binding-kind={
                  selectedHarnessRevisionBindingKind ?? ""
                }
                data-selected-revision-binding-ref={
                  selectedHarnessRevisionBindingRef ?? ""
                }
              >
                <h4>Source control posture</h4>
                <div className="workflow-rail-list">
                  <button
                    type="button"
                    className={`workflow-output-row is-${
                      harnessRevisionBinding ? "ready" : "blocked"
                    }`}
                    data-testid="workflow-harness-revision-binding-current"
                    data-revision-binding-kind="current"
                    data-revision-binding-ref={harnessRevisionBindingRef ?? ""}
                    disabled={
                      !harnessRevisionBindingRef || !onCopyHarnessDeepLink
                    }
                    onClick={() =>
                      harnessRevisionBindingRef &&
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        revisionBindingKind: "current",
                        revisionBindingRef: harnessRevisionBindingRef,
                      })
                    }
                  >
                    <strong>
                      {harnessRevisionBinding?.workflowPath ??
                        "workflow path pending"}
                    </strong>
                    <span>
                      {harnessRevisionBinding?.branch ??
                        workflow.metadata.branch ??
                        "main"}{" "}
                      · {harnessRevisionBinding?.revisionSource ?? "unbound"}
                    </span>
                    <small>
                      {harnessRevisionBinding?.activatedRevision ??
                        harnessRevisionBinding?.workflowContentHash ??
                        "content hash pending"}
                    </small>
                  </button>
                  <button
                    type="button"
                    className={`workflow-output-row is-${
                      harnessCandidateRevisionBinding ? "ready" : "blocked"
                    }`}
                    data-testid="workflow-harness-revision-binding-candidate"
                    data-revision-binding-kind="candidate"
                    data-revision-binding-ref={
                      harnessCandidateRevisionBindingRef ?? ""
                    }
                    disabled={
                      !harnessCandidateRevisionBindingRef ||
                      !onCopyHarnessDeepLink
                    }
                    onClick={() =>
                      harnessCandidateRevisionBindingRef &&
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        revisionBindingKind: "candidate",
                        revisionBindingRef: harnessCandidateRevisionBindingRef,
                      })
                    }
                  >
                    <strong>
                      {harnessCandidateRevisionBinding?.activationId ??
                        "candidate pending"}
                    </strong>
                    <span>
                      proposal{" "}
                      {harnessCandidateRevisionBinding?.proposalId ?? "none"} ·{" "}
                      {harnessCandidateRevisionBinding?.workflowContentHash ??
                        "hash pending"}
                    </span>
                    <small>
                      {harnessCandidateRevisionBinding?.workflowPath ??
                        "Run dry run binding"}
                    </small>
                  </button>
                  <button
                    type="button"
                    className={`workflow-output-row is-${
                      harnessRollbackRevisionBinding ? "ready" : "blocked"
                    }`}
                    data-testid="workflow-harness-revision-binding-rollback"
                    data-revision-binding-kind="rollback"
                    data-revision-binding-ref={
                      harnessRollbackRevisionBindingRef ?? ""
                    }
                    disabled={
                      !harnessRollbackRevisionBindingRef ||
                      !onCopyHarnessDeepLink
                    }
                    onClick={() =>
                      harnessRollbackRevisionBindingRef &&
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        revisionBindingKind: "rollback",
                        revisionBindingRef: harnessRollbackRevisionBindingRef,
                      })
                    }
                  >
                    <strong>
                      {harnessRollbackRevisionBinding?.activationId ??
                        harnessSelectedRollbackTarget}
                    </strong>
                    <span>
                      rollback revision{" "}
                      {harnessRevisionBinding?.rollbackRevision ??
                        harnessRollbackRevisionBinding?.activatedRevision ??
                        "pending"}
                    </span>
                    <small>
                      {harnessRollbackRevisionBinding?.workflowPath ??
                        "Rollback target revision will appear after drill."}
                    </small>
                  </button>
                </div>
              </section>
              {harnessForkWorkflow ? (
                <div
                  className="workflow-harness-activation-actions"
                  data-testid="workflow-harness-worker-binding-actions"
                >
                  <button
                    type="button"
                    data-testid="workflow-harness-worker-binding-refresh-candidate"
                    onClick={onRunHarnessActivationDryRun}
                  >
                    Dry run binding
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-worker-binding-check-readiness"
                    onClick={onCheckActivationReadiness}
                  >
                    Check binding
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-worker-binding-apply-candidate"
                    disabled={
                      harnessActivationCandidate?.decision !== "mintable" ||
                      !onApplyHarnessActivationCandidate
                    }
                    onClick={onApplyHarnessActivationCandidate}
                  >
                    Mint activation
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-worker-binding-run-rollback-drill"
                    disabled={!onRunHarnessRollbackDrill}
                    onClick={onRunHarnessRollbackDrill}
                  >
                    Run rollback drill
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-worker-binding-execute-rollback"
                    disabled={!onExecuteHarnessRollback}
                    onClick={onExecuteHarnessRollback}
                  >
                    Execute rollback
                  </button>
                </div>
              ) : null}
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-rollback-drill-proof"
                data-drill-status={
                  harnessActivationRollbackProof?.drillStatus ?? "not_run"
                }
                data-receipt-refs={harnessRollbackDrillReceiptRefs.join("|")}
              >
                <h4>Rollback proof</h4>
                <article
                  className={`workflow-output-row is-${
                    harnessActivationRollbackProof?.drillStatus === "passed"
                      ? "ready"
                      : "blocked"
                  }`}
                  data-receipt-refs={harnessRollbackDrillReceiptRefs.join("|")}
                >
                  <strong>
                    {harnessActivationRollbackProof?.rollbackTarget ??
                      harnessSelectedRollbackTarget}
                  </strong>
                  <span>
                    executed{" "}
                    {harnessActivationRollbackProof?.rollbackExecuted
                      ? "yes"
                      : "not yet"}
                    {" · "}
                    restored{" "}
                    {harnessActivationRollbackProof?.restoredWorkerBinding
                      ?.harnessActivationId ??
                      harnessActivationRollbackProof?.restoredWorkerBinding
                        ?.harnessWorkflowId ??
                      "pending"}
                  </span>
                  <small>
                    {harnessRollbackDrillReceiptRefs[0] ??
                      harnessActivationRollbackProof?.policyDecision ??
                      "rollback drill pending"}
                  </small>
                </article>
                {harnessRollbackDrillReceiptRefs.length > 0 ? (
                  <div
                    className="workflow-harness-authority-gate-actions"
                    data-testid="workflow-harness-rollback-drill-receipt-refs"
                  >
                    {harnessRollbackDrillReceiptRefs.map(
                      (receiptRef, index: number) => (
                        <button
                          key={receiptRef}
                          type="button"
                          className={`workflow-harness-ref-button ${
                            selectedHarnessReceiptRef === receiptRef
                              ? "is-active"
                              : ""
                          }`}
                          data-testid={`workflow-harness-rollback-drill-receipt-${index}`}
                          data-receipt-ref={receiptRef}
                          onClick={() =>
                            onSelectHarnessReceiptRef?.(receiptRef)
                          }
                        >
                          <code>{receiptRef}</code>
                        </button>
                      ),
                    )}
                  </div>
                ) : null}
              </section>
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-rollback-execution-proof"
                data-execution-status={
                  harnessActivationRollbackExecution?.executionStatus ??
                  "not_run"
                }
                data-receipt-refs={harnessRollbackExecutionReceiptRefs.join(
                  "|",
                )}
                data-restore-receipt-binding-ref={
                  harnessActivationRollbackExecution?.restoreReceiptBindingRef ??
                  ""
                }
              >
                <h4>Rollback execution</h4>
                <article
                  className={`workflow-output-row is-${
                    harnessActivationRollbackExecution?.executionStatus ===
                    "applied"
                      ? "ready"
                      : "blocked"
                  }`}
                  data-receipt-refs={harnessRollbackExecutionReceiptRefs.join(
                    "|",
                  )}
                >
                  <strong>
                    {harnessActivationRollbackExecution?.rollbackTarget ??
                      harnessSelectedRollbackTarget}
                  </strong>
                  <span>
                    executed{" "}
                    {harnessActivationRollbackExecution?.rollbackExecuted
                      ? "yes"
                      : "not yet"}
                    {" · "}
                    hash{" "}
                    {harnessActivationRollbackExecution?.hashVerified
                      ? "verified"
                      : "pending"}
                  </span>
                  <small>
                    {harnessRollbackExecutionReceiptRefs[0] ??
                      harnessActivationRollbackExecution?.policyDecision ??
                      "rollback execution pending"}
                  </small>
                </article>
                {harnessRollbackExecutionReceiptRefs.length > 0 ? (
                  <div
                    className="workflow-harness-authority-gate-actions"
                    data-testid="workflow-harness-rollback-execution-receipt-refs"
                  >
                    {harnessRollbackExecutionReceiptRefs.map(
                      (receiptRef, index: number) => (
                        <button
                          key={receiptRef}
                          type="button"
                          className={`workflow-harness-ref-button ${
                            selectedHarnessReceiptRef === receiptRef
                              ? "is-active"
                              : ""
                          }`}
                          data-testid={`workflow-harness-rollback-execution-receipt-${index}`}
                          data-receipt-ref={receiptRef}
                          onClick={() =>
                            onSelectHarnessReceiptRef?.(receiptRef)
                          }
                        >
                          <code>{receiptRef}</code>
                        </button>
                      ),
                    )}
                  </div>
                ) : null}
                {harnessActivationRollbackExecution ? (
                  <div className="workflow-inline-metadata">
                    <span>
                      {harnessActivationRollbackExecution.restoreStrategy}
                    </span>
                    <code>
                      {harnessActivationRollbackExecution.actualWorkflowContentHash ??
                        "hash pending"}
                    </code>
                  </div>
                ) : null}
              </section>
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-git-restore-proof"
                data-restore-strategy={
                  harnessActivationRollbackExecution?.restoreStrategy ??
                  "not_run"
                }
                data-restore-blockers={
                  harnessActivationRollbackExecution?.restoreBlockers?.length ??
                  0
                }
              >
                <h4>Git restore proof</h4>
                <article
                  className={`workflow-output-row is-${
                    harnessActivationRollbackExecution?.restoreBlockers?.length
                      ? "blocked"
                      : harnessActivationRollbackExecution?.executionStatus ===
                          "applied"
                        ? "ready"
                        : "blocked"
                  }`}
                  data-testid="workflow-harness-git-restore-summary"
                >
                  <strong>
                    {harnessActivationRollbackExecution?.restoredRevision ??
                      harnessActivationRollbackExecution
                        ?.restoredRevisionBinding?.activatedRevision ??
                      "revision pending"}
                  </strong>
                  <span>
                    {harnessActivationRollbackExecution?.restoreStrategy ??
                      "git restore not run"}
                    {" · "}
                    {harnessActivationRollbackExecution?.restoredFileSha256 ??
                      "file sha pending"}
                  </span>
                  <small>
                    {harnessActivationRollbackExecution?.restoreRelativeWorkflowPath ??
                      harnessActivationRollbackExecution?.workflowPath ??
                      "workflow path pending"}
                  </small>
                </article>
                <div
                  className="workflow-inline-metadata"
                  data-testid="workflow-harness-git-restore-paths"
                >
                  <span>
                    {harnessActivationRollbackExecution?.restoreRepoRoot ??
                      "repo root pending"}
                  </span>
                  <code>
                    {harnessActivationRollbackExecution?.restoreRelativeWorkflowPath ??
                      harnessActivationRollbackExecution?.workflowPath ??
                      "relative path pending"}
                  </code>
                </div>
                <div
                  className="workflow-inline-metadata"
                  data-testid="workflow-harness-git-restore-hashes"
                >
                  <span>
                    expected{" "}
                    {harnessActivationRollbackExecution?.expectedWorkflowContentHash ??
                      "pending"}
                  </span>
                  <code>
                    actual{" "}
                    {harnessActivationRollbackExecution?.actualWorkflowContentHash ??
                      "pending"}
                  </code>
                </div>
                {harnessActivationRollbackExecution?.restoreBlockers?.length ? (
                  <div
                    className="workflow-rail-list"
                    data-testid="workflow-harness-git-restore-blockers"
                  >
                    {harnessActivationRollbackExecution.restoreBlockers.map(
                      (blocker, index: number) => (
                        <article
                          key={`${blocker}-${index}`}
                          className="workflow-test-row is-blocked"
                          data-testid={`workflow-harness-git-restore-blocker-${index}`}
                        >
                          <strong>{blocker}</strong>
                          <span>restore blocker</span>
                        </article>
                      ),
                    )}
                  </div>
                ) : null}
              </section>
              <section
                className="workflow-rail-section"
                data-testid="workflow-harness-activation-audit"
                data-audit-count={harnessActivationAudit.length}
                data-receipt-refs={harnessActivationAuditReceiptRefs.join("|")}
                data-selected-activation-audit-event-id={
                  selectedHarnessActivationAuditEventId ?? ""
                }
              >
                <h4>Activation audit</h4>
                <article
                  className="workflow-output-row"
                  data-testid="workflow-harness-activation-audit-summary"
                  data-receipt-refs={latestHarnessActivationAuditReceiptRefs.join(
                    "|",
                  )}
                >
                  <strong>
                    {latestHarnessActivationAudit?.eventType ??
                      "no audit events"}
                  </strong>
                  <span>
                    {latestHarnessActivationAudit?.status ?? "pending"} ·{" "}
                    {latestHarnessActivationAudit?.rollbackTarget ??
                      "rollback not selected"}
                  </span>
                  <small>
                    {latestHarnessActivationAuditReceiptRefs[0] ??
                      latestHarnessActivationAudit?.summary ??
                      "Run a dry run to create history."}
                  </small>
                </article>
                {latestHarnessActivationAuditReceiptRefs.length > 0 ? (
                  <div
                    className="workflow-harness-authority-gate-actions"
                    data-testid="workflow-harness-activation-audit-summary-receipts"
                  >
                    {latestHarnessActivationAuditReceiptRefs.map(
                      (receiptRef, index: number) => (
                        <button
                          key={receiptRef}
                          type="button"
                          className={`workflow-harness-ref-button ${
                            selectedHarnessReceiptRef === receiptRef
                              ? "is-active"
                              : ""
                          }`}
                          data-testid={`workflow-harness-activation-audit-summary-receipt-${index}`}
                          data-receipt-ref={receiptRef}
                          onClick={() =>
                            onSelectHarnessReceiptRef?.(receiptRef)
                          }
                        >
                          <code>{receiptRef}</code>
                        </button>
                      ),
                    )}
                  </div>
                ) : null}
                <div
                  className="workflow-rail-list"
                  data-testid="workflow-harness-activation-audit-list"
                >
                  {harnessActivationAudit.slice(-6).map((event) => {
                    const eventReceiptRefs = workflowUniqueReceiptRefs(
                      event.receiptRefs ?? [],
                    );
                    return (
                      <article
                        key={event.eventId}
                        className={`workflow-test-row is-${
                          event.status === "blocked" ? "blocked" : "passed"
                        } ${
                          selectedHarnessActivationAuditEventId ===
                          event.eventId
                            ? "is-active"
                            : ""
                        }`}
                        data-testid={`workflow-harness-activation-audit-event-${event.eventId}`}
                        data-audit-event-id={event.eventId}
                        data-audit-event-type={event.eventType}
                        data-audit-receipt-refs={eventReceiptRefs.join("|")}
                      >
                        <strong>{event.eventType}</strong>
                        <span>
                          {event.status} ·{" "}
                          {event.activationId ??
                            event.nextActivationId ??
                            "no activation"}
                        </span>
                        <small>{eventReceiptRefs[0] ?? event.summary}</small>
                        {eventReceiptRefs.length > 0 ||
                        onCopyHarnessDeepLink ? (
                          <div
                            className="workflow-harness-authority-gate-actions"
                            data-testid={`workflow-harness-activation-audit-receipts-${event.eventId}`}
                          >
                            {onCopyHarnessDeepLink ? (
                              <button
                                type="button"
                                className={`workflow-harness-ref-button ${
                                  selectedHarnessActivationAuditEventId ===
                                  event.eventId
                                    ? "is-active"
                                    : ""
                                }`}
                                data-testid={`workflow-harness-activation-audit-event-link-${event.eventId}`}
                                data-activation-audit-event-id={event.eventId}
                                onClick={() =>
                                  onCopyHarnessDeepLink?.({
                                    panel: "settings",
                                    activationAuditEventId: event.eventId,
                                  })
                                }
                              >
                                <code>{event.eventId}</code>
                              </button>
                            ) : null}
                            {eventReceiptRefs.map((receiptRef, index: number) => (
                              <button
                                key={receiptRef}
                                type="button"
                                className={`workflow-harness-ref-button ${
                                  selectedHarnessReceiptRef === receiptRef
                                    ? "is-active"
                                    : ""
                                }`}
                                data-testid={`workflow-harness-activation-audit-receipt-${event.eventId}-${index}`}
                                data-receipt-ref={receiptRef}
                                onClick={() =>
                                  onSelectHarnessReceiptRef?.(receiptRef)
                                }
                              >
                                <code>{receiptRef}</code>
                              </button>
                            ))}
                          </div>
                        ) : null}
                      </article>
                    );
                  })}
                </div>
              </section>
            </section>
            {harnessForkWorkflow || blessedHarnessWorkflow ? (
              <section
                className="workflow-rail-section workflow-harness-activation-wizard"
                data-testid="workflow-harness-activation-wizard"
                data-activation-state={
                  workflow.metadata.harness?.activationState ?? "blocked"
                }
              >
                <h4>Activation wizard</h4>
                <dl
                  className="workflow-rail-stats"
                  data-testid="workflow-harness-activation-wizard-summary"
                >
                  <div>
                    <dt>State</dt>
                    <dd>
                      {workflow.metadata.harness?.activationState ?? "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Policy</dt>
                    <dd>
                      {harnessActivationRecord?.policyPosture ??
                        "proposal_only"}
                    </dd>
                  </div>
                  <div>
                    <dt>Canary</dt>
                    <dd>
                      {harnessActivationRecord?.canaryStatus ?? "not_run"}
                    </dd>
                  </div>
                  <div>
                    <dt>Rollback</dt>
                    <dd>{rollbackReady ? "ready" : "blocked"}</dd>
                  </div>
                  <div>
                    <dt>Handoff</dt>
                    <dd>
                      {harnessActivationWorkerHandoffTimelineReady
                        ? "timeline"
                        : "blocked"}
                    </dd>
                  </div>
                  <div>
                    <dt>Invariant</dt>
                    <dd>
                      {harnessActivationWorkerInvariantReady
                        ? "bound"
                        : "blocked"}
                    </dd>
                  </div>
                </dl>
                <article
                  className={`workflow-output-row is-${harnessActivationReady ? "ready" : "blocked"}`}
                  data-testid={
                    harnessActivationReady
                      ? "workflow-harness-activation-minted-proof"
                      : "workflow-harness-activation-blocked-proof"
                  }
                  data-worker-handoff-node-timeline-bound={
                    harnessActivationWorkerHandoffTimelineReady
                      ? "true"
                      : "false"
                  }
                  data-worker-handoff-node-attempt-count={
                    harnessActivationWorkerHandoffNodeAttempts.length
                  }
                  data-worker-handoff-node-attempt-ids={harnessActivationWorkerHandoffNodeAttemptIds.join(
                    ",",
                  )}
                  data-worker-handoff-replay-fixture-refs={harnessActivationWorkerHandoffReplayFixtureRefs.join(
                    ",",
                  )}
                  data-worker-launch-reviewed-import-invariant-bound={
                    harnessActivationWorkerInvariantReady ? "true" : "false"
                  }
                  data-worker-required-invariant-ids={harnessActivationWorkerRequiredInvariantIds.join(
                    ",",
                  )}
                  data-worker-invariant-blockers={harnessActivationWorkerInvariantBlockers.join(
                    ",",
                  )}
                >
                  <strong>
                    {harnessActivationReady
                      ? workflow.metadata.harness?.activationId
                      : "Activation blocked"}
                  </strong>
                  <span>
                    {harnessActivationReady
                      ? "activation id minted and worker binding validated"
                      : `${harnessActivationBlockers.length} blocker${
                          harnessActivationBlockers.length === 1 ? "" : "s"
                        } remain`}
                  </span>
                  <small>
                    rollback{" "}
                    {harnessActivationRecord?.rollbackTarget ?? "not set"} ·
                    worker{" "}
                    {harnessWorkerBinding?.harnessWorkflowId ?? "unbound"} ·
                    handoff {harnessActivationWorkerHandoffNodeAttempts.length}
                  </small>
                  <small>
                    invariant{" "}
                    {
                      DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT
                    }{" "}
                    ·{" "}
                    {harnessActivationWorkerInvariantReady
                      ? "bound"
                      : "blocked"}
                  </small>
                </article>
                {harnessActivationCandidate ? (
                  <section
                    className="workflow-rail-section"
                    data-testid="workflow-harness-activation-candidate"
                    data-candidate-decision={
                      harnessActivationCandidate.decision
                    }
                  >
                    <h4>Dry run candidate</h4>
                    <article
                      className={`workflow-output-row is-${
                        harnessActivationCandidate.decision === "mintable"
                          ? "ready"
                          : "blocked"
                      }`}
                      data-testid="workflow-harness-activation-candidate-decision"
                    >
                      <strong>{harnessActivationCandidate.candidateId}</strong>
                      <span>
                        {harnessActivationCandidate.decision}
                        {" · "}
                        {harnessActivationCandidate.activationIdPreview ??
                          "activation id blocked"}
                      </span>
                      <small>
                        canary {harnessActivationCandidate.canaryStatus} ·
                        rollback{" "}
                        {harnessActivationCandidate.rollbackAvailable
                          ? harnessActivationCandidate.rollbackTarget
                          : "blocked"}
                      </small>
                    </article>
	                    <article
	                      className="workflow-output-row"
	                      data-testid="workflow-harness-fork-mutation-canary"
	                      data-harness-fork-mutation-canary-id={
	                        harnessActivationCandidate.forkMutationCanary.canaryId
	                      }
	                      data-harness-fork-mutation-status={
	                        harnessActivationCandidate.forkMutationCanary.status
	                      }
	                      data-harness-fork-mutation-kind={
	                        harnessActivationCandidate.forkMutationCanary
	                          .mutationKind
	                      }
	                      data-harness-fork-mutation-diff-hash={
	                        harnessActivationCandidate.forkMutationCanary.diffHash
	                      }
	                      data-harness-fork-mutation-receipt-count={
	                        harnessActivationCandidate.forkMutationCanary
	                          .receiptRefs.length
	                      }
	                      data-harness-fork-mutation-replay-count={
	                        harnessActivationCandidate.forkMutationCanary
	                          .replayFixtureRefs.length
	                      }
	                      data-harness-fork-mutation-node-attempt-count={
	                        harnessActivationCandidate.forkMutationCanary
	                          .nodeAttemptIds.length
	                      }
	                    >
	                      <strong>
	                        {
	                          harnessActivationCandidate.forkMutationCanary
	                            .mutationKind
	                        }
	                      </strong>
	                      <span>
	                        {
	                          harnessActivationCandidate.forkMutationCanary
	                            .targetPath
	                        }
	                        {" · "}
	                        {
	                          harnessActivationCandidate.forkMutationCanary
	                            .status
	                        }
	                      </span>
	                      <small>
	                        {
	                          harnessActivationCandidate.forkMutationCanary
	                            .beforeValue
	                        }
	                        {" -> "}
	                        {
	                          harnessActivationCandidate.forkMutationCanary
	                            .afterValue
	                        }
	                        {" · "}
	                        {
	                          harnessActivationCandidate.forkMutationCanary
	                            .policyDecision
	                        }
	                      </small>
	                    </article>
	                    <article
	                      className="workflow-output-row"
	                      data-testid="workflow-harness-activation-candidate-worker-binding"
	                    >
                      <strong>
                        {
                          harnessActivationCandidate.workerBindingPreview
                            .harnessWorkflowId
                        }
                      </strong>
                      <span>
                        {harnessActivationCandidate.workerBindingPreview
                          .harnessActivationId ?? "activation blocked"}
                      </span>
                      <small>
                        {harnessActivationCandidate.workerBindingPreview.source}{" "}
                        ·{" "}
                        {
                          harnessActivationCandidate.workerBindingPreview
                            .harnessHash
                        }
                      </small>
                    </article>
                    <article
                      className={`workflow-output-row is-${
                        harnessActivationCandidate.rollbackRestoreCanary
                          .status === "passed" ||
                        harnessActivationCandidate.rollbackRestoreCanary
                          .status === "not_required"
                          ? "ready"
                          : "blocked"
                      }`}
                      data-testid="workflow-harness-rollback-restore-canary"
                      data-restore-canary-status={
                        harnessActivationCandidate.rollbackRestoreCanary.status
                      }
                      data-receipt-binding-ref={
                        harnessActivationCandidate.rollbackRestoreCanary
                          .receiptBindingRef ?? ""
                      }
                    >
                      <strong>
                        {harnessActivationCandidate.rollbackRestoreCanary
                          .restoredRevision ?? "restore canary pending"}
                      </strong>
                      <span>
                        {
                          harnessActivationCandidate.rollbackRestoreCanary
                            .restoreStrategy
                        }
                        {" · "}
                        {harnessActivationCandidate.rollbackRestoreCanary
                          .hashVerified
                          ? "hash verified"
                          : "hash blocked"}
                      </span>
                      <small>
                        {harnessActivationCandidate.rollbackRestoreCanary
                          .receiptBindingRef ??
                          harnessActivationCandidate.rollbackRestoreCanary
                            .relativeWorkflowPath ??
                          harnessActivationCandidate.rollbackRestoreCanary
                            .workflowPath}
                      </small>
                    </article>
                    <div
                      className="workflow-harness-activation-candidate-gates"
                      data-testid="workflow-harness-activation-candidate-gates"
                      data-selected-activation-gate-id={
                        selectedHarnessActivationGateId ?? ""
                      }
                    >
                      {harnessActivationCandidate.gateResults.map((gate) => {
                        const gateAction =
                          harnessActivationGateActions[gate.gateId] ?? null;
                        return (
                          <article
                            key={gate.gateId}
                            className={`workflow-test-row is-${gate.status} ${
                              selectedHarnessActivationGateId === gate.gateId
                                ? "is-active"
                                : ""
                            }`}
                            data-testid={`workflow-harness-activation-candidate-gate-${gate.gateId}`}
                            data-activation-gate-id={gate.gateId}
                            data-gate-action-id={gateAction?.actionId ?? ""}
                            data-gate-action-kind={gateAction?.kind ?? ""}
                            data-gate-action-impact={gateAction?.impact ?? ""}
                            data-gate-action-command={
                              gateAction?.commandTestId ?? ""
                            }
                          >
                            <strong>{gate.label}</strong>
                            <span>{gate.value}</span>
                            <small>{gate.detail}</small>
                            <div className="workflow-harness-authority-gate-actions">
                              {onCopyHarnessDeepLink ? (
                                <button
                                  type="button"
                                  className={`workflow-harness-ref-button ${
                                    selectedHarnessActivationGateId ===
                                    gate.gateId
                                      ? "is-active"
                                      : ""
                                  }`}
                                  data-testid={`workflow-harness-activation-candidate-gate-link-${gate.gateId}`}
                                  data-activation-gate-id={gate.gateId}
                                  onClick={() =>
                                    onCopyHarnessDeepLink?.({
                                      panel: "settings",
                                      activationGateId: gate.gateId,
                                    })
                                  }
                                >
                                  <code>{gate.gateId}</code>
                                </button>
                              ) : null}
                              {renderHarnessActivationGateAction(
                                gateAction,
                                `workflow-harness-activation-candidate-gate-action-${gate.gateId}`,
                              )}
                            </div>
                          </article>
                        );
                      })}
                    </div>
                    {harnessActivationCandidate.activationBlockers.length >
                    0 ? (
                      <div
                        className="workflow-rail-list"
                        data-testid="workflow-harness-activation-candidate-blockers"
                      >
                        {harnessActivationCandidate.activationBlockers
                          .slice(0, 5)
                          .map((blocker) => (
                            <article
                              key={blocker}
                              className="workflow-test-row is-blocked"
                            >
                              <strong>Blocked</strong>
                              <span>{blocker}</span>
                            </article>
                          ))}
                      </div>
                    ) : null}
                  </section>
                ) : (
                  <article
                    className="workflow-output-row"
                    data-testid="workflow-harness-activation-candidate-empty"
                  >
                    <strong>No activation candidate</strong>
                    <span>
                      Run a dry run to preview mintability without changing
                      activation state.
                    </span>
                    <small>
                      Dry-run candidates keep invalid forks blocked.
                    </small>
                  </article>
                )}
                <div
                  className="workflow-harness-activation-steps"
                  data-testid="workflow-harness-activation-steps"
                  data-selected-activation-gate-id={
                    selectedHarnessActivationGateId ?? ""
                  }
                >
                  {harnessActivationWizardSteps.map((step) => (
                    <article
                      key={step.id}
                      className={`workflow-test-row is-${step.ready ? "passed" : "blocked"} ${
                        selectedHarnessActivationGateId === step.id
                          ? "is-active"
                          : ""
                      }`}
                      data-testid={`workflow-harness-activation-step-${step.id}`}
                      data-activation-gate-id={step.id}
                      data-gate-action-id={step.gateAction.actionId}
                      data-gate-action-kind={step.gateAction.kind}
                      data-gate-action-impact={step.gateAction.impact}
                      data-gate-action-command={step.gateAction.commandTestId}
                      data-required-invariant-ids={(
                        step.requiredInvariantIds ?? []
                      ).join(",")}
                      data-invariant-blockers={(
                        step.invariantBlockers ?? []
                      ).join(",")}
                    >
                      <strong>{step.label}</strong>
                      <span>{step.value}</span>
                      <small>{step.detail}</small>
                      <div className="workflow-harness-authority-gate-actions">
                        {onCopyHarnessDeepLink ? (
                          <button
                            type="button"
                            className={`workflow-harness-ref-button ${
                              selectedHarnessActivationGateId === step.id
                                ? "is-active"
                                : ""
                            }`}
                            data-testid={`workflow-harness-activation-step-link-${step.id}`}
                            data-activation-gate-id={step.id}
                            onClick={() =>
                              onCopyHarnessDeepLink?.({
                                panel: "settings",
                                activationGateId: step.id,
                              })
                            }
                          >
                            <code>{step.id}</code>
                          </button>
                        ) : null}
                        {renderHarnessActivationGateAction(
                          step.gateAction,
                          `workflow-harness-activation-step-action-${step.id}`,
                        )}
                      </div>
                    </article>
                  ))}
                </div>
                {selectedHarnessActivationGateInspection ? (
                  <section
                    className="workflow-rail-section workflow-harness-activation-gate-inspector"
                    data-testid="workflow-harness-activation-gate-inspector"
                    data-selected-activation-gate-id={
                      selectedHarnessActivationGateInspection.gateId
                    }
                    data-selected-activation-gate-evidence-ref={
                      selectedHarnessActivationGateEvidenceRef ?? ""
                    }
                    data-selected-node-attempt-id={
                      selectedHarnessNodeAttemptId ?? ""
                    }
	                    data-selected-activation-gate-node-attempt-id={
	                      selectedHarnessActivationGateNodeAttemptId ?? ""
	                    }
	                    data-node-attempt-id={
	                      selectedHarnessActivationGateNodeAttempt?.attemptId ??
	                      selectedHarnessActivationGateNodeAttemptId ??
	                      ""
	                    }
	                    data-component-kind={
	                      selectedHarnessActivationGateNodeAttempt
	                        ?.componentKind ?? ""
	                    }
	                    data-component-id={
	                      selectedHarnessActivationGateNodeAttempt?.componentId ??
	                      ""
	                    }
	                    data-policy-decision={
	                      selectedHarnessActivationGateNodeAttempt
	                        ?.policyDecision ??
	                      selectedHarnessActivationGateMutationCanary
	                        ?.policyDecision ??
	                      ""
	                    }
	                    data-receipt-refs={
	                      selectedHarnessActivationGateNodeAttempt
	                        ?.receiptIds.join("|") ??
	                      selectedHarnessActivationGateInspection.receiptRefs.join(
	                        "|",
	                      )
	                    }
	                    data-replay-fixture-ref={
	                      selectedHarnessActivationGateNodeAttempt?.replay
	                        .fixtureRef ??
	                      selectedHarnessActivationGateInspection
	                        .replayFixtureRefs[0] ??
	                      ""
	                    }
	                    data-input-hash={
	                      selectedHarnessActivationGateNodeAttempt?.inputHash ?? ""
	                    }
	                    data-output-hash={
	                      selectedHarnessActivationGateNodeAttempt?.outputHash ??
	                      ""
	                    }
	                    data-mutation-diff-hash={
	                      selectedHarnessActivationGateMutationCanary?.diffHash ??
	                      ""
	                    }
	                    data-rollback-target={
	                      selectedHarnessActivationGateMutationCanary
	                        ?.rollbackTarget ?? ""
	                    }
	                    data-selected-activation-gate-receipt-ref={
	                      selectedHarnessActivationGateReceiptRef ?? ""
	                    }
                    data-selected-activation-gate-replay-fixture-ref={
                      selectedHarnessActivationGateReplayFixtureRef ?? ""
                    }
                    data-selected-canary-boundary-id={
                      selectedHarnessCanaryBoundary?.boundaryId ?? ""
                    }
                    data-selected-rollback-drill-id={
                      selectedHarnessRollbackDrillId
                    }
                    data-selected-rollback-restore-canary-id={
                      selectedHarnessRollbackRestoreCanaryId
                    }
                    data-selected-rollback-restore-receipt-ref={
                      selectedHarnessRollbackRestoreReceiptRef
                    }
                    data-gate-source-kind={
                      selectedHarnessActivationGateInspection.sourceKind
                    }
                    data-gate-status={
                      selectedHarnessActivationGateInspection.status
                    }
                    data-evidence-ref-count={
                      selectedHarnessActivationGateInspection.evidenceRefs
                        .length
                    }
                    data-node-attempt-ref-count={
                      selectedHarnessActivationGateInspection.nodeAttemptIds
                        .length
                    }
                    data-receipt-ref-count={
                      selectedHarnessActivationGateInspection.receiptRefs.length
                    }
                    data-replay-fixture-ref-count={
                      selectedHarnessActivationGateInspection.replayFixtureRefs
                        .length
                    }
                    data-required-invariant-ids={selectedHarnessActivationGateInspection.requiredInvariantIds.join(
                      ",",
                    )}
                    data-invariant-blockers={selectedHarnessActivationGateInspection.invariantBlockers.join(
                      ",",
                    )}
                    data-invariant-blocker-count={
                      selectedHarnessActivationGateInspection.invariantBlockers
                        .length
                    }
                    data-gate-action-id={
                      selectedHarnessActivationGateInspection.gateAction
                        ?.actionId ?? ""
                    }
                    data-gate-action-kind={
                      selectedHarnessActivationGateInspection.gateAction
                        ?.kind ?? ""
                    }
                    data-gate-action-impact={
                      selectedHarnessActivationGateInspection.gateAction
                        ?.impact ?? ""
                    }
                    data-gate-action-command={
                      selectedHarnessActivationGateInspection.gateAction
                        ?.commandTestId ?? ""
                    }
                    data-gate-action-disabled={
                      selectedHarnessActivationGateInspection.gateAction
                        ?.disabled
                        ? "true"
                        : "false"
                    }
                  >
                    <h4>Gate evidence</h4>
                    <article
                      className={`workflow-output-row is-${selectedHarnessActivationGateInspection.status}`}
                      data-testid="workflow-harness-activation-gate-summary"
                    >
                      <strong>
                        {selectedHarnessActivationGateInspection.label}
                      </strong>
                      <span>
                        {selectedHarnessActivationGateInspection.value}
                      </span>
                      <small>
                        {selectedHarnessActivationGateInspection.detail}
                      </small>
                      {selectedHarnessActivationGateInspection
                        .requiredInvariantIds.length > 0 ? (
                        <small>
                          invariants{" "}
                          {selectedHarnessActivationGateInspection.requiredInvariantIds.join(
                            ", ",
                          )}{" "}
                          · blockers{" "}
                          {
                            selectedHarnessActivationGateInspection
                              .invariantBlockers.length
                          }
                        </small>
                      ) : null}
                    </article>
                    <div
                      className="workflow-harness-authority-gate-actions"
                      data-testid="workflow-harness-activation-gate-actions"
                    >
                      {renderHarnessActivationGateAction(
                        selectedHarnessActivationGateInspection.gateAction,
                        "workflow-harness-activation-gate-action",
                      )}
                    </div>
                    {selectedHarnessActivationGateInspection.gateId ===
                    "package-evidence" ? (
                      <section
                        className="workflow-rail-list"
                        data-testid="workflow-harness-package-evidence-review"
                        data-harness-package-manifest-present={
                          harnessPackageManifest ? "true" : "false"
                        }
                        data-harness-package-schema-version={
                          harnessPackageManifest?.schemaVersion ?? ""
                        }
                        data-harness-package-evidence-ready={
                          harnessPackageEvidenceReady ? "true" : "false"
                        }
                        data-harness-package-evidence-blocker-count={
                          harnessPackageEvidenceBlockerCount
                        }
                        data-harness-package-evidence-ref-count={
                          harnessPackageEvidenceRefValues.length
                        }
                        data-harness-package-receipt-ref-count={
                          harnessPackageReceiptRefValues.length
                        }
                        data-harness-package-replay-fixture-ref-count={
                          harnessPackageReplayFixtureRefValues.length
                        }
	                        data-harness-package-rollback-restore-ref-count={
	                          harnessPackageRollbackRestoreReceiptRefs.length
	                        }
	                        data-harness-package-fork-mutation-canary-id={
	                          harnessPackageForkMutationCanary?.canaryId ?? ""
	                        }
	                        data-harness-package-fork-mutation-receipt-count={
	                          harnessPackageForkMutationCanaryReceiptRefs.length
	                        }
	                        data-harness-package-fork-mutation-replay-count={
	                          harnessPackageForkMutationCanaryReplayFixtureRefs.length
	                        }
	                        data-harness-package-fork-mutation-attempt-count={
	                          harnessPackageForkMutationCanaryNodeAttemptIds.length
	                        }
	                        data-harness-package-worker-handoff-attempt-count={
	                          harnessPackageWorkerHandoffNodeAttemptIds.length
	                        }
                        data-harness-package-worker-handoff-receipt-count={
                          harnessPackageWorkerHandoffReceiptIds.length
                        }
                        data-harness-package-deep-link-count={
                          harnessPackageDeepLinks.length
                        }
                      >
                        {packageImportReview ? (
                          <article
                            className={`workflow-test-row is-${
                              packageImportReview.evidence.packageEvidenceReady
                                ? "passed"
                                : "blocked"
                            }`}
                            data-testid="workflow-harness-package-import-review"
                            data-package-import-review-open="true"
                            data-package-import-source-workflow-path={
                              packageImportReview.source.sourceWorkflowPath ??
                              ""
                            }
                            data-package-import-source-workflow-id={
                              packageImportReview.source.workflowId ?? ""
                            }
                            data-package-import-source-activation-id={
                              packageImportReview.source.activationId ?? ""
                            }
                            data-package-import-source-workflow-content-hash={
                              packageImportReview.source.workflowContentHash ??
                              ""
                            }
                            data-package-import-source-harness-hash={
                              packageImportReview.source.harnessHash ?? ""
                            }
                            data-package-import-source-worker-binding-id={
                              packageImportReview.source
                                .workerBindingActivationId ?? ""
                            }
	                            data-package-import-source-policy-posture={
	                              packageImportReview.source.policyPosture ?? ""
	                            }
                            data-package-import-source-mutation-canary-id={
                              packageImportReview.source.forkMutationCanaryId ??
                              ""
                            }
                            data-package-import-source-mutation-canary-status={
                              packageImportReview.source
                                .forkMutationCanaryStatus ?? ""
                            }
                            data-package-import-source-mutation-canary-diff-hash={
                              packageImportReview.source
                                .forkMutationCanaryDiffHash ?? ""
                            }
                            data-package-import-source-mutation-canary-receipt-ref={
                              packageImportReview.source
                                .forkMutationCanaryReceiptRefs?.[0] ?? ""
                            }
                            data-package-import-source-mutation-canary-replay-fixture-ref={
                              packageImportReview.source
                                .forkMutationCanaryReplayFixtureRefs?.[0] ??
                              ""
                            }
                            data-package-import-source-mutation-canary-node-attempt-id={
                              packageImportReview.source
                                .forkMutationCanaryNodeAttemptIds?.[0] ?? ""
                            }
                            data-package-import-source-mutation-canary-rollback-target={
                              packageImportReview.source
                                .forkMutationCanaryRollbackTarget ?? ""
                            }
                            data-package-import-source-reviewed-package-snapshot-hash={
                              packageImportReview.source.reviewedPackageSnapshotHash ??
                              ""
                            }
                            data-package-import-source-chrome-locale={
                              packageImportReview.source.workflowChromeLocale ??
                              ""
                            }
                            data-package-import-source-replay-fixture-count={
                              packageImportReview.source.replayFixtureRefs
                                ?.length ?? 0
                            }
                            data-package-import-imported-workflow-path={
                              packageImportReview.imported.workflowPath
                            }
                            data-package-import-imported-workflow-id={
                              packageImportReview.imported.workflowId
                            }
                            data-package-import-imported-chrome-locale={
                              packageImportReview.imported
                                .workflowChromeLocale ?? ""
                            }
                            data-package-import-readiness-status={
                              packageImportReview.imported
                                .activationReadinessStatus ?? ""
                            }
                            data-package-import-evidence-ready={
                              packageImportReview.evidence.packageEvidenceReady
                                ? "true"
                                : "false"
                            }
                            data-package-import-chrome-locale-preserved={
                              packageImportReview.evidence
                                .workflowChromeLocalePreserved
                                ? "true"
                                : "false"
                            }
                            data-package-import-evidence-blocker-count={
                              packageImportReview.evidence.blockerCount
                            }
                            data-package-import-activation-enabled={
                              packageImportActivationEnabled ? "true" : "false"
                            }
                            data-package-import-replay-integrity-blocker-count={
                              packageImportReplayIntegrityBlockers.length
                            }
                            data-package-import-replay-integrity-blockers={
                              packageImportReplayIntegrityBlockers.join(",")
                            }
                          >
                            <strong>Import review</strong>
                            <span>
                              {packageImportReview.source.workflowName ??
                                packageImportReview.source.workflowId ??
                                "source package"}{" "}
                              to {packageImportReview.imported.workflowName}
                            </span>
                            <small>
                              {packageImportReview.evidence.packageEvidenceReady
                                ? "package evidence ready for activation"
                                : `${packageImportReview.evidence.blockerCount} package evidence blocker${
                                    packageImportReview.evidence
                                      .blockerCount === 1
                                      ? ""
                                      : "s"
                                  }`}
                            </small>
                            <div
                              className="workflow-harness-authority-gate-actions"
                              data-testid="workflow-harness-package-import-identity"
                            >
                              <div>
                                <strong>Source</strong>
                                <span>
                                  {packageImportReview.source.workflowSlug ??
                                    packageImportReview.source.workflowId ??
                                    "unknown"}
                                </span>
                                <small>
                                  {packageImportReview.source
                                    .sourceWorkflowPath ??
                                    packageImportReview.packagePath}
                                </small>
                                <small>
                                  Chrome locale{" "}
                                  {packageImportReview.source
                                    .workflowChromeLocale ?? "default"}
                                </small>
                              </div>
                              <div>
                                <strong>Imported</strong>
                                <span>
                                  {packageImportReview.imported.workflowSlug}
                                </span>
                                <small>
                                  {packageImportReview.imported.workflowPath}
                                </small>
                                <small>
                                  Chrome locale{" "}
                                  {packageImportReview.imported
                                    .workflowChromeLocale ?? "default"}
                                </small>
                              </div>
                            </div>
                            {packageImportActivationHandoff ? (
                              <section
                                className="workflow-rail-section"
                                data-testid="workflow-harness-package-import-handoff"
                                data-package-import-handoff-open="true"
                                data-package-import-handoff-decision={
                                  packageImportActivationHandoff.decision ?? ""
                                }
                                data-package-import-handoff-activation-id={
                                  packageImportActivationHandoff.activationIdPreview ??
                                  ""
                                }
	                                data-package-import-handoff-canary-status={
	                                  packageImportActivationHandoff.canaryStatus ??
	                                  ""
	                                }
	                                data-package-import-handoff-mutation-canary-id={
	                                  packageImportActivationHandoff
	                                    .forkMutationCanaryId ?? ""
	                                }
		                                data-package-import-handoff-mutation-canary-status={
		                                  packageImportActivationHandoff
		                                    .forkMutationCanaryStatus ?? ""
		                                }
                                data-package-import-handoff-mutation-canary-diff-hash={
                                  packageImportActivationHandoff
                                    .forkMutationCanaryDiffHash ?? ""
                                }
                                data-package-import-handoff-mutation-canary-receipt-ref={
                                  packageImportActivationHandoff
                                    .forkMutationCanaryReceiptRefs?.[0] ?? ""
                                }
                                data-package-import-handoff-mutation-canary-replay-fixture-ref={
                                  packageImportActivationHandoff
                                    .forkMutationCanaryReplayFixtureRefs?.[0] ??
                                  ""
                                }
                                data-package-import-handoff-mutation-canary-node-attempt-id={
                                  packageImportActivationHandoff
                                    .forkMutationCanaryNodeAttemptIds?.[0] ?? ""
                                }
                                data-package-import-handoff-mutation-canary-rollback-target={
                                  packageImportActivationHandoff
                                    .forkMutationCanaryRollbackTarget ?? ""
                                }
	                                data-package-import-handoff-rollback-target={
	                                  packageImportActivationHandoff.rollbackTarget ??
	                                  ""
                                }
                                data-package-import-handoff-rollback-available={
                                  packageImportActivationHandoff.rollbackAvailable
                                    ? "true"
                                    : "false"
                                }
                                data-package-import-handoff-worker-binding-id={
                                  packageImportHandoffWorkerBindingId
                                }
                                data-package-import-handoff-worker-workflow-id={
                                  packageImportActivationHandoff.workerBinding
                                    ?.harnessWorkflowId ?? ""
                                }
                                data-package-import-handoff-worker-hash={
                                  packageImportActivationHandoff.workerBinding
                                    ?.harnessHash ?? ""
                                }
                                data-package-import-handoff-workflow-content-hash={
                                  packageImportActivationHandoff.workflowContentHash ??
                                  ""
                                }
                                data-package-import-handoff-policy-posture={
                                  packageImportActivationHandoff.policyPosture ??
                                  ""
                                }
                                data-package-import-handoff-reviewed-package-snapshot-hash={
                                  packageImportActivationHandoff.reviewedPackageSnapshotHash ??
                                  ""
                                }
                                data-package-import-handoff-replay-fixture-count={
                                  packageImportActivationHandoff
                                    .replayFixtureRefs?.length ?? 0
                                }
                                data-package-import-handoff-mintable={
                                  packageImportActivationHandoff.mintable
                                    ? "true"
                                    : "false"
                                }
                                data-package-import-handoff-replay-integrity-blocker-count={
                                  packageImportReplayIntegrityBlockers.length
                                }
                                data-package-import-handoff-replay-integrity-blockers={
                                  packageImportReplayIntegrityBlockers.join(",")
                                }
                                data-package-import-handoff-blocker-count={
                                  packageImportActivationHandoff.blockerCount
                                }
                                data-package-import-handoff-package-evidence-ready={
                                  packageImportActivationHandoff.packageEvidenceReady
                                    ? "true"
                                    : "false"
                                }
                                data-package-import-handoff-activation-enabled={
                                  packageImportActivationEnabled
                                    ? "true"
                                    : "false"
                                }
                              >
                                <h4>Activation handoff</h4>
                                <article
                                  className={`workflow-output-row is-${
                                    packageImportActivationHandoff.mintable
                                      ? "ready"
                                      : "blocked"
                                  }`}
                                >
                                  <strong>
                                    {packageImportActivationHandoff.candidateId ??
                                      "handoff pending"}
                                  </strong>
                                  <span>
                                    {packageImportActivationHandoff.decision ??
                                      "unknown"}
                                    {" · "}
                                    {packageImportActivationHandoff.activationIdPreview ??
                                      "activation id blocked"}
                                  </span>
                                  <small>
	                                    canary{" "}
	                                    {packageImportActivationHandoff.canaryStatus ??
	                                      "not_run"}{" "}
	                                    · mutation{" "}
	                                    {packageImportActivationHandoff
	                                      .forkMutationCanaryStatus ??
	                                      "not_run"}{" "}
	                                    · rollback{" "}
                                    {packageImportActivationHandoff.rollbackTarget ??
                                      "not set"}{" "}
                                    · worker{" "}
                                    {packageImportHandoffWorkerBindingId ||
                                      "unbound"}
                                  </small>
                                </article>
                                <div
                                  className="workflow-harness-authority-gate-actions"
                                  data-testid="workflow-harness-package-import-handoff-links"
                                >
                                  <button
                                    type="button"
                                    className="workflow-harness-ref-button"
                                    data-testid="workflow-harness-package-import-handoff-activation-link"
                                    disabled={
                                      !packageImportActivationHandoff
                                        .deepLinkTargets.activationId
                                    }
                                    onClick={() =>
                                      onCopyHarnessDeepLink?.({
                                        panel: "settings",
                                        activationGateId: "activation-id",
                                        activationGateEvidenceRef:
                                          packageImportActivationHandoff
                                            .deepLinkTargets.activationId ??
                                          undefined,
                                      })
                                    }
                                  >
                                    <code>activation</code>
                                  </button>
                                  <button
                                    type="button"
                                    className="workflow-harness-ref-button"
                                    data-testid="workflow-harness-package-import-handoff-canary-link"
                                    disabled={
                                      !packageImportActivationHandoff
                                        .deepLinkTargets.canary
                                    }
                                    onClick={() =>
                                      onCopyHarnessDeepLink?.({
                                        panel: "settings",
                                        activationGateId: "canary",
                                        activationGateEvidenceRef:
                                          packageImportActivationHandoff
                                            .deepLinkTargets.canary ??
                                          undefined,
                                      })
                                    }
	                                  >
	                                    <code>canary</code>
	                                  </button>
                                  <button
                                    type="button"
                                    className="workflow-harness-ref-button"
                                    data-testid="workflow-harness-package-import-handoff-mutation-canary-link"
                                    disabled={
                                      !packageImportActivationHandoff
                                        .deepLinkTargets.mutationCanary ||
                                      !packageImportActivationHandoff
                                        .forkMutationCanaryNodeAttemptIds?.[0]
                                    }
                                    onClick={() =>
                                      onCopyHarnessDeepLink?.({
                                        panel: "outputs",
                                        activationGateId: "mutation-canary",
                                        activationGateEvidenceRef:
                                          packageImportActivationHandoff
                                            .deepLinkTargets.mutationCanary ??
                                          undefined,
                                        activationGateNodeAttemptId:
                                          packageImportActivationHandoff
                                            .forkMutationCanaryNodeAttemptIds?.[0],
                                        nodeAttemptId:
                                          packageImportActivationHandoff
                                            .forkMutationCanaryNodeAttemptIds?.[0],
                                        activationGateReceiptRef:
                                          packageImportActivationHandoff
                                            .forkMutationCanaryReceiptRefs?.[0],
                                        receiptRef:
                                          packageImportActivationHandoff
                                            .forkMutationCanaryReceiptRefs?.[0],
                                        activationGateReplayFixtureRef:
                                          packageImportActivationHandoff
                                            .forkMutationCanaryReplayFixtureRefs?.[0],
                                        replayFixtureRef:
                                          packageImportActivationHandoff
                                            .forkMutationCanaryReplayFixtureRefs?.[0],
                                      })
                                    }
                                  >
                                    <code>mutation</code>
                                  </button>
	                                  <button
	                                    type="button"
                                    className="workflow-harness-ref-button"
                                    data-testid="workflow-harness-package-import-handoff-rollback-link"
                                    disabled={
                                      !packageImportActivationHandoff
                                        .deepLinkTargets.rollbackRestore
                                    }
                                    onClick={() =>
                                      onCopyHarnessDeepLink?.({
                                        panel: "settings",
                                        activationGateId: "rollback-restore",
                                        activationGateEvidenceRef:
                                          packageImportActivationHandoff
                                            .deepLinkTargets.rollbackRestore ??
                                          undefined,
                                        rollbackTarget:
                                          packageImportActivationHandoff
                                            .deepLinkTargets.rollbackTarget ??
                                          undefined,
                                      })
                                    }
                                  >
                                    <code>rollback</code>
                                  </button>
                                  <button
                                    type="button"
                                    className="workflow-harness-ref-button"
                                    data-testid="workflow-harness-package-import-handoff-worker-link"
                                    disabled={
                                      !packageImportHandoffWorkerBindingId
                                    }
                                    onClick={() =>
                                      onCopyHarnessDeepLink?.({
                                        panel: "settings",
                                        workerBindingId:
                                          packageImportHandoffWorkerBindingId ||
                                          undefined,
                                      })
                                    }
                                  >
                                    <code>worker</code>
                                  </button>
                                </div>
                              </section>
                            ) : null}
                            <div className="workflow-harness-authority-gate-actions">
                              <button
                                type="button"
                                data-testid="workflow-harness-package-import-activate"
                                disabled={!packageImportActivationEnabled}
                                onClick={onApplyHarnessActivationCandidate}
                              >
                                {packageImportActivationEnabled
                                  ? "Activate reviewed import"
                                  : "Activation locked"}
                              </button>
                            </div>
                          </article>
                        ) : null}
                        <h4>Package evidence</h4>
                        {harnessPackageEvidenceReviewRows.map((row) => {
                          const rowRefs = workflowUniqueReceiptRefs(row.refs);
                          return (
                            <article
                              key={row.id}
                              className={`workflow-test-row is-${
                                row.ready ? "passed" : "blocked"
                              }`}
                              data-testid={`workflow-harness-package-evidence-row-${row.id}`}
                              data-package-evidence-row-id={row.id}
                              data-package-evidence-row-status={
                                row.ready ? "passed" : "blocked"
                              }
                              data-package-evidence-ref-kind={row.kind}
                              data-package-evidence-ref-count={rowRefs.length}
                            >
                              <strong>{row.label}</strong>
                              <span>
                                {row.ready ? "ready" : "missing"} · {row.value}
                              </span>
                              <small>{row.detail}</small>
                              <div
                                className="workflow-harness-authority-gate-actions"
                                data-testid={`workflow-harness-package-evidence-row-refs-${row.id}`}
                                data-package-evidence-refs={rowRefs.join("|")}
                              >
                                {rowRefs.slice(0, 6).map((ref, index) => {
                                  const packageLink =
                                    row.kind === "package_deep_link"
                                      ? (harnessPackageDeepLinks.find(
                                          (link) => link?.ref === ref,
                                        ) ?? null)
                                      : null;
                                  return (
                                    <button
                                      type="button"
                                      key={`${row.id}-${ref}-${index}`}
                                      className={`workflow-harness-ref-button ${
                                        selectedHarnessActivationGateEvidenceRef ===
                                          ref ||
                                        selectedHarnessActivationGateReceiptRef ===
                                          ref ||
                                        selectedHarnessActivationGateReplayFixtureRef ===
                                          ref ||
                                        selectedHarnessActivationGateNodeAttemptId ===
                                          ref
                                          ? "is-active"
                                          : ""
                                      }`}
                                      data-testid={`workflow-harness-package-evidence-row-ref-${row.id}-${index}`}
                                      data-package-evidence-ref-kind={row.kind}
                                      data-package-evidence-ref={ref}
                                      data-harness-package-deep-link-kind={
                                        packageLink?.kind ?? ""
                                      }
                                      data-harness-package-deep-link-hash={
                                        packageLink?.hash ?? ""
                                      }
                                      disabled={
                                        !onCopyHarnessDeepLink &&
                                        row.kind !== "receipt" &&
                                        row.kind !== "replay"
                                      }
	                                      onClick={() => {
	                                        if (row.kind === "mutation_canary") {
	                                          onCopyHarnessDeepLink?.({
	                                            panel: "settings",
	                                            activationGateId:
	                                              "mutation-canary",
	                                            activationGateEvidenceRef:
	                                              harnessPackageForkMutationCanary
	                                                ?.canaryId ?? ref,
	                                            activationGateReceiptRef:
	                                              harnessPackageForkMutationCanaryReceiptRefs[0],
	                                            receiptRef:
	                                              harnessPackageForkMutationCanaryReceiptRefs[0],
	                                            activationGateReplayFixtureRef:
	                                              harnessPackageForkMutationCanaryReplayFixtureRefs[0],
	                                            replayFixtureRef:
	                                              harnessPackageForkMutationCanaryReplayFixtureRefs[0],
	                                            activationGateNodeAttemptId:
	                                              harnessPackageForkMutationCanaryNodeAttemptIds[0],
	                                            nodeAttemptId:
	                                              harnessPackageForkMutationCanaryNodeAttemptIds[0],
	                                          });
	                                          return;
	                                        }
	                                        if (row.kind === "receipt") {
	                                          onCopyHarnessDeepLink
                                            ? onCopyHarnessDeepLink({
                                                panel: "settings",
                                                activationGateId:
                                                  "package-evidence",
                                                activationGateReceiptRef: ref,
                                                receiptRef: ref,
                                              })
                                            : onSelectHarnessReceiptRef?.(ref);
                                          return;
                                        }
                                        if (row.kind === "replay") {
                                          onCopyHarnessDeepLink
                                            ? onCopyHarnessDeepLink({
                                                panel: "settings",
                                                activationGateId:
                                                  "package-evidence",
                                                activationGateReplayFixtureRef:
                                                  ref,
                                                replayFixtureRef: ref,
                                              })
                                            : onSelectHarnessReplayFixtureRef?.(
                                                ref,
                                              );
                                          return;
                                        }
                                        if (row.kind === "node_attempt") {
                                          onCopyHarnessDeepLink?.({
                                            panel: "settings",
                                            activationGateId:
                                              "package-evidence",
                                            activationGateNodeAttemptId: ref,
                                            nodeAttemptId: ref,
                                          });
                                          return;
                                        }
                                        if (row.kind === "package_deep_link") {
                                          const target =
                                            workflowHarnessPackageDeepLinkTarget(
                                              packageLink,
                                            );
                                          if (target) {
                                            onCopyHarnessDeepLink?.(target);
                                          }
                                          return;
                                        }
                                        onCopyHarnessDeepLink?.({
                                          panel: "settings",
                                          activationGateId: "package-evidence",
                                          activationGateEvidenceRef: ref,
                                        });
                                      }}
                                    >
                                      <code>{ref}</code>
                                    </button>
                                  );
                                })}
                                {rowRefs.length === 0 ? (
                                  <span
                                    data-testid={`workflow-harness-package-evidence-row-missing-${row.id}`}
                                  >
                                    Missing {row.label.toLowerCase()}
                                  </span>
                                ) : null}
                              </div>
                            </article>
                          );
                        })}
                      </section>
                    ) : null}
                    <div
                      className="workflow-harness-authority-gate-actions"
                      data-testid="workflow-harness-activation-gate-evidence-refs"
                      data-evidence-refs={selectedHarnessActivationGateInspection.evidenceRefs.join(
                        "|",
                      )}
                    >
                      {selectedHarnessActivationGateInspection.evidenceRefs
                        .slice(0, 8)
                        .map((evidenceRef, index: number) => (
                          <button
                            type="button"
                            key={`${evidenceRef}-${index}`}
                            className={`workflow-harness-ref-button ${
                              selectedHarnessActivationGateEvidenceRef ===
                              evidenceRef
                                ? "is-active"
                                : ""
                            }`}
                            data-testid={`workflow-harness-activation-gate-evidence-${index}`}
                            data-activation-gate-id={
                              selectedHarnessActivationGateInspection.gateId
                            }
                            data-activation-gate-evidence-ref={evidenceRef}
                            disabled={!onCopyHarnessDeepLink}
                            onClick={() =>
                              onCopyHarnessDeepLink?.({
                                panel: "settings",
                                activationGateId:
                                  selectedHarnessActivationGateInspection.gateId,
                                activationGateEvidenceRef: evidenceRef,
                              })
                            }
                          >
                            <code>{evidenceRef}</code>
                          </button>
                        ))}
                      {selectedHarnessActivationGateInspection.evidenceRefs
                        .length === 0 ? (
                        <span>
                          No evidence refs captured for this gate yet.
                        </span>
                      ) : null}
                    </div>
                    {selectedHarnessActivationGateInspection.nodeAttemptIds
                      .length > 0 ? (
                      <div
                        className="workflow-harness-authority-gate-actions"
                        data-testid="workflow-harness-activation-gate-node-attempt-refs"
                        data-node-attempt-refs={selectedHarnessActivationGateInspection.nodeAttemptIds.join(
                          "|",
                        )}
                      >
                        {selectedHarnessActivationGateInspection.nodeAttemptIds.map(
                          (nodeAttemptId, index: number) => (
                            <button
                              type="button"
                              key={`${nodeAttemptId}-${index}`}
                              className={`workflow-harness-ref-button ${
                                selectedHarnessActivationGateNodeAttemptId ===
                                  nodeAttemptId ||
                                selectedHarnessNodeAttemptId === nodeAttemptId
                                  ? "is-active"
                                  : ""
                              }`}
                              data-testid={`workflow-harness-activation-gate-node-attempt-${index}`}
                              data-activation-gate-id={
                                selectedHarnessActivationGateInspection.gateId
                              }
                              data-activation-gate-node-attempt-id={
                                nodeAttemptId
                              }
                              onClick={() =>
                                onCopyHarnessDeepLink?.({
                                  panel: "settings",
                                  activationGateId:
                                    selectedHarnessActivationGateInspection.gateId,
                                  activationGateNodeAttemptId: nodeAttemptId,
                                  nodeAttemptId,
                                })
                              }
                            >
                              <code>{nodeAttemptId}</code>
                            </button>
                          ),
                        )}
                      </div>
                    ) : null}
                    {selectedHarnessActivationGateInspection.nodeAttemptIds
                      .length > 0 ? (
                      <ol
                        className="workflow-run-timeline"
                        data-testid="workflow-harness-activation-gate-node-timeline"
                        data-node-attempt-refs={selectedHarnessActivationGateInspection.nodeAttemptIds.join(
                          "|",
                        )}
                      >
	                        {harnessActivationGateNodeAttempts
	                          .filter((attempt) =>
	                            selectedHarnessActivationGateInspection.nodeAttemptIds.includes(
	                              attempt.attemptId,
	                            ),
	                          )
	                          .map((attempt) => {
	                            const attemptMutationCanary =
	                              harnessForkMutationCanaryNodeAttemptIds.includes(
	                                attempt.attemptId,
	                              )
	                                ? harnessForkMutationCanary
	                                : null;
	                            return (
	                            <li
	                              key={attempt.attemptId}
	                              className={`is-${attempt.status} ${
	                                selectedHarnessActivationGateNodeAttemptId ===
                                  attempt.attemptId ||
                                selectedHarnessNodeAttemptId ===
                                  attempt.attemptId
                                  ? "is-active"
                                  : ""
                              }`}
	                              data-testid={`workflow-harness-activation-gate-node-timeline-${attempt.attemptId}`}
	                              data-node-attempt-id={attempt.attemptId}
	                              data-workflow-node-id={attempt.workflowNodeId}
	                              data-component-kind={attempt.componentKind}
	                              data-component-id={attempt.componentId}
	                              data-execution-mode={attempt.executionMode}
	                              data-readiness={attempt.readiness}
	                              data-status={attempt.status}
	                              data-policy-decision={
	                                attempt.policyDecision ?? ""
	                              }
	                              data-receipt-refs={attempt.receiptIds.join("|")}
	                              data-replay-fixture-ref={
	                                attempt.replay.fixtureRef ?? ""
	                              }
	                              data-input-hash={attempt.inputHash ?? ""}
	                              data-output-hash={attempt.outputHash ?? ""}
	                              data-mutation-diff-hash={
	                                attemptMutationCanary?.diffHash ?? ""
	                              }
	                              data-rollback-target={
	                                attemptMutationCanary?.rollbackTarget ?? ""
	                              }
	                            >
                              <strong>{attempt.componentKind}</strong>
                              <span>
                                {attempt.executionMode} · {attempt.readiness} ·{" "}
                                {attempt.policyDecision ?? "policy pending"}
                              </span>
                              <small>
                                {attempt.receiptIds.length} receipts ·{" "}
	                                {attempt.replay.fixtureRef ?? "replay pending"}
	                              </small>
	                            </li>
	                            );
	                          })}
                      </ol>
                    ) : null}
                    {selectedHarnessActivationGateInspection.receiptRefs
                      .length > 0 ? (
                      <div
                        className="workflow-harness-authority-gate-actions"
                        data-testid="workflow-harness-activation-gate-receipt-refs"
                        data-receipt-refs={selectedHarnessActivationGateInspection.receiptRefs.join(
                          "|",
                        )}
                      >
                        {selectedHarnessActivationGateInspection.receiptRefs.map(
                          (receiptRef, index: number) => (
                            <button
                              type="button"
                              key={`${receiptRef}-${index}`}
                              className={`workflow-harness-ref-button ${
                                selectedHarnessActivationGateReceiptRef ===
                                  receiptRef ||
                                selectedHarnessReceiptRef === receiptRef
                                  ? "is-active"
                                  : ""
                              }`}
                              data-testid={`workflow-harness-activation-gate-receipt-${index}`}
                              data-activation-gate-id={
                                selectedHarnessActivationGateInspection.gateId
                              }
                              data-activation-gate-receipt-ref={receiptRef}
                              onClick={() =>
                                onCopyHarnessDeepLink
                                  ? onCopyHarnessDeepLink({
                                      panel: "settings",
                                      activationGateId:
                                        selectedHarnessActivationGateInspection.gateId,
                                      activationGateReceiptRef: receiptRef,
                                      receiptRef,
                                    })
                                  : onSelectHarnessReceiptRef?.(receiptRef)
                              }
                            >
                              <code>{receiptRef}</code>
                            </button>
                          ),
                        )}
                      </div>
                    ) : null}
                    {selectedHarnessActivationGateInspection.replayFixtureRefs
                      .length > 0 ? (
                      <div
                        className="workflow-harness-authority-gate-actions"
                        data-testid="workflow-harness-activation-gate-replay-refs"
                        data-replay-fixture-refs={selectedHarnessActivationGateInspection.replayFixtureRefs.join(
                          "|",
                        )}
                      >
                        {selectedHarnessActivationGateInspection.replayFixtureRefs.map(
                          (replayFixtureRef, index: number) => (
                            <button
                              type="button"
                              key={`${replayFixtureRef}-${index}`}
                              className={`workflow-harness-ref-button ${
                                selectedHarnessActivationGateReplayFixtureRef ===
                                  replayFixtureRef ||
                                selectedHarnessReplayFixtureRef ===
                                  replayFixtureRef
                                  ? "is-active"
                                  : ""
                              }`}
                              data-testid={`workflow-harness-activation-gate-replay-${index}`}
                              data-activation-gate-id={
                                selectedHarnessActivationGateInspection.gateId
                              }
                              data-activation-gate-replay-fixture-ref={
                                replayFixtureRef
                              }
                              onClick={() =>
                                onCopyHarnessDeepLink
                                  ? onCopyHarnessDeepLink({
                                      panel: "settings",
                                      activationGateId:
                                        selectedHarnessActivationGateInspection.gateId,
                                      activationGateReplayFixtureRef:
                                        replayFixtureRef,
                                      replayFixtureRef,
                                    })
                                  : onSelectHarnessReplayFixtureRef?.(
                                      replayFixtureRef,
                                    )
                              }
                            >
                              <code>{replayFixtureRef}</code>
                            </button>
                          ),
                        )}
                      </div>
                    ) : null}
                  </section>
                ) : null}
                {harnessActivationBlockers.length > 0 ? (
                  <div
                    className="workflow-rail-list"
                    data-testid="workflow-harness-activation-wizard-blockers"
                  >
                    {harnessActivationBlockers
                      .slice(0, 5)
                      .map((issue, index: number) => (
                        <button
                          key={`${issue.code}-${issue.nodeId ?? "workflow"}-${index}`}
                          type="button"
                          className="workflow-search-result is-blocked"
                          data-testid={`workflow-harness-activation-blocker-${index}`}
                          onClick={() => onResolveIssue(issue)}
                        >
                          <strong>{workflowIssueTitle(issue)}</strong>
                          <span>
                            {workflowNodeName(workflow, issue.nodeId)}
                          </span>
                          <small>{issue.message}</small>
                        </button>
                      ))}
                  </div>
                ) : null}
                <div
                  className="workflow-harness-activation-actions"
                  data-testid="workflow-harness-activation-actions"
                >
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-dry-run"
                    onClick={onRunHarnessActivationDryRun}
                  >
                    Dry run
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-run-readiness"
                    onClick={onCheckActivationReadiness}
                  >
                    Check readiness
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-review-proposal"
                    disabled={!activationGateProposal}
                    onClick={() => {
                      if (activationGateProposal) {
                        onSelectProposal(activationGateProposal);
                      }
                    }}
                  >
                    Review proposal
                  </button>
                  <button
                    type="button"
                    data-testid="workflow-harness-activation-first-blocker"
                    disabled={!firstHarnessActivationBlocker}
                    onClick={() => {
                      if (firstHarnessActivationBlocker) {
                        onResolveIssue(firstHarnessActivationBlocker);
                      }
                    }}
                  >
                    Inspect blocker
                  </button>
                </div>
              </section>
            ) : null}
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
