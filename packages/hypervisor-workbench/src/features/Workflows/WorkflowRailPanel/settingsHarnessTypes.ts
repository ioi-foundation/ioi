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
import type { WorkflowSettingsHarnessModel } from "../../../runtime/workflow-settings-harness-model";
import type {
  WorkflowHarnessActivationGateAction,
  WorkflowHarnessActivationWizardStep,
  WorkflowHarnessAuthorityGateProofView,
  WorkflowHarnessWorkbenchDeepLinkTarget,
} from "./types";

export type Nullable<T> = T | null | undefined;

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

export interface WorkflowSettingsHarnessActivationGateInspection extends WorkflowHarnessActivationCandidateGateResult {
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
  harnessActivationGateActions: Record<
    string,
    WorkflowHarnessActivationGateAction
  >;
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
  extends
    WorkflowSettingsHarnessActivationProps,
    WorkflowSettingsHarnessPackageRestoreProps,
    WorkflowSettingsHarnessRollbackProps,
    WorkflowSettingsHarnessWorkerBindingProps,
    WorkflowSettingsHarnessPromotionProps,
    WorkflowSettingsHarnessCallbacks {
  model: WorkflowSettingsHarnessModel;
  harnessWorkflow: boolean;
  workflow: WorkflowProject;
}
