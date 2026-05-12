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
import { WorkflowSettingsHarnessPromotionPanel } from "./settingsHarnessPromotionPanel";
import type { WorkflowSettingsHarnessModel } from "../../../runtime/workflow-settings-harness-model";
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
            <WorkflowSettingsHarnessPromotionPanel
              boundHarnessSlotIds={boundHarnessSlotIds}
              harnessActivationRecord={harnessActivationRecord}
              selectedHarnessActivationBlockerIndex={selectedHarnessActivationBlockerIndex}
              selectedHarnessActivationBlockerRef={selectedHarnessActivationBlockerRef}
              selectedHarnessActivationGateReceiptRef={selectedHarnessActivationGateReceiptRef}
              selectedHarnessActivationGateReplayFixtureRef={selectedHarnessActivationGateReplayFixtureRef}
              harnessAuthorityGateLiveProofs={harnessAuthorityGateLiveProofs}
              harnessAuthorityGateLiveReady={harnessAuthorityGateLiveReady}
              harnessAuthorityGateReadyCount={harnessAuthorityGateReadyCount}
              harnessAuthorityToolingNodeAuthorityGate={harnessAuthorityToolingNodeAuthorityGate}
              harnessAuthorityToolingProof={harnessAuthorityToolingProof}
              harnessCognitionNodeAuthorityGate={harnessCognitionNodeAuthorityGate}
              harnessForkComponentDiffRows={harnessForkComponentDiffRows}
              harnessForkComponentDiffStats={harnessForkComponentDiffStats}
              harnessForkMutationCanary={harnessForkMutationCanary}
              harnessForkMutationCanaryNodeAttemptIds={harnessForkMutationCanaryNodeAttemptIds}
              harnessForkWorkflow={harnessForkWorkflow}
              harnessLiveHandoffProof={harnessLiveHandoffProof}
              harnessPromotionClusters={harnessPromotionClusters}
              harnessReadOnlyRoutingNodeKinds={harnessReadOnlyRoutingNodeKinds}
              harnessReadOnlyRoutingProof={harnessReadOnlyRoutingProof}
              harnessReadOnlyRoutingReady={harnessReadOnlyRoutingReady}
              harnessReadOnlyRoutingRequiredScenarios={harnessReadOnlyRoutingRequiredScenarios}
              harnessRoutingModelNodeAuthorityGate={harnessRoutingModelNodeAuthorityGate}
              harnessRuntimeSelectorDecision={harnessRuntimeSelectorDecision}
              harnessSelectorLivePromotionReadinessBlockers={harnessSelectorLivePromotionReadinessBlockers}
              harnessSelectorLivePromotionReadinessProof={harnessSelectorLivePromotionReadinessProof}
              harnessSelectorLivePromotionReadinessReady={harnessSelectorLivePromotionReadinessReady}
              harnessSlots={harnessSlots}
              harnessVerificationOutputNodeAuthorityGate={harnessVerificationOutputNodeAuthorityGate}
              harnessCanaryExecutionBoundaries={harnessCanaryExecutionBoundaries}
              selectedHarnessCanaryBoundary={selectedHarnessCanaryBoundary}
              selectedHarnessRollbackDrillId={selectedHarnessRollbackDrillId}
              harnessDefaultRuntimeDispatchProof={harnessDefaultRuntimeDispatchProof}
              harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers}
              harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds}
              harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers}
              harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds}
              harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound={harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound}
              harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers}
              harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds}
              selectedHarnessReceiptRef={selectedHarnessReceiptRef}
              selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
              onCopyHarnessDeepLink={onCopyHarnessDeepLink}
              onInspectNode={onInspectNode}
              onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
              onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
              workflow={workflow}
            />
          </section>
  ) : null;
}
