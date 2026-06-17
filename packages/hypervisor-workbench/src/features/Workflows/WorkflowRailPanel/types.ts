import type {
  Node,
  WorkflowHarnessComponentKind,
  WorkflowRightPanel,
} from "../../../types/graph";

export type WorkflowHarnessAuthorityGateProofView = {
  id: "policy-gate" | "destructive-denial" | "approval-gate";
  label: string;
  componentKind: Extract<
    WorkflowHarnessComponentKind,
    "policy_gate" | "approval_gate"
  >;
  node: Node | null;
  ready: boolean;
  status: "live_ready" | "blocked";
  attemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  policyDecision: string;
  blockerState: string;
  componentId: string;
  runId: string;
  selectedPanel: WorkflowRightPanel;
};

export type WorkflowHarnessWorkbenchDeepLinkTarget = {
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

export type WorkflowHarnessActivationGateActionKind =
  | "inspect_blocker"
  | "check_readiness"
  | "review_proposal"
  | "run_activation_dry_run"
  | "run_replay_gate"
  | "run_rollback_drill"
  | "mint_activation";

export type WorkflowHarnessActivationGateActionImpact =
  | "inspect"
  | "collect_evidence"
  | "clear_blocker"
  | "mint_activation";

export type WorkflowHarnessActivationGateAction = {
  actionId: string;
  kind: WorkflowHarnessActivationGateActionKind;
  impact: WorkflowHarnessActivationGateActionImpact;
  label: string;
  detail: string;
  commandTestId: string;
  disabled: boolean;
  disabledReason?: string;
  onRun?: () => void;
};

export type WorkflowHarnessActivationWizardStep = {
  id: string;
  label: string;
  ready: boolean;
  value: string;
  detail: string;
  evidenceRefs: string[];
  nodeAttemptIds?: string[];
  receiptRefs?: string[];
  replayFixtureRefs?: string[];
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  gateAction: WorkflowHarnessActivationGateAction;
};
