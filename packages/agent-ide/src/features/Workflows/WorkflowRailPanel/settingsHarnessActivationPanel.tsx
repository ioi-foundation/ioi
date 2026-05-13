import type { WorkflowProject } from "../../../types/graph";
import { WorkflowSettingsHarnessActivationActions } from "./settingsHarnessActivationActions";
import { WorkflowSettingsHarnessActivationGatePanel } from "./settingsHarnessActivationGatePanel";
import { WorkflowSettingsHarnessActivationWizardDetails } from "./settingsHarnessActivationWizardDetails";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPackageRestoreProps,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

const ACTIVATION_WIZARD_TEST_ID = "workflow-harness-activation-wizard";
const ACTIVATION_STEP_TEST_ID_TEMPLATE =
  "workflow-harness-activation-step-${step.id}";
const ACTIVATION_CANDIDATE_GATE_TEST_ID_TEMPLATE =
  "workflow-harness-activation-candidate-gate-${gate.gateId}";
const ACTIVATION_STEP_ACTION_TEST_ID_TEMPLATE =
  "workflow-harness-activation-step-action-${step.id}";
const ACTIVATION_CANDIDATE_GATE_ACTION_TEST_ID_TEMPLATE =
  "workflow-harness-activation-candidate-gate-action-${gate.gateId}";

export interface WorkflowSettingsHarnessActivationPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "activationGateProposal"
      | "blessedHarnessWorkflow"
      | "firstHarnessActivationBlocker"
      | "harnessActivationBlockers"
      | "harnessActivationCandidate"
      | "harnessActivationGateActions"
      | "harnessActivationGateNodeAttempts"
      | "harnessActivationReady"
      | "harnessActivationRecord"
      | "harnessActivationWizardSteps"
      | "harnessActivationWorkerHandoffNodeAttemptIds"
      | "harnessActivationWorkerHandoffNodeAttempts"
      | "harnessActivationWorkerHandoffReplayFixtureRefs"
      | "harnessActivationWorkerHandoffTimelineReady"
      | "harnessActivationWorkerInvariantBlockers"
      | "harnessActivationWorkerInvariantReady"
      | "harnessActivationWorkerRequiredInvariantIds"
      | "packageImportActivationEnabled"
      | "packageImportActivationHandoff"
      | "packageImportHandoffWorkerBindingId"
      | "packageImportReplayIntegrityBlockers"
      | "packageImportReview"
      | "selectedHarnessActivationGateEvidenceRef"
      | "selectedHarnessActivationGateId"
      | "selectedHarnessActivationGateInspection"
      | "selectedHarnessActivationGateMutationCanary"
      | "selectedHarnessActivationGateNodeAttempt"
      | "selectedHarnessActivationGateNodeAttemptId"
      | "selectedHarnessActivationGateReceiptRef"
      | "selectedHarnessActivationGateReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessPackageRestoreProps,
      | "harnessPackageDeepLinks"
      | "harnessPackageEvidenceBlockerCount"
      | "harnessPackageEvidenceReady"
      | "harnessPackageEvidenceRefValues"
      | "harnessPackageEvidenceReviewRows"
      | "harnessPackageForkMutationCanary"
      | "harnessPackageForkMutationCanaryNodeAttemptIds"
      | "harnessPackageForkMutationCanaryReceiptRefs"
      | "harnessPackageForkMutationCanaryReplayFixtureRefs"
      | "harnessPackageManifest"
      | "harnessPackageReceiptRefValues"
      | "harnessPackageReplayFixtureRefValues"
      | "harnessPackageRollbackRestoreReceiptRefs"
      | "harnessPackageWorkerHandoffNodeAttemptIds"
      | "harnessPackageWorkerHandoffReceiptIds"
    >,
    Pick<
      WorkflowSettingsHarnessRollbackProps,
      | "rollbackReady"
      | "selectedHarnessCanaryBoundary"
      | "selectedHarnessRollbackDrillId"
      | "selectedHarnessRollbackRestoreCanaryId"
      | "selectedHarnessRollbackRestoreReceiptRef"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "harnessWorkerBinding"
      | "selectedHarnessNodeAttemptId"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessPromotionProps,
      | "harnessForkMutationCanary"
      | "harnessForkMutationCanaryNodeAttemptIds"
      | "harnessForkWorkflow"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onApplyHarnessActivationCandidate"
      | "onCheckActivationReadiness"
      | "onCopyHarnessDeepLink"
      | "onResolveIssue"
      | "onRunHarnessActivationDryRun"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
      | "onSelectProposal"
    > {
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessActivationPanel(
  props: WorkflowSettingsHarnessActivationPanelProps,
) {
  if (!props.harnessForkWorkflow && !props.blessedHarnessWorkflow) {
    return null;
  }

  return (
    <section
      className="workflow-rail-section workflow-harness-activation-wizard"
      data-testid={ACTIVATION_WIZARD_TEST_ID}
      data-activation-state={
        props.workflow.metadata.harness?.activationState ?? "blocked"
      }
    >
      <h4>Activation wizard</h4>
      <WorkflowSettingsHarnessActivationWizardDetails
        {...props}
        activationCandidateGateActionTestIdTemplate={
          ACTIVATION_CANDIDATE_GATE_ACTION_TEST_ID_TEMPLATE
        }
        activationCandidateGateTestIdTemplate={
          ACTIVATION_CANDIDATE_GATE_TEST_ID_TEMPLATE
        }
        activationStepActionTestIdTemplate={
          ACTIVATION_STEP_ACTION_TEST_ID_TEMPLATE
        }
        activationStepTestIdTemplate={ACTIVATION_STEP_TEST_ID_TEMPLATE}
      />
      <WorkflowSettingsHarnessActivationGatePanel {...props} />
      <WorkflowSettingsHarnessActivationActions {...props} />
    </section>
  );
}
