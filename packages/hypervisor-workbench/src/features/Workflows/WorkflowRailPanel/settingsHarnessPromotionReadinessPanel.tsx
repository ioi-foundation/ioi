import type { WorkflowProject } from "../../../types/graph";
import { WorkflowSettingsHarnessPromotionReadinessAuthorityGates } from "./settingsHarnessPromotionReadinessAuthorityGates";
import { WorkflowSettingsHarnessPromotionReadinessRoutingCanary } from "./settingsHarnessPromotionReadinessRoutingCanary";
import { WorkflowSettingsHarnessPromotionReadinessSummary } from "./settingsHarnessPromotionReadinessSummary";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

const SELECTOR_READINESS_TEST_ID =
  "workflow-harness-selector-live-promotion-readiness";
const AUTHORITY_GATE_LIVE_TEST_ID = "workflow-harness-authority-gate-live";

export interface WorkflowSettingsHarnessPromotionReadinessPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessPromotionProps,
      | "harnessAuthorityGateLiveProofs"
      | "harnessAuthorityGateLiveReady"
      | "harnessAuthorityGateReadyCount"
      | "harnessAuthorityToolingNodeAuthorityGate"
      | "harnessAuthorityToolingProof"
      | "harnessCognitionNodeAuthorityGate"
      | "harnessLiveHandoffProof"
      | "harnessReadOnlyRoutingNodeKinds"
      | "harnessReadOnlyRoutingProof"
      | "harnessReadOnlyRoutingReady"
      | "harnessReadOnlyRoutingRequiredScenarios"
      | "harnessRoutingModelNodeAuthorityGate"
      | "harnessRuntimeSelectorDecision"
      | "harnessSelectorLivePromotionReadinessBlockers"
      | "harnessSelectorLivePromotionReadinessProof"
      | "harnessSelectorLivePromotionReadinessReady"
      | "harnessVerificationOutputNodeAuthorityGate"
    >,
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "selectedHarnessActivationGateReceiptRef"
      | "selectedHarnessActivationGateReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessRollbackProps,
      | "harnessCanaryExecutionBoundaries"
      | "selectedHarnessCanaryBoundary"
      | "selectedHarnessRollbackDrillId"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "harnessDefaultRuntimeDispatchProof"
      | "harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers"
      | "harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds"
      | "harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers"
      | "harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds"
      | "harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound"
      | "harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers"
      | "harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCopyHarnessDeepLink"
      | "onInspectNode"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessPromotionReadinessPanel(
  props: WorkflowSettingsHarnessPromotionReadinessPanelProps,
) {
  return (
    <>
      <WorkflowSettingsHarnessPromotionReadinessSummary
        {...props}
        selectorReadinessTestId={SELECTOR_READINESS_TEST_ID}
      />
      <WorkflowSettingsHarnessPromotionReadinessAuthorityGates
        {...props}
        authorityGateLiveTestId={AUTHORITY_GATE_LIVE_TEST_ID}
      />
      <WorkflowSettingsHarnessPromotionReadinessRoutingCanary {...props} />
    </>
  );
}
