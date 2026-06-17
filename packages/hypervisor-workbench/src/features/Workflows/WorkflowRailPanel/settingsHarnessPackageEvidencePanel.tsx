import type {
  WorkflowSettingsHarnessActivationGateInspection,
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPackageRestoreProps,
} from "./settingsHarnessTypes";
import { WorkflowSettingsHarnessPackageEvidenceRowsPanel } from "./settingsHarnessPackageEvidenceRowsPanel";
import { WorkflowSettingsHarnessPackageImportReviewPanel } from "./settingsHarnessPackageImportReviewPanel";

export interface WorkflowSettingsHarnessPackageEvidencePanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "packageImportActivationEnabled"
      | "packageImportActivationHandoff"
      | "packageImportHandoffWorkerBindingId"
      | "packageImportReplayIntegrityBlockers"
      | "packageImportReview"
      | "selectedHarnessActivationGateEvidenceRef"
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
      WorkflowSettingsHarnessCallbacks,
      | "onApplyHarnessActivationCandidate"
      | "onCopyHarnessDeepLink"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {
  selectedHarnessActivationGateInspection: WorkflowSettingsHarnessActivationGateInspection;
}

export function WorkflowSettingsHarnessPackageEvidencePanel({
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
  packageImportActivationEnabled,
  packageImportActivationHandoff,
  packageImportHandoffWorkerBindingId,
  packageImportReplayIntegrityBlockers,
  packageImportReview,
  selectedHarnessActivationGateEvidenceRef,
  selectedHarnessActivationGateInspection,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  onApplyHarnessActivationCandidate,
  onCopyHarnessDeepLink,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
}: WorkflowSettingsHarnessPackageEvidencePanelProps) {
  if (selectedHarnessActivationGateInspection.gateId !== "package-evidence") {
    return null;
  }

  return (
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
      data-harness-package-deep-link-count={harnessPackageDeepLinks.length}
    >
      <WorkflowSettingsHarnessPackageImportReviewPanel
        packageImportActivationEnabled={packageImportActivationEnabled}
        packageImportActivationHandoff={packageImportActivationHandoff}
        packageImportHandoffWorkerBindingId={
          packageImportHandoffWorkerBindingId
        }
        packageImportReplayIntegrityBlockers={
          packageImportReplayIntegrityBlockers
        }
        packageImportReview={packageImportReview}
        onApplyHarnessActivationCandidate={onApplyHarnessActivationCandidate}
        onCopyHarnessDeepLink={onCopyHarnessDeepLink}
      />
      <WorkflowSettingsHarnessPackageEvidenceRowsPanel
        harnessPackageDeepLinks={harnessPackageDeepLinks}
        harnessPackageEvidenceReviewRows={harnessPackageEvidenceReviewRows}
        harnessPackageForkMutationCanary={harnessPackageForkMutationCanary}
        harnessPackageForkMutationCanaryNodeAttemptIds={
          harnessPackageForkMutationCanaryNodeAttemptIds
        }
        harnessPackageForkMutationCanaryReceiptRefs={
          harnessPackageForkMutationCanaryReceiptRefs
        }
        harnessPackageForkMutationCanaryReplayFixtureRefs={
          harnessPackageForkMutationCanaryReplayFixtureRefs
        }
        selectedHarnessActivationGateEvidenceRef={
          selectedHarnessActivationGateEvidenceRef
        }
        selectedHarnessActivationGateNodeAttemptId={
          selectedHarnessActivationGateNodeAttemptId
        }
        selectedHarnessActivationGateReceiptRef={
          selectedHarnessActivationGateReceiptRef
        }
        selectedHarnessActivationGateReplayFixtureRef={
          selectedHarnessActivationGateReplayFixtureRef
        }
        onCopyHarnessDeepLink={onCopyHarnessDeepLink}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
        onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
      />
    </section>
  );
}
