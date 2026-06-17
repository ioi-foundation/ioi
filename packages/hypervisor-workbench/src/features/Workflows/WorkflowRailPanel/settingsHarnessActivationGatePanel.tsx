import type { ReactNode } from "react";

import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPackageRestoreProps,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";
import { WorkflowSettingsHarnessActivationGateRefsPanel } from "./settingsHarnessActivationGateRefsPanel";
import { WorkflowSettingsHarnessActivationGateTimelinePanel } from "./settingsHarnessActivationGateTimelinePanel";
import { WorkflowSettingsHarnessPackageEvidencePanel } from "./settingsHarnessPackageEvidencePanel";
import type { WorkflowHarnessActivationGateAction } from "./types";

export interface WorkflowSettingsHarnessActivationGatePanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "harnessActivationGateNodeAttempts"
      | "packageImportActivationEnabled"
      | "packageImportActivationHandoff"
      | "packageImportHandoffWorkerBindingId"
      | "packageImportReplayIntegrityBlockers"
      | "packageImportReview"
      | "selectedHarnessActivationGateEvidenceRef"
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
      | "selectedHarnessCanaryBoundary"
      | "selectedHarnessRollbackDrillId"
      | "selectedHarnessRollbackRestoreCanaryId"
      | "selectedHarnessRollbackRestoreReceiptRef"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "selectedHarnessNodeAttemptId"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessPromotionProps,
      "harnessForkMutationCanary" | "harnessForkMutationCanaryNodeAttemptIds"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onApplyHarnessActivationCandidate"
      | "onCopyHarnessDeepLink"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {}

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

export function WorkflowSettingsHarnessActivationGatePanel({
  harnessActivationGateNodeAttempts,
  harnessForkMutationCanary,
  harnessForkMutationCanaryNodeAttemptIds,
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
  selectedHarnessActivationGateMutationCanary,
  selectedHarnessActivationGateNodeAttempt,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  selectedHarnessCanaryBoundary,
  selectedHarnessNodeAttemptId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  selectedHarnessRollbackDrillId,
  selectedHarnessRollbackRestoreCanaryId,
  selectedHarnessRollbackRestoreReceiptRef,
  onApplyHarnessActivationCandidate,
  onCopyHarnessDeepLink,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
}: WorkflowSettingsHarnessActivationGatePanelProps) {
  return (
    <>
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
          data-selected-node-attempt-id={selectedHarnessNodeAttemptId ?? ""}
          data-selected-activation-gate-node-attempt-id={
            selectedHarnessActivationGateNodeAttemptId ?? ""
          }
          data-node-attempt-id={
            selectedHarnessActivationGateNodeAttempt?.attemptId ??
            selectedHarnessActivationGateNodeAttemptId ??
            ""
          }
          data-component-kind={
            selectedHarnessActivationGateNodeAttempt?.componentKind ?? ""
          }
          data-component-id={
            selectedHarnessActivationGateNodeAttempt?.componentId ?? ""
          }
          data-policy-decision={
            selectedHarnessActivationGateNodeAttempt?.policyDecision ??
            selectedHarnessActivationGateMutationCanary?.policyDecision ??
            ""
          }
          data-receipt-refs={
            selectedHarnessActivationGateNodeAttempt?.receiptIds.join("|") ??
            selectedHarnessActivationGateInspection.receiptRefs.join("|")
          }
          data-replay-fixture-ref={
            selectedHarnessActivationGateNodeAttempt?.replay.fixtureRef ??
            selectedHarnessActivationGateInspection.replayFixtureRefs[0] ??
            ""
          }
          data-input-hash={
            selectedHarnessActivationGateNodeAttempt?.inputHash ?? ""
          }
          data-output-hash={
            selectedHarnessActivationGateNodeAttempt?.outputHash ?? ""
          }
          data-mutation-diff-hash={
            selectedHarnessActivationGateMutationCanary?.diffHash ?? ""
          }
          data-rollback-target={
            selectedHarnessActivationGateMutationCanary?.rollbackTarget ?? ""
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
          data-selected-rollback-drill-id={selectedHarnessRollbackDrillId}
          data-selected-rollback-restore-canary-id={
            selectedHarnessRollbackRestoreCanaryId
          }
          data-selected-rollback-restore-receipt-ref={
            selectedHarnessRollbackRestoreReceiptRef
          }
          data-gate-source-kind={
            selectedHarnessActivationGateInspection.sourceKind
          }
          data-gate-status={selectedHarnessActivationGateInspection.status}
          data-evidence-ref-count={
            selectedHarnessActivationGateInspection.evidenceRefs.length
          }
          data-node-attempt-ref-count={
            selectedHarnessActivationGateInspection.nodeAttemptIds.length
          }
          data-receipt-ref-count={
            selectedHarnessActivationGateInspection.receiptRefs.length
          }
          data-replay-fixture-ref-count={
            selectedHarnessActivationGateInspection.replayFixtureRefs.length
          }
          data-required-invariant-ids={selectedHarnessActivationGateInspection.requiredInvariantIds.join(
            ",",
          )}
          data-invariant-blockers={selectedHarnessActivationGateInspection.invariantBlockers.join(
            ",",
          )}
          data-invariant-blocker-count={
            selectedHarnessActivationGateInspection.invariantBlockers.length
          }
          data-gate-action-id={
            selectedHarnessActivationGateInspection.gateAction?.actionId ?? ""
          }
          data-gate-action-kind={
            selectedHarnessActivationGateInspection.gateAction?.kind ?? ""
          }
          data-gate-action-impact={
            selectedHarnessActivationGateInspection.gateAction?.impact ?? ""
          }
          data-gate-action-command={
            selectedHarnessActivationGateInspection.gateAction?.commandTestId ??
            ""
          }
          data-gate-action-disabled={
            selectedHarnessActivationGateInspection.gateAction?.disabled
              ? "true"
              : "false"
          }
        >
          <h4>Gate evidence</h4>
          <article
            className={`workflow-output-row is-${selectedHarnessActivationGateInspection.status}`}
            data-testid="workflow-harness-activation-gate-summary"
          >
            <strong>{selectedHarnessActivationGateInspection.label}</strong>
            <span>{selectedHarnessActivationGateInspection.value}</span>
            <small>{selectedHarnessActivationGateInspection.detail}</small>
            {selectedHarnessActivationGateInspection.requiredInvariantIds
              .length > 0 ? (
              <small>
                invariants{" "}
                {selectedHarnessActivationGateInspection.requiredInvariantIds.join(
                  ", ",
                )}{" "}
                · blockers{" "}
                {
                  selectedHarnessActivationGateInspection.invariantBlockers
                    .length
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
          <WorkflowSettingsHarnessPackageEvidencePanel
            harnessPackageDeepLinks={harnessPackageDeepLinks}
            harnessPackageEvidenceBlockerCount={
              harnessPackageEvidenceBlockerCount
            }
            harnessPackageEvidenceReady={harnessPackageEvidenceReady}
            harnessPackageEvidenceRefValues={harnessPackageEvidenceRefValues}
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
            harnessPackageManifest={harnessPackageManifest}
            harnessPackageReceiptRefValues={harnessPackageReceiptRefValues}
            harnessPackageReplayFixtureRefValues={
              harnessPackageReplayFixtureRefValues
            }
            harnessPackageRollbackRestoreReceiptRefs={
              harnessPackageRollbackRestoreReceiptRefs
            }
            harnessPackageWorkerHandoffNodeAttemptIds={
              harnessPackageWorkerHandoffNodeAttemptIds
            }
            harnessPackageWorkerHandoffReceiptIds={
              harnessPackageWorkerHandoffReceiptIds
            }
            packageImportActivationEnabled={packageImportActivationEnabled}
            packageImportActivationHandoff={packageImportActivationHandoff}
            packageImportHandoffWorkerBindingId={
              packageImportHandoffWorkerBindingId
            }
            packageImportReplayIntegrityBlockers={
              packageImportReplayIntegrityBlockers
            }
            packageImportReview={packageImportReview}
            selectedHarnessActivationGateEvidenceRef={
              selectedHarnessActivationGateEvidenceRef
            }
            selectedHarnessActivationGateInspection={
              selectedHarnessActivationGateInspection
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
            onApplyHarnessActivationCandidate={
              onApplyHarnessActivationCandidate
            }
            onCopyHarnessDeepLink={onCopyHarnessDeepLink}
            onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
            onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
          />
          <WorkflowSettingsHarnessActivationGateRefsPanel
            selectedHarnessActivationGateEvidenceRef={
              selectedHarnessActivationGateEvidenceRef
            }
            selectedHarnessActivationGateInspection={
              selectedHarnessActivationGateInspection
            }
            selectedHarnessActivationGateReceiptRef={
              selectedHarnessActivationGateReceiptRef
            }
            selectedHarnessActivationGateReplayFixtureRef={
              selectedHarnessActivationGateReplayFixtureRef
            }
            selectedHarnessReceiptRef={selectedHarnessReceiptRef}
            selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
            onCopyHarnessDeepLink={onCopyHarnessDeepLink}
            onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
            onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
          />
          <WorkflowSettingsHarnessActivationGateTimelinePanel
            harnessActivationGateNodeAttempts={
              harnessActivationGateNodeAttempts
            }
            harnessForkMutationCanary={harnessForkMutationCanary}
            harnessForkMutationCanaryNodeAttemptIds={
              harnessForkMutationCanaryNodeAttemptIds
            }
            selectedHarnessActivationGateInspection={
              selectedHarnessActivationGateInspection
            }
            selectedHarnessActivationGateNodeAttemptId={
              selectedHarnessActivationGateNodeAttemptId
            }
            selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
            onCopyHarnessDeepLink={onCopyHarnessDeepLink}
          />
        </section>
      ) : null}
    </>
  );
}
