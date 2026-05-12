import type { ReactNode } from "react";

import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPackageRestoreProps,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";
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
                    selectedHarnessActivationGateEvidenceRef === evidenceRef
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
            {selectedHarnessActivationGateInspection.evidenceRefs.length ===
            0 ? (
              <span>No evidence refs captured for this gate yet.</span>
            ) : null}
          </div>
          {selectedHarnessActivationGateInspection.nodeAttemptIds.length > 0 ? (
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
                    data-activation-gate-node-attempt-id={nodeAttemptId}
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
          {selectedHarnessActivationGateInspection.nodeAttemptIds.length > 0 ? (
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
                        selectedHarnessNodeAttemptId === attempt.attemptId
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
                      data-policy-decision={attempt.policyDecision ?? ""}
                      data-receipt-refs={attempt.receiptIds.join("|")}
                      data-replay-fixture-ref={attempt.replay.fixtureRef ?? ""}
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
          {selectedHarnessActivationGateInspection.receiptRefs.length > 0 ? (
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
                      selectedHarnessActivationGateReceiptRef === receiptRef ||
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
          {selectedHarnessActivationGateInspection.replayFixtureRefs.length >
          0 ? (
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
                      selectedHarnessReplayFixtureRef === replayFixtureRef
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-activation-gate-replay-${index}`}
                    data-activation-gate-id={
                      selectedHarnessActivationGateInspection.gateId
                    }
                    data-activation-gate-replay-fixture-ref={replayFixtureRef}
                    onClick={() =>
                      onCopyHarnessDeepLink
                        ? onCopyHarnessDeepLink({
                            panel: "settings",
                            activationGateId:
                              selectedHarnessActivationGateInspection.gateId,
                            activationGateReplayFixtureRef: replayFixtureRef,
                            replayFixtureRef,
                          })
                        : onSelectHarnessReplayFixtureRef?.(replayFixtureRef)
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
    </>
  );
}
