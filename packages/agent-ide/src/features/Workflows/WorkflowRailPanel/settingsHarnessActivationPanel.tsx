import type { ReactNode } from "react";

import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import {
  workflowIssueTitle,
  workflowNodeName,
  workflowUniqueReceiptRefs,
} from "../../../runtime/workflow-rail-model";
import type { WorkflowProject } from "../../../types/graph";
import { workflowHarnessPackageDeepLinkTarget } from "./statusPrimitives";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPackageRestoreProps,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";
import type { WorkflowHarnessActivationGateAction } from "./types";

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

export function WorkflowSettingsHarnessActivationPanel({
  activationGateProposal,
  blessedHarnessWorkflow,
  firstHarnessActivationBlocker,
  harnessActivationBlockers,
  harnessActivationCandidate,
  harnessActivationGateActions,
  harnessActivationGateNodeAttempts,
  harnessActivationReady,
  harnessActivationRecord,
  harnessActivationWizardSteps,
  harnessActivationWorkerHandoffNodeAttemptIds,
  harnessActivationWorkerHandoffNodeAttempts,
  harnessActivationWorkerHandoffReplayFixtureRefs,
  harnessActivationWorkerHandoffTimelineReady,
  harnessActivationWorkerInvariantBlockers,
  harnessActivationWorkerInvariantReady,
  harnessActivationWorkerRequiredInvariantIds,
  packageImportActivationEnabled,
  packageImportActivationHandoff,
  packageImportHandoffWorkerBindingId,
  packageImportReplayIntegrityBlockers,
  packageImportReview,
  selectedHarnessActivationGateEvidenceRef,
  selectedHarnessActivationGateId,
  selectedHarnessActivationGateInspection,
  selectedHarnessActivationGateMutationCanary,
  selectedHarnessActivationGateNodeAttempt,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
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
  rollbackReady,
  selectedHarnessCanaryBoundary,
  selectedHarnessRollbackDrillId,
  selectedHarnessRollbackRestoreCanaryId,
  selectedHarnessRollbackRestoreReceiptRef,
  harnessWorkerBinding,
  selectedHarnessNodeAttemptId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  harnessForkMutationCanary,
  harnessForkMutationCanaryNodeAttemptIds,
  harnessForkWorkflow,
  onApplyHarnessActivationCandidate,
  onCheckActivationReadiness,
  onCopyHarnessDeepLink,
  onResolveIssue,
  onRunHarnessActivationDryRun,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onSelectProposal,
  workflow,
}: WorkflowSettingsHarnessActivationPanelProps) {
  return (
    <>
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
              <dd>{workflow.metadata.harness?.activationState ?? "blocked"}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>
                {harnessActivationRecord?.policyPosture ?? "proposal_only"}
              </dd>
            </div>
            <div>
              <dt>Canary</dt>
              <dd>{harnessActivationRecord?.canaryStatus ?? "not_run"}</dd>
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
                {harnessActivationWorkerInvariantReady ? "bound" : "blocked"}
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
              harnessActivationWorkerHandoffTimelineReady ? "true" : "false"
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
              rollback {harnessActivationRecord?.rollbackTarget ?? "not set"} ·
              worker {harnessWorkerBinding?.harnessWorkflowId ?? "unbound"} ·
              handoff {harnessActivationWorkerHandoffNodeAttempts.length}
            </small>
            <small>
              invariant{" "}
              {DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT}{" "}
              · {harnessActivationWorkerInvariantReady ? "bound" : "blocked"}
            </small>
          </article>
          {harnessActivationCandidate ? (
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-activation-candidate"
              data-candidate-decision={harnessActivationCandidate.decision}
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
                  canary {harnessActivationCandidate.canaryStatus} · rollback{" "}
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
                  harnessActivationCandidate.forkMutationCanary.mutationKind
                }
                data-harness-fork-mutation-diff-hash={
                  harnessActivationCandidate.forkMutationCanary.diffHash
                }
                data-harness-fork-mutation-receipt-count={
                  harnessActivationCandidate.forkMutationCanary.receiptRefs
                    .length
                }
                data-harness-fork-mutation-replay-count={
                  harnessActivationCandidate.forkMutationCanary
                    .replayFixtureRefs.length
                }
                data-harness-fork-mutation-node-attempt-count={
                  harnessActivationCandidate.forkMutationCanary.nodeAttemptIds
                    .length
                }
              >
                <strong>
                  {harnessActivationCandidate.forkMutationCanary.mutationKind}
                </strong>
                <span>
                  {harnessActivationCandidate.forkMutationCanary.targetPath}
                  {" · "}
                  {harnessActivationCandidate.forkMutationCanary.status}
                </span>
                <small>
                  {harnessActivationCandidate.forkMutationCanary.beforeValue}
                  {" -> "}
                  {harnessActivationCandidate.forkMutationCanary.afterValue}
                  {" · "}
                  {harnessActivationCandidate.forkMutationCanary.policyDecision}
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
                  {harnessActivationCandidate.workerBindingPreview.source} ·{" "}
                  {harnessActivationCandidate.workerBindingPreview.harnessHash}
                </small>
              </article>
              <article
                className={`workflow-output-row is-${
                  harnessActivationCandidate.rollbackRestoreCanary.status ===
                    "passed" ||
                  harnessActivationCandidate.rollbackRestoreCanary.status ===
                    "not_required"
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
                  {harnessActivationCandidate.rollbackRestoreCanary.hashVerified
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
                      data-gate-action-command={gateAction?.commandTestId ?? ""}
                    >
                      <strong>{gate.label}</strong>
                      <span>{gate.value}</span>
                      <small>{gate.detail}</small>
                      <div className="workflow-harness-authority-gate-actions">
                        {onCopyHarnessDeepLink ? (
                          <button
                            type="button"
                            className={`workflow-harness-ref-button ${
                              selectedHarnessActivationGateId === gate.gateId
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
              {harnessActivationCandidate.activationBlockers.length > 0 ? (
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
                Run a dry run to preview mintability without changing activation
                state.
              </span>
              <small>Dry-run candidates keep invalid forks blocked.</small>
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
                  selectedHarnessActivationGateId === step.id ? "is-active" : ""
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
                data-invariant-blockers={(step.invariantBlockers ?? []).join(
                  ",",
                )}
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
                selectedHarnessActivationGateNodeAttempt?.receiptIds.join(
                  "|",
                ) ??
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
                selectedHarnessActivationGateMutationCanary?.rollbackTarget ??
                ""
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
                selectedHarnessActivationGateInspection.gateAction?.actionId ??
                ""
              }
              data-gate-action-kind={
                selectedHarnessActivationGateInspection.gateAction?.kind ?? ""
              }
              data-gate-action-impact={
                selectedHarnessActivationGateInspection.gateAction?.impact ?? ""
              }
              data-gate-action-command={
                selectedHarnessActivationGateInspection.gateAction
                  ?.commandTestId ?? ""
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
                        packageImportReview.source.sourceWorkflowPath ?? ""
                      }
                      data-package-import-source-workflow-id={
                        packageImportReview.source.workflowId ?? ""
                      }
                      data-package-import-source-activation-id={
                        packageImportReview.source.activationId ?? ""
                      }
                      data-package-import-source-workflow-content-hash={
                        packageImportReview.source.workflowContentHash ?? ""
                      }
                      data-package-import-source-harness-hash={
                        packageImportReview.source.harnessHash ?? ""
                      }
                      data-package-import-source-worker-binding-id={
                        packageImportReview.source.workerBindingActivationId ??
                        ""
                      }
                      data-package-import-source-policy-posture={
                        packageImportReview.source.policyPosture ?? ""
                      }
                      data-package-import-source-mutation-canary-id={
                        packageImportReview.source.forkMutationCanaryId ?? ""
                      }
                      data-package-import-source-mutation-canary-status={
                        packageImportReview.source.forkMutationCanaryStatus ??
                        ""
                      }
                      data-package-import-source-mutation-canary-diff-hash={
                        packageImportReview.source.forkMutationCanaryDiffHash ??
                        ""
                      }
                      data-package-import-source-mutation-canary-receipt-ref={
                        packageImportReview.source
                          .forkMutationCanaryReceiptRefs?.[0] ?? ""
                      }
                      data-package-import-source-mutation-canary-replay-fixture-ref={
                        packageImportReview.source
                          .forkMutationCanaryReplayFixtureRefs?.[0] ?? ""
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
                        packageImportReview.source
                          .reviewedPackageSnapshotHash ?? ""
                      }
                      data-package-import-source-chrome-locale={
                        packageImportReview.source.workflowChromeLocale ?? ""
                      }
                      data-package-import-source-replay-fixture-count={
                        packageImportReview.source.replayFixtureRefs?.length ??
                        0
                      }
                      data-package-import-imported-workflow-path={
                        packageImportReview.imported.workflowPath
                      }
                      data-package-import-imported-workflow-id={
                        packageImportReview.imported.workflowId
                      }
                      data-package-import-imported-chrome-locale={
                        packageImportReview.imported.workflowChromeLocale ?? ""
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
                      data-package-import-replay-integrity-blockers={packageImportReplayIntegrityBlockers.join(
                        ",",
                      )}
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
                              packageImportReview.evidence.blockerCount === 1
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
                            {packageImportReview.source.sourceWorkflowPath ??
                              packageImportReview.packagePath}
                          </small>
                          <small>
                            Chrome locale{" "}
                            {packageImportReview.source.workflowChromeLocale ??
                              "default"}
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
                            packageImportActivationHandoff.canaryStatus ?? ""
                          }
                          data-package-import-handoff-mutation-canary-id={
                            packageImportActivationHandoff.forkMutationCanaryId ??
                            ""
                          }
                          data-package-import-handoff-mutation-canary-status={
                            packageImportActivationHandoff.forkMutationCanaryStatus ??
                            ""
                          }
                          data-package-import-handoff-mutation-canary-diff-hash={
                            packageImportActivationHandoff.forkMutationCanaryDiffHash ??
                            ""
                          }
                          data-package-import-handoff-mutation-canary-receipt-ref={
                            packageImportActivationHandoff
                              .forkMutationCanaryReceiptRefs?.[0] ?? ""
                          }
                          data-package-import-handoff-mutation-canary-replay-fixture-ref={
                            packageImportActivationHandoff
                              .forkMutationCanaryReplayFixtureRefs?.[0] ?? ""
                          }
                          data-package-import-handoff-mutation-canary-node-attempt-id={
                            packageImportActivationHandoff
                              .forkMutationCanaryNodeAttemptIds?.[0] ?? ""
                          }
                          data-package-import-handoff-mutation-canary-rollback-target={
                            packageImportActivationHandoff.forkMutationCanaryRollbackTarget ??
                            ""
                          }
                          data-package-import-handoff-rollback-target={
                            packageImportActivationHandoff.rollbackTarget ?? ""
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
                            packageImportActivationHandoff.policyPosture ?? ""
                          }
                          data-package-import-handoff-reviewed-package-snapshot-hash={
                            packageImportActivationHandoff.reviewedPackageSnapshotHash ??
                            ""
                          }
                          data-package-import-handoff-replay-fixture-count={
                            packageImportActivationHandoff.replayFixtureRefs
                              ?.length ?? 0
                          }
                          data-package-import-handoff-mintable={
                            packageImportActivationHandoff.mintable
                              ? "true"
                              : "false"
                          }
                          data-package-import-handoff-replay-integrity-blocker-count={
                            packageImportReplayIntegrityBlockers.length
                          }
                          data-package-import-handoff-replay-integrity-blockers={packageImportReplayIntegrityBlockers.join(
                            ",",
                          )}
                          data-package-import-handoff-blocker-count={
                            packageImportActivationHandoff.blockerCount
                          }
                          data-package-import-handoff-package-evidence-ready={
                            packageImportActivationHandoff.packageEvidenceReady
                              ? "true"
                              : "false"
                          }
                          data-package-import-handoff-activation-enabled={
                            packageImportActivationEnabled ? "true" : "false"
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
                              {packageImportActivationHandoff.forkMutationCanaryStatus ??
                                "not_run"}{" "}
                              · rollback{" "}
                              {packageImportActivationHandoff.rollbackTarget ??
                                "not set"}{" "}
                              · worker{" "}
                              {packageImportHandoffWorkerBindingId || "unbound"}
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
                                !packageImportActivationHandoff.deepLinkTargets
                                  .activationId
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
                                !packageImportActivationHandoff.deepLinkTargets
                                  .canary
                              }
                              onClick={() =>
                                onCopyHarnessDeepLink?.({
                                  panel: "settings",
                                  activationGateId: "canary",
                                  activationGateEvidenceRef:
                                    packageImportActivationHandoff
                                      .deepLinkTargets.canary ?? undefined,
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
                                !packageImportActivationHandoff.deepLinkTargets
                                  .mutationCanary ||
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
                                !packageImportActivationHandoff.deepLinkTargets
                                  .rollbackRestore
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
                              disabled={!packageImportHandoffWorkerBindingId}
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
                                      activationGateId: "mutation-canary",
                                      activationGateEvidenceRef:
                                        harnessPackageForkMutationCanary?.canaryId ??
                                        ref,
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
                                          activationGateId: "package-evidence",
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
                                          activationGateId: "package-evidence",
                                          activationGateReplayFixtureRef: ref,
                                          replayFixtureRef: ref,
                                        })
                                      : onSelectHarnessReplayFixtureRef?.(ref);
                                    return;
                                  }
                                  if (row.kind === "node_attempt") {
                                    onCopyHarnessDeepLink?.({
                                      panel: "settings",
                                      activationGateId: "package-evidence",
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
              {selectedHarnessActivationGateInspection.nodeAttemptIds.length >
              0 ? (
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
              {selectedHarnessActivationGateInspection.nodeAttemptIds.length >
              0 ? (
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
              {selectedHarnessActivationGateInspection.receiptRefs.length >
              0 ? (
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
                          selectedHarnessReplayFixtureRef === replayFixtureRef
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
                    <span>{workflowNodeName(workflow, issue.nodeId)}</span>
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
    </>
  );
}
