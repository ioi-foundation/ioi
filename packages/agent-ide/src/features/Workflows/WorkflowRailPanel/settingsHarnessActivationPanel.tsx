import type { ReactNode } from "react";

import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import {
  workflowIssueTitle,
  workflowNodeName,
} from "../../../runtime/workflow-rail-model";
import type { WorkflowProject } from "../../../types/graph";
import { WorkflowSettingsHarnessActivationGatePanel } from "./settingsHarnessActivationGatePanel";
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
          <WorkflowSettingsHarnessActivationGatePanel
            harnessActivationGateNodeAttempts={
              harnessActivationGateNodeAttempts
            }
            harnessForkMutationCanary={harnessForkMutationCanary}
            harnessForkMutationCanaryNodeAttemptIds={
              harnessForkMutationCanaryNodeAttemptIds
            }
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
            selectedHarnessActivationGateMutationCanary={
              selectedHarnessActivationGateMutationCanary
            }
            selectedHarnessActivationGateNodeAttempt={
              selectedHarnessActivationGateNodeAttempt
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
            selectedHarnessCanaryBoundary={selectedHarnessCanaryBoundary}
            selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
            selectedHarnessReceiptRef={selectedHarnessReceiptRef}
            selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
            selectedHarnessRollbackDrillId={selectedHarnessRollbackDrillId}
            selectedHarnessRollbackRestoreCanaryId={
              selectedHarnessRollbackRestoreCanaryId
            }
            selectedHarnessRollbackRestoreReceiptRef={
              selectedHarnessRollbackRestoreReceiptRef
            }
            onApplyHarnessActivationCandidate={
              onApplyHarnessActivationCandidate
            }
            onCopyHarnessDeepLink={onCopyHarnessDeepLink}
            onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
            onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
          />
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
