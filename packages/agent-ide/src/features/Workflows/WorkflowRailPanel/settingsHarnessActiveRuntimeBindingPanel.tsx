import { WorkflowSettingsHarnessActiveRuntimeBindingDeepLinks } from "./settingsHarnessActiveRuntimeBindingDeepLinks";
import { WorkflowSettingsHarnessActiveRuntimeBindingSummary } from "./settingsHarnessActiveRuntimeBindingSummary";
import type {
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActiveRuntimeBindingPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessRollbackProps,
      | "harnessActiveRuntimeBinding"
      | "harnessActiveRuntimeRollbackApplyBlockers"
      | "harnessActiveRuntimeRollbackApplyDisabled"
      | "harnessActiveRuntimeRollbackApplyProof"
      | "harnessActiveRuntimeRollbackDryRunPassed"
      | "harnessActiveRuntimeRollbackExecutionProof"
      | "harnessActiveRuntimeRollbackProofBindingBlockers"
      | "harnessActiveRuntimeRollbackProofStillBound"
      | "selectedHarnessRollbackTarget"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "selectedHarnessDefaultDispatchId"
      | "selectedHarnessNodeAttemptId"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
      | "selectedHarnessSelectorDecisionId"
      | "selectedHarnessWorkerBindingId"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCopyHarnessDeepLink"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
      | "onSelectHarnessRollbackTarget"
    > {}

export function WorkflowSettingsHarnessActiveRuntimeBindingPanel({
  harnessActiveRuntimeBinding,
  harnessActiveRuntimeRollbackApplyBlockers,
  harnessActiveRuntimeRollbackApplyDisabled,
  harnessActiveRuntimeRollbackApplyProof,
  harnessActiveRuntimeRollbackDryRunPassed,
  harnessActiveRuntimeRollbackExecutionProof,
  harnessActiveRuntimeRollbackProofBindingBlockers,
  harnessActiveRuntimeRollbackProofStillBound,
  selectedHarnessDefaultDispatchId,
  selectedHarnessNodeAttemptId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  selectedHarnessRollbackTarget,
  selectedHarnessSelectorDecisionId,
  selectedHarnessWorkerBindingId,
  onCopyHarnessDeepLink,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onSelectHarnessRollbackTarget,
}: WorkflowSettingsHarnessActiveRuntimeBindingPanelProps) {
  if (!harnessActiveRuntimeBinding) {
    return null;
  }

  return (
    <section
      className="workflow-rail-section workflow-harness-active-runtime-binding"
      data-testid="workflow-harness-active-runtime-binding"
      data-binding-matched={
        harnessActiveRuntimeBinding.bindingMatched ? "true" : "false"
      }
      data-workflow-id={harnessActiveRuntimeBinding.workflowId}
      data-activation-id={harnessActiveRuntimeBinding.activationId}
      data-harness-hash={harnessActiveRuntimeBinding.harnessHash}
      data-selector-decision-id={harnessActiveRuntimeBinding.selectorDecisionId}
      data-default-dispatch-id={harnessActiveRuntimeBinding.defaultDispatchId}
      data-worker-binding-id={harnessActiveRuntimeBinding.workerBindingId}
      data-rollback-target={harnessActiveRuntimeBinding.rollbackTarget}
      data-worker-binding-authority-ready={
        harnessActiveRuntimeBinding.workerBindingAuthorityReady
          ? "true"
          : "false"
      }
      data-worker-launch-reviewed-import-invariant-bound={
        harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
          ? "true"
          : "false"
      }
      data-worker-required-invariant-ids={harnessActiveRuntimeBinding.workerBindingRequiredInvariantIds.join(
        ",",
      )}
      data-worker-invariant-blockers={harnessActiveRuntimeBinding.workerInvariantBlockers.join(
        ",",
      )}
      data-worker-binding-registry-bound={
        harnessActiveRuntimeBinding.workerBindingRegistryBound
          ? "true"
          : "false"
      }
      data-worker-binding-registry-status={
        harnessActiveRuntimeBinding.workerBindingRegistryStatus
      }
      data-worker-attach-status={harnessActiveRuntimeBinding.workerAttachStatus}
      data-worker-attach-accepted={
        harnessActiveRuntimeBinding.workerAttachAccepted ? "true" : "false"
      }
      data-live-promotion-readiness-proof-id={
        harnessActiveRuntimeBinding.selectorLivePromotionReadinessProofId
      }
      data-live-promotion-readiness-proof-match={
        harnessActiveRuntimeBinding.livePromotionReadinessProofIdsMatch
          ? "true"
          : "false"
      }
      data-selected-selector-decision-id={
        selectedHarnessSelectorDecisionId ?? ""
      }
      data-selected-default-dispatch-id={selectedHarnessDefaultDispatchId ?? ""}
      data-selected-worker-binding-id={selectedHarnessWorkerBindingId ?? ""}
      data-selected-rollback-target={selectedHarnessRollbackTarget ?? ""}
      data-selected-receipt-ref={selectedHarnessReceiptRef ?? ""}
      data-selected-replay-fixture-ref={selectedHarnessReplayFixtureRef ?? ""}
      data-selected-node-attempt-id={selectedHarnessNodeAttemptId ?? ""}
      data-rollback-proof-bound={
        harnessActiveRuntimeBinding.workerRollbackProof.bound ? "true" : "false"
      }
      data-rollback-proof-blockers={harnessActiveRuntimeBinding.workerRollbackProof.blockers.join(
        ",",
      )}
      data-rollback-readiness-proof-id={
        harnessActiveRuntimeBinding.workerRollbackProof.readinessProofId
      }
      data-rollback-live-shadow-gate-id={
        harnessActiveRuntimeBinding.workerRollbackProof
          .liveShadowComparisonGateId
      }
      data-rollback-live-shadow-gate-ready={
        harnessActiveRuntimeBinding.workerRollbackProof
          .liveShadowComparisonGateReady
          ? "true"
          : "false"
      }
      data-rollback-activation-id={
        harnessActiveRuntimeBinding.workerRollbackProof.activationId
      }
      data-rollback-harness-hash={
        harnessActiveRuntimeBinding.workerRollbackProof.harnessHash
      }
      data-rollback-policy-decision={
        harnessActiveRuntimeBinding.workerRollbackProof.policyDecision
      }
      data-rollback-launch-envelope-id={
        harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
          ?.envelopeId ?? ""
      }
      data-rollback-handoff-receipt-id={
        harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
          ?.receiptId ?? ""
      }
      data-rollback-node-attempt-id={
        harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt?.attemptId ??
        ""
      }
      data-rollback-replay-fixture-ref={
        harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef
      }
      data-rollback-execution-dry-run-status={
        harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryStatus ??
        "not_run"
      }
      data-rollback-execution-canary-result-id={
        harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryResultId ?? ""
      }
      data-rollback-execution-canary-status={
        harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryStatus ??
        "not_run"
      }
      data-rollback-execution-canary-hash-verified={
        harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryHashVerified
          ? "true"
          : "false"
      }
      data-rollback-execution-apply-readiness={
        harnessActiveRuntimeRollbackProofStillBound &&
        harnessActiveRuntimeRollbackDryRunPassed
          ? "ready"
          : "blocked"
      }
      data-rollback-execution-apply-disabled={
        harnessActiveRuntimeRollbackApplyDisabled ? "true" : "false"
      }
      data-rollback-execution-apply-policy-decision={
        harnessActiveRuntimeRollbackExecutionProof?.apply.policyDecision ?? ""
      }
      data-rollback-apply-execution-status={
        harnessActiveRuntimeRollbackApplyProof?.applyStatus ?? "not_run"
      }
      data-rollback-apply-execution-id={
        harnessActiveRuntimeRollbackApplyProof?.executionId ?? ""
      }
      data-rollback-apply-receipt-id={
        harnessActiveRuntimeRollbackApplyProof?.rollbackReceiptId ?? ""
      }
      data-rollback-apply-audit-event-id={
        harnessActiveRuntimeRollbackApplyProof?.auditEventId ?? ""
      }
      data-rollback-apply-target-verified={
        harnessActiveRuntimeRollbackApplyProof?.rollbackTargetVerified
          ? "true"
          : "false"
      }
      data-rollback-apply-hash-verified={
        harnessActiveRuntimeRollbackApplyProof?.hashVerified ? "true" : "false"
      }
      data-rollback-apply-policy-decision={
        harnessActiveRuntimeRollbackApplyProof?.policyDecision ?? ""
      }
      data-rollback-apply-blockers={harnessActiveRuntimeRollbackApplyBlockers.join(
        ",",
      )}
      data-rollback-execution-blockers={[
        ...(harnessActiveRuntimeRollbackExecutionProof?.blockers ?? []),
        ...(harnessActiveRuntimeRollbackExecutionProof?.dryRun.blockers ?? []),
        ...harnessActiveRuntimeRollbackProofBindingBlockers,
      ].join(",")}
    >
      <WorkflowSettingsHarnessActiveRuntimeBindingSummary
        harnessActiveRuntimeBinding={harnessActiveRuntimeBinding}
      />
      <WorkflowSettingsHarnessActiveRuntimeBindingDeepLinks
        dataTestId="workflow-harness-active-runtime-binding-deep-links"
        harnessActiveRuntimeBinding={harnessActiveRuntimeBinding}
        selectedHarnessDefaultDispatchId={selectedHarnessDefaultDispatchId}
        selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
        selectedHarnessReceiptRef={selectedHarnessReceiptRef}
        selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
        selectedHarnessRollbackTarget={selectedHarnessRollbackTarget ?? null}
        selectedHarnessSelectorDecisionId={selectedHarnessSelectorDecisionId}
        selectedHarnessWorkerBindingId={selectedHarnessWorkerBindingId}
        onCopyHarnessDeepLink={onCopyHarnessDeepLink}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
        onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
        onSelectHarnessRollbackTarget={onSelectHarnessRollbackTarget}
      />
      {harnessActiveRuntimeBinding.blockers.length > 0 ? (
        <div
          className="workflow-rail-list"
          data-testid="workflow-harness-active-runtime-binding-blockers"
          data-activation-blockers={harnessActiveRuntimeBinding.blockers.join(
            "|",
          )}
        >
          {harnessActiveRuntimeBinding.blockers.map((blocker) => (
            <article key={blocker} className="workflow-test-row is-blocked">
              <strong>Blocked</strong>
              <span>{blocker}</span>
            </article>
          ))}
        </div>
      ) : null}
    </section>
  );
}
