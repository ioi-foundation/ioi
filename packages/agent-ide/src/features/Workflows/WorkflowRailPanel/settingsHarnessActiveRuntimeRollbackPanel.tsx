import { WorkflowSettingsHarnessActiveRuntimeBindingPanel } from "./settingsHarnessActiveRuntimeBindingPanel";
import { WorkflowSettingsHarnessRollbackRestoreProofPanel } from "./settingsHarnessRollbackRestoreProofPanel";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActiveRuntimeRollbackPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      "harnessActivationRollbackExecution" | "harnessActivationRollbackProof"
    >,
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
      | "harnessRollbackDrillReceiptRefs"
      | "harnessRollbackExecutionReceiptRefs"
      | "harnessSelectedRollbackTarget"
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
    Pick<WorkflowSettingsHarnessPromotionProps, "harnessForkWorkflow">,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onApplyActiveRuntimeRollback"
      | "onCopyHarnessDeepLink"
      | "onExecuteHarnessRollback"
      | "onRunActiveRuntimeRollbackDryRun"
      | "onRunHarnessRollbackDrill"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
      | "onSelectHarnessRollbackTarget"
    > {}

export function WorkflowSettingsHarnessActiveRuntimeRollbackPanel({
  harnessActivationRollbackExecution,
  harnessActivationRollbackProof,
  harnessActiveRuntimeBinding,
  harnessActiveRuntimeRollbackApplyBlockers,
  harnessActiveRuntimeRollbackApplyDisabled,
  harnessActiveRuntimeRollbackApplyProof,
  harnessActiveRuntimeRollbackDryRunPassed,
  harnessActiveRuntimeRollbackExecutionProof,
  harnessActiveRuntimeRollbackProofBindingBlockers,
  harnessActiveRuntimeRollbackProofStillBound,
  harnessForkWorkflow,
  harnessRollbackDrillReceiptRefs,
  harnessRollbackExecutionReceiptRefs,
  harnessSelectedRollbackTarget,
  selectedHarnessDefaultDispatchId,
  selectedHarnessNodeAttemptId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  selectedHarnessRollbackTarget,
  selectedHarnessSelectorDecisionId,
  selectedHarnessWorkerBindingId,
  onApplyActiveRuntimeRollback,
  onCopyHarnessDeepLink,
  onExecuteHarnessRollback,
  onRunActiveRuntimeRollbackDryRun,
  onRunHarnessRollbackDrill,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onSelectHarnessRollbackTarget,
}: WorkflowSettingsHarnessActiveRuntimeRollbackPanelProps) {
  return (
    <>
      <WorkflowSettingsHarnessActiveRuntimeBindingPanel
        harnessActiveRuntimeBinding={harnessActiveRuntimeBinding}
        harnessActiveRuntimeRollbackApplyBlockers={
          harnessActiveRuntimeRollbackApplyBlockers
        }
        harnessActiveRuntimeRollbackApplyDisabled={
          harnessActiveRuntimeRollbackApplyDisabled
        }
        harnessActiveRuntimeRollbackApplyProof={
          harnessActiveRuntimeRollbackApplyProof
        }
        harnessActiveRuntimeRollbackDryRunPassed={
          harnessActiveRuntimeRollbackDryRunPassed
        }
        harnessActiveRuntimeRollbackExecutionProof={
          harnessActiveRuntimeRollbackExecutionProof
        }
        harnessActiveRuntimeRollbackProofBindingBlockers={
          harnessActiveRuntimeRollbackProofBindingBlockers
        }
        harnessActiveRuntimeRollbackProofStillBound={
          harnessActiveRuntimeRollbackProofStillBound
        }
        selectedHarnessDefaultDispatchId={selectedHarnessDefaultDispatchId}
        selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
        selectedHarnessReceiptRef={selectedHarnessReceiptRef}
        selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
        selectedHarnessRollbackTarget={selectedHarnessRollbackTarget}
        selectedHarnessSelectorDecisionId={selectedHarnessSelectorDecisionId}
        selectedHarnessWorkerBindingId={selectedHarnessWorkerBindingId}
        onCopyHarnessDeepLink={onCopyHarnessDeepLink}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
        onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
        onSelectHarnessRollbackTarget={onSelectHarnessRollbackTarget}
      />
      {harnessActiveRuntimeBinding ? (
        <article
          className={`workflow-output-row is-${
            harnessActiveRuntimeBinding.workerRollbackProof.bound
              ? "ready"
              : "blocked"
          }`}
          data-testid="workflow-harness-active-runtime-rollback-proof"
          data-rollback-proof-bound={
            harnessActiveRuntimeBinding.workerRollbackProof.bound
              ? "true"
              : "false"
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
            harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
              ?.attemptId ?? ""
          }
          data-rollback-replay-fixture-ref={
            harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef
          }
          data-rollback-execution-dry-run-status={
            harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryStatus ??
            "not_run"
          }
          data-rollback-execution-canary-result-id={
            harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryResultId ??
            ""
          }
          data-rollback-execution-canary-status={
            harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryStatus ??
            "not_run"
          }
          data-rollback-execution-canary-hash-verified={
            harnessActiveRuntimeRollbackExecutionProof?.dryRun
              .canaryHashVerified
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
            harnessActiveRuntimeRollbackExecutionProof?.apply.policyDecision ??
            ""
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
            harnessActiveRuntimeRollbackApplyProof?.hashVerified
              ? "true"
              : "false"
          }
          data-rollback-apply-policy-decision={
            harnessActiveRuntimeRollbackApplyProof?.policyDecision ?? ""
          }
          data-rollback-apply-blockers={harnessActiveRuntimeRollbackApplyBlockers.join(
            ",",
          )}
          data-rollback-execution-blockers={[
            ...(harnessActiveRuntimeRollbackExecutionProof?.blockers ?? []),
            ...(harnessActiveRuntimeRollbackExecutionProof?.dryRun.blockers ??
              []),
            ...harnessActiveRuntimeRollbackProofBindingBlockers,
          ].join(",")}
        >
          <strong>Rollback proof</strong>
          <span>
            {harnessActiveRuntimeBinding.workerRollbackProof.bound
              ? "bound to live-shadow gate"
              : "blocked"}
          </span>
          <small>
            readiness{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof.readinessProofId ||
              "missing"}
          </small>
          <small>
            gate{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof
              .liveShadowComparisonGateId || "missing"}{" "}
            ·{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof
              .liveShadowComparisonGateReady
              ? "ready"
              : "blocked"}
          </small>
          <small>
            policy{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof.policyDecision ||
              "missing"}
          </small>
          <small>
            envelope{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
              ?.envelopeId ?? "missing"}
          </small>
          <small>
            handoff{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
              ?.receiptId ?? "missing"}
          </small>
          <small>
            attempt{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
              ?.attemptId ?? "missing"}
          </small>
          <small>
            replay{" "}
            {harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef ||
              "missing"}
          </small>
          <small>
            dry run{" "}
            {harnessActiveRuntimeRollbackExecutionProof?.dryRun.canaryStatus ??
              "not run"}{" "}
            · canary{" "}
            {harnessActiveRuntimeRollbackExecutionProof?.dryRun
              .canaryResultId ?? "pending"}
          </small>
          <small>
            apply{" "}
            {harnessActiveRuntimeRollbackApplyDisabled ? "blocked" : "ready"} ·
            proof{" "}
            {harnessActiveRuntimeRollbackProofStillBound
              ? "bound"
              : "not restored"}
          </small>
          <small>
            rollback apply{" "}
            {harnessActiveRuntimeRollbackApplyProof?.applyStatus ?? "not run"} ·
            receipt{" "}
            {harnessActiveRuntimeRollbackApplyProof?.rollbackReceiptId ??
              "pending"}
          </small>
          {harnessActiveRuntimeBinding.workerRollbackProof.blockers.length >
          0 ? (
            <small>
              blockers{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof.blockers.join(
                ", ",
              )}
            </small>
          ) : null}
          <div className="workflow-harness-authority-gate-actions">
            <button
              type="button"
              data-testid="workflow-harness-active-runtime-rollback-dry-run"
              data-rollback-action-kind="dry_run"
              disabled={
                !onRunActiveRuntimeRollbackDryRun ||
                !harnessActiveRuntimeBinding.workerRollbackProof.bound
              }
              onClick={onRunActiveRuntimeRollbackDryRun}
            >
              Rollback dry run
            </button>
            <button
              type="button"
              data-testid="workflow-harness-active-runtime-rollback-apply"
              data-rollback-action-kind="apply"
              data-rollback-apply-disabled={
                harnessActiveRuntimeRollbackApplyDisabled ? "true" : "false"
              }
              disabled={harnessActiveRuntimeRollbackApplyDisabled}
              onClick={onApplyActiveRuntimeRollback}
            >
              Apply rollback
            </button>
          </div>
        </article>
      ) : null}
      {harnessForkWorkflow ? (
        <div
          className="workflow-harness-activation-actions"
          data-testid="workflow-harness-active-runtime-rollback-actions"
        >
          <button
            type="button"
            data-testid="workflow-harness-worker-binding-run-rollback-drill"
            disabled={!onRunHarnessRollbackDrill}
            onClick={onRunHarnessRollbackDrill}
          >
            Run rollback drill
          </button>
          <button
            type="button"
            data-testid="workflow-harness-worker-binding-execute-rollback"
            disabled={!onExecuteHarnessRollback}
            onClick={onExecuteHarnessRollback}
          >
            Execute rollback
          </button>
        </div>
      ) : null}
      <WorkflowSettingsHarnessRollbackRestoreProofPanel
        harnessActivationRollbackExecution={harnessActivationRollbackExecution}
        harnessActivationRollbackProof={harnessActivationRollbackProof}
        harnessRollbackDrillReceiptRefs={harnessRollbackDrillReceiptRefs}
        harnessRollbackExecutionReceiptRefs={
          harnessRollbackExecutionReceiptRefs
        }
        harnessSelectedRollbackTarget={harnessSelectedRollbackTarget}
        selectedHarnessReceiptRef={selectedHarnessReceiptRef}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
      />
    </>
  );
}
