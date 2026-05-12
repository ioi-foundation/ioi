import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessRollbackRestoreProofPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "harnessActivationRollbackExecution"
      | "harnessActivationRollbackProof"
    >,
    Pick<
      WorkflowSettingsHarnessRollbackProps,
      | "harnessRollbackDrillReceiptRefs"
      | "harnessRollbackExecutionReceiptRefs"
      | "harnessSelectedRollbackTarget"
    >,
    Pick<WorkflowSettingsHarnessWorkerBindingProps, "selectedHarnessReceiptRef">,
    Pick<WorkflowSettingsHarnessCallbacks, "onSelectHarnessReceiptRef"> {}

export function WorkflowSettingsHarnessRollbackRestoreProofPanel({
  harnessActivationRollbackExecution,
  harnessActivationRollbackProof,
  harnessRollbackDrillReceiptRefs,
  harnessRollbackExecutionReceiptRefs,
  harnessSelectedRollbackTarget,
  selectedHarnessReceiptRef,
  onSelectHarnessReceiptRef,
}: WorkflowSettingsHarnessRollbackRestoreProofPanelProps) {
  return (
    <>
      <section
        className="workflow-rail-section"
        data-testid="workflow-harness-rollback-drill-proof"
        data-drill-status={
          harnessActivationRollbackProof?.drillStatus ?? "not_run"
        }
        data-receipt-refs={harnessRollbackDrillReceiptRefs.join("|")}
      >
        <h4>Rollback proof</h4>
        <article
          className={`workflow-output-row is-${
            harnessActivationRollbackProof?.drillStatus === "passed"
              ? "ready"
              : "blocked"
          }`}
          data-receipt-refs={harnessRollbackDrillReceiptRefs.join("|")}
        >
          <strong>
            {harnessActivationRollbackProof?.rollbackTarget ??
              harnessSelectedRollbackTarget}
          </strong>
          <span>
            executed{" "}
            {harnessActivationRollbackProof?.rollbackExecuted
              ? "yes"
              : "not yet"}
            {" · "}
            restored{" "}
            {harnessActivationRollbackProof?.restoredWorkerBinding
              ?.harnessActivationId ??
              harnessActivationRollbackProof?.restoredWorkerBinding
                ?.harnessWorkflowId ??
              "pending"}
          </span>
          <small>
            {harnessRollbackDrillReceiptRefs[0] ??
              harnessActivationRollbackProof?.policyDecision ??
              "rollback drill pending"}
          </small>
        </article>
        {harnessRollbackDrillReceiptRefs.length > 0 ? (
          <div
            className="workflow-harness-authority-gate-actions"
            data-testid="workflow-harness-rollback-drill-receipt-refs"
          >
            {harnessRollbackDrillReceiptRefs.map(
              (receiptRef, index: number) => (
                <button
                  key={receiptRef}
                  type="button"
                  className={`workflow-harness-ref-button ${
                    selectedHarnessReceiptRef === receiptRef ? "is-active" : ""
                  }`}
                  data-testid={`workflow-harness-rollback-drill-receipt-${index}`}
                  data-receipt-ref={receiptRef}
                  onClick={() => onSelectHarnessReceiptRef?.(receiptRef)}
                >
                  <code>{receiptRef}</code>
                </button>
              ),
            )}
          </div>
        ) : null}
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-harness-rollback-execution-proof"
        data-execution-status={
          harnessActivationRollbackExecution?.executionStatus ?? "not_run"
        }
        data-receipt-refs={harnessRollbackExecutionReceiptRefs.join("|")}
        data-restore-receipt-binding-ref={
          harnessActivationRollbackExecution?.restoreReceiptBindingRef ?? ""
        }
      >
        <h4>Rollback execution</h4>
        <article
          className={`workflow-output-row is-${
            harnessActivationRollbackExecution?.executionStatus === "applied"
              ? "ready"
              : "blocked"
          }`}
          data-receipt-refs={harnessRollbackExecutionReceiptRefs.join("|")}
        >
          <strong>
            {harnessActivationRollbackExecution?.rollbackTarget ??
              harnessSelectedRollbackTarget}
          </strong>
          <span>
            executed{" "}
            {harnessActivationRollbackExecution?.rollbackExecuted
              ? "yes"
              : "not yet"}
            {" · "}
            hash{" "}
            {harnessActivationRollbackExecution?.hashVerified
              ? "verified"
              : "pending"}
          </span>
          <small>
            {harnessRollbackExecutionReceiptRefs[0] ??
              harnessActivationRollbackExecution?.policyDecision ??
              "rollback execution pending"}
          </small>
        </article>
        {harnessRollbackExecutionReceiptRefs.length > 0 ? (
          <div
            className="workflow-harness-authority-gate-actions"
            data-testid="workflow-harness-rollback-execution-receipt-refs"
          >
            {harnessRollbackExecutionReceiptRefs.map(
              (receiptRef, index: number) => (
                <button
                  key={receiptRef}
                  type="button"
                  className={`workflow-harness-ref-button ${
                    selectedHarnessReceiptRef === receiptRef ? "is-active" : ""
                  }`}
                  data-testid={`workflow-harness-rollback-execution-receipt-${index}`}
                  data-receipt-ref={receiptRef}
                  onClick={() => onSelectHarnessReceiptRef?.(receiptRef)}
                >
                  <code>{receiptRef}</code>
                </button>
              ),
            )}
          </div>
        ) : null}
        {harnessActivationRollbackExecution ? (
          <div className="workflow-inline-metadata">
            <span>{harnessActivationRollbackExecution.restoreStrategy}</span>
            <code>
              {harnessActivationRollbackExecution.actualWorkflowContentHash ??
                "hash pending"}
            </code>
          </div>
        ) : null}
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-harness-git-restore-proof"
        data-restore-strategy={
          harnessActivationRollbackExecution?.restoreStrategy ?? "not_run"
        }
        data-restore-blockers={
          harnessActivationRollbackExecution?.restoreBlockers?.length ?? 0
        }
      >
        <h4>Git restore proof</h4>
        <article
          className={`workflow-output-row is-${
            harnessActivationRollbackExecution?.restoreBlockers?.length
              ? "blocked"
              : harnessActivationRollbackExecution?.executionStatus ===
                  "applied"
                ? "ready"
                : "blocked"
          }`}
          data-testid="workflow-harness-git-restore-summary"
        >
          <strong>
            {harnessActivationRollbackExecution?.restoredRevision ??
              harnessActivationRollbackExecution?.restoredRevisionBinding
                ?.activatedRevision ??
              "revision pending"}
          </strong>
          <span>
            {harnessActivationRollbackExecution?.restoreStrategy ??
              "git restore not run"}
            {" · "}
            {harnessActivationRollbackExecution?.restoredFileSha256 ??
              "file sha pending"}
          </span>
          <small>
            {harnessActivationRollbackExecution?.restoreRelativeWorkflowPath ??
              harnessActivationRollbackExecution?.workflowPath ??
              "workflow path pending"}
          </small>
        </article>
        <div
          className="workflow-inline-metadata"
          data-testid="workflow-harness-git-restore-paths"
        >
          <span>
            {harnessActivationRollbackExecution?.restoreRepoRoot ??
              "repo root pending"}
          </span>
          <code>
            {harnessActivationRollbackExecution?.restoreRelativeWorkflowPath ??
              harnessActivationRollbackExecution?.workflowPath ??
              "relative path pending"}
          </code>
        </div>
        <div
          className="workflow-inline-metadata"
          data-testid="workflow-harness-git-restore-hashes"
        >
          <span>
            expected{" "}
            {harnessActivationRollbackExecution?.expectedWorkflowContentHash ??
              "pending"}
          </span>
          <code>
            actual{" "}
            {harnessActivationRollbackExecution?.actualWorkflowContentHash ??
              "pending"}
          </code>
        </div>
        {harnessActivationRollbackExecution?.restoreBlockers?.length ? (
          <div
            className="workflow-rail-list"
            data-testid="workflow-harness-git-restore-blockers"
          >
            {harnessActivationRollbackExecution.restoreBlockers.map(
              (blocker, index: number) => (
                <article
                  key={`${blocker}-${index}`}
                  className="workflow-test-row is-blocked"
                  data-testid={`workflow-harness-git-restore-blocker-${index}`}
                >
                  <strong>{blocker}</strong>
                  <span>restore blocker</span>
                </article>
              ),
            )}
          </div>
        ) : null}
      </section>
    </>
  );
}
