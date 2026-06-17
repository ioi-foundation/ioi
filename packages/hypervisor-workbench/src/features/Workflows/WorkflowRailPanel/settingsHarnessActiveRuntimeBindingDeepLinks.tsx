import type {
  WorkflowSettingsHarnessActiveRuntimeBinding,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActiveRuntimeBindingDeepLinksProps
  extends Pick<
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
    > {
  dataTestId: string;
  harnessActiveRuntimeBinding: WorkflowSettingsHarnessActiveRuntimeBinding;
  selectedHarnessRollbackTarget: string | null;
}

export function WorkflowSettingsHarnessActiveRuntimeBindingDeepLinks({
  dataTestId,
  harnessActiveRuntimeBinding,
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
}: WorkflowSettingsHarnessActiveRuntimeBindingDeepLinksProps) {
  return (
    <div
      className="workflow-harness-authority-gate-actions"
      data-testid={dataTestId}
    >
      <button
        type="button"
        className={`workflow-harness-ref-button ${
          selectedHarnessSelectorDecisionId ===
          harnessActiveRuntimeBinding.selectorDecisionId
            ? "is-active"
            : ""
        }`}
        data-testid="workflow-harness-active-runtime-binding-selector-link"
        data-deep-link-kind="selector_decision"
        data-deep-link-target={harnessActiveRuntimeBinding.selectorDecisionId}
        disabled={!onCopyHarnessDeepLink}
        onClick={() =>
          onCopyHarnessDeepLink?.({
            panel: "settings",
            selectorDecisionId: harnessActiveRuntimeBinding.selectorDecisionId,
          })
        }
      >
        <code>{harnessActiveRuntimeBinding.selectorDecisionId}</code>
      </button>
      <button
        type="button"
        className={`workflow-harness-ref-button ${
          selectedHarnessDefaultDispatchId ===
          harnessActiveRuntimeBinding.defaultDispatchId
            ? "is-active"
            : ""
        }`}
        data-testid="workflow-harness-active-runtime-binding-dispatch-link"
        data-deep-link-kind="default_dispatch"
        data-deep-link-target={harnessActiveRuntimeBinding.defaultDispatchId}
        disabled={!onCopyHarnessDeepLink}
        onClick={() =>
          onCopyHarnessDeepLink?.({
            panel: "settings",
            dispatchId: harnessActiveRuntimeBinding.defaultDispatchId,
          })
        }
      >
        <code>{harnessActiveRuntimeBinding.defaultDispatchId}</code>
      </button>
      <button
        type="button"
        className={`workflow-harness-ref-button ${
          selectedHarnessWorkerBindingId ===
          harnessActiveRuntimeBinding.workerBindingId
            ? "is-active"
            : ""
        }`}
        data-testid="workflow-harness-active-runtime-binding-worker-link"
        data-deep-link-kind="worker_binding"
        data-deep-link-target={harnessActiveRuntimeBinding.workerBindingId}
        disabled={!onCopyHarnessDeepLink}
        onClick={() =>
          onCopyHarnessDeepLink?.({
            panel: "settings",
            workerBindingId: harnessActiveRuntimeBinding.workerBindingId,
          })
        }
      >
        <code>
          {harnessActiveRuntimeBinding.workerBinding?.source ?? "worker"}
          {" · "}
          {harnessActiveRuntimeBinding.workerBindingId}
        </code>
      </button>
      <button
        type="button"
        className={`workflow-harness-ref-button ${
          selectedHarnessRollbackTarget ===
          harnessActiveRuntimeBinding.rollbackTarget
            ? "is-active"
            : ""
        }`}
        data-testid="workflow-harness-active-runtime-binding-rollback-link"
        data-deep-link-kind="rollback_target"
        data-deep-link-target={harnessActiveRuntimeBinding.rollbackTarget}
        data-rollback-target={harnessActiveRuntimeBinding.rollbackTarget}
        onClick={() => {
          onSelectHarnessRollbackTarget?.(
            harnessActiveRuntimeBinding.rollbackTarget,
          );
          onCopyHarnessDeepLink?.({
            panel: "settings",
            rollbackTarget: harnessActiveRuntimeBinding.rollbackTarget,
          });
        }}
      >
        <code>{harnessActiveRuntimeBinding.rollbackTarget}</code>
      </button>
      {harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope ? (
        <button
          type="button"
          className={`workflow-harness-ref-button ${
            selectedHarnessReceiptRef ===
            harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
              .envelopeId
              ? "is-active"
              : ""
          }`}
          data-testid="workflow-harness-active-runtime-rollback-proof-launch-envelope-link"
          data-deep-link-kind="rollback_launch_envelope"
          data-receipt-ref={
            harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
              .envelopeId
          }
          onClick={() => {
            const envelopeId =
              harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
                ?.envelopeId;
            if (!envelopeId) return;
            onSelectHarnessReceiptRef?.(envelopeId);
            onCopyHarnessDeepLink?.({
              panel: "outputs",
              receiptRef: envelopeId,
            });
          }}
        >
          <code>
            {
              harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
                .envelopeId
            }
          </code>
        </button>
      ) : null}
      {harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt ? (
        <button
          type="button"
          className={`workflow-harness-ref-button ${
            selectedHarnessReceiptRef ===
            harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
              .receiptId
              ? "is-active"
              : ""
          }`}
          data-testid="workflow-harness-active-runtime-rollback-proof-handoff-receipt-link"
          data-deep-link-kind="rollback_handoff_receipt"
          data-receipt-ref={
            harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
              .receiptId
          }
          onClick={() => {
            const receiptId =
              harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
                ?.receiptId;
            if (!receiptId) return;
            onSelectHarnessReceiptRef?.(receiptId);
            onCopyHarnessDeepLink?.({
              panel: "outputs",
              receiptRef: receiptId,
            });
          }}
        >
          <code>
            {
              harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
                .receiptId
            }
          </code>
        </button>
      ) : null}
      {harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt ? (
        <button
          type="button"
          className={`workflow-harness-ref-button ${
            selectedHarnessNodeAttemptId ===
            harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
              .attemptId
              ? "is-active"
              : ""
          }`}
          data-testid="workflow-harness-active-runtime-rollback-proof-node-attempt-link"
          data-deep-link-kind="rollback_node_attempt"
          data-node-attempt-id={
            harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt.attemptId
          }
          onClick={() => {
            const rollbackAttempt =
              harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt;
            if (!rollbackAttempt) return;
            onCopyHarnessDeepLink?.({
              panel: "outputs",
              nodeAttemptId: rollbackAttempt.attemptId,
              receiptRef:
                harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
                  ?.receiptId,
              replayFixtureRef:
                harnessActiveRuntimeBinding.workerRollbackProof
                  .replayFixtureRef || undefined,
            });
          }}
        >
          <code>
            {
              harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
                .attemptId
            }
          </code>
        </button>
      ) : null}
      {harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef ? (
        <button
          type="button"
          className={`workflow-harness-ref-button ${
            selectedHarnessReplayFixtureRef ===
            harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef
              ? "is-active"
              : ""
          }`}
          data-testid="workflow-harness-active-runtime-rollback-proof-replay-link"
          data-deep-link-kind="rollback_replay_fixture"
          data-replay-fixture-ref={
            harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef
          }
          onClick={() => {
            const replayFixtureRef =
              harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef;
            if (!replayFixtureRef) return;
            onSelectHarnessReplayFixtureRef?.(replayFixtureRef);
            onCopyHarnessDeepLink?.({
              panel: "outputs",
              replayFixtureRef,
            });
          }}
        >
          <code>
            {harnessActiveRuntimeBinding.workerRollbackProof.replayFixtureRef}
          </code>
        </button>
      ) : null}
      {harnessActiveRuntimeBinding.receiptRefs
        .slice(0, 4)
        .map((receiptRef, index: number) => (
          <button
            key={receiptRef}
            type="button"
            className={`workflow-harness-ref-button ${
              selectedHarnessReceiptRef === receiptRef ? "is-active" : ""
            }`}
            data-testid={`workflow-harness-active-runtime-binding-receipt-${index}`}
            data-deep-link-kind="receipt"
            data-receipt-ref={receiptRef}
            onClick={() => {
              onSelectHarnessReceiptRef?.(receiptRef);
              onCopyHarnessDeepLink?.({
                panel: "outputs",
                receiptRef,
              });
            }}
          >
            <code>{receiptRef}</code>
          </button>
        ))}
      {harnessActiveRuntimeBinding.replayFixtureRefs
        .slice(0, 4)
        .map((replayFixtureRef, index: number) => (
          <button
            key={replayFixtureRef}
            type="button"
            className={`workflow-harness-ref-button ${
              selectedHarnessReplayFixtureRef === replayFixtureRef
                ? "is-active"
                : ""
            }`}
            data-testid={`workflow-harness-active-runtime-binding-replay-${index}`}
            data-deep-link-kind="replay_fixture"
            data-replay-fixture-ref={replayFixtureRef}
            onClick={() => {
              onSelectHarnessReplayFixtureRef?.(replayFixtureRef);
              onCopyHarnessDeepLink?.({
                panel: "outputs",
                replayFixtureRef,
              });
            }}
          >
            <code>{replayFixtureRef}</code>
          </button>
        ))}
    </div>
  );
}
