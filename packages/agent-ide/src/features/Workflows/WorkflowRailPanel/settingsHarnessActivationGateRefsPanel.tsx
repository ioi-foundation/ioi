import type {
  WorkflowSettingsHarnessActivationGateInspection,
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActivationGateRefsPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "selectedHarnessActivationGateEvidenceRef"
      | "selectedHarnessActivationGateReceiptRef"
      | "selectedHarnessActivationGateReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      "selectedHarnessReceiptRef" | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCopyHarnessDeepLink"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {
  selectedHarnessActivationGateInspection: WorkflowSettingsHarnessActivationGateInspection;
}

export function WorkflowSettingsHarnessActivationGateRefsPanel({
  selectedHarnessActivationGateEvidenceRef,
  selectedHarnessActivationGateInspection,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  onCopyHarnessDeepLink,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
}: WorkflowSettingsHarnessActivationGateRefsPanelProps) {
  return (
    <>
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
        {selectedHarnessActivationGateInspection.evidenceRefs.length === 0 ? (
          <span>No evidence refs captured for this gate yet.</span>
        ) : null}
      </div>
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
      {selectedHarnessActivationGateInspection.replayFixtureRefs.length > 0 ? (
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
    </>
  );
}
