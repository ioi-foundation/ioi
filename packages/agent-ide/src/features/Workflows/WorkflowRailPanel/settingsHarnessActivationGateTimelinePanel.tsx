import type {
  WorkflowSettingsHarnessActivationGateInspection,
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActivationGateTimelinePanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "harnessActivationGateNodeAttempts"
      | "selectedHarnessActivationGateNodeAttemptId"
    >,
    Pick<
      WorkflowSettingsHarnessPromotionProps,
      "harnessForkMutationCanary" | "harnessForkMutationCanaryNodeAttemptIds"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      "selectedHarnessNodeAttemptId"
    >,
    Pick<WorkflowSettingsHarnessCallbacks, "onCopyHarnessDeepLink"> {
  selectedHarnessActivationGateInspection: WorkflowSettingsHarnessActivationGateInspection;
}

export function WorkflowSettingsHarnessActivationGateTimelinePanel({
  harnessActivationGateNodeAttempts,
  harnessForkMutationCanary,
  harnessForkMutationCanaryNodeAttemptIds,
  selectedHarnessActivationGateInspection,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessNodeAttemptId,
  onCopyHarnessDeepLink,
}: WorkflowSettingsHarnessActivationGateTimelinePanelProps) {
  return (
    <>
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
    </>
  );
}
