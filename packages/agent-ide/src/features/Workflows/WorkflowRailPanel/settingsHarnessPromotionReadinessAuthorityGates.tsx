import { workflowProofString } from "./statusPrimitives";
import type {
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";
import type { WorkflowHarnessAuthorityGateProofView } from "./types";

interface WorkflowSettingsHarnessPromotionReadinessAuthorityGateRowsProps
  extends Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      "selectedHarnessReceiptRef" | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onInspectNode"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {
  gates: WorkflowHarnessAuthorityGateProofView[];
  listTestId: string;
  gateTestIdPrefix: string;
}

function WorkflowSettingsHarnessPromotionReadinessAuthorityGateRows({
  gates,
  gateTestIdPrefix,
  listTestId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  onInspectNode,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
}: WorkflowSettingsHarnessPromotionReadinessAuthorityGateRowsProps) {
  return (
    <div
      className="workflow-rail-list workflow-harness-authority-gate-list"
      data-testid={listTestId}
    >
      {gates.map((gate) => {
        const receiptRef = gate.receiptIds[0] ?? null;
        const replayFixtureRef = gate.replayFixtureRefs[0] ?? null;
        return (
          <article
            key={gate.id}
            className={`workflow-test-row workflow-harness-authority-gate-row is-${
              gate.ready ? "passed" : "blocked"
            }`}
            data-testid={`${gateTestIdPrefix}-${gate.id}`}
            data-component-kind={gate.componentKind}
            data-authority-gate-status={gate.status}
          >
            <strong>{gate.label}</strong>
            <span>
              {gate.componentKind} · {gate.status} · {gate.attemptIds.length}{" "}
              attempts
            </span>
            <small>{gate.policyDecision}</small>
            <small data-testid={`${gateTestIdPrefix}-deep-links-${gate.id}`}>
              component {gate.componentId} · run {gate.runId} · replay{" "}
              {replayFixtureRef ?? "pending"} · panel {gate.selectedPanel}
            </small>
            <small>blocker {gate.blockerState}</small>
            <div className="workflow-harness-authority-gate-actions">
              <button
                type="button"
                className="workflow-harness-ref-button"
                data-testid={`${gateTestIdPrefix}-component-${gate.id}`}
                disabled={!gate.node}
                onClick={() => gate.node && onInspectNode(gate.node.id)}
              >
                <code>{gate.componentId}</code>
              </button>
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  receiptRef && selectedHarnessReceiptRef === receiptRef
                    ? "is-active"
                    : ""
                }`}
                data-testid={`${gateTestIdPrefix}-receipt-${gate.id}`}
                disabled={!receiptRef}
                onClick={() =>
                  receiptRef && onSelectHarnessReceiptRef?.(receiptRef)
                }
              >
                <code>{receiptRef ?? "receipt pending"}</code>
              </button>
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  replayFixtureRef &&
                  selectedHarnessReplayFixtureRef === replayFixtureRef
                    ? "is-active"
                    : ""
                }`}
                data-testid={`${gateTestIdPrefix}-replay-${gate.id}`}
                disabled={!replayFixtureRef}
                onClick={() =>
                  replayFixtureRef &&
                  onSelectHarnessReplayFixtureRef?.(replayFixtureRef)
                }
              >
                <code>{replayFixtureRef ?? "replay pending"}</code>
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
}

export interface WorkflowSettingsHarnessPromotionReadinessAuthorityGatesProps
  extends Pick<
      WorkflowSettingsHarnessPromotionProps,
      | "harnessAuthorityGateLiveProofs"
      | "harnessAuthorityGateLiveReady"
      | "harnessAuthorityGateReadyCount"
      | "harnessAuthorityToolingProof"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "harnessDefaultRuntimeDispatchProof"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onInspectNode"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {
  authorityGateLiveTestId: string;
}

export function WorkflowSettingsHarnessPromotionReadinessAuthorityGates({
  authorityGateLiveTestId,
  harnessAuthorityGateLiveProofs,
  harnessAuthorityGateLiveReady,
  harnessAuthorityGateReadyCount,
  harnessAuthorityToolingProof,
  harnessDefaultRuntimeDispatchProof,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  onInspectNode,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
}: WorkflowSettingsHarnessPromotionReadinessAuthorityGatesProps) {
  if (!harnessDefaultRuntimeDispatchProof) {
    return null;
  }

  return (
    <section
      className="workflow-rail-section workflow-harness-authority-gates"
      data-testid={authorityGateLiveTestId}
    >
      <h4>Authority tooling gates</h4>
      <dl
        className="workflow-rail-stats"
        data-testid="workflow-harness-authority-gate-summary"
      >
        <div>
          <dt>Ready</dt>
          <dd>
            {harnessAuthorityGateReadyCount}/
            {harnessAuthorityGateLiveProofs.length}
          </dd>
        </div>
        <div>
          <dt>Receipts</dt>
          <dd>
            {
              harnessDefaultRuntimeDispatchProof.authorityToolingGateLiveReceiptIds
                .length
            }
          </dd>
        </div>
        <div>
          <dt>Replay</dt>
          <dd>
            {
              harnessDefaultRuntimeDispatchProof
                .authorityToolingGateLiveReplayFixtureRefs.length
            }
          </dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{harnessAuthorityGateLiveReady ? "live" : "blocked"}</dd>
        </div>
      </dl>
      <article
        className={`workflow-output-row is-${
          harnessAuthorityGateLiveReady ? "ready" : "blocked"
        }`}
        data-testid="workflow-harness-authority-gate-rollup"
      >
        <strong>
          {workflowProofString(
            harnessAuthorityToolingProof,
            "policyDecision",
            "authority gate proof pending",
          )}
        </strong>
        <span>
          destructive denied{" "}
          {harnessDefaultRuntimeDispatchProof.authorityToolingDestructiveRouteDenied
            ? "yes"
            : "review"}{" "}
          · approvals blocked{" "}
          {harnessDefaultRuntimeDispatchProof.authorityToolingMutatingToolCallsBlocked
            ? "yes"
            : "review"}
        </span>
        <small>
          side effects{" "}
          {harnessDefaultRuntimeDispatchProof.authorityToolingSideEffectsExecuted
            ? "executed"
            : "not executed"}{" "}
          · rollback{" "}
          {harnessDefaultRuntimeDispatchProof.authorityToolingRollbackAvailable
            ? "ready"
            : "blocked"}
        </small>
      </article>
      <WorkflowSettingsHarnessPromotionReadinessAuthorityGateRows
        gates={harnessAuthorityGateLiveProofs}
        listTestId="workflow-harness-authority-gate-list"
        gateTestIdPrefix="workflow-harness-authority-gate"
        selectedHarnessReceiptRef={selectedHarnessReceiptRef}
        selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
        onInspectNode={onInspectNode}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
        onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
      />
    </section>
  );
}
