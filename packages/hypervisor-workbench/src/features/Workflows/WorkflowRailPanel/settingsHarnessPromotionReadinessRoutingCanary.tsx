import type { WorkflowProject } from "../../../types/graph";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessPromotionReadinessRoutingCanaryProps
  extends Pick<
      WorkflowSettingsHarnessPromotionProps,
      | "harnessReadOnlyRoutingNodeKinds"
      | "harnessReadOnlyRoutingProof"
      | "harnessReadOnlyRoutingReady"
      | "harnessReadOnlyRoutingRequiredScenarios"
    >,
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "selectedHarnessActivationGateReceiptRef"
      | "selectedHarnessActivationGateReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessRollbackProps,
      | "harnessCanaryExecutionBoundaries"
      | "selectedHarnessCanaryBoundary"
      | "selectedHarnessRollbackDrillId"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "harnessDefaultRuntimeDispatchProof"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      "onCopyHarnessDeepLink" | "onInspectNode"
    > {
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessPromotionReadinessRoutingCanary({
  harnessReadOnlyRoutingNodeKinds,
  harnessReadOnlyRoutingProof,
  harnessReadOnlyRoutingReady,
  harnessReadOnlyRoutingRequiredScenarios,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  harnessCanaryExecutionBoundaries,
  selectedHarnessCanaryBoundary,
  selectedHarnessRollbackDrillId,
  harnessDefaultRuntimeDispatchProof,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  onCopyHarnessDeepLink,
  onInspectNode,
  workflow,
}: WorkflowSettingsHarnessPromotionReadinessRoutingCanaryProps) {
  return (
    <>
      {harnessReadOnlyRoutingProof ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-harness-read-only-routing-proof"
        >
          <h4>Read-only routing</h4>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-read-only-routing-summary"
          >
            <div>
              <dt>Mode</dt>
              <dd>
                {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingMode ??
                  String(harnessReadOnlyRoutingProof.mode ?? "unknown")}
              </dd>
            </div>
            <div>
              <dt>Scenario</dt>
              <dd>
                {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenario ??
                  String(harnessReadOnlyRoutingProof.scenario ?? "pending")}
              </dd>
            </div>
            <div>
              <dt>Nodes</dt>
              <dd>{harnessReadOnlyRoutingNodeKinds.length}</dd>
            </div>
            <div>
              <dt>Mutation</dt>
              <dd>{harnessReadOnlyRoutingReady ? "blocked" : "review"}</dd>
            </div>
          </dl>
          <article
            className="workflow-output-row"
            data-testid="workflow-harness-read-only-routing-no-mutation"
          >
            <strong>
              {harnessReadOnlyRoutingReady
                ? "No mutation proof ready"
                : "No mutation proof incomplete"}
            </strong>
            <span>
              side effects{" "}
              {harnessReadOnlyRoutingProof.sideEffectsExecuted === false
                ? "not executed"
                : "review"}{" "}
              · mutation{" "}
              {harnessReadOnlyRoutingProof.mutationExecuted === false
                ? "not executed"
                : "review"}
            </span>
            <small>
              source material{" "}
              {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingSourceMaterialReady
                ? "ready"
                : "pending"}{" "}
              · rollback{" "}
              {harnessReadOnlyRoutingProof.rollbackAvailable
                ? "ready"
                : "blocked"}
            </small>
          </article>
          <div
            className="workflow-rail-list"
            data-testid="workflow-harness-read-only-routing-node-kinds"
          >
            {harnessReadOnlyRoutingNodeKinds.map((kind) => {
              const nodeItem = workflow.nodes.find(
                (candidate) => candidate.runtimeBinding?.componentKind === kind,
              );
              return (
                <button
                  key={kind}
                  type="button"
                  className="workflow-search-result is-ready"
                  data-testid={`workflow-harness-read-only-routing-node-${kind}`}
                  disabled={!nodeItem}
                  onClick={() => nodeItem && onInspectNode(nodeItem.id)}
                >
                  <strong>{nodeItem?.name ?? kind}</strong>
                  <span>{kind} · workflow-owned</span>
                  <small>
                    {nodeItem?.runtimeBinding?.readiness ?? "binding pending"}
                  </small>
                </button>
              );
            })}
          </div>
          <div
            className="workflow-rail-list"
            data-testid="workflow-harness-read-only-routing-receipts"
          >
            <article className="workflow-output-row">
              <strong>Attempts</strong>
              <span>
                {harnessDefaultRuntimeDispatchProof
                  ?.readOnlyCapabilityRoutingAttemptIds.length ?? 0}{" "}
                node attempts
              </span>
              <small>
                {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingAttemptIds
                  .slice(0, 2)
                  .join(", ") ?? "pending"}
              </small>
            </article>
            <article className="workflow-output-row">
              <strong>Receipts</strong>
              <span>
                {harnessDefaultRuntimeDispatchProof
                  ?.readOnlyCapabilityRoutingReceiptIds.length ?? 0}{" "}
                receipt refs
              </span>
              <small>
                {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReceiptIds
                  .slice(0, 2)
                  .join(", ") ?? "pending"}
              </small>
            </article>
            <article className="workflow-output-row">
              <strong>Replay fixtures</strong>
              <span>
                {harnessDefaultRuntimeDispatchProof
                  ?.readOnlyCapabilityRoutingReplayFixtureRefs.length ?? 0}{" "}
                fixture refs
              </span>
              <small>
                {harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingReplayFixtureRefs
                  .slice(0, 2)
                  .join(", ") ?? "pending"}
              </small>
            </article>
          </div>
          {harnessReadOnlyRoutingRequiredScenarios.length > 0 ? (
            <div
              className="workflow-rail-list"
              data-testid="workflow-harness-read-only-routing-scenarios"
            >
              {harnessReadOnlyRoutingRequiredScenarios.map((scenario) => (
                <article
                  key={scenario}
                  className={`workflow-test-row is-${
                    scenario ===
                    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey
                      ? "passed"
                      : "idle"
                  }`}
                >
                  <strong>{scenario}</strong>
                  <span>
                    {scenario ===
                    harnessDefaultRuntimeDispatchProof?.readOnlyCapabilityRoutingScenarioCoverageKey
                      ? "current coverage key"
                      : "retained requirement"}
                  </span>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      ) : null}
      {harnessCanaryExecutionBoundaries.length > 0 ? (
        <div
          className="workflow-rail-list"
          data-testid="workflow-harness-canary-execution-boundaries"
          data-selected-canary-boundary-id={
            selectedHarnessCanaryBoundary?.boundaryId ?? ""
          }
          data-selected-rollback-drill-id={selectedHarnessRollbackDrillId}
          data-selected-canary-receipt-ref={
            selectedHarnessActivationGateReceiptRef ??
            selectedHarnessReceiptRef ??
            ""
          }
          data-selected-canary-replay-fixture-ref={
            selectedHarnessActivationGateReplayFixtureRef ??
            selectedHarnessReplayFixtureRef ??
            ""
          }
          data-canary-boundary-count={harnessCanaryExecutionBoundaries.length}
          data-rollback-drill-count={
            harnessCanaryExecutionBoundaries.filter(
              (boundary) => boundary.rollbackDrill.drillStatus,
            ).length
          }
        >
          {harnessCanaryExecutionBoundaries.map((boundary) => (
            <article
              key={boundary.boundaryId}
              className={`workflow-output-row ${
                selectedHarnessCanaryBoundary?.boundaryId ===
                boundary.boundaryId
                  ? "is-active"
                  : ""
              }`}
              data-testid="workflow-harness-canary-execution-boundary"
              data-canary-boundary-id={boundary.boundaryId}
              data-rollback-drill-id={boundary.rollbackDrill.drillId}
              data-receipt-refs={boundary.receiptIds.join("|")}
              data-replay-fixture-refs={boundary.replayFixtureRefs.join("|")}
              data-rollback-target={boundary.rollbackTarget}
              data-canary-status={boundary.status}
              data-rollback-drill-status={boundary.rollbackDrill.drillStatus}
              data-canary-eligible={boundary.canaryEligible ? "true" : "false"}
            >
              <strong>{boundary.clusterLabel}</strong>
              <span>
                {boundary.status} · {boundary.executorKind}
              </span>
              <small>
                rollback drill {boundary.rollbackDrill.drillStatus} ·{" "}
                {boundary.executedComponentKinds.length} nodes
              </small>
              {onCopyHarnessDeepLink ? (
                <div className="workflow-harness-authority-gate-actions">
                  <button
                    type="button"
                    data-testid={`workflow-harness-canary-boundary-link-${boundary.clusterId}`}
                    onClick={() =>
                      onCopyHarnessDeepLink({
                        panel: "settings",
                        activationGateId: "canary",
                        activationGateEvidenceRef: boundary.boundaryId,
                        activationGateReceiptRef: boundary.receiptIds[0],
                        receiptRef: boundary.receiptIds[0],
                        activationGateReplayFixtureRef:
                          boundary.replayFixtureRefs[0],
                        replayFixtureRef: boundary.replayFixtureRefs[0],
                      })
                    }
                  >
                    Boundary
                  </button>
                  <button
                    type="button"
                    data-testid={`workflow-harness-canary-rollback-drill-link-${boundary.clusterId}`}
                    onClick={() =>
                      onCopyHarnessDeepLink({
                        panel: "settings",
                        activationGateId: "canary",
                        activationGateEvidenceRef:
                          boundary.rollbackDrill.drillId,
                        activationGateReceiptRef: boundary.receiptIds[0],
                        receiptRef: boundary.receiptIds[0],
                        activationGateReplayFixtureRef:
                          boundary.replayFixtureRefs[0],
                        replayFixtureRef: boundary.replayFixtureRefs[0],
                      })
                    }
                  >
                    Drill
                  </button>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      ) : null}
    </>
  );
}
