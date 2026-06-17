import type { WorkflowProject } from "../../../types/graph";
import { WorkflowSettingsHarnessPromotionReadinessPanel } from "./settingsHarnessPromotionReadinessPanel";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessPromotionPanelProps
  extends
    WorkflowSettingsHarnessPromotionProps,
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "boundHarnessSlotIds"
      | "harnessActivationRecord"
      | "selectedHarnessActivationBlockerIndex"
      | "selectedHarnessActivationBlockerRef"
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
      | "harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers"
      | "harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds"
      | "harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers"
      | "harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds"
      | "harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound"
      | "harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers"
      | "harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCopyHarnessDeepLink"
      | "onInspectNode"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessPromotionPanel({
  boundHarnessSlotIds,
  harnessActivationRecord,
  selectedHarnessActivationBlockerIndex,
  selectedHarnessActivationBlockerRef,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  harnessAuthorityGateLiveProofs,
  harnessAuthorityGateLiveReady,
  harnessAuthorityGateReadyCount,
  harnessAuthorityToolingNodeAuthorityGate,
  harnessAuthorityToolingProof,
  harnessCognitionNodeAuthorityGate,
  harnessForkComponentDiffRows,
  harnessForkComponentDiffStats,
  harnessForkWorkflow,
  harnessLiveHandoffProof,
  harnessPromotionClusters,
  harnessReadOnlyRoutingNodeKinds,
  harnessReadOnlyRoutingProof,
  harnessReadOnlyRoutingReady,
  harnessReadOnlyRoutingRequiredScenarios,
  harnessRoutingModelNodeAuthorityGate,
  harnessRuntimeSelectorDecision,
  harnessSelectorLivePromotionReadinessBlockers,
  harnessSelectorLivePromotionReadinessProof,
  harnessSelectorLivePromotionReadinessReady,
  harnessSlots,
  harnessVerificationOutputNodeAuthorityGate,
  harnessCanaryExecutionBoundaries,
  selectedHarnessCanaryBoundary,
  selectedHarnessRollbackDrillId,
  harnessDefaultRuntimeDispatchProof,
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds,
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds,
  harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound,
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  onCopyHarnessDeepLink,
  onInspectNode,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  workflow,
}: WorkflowSettingsHarnessPromotionPanelProps) {
  return (
    <>
      <WorkflowSettingsHarnessPromotionReadinessPanel
        harnessAuthorityGateLiveProofs={harnessAuthorityGateLiveProofs}
        harnessAuthorityGateLiveReady={harnessAuthorityGateLiveReady}
        harnessAuthorityGateReadyCount={harnessAuthorityGateReadyCount}
        harnessAuthorityToolingNodeAuthorityGate={
          harnessAuthorityToolingNodeAuthorityGate
        }
        harnessAuthorityToolingProof={harnessAuthorityToolingProof}
        harnessCognitionNodeAuthorityGate={harnessCognitionNodeAuthorityGate}
        harnessDefaultRuntimeDispatchProof={harnessDefaultRuntimeDispatchProof}
        harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers={
          harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers
        }
        harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds={
          harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds
        }
        harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers={
          harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers
        }
        harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds={
          harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds
        }
        harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound={
          harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound
        }
        harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers={
          harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers
        }
        harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds={
          harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds
        }
        harnessLiveHandoffProof={harnessLiveHandoffProof}
        harnessReadOnlyRoutingNodeKinds={harnessReadOnlyRoutingNodeKinds}
        harnessReadOnlyRoutingProof={harnessReadOnlyRoutingProof}
        harnessReadOnlyRoutingReady={harnessReadOnlyRoutingReady}
        harnessReadOnlyRoutingRequiredScenarios={
          harnessReadOnlyRoutingRequiredScenarios
        }
        harnessRoutingModelNodeAuthorityGate={
          harnessRoutingModelNodeAuthorityGate
        }
        harnessRuntimeSelectorDecision={harnessRuntimeSelectorDecision}
        harnessSelectorLivePromotionReadinessBlockers={
          harnessSelectorLivePromotionReadinessBlockers
        }
        harnessSelectorLivePromotionReadinessProof={
          harnessSelectorLivePromotionReadinessProof
        }
        harnessSelectorLivePromotionReadinessReady={
          harnessSelectorLivePromotionReadinessReady
        }
        harnessVerificationOutputNodeAuthorityGate={
          harnessVerificationOutputNodeAuthorityGate
        }
        harnessCanaryExecutionBoundaries={harnessCanaryExecutionBoundaries}
        selectedHarnessActivationGateReceiptRef={
          selectedHarnessActivationGateReceiptRef
        }
        selectedHarnessActivationGateReplayFixtureRef={
          selectedHarnessActivationGateReplayFixtureRef
        }
        selectedHarnessCanaryBoundary={selectedHarnessCanaryBoundary}
        selectedHarnessReceiptRef={selectedHarnessReceiptRef}
        selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
        selectedHarnessRollbackDrillId={selectedHarnessRollbackDrillId}
        onCopyHarnessDeepLink={onCopyHarnessDeepLink}
        onInspectNode={onInspectNode}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
        onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
        workflow={workflow}
      />
      {workflow.metadata.harness?.forkedFrom ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-lineage"
        >
          <strong>Fork lineage</strong>
          <span>{workflow.metadata.harness.forkedFrom.harnessWorkflowId}</span>
          <small>{workflow.metadata.harness.forkedFrom.harnessHash}</small>
        </article>
      ) : null}
      {workflow.metadata.harness?.forkedFrom ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-harness-fork-component-diff"
        >
          <h4>Blessed vs fork components</h4>
          <dl
            className="workflow-rail-stats"
            data-testid="workflow-harness-fork-component-diff-summary"
          >
            <div>
              <dt>Unchanged</dt>
              <dd>{harnessForkComponentDiffStats.unchanged ?? 0}</dd>
            </div>
            <div>
              <dt>Changed</dt>
              <dd>{harnessForkComponentDiffStats.changed ?? 0}</dd>
            </div>
            <div>
              <dt>Missing</dt>
              <dd>{harnessForkComponentDiffStats.missing_from_fork ?? 0}</dd>
            </div>
            <div>
              <dt>Fork-only</dt>
              <dd>{harnessForkComponentDiffStats.fork_only ?? 0}</dd>
            </div>
          </dl>
          <div
            className="workflow-rail-list"
            data-testid="workflow-harness-fork-component-diff-list"
          >
            {harnessForkComponentDiffRows.map((row) => (
              <button
                key={row.componentId}
                type="button"
                className={`workflow-search-result is-${
                  row.status === "unchanged" ? "ready" : "blocked"
                }`}
                data-testid={`workflow-harness-fork-component-diff-row-${row.componentId}`}
                data-component-diff-status={row.status}
                disabled={!row.nodeId}
                onClick={() => row.nodeId && onInspectNode(row.nodeId)}
              >
                <strong>{row.label}</strong>
                <span>
                  {row.status} · {row.kind}
                </span>
                <small>
                  blessed {row.blessedVersion} ({row.blessedReadiness}) · fork{" "}
                  {row.forkVersion} ({row.forkReadiness})
                </small>
              </button>
            ))}
          </div>
        </section>
      ) : null}
      <div className="workflow-rail-list" data-testid="workflow-harness-slots">
        {harnessSlots.map((slot) => {
          const ready = boundHarnessSlotIds.has(slot.slotId);
          return (
            <article
              key={slot.slotId}
              className={`workflow-test-row is-${ready ? "passed" : "blocked"}`}
            >
              <strong>{slot.label}</strong>
              <span>
                {ready ? "bound" : "unbound"} · {slot.kind}
              </span>
              <small>{slot.description}</small>
            </article>
          );
        })}
      </div>
      <div
        className="workflow-rail-list"
        data-testid="workflow-harness-promotion-clusters"
      >
        {harnessPromotionClusters.map((cluster) => {
          const replayGateProof = cluster.replayGateProof;
          const replayGateStatus = replayGateProof?.gateStatus ?? "not_run";
          const replayGateReady =
            replayGateStatus === "passed" &&
            replayGateProof?.activationGateImpact === "passed";
          return (
            <article
              key={cluster.clusterId}
              className={`workflow-test-row is-${
                replayGateReady
                  ? "passed"
                  : replayGateStatus === "blocked" ||
                      replayGateStatus === "failed"
                    ? "blocked"
                    : "idle"
              }`}
              data-testid={`workflow-harness-promotion-cluster-replay-gate-${cluster.clusterId}`}
              data-replay-gate-status={replayGateStatus}
              data-activation-gate-impact={
                replayGateProof?.activationGateImpact ?? "pending"
              }
              data-replay-gate-id={replayGateProof?.gateId ?? ""}
            >
              <strong>{cluster.label}</strong>
              <span>
                {cluster.requiredExecutionMode} · replay gate {replayGateStatus}
              </span>
              <small>
                {cluster.componentKinds.length} components ·{" "}
                {replayGateProof?.totalFixtures ?? 0} fixtures · rollback{" "}
                {cluster.rollbackTarget}
              </small>
            </article>
          );
        })}
      </div>
      {harnessForkWorkflow ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-activation-blockers"
          data-activation-blockers={(
            harnessActivationRecord?.activationBlockers ?? []
          ).join("|")}
          data-selected-activation-blocker-index={
            selectedHarnessActivationBlockerIndex ?? ""
          }
          data-selected-activation-blocker-ref={
            selectedHarnessActivationBlockerRef ?? ""
          }
        >
          <strong>Activation blockers</strong>
          <span>
            {(harnessActivationRecord?.activationBlockers ?? []).length > 0
              ? harnessActivationRecord?.activationBlockers.join(", ")
              : "None"}
          </span>
          <small>
            {workflow.metadata.harness?.activationState ?? "blocked"}
          </small>
          {(harnessActivationRecord?.activationBlockers ?? []).length > 0 ? (
            <div className="workflow-harness-authority-gate-actions">
              {(harnessActivationRecord?.activationBlockers ?? [])
                .slice(0, 5)
                .map((blocker, index: number) => (
                  <button
                    key={`${blocker}-${index}`}
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessActivationBlockerRef === blocker
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-activation-blocker-link-${index}`}
                    data-activation-blocker-index={String(index)}
                    data-activation-blocker-ref={blocker}
                    disabled={!onCopyHarnessDeepLink}
                    onClick={() =>
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        activationBlockerIndex: String(index),
                        activationBlockerRef: blocker,
                      })
                    }
                  >
                    <code>{blocker}</code>
                  </button>
                ))}
            </div>
          ) : null}
        </article>
      ) : null}
    </>
  );
}
