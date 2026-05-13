import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import type {
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessPromotionReadinessSummaryProps
  extends Pick<
      WorkflowSettingsHarnessPromotionProps,
      | "harnessAuthorityToolingNodeAuthorityGate"
      | "harnessCognitionNodeAuthorityGate"
      | "harnessLiveHandoffProof"
      | "harnessRoutingModelNodeAuthorityGate"
      | "harnessRuntimeSelectorDecision"
      | "harnessSelectorLivePromotionReadinessBlockers"
      | "harnessSelectorLivePromotionReadinessProof"
      | "harnessSelectorLivePromotionReadinessReady"
      | "harnessVerificationOutputNodeAuthorityGate"
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
    > {
  selectorReadinessTestId: string;
}

export function WorkflowSettingsHarnessPromotionReadinessSummary({
  harnessAuthorityToolingNodeAuthorityGate,
  harnessCognitionNodeAuthorityGate,
  harnessLiveHandoffProof,
  harnessRoutingModelNodeAuthorityGate,
  harnessRuntimeSelectorDecision,
  harnessSelectorLivePromotionReadinessBlockers,
  harnessSelectorLivePromotionReadinessProof,
  harnessSelectorLivePromotionReadinessReady,
  harnessVerificationOutputNodeAuthorityGate,
  harnessDefaultRuntimeDispatchProof,
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds,
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds,
  harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound,
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers,
  harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds,
  selectorReadinessTestId,
}: WorkflowSettingsHarnessPromotionReadinessSummaryProps) {
  return (
    <>
      {harnessLiveHandoffProof ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-live-handoff"
        >
          <strong>{harnessLiveHandoffProof.selector}</strong>
          <span>
            canary {harnessLiveHandoffProof.canaryStatus} · rollback{" "}
            {harnessLiveHandoffProof.rollbackAvailable ? "ready" : "blocked"}
          </span>
          <small>
            default {harnessLiveHandoffProof.productionDefaultSelector} ·{" "}
            {harnessLiveHandoffProof.runtimeAuthority}
          </small>
        </article>
      ) : null}
      {harnessRuntimeSelectorDecision ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-runtime-selector"
        >
          <strong>{harnessRuntimeSelectorDecision.selectedSelector}</strong>
          <span>
            default {harnessRuntimeSelectorDecision.productionDefaultSelector} ·{" "}
            {harnessRuntimeSelectorDecision.executionMode}
          </span>
          <small>{harnessRuntimeSelectorDecision.policyDecision}</small>
        </article>
      ) : null}
      {harnessSelectorLivePromotionReadinessProof ? (
        <article
          className={`workflow-output-row is-${
            harnessSelectorLivePromotionReadinessReady ? "ready" : "blocked"
          }`}
          data-testid={selectorReadinessTestId}
          data-readiness={
            harnessSelectorLivePromotionReadinessReady
              ? "live_ready"
              : "blocked"
          }
        >
          <strong>
            selector readiness{" "}
            {harnessSelectorLivePromotionReadinessReady ? "ready" : "blocked"}
          </strong>
          <span>
            {harnessSelectorLivePromotionReadinessProof.clusterReadiness.length}{" "}
            clusters · rollback{" "}
            {harnessSelectorLivePromotionReadinessProof.rollbackAvailable
              ? "ready"
              : "blocked"}
          </span>
          <small>
            {harnessSelectorLivePromotionReadinessBlockers.length} blockers ·{" "}
            {harnessRuntimeSelectorDecision?.livePromotionReadinessPolicyDecision ??
              harnessSelectorLivePromotionReadinessProof.policyDecision}
          </small>
        </article>
      ) : null}
      {harnessDefaultRuntimeDispatchProof ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-default-runtime-dispatch"
          data-cognition-node-authority-mode={
            harnessCognitionNodeAuthorityGate?.authorityMode ?? ""
          }
          data-cognition-node-authority-authoritative={
            harnessCognitionNodeAuthorityGate?.authoritative ? "true" : "false"
          }
          data-cognition-node-authority-policy-decision={
            harnessCognitionNodeAuthorityGate?.policyDecision ?? ""
          }
          data-cognition-node-authority-blockers={(
            harnessCognitionNodeAuthorityGate?.blockers ?? []
          ).join(",")}
          data-cognition-node-authority-component-kinds={(
            harnessCognitionNodeAuthorityGate?.componentKinds ?? []
          ).join(",")}
          data-cognition-node-authority-action-frame-ids={(
            harnessCognitionNodeAuthorityGate?.actionFrameIds ?? []
          ).join(",")}
          data-cognition-node-authority-attempt-ids={(
            harnessCognitionNodeAuthorityGate?.attemptIds ?? []
          ).join(",")}
          data-cognition-node-authority-receipt-ids={(
            harnessCognitionNodeAuthorityGate?.receiptIds ?? []
          ).join(",")}
          data-cognition-node-authority-replay-fixture-refs={(
            harnessCognitionNodeAuthorityGate?.replayFixtureRefs ?? []
          ).join(",")}
          data-routing-model-node-authority-mode={
            harnessRoutingModelNodeAuthorityGate?.authorityMode ?? ""
          }
          data-routing-model-node-authority-authoritative={
            harnessRoutingModelNodeAuthorityGate?.authoritative
              ? "true"
              : "false"
          }
          data-routing-model-node-authority-policy-decision={
            harnessRoutingModelNodeAuthorityGate?.policyDecision ?? ""
          }
          data-routing-model-node-authority-visible-output-authority={
            harnessRoutingModelNodeAuthorityGate?.visibleOutputAuthority ?? ""
          }
          data-routing-model-node-authority-blockers={(
            harnessRoutingModelNodeAuthorityGate?.blockers ?? []
          ).join(",")}
          data-routing-model-node-authority-component-kinds={(
            harnessRoutingModelNodeAuthorityGate?.componentKinds ?? []
          ).join(",")}
          data-routing-model-node-authority-action-frame-ids={(
            harnessRoutingModelNodeAuthorityGate?.actionFrameIds ?? []
          ).join(",")}
          data-routing-model-node-authority-attempt-ids={(
            harnessRoutingModelNodeAuthorityGate?.attemptIds ?? []
          ).join(",")}
          data-routing-model-node-authority-receipt-ids={(
            harnessRoutingModelNodeAuthorityGate?.receiptIds ?? []
          ).join(",")}
          data-routing-model-node-authority-replay-fixture-refs={(
            harnessRoutingModelNodeAuthorityGate?.replayFixtureRefs ?? []
          ).join(",")}
          data-verification-output-node-authority-mode={
            harnessVerificationOutputNodeAuthorityGate?.authorityMode ?? ""
          }
          data-verification-output-node-authority-authoritative={
            harnessVerificationOutputNodeAuthorityGate?.authoritative
              ? "true"
              : "false"
          }
          data-verification-output-node-authority-policy-decision={
            harnessVerificationOutputNodeAuthorityGate?.policyDecision ?? ""
          }
          data-verification-output-node-authority-visible-write-committed={
            harnessVerificationOutputNodeAuthorityGate?.outputWriterVisibleWriteCommitted
              ? "true"
              : "false"
          }
          data-verification-output-node-authority-blockers={(
            harnessVerificationOutputNodeAuthorityGate?.blockers ?? []
          ).join(",")}
          data-verification-output-node-authority-component-kinds={(
            harnessVerificationOutputNodeAuthorityGate?.componentKinds ?? []
          ).join(",")}
          data-verification-output-node-authority-action-frame-ids={(
            harnessVerificationOutputNodeAuthorityGate?.actionFrameIds ?? []
          ).join(",")}
          data-verification-output-node-authority-attempt-ids={(
            harnessVerificationOutputNodeAuthorityGate?.attemptIds ?? []
          ).join(",")}
          data-verification-output-node-authority-receipt-ids={(
            harnessVerificationOutputNodeAuthorityGate?.receiptIds ?? []
          ).join(",")}
          data-verification-output-node-authority-replay-fixture-refs={(
            harnessVerificationOutputNodeAuthorityGate?.replayFixtureRefs ?? []
          ).join(",")}
          data-authority-tooling-node-authority-mode={
            harnessAuthorityToolingNodeAuthorityGate?.authorityMode ?? ""
          }
          data-authority-tooling-node-authority-authoritative={
            harnessAuthorityToolingNodeAuthorityGate?.authoritative
              ? "true"
              : "false"
          }
          data-authority-tooling-node-authority-policy-decision={
            harnessAuthorityToolingNodeAuthorityGate?.policyDecision ?? ""
          }
          data-authority-tooling-node-authority-read-only-route-accepted={
            harnessAuthorityToolingNodeAuthorityGate?.readOnlyRouteAccepted
              ? "true"
              : "false"
          }
          data-authority-tooling-node-authority-destructive-route-denied={
            harnessAuthorityToolingNodeAuthorityGate?.destructiveRouteDenied
              ? "true"
              : "false"
          }
          data-authority-tooling-node-authority-side-effects-executed={
            harnessAuthorityToolingNodeAuthorityGate?.sideEffectsExecuted
              ? "true"
              : "false"
          }
          data-authority-tooling-node-authority-blockers={(
            harnessAuthorityToolingNodeAuthorityGate?.blockers ?? []
          ).join(",")}
          data-authority-tooling-node-authority-component-kinds={(
            harnessAuthorityToolingNodeAuthorityGate?.componentKinds ?? []
          ).join(",")}
          data-authority-tooling-node-authority-action-frame-ids={(
            harnessAuthorityToolingNodeAuthorityGate?.actionFrameIds ?? []
          ).join(",")}
          data-authority-tooling-node-authority-attempt-ids={(
            harnessAuthorityToolingNodeAuthorityGate?.attemptIds ?? []
          ).join(",")}
          data-authority-tooling-node-authority-receipt-ids={(
            harnessAuthorityToolingNodeAuthorityGate?.receiptIds ?? []
          ).join(",")}
          data-authority-tooling-node-authority-replay-fixture-refs={(
            harnessAuthorityToolingNodeAuthorityGate?.replayFixtureRefs ?? []
          ).join(",")}
          data-worker-attach-lifecycle-complete={
            harnessDefaultRuntimeDispatchProof.workerAttachLifecycleComplete
              ? "true"
              : "false"
          }
          data-worker-attach-lifecycle-statuses={(
            harnessDefaultRuntimeDispatchProof.workerAttachLifecycleStatuses ??
            []
          ).join(",")}
          data-worker-session-record-id={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.sessionRecordId ?? ""
          }
          data-worker-session-status={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.currentStatus ?? ""
          }
          data-worker-session-persistence-key={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.persistenceKey ?? ""
          }
          data-worker-session-record-persistence-key={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.recordPersistenceKey ?? ""
          }
          data-worker-session-persisted={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.persistedInRuntimeCheckpoint
              ? "true"
              : "false"
          }
          data-worker-session-restored={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.restoredFromPersistedSession
              ? "true"
              : "false"
          }
          data-worker-session-checkpoint-source={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.runtimeCheckpointSource ?? ""
          }
          data-worker-session-launch-authority-ready={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.launchAuthorityReady
              ? "true"
              : "false"
          }
          data-worker-session-launch-authority-source={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.launchAuthoritySource ?? ""
          }
          data-worker-launch-reviewed-import-invariant-bound={
            harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound
              ? "true"
              : "false"
          }
          data-worker-session-launch-authority-invariant-ids={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantIds.join(
            ",",
          )}
          data-worker-session-launch-authority-invariant-blockers={harnessDefaultRuntimeDispatchWorkerSessionLaunchAuthorityInvariantBlockers.join(
            ",",
          )}
          data-worker-session-rollback-handoff-ready={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.rollbackHandoffReady
              ? "true"
              : "false"
          }
          data-worker-session-rollback-handoff-target={
            harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.rollbackHandoffTarget ?? ""
          }
          data-worker-launch-envelope-count={
            (harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopes ?? [])
              .length
          }
          data-worker-launch-envelope-ids={(
            harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopeIds ?? []
          ).join(",")}
          data-worker-launch-envelope-invariant-ids={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantIds.join(
            ",",
          )}
          data-worker-launch-envelope-invariant-blockers={harnessDefaultRuntimeDispatchWorkerLaunchEnvelopeInvariantBlockers.join(
            ",",
          )}
          data-worker-handoff-receipt-count={
            (harnessDefaultRuntimeDispatchProof.workerHandoffReceipts ?? [])
              .length
          }
          data-worker-handoff-receipt-ids={(
            harnessDefaultRuntimeDispatchProof.workerHandoffReceiptIds ?? []
          ).join(",")}
          data-worker-handoff-receipt-invariant-ids={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantIds.join(
            ",",
          )}
          data-worker-handoff-receipt-invariant-blockers={harnessDefaultRuntimeDispatchWorkerHandoffReceiptInvariantBlockers.join(
            ",",
          )}
          data-worker-rollback-handoff-receipt-status={
            harnessDefaultRuntimeDispatchProof.workerHandoffReceipts?.find(
              (receipt) => receipt.phase === "rollback",
            )?.handoffStatus ?? ""
          }
        >
          <strong>{harnessDefaultRuntimeDispatchProof.selectedSelector}</strong>
          <span>
            {harnessDefaultRuntimeDispatchProof.executionMode} ·{" "}
            {harnessDefaultRuntimeDispatchProof.outputWriterStatus}
          </span>
          <small>
            {harnessDefaultRuntimeDispatchProof.acceptedClusterIds.length}{" "}
            clusters ·{" "}
            {harnessDefaultRuntimeDispatchProof.dispatchNodeAttemptIds.length}{" "}
            attempts
          </small>
          <small>
            cognition{" "}
            {harnessCognitionNodeAuthorityGate?.authoritative
              ? "node authoritative"
              : "authority blocked"}{" "}
            · {harnessCognitionNodeAuthorityGate?.componentKinds.length ?? 0}{" "}
            nodes
          </small>
          <small>
            routing/model{" "}
            {harnessRoutingModelNodeAuthorityGate?.authoritative
              ? "gated node authority"
              : "authority blocked"}{" "}
            · {harnessRoutingModelNodeAuthorityGate?.componentKinds.length ?? 0}{" "}
            nodes
          </small>
          <small>
            verification/output{" "}
            {harnessVerificationOutputNodeAuthorityGate?.authoritative
              ? "gated node authority"
              : "authority blocked"}{" "}
            ·{" "}
            {harnessVerificationOutputNodeAuthorityGate?.componentKinds
              .length ?? 0}{" "}
            nodes
          </small>
          <small>
            authority/tooling{" "}
            {harnessAuthorityToolingNodeAuthorityGate?.authoritative
              ? "gated node authority"
              : "authority blocked"}{" "}
            ·{" "}
            {harnessAuthorityToolingNodeAuthorityGate?.componentKinds.length ??
              0}{" "}
            nodes
          </small>
          <small>
            worker lifecycle{" "}
            {(
              harnessDefaultRuntimeDispatchProof.workerAttachLifecycleStatuses ??
              []
            ).join(" / ") || "missing"}
          </small>
          <small>
            worker session{" "}
            {harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.currentStatus ?? "missing"}
          </small>
          <small>
            worker checkpoint{" "}
            {harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.persistedInRuntimeCheckpoint
              ? "persisted"
              : "missing"}{" "}
            /{" "}
            {harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.restoredFromPersistedSession
              ? "restored"
              : "not restored"}
          </small>
          <small>
            launch{" "}
            {harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.launchAuthorityReady
              ? "authoritative"
              : "blocked"}{" "}
            / rollback{" "}
            {harnessDefaultRuntimeDispatchProof.workerSessionRecord
              ?.rollbackHandoffReady
              ? "handoff ready"
              : "handoff blocked"}
          </small>
          <small>
            launch invariant{" "}
            {DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT} ·{" "}
            {harnessDefaultRuntimeDispatchWorkerLaunchReviewedImportInvariantBound
              ? "bound"
              : "blocked"}
          </small>
          <small>
            envelopes{" "}
            {
              (harnessDefaultRuntimeDispatchProof.workerLaunchEnvelopes ?? [])
                .length
            }{" "}
            · handoff receipts{" "}
            {
              (harnessDefaultRuntimeDispatchProof.workerHandoffReceipts ?? [])
                .length
            }
          </small>
        </article>
      ) : null}
    </>
  );
}
