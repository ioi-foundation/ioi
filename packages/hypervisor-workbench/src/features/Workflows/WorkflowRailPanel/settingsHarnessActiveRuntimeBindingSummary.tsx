import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import type { WorkflowSettingsHarnessActiveRuntimeBinding } from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActiveRuntimeBindingSummaryProps {
  harnessActiveRuntimeBinding: WorkflowSettingsHarnessActiveRuntimeBinding;
}

export function WorkflowSettingsHarnessActiveRuntimeBindingSummary({
  harnessActiveRuntimeBinding,
}: WorkflowSettingsHarnessActiveRuntimeBindingSummaryProps) {
  return (
    <>
      <h4>Active runtime binding</h4>
      <dl
        className="workflow-rail-stats"
        data-testid="workflow-harness-active-runtime-binding-summary"
      >
        <div>
          <dt>Mode</dt>
          <dd>{harnessActiveRuntimeBinding.executionMode}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>
            {harnessActiveRuntimeBinding.bindingMatched ? "matched" : "blocked"}
          </dd>
        </div>
        <div>
          <dt>Receipts</dt>
          <dd>{harnessActiveRuntimeBinding.receiptRefs.length}</dd>
        </div>
        <div>
          <dt>Replay</dt>
          <dd>{harnessActiveRuntimeBinding.replayFixtureRefs.length}</dd>
        </div>
        <div>
          <dt>Authority</dt>
          <dd>
            {harnessActiveRuntimeBinding.workerBindingAuthorityReady
              ? "ready"
              : "blocked"}
          </dd>
        </div>
        <div>
          <dt>Invariant</dt>
          <dd>
            {harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
              ? "bound"
              : "blocked"}
          </dd>
        </div>
        <div>
          <dt>Package</dt>
          <dd>
            {harnessActiveRuntimeBinding.workerRegistryReviewedPackageBound
              ? "bound"
              : "blocked"}
          </dd>
        </div>
        <div>
          <dt>Registry</dt>
          <dd>{harnessActiveRuntimeBinding.workerBindingRegistryStatus}</dd>
        </div>
        <div>
          <dt>Attach</dt>
          <dd>{harnessActiveRuntimeBinding.workerAttachStatus}</dd>
        </div>
        <div>
          <dt>Lifecycle</dt>
          <dd>
            {harnessActiveRuntimeBinding.workerAttachLifecycleComplete
              ? "complete"
              : "blocked"}
          </dd>
        </div>
        <div>
          <dt>Worker</dt>
          <dd>{harnessActiveRuntimeBinding.workerSessionStatus}</dd>
        </div>
        <div>
          <dt>Handoff</dt>
          <dd>
            {harnessActiveRuntimeBinding.workerHandoffNodeTimelineBound
              ? "timeline"
              : "blocked"}
          </dd>
        </div>
      </dl>
      <article
        className={`workflow-output-row is-${
          harnessActiveRuntimeBinding.bindingMatched ? "ready" : "blocked"
        }`}
        data-testid="workflow-harness-active-runtime-binding-rollup"
        data-runtime-authority={harnessActiveRuntimeBinding.runtimeAuthority}
        data-selected-selector={harnessActiveRuntimeBinding.selectedSelector}
        data-production-default-selector={
          harnessActiveRuntimeBinding.productionDefaultSelector
        }
        data-selector-live-promotion-readiness-ready={
          harnessActiveRuntimeBinding.selectorLivePromotionReadinessReady
            ? "true"
            : "false"
        }
        data-dispatch-live-promotion-readiness-ready={
          harnessActiveRuntimeBinding.dispatchLivePromotionReadinessReady
            ? "true"
            : "false"
        }
        data-invalid-fork-live-activation-blocked={
          harnessActiveRuntimeBinding.invalidForkLiveActivationBlocked
            ? "true"
            : "false"
        }
        data-worker-launch-reviewed-import-invariant-bound={
          harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
            ? "true"
            : "false"
        }
        data-worker-registry-reviewed-package-bound={
          harnessActiveRuntimeBinding.workerRegistryReviewedPackageBound
            ? "true"
            : "false"
        }
        data-worker-registry-reviewed-package-snapshot-hash={
          harnessActiveRuntimeBinding.workerBindingRegistryRecord
            ?.reviewedPackageSnapshotHash ?? ""
        }
        data-worker-registry-reviewed-package-workflow-hash={
          harnessActiveRuntimeBinding.workerBindingRegistryRecord
            ?.reviewedWorkflowContentHash ?? ""
        }
        data-worker-registry-reviewed-package-replay-fixtures={(
          harnessActiveRuntimeBinding.workerBindingRegistryRecord
            ?.reviewedReplayFixtureRefs ?? []
        ).join(",")}
        data-worker-binding-required-invariant-ids={harnessActiveRuntimeBinding.workerBindingRequiredInvariantIds.join(
          ",",
        )}
        data-worker-binding-invariant-blockers={harnessActiveRuntimeBinding.workerBindingInvariantBlockers.join(
          ",",
        )}
        data-worker-registry-required-invariant-ids={harnessActiveRuntimeBinding.workerRegistryRequiredInvariantIds.join(
          ",",
        )}
        data-worker-registry-invariant-blockers={harnessActiveRuntimeBinding.workerRegistryInvariantBlockers.join(
          ",",
        )}
        data-worker-attach-required-invariant-ids={harnessActiveRuntimeBinding.workerAttachRequiredInvariantIds.join(
          ",",
        )}
        data-worker-attach-invariant-blockers={harnessActiveRuntimeBinding.workerAttachInvariantBlockers.join(
          ",",
        )}
        data-worker-attach-lifecycle-required-invariant-ids={harnessActiveRuntimeBinding.workerAttachLifecycleRequiredInvariantIds.join(
          ",",
        )}
        data-worker-attach-lifecycle-invariant-blockers={harnessActiveRuntimeBinding.workerAttachLifecycleInvariantBlockers.join(
          ",",
        )}
        data-worker-session-required-invariant-ids={harnessActiveRuntimeBinding.workerSessionRequiredInvariantIds.join(
          ",",
        )}
        data-worker-session-invariant-blockers={harnessActiveRuntimeBinding.workerSessionInvariantBlockers.join(
          ",",
        )}
        data-worker-session-launch-authority-invariant-ids={harnessActiveRuntimeBinding.workerSessionLaunchAuthorityInvariantIds.join(
          ",",
        )}
        data-worker-session-launch-authority-invariant-blockers={harnessActiveRuntimeBinding.workerSessionLaunchAuthorityInvariantBlockers.join(
          ",",
        )}
        data-worker-launch-envelope-invariant-ids={harnessActiveRuntimeBinding.workerLaunchEnvelopeInvariantIds.join(
          ",",
        )}
        data-worker-launch-envelope-invariant-blockers={harnessActiveRuntimeBinding.workerLaunchEnvelopeInvariantBlockers.join(
          ",",
        )}
        data-worker-handoff-receipt-invariant-ids={harnessActiveRuntimeBinding.workerHandoffReceiptInvariantIds.join(
          ",",
        )}
        data-worker-handoff-receipt-invariant-blockers={harnessActiveRuntimeBinding.workerHandoffReceiptInvariantBlockers.join(
          ",",
        )}
        data-worker-binding-registry-record-id={
          harnessActiveRuntimeBinding.workerBindingRegistryRecord
            ?.registryRecordId ?? ""
        }
        data-worker-attach-receipt-id={
          harnessActiveRuntimeBinding.workerAttachReceipt?.receiptId ?? ""
        }
        data-worker-attach-resume-receipt-id={
          harnessActiveRuntimeBinding.workerAttachResumeReceipt?.receiptId ?? ""
        }
        data-worker-attach-rollback-receipt-id={
          harnessActiveRuntimeBinding.workerAttachRollbackReceipt?.receiptId ?? ""
        }
        data-worker-attach-lifecycle-complete={
          harnessActiveRuntimeBinding.workerAttachLifecycleComplete
            ? "true"
            : "false"
        }
        data-worker-attach-lifecycle-statuses={harnessActiveRuntimeBinding.workerAttachLifecycleStatuses.join(
          ",",
        )}
        data-worker-attach-lifecycle-attempt-ids={harnessActiveRuntimeBinding.workerAttachLifecycleAttemptIds.join(
          ",",
        )}
        data-worker-session-record-id={
          harnessActiveRuntimeBinding.workerSessionRecordId
        }
        data-worker-session-status={
          harnessActiveRuntimeBinding.workerSessionStatus
        }
        data-worker-session-accepted={
          harnessActiveRuntimeBinding.workerSessionAccepted ? "true" : "false"
        }
        data-worker-session-worker-id={
          harnessActiveRuntimeBinding.workerSessionRecord?.workerId ?? ""
        }
        data-worker-session-rollback-target={
          harnessActiveRuntimeBinding.workerSessionRecord?.rollbackTarget ?? ""
        }
        data-worker-session-current-attempt-id={
          harnessActiveRuntimeBinding.workerSessionRecord?.currentAttemptId ?? ""
        }
        data-worker-session-persistence-key={
          harnessActiveRuntimeBinding.workerSessionRecord?.persistenceKey ?? ""
        }
        data-worker-session-record-persistence-key={
          harnessActiveRuntimeBinding.workerSessionRecord?.recordPersistenceKey ?? ""
        }
        data-worker-session-persisted={
          harnessActiveRuntimeBinding.workerSessionRecord
            ?.persistedInRuntimeCheckpoint
            ? "true"
            : "false"
        }
        data-worker-session-restored={
          harnessActiveRuntimeBinding.workerSessionRecord
            ?.restoredFromPersistedSession
            ? "true"
            : "false"
        }
        data-worker-session-checkpoint-source={
          harnessActiveRuntimeBinding.workerSessionRecord?.runtimeCheckpointSource ??
          ""
        }
        data-worker-session-launch-authority-ready={
          harnessActiveRuntimeBinding.workerSessionRecord?.launchAuthorityReady
            ? "true"
            : "false"
        }
        data-worker-session-launch-authority-source={
          harnessActiveRuntimeBinding.workerSessionRecord?.launchAuthoritySource ??
          ""
        }
        data-worker-session-rollback-handoff-ready={
          harnessActiveRuntimeBinding.workerSessionRecord?.rollbackHandoffReady
            ? "true"
            : "false"
        }
        data-worker-session-rollback-handoff-target={
          harnessActiveRuntimeBinding.workerSessionRecord?.rollbackHandoffTarget ??
          ""
        }
        data-worker-launch-envelope-count={
          harnessActiveRuntimeBinding.workerLaunchEnvelopes.length
        }
        data-worker-launch-envelope-ids={harnessActiveRuntimeBinding.workerLaunchEnvelopeIds.join(
          ",",
        )}
        data-worker-launch-envelopes-accepted={
          harnessActiveRuntimeBinding.workerLaunchEnvelopesAccepted
            ? "true"
            : "false"
        }
        data-worker-handoff-receipt-count={
          harnessActiveRuntimeBinding.workerHandoffReceipts.length
        }
        data-worker-handoff-receipt-ids={harnessActiveRuntimeBinding.workerHandoffReceiptIds.join(
          ",",
        )}
        data-worker-handoff-receipts-accepted={
          harnessActiveRuntimeBinding.workerHandoffReceiptsAccepted
            ? "true"
            : "false"
        }
        data-worker-handoff-node-attempt-count={
          harnessActiveRuntimeBinding.workerHandoffNodeAttempts.length
        }
        data-worker-handoff-node-attempt-ids={harnessActiveRuntimeBinding.workerHandoffNodeAttemptIds.join(
          ",",
        )}
        data-worker-handoff-replay-fixture-refs={harnessActiveRuntimeBinding.workerHandoffReplayFixtureRefs.join(
          ",",
        )}
        data-worker-handoff-node-timeline-bound={
          harnessActiveRuntimeBinding.workerHandoffNodeTimelineBound
            ? "true"
            : "false"
        }
        data-worker-rollback-handoff-receipt-status={
          harnessActiveRuntimeBinding.workerHandoffReceipts.find(
            (receipt) => receipt.phase === "rollback",
          )?.handoffStatus ?? ""
        }
      >
        <strong>{harnessActiveRuntimeBinding.activationId}</strong>
        <span>
          {harnessActiveRuntimeBinding.workflowId} ·{" "}
          {harnessActiveRuntimeBinding.executionMode}
        </span>
        <small>
          {harnessActiveRuntimeBinding.runtimeAuthority} · rollback{" "}
          {harnessActiveRuntimeBinding.rollbackAvailable
            ? harnessActiveRuntimeBinding.rollbackTarget
            : "blocked"}
        </small>
        <small>
          proof {harnessActiveRuntimeBinding.selectorLivePromotionReadinessProofId}
        </small>
        <small>
          registry{" "}
          {harnessActiveRuntimeBinding.workerBindingRegistryRecord
            ?.registryRecordId ?? "missing"}
        </small>
        <small>
          package snapshot{" "}
          {harnessActiveRuntimeBinding.workerBindingRegistryRecord
            ?.reviewedPackageSnapshotHash ?? "missing"}
        </small>
        <small>
          attach{" "}
          {harnessActiveRuntimeBinding.workerAttachReceipt?.receiptId ??
            "missing"}
        </small>
        <small>
          lifecycle{" "}
          {harnessActiveRuntimeBinding.workerAttachLifecycleStatuses.join(
            " / ",
          ) || "missing"}
        </small>
        <small>
          worker session{" "}
          {harnessActiveRuntimeBinding.workerSessionRecord?.sessionRecordId ??
            "missing"}
        </small>
        <small>
          checkpoint{" "}
          {harnessActiveRuntimeBinding.workerSessionRecord
            ?.persistedInRuntimeCheckpoint
            ? "persisted"
            : "missing"}{" "}
          /{" "}
          {harnessActiveRuntimeBinding.workerSessionRecord
            ?.restoredFromPersistedSession
            ? "restored"
            : "not restored"}
        </small>
        <small>
          launch{" "}
          {harnessActiveRuntimeBinding.workerSessionRecord?.launchAuthorityReady
            ? "authoritative"
            : "blocked"}{" "}
          / rollback{" "}
          {harnessActiveRuntimeBinding.workerSessionRecord?.rollbackHandoffReady
            ? "handoff ready"
            : "handoff blocked"}
        </small>
        <small>
          invariant{" "}
          {DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT} ·{" "}
          {harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
            ? "bound"
            : "blocked"}
        </small>
        {harnessActiveRuntimeBinding.workerInvariantBlockers.length > 0 ? (
          <small>
            invariant blockers{" "}
            {harnessActiveRuntimeBinding.workerInvariantBlockers.join(", ")}
          </small>
        ) : null}
        <small>
          envelopes {harnessActiveRuntimeBinding.workerLaunchEnvelopes.length} ·
          handoff receipts{" "}
          {harnessActiveRuntimeBinding.workerHandoffReceipts.length}
        </small>
        <small>
          handoff attempts{" "}
          {harnessActiveRuntimeBinding.workerHandoffNodeAttempts.length} · replay
          fixtures{" "}
          {harnessActiveRuntimeBinding.workerHandoffReplayFixtureRefs.length}
        </small>
      </article>
    </>
  );
}
