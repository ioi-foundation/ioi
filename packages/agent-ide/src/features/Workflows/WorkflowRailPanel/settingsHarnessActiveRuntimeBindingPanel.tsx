import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import type {
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActiveRuntimeBindingPanelProps
  extends
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
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCopyHarnessDeepLink"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
      | "onSelectHarnessRollbackTarget"
    > {}

export function WorkflowSettingsHarnessActiveRuntimeBindingPanel({
  harnessActiveRuntimeBinding,
  harnessActiveRuntimeRollbackApplyBlockers,
  harnessActiveRuntimeRollbackApplyDisabled,
  harnessActiveRuntimeRollbackApplyProof,
  harnessActiveRuntimeRollbackDryRunPassed,
  harnessActiveRuntimeRollbackExecutionProof,
  harnessActiveRuntimeRollbackProofBindingBlockers,
  harnessActiveRuntimeRollbackProofStillBound,
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
}: WorkflowSettingsHarnessActiveRuntimeBindingPanelProps) {
  return (
    <>
      {harnessActiveRuntimeBinding ? (
        <section
          className="workflow-rail-section workflow-harness-active-runtime-binding"
          data-testid="workflow-harness-active-runtime-binding"
          data-binding-matched={
            harnessActiveRuntimeBinding.bindingMatched ? "true" : "false"
          }
          data-workflow-id={harnessActiveRuntimeBinding.workflowId}
          data-activation-id={harnessActiveRuntimeBinding.activationId}
          data-harness-hash={harnessActiveRuntimeBinding.harnessHash}
          data-selector-decision-id={
            harnessActiveRuntimeBinding.selectorDecisionId
          }
          data-default-dispatch-id={
            harnessActiveRuntimeBinding.defaultDispatchId
          }
          data-worker-binding-id={harnessActiveRuntimeBinding.workerBindingId}
          data-rollback-target={harnessActiveRuntimeBinding.rollbackTarget}
          data-worker-binding-authority-ready={
            harnessActiveRuntimeBinding.workerBindingAuthorityReady
              ? "true"
              : "false"
          }
          data-worker-launch-reviewed-import-invariant-bound={
            harnessActiveRuntimeBinding.workerLaunchReviewedImportInvariantBound
              ? "true"
              : "false"
          }
          data-worker-required-invariant-ids={harnessActiveRuntimeBinding.workerBindingRequiredInvariantIds.join(
            ",",
          )}
          data-worker-invariant-blockers={harnessActiveRuntimeBinding.workerInvariantBlockers.join(
            ",",
          )}
          data-worker-binding-registry-bound={
            harnessActiveRuntimeBinding.workerBindingRegistryBound
              ? "true"
              : "false"
          }
          data-worker-binding-registry-status={
            harnessActiveRuntimeBinding.workerBindingRegistryStatus
          }
          data-worker-attach-status={
            harnessActiveRuntimeBinding.workerAttachStatus
          }
          data-worker-attach-accepted={
            harnessActiveRuntimeBinding.workerAttachAccepted ? "true" : "false"
          }
          data-live-promotion-readiness-proof-id={
            harnessActiveRuntimeBinding.selectorLivePromotionReadinessProofId
          }
          data-live-promotion-readiness-proof-match={
            harnessActiveRuntimeBinding.livePromotionReadinessProofIdsMatch
              ? "true"
              : "false"
          }
          data-selected-selector-decision-id={
            selectedHarnessSelectorDecisionId ?? ""
          }
          data-selected-default-dispatch-id={
            selectedHarnessDefaultDispatchId ?? ""
          }
          data-selected-worker-binding-id={selectedHarnessWorkerBindingId ?? ""}
          data-selected-rollback-target={selectedHarnessRollbackTarget ?? ""}
          data-selected-receipt-ref={selectedHarnessReceiptRef ?? ""}
          data-selected-replay-fixture-ref={
            selectedHarnessReplayFixtureRef ?? ""
          }
          data-selected-node-attempt-id={selectedHarnessNodeAttemptId ?? ""}
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
                {harnessActiveRuntimeBinding.bindingMatched
                  ? "matched"
                  : "blocked"}
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
            data-runtime-authority={
              harnessActiveRuntimeBinding.runtimeAuthority
            }
            data-selected-selector={
              harnessActiveRuntimeBinding.selectedSelector
            }
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
              harnessActiveRuntimeBinding.workerAttachResumeReceipt
                ?.receiptId ?? ""
            }
            data-worker-attach-rollback-receipt-id={
              harnessActiveRuntimeBinding.workerAttachRollbackReceipt
                ?.receiptId ?? ""
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
              harnessActiveRuntimeBinding.workerSessionAccepted
                ? "true"
                : "false"
            }
            data-worker-session-worker-id={
              harnessActiveRuntimeBinding.workerSessionRecord?.workerId ?? ""
            }
            data-worker-session-rollback-target={
              harnessActiveRuntimeBinding.workerSessionRecord?.rollbackTarget ??
              ""
            }
            data-worker-session-current-attempt-id={
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.currentAttemptId ?? ""
            }
            data-worker-session-persistence-key={
              harnessActiveRuntimeBinding.workerSessionRecord?.persistenceKey ??
              ""
            }
            data-worker-session-record-persistence-key={
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.recordPersistenceKey ?? ""
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
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.runtimeCheckpointSource ?? ""
            }
            data-worker-session-launch-authority-ready={
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.launchAuthorityReady
                ? "true"
                : "false"
            }
            data-worker-session-launch-authority-source={
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.launchAuthoritySource ?? ""
            }
            data-worker-session-rollback-handoff-ready={
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.rollbackHandoffReady
                ? "true"
                : "false"
            }
            data-worker-session-rollback-handoff-target={
              harnessActiveRuntimeBinding.workerSessionRecord
                ?.rollbackHandoffTarget ?? ""
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
              proof{" "}
              {
                harnessActiveRuntimeBinding.selectorLivePromotionReadinessProofId
              }
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
              {harnessActiveRuntimeBinding.workerSessionRecord
                ?.sessionRecordId ?? "missing"}
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
              {harnessActiveRuntimeBinding.workerSessionRecord
                ?.launchAuthorityReady
                ? "authoritative"
                : "blocked"}{" "}
              / rollback{" "}
              {harnessActiveRuntimeBinding.workerSessionRecord
                ?.rollbackHandoffReady
                ? "handoff ready"
                : "handoff blocked"}
            </small>
            <small>
              invariant{" "}
              {DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT}{" "}
              ·{" "}
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
              envelopes{" "}
              {harnessActiveRuntimeBinding.workerLaunchEnvelopes.length} ·
              handoff receipts{" "}
              {harnessActiveRuntimeBinding.workerHandoffReceipts.length}
            </small>
            <small>
              handoff attempts{" "}
              {harnessActiveRuntimeBinding.workerHandoffNodeAttempts.length} ·
              replay fixtures{" "}
              {
                harnessActiveRuntimeBinding.workerHandoffReplayFixtureRefs
                  .length
              }
            </small>
          </article>
          <div
            className="workflow-harness-authority-gate-actions"
            data-testid="workflow-harness-active-runtime-binding-deep-links"
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
              data-deep-link-target={
                harnessActiveRuntimeBinding.selectorDecisionId
              }
              disabled={!onCopyHarnessDeepLink}
              onClick={() =>
                onCopyHarnessDeepLink?.({
                  panel: "settings",
                  selectorDecisionId:
                    harnessActiveRuntimeBinding.selectorDecisionId,
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
              data-deep-link-target={
                harnessActiveRuntimeBinding.defaultDispatchId
              }
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
              data-deep-link-target={
                harnessActiveRuntimeBinding.workerBindingId
              }
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
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .launchEnvelope?.envelopeId;
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
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .launchEnvelope.envelopeId
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
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .handoffReceipt?.receiptId;
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
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .handoffReceipt.receiptId
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
                  harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
                    .attemptId
                }
                onClick={() => {
                  const rollbackAttempt =
                    harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt;
                  if (!rollbackAttempt) return;
                  onCopyHarnessDeepLink?.({
                    panel: "outputs",
                    nodeAttemptId: rollbackAttempt.attemptId,
                    receiptRef:
                      harnessActiveRuntimeBinding.workerRollbackProof
                        .handoffReceipt?.receiptId,
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
            {harnessActiveRuntimeBinding.workerRollbackProof
              .replayFixtureRef ? (
              <button
                type="button"
                className={`workflow-harness-ref-button ${
                  selectedHarnessReplayFixtureRef ===
                  harnessActiveRuntimeBinding.workerRollbackProof
                    .replayFixtureRef
                    ? "is-active"
                    : ""
                }`}
                data-testid="workflow-harness-active-runtime-rollback-proof-replay-link"
                data-deep-link-kind="rollback_replay_fixture"
                data-replay-fixture-ref={
                  harnessActiveRuntimeBinding.workerRollbackProof
                    .replayFixtureRef
                }
                onClick={() => {
                  const replayFixtureRef =
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .replayFixtureRef;
                  if (!replayFixtureRef) return;
                  onSelectHarnessReplayFixtureRef?.(replayFixtureRef);
                  onCopyHarnessDeepLink?.({
                    panel: "outputs",
                    replayFixtureRef,
                  });
                }}
              >
                <code>
                  {
                    harnessActiveRuntimeBinding.workerRollbackProof
                      .replayFixtureRef
                  }
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
          {harnessActiveRuntimeBinding.blockers.length > 0 ? (
            <div
              className="workflow-rail-list"
              data-testid="workflow-harness-active-runtime-binding-blockers"
              data-activation-blockers={harnessActiveRuntimeBinding.blockers.join(
                "|",
              )}
            >
              {harnessActiveRuntimeBinding.blockers.map((blocker) => (
                <article key={blocker} className="workflow-test-row is-blocked">
                  <strong>Blocked</strong>
                  <span>{blocker}</span>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      ) : null}
    </>
  );
}
