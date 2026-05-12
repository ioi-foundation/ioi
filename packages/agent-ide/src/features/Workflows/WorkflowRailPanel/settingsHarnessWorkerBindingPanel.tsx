import { DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT } from "../../../runtime/harness-workflow";
import { workflowUniqueReceiptRefs } from "../../../runtime/workflow-rail-model";
import type { WorkflowProject } from "../../../types/graph";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessPanel";

export interface WorkflowSettingsHarnessWorkerBindingPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "harnessActivationAudit"
      | "harnessActivationAuditReceiptRefs"
      | "harnessActivationCandidate"
      | "harnessActivationRecord"
      | "harnessActivationRollbackExecution"
      | "harnessActivationRollbackProof"
      | "latestHarnessActivationAudit"
      | "latestHarnessActivationAuditReceiptRefs"
      | "selectedHarnessActivationAuditEventId"
    >,
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
      | "harnessBindingRollbackAvailable"
      | "harnessBindingRollbackHash"
      | "harnessBindingRollbackTargets"
      | "harnessRollbackDrillReceiptRefs"
      | "harnessRollbackExecutionReceiptRefs"
      | "harnessRollbackRevisionBinding"
      | "harnessRollbackRevisionBindingRef"
      | "harnessSelectedRollbackTarget"
      | "selectedHarnessRollbackTarget"
    >,
    Pick<
      WorkflowSettingsHarnessWorkerBindingProps,
      | "harnessBindingInspectorStatus"
      | "harnessBindingVersionEntries"
      | "harnessCandidateRevisionBinding"
      | "harnessCandidateRevisionBindingRef"
      | "harnessCandidateWorkerBinding"
      | "harnessCurrentWorkerBinding"
      | "harnessRevisionBinding"
      | "harnessRevisionBindingRef"
      | "harnessWorkerBinding"
      | "selectedHarnessDefaultDispatchId"
      | "selectedHarnessNodeAttemptId"
      | "selectedHarnessReceiptRef"
      | "selectedHarnessReplayFixtureRef"
      | "selectedHarnessRevisionBindingKind"
      | "selectedHarnessRevisionBindingRef"
      | "selectedHarnessSelectorDecisionId"
      | "selectedHarnessWorkerBindingId"
    >,
    Pick<WorkflowSettingsHarnessPromotionProps, "harnessForkWorkflow">,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onApplyActiveRuntimeRollback"
      | "onApplyHarnessActivationCandidate"
      | "onCheckActivationReadiness"
      | "onCopyHarnessDeepLink"
      | "onExecuteHarnessRollback"
      | "onRunActiveRuntimeRollbackDryRun"
      | "onRunHarnessActivationDryRun"
      | "onRunHarnessRollbackDrill"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
      | "onSelectHarnessRollbackTarget"
    > {
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessWorkerBindingPanel({
  harnessActivationAudit,
  harnessActivationAuditReceiptRefs,
  harnessActivationCandidate,
  harnessActivationRecord,
  harnessActivationRollbackExecution,
  harnessActivationRollbackProof,
  latestHarnessActivationAudit,
  latestHarnessActivationAuditReceiptRefs,
  selectedHarnessActivationAuditEventId,
  harnessActiveRuntimeBinding,
  harnessActiveRuntimeRollbackApplyBlockers,
  harnessActiveRuntimeRollbackApplyDisabled,
  harnessActiveRuntimeRollbackApplyProof,
  harnessActiveRuntimeRollbackDryRunPassed,
  harnessActiveRuntimeRollbackExecutionProof,
  harnessActiveRuntimeRollbackProofBindingBlockers,
  harnessActiveRuntimeRollbackProofStillBound,
  harnessBindingRollbackAvailable,
  harnessBindingRollbackHash,
  harnessBindingRollbackTargets,
  harnessRollbackDrillReceiptRefs,
  harnessRollbackExecutionReceiptRefs,
  harnessRollbackRevisionBinding,
  harnessRollbackRevisionBindingRef,
  harnessSelectedRollbackTarget,
  selectedHarnessRollbackTarget,
  harnessBindingInspectorStatus,
  harnessBindingVersionEntries,
  harnessCandidateRevisionBinding,
  harnessCandidateRevisionBindingRef,
  harnessCandidateWorkerBinding,
  harnessCurrentWorkerBinding,
  harnessRevisionBinding,
  harnessRevisionBindingRef,
  harnessWorkerBinding,
  selectedHarnessDefaultDispatchId,
  selectedHarnessNodeAttemptId,
  selectedHarnessReceiptRef,
  selectedHarnessReplayFixtureRef,
  selectedHarnessRevisionBindingKind,
  selectedHarnessRevisionBindingRef,
  selectedHarnessSelectorDecisionId,
  selectedHarnessWorkerBindingId,
  harnessForkWorkflow,
  onApplyActiveRuntimeRollback,
  onApplyHarnessActivationCandidate,
  onCheckActivationReadiness,
  onCopyHarnessDeepLink,
  onExecuteHarnessRollback,
  onRunActiveRuntimeRollbackDryRun,
  onRunHarnessActivationDryRun,
  onRunHarnessRollbackDrill,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
  onSelectHarnessRollbackTarget,
  workflow,
}: WorkflowSettingsHarnessWorkerBindingPanelProps) {
  return (
    <>
      {harnessWorkerBinding ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-worker-identity"
        >
          <strong>{harnessWorkerBinding.harnessWorkflowId}</strong>
          <span>
            {harnessWorkerBinding.harnessActivationId ?? "activation blocked"}
          </span>
          <small>
            {harnessWorkerBinding.executionMode ?? "projection"} ·{" "}
            {harnessWorkerBinding.harnessHash}
          </small>
        </article>
      ) : null}
      {harnessActivationRecord ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-harness-activation-record"
        >
          <strong>
            {harnessActivationRecord.activationId ?? "activation not minted"}
          </strong>
          <span>
            {harnessActivationRecord.activationState} · canary{" "}
            {harnessActivationRecord.canaryStatus}
          </span>
          <small>
            rollback{" "}
            {harnessActivationRecord.rollbackAvailable ? "ready" : "blocked"} ·{" "}
            {harnessActivationRecord.rollbackTarget}
          </small>
        </article>
      ) : null}
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
          <article
            className={`workflow-output-row is-${
              harnessActiveRuntimeBinding.workerRollbackProof.bound
                ? "ready"
                : "blocked"
            }`}
            data-testid="workflow-harness-active-runtime-rollback-proof"
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
              harnessActiveRuntimeRollbackExecutionProof?.dryRun
                .canaryResultId ?? ""
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
              harnessActiveRuntimeRollbackExecutionProof?.apply
                .policyDecision ?? ""
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
            <strong>Rollback proof</strong>
            <span>
              {harnessActiveRuntimeBinding.workerRollbackProof.bound
                ? "bound to live-shadow gate"
                : "blocked"}
            </span>
            <small>
              readiness{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof
                .readinessProofId || "missing"}
            </small>
            <small>
              gate{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof
                .liveShadowComparisonGateId || "missing"}{" "}
              ·{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof
                .liveShadowComparisonGateReady
                ? "ready"
                : "blocked"}
            </small>
            <small>
              policy{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof.policyDecision ||
                "missing"}
            </small>
            <small>
              envelope{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof.launchEnvelope
                ?.envelopeId ?? "missing"}
            </small>
            <small>
              handoff{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof.handoffReceipt
                ?.receiptId ?? "missing"}
            </small>
            <small>
              attempt{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof.nodeAttempt
                ?.attemptId ?? "missing"}
            </small>
            <small>
              replay{" "}
              {harnessActiveRuntimeBinding.workerRollbackProof
                .replayFixtureRef || "missing"}
            </small>
            <small>
              dry run{" "}
              {harnessActiveRuntimeRollbackExecutionProof?.dryRun
                .canaryStatus ?? "not run"}{" "}
              · canary{" "}
              {harnessActiveRuntimeRollbackExecutionProof?.dryRun
                .canaryResultId ?? "pending"}
            </small>
            <small>
              apply{" "}
              {harnessActiveRuntimeRollbackApplyDisabled ? "blocked" : "ready"}{" "}
              · proof{" "}
              {harnessActiveRuntimeRollbackProofStillBound
                ? "bound"
                : "not restored"}
            </small>
            <small>
              rollback apply{" "}
              {harnessActiveRuntimeRollbackApplyProof?.applyStatus ?? "not run"}{" "}
              · receipt{" "}
              {harnessActiveRuntimeRollbackApplyProof?.rollbackReceiptId ??
                "pending"}
            </small>
            {harnessActiveRuntimeBinding.workerRollbackProof.blockers.length >
            0 ? (
              <small>
                blockers{" "}
                {harnessActiveRuntimeBinding.workerRollbackProof.blockers.join(
                  ", ",
                )}
              </small>
            ) : null}
            <div className="workflow-harness-authority-gate-actions">
              <button
                type="button"
                data-testid="workflow-harness-active-runtime-rollback-dry-run"
                data-rollback-action-kind="dry_run"
                disabled={
                  !onRunActiveRuntimeRollbackDryRun ||
                  !harnessActiveRuntimeBinding.workerRollbackProof.bound
                }
                onClick={onRunActiveRuntimeRollbackDryRun}
              >
                Rollback dry run
              </button>
              <button
                type="button"
                data-testid="workflow-harness-active-runtime-rollback-apply"
                data-rollback-action-kind="apply"
                data-rollback-apply-disabled={
                  harnessActiveRuntimeRollbackApplyDisabled ? "true" : "false"
                }
                disabled={harnessActiveRuntimeRollbackApplyDisabled}
                onClick={onApplyActiveRuntimeRollback}
              >
                Apply rollback
              </button>
            </div>
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
      <section
        className="workflow-rail-section"
        data-testid="workflow-harness-worker-binding-inspector"
        data-binding-status={harnessBindingInspectorStatus}
        data-component-version-count={harnessBindingVersionEntries.length}
      >
        <h4>Worker binding inspector</h4>
        <dl
          className="workflow-rail-stats"
          data-testid="workflow-harness-worker-binding-summary"
        >
          <div>
            <dt>Current</dt>
            <dd>
              {harnessCurrentWorkerBinding?.harnessActivationId ??
                workflow.metadata.harness?.activationId ??
                "blocked"}
            </dd>
          </div>
          <div>
            <dt>Candidate</dt>
            <dd>
              {harnessActivationCandidate?.activationIdPreview ??
                harnessActivationCandidate?.decision ??
                "none"}
            </dd>
          </div>
          <div>
            <dt>Versions</dt>
            <dd>{harnessBindingVersionEntries.length}</dd>
          </div>
          <div>
            <dt>Rollback</dt>
            <dd>{harnessBindingRollbackAvailable ? "ready" : "blocked"}</dd>
          </div>
          <div>
            <dt>History</dt>
            <dd>{harnessActivationAudit.length}</dd>
          </div>
          <div>
            <dt>Drill</dt>
            <dd>{harnessActivationRollbackProof?.drillStatus ?? "not_run"}</dd>
          </div>
          <div>
            <dt>Revision</dt>
            <dd>{harnessRevisionBinding?.revisionSource ?? "unbound"}</dd>
          </div>
        </dl>
        <div
          className="workflow-rail-list"
          data-testid="workflow-harness-worker-binding-picker"
        >
          <article
            className={`workflow-output-row is-${
              harnessCurrentWorkerBinding ? "ready" : "blocked"
            }`}
            data-testid="workflow-harness-worker-binding-option-current"
            data-binding-source={
              harnessCurrentWorkerBinding?.source ?? "unbound"
            }
          >
            <strong>
              {harnessCurrentWorkerBinding?.harnessWorkflowId ??
                workflow.metadata.harness?.harnessWorkflowId ??
                "unbound"}
            </strong>
            <span>
              current ·{" "}
              {harnessCurrentWorkerBinding?.harnessActivationId ??
                workflow.metadata.harness?.activationId ??
                "activation blocked"}
            </span>
            <small>
              {harnessCurrentWorkerBinding?.executionMode ??
                workflow.metadata.harness?.executionMode ??
                "projection"}{" "}
              ·{" "}
              {harnessCurrentWorkerBinding?.harnessHash ??
                workflow.metadata.harness?.harnessHash ??
                "hash pending"}
            </small>
          </article>
          <article
            className={`workflow-output-row is-${
              harnessActivationCandidate?.decision === "mintable"
                ? "ready"
                : "blocked"
            }`}
            data-testid="workflow-harness-worker-binding-option-candidate"
            data-candidate-decision={
              harnessActivationCandidate?.decision ?? "not_generated"
            }
          >
            <strong>
              {harnessCandidateWorkerBinding?.harnessWorkflowId ??
                workflow.metadata.harness?.packageName ??
                "candidate pending"}
            </strong>
            <span>
              candidate ·{" "}
              {harnessCandidateWorkerBinding?.harnessActivationId ??
                harnessActivationCandidate?.activationIdPreview ??
                "activation blocked"}
            </span>
            <small>
              {harnessCandidateWorkerBinding?.source ?? "fork"} ·{" "}
              {harnessCandidateWorkerBinding?.harnessHash ??
                workflow.metadata.harness?.harnessHash ??
                "hash pending"}
            </small>
          </article>
          <article
            className={`workflow-output-row is-${
              harnessBindingRollbackAvailable ? "ready" : "blocked"
            }`}
            data-testid="workflow-harness-worker-binding-option-rollback"
            data-rollback-available={
              harnessBindingRollbackAvailable ? "true" : "false"
            }
          >
            <strong>{harnessSelectedRollbackTarget}</strong>
            <span>
              rollback ·{" "}
              {harnessActivationRecord?.canaryStatus ??
                workflow.metadata.harness?.activationState ??
                "not_run"}
            </span>
            <small>{harnessBindingRollbackHash}</small>
          </article>
        </div>
        <div
          className="workflow-harness-authority-gate-actions"
          data-testid="workflow-harness-worker-binding-rollback-targets"
        >
          {harnessBindingRollbackTargets.map(
            (rollbackTarget, index: number) => (
              <button
                key={rollbackTarget}
                type="button"
                className={`workflow-harness-ref-button ${
                  rollbackTarget === harnessSelectedRollbackTarget
                    ? "is-active"
                    : ""
                }`}
                data-testid={`workflow-harness-worker-binding-rollback-target-${index}`}
                data-rollback-target={rollbackTarget}
                onClick={() => onSelectHarnessRollbackTarget?.(rollbackTarget)}
              >
                <code>{rollbackTarget}</code>
              </button>
            ),
          )}
        </div>
        <div
          className="workflow-rail-list"
          data-testid="workflow-harness-worker-binding-version-set"
        >
          {harnessBindingVersionEntries
            .slice(0, 8)
            .map(([componentId, version]) => (
              <article
                key={componentId}
                className="workflow-test-row"
                data-testid={`workflow-harness-worker-binding-version-${componentId}`}
              >
                <strong>{componentId}</strong>
                <span>{version}</span>
              </article>
            ))}
          {harnessBindingVersionEntries.length > 8 ? (
            <article className="workflow-output-row">
              <strong>
                {harnessBindingVersionEntries.length - 8} more component
                versions
              </strong>
              <span>
                Full version set remains bound in activation metadata.
              </span>
            </article>
          ) : null}
        </div>
        <section
          className="workflow-rail-section"
          data-testid="workflow-harness-revision-binding"
          data-revision-source={
            harnessRevisionBinding?.revisionSource ?? "unbound"
          }
          data-current-revision-binding-ref={harnessRevisionBindingRef ?? ""}
          data-candidate-revision-binding-ref={
            harnessCandidateRevisionBindingRef ?? ""
          }
          data-rollback-revision-binding-ref={
            harnessRollbackRevisionBindingRef ?? ""
          }
          data-selected-revision-binding-kind={
            selectedHarnessRevisionBindingKind ?? ""
          }
          data-selected-revision-binding-ref={
            selectedHarnessRevisionBindingRef ?? ""
          }
        >
          <h4>Source control posture</h4>
          <div className="workflow-rail-list">
            <button
              type="button"
              className={`workflow-output-row is-${
                harnessRevisionBinding ? "ready" : "blocked"
              }`}
              data-testid="workflow-harness-revision-binding-current"
              data-revision-binding-kind="current"
              data-revision-binding-ref={harnessRevisionBindingRef ?? ""}
              disabled={!harnessRevisionBindingRef || !onCopyHarnessDeepLink}
              onClick={() =>
                harnessRevisionBindingRef &&
                onCopyHarnessDeepLink?.({
                  panel: "settings",
                  revisionBindingKind: "current",
                  revisionBindingRef: harnessRevisionBindingRef,
                })
              }
            >
              <strong>
                {harnessRevisionBinding?.workflowPath ??
                  "workflow path pending"}
              </strong>
              <span>
                {harnessRevisionBinding?.branch ??
                  workflow.metadata.branch ??
                  "main"}{" "}
                · {harnessRevisionBinding?.revisionSource ?? "unbound"}
              </span>
              <small>
                {harnessRevisionBinding?.activatedRevision ??
                  harnessRevisionBinding?.workflowContentHash ??
                  "content hash pending"}
              </small>
            </button>
            <button
              type="button"
              className={`workflow-output-row is-${
                harnessCandidateRevisionBinding ? "ready" : "blocked"
              }`}
              data-testid="workflow-harness-revision-binding-candidate"
              data-revision-binding-kind="candidate"
              data-revision-binding-ref={
                harnessCandidateRevisionBindingRef ?? ""
              }
              disabled={
                !harnessCandidateRevisionBindingRef || !onCopyHarnessDeepLink
              }
              onClick={() =>
                harnessCandidateRevisionBindingRef &&
                onCopyHarnessDeepLink?.({
                  panel: "settings",
                  revisionBindingKind: "candidate",
                  revisionBindingRef: harnessCandidateRevisionBindingRef,
                })
              }
            >
              <strong>
                {harnessCandidateRevisionBinding?.activationId ??
                  "candidate pending"}
              </strong>
              <span>
                proposal {harnessCandidateRevisionBinding?.proposalId ?? "none"}{" "}
                ·{" "}
                {harnessCandidateRevisionBinding?.workflowContentHash ??
                  "hash pending"}
              </span>
              <small>
                {harnessCandidateRevisionBinding?.workflowPath ??
                  "Run dry run binding"}
              </small>
            </button>
            <button
              type="button"
              className={`workflow-output-row is-${
                harnessRollbackRevisionBinding ? "ready" : "blocked"
              }`}
              data-testid="workflow-harness-revision-binding-rollback"
              data-revision-binding-kind="rollback"
              data-revision-binding-ref={
                harnessRollbackRevisionBindingRef ?? ""
              }
              disabled={
                !harnessRollbackRevisionBindingRef || !onCopyHarnessDeepLink
              }
              onClick={() =>
                harnessRollbackRevisionBindingRef &&
                onCopyHarnessDeepLink?.({
                  panel: "settings",
                  revisionBindingKind: "rollback",
                  revisionBindingRef: harnessRollbackRevisionBindingRef,
                })
              }
            >
              <strong>
                {harnessRollbackRevisionBinding?.activationId ??
                  harnessSelectedRollbackTarget}
              </strong>
              <span>
                rollback revision{" "}
                {harnessRevisionBinding?.rollbackRevision ??
                  harnessRollbackRevisionBinding?.activatedRevision ??
                  "pending"}
              </span>
              <small>
                {harnessRollbackRevisionBinding?.workflowPath ??
                  "Rollback target revision will appear after drill."}
              </small>
            </button>
          </div>
        </section>
        {harnessForkWorkflow ? (
          <div
            className="workflow-harness-activation-actions"
            data-testid="workflow-harness-worker-binding-actions"
          >
            <button
              type="button"
              data-testid="workflow-harness-worker-binding-refresh-candidate"
              onClick={onRunHarnessActivationDryRun}
            >
              Dry run binding
            </button>
            <button
              type="button"
              data-testid="workflow-harness-worker-binding-check-readiness"
              onClick={onCheckActivationReadiness}
            >
              Check binding
            </button>
            <button
              type="button"
              data-testid="workflow-harness-worker-binding-apply-candidate"
              disabled={
                harnessActivationCandidate?.decision !== "mintable" ||
                !onApplyHarnessActivationCandidate
              }
              onClick={onApplyHarnessActivationCandidate}
            >
              Mint activation
            </button>
            <button
              type="button"
              data-testid="workflow-harness-worker-binding-run-rollback-drill"
              disabled={!onRunHarnessRollbackDrill}
              onClick={onRunHarnessRollbackDrill}
            >
              Run rollback drill
            </button>
            <button
              type="button"
              data-testid="workflow-harness-worker-binding-execute-rollback"
              disabled={!onExecuteHarnessRollback}
              onClick={onExecuteHarnessRollback}
            >
              Execute rollback
            </button>
          </div>
        ) : null}
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
                      selectedHarnessReceiptRef === receiptRef
                        ? "is-active"
                        : ""
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
                      selectedHarnessReceiptRef === receiptRef
                        ? "is-active"
                        : ""
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
        <section
          className="workflow-rail-section"
          data-testid="workflow-harness-activation-audit"
          data-audit-count={harnessActivationAudit.length}
          data-receipt-refs={harnessActivationAuditReceiptRefs.join("|")}
          data-selected-activation-audit-event-id={
            selectedHarnessActivationAuditEventId ?? ""
          }
        >
          <h4>Activation audit</h4>
          <article
            className="workflow-output-row"
            data-testid="workflow-harness-activation-audit-summary"
            data-receipt-refs={latestHarnessActivationAuditReceiptRefs.join(
              "|",
            )}
          >
            <strong>
              {latestHarnessActivationAudit?.eventType ?? "no audit events"}
            </strong>
            <span>
              {latestHarnessActivationAudit?.status ?? "pending"} ·{" "}
              {latestHarnessActivationAudit?.rollbackTarget ??
                "rollback not selected"}
            </span>
            <small>
              {latestHarnessActivationAuditReceiptRefs[0] ??
                latestHarnessActivationAudit?.summary ??
                "Run a dry run to create history."}
            </small>
          </article>
          {latestHarnessActivationAuditReceiptRefs.length > 0 ? (
            <div
              className="workflow-harness-authority-gate-actions"
              data-testid="workflow-harness-activation-audit-summary-receipts"
            >
              {latestHarnessActivationAuditReceiptRefs.map(
                (receiptRef, index: number) => (
                  <button
                    key={receiptRef}
                    type="button"
                    className={`workflow-harness-ref-button ${
                      selectedHarnessReceiptRef === receiptRef
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-activation-audit-summary-receipt-${index}`}
                    data-receipt-ref={receiptRef}
                    onClick={() => onSelectHarnessReceiptRef?.(receiptRef)}
                  >
                    <code>{receiptRef}</code>
                  </button>
                ),
              )}
            </div>
          ) : null}
          <div
            className="workflow-rail-list"
            data-testid="workflow-harness-activation-audit-list"
          >
            {harnessActivationAudit.slice(-6).map((event) => {
              const eventReceiptRefs = workflowUniqueReceiptRefs(
                event.receiptRefs ?? [],
              );
              return (
                <article
                  key={event.eventId}
                  className={`workflow-test-row is-${
                    event.status === "blocked" ? "blocked" : "passed"
                  } ${
                    selectedHarnessActivationAuditEventId === event.eventId
                      ? "is-active"
                      : ""
                  }`}
                  data-testid={`workflow-harness-activation-audit-event-${event.eventId}`}
                  data-audit-event-id={event.eventId}
                  data-audit-event-type={event.eventType}
                  data-audit-receipt-refs={eventReceiptRefs.join("|")}
                >
                  <strong>{event.eventType}</strong>
                  <span>
                    {event.status} ·{" "}
                    {event.activationId ??
                      event.nextActivationId ??
                      "no activation"}
                  </span>
                  <small>{eventReceiptRefs[0] ?? event.summary}</small>
                  {eventReceiptRefs.length > 0 || onCopyHarnessDeepLink ? (
                    <div
                      className="workflow-harness-authority-gate-actions"
                      data-testid={`workflow-harness-activation-audit-receipts-${event.eventId}`}
                    >
                      {onCopyHarnessDeepLink ? (
                        <button
                          type="button"
                          className={`workflow-harness-ref-button ${
                            selectedHarnessActivationAuditEventId ===
                            event.eventId
                              ? "is-active"
                              : ""
                          }`}
                          data-testid={`workflow-harness-activation-audit-event-link-${event.eventId}`}
                          data-activation-audit-event-id={event.eventId}
                          onClick={() =>
                            onCopyHarnessDeepLink?.({
                              panel: "settings",
                              activationAuditEventId: event.eventId,
                            })
                          }
                        >
                          <code>{event.eventId}</code>
                        </button>
                      ) : null}
                      {eventReceiptRefs.map((receiptRef, index: number) => (
                        <button
                          key={receiptRef}
                          type="button"
                          className={`workflow-harness-ref-button ${
                            selectedHarnessReceiptRef === receiptRef
                              ? "is-active"
                              : ""
                          }`}
                          data-testid={`workflow-harness-activation-audit-receipt-${event.eventId}-${index}`}
                          data-receipt-ref={receiptRef}
                          onClick={() =>
                            onSelectHarnessReceiptRef?.(receiptRef)
                          }
                        >
                          <code>{receiptRef}</code>
                        </button>
                      ))}
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        </section>
      </section>
    </>
  );
}
