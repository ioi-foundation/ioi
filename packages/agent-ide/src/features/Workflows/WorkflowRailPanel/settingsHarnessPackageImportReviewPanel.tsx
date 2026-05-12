import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessPackageImportReviewPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "packageImportActivationEnabled"
      | "packageImportActivationHandoff"
      | "packageImportHandoffWorkerBindingId"
      | "packageImportReplayIntegrityBlockers"
      | "packageImportReview"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      "onApplyHarnessActivationCandidate" | "onCopyHarnessDeepLink"
    > {}

export function WorkflowSettingsHarnessPackageImportReviewPanel({
  packageImportActivationEnabled,
  packageImportActivationHandoff,
  packageImportHandoffWorkerBindingId,
  packageImportReplayIntegrityBlockers,
  packageImportReview,
  onApplyHarnessActivationCandidate,
  onCopyHarnessDeepLink,
}: WorkflowSettingsHarnessPackageImportReviewPanelProps) {
  return (
    <>
      {packageImportReview ? (
        <article
          className={`workflow-test-row is-${
            packageImportReview.evidence.packageEvidenceReady
              ? "passed"
              : "blocked"
          }`}
          data-testid="workflow-harness-package-import-review"
          data-package-import-review-open="true"
          data-package-import-source-workflow-path={
            packageImportReview.source.sourceWorkflowPath ?? ""
          }
          data-package-import-source-workflow-id={
            packageImportReview.source.workflowId ?? ""
          }
          data-package-import-source-activation-id={
            packageImportReview.source.activationId ?? ""
          }
          data-package-import-source-workflow-content-hash={
            packageImportReview.source.workflowContentHash ?? ""
          }
          data-package-import-source-harness-hash={
            packageImportReview.source.harnessHash ?? ""
          }
          data-package-import-source-worker-binding-id={
            packageImportReview.source.workerBindingActivationId ?? ""
          }
          data-package-import-source-policy-posture={
            packageImportReview.source.policyPosture ?? ""
          }
          data-package-import-source-mutation-canary-id={
            packageImportReview.source.forkMutationCanaryId ?? ""
          }
          data-package-import-source-mutation-canary-status={
            packageImportReview.source.forkMutationCanaryStatus ?? ""
          }
          data-package-import-source-mutation-canary-diff-hash={
            packageImportReview.source.forkMutationCanaryDiffHash ?? ""
          }
          data-package-import-source-mutation-canary-receipt-ref={
            packageImportReview.source.forkMutationCanaryReceiptRefs?.[0] ?? ""
          }
          data-package-import-source-mutation-canary-replay-fixture-ref={
            packageImportReview.source
              .forkMutationCanaryReplayFixtureRefs?.[0] ?? ""
          }
          data-package-import-source-mutation-canary-node-attempt-id={
            packageImportReview.source.forkMutationCanaryNodeAttemptIds?.[0] ??
            ""
          }
          data-package-import-source-mutation-canary-rollback-target={
            packageImportReview.source.forkMutationCanaryRollbackTarget ?? ""
          }
          data-package-import-source-reviewed-package-snapshot-hash={
            packageImportReview.source.reviewedPackageSnapshotHash ?? ""
          }
          data-package-import-source-chrome-locale={
            packageImportReview.source.workflowChromeLocale ?? ""
          }
          data-package-import-source-replay-fixture-count={
            packageImportReview.source.replayFixtureRefs?.length ?? 0
          }
          data-package-import-imported-workflow-path={
            packageImportReview.imported.workflowPath
          }
          data-package-import-imported-workflow-id={
            packageImportReview.imported.workflowId
          }
          data-package-import-imported-chrome-locale={
            packageImportReview.imported.workflowChromeLocale ?? ""
          }
          data-package-import-readiness-status={
            packageImportReview.imported.activationReadinessStatus ?? ""
          }
          data-package-import-evidence-ready={
            packageImportReview.evidence.packageEvidenceReady ? "true" : "false"
          }
          data-package-import-chrome-locale-preserved={
            packageImportReview.evidence.workflowChromeLocalePreserved
              ? "true"
              : "false"
          }
          data-package-import-evidence-blocker-count={
            packageImportReview.evidence.blockerCount
          }
          data-package-import-activation-enabled={
            packageImportActivationEnabled ? "true" : "false"
          }
          data-package-import-replay-integrity-blocker-count={
            packageImportReplayIntegrityBlockers.length
          }
          data-package-import-replay-integrity-blockers={packageImportReplayIntegrityBlockers.join(
            ",",
          )}
        >
          <strong>Import review</strong>
          <span>
            {packageImportReview.source.workflowName ??
              packageImportReview.source.workflowId ??
              "source package"}{" "}
            to {packageImportReview.imported.workflowName}
          </span>
          <small>
            {packageImportReview.evidence.packageEvidenceReady
              ? "package evidence ready for activation"
              : `${packageImportReview.evidence.blockerCount} package evidence blocker${
                  packageImportReview.evidence.blockerCount === 1 ? "" : "s"
                }`}
          </small>
          <div
            className="workflow-harness-authority-gate-actions"
            data-testid="workflow-harness-package-import-identity"
          >
            <div>
              <strong>Source</strong>
              <span>
                {packageImportReview.source.workflowSlug ??
                  packageImportReview.source.workflowId ??
                  "unknown"}
              </span>
              <small>
                {packageImportReview.source.sourceWorkflowPath ??
                  packageImportReview.packagePath}
              </small>
              <small>
                Chrome locale{" "}
                {packageImportReview.source.workflowChromeLocale ?? "default"}
              </small>
            </div>
            <div>
              <strong>Imported</strong>
              <span>{packageImportReview.imported.workflowSlug}</span>
              <small>{packageImportReview.imported.workflowPath}</small>
              <small>
                Chrome locale{" "}
                {packageImportReview.imported.workflowChromeLocale ?? "default"}
              </small>
            </div>
          </div>
          {packageImportActivationHandoff ? (
            <section
              className="workflow-rail-section"
              data-testid="workflow-harness-package-import-handoff"
              data-package-import-handoff-open="true"
              data-package-import-handoff-decision={
                packageImportActivationHandoff.decision ?? ""
              }
              data-package-import-handoff-activation-id={
                packageImportActivationHandoff.activationIdPreview ?? ""
              }
              data-package-import-handoff-canary-status={
                packageImportActivationHandoff.canaryStatus ?? ""
              }
              data-package-import-handoff-mutation-canary-id={
                packageImportActivationHandoff.forkMutationCanaryId ?? ""
              }
              data-package-import-handoff-mutation-canary-status={
                packageImportActivationHandoff.forkMutationCanaryStatus ?? ""
              }
              data-package-import-handoff-mutation-canary-diff-hash={
                packageImportActivationHandoff.forkMutationCanaryDiffHash ?? ""
              }
              data-package-import-handoff-mutation-canary-receipt-ref={
                packageImportActivationHandoff
                  .forkMutationCanaryReceiptRefs?.[0] ?? ""
              }
              data-package-import-handoff-mutation-canary-replay-fixture-ref={
                packageImportActivationHandoff
                  .forkMutationCanaryReplayFixtureRefs?.[0] ?? ""
              }
              data-package-import-handoff-mutation-canary-node-attempt-id={
                packageImportActivationHandoff
                  .forkMutationCanaryNodeAttemptIds?.[0] ?? ""
              }
              data-package-import-handoff-mutation-canary-rollback-target={
                packageImportActivationHandoff.forkMutationCanaryRollbackTarget ??
                ""
              }
              data-package-import-handoff-rollback-target={
                packageImportActivationHandoff.rollbackTarget ?? ""
              }
              data-package-import-handoff-rollback-available={
                packageImportActivationHandoff.rollbackAvailable
                  ? "true"
                  : "false"
              }
              data-package-import-handoff-worker-binding-id={
                packageImportHandoffWorkerBindingId
              }
              data-package-import-handoff-worker-workflow-id={
                packageImportActivationHandoff.workerBinding
                  ?.harnessWorkflowId ?? ""
              }
              data-package-import-handoff-worker-hash={
                packageImportActivationHandoff.workerBinding?.harnessHash ?? ""
              }
              data-package-import-handoff-workflow-content-hash={
                packageImportActivationHandoff.workflowContentHash ?? ""
              }
              data-package-import-handoff-policy-posture={
                packageImportActivationHandoff.policyPosture ?? ""
              }
              data-package-import-handoff-reviewed-package-snapshot-hash={
                packageImportActivationHandoff.reviewedPackageSnapshotHash ?? ""
              }
              data-package-import-handoff-replay-fixture-count={
                packageImportActivationHandoff.replayFixtureRefs?.length ?? 0
              }
              data-package-import-handoff-mintable={
                packageImportActivationHandoff.mintable ? "true" : "false"
              }
              data-package-import-handoff-replay-integrity-blocker-count={
                packageImportReplayIntegrityBlockers.length
              }
              data-package-import-handoff-replay-integrity-blockers={packageImportReplayIntegrityBlockers.join(
                ",",
              )}
              data-package-import-handoff-blocker-count={
                packageImportActivationHandoff.blockerCount
              }
              data-package-import-handoff-package-evidence-ready={
                packageImportActivationHandoff.packageEvidenceReady
                  ? "true"
                  : "false"
              }
              data-package-import-handoff-activation-enabled={
                packageImportActivationEnabled ? "true" : "false"
              }
            >
              <h4>Activation handoff</h4>
              <article
                className={`workflow-output-row is-${
                  packageImportActivationHandoff.mintable ? "ready" : "blocked"
                }`}
              >
                <strong>
                  {packageImportActivationHandoff.candidateId ??
                    "handoff pending"}
                </strong>
                <span>
                  {packageImportActivationHandoff.decision ?? "unknown"}
                  {" · "}
                  {packageImportActivationHandoff.activationIdPreview ??
                    "activation id blocked"}
                </span>
                <small>
                  canary{" "}
                  {packageImportActivationHandoff.canaryStatus ?? "not_run"} ·
                  mutation{" "}
                  {packageImportActivationHandoff.forkMutationCanaryStatus ??
                    "not_run"}{" "}
                  · rollback{" "}
                  {packageImportActivationHandoff.rollbackTarget ?? "not set"} ·
                  worker {packageImportHandoffWorkerBindingId || "unbound"}
                </small>
              </article>
              <div
                className="workflow-harness-authority-gate-actions"
                data-testid="workflow-harness-package-import-handoff-links"
              >
                <button
                  type="button"
                  className="workflow-harness-ref-button"
                  data-testid="workflow-harness-package-import-handoff-activation-link"
                  disabled={
                    !packageImportActivationHandoff.deepLinkTargets.activationId
                  }
                  onClick={() =>
                    onCopyHarnessDeepLink?.({
                      panel: "settings",
                      activationGateId: "activation-id",
                      activationGateEvidenceRef:
                        packageImportActivationHandoff.deepLinkTargets
                          .activationId ?? undefined,
                    })
                  }
                >
                  <code>activation</code>
                </button>
                <button
                  type="button"
                  className="workflow-harness-ref-button"
                  data-testid="workflow-harness-package-import-handoff-canary-link"
                  disabled={
                    !packageImportActivationHandoff.deepLinkTargets.canary
                  }
                  onClick={() =>
                    onCopyHarnessDeepLink?.({
                      panel: "settings",
                      activationGateId: "canary",
                      activationGateEvidenceRef:
                        packageImportActivationHandoff.deepLinkTargets.canary ??
                        undefined,
                    })
                  }
                >
                  <code>canary</code>
                </button>
                <button
                  type="button"
                  className="workflow-harness-ref-button"
                  data-testid="workflow-harness-package-import-handoff-mutation-canary-link"
                  disabled={
                    !packageImportActivationHandoff.deepLinkTargets
                      .mutationCanary ||
                    !packageImportActivationHandoff
                      .forkMutationCanaryNodeAttemptIds?.[0]
                  }
                  onClick={() =>
                    onCopyHarnessDeepLink?.({
                      panel: "outputs",
                      activationGateId: "mutation-canary",
                      activationGateEvidenceRef:
                        packageImportActivationHandoff.deepLinkTargets
                          .mutationCanary ?? undefined,
                      activationGateNodeAttemptId:
                        packageImportActivationHandoff
                          .forkMutationCanaryNodeAttemptIds?.[0],
                      nodeAttemptId:
                        packageImportActivationHandoff
                          .forkMutationCanaryNodeAttemptIds?.[0],
                      activationGateReceiptRef:
                        packageImportActivationHandoff
                          .forkMutationCanaryReceiptRefs?.[0],
                      receiptRef:
                        packageImportActivationHandoff
                          .forkMutationCanaryReceiptRefs?.[0],
                      activationGateReplayFixtureRef:
                        packageImportActivationHandoff
                          .forkMutationCanaryReplayFixtureRefs?.[0],
                      replayFixtureRef:
                        packageImportActivationHandoff
                          .forkMutationCanaryReplayFixtureRefs?.[0],
                    })
                  }
                >
                  <code>mutation</code>
                </button>
                <button
                  type="button"
                  className="workflow-harness-ref-button"
                  data-testid="workflow-harness-package-import-handoff-rollback-link"
                  disabled={
                    !packageImportActivationHandoff.deepLinkTargets
                      .rollbackRestore
                  }
                  onClick={() =>
                    onCopyHarnessDeepLink?.({
                      panel: "settings",
                      activationGateId: "rollback-restore",
                      activationGateEvidenceRef:
                        packageImportActivationHandoff.deepLinkTargets
                          .rollbackRestore ?? undefined,
                      rollbackTarget:
                        packageImportActivationHandoff.deepLinkTargets
                          .rollbackTarget ?? undefined,
                    })
                  }
                >
                  <code>rollback</code>
                </button>
                <button
                  type="button"
                  className="workflow-harness-ref-button"
                  data-testid="workflow-harness-package-import-handoff-worker-link"
                  disabled={!packageImportHandoffWorkerBindingId}
                  onClick={() =>
                    onCopyHarnessDeepLink?.({
                      panel: "settings",
                      workerBindingId:
                        packageImportHandoffWorkerBindingId || undefined,
                    })
                  }
                >
                  <code>worker</code>
                </button>
              </div>
            </section>
          ) : null}
          <div className="workflow-harness-authority-gate-actions">
            <button
              type="button"
              data-testid="workflow-harness-package-import-activate"
              disabled={!packageImportActivationEnabled}
              onClick={onApplyHarnessActivationCandidate}
            >
              {packageImportActivationEnabled
                ? "Activate reviewed import"
                : "Activation locked"}
            </button>
          </div>
        </article>
      ) : null}
    </>
  );
}
