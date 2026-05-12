import { workflowUniqueReceiptRefs } from "../../../runtime/workflow-rail-model";
import { WorkflowSettingsHarnessActiveRuntimeRollbackPanel } from "./settingsHarnessActiveRuntimeRollbackPanel";
import type { WorkflowProject } from "../../../types/graph";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPromotionProps,
  WorkflowSettingsHarnessRollbackProps,
  WorkflowSettingsHarnessWorkerBindingProps,
} from "./settingsHarnessTypes";

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
      <WorkflowSettingsHarnessActiveRuntimeRollbackPanel
        harnessActivationRollbackExecution={harnessActivationRollbackExecution}
        harnessActivationRollbackProof={harnessActivationRollbackProof}
        harnessActiveRuntimeBinding={harnessActiveRuntimeBinding}
        harnessActiveRuntimeRollbackApplyBlockers={
          harnessActiveRuntimeRollbackApplyBlockers
        }
        harnessActiveRuntimeRollbackApplyDisabled={
          harnessActiveRuntimeRollbackApplyDisabled
        }
        harnessActiveRuntimeRollbackApplyProof={
          harnessActiveRuntimeRollbackApplyProof
        }
        harnessActiveRuntimeRollbackDryRunPassed={
          harnessActiveRuntimeRollbackDryRunPassed
        }
        harnessActiveRuntimeRollbackExecutionProof={
          harnessActiveRuntimeRollbackExecutionProof
        }
        harnessActiveRuntimeRollbackProofBindingBlockers={
          harnessActiveRuntimeRollbackProofBindingBlockers
        }
        harnessActiveRuntimeRollbackProofStillBound={
          harnessActiveRuntimeRollbackProofStillBound
        }
        harnessForkWorkflow={harnessForkWorkflow}
        harnessRollbackDrillReceiptRefs={harnessRollbackDrillReceiptRefs}
        harnessRollbackExecutionReceiptRefs={
          harnessRollbackExecutionReceiptRefs
        }
        harnessSelectedRollbackTarget={harnessSelectedRollbackTarget}
        selectedHarnessDefaultDispatchId={selectedHarnessDefaultDispatchId}
        selectedHarnessNodeAttemptId={selectedHarnessNodeAttemptId}
        selectedHarnessReceiptRef={selectedHarnessReceiptRef}
        selectedHarnessReplayFixtureRef={selectedHarnessReplayFixtureRef}
        selectedHarnessRollbackTarget={selectedHarnessRollbackTarget}
        selectedHarnessSelectorDecisionId={selectedHarnessSelectorDecisionId}
        selectedHarnessWorkerBindingId={selectedHarnessWorkerBindingId}
        onApplyActiveRuntimeRollback={onApplyActiveRuntimeRollback}
        onCopyHarnessDeepLink={onCopyHarnessDeepLink}
        onExecuteHarnessRollback={onExecuteHarnessRollback}
        onRunActiveRuntimeRollbackDryRun={onRunActiveRuntimeRollbackDryRun}
        onRunHarnessRollbackDrill={onRunHarnessRollbackDrill}
        onSelectHarnessReceiptRef={onSelectHarnessReceiptRef}
        onSelectHarnessReplayFixtureRef={onSelectHarnessReplayFixtureRef}
        onSelectHarnessRollbackTarget={onSelectHarnessRollbackTarget}
      />
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
          </div>
        ) : null}
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
