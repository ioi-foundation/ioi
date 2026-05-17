import type {
  WorkflowPortablePackage,
  WorkflowValidationIssue,
} from "../../../types/graph";
import {
  workflowReadinessModel,
  type WorkflowReadinessModelInput,
} from "../../../runtime/workflow-readiness-model";
import type { WorkflowCapabilityRepairAction } from "../../../runtime/workflow-run-capability-receipts";
import {
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeName,
  workflowReadinessStatusLabel,
} from "../../../runtime/workflow-rail-model";

type WorkflowReadinessPanelProps = WorkflowReadinessModelInput & {
  portablePackage: WorkflowPortablePackage | null;
  onResolveIssue: (issue: WorkflowValidationIssue) => void;
  onInspectNode: (nodeId: string) => void;
  onConfigureNode: () => void;
  onExportPackage: () => void;
  onOpenImportPackage: () => void;
  onCapabilityRepairAction?: (
    action: WorkflowCapabilityRepairAction,
  ) => void | Promise<void>;
};

function workflowSchedulerLaneDomId(id: string): string {
  return id.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "");
}

export function WorkflowReadinessPanel({
  validationResult,
  readinessResult,
  workflow,
  tests,
  portablePackage,
  operationalSideEffectNodes,
  hasErrorOrRetryPath,
  criticalAiNodeIds,
  productionProfile,
  coveredNodeIds,
  mcpToolNodes,
  harnessWorkflow,
  harnessSlots,
  boundHarnessSlotIds,
  harnessActivationReady,
  harnessDefaultRuntimeDispatchProof,
  harnessAuthorityGateLiveReady,
  runtimeCodingToolBudgetEvidence,
  onResolveIssue,
  onInspectNode,
  onConfigureNode,
  onExportPackage,
  onOpenImportPackage,
  onCapabilityRepairAction,
}: WorkflowReadinessPanelProps) {
  const {
    result,
    blockers,
    readinessWarnings,
    policyRequiredNodeIds,
    schedulerLaneReadiness,
    schedulerLaneReadyCount,
    capabilityPreflight,
    codingToolBudgetPreflight,
    readinessItems,
    passedReadinessChecks,
    attentionIssues,
  } = workflowReadinessModel({
    validationResult,
    readinessResult,
    workflow,
    tests,
    operationalSideEffectNodes,
    hasErrorOrRetryPath,
    criticalAiNodeIds,
    productionProfile,
    coveredNodeIds,
    mcpToolNodes,
    harnessWorkflow,
    harnessSlots,
    boundHarnessSlotIds,
    harnessActivationReady,
    harnessDefaultRuntimeDispatchProof,
    harnessAuthorityGateLiveReady,
    runtimeCodingToolBudgetEvidence,
  });

  return (
    <>
      <h3>Readiness</h3>
      <dl
        className="workflow-rail-stats"
        data-testid="workflow-readiness-summary"
      >
        <div>
          <dt>Status</dt>
          <dd>{workflowReadinessStatusLabel(result)}</dd>
        </div>
        <div>
          <dt>Checks</dt>
          <dd>
            {passedReadinessChecks}/{readinessItems.length}
          </dd>
        </div>
        <div>
          <dt>Blockers</dt>
          <dd>{blockers.length}</dd>
        </div>
        <div>
          <dt>Warnings</dt>
          <dd>{readinessWarnings.length}</dd>
        </div>
      </dl>
      {attentionIssues.length > 0 ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-readiness-attention"
        >
          <h4>Needs attention</h4>
          {attentionIssues.slice(0, 4).map(({ issue, status }, index) => {
            const nodeName = issue.nodeId
              ? workflowNodeName(workflow, issue.nodeId)
              : "Workflow";
            return (
              <button
                key={`${status}-${issue.code}-${issue.nodeId ?? "workflow"}-${index}`}
                type="button"
                className={`workflow-search-result is-${status}`}
                data-testid={`workflow-readiness-attention-${index}`}
                onClick={() => onResolveIssue(issue)}
              >
                <strong>{workflowIssueTitle(issue)}</strong>
                <span>{nodeName}</span>
                <small>{issue.message || issue.code}</small>
                <small>{workflowIssueActionLabel(issue)}</small>
              </button>
            );
          })}
        </section>
      ) : null}
      <div
        className="workflow-rail-list"
        data-testid="workflow-readiness-checklist"
      >
        {readinessItems.map((item) => (
          <article
            key={item.label}
            className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}
          >
            <strong>{item.label}</strong>
            <span>{item.ready ? "Ready" : "Needs attention"}</span>
          </article>
        ))}
      </div>
      {capabilityPreflight ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-readiness-capability-preflight"
          data-preflight-status={capabilityPreflight.status}
          data-source-kind={capabilityPreflight.sourceKind}
          data-row-count={capabilityPreflight.rowCount}
          data-target-node-ids={capabilityPreflight.targetNodeIds.join("|")}
          data-capability-refs={capabilityPreflight.capabilityRefs.join("|")}
          data-binding-kinds={capabilityPreflight.bindingKinds.join("|")}
          data-blocker-reasons={capabilityPreflight.blockerReasons.join("|")}
          data-receipt-refs={capabilityPreflight.receiptRefs.join("|")}
          data-policy-decision-refs={
            capabilityPreflight.policyDecisionRefs.join("|")
          }
        >
          <h4>Capability preflight</h4>
          <button
            type="button"
            className="workflow-search-result is-blocked"
            data-testid="workflow-readiness-capability-preflight-action"
            onClick={() => onResolveIssue(capabilityPreflight.issue)}
          >
            <strong>{workflowIssueTitle(capabilityPreflight.issue)}</strong>
            <span>
              {capabilityPreflight.rowCount} blocked binding
              {capabilityPreflight.rowCount === 1 ? "" : "s"} ·{" "}
              {capabilityPreflight.bindingKinds.join(", ")}
            </span>
            <small>{capabilityPreflight.issue.message}</small>
            <small>{workflowIssueActionLabel(capabilityPreflight.issue)}</small>
          </button>
          <div className="workflow-rail-list">
            {capabilityPreflight.rows.slice(0, 6).map((row) => (
              <article
                key={`${row.nodeId}-${row.capabilityRef}`}
                className="workflow-test-row is-blocked"
                data-testid={`workflow-readiness-capability-preflight-row-${row.nodeId}`}
                data-node-id={row.nodeId}
                data-binding-kind={row.bindingKind}
                data-capability-ref={row.capabilityRef}
                data-route-id={row.routeId ?? ""}
                data-readiness-status={row.readinessStatus}
                data-grant-status={row.grantStatus}
                data-policy-status={row.policyStatus}
                data-receipt-required={row.receiptRequired}
                data-receipt-types={row.receiptTypes.join("|")}
                data-authority-scopes={row.authorityScopes.join("|")}
                data-authority-scope-requirements={row.authorityScopeRequirements.join(
                  "|",
                )}
                data-blocker-reasons={row.blockerReasons.join("|")}
                data-repair-action-kinds={row.repairActions
                  .map((action) => action.kind)
                  .join("|")}
              >
                <strong>{row.nodeName}</strong>
                <span>
                  {row.bindingKind} · {row.mode} · {row.readinessStatus}
                </span>
                <small>{row.capabilityRef}</small>
                <small>
                  grant {row.grantStatus} · policy {row.policyStatus} ·{" "}
                  receipts {row.receiptRequired ? "required" : "missing"}
                </small>
                <small>fail-closed · {row.blockerReasons.join(", ")}</small>
                {row.repairActions.length > 0 ? (
                  <div
                    className="workflow-harness-authority-gate-actions"
                    data-testid={`workflow-readiness-capability-repair-actions-${row.nodeId}`}
                  >
                    {row.repairActions.map((action) => (
                      <button
                        key={action.id}
                        type="button"
                        className="workflow-secondary-action"
                        data-testid={`workflow-readiness-capability-repair-${action.kind}-${row.nodeId}`}
                        data-action-kind={action.kind}
                        data-target-surface={action.targetSurface}
                        data-authority-endpoint={action.authorityEndpoint ?? ""}
                        data-catalog-endpoint={action.catalogEndpoint ?? ""}
                        data-missing-fields={action.missingFields.join("|")}
                        title={action.detail}
                        onClick={() => onCapabilityRepairAction?.(action)}
                      >
                        {action.label}
                      </button>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}
      {codingToolBudgetPreflight ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-readiness-coding-tool-budget-preflight"
          data-preflight-status={codingToolBudgetPreflight.status}
          data-source-kind={codingToolBudgetPreflight.sourceKind}
          data-budget-row-count={codingToolBudgetPreflight.rowCount}
          data-target-node-ids={codingToolBudgetPreflight.targetNodeIds.join("|")}
          data-evidence-workflow-node-ids={
            codingToolBudgetPreflight.evidenceWorkflowNodeIds.join("|")
          }
          data-event-ids={codingToolBudgetPreflight.eventIds.join("|")}
          data-tool-names={codingToolBudgetPreflight.toolNames.join("|")}
          data-tool-call-ids={codingToolBudgetPreflight.toolCallIds.join("|")}
          data-budget-statuses={
            codingToolBudgetPreflight.budgetStatuses.join("|")
          }
          data-context-budget-statuses={
            codingToolBudgetPreflight.contextBudgetStatuses.join("|")
          }
          data-total-tokens={codingToolBudgetPreflight.totalTokens ?? ""}
          data-cost-estimate-usd={
            codingToolBudgetPreflight.costEstimateUsd ?? ""
          }
          data-context-pressure={
            codingToolBudgetPreflight.contextPressure ?? ""
          }
          data-context-pressure-status={
            codingToolBudgetPreflight.contextPressureStatus ?? ""
          }
          data-mutation-blocked={codingToolBudgetPreflight.mutationBlocked}
          data-receipt-refs={codingToolBudgetPreflight.receiptRefs.join("|")}
          data-policy-decision-refs={
            codingToolBudgetPreflight.policyDecisionRefs.join("|")
          }
        >
          <h4>Coding budget preflight</h4>
          <button
            type="button"
            className={`workflow-search-result is-${codingToolBudgetPreflight.status}`}
            data-testid="workflow-readiness-coding-tool-budget-preflight-action"
            onClick={() => onResolveIssue(codingToolBudgetPreflight.issue)}
          >
            <strong>{workflowIssueTitle(codingToolBudgetPreflight.issue)}</strong>
            <span>
              {codingToolBudgetPreflight.toolNames.join(", ") ||
                "coding tool"}{" "}
              · {codingToolBudgetPreflight.rowCount} evidence rows
            </span>
            <small>{codingToolBudgetPreflight.issue.message}</small>
            <small>{workflowIssueActionLabel(codingToolBudgetPreflight.issue)}</small>
          </button>
        </section>
      ) : null}
      <section
        className="workflow-rail-section"
        data-testid="workflow-readiness-scheduler-lanes"
        data-ready-count={schedulerLaneReadyCount}
        data-total-count={schedulerLaneReadiness.length}
      >
        <h4>Scheduler lanes</h4>
        <div className="workflow-rail-list">
          {schedulerLaneReadiness.map((lane) => (
            <article
              key={lane.id}
              className={`workflow-test-row is-${lane.status === "ready" ? "passed" : "blocked"}`}
              data-testid={`workflow-readiness-scheduler-lane-${workflowSchedulerLaneDomId(lane.id)}`}
              data-readiness={lane.status}
              data-proof-check={lane.proofCheckKey}
              data-capability-scope={lane.capabilityScope}
            >
              <strong>{lane.label}</strong>
              <span>
                {lane.status === "ready" ? "Ready" : "Needs attention"}
              </span>
              <small>{lane.capabilityScope}</small>
              <small>{lane.proofCheckKey}</small>
            </article>
          ))}
        </div>
      </section>
      {blockers.length > 0 ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-readiness-blockers"
        >
          <h4>Blockers</h4>
          {blockers.slice(0, 8).map((issue, index) => {
            const nodeName = issue.nodeId
              ? workflowNodeName(workflow, issue.nodeId)
              : "Workflow";
            return (
              <button
                key={`${issue.code ?? "issue"}-${issue.nodeId}-${index}`}
                type="button"
                className="workflow-search-result is-blocked"
                data-testid={`workflow-readiness-blocker-${index}`}
                onClick={() => onResolveIssue(issue)}
              >
                <strong>{workflowIssueTitle(issue)}</strong>
                <span>{nodeName}</span>
                <small>{issue.message || issue.code}</small>
                <small>{workflowIssueActionLabel(issue)}</small>
              </button>
            );
          })}
        </section>
      ) : null}
      {readinessWarnings.length > 0 ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-readiness-warnings"
        >
          <h4>Warnings</h4>
          {readinessWarnings.slice(0, 6).map((issue, index) => (
            <button
              key={`${issue.code}-${index}`}
              type="button"
              className="workflow-search-result is-warning"
              data-testid={`workflow-readiness-warning-${index}`}
              onClick={() => onResolveIssue(issue)}
            >
              <strong>{workflowIssueTitle(issue)}</strong>
              <span>{issue.message}</span>
              <small>{workflowIssueActionLabel(issue)}</small>
            </button>
          ))}
        </section>
      ) : null}
      {policyRequiredNodeIds.length > 0 ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-readiness-policy-nodes"
        >
          <h4>Policy required</h4>
          {policyRequiredNodeIds.slice(0, 6).map((nodeId) => (
            <button
              key={nodeId}
              type="button"
              className="workflow-search-result is-blocked"
              data-testid={`workflow-readiness-policy-node-${nodeId}`}
              onClick={() => {
                onInspectNode(nodeId);
                onConfigureNode();
              }}
            >
              <strong>{workflowNodeName(workflow, nodeId)}</strong>
              <span>Privileged boundary needs an approval or policy gate.</span>
              <small>Open configuration</small>
            </button>
          ))}
        </section>
      ) : null}
      <section
        className="workflow-package-readiness"
        data-testid="workflow-portable-package"
      >
        <h4>Portable package</h4>
        <p>
          Export graph, tests, fixtures, functions, bindings, policies, and
          output definitions for another checkout.
        </p>
        <div className="workflow-package-actions">
          <button
            type="button"
            data-testid="workflow-export-package"
            onClick={onExportPackage}
          >
            Export package
          </button>
          <button
            type="button"
            data-testid="workflow-import-package-open"
            onClick={onOpenImportPackage}
          >
            Import package
          </button>
        </div>
        {portablePackage ? (
          <article
            className={`workflow-test-row is-${portablePackage.manifest.portable ? "passed" : "blocked"}`}
            data-testid="workflow-package-summary"
            data-harness-package-manifest-present={
              portablePackage.manifest.harnessPackageManifest ? "true" : "false"
            }
            data-harness-package-receipt-ref-count={
              portablePackage.manifest.harnessPackageManifest?.receiptRefs
                .length ?? 0
            }
            data-harness-package-replay-fixture-ref-count={
              portablePackage.manifest.harnessPackageManifest?.replayFixtureRefs
                .length ?? 0
            }
            data-harness-package-deep-link-count={
              portablePackage.manifest.harnessPackageManifest?.deepLinks
                .length ?? 0
            }
            data-workflow-chrome-locale={
              portablePackage.manifest.workflowChromeLocale ?? ""
            }
          >
            <strong>
              {portablePackage.manifest.portable
                ? "Portable"
                : "Exported with blockers"}
            </strong>
            <span>
              {portablePackage.manifest.files.length} files, readiness{" "}
              {portablePackage.manifest.readinessStatus}
            </span>
            <small>
              Chrome locale{" "}
              {portablePackage.manifest.workflowChromeLocale ?? "default"}
            </small>
          </article>
        ) : null}
      </section>
    </>
  );
}
