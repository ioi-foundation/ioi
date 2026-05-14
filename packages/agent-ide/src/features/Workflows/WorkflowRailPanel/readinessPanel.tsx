import type {
  WorkflowPortablePackage,
  WorkflowValidationIssue,
} from "../../../types/graph";
import {
  workflowReadinessModel,
  type WorkflowReadinessModelInput,
} from "../../../runtime/workflow-readiness-model";
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
}: WorkflowReadinessPanelProps) {
  const {
    result,
    blockers,
    readinessWarnings,
    policyRequiredNodeIds,
    schedulerLaneReadiness,
    schedulerLaneReadyCount,
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
