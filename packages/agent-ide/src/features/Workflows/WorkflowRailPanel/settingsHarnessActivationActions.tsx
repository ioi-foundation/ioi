import {
  workflowIssueTitle,
  workflowNodeName,
} from "../../../runtime/workflow-rail-model";
import type { WorkflowProject } from "../../../types/graph";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessActivationActionsProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "activationGateProposal"
      | "firstHarnessActivationBlocker"
      | "harnessActivationBlockers"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCheckActivationReadiness"
      | "onResolveIssue"
      | "onRunHarnessActivationDryRun"
      | "onSelectProposal"
    > {
  workflow: WorkflowProject;
}

export function WorkflowSettingsHarnessActivationActions({
  activationGateProposal,
  firstHarnessActivationBlocker,
  harnessActivationBlockers,
  onCheckActivationReadiness,
  onResolveIssue,
  onRunHarnessActivationDryRun,
  onSelectProposal,
  workflow,
}: WorkflowSettingsHarnessActivationActionsProps) {
  return (
    <>
      {harnessActivationBlockers.length > 0 ? (
        <div
          className="workflow-rail-list"
          data-testid="workflow-harness-activation-wizard-blockers"
        >
          {harnessActivationBlockers.slice(0, 5).map((issue, index) => (
            <button
              key={`${issue.code}-${issue.nodeId ?? "workflow"}-${index}`}
              type="button"
              className="workflow-search-result is-blocked"
              data-testid={`workflow-harness-activation-blocker-${index}`}
              onClick={() => onResolveIssue(issue)}
            >
              <strong>{workflowIssueTitle(issue)}</strong>
              <span>{workflowNodeName(workflow, issue.nodeId)}</span>
              <small>{issue.message}</small>
            </button>
          ))}
        </div>
      ) : null}
      <div
        className="workflow-harness-activation-actions"
        data-testid="workflow-harness-activation-actions"
      >
        <button
          type="button"
          data-testid="workflow-harness-activation-dry-run"
          onClick={onRunHarnessActivationDryRun}
        >
          Dry run
        </button>
        <button
          type="button"
          data-testid="workflow-harness-activation-run-readiness"
          onClick={onCheckActivationReadiness}
        >
          Check readiness
        </button>
        <button
          type="button"
          data-testid="workflow-harness-activation-review-proposal"
          disabled={!activationGateProposal}
          onClick={() => {
            if (activationGateProposal) {
              onSelectProposal(activationGateProposal);
            }
          }}
        >
          Review proposal
        </button>
        <button
          type="button"
          data-testid="workflow-harness-activation-first-blocker"
          disabled={!firstHarnessActivationBlocker}
          onClick={() => {
            if (firstHarnessActivationBlocker) {
              onResolveIssue(firstHarnessActivationBlocker);
            }
          }}
        >
          Inspect blocker
        </button>
      </div>
    </>
  );
}
