import type {
  WorkflowCheckpoint,
  WorkflowDogfoodRun,
  WorkflowProject,
  WorkflowRunSummary,
} from "../../../types/graph";
import type { WorkflowRunHistoryModel } from "../../../runtime/workflow-run-history-model";
import type {
  WorkflowRuntimeContextPressureActionDescriptor,
  WorkflowRuntimeDiagnosticsRepairActionDescriptor,
  WorkflowRuntimeWorkspaceTrustActionDescriptor,
} from "../../../runtime/workflow-runtime-event-projection";
import {
  workflowDurationLabel,
  workflowEventLabel,
  workflowNodeName,
  workflowNodeRunChildLineage,
  workflowTimeLabel,
  workflowWorkbenchCheckSummary,
  workflowWorkbenchCheckTitle,
} from "../../../runtime/workflow-rail-model";

type WorkflowRunsPanelProps = {
  workflow: WorkflowProject;
  model: WorkflowRunHistoryModel;
  runSearchQuery: string;
  runStatusFilter: string;
  checkpoints: WorkflowCheckpoint[];
  dogfoodRun: WorkflowDogfoodRun | null;
  accessibleStatusLabel: (status: unknown) => string;
  onRunSearchQueryChange: (query: string) => void;
  onRunStatusFilterChange: (status: string) => void;
  onOpenExecutions?: () => void;
  onSelectRun: (run: WorkflowRunSummary) => void;
  onCompareRun: (run: WorkflowRunSummary) => void;
  onInspectNode: (nodeId: string) => void;
  onExecuteRuntimeDiagnosticsRepair?: (
    action: WorkflowRuntimeDiagnosticsRepairActionDescriptor,
  ) => void | Promise<void>;
  onExecuteRuntimeContextPressureAction?: (
    action: WorkflowRuntimeContextPressureActionDescriptor,
  ) => void | Promise<void>;
  onExecuteRuntimeWorkspaceTrustAction?: (
    action: WorkflowRuntimeWorkspaceTrustActionDescriptor,
  ) => void | Promise<void>;
};

export function WorkflowRunsPanel({
  workflow,
  model,
  runSearchQuery,
  runStatusFilter,
  checkpoints,
  dogfoodRun,
  accessibleStatusLabel,
  onRunSearchQueryChange,
  onRunStatusFilterChange,
  onOpenExecutions,
  onSelectRun,
  onCompareRun,
  onInspectNode,
  onExecuteRuntimeDiagnosticsRepair,
  onExecuteRuntimeContextPressureAction,
  onExecuteRuntimeWorkspaceTrustAction,
}: WorkflowRunsPanelProps) {
  const {
    totalRuns,
    filteredRuns,
    visibleRows,
    runStatuses,
    statusCounts,
    selectedRun,
    comparison,
    defaultCompareRun,
    interrupt,
    interruptPreview,
    harnessAttempts,
    harnessComparisons,
    timelineEvents,
    runtimeEventProjection,
    runtimePolicyStack,
    runtimeEditProposalPolicyStack,
    tuiControlStateProjection,
  } = model;

  return (
    <>
      <h3>Runs</h3>
      <p>
        {totalRuns === 0
          ? "No runs yet."
          : `Showing ${visibleRows.length} of ${filteredRuns.length} matching runs. Select one to inspect attempts and state changes.`}
      </p>
      {onOpenExecutions ? (
        <button
          type="button"
          className="workflow-secondary-action"
          data-testid="workflow-open-executions"
          onClick={onOpenExecutions}
        >
          Open Executions
        </button>
      ) : null}
      {totalRuns > 0 ? (
        <div className="workflow-run-filters" data-testid="workflow-run-filters">
          <input
            data-testid="workflow-run-search-input"
            placeholder="Search runs..."
            value={runSearchQuery}
            onChange={(event) => onRunSearchQueryChange(event.target.value)}
          />
          <div
            className="workflow-node-group-filter"
            data-testid="workflow-run-status-filter"
          >
            {["all", ...runStatuses].map((status) => (
              <button
                key={status}
                type="button"
                className={runStatusFilter === status ? "is-active" : ""}
                data-testid={`workflow-run-status-${status}`}
                aria-label={
                  status === "all"
                    ? "Filter runs by all statuses"
                    : `Filter runs by ${accessibleStatusLabel(status)}`
                }
                onClick={() => onRunStatusFilterChange(status)}
              >
                {status === "all" ? status : accessibleStatusLabel(status)}
                <small>
                  {status === "all"
                    ? totalRuns
                    : (statusCounts as Record<string, number | undefined>)[
                        status
                      ] ?? 0}
                </small>
              </button>
            ))}
          </div>
        </div>
      ) : null}
      <div className="workflow-run-list" data-testid="workflow-runs-list">
        {visibleRows.map(({ run, selected, compare }) => (
          <button
            key={run.id}
            type="button"
            className={`workflow-run-card is-${run.status} ${selected ? "is-active" : ""} ${compare ? "is-compare" : ""}`}
            data-testid={`workflow-run-${run.id}`}
            data-accessible-status={run.status}
            data-accessible-status-text={accessibleStatusLabel(run.status)}
            aria-label={`Run ${accessibleStatusLabel(run.status)}: ${run.summary}`}
            onClick={() => onSelectRun(run)}
          >
            <strong>{accessibleStatusLabel(run.status)}</strong>
            <span>{run.summary}</span>
            <small>
              {workflowDurationLabel(run.startedAtMs, run.finishedAtMs)} ·{" "}
              {run.checkpointCount ?? 0} checkpoints
            </small>
          </button>
        ))}
        {totalRuns > 0 && visibleRows.length === 0 ? (
          <article
            className="workflow-output-row"
            data-testid="workflow-runs-empty-filtered"
          >
            <strong>No matching runs</strong>
            <span>
              Adjust the status filter or search by run summary, status, or id.
            </span>
          </article>
        ) : null}
      </div>
      {selectedRun && defaultCompareRun ? (
        <button
          type="button"
          className="workflow-secondary-action"
          data-testid="workflow-compare-run"
          onClick={() => onCompareRun(defaultCompareRun)}
        >
          Compare with previous run
        </button>
      ) : null}
      {comparison ? (
        <article
          className="workflow-run-comparison"
          data-testid="workflow-run-compare"
        >
          <strong>Run comparison</strong>
          <span>
            {comparison.baselineStatus} to {comparison.targetStatus} ·{" "}
            {comparison.changedNodes.length} node changes
          </span>
          <dl>
            <div>
              <dt>Duration</dt>
              <dd>
                {comparison.durationDeltaMs === null
                  ? "running"
                  : `${comparison.durationDeltaMs >= 0 ? "+" : ""}${comparison.durationDeltaMs} ms`}
              </dd>
            </div>
            <div>
              <dt>Checkpoints</dt>
              <dd>
                {comparison.checkpointDelta >= 0 ? "+" : ""}
                {comparison.checkpointDelta}
              </dd>
            </div>
            <div>
              <dt>Events</dt>
              <dd>
                {comparison.eventDelta >= 0 ? "+" : ""}
                {comparison.eventDelta}
              </dd>
            </div>
            <div>
              <dt>State</dt>
              <dd>{comparison.stateChanges.length} changes</dd>
            </div>
          </dl>
          {comparison.changedNodes.slice(0, 5).map((change) => (
            <button
              key={change.nodeId}
              type="button"
              className="workflow-run-comparison-node"
              data-testid={`workflow-run-compare-node-${change.nodeId}`}
              onClick={() => onInspectNode(change.nodeId)}
            >
              <strong>{change.nodeName}</strong>
              <span>
                {change.before}
                {" -> "}
                {change.after}
              </span>
              <small>
                {change.inputChanged ? "input changed" : "input stable"}
                {" · "}
                {change.outputChanged ? "output changed" : "output stable"}
                {change.errorChanged ? " · error changed" : ""}
              </small>
            </button>
          ))}
        </article>
      ) : null}
      {interrupt ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-run-interrupt"
        >
          <strong>Paused at human input</strong>
          <span>{interrupt.prompt}</span>
          {interruptPreview?.binding ? (
            <small data-testid="workflow-interrupt-preview">
              {interruptPreview.binding.bindingKind ?? "action"} ·{" "}
              {interruptPreview.binding.ref ?? "configured node"} ·{" "}
              {interruptPreview.binding.sideEffectClass ?? "side effect"}
            </small>
          ) : null}
        </article>
      ) : null}
      {selectedRun ? (
        <div className="workflow-run-inspector" data-testid="workflow-run-inspector">
          <h4>Attempts</h4>
          {selectedRun.nodeRuns.slice(0, 8).map((nodeRun) => {
            const childLineage = workflowNodeRunChildLineage(nodeRun);
            return (
              <button
                key={`${nodeRun.nodeId}-${nodeRun.attempt}-${nodeRun.startedAtMs}`}
                type="button"
                className={`workflow-run-attempt is-${nodeRun.status}`}
                data-testid={`workflow-run-attempt-${nodeRun.nodeId}`}
                data-accessible-status={nodeRun.status}
                data-accessible-status-text={accessibleStatusLabel(nodeRun.status)}
                aria-label={`${workflowNodeName(workflow, nodeRun.nodeId)} ${accessibleStatusLabel(nodeRun.status)} attempt ${nodeRun.attempt}`}
                onClick={() => onInspectNode(nodeRun.nodeId)}
              >
                <strong>{workflowNodeName(workflow, nodeRun.nodeId)}</strong>
                <span>
                  {nodeRun.status} · attempt {nodeRun.attempt}
                </span>
                <small>
                  {workflowDurationLabel(
                    nodeRun.startedAtMs,
                    nodeRun.finishedAtMs,
                  )}
                  {" · "}
                  {nodeRun.input === undefined
                    ? "input not captured"
                    : "input captured"}
                </small>
                <small
                  className="workflow-run-lifecycle"
                  data-testid="workflow-run-attempt-lifecycle"
                >
                  {(nodeRun.lifecycle?.length ?? 0) > 0
                    ? `${nodeRun.lifecycle?.length} run steps`
                    : "run steps pending"}
                  {nodeRun.checkpointId ? ` · checkpoint saved` : ""}
                </small>
                {childLineage ? (
                  <small
                    className="workflow-run-child-lineage"
                    data-testid="workflow-run-child-lineage"
                    data-node-id={nodeRun.nodeId}
                  >
                    Child run {childLineage.childRunStatus} ·{" "}
                    {childLineage.childRunId}
                  </small>
                ) : null}
                {nodeRun.harnessAttempt ? (
                  <small data-testid="workflow-run-harness-attempt">
                    {nodeRun.harnessAttempt.executionMode} ·{" "}
                    {nodeRun.harnessAttempt.readiness} ·{" "}
                    {nodeRun.harnessAttempt.replay.determinism}
                  </small>
                ) : null}
              </button>
            );
          })}
          {runtimeEventProjection.eventCount > 0 ? (
            <section
              className="workflow-run-runtime-event-graph"
              data-testid="workflow-run-runtime-event-graph"
              data-schema-version={runtimeEventProjection.schemaVersion}
              data-event-count={runtimeEventProjection.eventCount}
              data-latest-event-id={runtimeEventProjection.latestEventId ?? ""}
              data-latest-cursor={runtimeEventProjection.latestCursor ?? ""}
            >
              <h4>Runtime event graph</h4>
              <div
                className="workflow-run-runtime-event-summary"
                data-testid="workflow-run-runtime-event-summary"
              >
                <span>{runtimeEventProjection.eventCount} events</span>
                <span>{runtimeEventProjection.reactFlowNodes.length} nodes</span>
                <span>{runtimeEventProjection.reactFlowEdges.length} edges</span>
              </div>
              {runtimePolicyStack.status !== "not_required" ? (
                <ol
                  className="workflow-run-policy-stack"
                  data-testid="workflow-run-policy-stack"
                  data-schema-version={runtimePolicyStack.schemaVersion}
                  data-policy-stack-status={runtimePolicyStack.status}
                  data-policy-stack-stage-count={
                    runtimePolicyStack.stages.length
                  }
                  data-approval-id={runtimePolicyStack.approvalId ?? ""}
                  data-warning-id={runtimePolicyStack.warningId ?? ""}
                  data-tool-call-id={runtimePolicyStack.toolCallId ?? ""}
                  data-receipt-refs={runtimePolicyStack.receiptRefs.join("|")}
                  data-policy-decision-refs={
                    runtimePolicyStack.policyDecisionRefs.join("|")
                  }
                >
                  {runtimePolicyStack.stages.map((stage) => (
                    <li
                      key={stage.kind}
                      className={`workflow-run-policy-stack-stage is-${stage.status}`}
                      data-testid={`workflow-run-policy-stack-stage-${stage.kind}`}
                      data-stage-kind={stage.kind}
                      data-stage-status={stage.status}
                      data-event-id={stage.eventId ?? ""}
                      data-event-seq={stage.eventSeq ?? ""}
                      data-thread-id={stage.threadId ?? ""}
                      data-workflow-graph-id={stage.workflowGraphId ?? ""}
                      data-workflow-node-id={stage.workflowNodeId ?? ""}
                      data-approval-id={stage.approvalId ?? ""}
                      data-warning-id={stage.warningId ?? ""}
                      data-tool-call-id={stage.toolCallId ?? ""}
                      data-receipt-refs={stage.receiptRefs.join("|")}
                      data-policy-decision-refs={
                        stage.policyDecisionRefs.join("|")
                      }
                    >
                      <span>{stage.label}</span>
                      <small>{accessibleStatusLabel(stage.status)}</small>
                    </li>
                  ))}
                </ol>
              ) : null}
              {runtimeEditProposalPolicyStack.status !== "not_required" ? (
                <ol
                  className="workflow-run-policy-stack workflow-run-edit-proposal-policy-stack"
                  data-testid="workflow-run-edit-proposal-policy-stack"
                  data-schema-version={
                    runtimeEditProposalPolicyStack.schemaVersion
                  }
                  data-policy-stack-status={
                    runtimeEditProposalPolicyStack.status
                  }
                  data-policy-stack-stage-count={
                    runtimeEditProposalPolicyStack.stages.length
                  }
                  data-proposal-id={
                    runtimeEditProposalPolicyStack.proposalId ?? ""
                  }
                  data-approval-id={
                    runtimeEditProposalPolicyStack.approvalId ?? ""
                  }
                  data-target-workflow-node-ids={
                    runtimeEditProposalPolicyStack.targetWorkflowNodeIds.join("|")
                  }
                  data-mutation-executed={
                    runtimeEditProposalPolicyStack.mutationExecuted
                  }
                  data-receipt-refs={
                    runtimeEditProposalPolicyStack.receiptRefs.join("|")
                  }
                  data-policy-decision-refs={
                    runtimeEditProposalPolicyStack.policyDecisionRefs.join("|")
                  }
                >
                  {runtimeEditProposalPolicyStack.stages.map((stage) => (
                    <li
                      key={stage.kind}
                      className={`workflow-run-policy-stack-stage is-${stage.status}`}
                      data-testid={`workflow-run-edit-proposal-policy-stack-stage-${stage.kind}`}
                      data-stage-kind={stage.kind}
                      data-stage-status={stage.status}
                      data-event-id={stage.eventId ?? ""}
                      data-event-seq={stage.eventSeq ?? ""}
                      data-thread-id={stage.threadId ?? ""}
                      data-workflow-graph-id={stage.workflowGraphId ?? ""}
                      data-workflow-node-id={stage.workflowNodeId ?? ""}
                      data-proposal-id={stage.proposalId ?? ""}
                      data-approval-id={stage.approvalId ?? ""}
                      data-receipt-refs={stage.receiptRefs.join("|")}
                      data-policy-decision-refs={
                        stage.policyDecisionRefs.join("|")
                      }
                    >
                      <span>{stage.label}</span>
                      <small>{accessibleStatusLabel(stage.status)}</small>
                    </li>
                  ))}
                </ol>
              ) : null}
              <ol
                className="workflow-run-runtime-event-nodes"
                data-testid="workflow-run-runtime-event-nodes"
              >
                {runtimeEventProjection.reactFlowNodes.slice(0, 8).map((node) => (
                  <li
                    key={node.id}
                    className={`workflow-run-runtime-event-node is-${node.data.status}`}
                    data-testid={`workflow-run-runtime-event-node-${node.id}`}
                    data-react-flow-node-id={node.id}
                    data-node-kind={node.data.nodeKind}
                    data-workflow-node-id={node.data.workflowNodeId}
                    data-workflow-graph-id={node.data.workflowGraphId ?? ""}
                    data-component-kind={node.data.componentKind}
                    data-thread-id={node.data.threadId}
                    data-accessible-status={node.data.status}
                    data-accessible-status-text={accessibleStatusLabel(
                      node.data.status,
                    )}
                    data-event-id={node.data.latestEventId}
                    data-event-ids={node.data.eventIds.join("|")}
                    data-event-cursor={node.data.latestCursor}
                    data-latest-seq={node.data.latestSeq}
                    data-receipt-refs={node.data.receiptRefs.join("|")}
                    data-artifact-refs={node.data.artifactRefs.join("|")}
                    data-policy-decision-refs={node.data.policyDecisionRefs.join("|")}
                    data-rollback-refs={node.data.rollbackRefs.join("|")}
                    data-diagnostics-repair-action-count={
                      node.data.diagnosticsRepairActions.length
                    }
                    data-context-pressure-action-count={
                      node.data.contextPressureActions.length
                    }
                    data-workspace-trust-action-count={
                      node.data.workspaceTrustActions.length
                    }
                    data-tool-name={node.data.toolName ?? ""}
                    data-approval-id={node.data.approvalId ?? ""}
                    data-tui-deep-link-schema-version={
                      node.data.tuiDeepLink.schemaVersion
                    }
                    data-tui-reopen-command={node.data.tuiDeepLink.reopenCommand}
                    data-tui-reopen-args={node.data.tuiDeepLink.args.join("|")}
                    data-tui-since-seq={node.data.tuiDeepLink.sinceSeq}
                    data-tui-last-event-id={node.data.tuiDeepLink.lastEventId}
                  >
                    <details>
                      <summary
                        aria-label={`${node.data.label} ${accessibleStatusLabel(
                          node.data.status,
                        )} runtime event node`}
                      >
                        <strong>{node.data.label}</strong>
                        <span>
                          {node.data.componentKind} ·{" "}
                          {accessibleStatusLabel(node.data.status)}
                        </span>
                        <small>{node.data.latestCursor}</small>
                      </summary>
                      <dl>
                        <div>
                          <dt>Event</dt>
                          <dd>{node.data.latestEventId}</dd>
                        </div>
                        <div>
                          <dt>Seq</dt>
                          <dd>
                            {node.data.firstSeq} {"->"} {node.data.latestSeq}
                          </dd>
                        </div>
                        <div>
                          <dt>Turn</dt>
                          <dd>{node.data.turnIds.join(", ") || "none"}</dd>
                        </div>
                        <div>
                          <dt>Evidence</dt>
                          <dd>
                            {node.data.receiptRefs.length} receipts ·{" "}
                            {node.data.artifactRefs.length} artifacts ·{" "}
                            {node.data.policyDecisionRefs.length} policies
                          </dd>
                        </div>
                        <div>
                          <dt>Runtime kind</dt>
                          <dd>{node.data.eventKinds.join(", ")}</dd>
                        </div>
                        <div>
                          <dt>TUI</dt>
                          <dd data-testid="workflow-run-runtime-event-tui-reopen">
                            {node.data.tuiDeepLink.reopenCommand}
                          </dd>
                        </div>
                      </dl>
                      {node.data.diagnosticsRepairActions.length > 0 ? (
                        <div
                          className="workflow-run-diagnostics-repair-actions"
                          data-testid={`workflow-run-diagnostics-repair-actions-${node.id}`}
                          data-action-count={
                            node.data.diagnosticsRepairActions.length
                          }
                        >
                          {node.data.diagnosticsRepairActions.map((action) => (
                            <button
                              key={action.id}
                              type="button"
                              className="workflow-secondary-action"
                              data-testid={`workflow-run-diagnostics-repair-action-${action.action}`}
                              data-action-id={action.id}
                              data-action={action.action}
                              data-decision-id={action.decisionId}
                              data-thread-id={action.threadId}
                              data-workflow-graph-id={
                                action.workflowGraphId ?? ""
                              }
                              data-workflow-node-id={action.workflowNodeId}
                              data-requires-approval={action.requiresApproval}
                              data-approval-granted={action.approvalGranted}
                              data-allow-conflicts={action.allowConflicts}
                              data-executable={action.executable}
                              title={action.summary ?? action.label}
                              aria-label={`${action.label} diagnostics repair decision`}
                              disabled={
                                !action.executable ||
                                !onExecuteRuntimeDiagnosticsRepair
                              }
                              onClick={() => {
                                void onExecuteRuntimeDiagnosticsRepair?.(action);
                              }}
                            >
                              {action.label}
                            </button>
                          ))}
                        </div>
                      ) : null}
                      {node.data.contextPressureActions.length > 0 ? (
                        <div
                          className="workflow-run-context-pressure-actions"
                          data-testid={`workflow-run-context-pressure-actions-${node.id}`}
                          data-action-count={
                            node.data.contextPressureActions.length
                          }
                        >
                          {node.data.contextPressureActions.map((action) => (
                            <button
                              key={action.id}
                              type="button"
                              className="workflow-secondary-action"
                              data-testid={`workflow-run-context-pressure-action-${action.action}`}
                              data-action-id={action.id}
                              data-action={action.action}
                              data-action-status={action.status}
                              data-scope={action.scope}
                              data-pressure={action.pressure ?? ""}
                              data-pressure-status={action.pressureStatus ?? ""}
                              data-thread-id={action.threadId}
                              data-turn-id={action.turnId ?? ""}
                              data-workflow-graph-id={
                                action.workflowGraphId ?? ""
                              }
                              data-workflow-node-id={action.workflowNodeId}
                              data-source-event-id={action.sourceEventId ?? ""}
                              data-event-id={action.eventId}
                              data-executable={action.executable}
                              title={action.summary ?? action.label}
                              aria-label={`${action.label} context pressure action`}
                              disabled={
                                !action.executable ||
                                !onExecuteRuntimeContextPressureAction
                              }
                              onClick={() => {
                                void onExecuteRuntimeContextPressureAction?.(
                                  action,
                                );
                              }}
                            >
                              {action.label}
                            </button>
                          ))}
                        </div>
                      ) : null}
                      {node.data.workspaceTrustActions.length > 0 ? (
                        <div
                          className="workflow-run-workspace-trust-actions"
                          data-testid={`workflow-run-workspace-trust-actions-${node.id}`}
                          data-action-count={
                            node.data.workspaceTrustActions.length
                          }
                        >
                          {node.data.workspaceTrustActions.map((action) => (
                            <button
                              key={action.id}
                              type="button"
                              className="workflow-secondary-action"
                              data-testid={`workflow-run-workspace-trust-action-${action.action}`}
                              data-action-id={action.id}
                              data-action={action.action}
                              data-action-status={action.status}
                              data-warning-id={action.warningId}
                              data-severity={action.severity ?? ""}
                              data-mode={action.mode ?? ""}
                              data-approval-mode={action.approvalMode ?? ""}
                              data-thread-id={action.threadId}
                              data-workflow-graph-id={
                                action.workflowGraphId ?? ""
                              }
                              data-workflow-node-id={action.workflowNodeId}
                              data-source-event-id={action.sourceEventId ?? ""}
                              data-event-id={action.eventId}
                              data-executable={action.executable}
                              title={action.summary ?? action.label}
                              aria-label={`${action.label} workspace trust action`}
                              disabled={
                                !action.executable ||
                                !onExecuteRuntimeWorkspaceTrustAction
                              }
                              onClick={() => {
                                void onExecuteRuntimeWorkspaceTrustAction?.(
                                  action,
                                );
                              }}
                            >
                              {action.label}
                            </button>
                          ))}
                        </div>
                      ) : null}
                    </details>
                  </li>
                ))}
              </ol>
              {runtimeEventProjection.reactFlowEdges.length > 0 ? (
                <ol
                  className="workflow-run-runtime-event-edges"
                  data-testid="workflow-run-runtime-event-edges"
                >
                  {runtimeEventProjection.reactFlowEdges
                    .slice(0, 8)
                    .map((edge) => (
                      <li
                        key={edge.id}
                        className="workflow-run-runtime-event-edge"
                        data-testid={`workflow-run-runtime-event-edge-${edge.id}`}
                        data-react-flow-edge-id={edge.id}
                        data-source-node-id={edge.source}
                        data-target-node-id={edge.target}
                        data-event-ids={edge.data.eventIds.join("|")}
                      >
                        <span>
                          {edge.source} {"->"} {edge.target}
                        </span>
                        <small>
                          seq {edge.data.sourceLatestSeq} {"->"}{" "}
                          {edge.data.targetFirstSeq}
                        </small>
                      </li>
                    ))}
                </ol>
              ) : null}
            </section>
          ) : null}
          {tuiControlStateProjection.rowCount > 0 ? (
            <section
              className="workflow-run-tui-control-state"
              data-testid="workflow-run-tui-control-state"
              data-schema-version={tuiControlStateProjection.schemaVersion}
              data-source-schema-version={
                tuiControlStateProjection.sourceSchemaVersion ?? ""
              }
              data-thread-id={tuiControlStateProjection.threadId ?? ""}
              data-current-turn-id={
                tuiControlStateProjection.currentTurnId ?? ""
              }
              data-last-cursor={tuiControlStateProjection.lastCursor ?? ""}
              data-last-event-id={tuiControlStateProjection.lastEventId ?? ""}
              data-command-count={tuiControlStateProjection.commandCount}
              data-validation-error-count={
                tuiControlStateProjection.validationErrorCount
              }
              data-approval-count={tuiControlStateProjection.approvalCount}
              data-approval-decision-count={
                tuiControlStateProjection.approvalDecisionCount
              }
              data-job-count={tuiControlStateProjection.jobCount}
              data-run-lifecycle-count={
                tuiControlStateProjection.runLifecycleCount
              }
              data-mcp-row-count={tuiControlStateProjection.mcpRowCount}
              data-memory-row-count={tuiControlStateProjection.memoryRowCount}
              data-usage-row-count={tuiControlStateProjection.usageRowCount}
              data-subagent-row-count={tuiControlStateProjection.subagentRowCount}
              data-subagent-child-subflow-count={
                tuiControlStateProjection.subagentChildSubflowCount
              }
              data-subagent-child-subflow-node-count={
                tuiControlStateProjection.subagentChildSubflowReactFlowNodes.length
              }
              data-subagent-child-subflow-edge-count={
                tuiControlStateProjection.subagentChildSubflowReactFlowEdges.length
              }
            >
              <h4>TUI control state</h4>
              <div
                className="workflow-run-runtime-event-summary"
                data-testid="workflow-run-tui-control-state-summary"
              >
                <span>{tuiControlStateProjection.commandCount} commands</span>
                <span>
                  {tuiControlStateProjection.validationErrorCount} validation
                </span>
                <span>{tuiControlStateProjection.approvalCount} approvals</span>
                <span>{tuiControlStateProjection.jobCount} jobs</span>
                <span>
                  {tuiControlStateProjection.runLifecycleCount} run lifecycles
                </span>
                <span>{tuiControlStateProjection.mcpRowCount} MCP</span>
                <span>{tuiControlStateProjection.memoryRowCount} memory</span>
                <span>{tuiControlStateProjection.usageRowCount} usage</span>
                <span>{tuiControlStateProjection.subagentRowCount} subagents</span>
                <span>
                  {tuiControlStateProjection.subagentChildSubflowCount} child
                  subflows
                </span>
                <span>
                  {tuiControlStateProjection.currentTurnId ?? "no active turn"}
                </span>
              </div>
              <ol
                className="workflow-run-tui-control-state-rows"
                data-testid="workflow-run-tui-control-state-rows"
              >
                {tuiControlStateProjection.rows.slice(-8).map((row) => (
                  <li
                    key={row.id}
                    className={`workflow-run-tui-control-state-row is-${row.status}`}
                    data-testid={`workflow-run-tui-control-state-row-${row.id}`}
                    data-row-kind={row.rowKind}
                    data-row-status={row.status}
                    data-command={row.command ?? ""}
                    data-raw-input={row.rawInput ?? ""}
                    data-approval-id={row.approvalId ?? ""}
                    data-job-id={row.jobId ?? ""}
                    data-run-id={row.runId ?? ""}
                    data-model-id={row.modelId ?? ""}
                    data-mcp-server-id={row.mcpServerId ?? ""}
                    data-mcp-tool-name={row.mcpToolName ?? ""}
                    data-mcp-tool-call-id={row.mcpToolCallId ?? ""}
                    data-mcp-operation={row.mcpOperation ?? ""}
                    data-memory-record-id={row.memoryRecordId ?? ""}
                    data-memory-scope={row.memoryScope ?? ""}
                    data-memory-key={row.memoryKey ?? ""}
                    data-memory-operation={row.memoryOperation ?? ""}
                    data-usage-scope={row.usageScope ?? ""}
                    data-usage-total-tokens={row.usageTotalTokens ?? ""}
                    data-usage-input-tokens={row.usageInputTokens ?? ""}
                    data-usage-output-tokens={row.usageOutputTokens ?? ""}
                    data-usage-cost-estimate-usd={
                      row.usageCostEstimateUsd ?? ""
                    }
                    data-usage-context-pressure={
                      row.usageContextPressure ?? ""
                    }
                    data-usage-context-pressure-status={
                      row.usageContextPressureStatus ?? ""
                    }
                    data-usage-run-count={row.usageRunCount ?? ""}
                    data-usage-subagent-count={row.usageSubagentCount ?? ""}
                    data-subagent-id={row.subagentId ?? ""}
                    data-subagent-role={row.subagentRole ?? ""}
                    data-subagent-operation={row.subagentOperation ?? ""}
                    data-subagent-lifecycle-status={
                      row.subagentLifecycleStatus ?? ""
                    }
                    data-subagent-output-contract-status={
                      row.subagentOutputContractStatus ?? ""
                    }
                    data-subagent-cancellation-inheritance={
                      row.subagentCancellationInheritance ?? ""
                    }
                    data-subagent-merge-policy={row.subagentMergePolicy ?? ""}
                    data-subagent-tool-pack={row.subagentToolPack ?? ""}
                    data-subagent-budget-status={
                      row.subagentBudgetStatus ?? ""
                    }
                    data-subagent-cost-estimate-usd={
                      row.subagentCostEstimateUsd ?? ""
                    }
                    data-subagent-token-estimate={
                      row.subagentTokenEstimate ?? ""
                    }
                    data-subagent-run-id={row.subagentRunId ?? ""}
                    data-subagent-child-thread-id={
                      row.subagentChildThreadId ?? ""
                    }
                    data-route-id={row.routeId ?? ""}
                    data-reasoning-effort={row.reasoningEffort ?? ""}
                    data-thread-id={row.threadId ?? ""}
                    data-turn-id={row.turnId ?? ""}
                    data-workflow-graph-id={row.workflowGraphId ?? ""}
                    data-cursor={row.cursor ?? ""}
                    data-event-id={row.eventId ?? ""}
                    data-receipt-refs={row.receiptRefs.join("|")}
                    data-policy-decision-refs={row.policyDecisionRefs.join("|")}
                    data-react-flow-node-id={row.reactFlowNodeId}
                    data-sequence={row.sequence ?? ""}
                    tabIndex={0}
                    aria-label={`${row.label} ${accessibleStatusLabel(row.status)}`}
                  >
                    <strong>{row.label}</strong>
                    <span>
                      {row.message ??
                        row.rawInput ??
                        row.cursor ??
                        row.threadId ??
                        "state captured"}
                    </span>
                    <small>
                      {row.cursor ?? "cursor pending"}
                      {row.turnId ? ` · ${row.turnId}` : ""}
                    </small>
                  </li>
                ))}
              </ol>
              {tuiControlStateProjection.subagentChildSubflowCount > 0 ? (
                <ol
                  className="workflow-run-subagent-subflows"
                  data-testid="workflow-run-subagent-subflows"
                >
                  {tuiControlStateProjection.subagentChildSubflows.map(
                    (subflow) => (
                      <li
                        key={subflow.id}
                        className={`workflow-run-subagent-subflow is-${subflow.subagentLifecycleStatus ?? "unknown"}`}
                        data-testid={`workflow-run-subagent-subflow-${subflow.id}`}
                        data-subflow-id={subflow.id}
                        data-parent-react-flow-node-id={
                          subflow.parentReactFlowNodeId
                        }
                        data-child-react-flow-node-id={
                          subflow.childReactFlowNodeId
                        }
                        data-child-run-react-flow-node-id={
                          subflow.childRunReactFlowNodeId ?? ""
                        }
                        data-workflow-graph-id={subflow.workflowGraphId ?? ""}
                        data-subagent-id={subflow.subagentId ?? ""}
                        data-subagent-role={subflow.subagentRole ?? ""}
                        data-subagent-operation={
                          subflow.subagentOperation ?? ""
                        }
                        data-subagent-budget-status={
                          subflow.subagentBudgetStatus ?? ""
                        }
                        data-subagent-cost-estimate-usd={
                          subflow.subagentCostEstimateUsd ?? ""
                        }
                        data-subagent-token-estimate={
                          subflow.subagentTokenEstimate ?? ""
                        }
                        data-child-thread-id={subflow.childThreadId}
                        data-child-run-id={subflow.childRunId ?? ""}
                        data-react-flow-edge-count={
                          subflow.reactFlowEdges.length
                        }
                      >
                        <details>
                          <summary>
                            <strong>{subflow.label}</strong>
                            <span>{subflow.childThreadId}</span>
                            <small>
                              {subflow.childRunId ?? "child run pending"}
                            </small>
                          </summary>
                          <dl>
                            <div>
                              <dt>Parent node</dt>
                              <dd>{subflow.parentReactFlowNodeId}</dd>
                            </div>
                            <div>
                              <dt>Graph</dt>
                              <dd>{subflow.workflowGraphId ?? "unscoped"}</dd>
                            </div>
                            <div>
                              <dt>Lifecycle</dt>
                              <dd>
                                {subflow.subagentLifecycleStatus ?? "unknown"}
                              </dd>
                            </div>
                            <div>
                              <dt>Budget</dt>
                              <dd>{subflow.subagentBudgetStatus ?? "untracked"}</dd>
                            </div>
                            <div>
                              <dt>Tokens</dt>
                              <dd>{subflow.subagentTokenEstimate ?? "unknown"}</dd>
                            </div>
                            <div>
                              <dt>Cost</dt>
                              <dd>
                                {subflow.subagentCostEstimateUsd == null
                                  ? "unknown"
                                  : `$${subflow.subagentCostEstimateUsd.toFixed(6)}`}
                              </dd>
                            </div>
                            <div>
                              <dt>Merge</dt>
                              <dd>{subflow.subagentMergePolicy ?? "default"}</dd>
                            </div>
                            <div>
                              <dt>Cancellation</dt>
                              <dd>
                                {subflow.subagentCancellationInheritance ??
                                  "default"}
                              </dd>
                            </div>
                            <div>
                              <dt>Edges</dt>
                              <dd>{subflow.reactFlowEdges.length}</dd>
                            </div>
                          </dl>
                        </details>
                      </li>
                    ),
                  )}
                </ol>
              ) : null}
            </section>
          ) : null}
          {harnessAttempts.length > 0 ? (
            <>
              <h4>Harness timeline</h4>
              <ol
                className="workflow-run-timeline"
                data-testid="workflow-run-harness-timeline"
              >
                {harnessAttempts.slice(-10).map((attempt) => (
                  <li
                    key={attempt.attemptId}
                    className={`is-${attempt.status}`}
                    tabIndex={0}
                    data-testid={`workflow-run-harness-timeline-node-${attempt.attemptId}`}
                    data-node-attempt-id={attempt.attemptId}
                    data-workflow-node-id={attempt.workflowNodeId}
                    data-component-kind={attempt.componentKind}
                    data-component-id={attempt.componentId}
                    data-harness-workflow-id={attempt.harnessWorkflowId}
                    data-harness-activation-id={attempt.harnessActivationId}
                    data-harness-hash={attempt.harnessHash}
                    data-execution-mode={attempt.executionMode}
                    data-readiness={attempt.readiness}
                    data-status={attempt.status}
                    data-accessible-status={attempt.status}
                    data-accessible-status-text={accessibleStatusLabel(attempt.status)}
                    data-policy-decision={attempt.policyDecision ?? ""}
                    data-receipt-refs={attempt.receiptIds.join("|")}
                    data-replay-fixture-ref={attempt.replay.fixtureRef ?? ""}
                    data-input-hash={attempt.inputHash ?? ""}
                    data-output-hash={attempt.outputHash ?? ""}
                    aria-label={`${workflowNodeName(workflow, attempt.workflowNodeId)} ${accessibleStatusLabel(attempt.status)} harness attempt`}
                  >
                    <strong>
                      {workflowNodeName(workflow, attempt.workflowNodeId)}
                    </strong>
                    <span>
                      {attempt.executionMode} · {attempt.readiness} ·{" "}
                      {attempt.replay.determinism}
                    </span>
                    <small>
                      {attempt.receiptIds.length} receipts ·{" "}
                      {attempt.replay.redactionPolicy}
                    </small>
                  </li>
                ))}
              </ol>
            </>
          ) : null}
          {harnessComparisons.length > 0 ? (
            <>
              <h4>Live vs shadow</h4>
              <ol
                className="workflow-run-timeline"
                data-testid="workflow-run-harness-shadow-comparison"
              >
                {harnessComparisons.slice(-6).map((comparisonItem) => (
                  <li
                    key={`${comparisonItem.liveAttemptId}-${comparisonItem.shadowAttemptId}`}
                    className={`is-${comparisonItem.divergence}`}
                    tabIndex={0}
                    data-live-attempt-id={comparisonItem.liveAttemptId}
                    data-shadow-attempt-id={comparisonItem.shadowAttemptId}
                    data-workflow-node-id={comparisonItem.workflowNodeId}
                    data-component-kind={comparisonItem.componentKind}
                    data-divergence={comparisonItem.divergence}
                    data-blocking={comparisonItem.blocking ? "true" : "false"}
                    data-evidence-refs={comparisonItem.evidenceRefs.join("|")}
                  >
                    <strong>{comparisonItem.divergence}</strong>
                    <span>{comparisonItem.summary}</span>
                    <small>
                      {comparisonItem.blocking ? "blocking" : "non-blocking"}
                    </small>
                  </li>
                ))}
              </ol>
            </>
          ) : null}
          <h4>Timeline</h4>
          <ol className="workflow-run-timeline" data-testid="workflow-run-timeline">
            {timelineEvents.slice(-10).map((event) => (
              <li
                key={event.id}
                className={`is-${event.status ?? event.kind}`}
                tabIndex={0}
                data-accessible-status={event.status ?? event.kind}
                data-accessible-status-text={accessibleStatusLabel(
                  event.status ?? event.kind,
                )}
                aria-label={`${workflowEventLabel(event)} ${accessibleStatusLabel(event.status ?? event.kind)}`}
              >
                <strong>{workflowEventLabel(event)}</strong>
                <span>
                  {event.message ?? workflowNodeName(workflow, event.nodeId)}
                </span>
                <small>{workflowTimeLabel(event.createdAtMs)}</small>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      {checkpoints.slice(0, 4).map((checkpoint) => (
        <article
          key={checkpoint.id}
          className="workflow-output-row"
          data-testid={`workflow-checkpoint-${checkpoint.id}`}
        >
          <strong>{checkpoint.status}</strong>
          <span>{checkpoint.summary}</span>
        </article>
      ))}
      {dogfoodRun ? (
        <article
          className="workflow-output-row"
          data-testid="workflow-dogfood-result"
        >
          <strong>{workflowWorkbenchCheckTitle(dogfoodRun.status)}</strong>
          <span>
            {workflowWorkbenchCheckSummary(dogfoodRun.workflowPaths.length)}
          </span>
        </article>
      ) : null}
    </>
  );
}
