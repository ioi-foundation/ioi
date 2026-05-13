import type {
  WorkflowCheckpoint,
  WorkflowDogfoodRun,
  WorkflowProject,
  WorkflowRunSummary,
} from "../../../types/graph";
import type { WorkflowRunHistoryModel } from "../../../runtime/workflow-run-history-model";
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
                    data-thread-id={row.threadId ?? ""}
                    data-turn-id={row.turnId ?? ""}
                    data-cursor={row.cursor ?? ""}
                    data-event-id={row.eventId ?? ""}
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
