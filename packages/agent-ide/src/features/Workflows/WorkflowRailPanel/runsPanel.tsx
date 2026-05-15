import type {
  WorkflowCheckpoint,
  WorkflowDogfoodRun,
  WorkflowProject,
  WorkflowRunSummary,
} from "../../../types/graph";
import type { WorkflowRunHistoryModel } from "../../../runtime/workflow-run-history-model";
import type { WorkflowRuntimeTelemetrySummary } from "../../../runtime/workflow-runtime-telemetry-summary";
import type {
  WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  WorkflowRuntimeContextPressureActionDescriptor,
  WorkflowRuntimeDiagnosticsRepairActionDescriptor,
  WorkflowRuntimeTuiControlStateRow,
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
  runSourceFilter: string;
  checkpoints: WorkflowCheckpoint[];
  dogfoodRun: WorkflowDogfoodRun | null;
  accessibleStatusLabel: (status: unknown) => string;
  onRunSearchQueryChange: (query: string) => void;
  onRunStatusFilterChange: (status: string) => void;
  onRunSourceFilterChange: (sourceKind: string) => void;
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
  onExecuteRuntimeCodingToolBudgetRecovery?: (
    action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  ) => void | Promise<void>;
  onCreateRuntimeCodingToolBudgetRecoverySubflow?: (
    action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  ) => void;
  onBindRuntimeCodingToolBudgetRecoveryTemplate?: (
    action: WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor,
  ) => void;
  onBindRuntimeTelemetrySource?: (
    summary: WorkflowRuntimeTelemetrySummary,
  ) => void;
  onMaterializeRuntimeTelemetryBudgetChain?: (
    summary: WorkflowRuntimeTelemetrySummary,
  ) => void;
  onMaterializeRuntimeTerminalCodingLoop?: (
    row: WorkflowRuntimeTuiControlStateRow,
  ) => void;
};

function codingToolBudgetRecoverySubflowSeed(
  actions: readonly WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor[],
): WorkflowRuntimeCodingToolBudgetRecoveryActionDescriptor | null {
  return (
    actions.find((action) => action.action === "request_approval") ??
    actions.find((action) => action.action === "approve_override") ??
    actions[0] ??
    null
  );
}

function embeddableComputerUseScreenRef(ref: string | null): string | null {
  const value = ref?.trim();
  if (!value) return null;
  return /^(https?:\/\/|data:image\/|blob:|\/)/i.test(value) ? value : null;
}

export function WorkflowRunsPanel({
  workflow,
  model,
  runSearchQuery,
  runStatusFilter,
  runSourceFilter,
  checkpoints,
  dogfoodRun,
  accessibleStatusLabel,
  onRunSearchQueryChange,
  onRunStatusFilterChange,
  onRunSourceFilterChange,
  onOpenExecutions,
  onSelectRun,
  onCompareRun,
  onInspectNode,
  onExecuteRuntimeDiagnosticsRepair,
  onExecuteRuntimeContextPressureAction,
  onExecuteRuntimeWorkspaceTrustAction,
  onExecuteRuntimeCodingToolBudgetRecovery,
  onCreateRuntimeCodingToolBudgetRecoverySubflow,
  onBindRuntimeCodingToolBudgetRecoveryTemplate,
  onBindRuntimeTelemetrySource,
  onMaterializeRuntimeTelemetryBudgetChain,
  onMaterializeRuntimeTerminalCodingLoop,
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
    runtimeTelemetrySummary,
    runtimeTelemetrySourceFilter,
    runtimeTelemetrySourceFilters,
    runtimeCodingToolBudgetEvidence,
    computerUseWorkbench,
    modelInvocationTraces,
    tuiControlStateProjection,
    visibleTuiControlStateRows,
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
          {runtimeTelemetrySourceFilters.length > 0 ? (
            <div
              className="workflow-node-group-filter workflow-run-source-filter"
              data-testid="workflow-run-source-filter"
              data-active-source-filter={runtimeTelemetrySourceFilter}
              data-run-source-filter={runSourceFilter}
            >
              <button
                type="button"
                className={runtimeTelemetrySourceFilter === "all" ? "is-active" : ""}
                data-testid="workflow-run-source-all"
                data-source-kind="all"
                aria-label="Filter run telemetry by all sources"
                onClick={() => onRunSourceFilterChange("all")}
              >
                all sources
                <small>{runtimeTelemetrySourceFilters.length}</small>
              </button>
              {runtimeTelemetrySourceFilters.map((source) => (
                <button
                  key={source.sourceKind}
                  type="button"
                  className={source.active ? "is-active" : ""}
                  data-testid={`workflow-run-source-${source.sourceKind}`}
                  data-source-kind={source.sourceKind}
                  data-source-count={source.count}
                  data-blocks-mutation={source.blocksMutation}
                  aria-label={`Filter run telemetry by ${source.label}`}
                  onClick={() => onRunSourceFilterChange(source.sourceKind)}
                >
                  {source.label}
                  <small>{source.count}</small>
                </button>
              ))}
            </div>
          ) : null}
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
          {modelInvocationTraces.length > 0 ? (
            <section
              className="workflow-run-comparison"
              data-testid="workflow-run-model-invocation-trace"
              data-model-invocation-count={modelInvocationTraces.length}
              data-model-refs={modelInvocationTraces
                .map((trace) => trace.modelRef)
                .join("|")}
              data-model-ids={modelInvocationTraces
                .map((trace) => trace.modelId)
                .join("|")}
              data-response-hashes={modelInvocationTraces
                .map((trace) => trace.responseHash)
                .join("|")}
            >
              <h4>Model pipeline</h4>
              <span>
                {modelInvocationTraces.length} invocation
                {modelInvocationTraces.length === 1 ? "" : "s"} with prompt,
                binding, and response evidence.
              </span>
              <div
                className="workflow-run-runtime-event-summary"
                data-testid="workflow-run-model-invocation-summary"
              >
                <span>{modelInvocationTraces[0]?.mode ?? "model"}</span>
                <span>{modelInvocationTraces[0]?.modelRef ?? "model"}</span>
                <span>
                  {modelInvocationTraces[0]?.trace.length ?? 0} trace steps
                </span>
              </div>
              <div className="workflow-run-comparison-list">
                {modelInvocationTraces.map((invocation) => (
                  <article
                    key={`${invocation.nodeId}-${invocation.responseHash}`}
                    className="workflow-run-comparison-node"
                    data-testid={`workflow-run-model-invocation-node-${invocation.nodeId}`}
                    data-node-id={invocation.nodeId}
                    data-model-ref={invocation.modelRef}
                    data-model-id={invocation.modelId}
                    data-mode={invocation.mode}
                    data-prompt-hash={invocation.promptHash}
                    data-response-hash={invocation.responseHash}
                  >
                    <strong>{invocation.nodeName}</strong>
                    <span>
                      {invocation.modelRef} · {invocation.modelId} ·{" "}
                      {invocation.mode}
                    </span>
                    <small>{invocation.promptUser}</small>
                    <small>
                      {invocation.promptHash} · {invocation.responseHash}
                    </small>
                    <ol
                      className="workflow-run-policy-stack"
                      data-testid="workflow-run-model-invocation-steps"
                    >
                      {invocation.trace.map((step, index) => (
                        <li
                          key={`${invocation.nodeId}-${step.phase}-${index}`}
                          className="workflow-run-policy-stack-stage is-completed"
                          data-testid="workflow-run-model-invocation-step"
                          data-phase={step.phase}
                        >
                          <span>{step.phase}</span>
                          <small>
                            {step.summary}
                            {step.detail ? ` · ${step.detail}` : ""}
                          </small>
                        </li>
                      ))}
                    </ol>
                    <button
                      type="button"
                      className="workflow-secondary-action"
                      data-testid={`workflow-run-model-invocation-inspect-${invocation.nodeId}`}
                      onClick={() => onInspectNode(invocation.nodeId)}
                    >
                      Inspect node
                    </button>
                  </article>
                ))}
              </div>
            </section>
          ) : null}
          {runtimeTelemetrySummary.sourceKinds.length > 0 ? (
            <section
              className="workflow-run-telemetry-summary"
              data-testid="workflow-run-telemetry-summary"
              data-schema-version={runtimeTelemetrySummary.schemaVersion}
              data-telemetry-status={runtimeTelemetrySummary.status}
              data-source-kinds={runtimeTelemetrySummary.sourceKinds.join("|")}
              data-thread-ids={runtimeTelemetrySummary.threadIds.join("|")}
              data-turn-ids={runtimeTelemetrySummary.turnIds.join("|")}
              data-workflow-graph-ids={
                runtimeTelemetrySummary.workflowGraphIds.join("|")
              }
              data-workflow-node-ids={
                runtimeTelemetrySummary.workflowNodeIds.join("|")
              }
              data-event-ids={runtimeTelemetrySummary.eventIds.join("|")}
              data-latest-seq={runtimeTelemetrySummary.latestSeq ?? ""}
              data-latest-cursor={runtimeTelemetrySummary.latestCursor ?? ""}
              data-latest-event-id={runtimeTelemetrySummary.latestEventId ?? ""}
              data-runtime-event-count={
                runtimeTelemetrySummary.runtimeEventCount
              }
              data-usage-event-count={runtimeTelemetrySummary.usageEventCount}
              data-context-pressure-event-count={
                runtimeTelemetrySummary.contextPressureEventCount
              }
              data-context-pressure-alert-count={
                runtimeTelemetrySummary.contextPressureAlertCount
              }
              data-tui-row-count={runtimeTelemetrySummary.tuiRowCount}
              data-usage-row-count={runtimeTelemetrySummary.usageRowCount}
              data-cost-row-count={runtimeTelemetrySummary.costRowCount}
              data-context-row-count={runtimeTelemetrySummary.contextRowCount}
              data-subagent-row-count={runtimeTelemetrySummary.subagentRowCount}
              data-coding-tool-budget-row-count={
                runtimeTelemetrySummary.codingToolBudgetRowCount
              }
              data-total-tokens={runtimeTelemetrySummary.totalTokens ?? ""}
              data-input-tokens={runtimeTelemetrySummary.inputTokens ?? ""}
              data-output-tokens={runtimeTelemetrySummary.outputTokens ?? ""}
              data-cost-estimate-usd={
                runtimeTelemetrySummary.costEstimateUsd ?? ""
              }
              data-context-pressure={
                runtimeTelemetrySummary.contextPressure ?? ""
              }
              data-context-pressure-status={
                runtimeTelemetrySummary.contextPressureStatus ?? ""
              }
              data-run-count={runtimeTelemetrySummary.runCount ?? ""}
              data-subagent-count={runtimeTelemetrySummary.subagentCount ?? ""}
              data-receipt-refs={runtimeTelemetrySummary.receiptRefs.join("|")}
              data-policy-decision-refs={
                runtimeTelemetrySummary.policyDecisionRefs.join("|")
              }
            >
              <h4>Usage and context</h4>
              <div
                className="workflow-run-runtime-event-summary"
                data-testid="workflow-run-telemetry-summary-metrics"
              >
                <span>
                  {runtimeTelemetrySummary.totalTokens ?? 0} tokens
                </span>
                <span>
                  {formatTelemetryCost(runtimeTelemetrySummary.costEstimateUsd)}
                </span>
                <span>
                  context{" "}
                  {runtimeTelemetrySummary.contextPressure === null
                    ? "pending"
                    : runtimeTelemetrySummary.contextPressure}
                </span>
                <span>{accessibleStatusLabel(runtimeTelemetrySummary.status)}</span>
                <span>
                  {runtimeTelemetrySummary.subagentCount ?? 0} subagents
                </span>
                <span>
                  {runtimeTelemetrySummary.codingToolBudgetRowCount} coding
                  budgets
                </span>
              </div>
              <button
                type="button"
                className="workflow-secondary-action"
                data-testid="workflow-run-telemetry-bind-source"
                data-schema-version={runtimeTelemetrySummary.schemaVersion}
                data-telemetry-status={runtimeTelemetrySummary.status}
                data-thread-ids={runtimeTelemetrySummary.threadIds.join("|")}
                data-turn-ids={runtimeTelemetrySummary.turnIds.join("|")}
                data-source-kinds={runtimeTelemetrySummary.sourceKinds.join("|")}
                data-latest-event-id={runtimeTelemetrySummary.latestEventId ?? ""}
                data-latest-cursor={runtimeTelemetrySummary.latestCursor ?? ""}
                disabled={!onBindRuntimeTelemetrySource}
                title="Bind this usage/context telemetry summary into runtime budget nodes."
                aria-label="Bind runtime telemetry source"
                onClick={() => {
                  onBindRuntimeTelemetrySource?.(runtimeTelemetrySummary);
                }}
              >
                Bind telemetry source
              </button>
              <button
                type="button"
                className="workflow-secondary-action"
                data-testid="workflow-run-telemetry-budget-chain-materialize"
                data-schema-version={runtimeTelemetrySummary.schemaVersion}
                data-telemetry-status={runtimeTelemetrySummary.status}
                data-thread-ids={runtimeTelemetrySummary.threadIds.join("|")}
                data-turn-ids={runtimeTelemetrySummary.turnIds.join("|")}
                data-source-kinds={runtimeTelemetrySummary.sourceKinds.join("|")}
                data-latest-event-id={runtimeTelemetrySummary.latestEventId ?? ""}
                data-latest-cursor={runtimeTelemetrySummary.latestCursor ?? ""}
                disabled={!onMaterializeRuntimeTelemetryBudgetChain}
                title="Create or hydrate a telemetry-governed budget chain from this run evidence."
                aria-label="Create telemetry budget chain"
                onClick={() => {
                  onMaterializeRuntimeTelemetryBudgetChain?.(
                    runtimeTelemetrySummary,
                  );
                }}
              >
                Use budget chain
              </button>
              {runtimeTelemetrySourceFilters.length > 0 ? (
                <div
                  className="workflow-run-telemetry-source-kinds"
                  data-testid="workflow-run-telemetry-source-kinds"
                  data-active-source-filter={runtimeTelemetrySourceFilter}
                >
                  {runtimeTelemetrySourceFilters.map((source) => (
                    <span
                      key={source.sourceKind}
                      data-source-kind={source.sourceKind}
                      data-source-count={source.count}
                      data-source-active={source.active}
                      data-blocks-mutation={source.blocksMutation}
                    >
                      {source.label} · {source.count}
                    </span>
                  ))}
                </div>
              ) : null}
              {runtimeCodingToolBudgetEvidence ? (
                <article
                  className={`workflow-run-telemetry-budget-evidence is-${runtimeCodingToolBudgetEvidence.status}`}
                  data-testid="workflow-run-coding-tool-budget-evidence"
                  data-source-kind={runtimeCodingToolBudgetEvidence.sourceKind}
                  data-budget-row-count={
                    runtimeCodingToolBudgetEvidence.rowCount
                  }
                  data-event-ids={
                    runtimeCodingToolBudgetEvidence.eventIds.join("|")
                  }
                  data-workflow-node-ids={
                    runtimeCodingToolBudgetEvidence.workflowNodeIds.join("|")
                  }
                  data-tool-names={
                    runtimeCodingToolBudgetEvidence.toolNames.join("|")
                  }
                  data-tool-call-ids={
                    runtimeCodingToolBudgetEvidence.toolCallIds.join("|")
                  }
                  data-budget-statuses={
                    runtimeCodingToolBudgetEvidence.budgetStatuses.join("|")
                  }
                  data-context-budget-statuses={
                    runtimeCodingToolBudgetEvidence.contextBudgetStatuses.join("|")
                  }
                  data-total-tokens={
                    runtimeCodingToolBudgetEvidence.totalTokens ?? ""
                  }
                  data-cost-estimate-usd={
                    runtimeCodingToolBudgetEvidence.costEstimateUsd ?? ""
                  }
                  data-context-pressure={
                    runtimeCodingToolBudgetEvidence.contextPressure ?? ""
                  }
                  data-context-pressure-status={
                    runtimeCodingToolBudgetEvidence.contextPressureStatus ?? ""
                  }
                  data-mutation-blocked={
                    runtimeCodingToolBudgetEvidence.mutationBlocked
                  }
                  data-receipt-refs={
                    runtimeCodingToolBudgetEvidence.receiptRefs.join("|")
                  }
                  data-policy-decision-refs={
                    runtimeCodingToolBudgetEvidence.policyDecisionRefs.join("|")
                  }
                >
                  <strong>{runtimeCodingToolBudgetEvidence.label}</strong>
                  <span>
                    {runtimeCodingToolBudgetEvidence.rowCount} rows ·{" "}
                    {accessibleStatusLabel(runtimeCodingToolBudgetEvidence.status)}
                    {runtimeCodingToolBudgetEvidence.mutationBlocked
                      ? " · mutation blocked"
                      : ""}
                  </span>
                  <small>
                    {runtimeCodingToolBudgetEvidence.toolNames.join(", ") ||
                      "coding tool"}{" "}
                    · {runtimeCodingToolBudgetEvidence.eventIds[0] ?? "event pending"}
                  </small>
                </article>
              ) : null}
            </section>
          ) : null}
          {computerUseWorkbench ? (
            <section
              className={`workflow-run-computer-use-workbench is-${computerUseWorkbench.status}`}
              data-testid="workflow-run-computer-use-workbench"
              data-status={computerUseWorkbench.status}
              data-lane={computerUseWorkbench.lane ?? ""}
              data-session-mode={computerUseWorkbench.sessionMode ?? ""}
              data-lease-id={computerUseWorkbench.leaseId ?? ""}
              data-controlled-relaunch-launch-ref={
                computerUseWorkbench.controlledRelaunchLaunchRef ?? ""
              }
              data-controlled-relaunch-launch-status={
                computerUseWorkbench.controlledRelaunchLaunchStatus ?? ""
              }
              data-controlled-relaunch-process-ref={
                computerUseWorkbench.controlledRelaunchProcessRef ?? ""
              }
              data-controlled-relaunch-profile-dir-ref={
                computerUseWorkbench.controlledRelaunchProfileDirRef ?? ""
              }
              data-controlled-relaunch-endpoint-ref={
                computerUseWorkbench.controlledRelaunchEndpointRef ?? ""
              }
              data-controlled-relaunch-approval-ref={
                computerUseWorkbench.controlledRelaunchApprovalRef ?? ""
              }
              data-observation-ref={computerUseWorkbench.observationRef ?? ""}
              data-screen-ref={computerUseWorkbench.screenRef ?? ""}
              data-som-ref={computerUseWorkbench.somRef ?? ""}
              data-coordinate-space-id={
                computerUseWorkbench.coordinateSpaceId ?? ""
              }
              data-target-index-ref={computerUseWorkbench.targetIndexRef ?? ""}
              data-target-count={computerUseWorkbench.targetCount}
              data-affordance-count={computerUseWorkbench.affordanceCount}
              data-detected-patterns={
                computerUseWorkbench.detectedPatterns.join("|")
              }
              data-proposal-ref={computerUseWorkbench.proposalRef ?? ""}
              data-action-ref={computerUseWorkbench.actionRef ?? ""}
              data-action-kind={computerUseWorkbench.actionKind ?? ""}
              data-execution-ref={computerUseWorkbench.executionRef ?? ""}
              data-execution-status={computerUseWorkbench.executionStatus ?? ""}
              data-execution-adapter-id={
                computerUseWorkbench.executionAdapterId ?? ""
              }
              data-execution-provider-id={
                computerUseWorkbench.executionProviderId ?? ""
              }
              data-execution-preflight-status={
                computerUseWorkbench.executionPreflightStatus ?? ""
              }
              data-execution-requires-reobserve={
                computerUseWorkbench.executionRequiresReobserve === null
                  ? ""
                  : String(computerUseWorkbench.executionRequiresReobserve)
              }
              data-verification-status={
                computerUseWorkbench.verificationStatus ?? ""
              }
              data-commit-gate-status={
                computerUseWorkbench.commitGateStatus ?? ""
              }
              data-policy-decision-ref={
                computerUseWorkbench.policyDecisionRef ?? ""
              }
              data-policy-outcome={computerUseWorkbench.policyOutcome ?? ""}
              data-policy-authority-scope={
                computerUseWorkbench.policyAuthorityScope ?? ""
              }
              data-policy-approval-ref={
                computerUseWorkbench.policyApprovalRef ?? ""
              }
              data-policy-external-effect={
                computerUseWorkbench.policyExternalEffect ?? ""
              }
              data-policy-fail-closed={
                computerUseWorkbench.policyFailClosed ?? ""
              }
              data-blocker={computerUseWorkbench.blocker ?? ""}
              data-retention-mode={computerUseWorkbench.retentionMode ?? ""}
              data-authority-required={
                computerUseWorkbench.authorityRequired ?? ""
              }
              data-event-ids={computerUseWorkbench.eventIds.join("|")}
              data-workflow-node-ids={
                computerUseWorkbench.workflowNodeIds.join("|")
              }
              data-artifact-refs={computerUseWorkbench.artifactRefs.join("|")}
              data-artifact-preview-count={
                computerUseWorkbench.artifactPreviews.length
              }
              data-visual-target-refs={computerUseWorkbench.visualTargetSummaries
                .map((target) => target.targetRef)
                .join("|")}
            >
              <h4>Computer-use workbench</h4>
              <div className="workflow-run-computer-use-workbench-grid">
                {computerUseWorkbench.controlledRelaunchLaunchRef ? (
                  <article
                    className="workflow-run-computer-use-pane"
                    data-testid="workflow-run-computer-use-launch-pane"
                    data-launch-ref={
                      computerUseWorkbench.controlledRelaunchLaunchRef
                    }
                    data-launch-status={
                      computerUseWorkbench.controlledRelaunchLaunchStatus ?? ""
                    }
                    data-process-ref={
                      computerUseWorkbench.controlledRelaunchProcessRef ?? ""
                    }
                    data-profile-dir-ref={
                      computerUseWorkbench.controlledRelaunchProfileDirRef ?? ""
                    }
                    data-endpoint-ref={
                      computerUseWorkbench.controlledRelaunchEndpointRef ?? ""
                    }
                    data-approval-ref={
                      computerUseWorkbench.controlledRelaunchApprovalRef ?? ""
                    }
                  >
                    <strong>Browser launch</strong>
                    <span>
                      {[
                        computerUseWorkbench.controlledRelaunchLaunchStatus,
                        computerUseWorkbench.controlledRelaunchLaunchRef,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </span>
                    <small>
                      {[
                        computerUseWorkbench.controlledRelaunchEndpointRef,
                        computerUseWorkbench.controlledRelaunchProcessRef,
                        computerUseWorkbench.controlledRelaunchProfileDirRef,
                        computerUseWorkbench.controlledRelaunchApprovalRef,
                      ]
                        .filter(Boolean)
                        .join(" · ") || "launch evidence pending"}
                    </small>
                  </article>
                ) : null}
                <article
                  className="workflow-run-computer-use-pane"
                  data-testid="workflow-run-computer-use-screen-pane"
                  data-screen-ref={computerUseWorkbench.screenRef ?? ""}
                  data-som-ref={computerUseWorkbench.somRef ?? ""}
                  data-coordinate-space-id={
                    computerUseWorkbench.coordinateSpaceId ?? ""
                  }
                >
                  <strong>Screen</strong>
                  <span>
                    {[
                      computerUseWorkbench.screenRef ?? "screen pending",
                      computerUseWorkbench.somRef
                        ? `overlay ${computerUseWorkbench.somRef}`
                        : null,
                      computerUseWorkbench.coordinateSpaceId,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                  <small>
                    {[
                      computerUseWorkbench.lane,
                      computerUseWorkbench.sessionMode,
                      computerUseWorkbench.observationRef,
                    ]
                      .filter(Boolean)
                      .join(" · ") || "observation pending"}
                  </small>
                </article>
                <article
                  className="workflow-run-computer-use-pane"
                  data-testid="workflow-run-computer-use-overlay-pane"
                  data-target-count={computerUseWorkbench.targetCount}
                  data-affordance-count={computerUseWorkbench.affordanceCount}
                >
                  <strong>Target overlay</strong>
                  <span>
                    {computerUseWorkbench.targetCount} targets ·{" "}
                    {computerUseWorkbench.affordanceCount} affordances
                  </span>
                  <small>
                    {computerUseWorkbench.detectedPatterns.join(", ") ||
                      "patterns pending"}
                  </small>
                </article>
                <article
                  className="workflow-run-computer-use-pane"
                  data-testid="workflow-run-computer-use-action-pane"
                  data-proposal-ref={computerUseWorkbench.proposalRef ?? ""}
                  data-action-ref={computerUseWorkbench.actionRef ?? ""}
                  data-verification-status={
                    computerUseWorkbench.verificationStatus ?? ""
                  }
                  data-execution-status={
                    computerUseWorkbench.executionStatus ?? ""
                  }
                  data-execution-provider-id={
                    computerUseWorkbench.executionProviderId ?? ""
                  }
                  data-execution-preflight-status={
                    computerUseWorkbench.executionPreflightStatus ?? ""
                  }
                  data-execution-requires-reobserve={
                    computerUseWorkbench.executionRequiresReobserve === null
                      ? ""
                      : String(computerUseWorkbench.executionRequiresReobserve)
                  }
                >
                  <strong>Action path</strong>
                  <span>
                    {computerUseWorkbench.actionRef
                      ? [
                          computerUseWorkbench.actionKind,
                          computerUseWorkbench.actionRef,
                        ]
                          .filter(Boolean)
                          .join(" · ")
                      : computerUseWorkbench.proposalRef
                        ? `proposal ${computerUseWorkbench.proposalRef}`
                        : "proposal pending"}
                  </span>
                  <small>
                    {[
                      computerUseWorkbench.executionStatus
                        ? `execution ${computerUseWorkbench.executionStatus}`
                        : null,
                      computerUseWorkbench.executionProviderId
                        ? `provider ${computerUseWorkbench.executionProviderId}`
                        : computerUseWorkbench.executionAdapterId,
                      computerUseWorkbench.executionPreflightStatus
                        ? `preflight ${computerUseWorkbench.executionPreflightStatus}`
                        : null,
                      computerUseWorkbench.executionRequiresReobserve === true
                        ? "reobserve required"
                        : null,
                      computerUseWorkbench.verificationStatus,
                      computerUseWorkbench.commitGateStatus,
                      computerUseWorkbench.blocker,
                    ]
                      .filter(Boolean)
                      .join(" · ") || "verification pending"}
                  </small>
                </article>
                <article
                  className="workflow-run-computer-use-pane"
                  data-testid="workflow-run-computer-use-policy-pane"
                  data-policy-decision-ref={
                    computerUseWorkbench.policyDecisionRef ?? ""
                  }
                  data-policy-outcome={computerUseWorkbench.policyOutcome ?? ""}
                  data-policy-authority-scope={
                    computerUseWorkbench.policyAuthorityScope ?? ""
                  }
                  data-policy-approval-ref={
                    computerUseWorkbench.policyApprovalRef ?? ""
                  }
                  data-policy-external-effect={
                    computerUseWorkbench.policyExternalEffect ?? ""
                  }
                  data-policy-fail-closed={
                    computerUseWorkbench.policyFailClosed ?? ""
                  }
                >
                  <strong>Policy</strong>
                  <span>
                    {[
                      computerUseWorkbench.policyOutcome,
                      computerUseWorkbench.policyFailClosed === true
                        ? "fail closed"
                        : computerUseWorkbench.policyFailClosed === false
                          ? "allowed"
                          : null,
                      computerUseWorkbench.policyExternalEffect === true
                        ? "external effect"
                        : computerUseWorkbench.policyExternalEffect === false
                          ? "no external effect"
                          : null,
                    ]
                      .filter(Boolean)
                      .join(" · ") || "policy pending"}
                  </span>
                  <small>
                    {[
                      computerUseWorkbench.policyDecisionRef,
                      computerUseWorkbench.policyAuthorityScope,
                      computerUseWorkbench.policyApprovalRef,
                    ]
                      .filter(Boolean)
                      .join(" · ") || "decision evidence pending"}
                  </small>
                </article>
              </div>
              {computerUseWorkbench.overlayViewport ? (
                <figure
                  className="workflow-run-computer-use-visual-preview"
                  data-testid="workflow-run-computer-use-visual-preview"
                  data-preview-kind={
                    embeddableComputerUseScreenRef(
                      computerUseWorkbench.screenRef,
                    )
                      ? "image"
                      : "overlay"
                  }
                  data-screen-ref={computerUseWorkbench.screenRef ?? ""}
                  data-som-ref={computerUseWorkbench.somRef ?? ""}
                  data-coordinate-space-id={
                    computerUseWorkbench.overlayViewport.coordinateSpaceId ?? ""
                  }
                  data-viewport-width={computerUseWorkbench.overlayViewport.width}
                  data-viewport-height={
                    computerUseWorkbench.overlayViewport.height
                  }
                >
                  <svg
                    viewBox={`0 0 ${computerUseWorkbench.overlayViewport.width} ${computerUseWorkbench.overlayViewport.height}`}
                    role="img"
                    aria-label="Computer-use target overlay"
                    preserveAspectRatio="xMidYMid meet"
                  >
                    <rect
                      className="workflow-run-computer-use-preview-surface"
                      x="0"
                      y="0"
                      width={computerUseWorkbench.overlayViewport.width}
                      height={computerUseWorkbench.overlayViewport.height}
                    />
                    {embeddableComputerUseScreenRef(
                      computerUseWorkbench.screenRef,
                    ) ? (
                      <image
                        href={
                          embeddableComputerUseScreenRef(
                            computerUseWorkbench.screenRef,
                          ) ?? undefined
                        }
                        x="0"
                        y="0"
                        width={computerUseWorkbench.overlayViewport.width}
                        height={computerUseWorkbench.overlayViewport.height}
                        preserveAspectRatio="xMidYMid slice"
                      />
                    ) : null}
                    {computerUseWorkbench.visualTargetSummaries
                      .filter((target) => target.bounds)
                      .slice(0, 12)
                      .map((target, index) => (
                        <g key={target.targetRef}>
                          <title>
                            {[
                              target.label ?? target.targetRef,
                              target.role,
                              target.availableActions.join(", "),
                            ]
                              .filter(Boolean)
                              .join(" · ")}
                          </title>
                          <rect
                            className="workflow-run-computer-use-preview-target"
                            x={target.bounds?.x ?? 0}
                            y={target.bounds?.y ?? 0}
                            width={target.bounds?.width ?? 1}
                            height={target.bounds?.height ?? 1}
                          />
                          <text
                            className="workflow-run-computer-use-preview-label"
                            x={(target.bounds?.x ?? 0) + 6}
                            y={(target.bounds?.y ?? 0) + 16}
                          >
                            {target.somId ?? index + 1}
                          </text>
                        </g>
                      ))}
                  </svg>
                  <figcaption>
                    {computerUseWorkbench.screenRef ??
                      "screen artifact not retained"}{" "}
                    · {computerUseWorkbench.visualTargetSummaries.length} target
                    boxes
                  </figcaption>
                </figure>
              ) : null}
              {computerUseWorkbench.visualTargetSummaries.length > 0 ? (
                <ol
                  className="workflow-run-computer-use-targets"
                  data-testid="workflow-run-computer-use-targets"
                >
                  {computerUseWorkbench.visualTargetSummaries
                    .slice(0, 6)
                    .map((target) => (
                      <li
                        key={target.targetRef}
                        data-target-ref={target.targetRef}
                        data-target-role={target.role ?? ""}
                        data-som-id={target.somId ?? ""}
                        data-confidence={target.confidence ?? ""}
                        data-bounds-summary={target.boundsSummary ?? ""}
                        data-available-actions={target.availableActions.join("|")}
                      >
                        <strong>
                          {target.label ?? target.targetRef}
                        </strong>
                        <span>
                          {[
                            target.role,
                            target.somId === null
                              ? null
                              : `mark ${target.somId}`,
                            target.boundsSummary,
                          ]
                            .filter(Boolean)
                            .join(" · ") || "target evidence"}
                        </span>
                        <small>
                          {target.availableActions.join(", ") ||
                            "actions pending"}
                        </small>
                      </li>
                  ))}
                </ol>
              ) : null}
              {computerUseWorkbench.artifactPreviews.length > 0 ? (
                <ol
                  className="workflow-run-computer-use-artifacts"
                  data-testid="workflow-run-computer-use-artifacts"
                  data-artifact-preview-count={
                    computerUseWorkbench.artifactPreviews.length
                  }
                >
                  {computerUseWorkbench.artifactPreviews
                    .slice(0, 8)
                    .map((artifact) => (
                      <li
                        key={artifact.artifactRef}
                        data-artifact-ref={artifact.artifactRef}
                        data-preview-kind={artifact.previewKind}
                        data-fetch-path={artifact.fetchPath ?? ""}
                        data-embeddable-url={artifact.embeddableUrl ?? ""}
                      >
                        <strong>{artifact.label}</strong>
                        <span>{artifact.artifactRef}</span>
                        <small>
                          {artifact.previewKind === "embedded_image"
                            ? "inline preview"
                            : artifact.fetchPath
                              ? `runtime artifact · ${artifact.fetchPath}`
                              : "opaque reference"}
                        </small>
                      </li>
                    ))}
                </ol>
              ) : null}
            </section>
          ) : null}
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
                    data-coding-tool-budget-recovery-action-count={
                      node.data.codingToolBudgetRecoveryActions.length
                    }
                    data-computer-use-step={node.data.computerUse?.step ?? ""}
                    data-computer-use-lane={node.data.computerUse?.lane ?? ""}
                    data-computer-use-session-mode={
                      node.data.computerUse?.sessionMode ?? ""
                    }
                    data-computer-use-lease-id={
                      node.data.computerUse?.leaseId ?? ""
                    }
                    data-computer-use-browser-discovery-ref={
                      node.data.computerUse?.browserDiscoveryRef ?? ""
                    }
                    data-computer-use-browser-process-count={
                      node.data.computerUse?.browserProcessCount ?? ""
                    }
                    data-computer-use-cdp-endpoint-count={
                      node.data.computerUse?.cdpEndpointCount ?? ""
                    }
                    data-computer-use-proposal-ref={
                      node.data.computerUse?.proposalRef ?? ""
                    }
                    data-computer-use-action-ref={
                      node.data.computerUse?.actionRef ?? ""
                    }
                    data-computer-use-verification-ref={
                      node.data.computerUse?.verificationRef ?? ""
                    }
                    data-computer-use-commit-gate-ref={
                      node.data.computerUse?.commitGateRef ?? ""
                    }
                    data-computer-use-commit-gate-status={
                      node.data.computerUse?.commitGateStatus ?? ""
                    }
                    data-computer-use-outcome-ref={
                      node.data.computerUse?.outcomeRef ?? ""
                    }
                    data-computer-use-human-handoff-ref={
                      node.data.computerUse?.humanHandoffRef ?? ""
                    }
                    data-computer-use-cleanup-ref={
                      node.data.computerUse?.cleanupRef ?? ""
                    }
                    data-computer-use-blocker={
                      node.data.computerUse?.blocker ?? ""
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
                      {node.data.computerUse ? (
                        <div
                          className={`workflow-run-computer-use-trace is-${node.data.computerUse.status}`}
                          data-testid={`workflow-run-computer-use-trace-${node.id}`}
                          data-schema-version={node.data.computerUse.schemaVersion}
                          data-step={node.data.computerUse.step ?? ""}
                          data-lane={node.data.computerUse.lane ?? ""}
                          data-session-mode={
                            node.data.computerUse.sessionMode ?? ""
                          }
                          data-lease-id={node.data.computerUse.leaseId ?? ""}
                          data-observation-ref={
                            node.data.computerUse.observationRef ?? ""
                          }
                          data-target-index-ref={
                            node.data.computerUse.targetIndexRef ?? ""
                          }
                          data-affordance-graph-ref={
                            node.data.computerUse.affordanceGraphRef ?? ""
                          }
                          data-browser-discovery-ref={
                            node.data.computerUse.browserDiscoveryRef ?? ""
                          }
                          data-browser-process-count={
                            node.data.computerUse.browserProcessCount ?? ""
                          }
                          data-cdp-endpoint-count={
                            node.data.computerUse.cdpEndpointCount ?? ""
                          }
                          data-default-profile-blocker-count={
                            node.data.computerUse.defaultProfileBlockerCount ?? ""
                          }
                          data-proposal-ref={
                            node.data.computerUse.proposalRef ?? ""
                          }
                          data-action-ref={node.data.computerUse.actionRef ?? ""}
                          data-action-kind={
                            node.data.computerUse.actionKind ?? ""
                          }
                          data-action-receipt-ref={
                            node.data.computerUse.actionReceiptRef ?? ""
                          }
                          data-execution-ref={
                            node.data.computerUse.executionRef ?? ""
                          }
                          data-execution-status={
                            node.data.computerUse.executionStatus ?? ""
                          }
                          data-execution-adapter-id={
                            node.data.computerUse.executionAdapterId ?? ""
                          }
                          data-execution-provider-id={
                            node.data.computerUse.executionProviderId ?? ""
                          }
                          data-execution-preflight-status={
                            node.data.computerUse.executionPreflightStatus ?? ""
                          }
                          data-execution-requires-reobserve={
                            node.data.computerUse.executionRequiresReobserve ===
                            null
                              ? ""
                              : String(
                                  node.data.computerUse
                                    .executionRequiresReobserve,
                                )
                          }
                          data-verification-ref={
                            node.data.computerUse.verificationRef ?? ""
                          }
                          data-verification-status={
                            node.data.computerUse.verificationStatus ?? ""
                          }
                          data-commit-gate-ref={
                            node.data.computerUse.commitGateRef ?? ""
                          }
                          data-commit-gate-status={
                            node.data.computerUse.commitGateStatus ?? ""
                          }
                          data-outcome-ref={node.data.computerUse.outcomeRef ?? ""}
                          data-human-handoff-ref={
                            node.data.computerUse.humanHandoffRef ?? ""
                          }
                          data-trajectory-ref={
                            node.data.computerUse.trajectoryRef ?? ""
                          }
                          data-cleanup-ref={
                            node.data.computerUse.cleanupRef ?? ""
                          }
                          data-cleanup-status={
                            node.data.computerUse.cleanupStatus ?? ""
                          }
                          data-retention-mode={
                            node.data.computerUse.retentionMode ?? ""
                          }
                          data-risk-posture={
                            node.data.computerUse.riskPosture ?? ""
                          }
                          data-authority-required={
                            node.data.computerUse.authorityRequired ?? ""
                          }
                          data-target-count={
                            node.data.computerUse.targetCount ?? ""
                          }
                          data-affordance-count={
                            node.data.computerUse.affordanceCount ?? ""
                          }
                          data-detected-patterns={
                            node.data.computerUse.detectedPatterns.join("|")
                          }
                          data-blocker={node.data.computerUse.blocker ?? ""}
                          data-workflow-graph-id={
                            node.data.computerUse.workflowGraphId ?? ""
                          }
                          data-workflow-node-id={
                            node.data.computerUse.workflowNodeId ?? ""
                          }
                          data-tool-ref={node.data.computerUse.toolRef ?? ""}
                          data-authority-scopes={
                            node.data.computerUse.authorityScopes.join("|")
                          }
                          data-fail-closed-when-unavailable={
                            node.data.computerUse.failClosedWhenUnavailable ===
                            null
                              ? ""
                              : String(
                                  node.data.computerUse
                                    .failClosedWhenUnavailable,
                                )
                          }
                        >
                          <span>Computer use trace</span>
                          <dl>
                            <div>
                              <dt>Lane</dt>
                              <dd>
                                {[node.data.computerUse.lane, node.data.computerUse.sessionMode]
                                  .filter(Boolean)
                                  .join(" / ") || "unknown"}
                              </dd>
                            </div>
                            <div>
                              <dt>Lease</dt>
                              <dd>{node.data.computerUse.leaseId ?? "none"}</dd>
                            </div>
                            {node.data.computerUse.toolRef ? (
                              <div>
                                <dt>Tool</dt>
                                <dd>{node.data.computerUse.toolRef}</dd>
                              </div>
                            ) : null}
                            <div>
                              <dt>Targeting</dt>
                              <dd>
                                {node.data.computerUse.targetCount ?? 0} targets ·{" "}
                                {node.data.computerUse.affordanceCount ?? 0} affordances
                              </dd>
                            </div>
                            {node.data.computerUse.browserDiscoveryRef ? (
                              <div>
                                <dt>Discovery</dt>
                                <dd>
                                  {[
                                    node.data.computerUse.browserDiscoveryRef,
                                    `${node.data.computerUse.browserProcessCount ?? 0} browsers`,
                                    `${node.data.computerUse.cdpEndpointCount ?? 0} CDP`,
                                    `${node.data.computerUse.defaultProfileBlockerCount ?? 0} blockers`,
                                  ].join(" · ")}
                                </dd>
                              </div>
                            ) : null}
                            {node.data.computerUse.controlledRelaunchLaunchRef ? (
                              <div>
                                <dt>Launch</dt>
                                <dd>
                                  {[
                                    node.data.computerUse
                                      .controlledRelaunchLaunchStatus,
                                    node.data.computerUse
                                      .controlledRelaunchLaunchRef,
                                    node.data.computerUse
                                      .controlledRelaunchEndpointRef,
                                  ]
                                    .filter(Boolean)
                                    .join(" · ")}
                                </dd>
                              </div>
                            ) : null}
                            <div>
                              <dt>Proposal</dt>
                              <dd>
                                {node.data.computerUse.proposalRef ?? "pending"}
                              </dd>
                            </div>
	                            <div>
	                              <dt>Action</dt>
	                              <dd>
	                                {node.data.computerUse.actionRef
                                  ? [
                                      node.data.computerUse.actionKind,
                                      node.data.computerUse.actionRef,
                                    ]
                                      .filter(Boolean)
                                      .join(" · ")
                                  : node.data.computerUse.proposalRef
                                    ? "not executed"
	                                    : "pending"}
	                              </dd>
	                            </div>
                            {node.data.computerUse.executionStatus ||
                            node.data.computerUse.executionProviderId ||
                            node.data.computerUse.executionAdapterId ? (
                              <div>
                                <dt>Executor</dt>
                                <dd>
                                  {[
                                    node.data.computerUse.executionStatus,
                                    node.data.computerUse.executionProviderId ??
                                      node.data.computerUse.executionAdapterId,
                                    node.data.computerUse
                                      .executionPreflightStatus
                                      ? `preflight ${node.data.computerUse.executionPreflightStatus}`
                                      : null,
                                    node.data.computerUse
                                      .executionRequiresReobserve === true
                                      ? "reobserve required"
                                      : null,
                                  ]
                                    .filter(Boolean)
                                    .join(" · ")}
                                </dd>
                              </div>
                            ) : null}
	                            <div>
	                              <dt>Verification</dt>
                              <dd>
                                {node.data.computerUse.verificationStatus ??
                                  node.data.computerUse.verificationRef ??
                                  "pending"}
                              </dd>
                            </div>
                            {node.data.computerUse.commitGateRef ||
                            node.data.computerUse.commitGateStatus ? (
                              <div>
                                <dt>Commit gate</dt>
                                <dd>
                                  {[
                                    node.data.computerUse.commitGateStatus,
                                    node.data.computerUse.commitGateRef,
                                  ]
                                    .filter(Boolean)
                                    .join(" · ")}
                                </dd>
                              </div>
                            ) : null}
                            {node.data.computerUse.outcomeRef ? (
                              <div>
                                <dt>Outcome</dt>
                                <dd>{node.data.computerUse.outcomeRef}</dd>
                              </div>
                            ) : null}
                            {node.data.computerUse.humanHandoffRef ? (
                              <div>
                                <dt>Handoff</dt>
                                <dd>{node.data.computerUse.humanHandoffRef}</dd>
                              </div>
                            ) : null}
                            <div>
                              <dt>Retention</dt>
                              <dd>
                                {node.data.computerUse.retentionMode ??
                                  "policy default"}
                              </dd>
                            </div>
                            <div>
                              <dt>Authority</dt>
                              <dd>
                                {node.data.computerUse.authorityScopes[0] ??
                                  node.data.computerUse.authorityRequired ??
                                  "policy default"}
                              </dd>
                            </div>
                            {node.data.computerUse.blocker ? (
                              <div>
                                <dt>Blocker</dt>
                                <dd>{node.data.computerUse.blocker}</dd>
                              </div>
                            ) : null}
                            {node.data.computerUse.recoveryPolicy ? (
                              <div>
                                <dt>Recovery</dt>
                                <dd>
                                  {String(
                                    node.data.computerUse.recoveryPolicy[
                                      "failure_class"
                                    ] ??
                                      node.data.computerUse.recoveryPolicy[
                                        "failureClass"
                                      ] ??
                                      "policy attached",
                                  )}
                                </dd>
                              </div>
                            ) : null}
                          </dl>
                        </div>
                      ) : null}
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
                      {node.data.codingToolBudgetRecoveryActions.length > 0 ? (
                        <div
                          className="workflow-run-coding-tool-budget-recovery-actions"
                          data-testid={`workflow-run-coding-tool-budget-recovery-actions-${node.id}`}
                          data-action-count={
                            node.data.codingToolBudgetRecoveryActions.length
                          }
                        >
                          {(() => {
                            const subflowSeed =
                              codingToolBudgetRecoverySubflowSeed(
                                node.data.codingToolBudgetRecoveryActions,
                              );
                            return subflowSeed ? (
                              <button
                                type="button"
                                className="workflow-secondary-action"
                                data-testid={`workflow-run-coding-tool-budget-recovery-subflow-${node.id}`}
                                data-source-event-id={
                                  subflowSeed.sourceEventId ?? ""
                                }
                                data-event-id={subflowSeed.eventId}
                                data-run-id={subflowSeed.runId ?? ""}
                                data-thread-id={subflowSeed.threadId}
                                data-workflow-graph-id={
                                  subflowSeed.workflowGraphId ?? ""
                                }
                                data-workflow-node-id={
                                  subflowSeed.workflowNodeId
                                }
                                data-target-node-ids={
                                  subflowSeed.targetNodeIds.join("|")
                                }
                                disabled={
                                  !onCreateRuntimeCodingToolBudgetRecoverySubflow
                                }
                                title="Create a prewired React Flow recovery sequence from this blocked budget row."
                                aria-label="Create coding-tool budget recovery subflow"
                                onClick={() => {
                                  onCreateRuntimeCodingToolBudgetRecoverySubflow?.(
                                    subflowSeed,
                                  );
                                }}
                              >
                                Create recovery subflow
                              </button>
                            ) : null;
                          })()}
                          {(() => {
                            const bindingSeed =
                              codingToolBudgetRecoverySubflowSeed(
                                node.data.codingToolBudgetRecoveryActions,
                              );
                            return bindingSeed ? (
                              <button
                                type="button"
                                className="workflow-secondary-action"
                                data-testid={`workflow-run-coding-tool-budget-recovery-bind-template-${node.id}`}
                                data-source-event-id={
                                  bindingSeed.sourceEventId ?? ""
                                }
                                data-event-id={bindingSeed.eventId}
                                data-run-id={bindingSeed.runId ?? ""}
                                data-thread-id={bindingSeed.threadId}
                                data-workflow-graph-id={
                                  bindingSeed.workflowGraphId ?? ""
                                }
                                data-workflow-node-id={
                                  bindingSeed.workflowNodeId
                                }
                                data-target-node-ids={
                                  bindingSeed.targetNodeIds.join("|")
                                }
                                disabled={
                                  !onBindRuntimeCodingToolBudgetRecoveryTemplate
                                }
                                title="Bind an existing reusable recovery template to this blocked budget evidence."
                                aria-label="Bind coding-tool budget recovery template"
                                onClick={() => {
                                  onBindRuntimeCodingToolBudgetRecoveryTemplate?.(
                                    bindingSeed,
                                  );
                                }}
                              >
                                Bind recovery template
                              </button>
                            ) : null;
                          })()}
                          {node.data.codingToolBudgetRecoveryActions.map((action) => (
                            <button
                              key={action.id}
                              type="button"
                              className="workflow-secondary-action"
                              data-testid={`workflow-run-coding-tool-budget-recovery-action-${action.action}`}
                              data-action-id={action.id}
                              data-action={action.action}
                              data-action-status={action.status}
                              data-thread-id={action.threadId}
                              data-run-id={action.runId ?? ""}
                              data-workflow-graph-id={
                                action.workflowGraphId ?? ""
                              }
                              data-workflow-node-id={action.workflowNodeId}
                              data-source-event-id={action.sourceEventId ?? ""}
                              data-event-id={action.eventId}
                              data-approval-id={action.approvalId ?? ""}
                              data-approval-request-event-id={
                                action.approvalRequestEventId ?? ""
                              }
                              data-approval-decision-event-id={
                                action.approvalDecisionEventId ?? ""
                              }
                              data-target-node-ids={
                                action.targetNodeIds.join("|")
                              }
                              data-receipt-refs={action.receiptRefs.join("|")}
                              data-policy-decision-refs={
                                action.policyDecisionRefs.join("|")
                              }
                              data-recovery-policy-schema-version={
                                action.recoveryPolicy?.schemaVersion ?? ""
                              }
                              data-recovery-policy-approval-scope={
                                action.recoveryPolicy?.approvalScope ?? ""
                              }
                              data-recovery-policy-operator-role={
                                action.recoveryPolicy?.operatorRole ?? ""
                              }
                              data-recovery-policy-retry-limit={
                                action.recoveryPolicy?.retryLimit ?? ""
                              }
                              data-recovery-policy-ttl-ms={
                                action.recoveryPolicy?.ttlMs ?? ""
                              }
                              data-recovery-policy-target-node-ids={
                                action.recoveryPolicy?.targetNodeIds.join("|") ?? ""
                              }
                              data-executable={action.executable}
                              title={action.summary ?? action.label}
                              aria-label={`${action.label} coding-tool budget recovery action`}
                              disabled={
                                (!action.executable &&
                                  action.action !== "review_receipt") ||
                                !onExecuteRuntimeCodingToolBudgetRecovery
                              }
                              onClick={() => {
                                void onExecuteRuntimeCodingToolBudgetRecovery?.(
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
              data-coding-tool-row-count={
                tuiControlStateProjection.codingToolRowCount
              }
              data-coding-tool-budget-row-count={
                tuiControlStateProjection.codingToolBudgetRowCount
              }
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
              data-source-filter={runtimeTelemetrySourceFilter}
              data-visible-row-count={visibleTuiControlStateRows.length}
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
                <span>
                  {tuiControlStateProjection.codingToolRowCount} coding tools
                </span>
                <span>
                  {tuiControlStateProjection.codingToolBudgetRowCount} coding
                  budgets
                </span>
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
                {visibleTuiControlStateRows.slice(-8).map((row) => (
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
                    data-tool-name={row.toolName ?? ""}
                    data-tool-call-id={row.toolCallId ?? ""}
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
                    data-coding-tool-budget-status={
                      row.codingToolBudgetStatus ?? ""
                    }
                    data-coding-tool-budget-reason={
                      row.codingToolBudgetReason ?? ""
                    }
                    data-coding-tool-context-budget-status={
                      row.codingToolContextBudgetStatus ?? ""
                    }
                    data-coding-tool-budget-mode={
                      row.codingToolBudgetMode ?? ""
                    }
                    data-coding-tool-budget-decision-id={
                      row.codingToolBudgetDecisionId ?? ""
                    }
                    data-coding-tool-budget-check-count={
                      row.codingToolBudgetCheckCount ?? ""
                    }
                    data-coding-tool-budget-violation-count={
                      row.codingToolBudgetViolationCount ?? ""
                    }
                    data-coding-tool-budget-usage-total-tokens={
                      row.codingToolBudgetUsageTotalTokens ?? ""
                    }
                    data-coding-tool-budget-usage-cost-estimate-usd={
                      row.codingToolBudgetUsageCostEstimateUsd ?? ""
                    }
                    data-coding-tool-budget-usage-context-pressure={
                      row.codingToolBudgetUsageContextPressure ?? ""
                    }
                    data-coding-tool-mutation-blocked={
                      row.codingToolMutationBlocked ?? ""
                    }
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
                    {row.rowKind === "coding_tool" ? (
                      <button
                        type="button"
                        className="workflow-secondary-action"
                        data-testid={`workflow-run-terminal-coding-loop-materialize-${row.id}`}
                        data-row-id={row.id}
                        data-thread-id={row.threadId ?? ""}
                        data-turn-id={row.turnId ?? ""}
                        data-tool-name={row.toolName ?? ""}
                        data-tool-call-id={row.toolCallId ?? ""}
                        data-event-id={row.eventId ?? ""}
                        data-cursor={row.cursor ?? ""}
                        disabled={!onMaterializeRuntimeTerminalCodingLoop}
                        title="Create or hydrate a React Flow terminal coding loop from this daemon-owned TUI coding-tool row."
                        aria-label="Create terminal coding loop"
                        onClick={() => {
                          onMaterializeRuntimeTerminalCodingLoop?.(row);
                        }}
                      >
                        Use terminal loop
                      </button>
                    ) : null}
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

function formatTelemetryCost(costEstimateUsd: number | null): string {
  if (costEstimateUsd === null) return "cost pending";
  return `$${costEstimateUsd.toFixed(6)}`;
}
