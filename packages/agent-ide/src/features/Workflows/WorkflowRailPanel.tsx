import { useState } from "react";
import type {
  GraphGlobalConfig,
  Node,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowCheckpoint,
  WorkflowConnectionClass,
  WorkflowDogfoodRun,
  WorkflowNodeFixture,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRightPanel,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowTestRunResult,
  WorkflowValidationResult,
} from "../../types/graph";
import { workflowInterruptPreview } from "../../runtime/workflow-bottom-panel-model";
import {
  harnessNodeEvidenceSummary,
  harnessSlotsForWorkflow,
  workflowHarnessWorkerBinding,
  workflowIsBlessedHarness,
  workflowIsHarness,
  workflowIsHarnessFork,
} from "../../runtime/harness-workflow";
import { workflowValuePreview } from "../../runtime/workflow-value-preview";
import {
  compareRunRecords,
  workflowBindingCheckResult,
  workflowBindingRegistryRows,
  workflowBindingRegistrySummary,
  workflowDurationLabel,
  workflowEnvironmentProfile,
  workflowEventLabel,
  workflowFileBundleItems,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeRunChildLineage,
  workflowNodeName,
  workflowRailSearchResults,
  workflowReadinessStatusLabel,
  workflowSelectedNodeBindingSummary,
  workflowWorkbenchCheckSummary,
  workflowWorkbenchCheckTitle,
  workflowTimeLabel,
} from "../../runtime/workflow-rail-model";

export function WorkflowRailPanel({
  panel,
  selectedNode,
  tests,
  proposals,
  runs,
  validationResult,
  readinessResult,
  testResult,
  workflow,
  lastRunResult,
  selectedRunId,
  compareRunResult,
  compareRunId,
  runEvents,
  dogfoodRun,
  portablePackage,
  bindingManifest,
  selectedNodeFixtures,
  checkpoints,
  onSelectRun,
  onCompareRun,
  onOpenExecutions,
  onInspectNode,
  onConfigureNode,
  onSelectProposal,
  onExportPackage,
  onOpenImportPackage,
  onGenerateBindingManifest,
  onUpdateEnvironmentProfile,
  onUpdateProductionProfile,
  onCheckBinding,
  onResolveIssue,
  onRunNode,
  onRunUpstream,
  onCaptureFixtureForNode,
  onDryRunFixtureForNode,
  onPinFixtureForNode,
  onAddTestFromOutput,
}: {
  panel: WorkflowRightPanel;
  selectedNode: Node | null;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  runs: WorkflowRunSummary[];
  validationResult: WorkflowValidationResult | null;
  readinessResult: WorkflowValidationResult | null;
  testResult: WorkflowTestRunResult | null;
  workflow: WorkflowProject;
  lastRunResult: WorkflowRunResult | null;
  selectedRunId: string | null;
  compareRunResult: WorkflowRunResult | null;
  compareRunId: string | null;
  runEvents: WorkflowStreamEvent[];
  dogfoodRun: WorkflowDogfoodRun | null;
  portablePackage: WorkflowPortablePackage | null;
  bindingManifest: WorkflowBindingManifest | null;
  selectedNodeFixtures: WorkflowNodeFixture[];
  checkpoints: WorkflowCheckpoint[];
  onSelectRun: (run: WorkflowRunSummary) => void;
  onCompareRun: (run: WorkflowRunSummary) => void;
  onOpenExecutions?: () => void;
  onInspectNode: (nodeId: string) => void;
  onConfigureNode: () => void;
  onSelectProposal: (proposal: WorkflowProposal) => void;
  onExportPackage: () => void;
  onOpenImportPackage: () => void;
  onGenerateBindingManifest: () => void;
  onUpdateEnvironmentProfile: (updates: Partial<NonNullable<GraphGlobalConfig["environmentProfile"]>>) => void;
  onUpdateProductionProfile: (updates: NonNullable<GraphGlobalConfig["production"]>) => void;
  onCheckBinding?: (
    row: ReturnType<typeof workflowBindingRegistryRows>[number],
  ) => WorkflowBindingCheckResult | Promise<WorkflowBindingCheckResult>;
  onResolveIssue: (issue: WorkflowValidationIssue) => void;
  onRunNode: (node: Node, fixture?: WorkflowNodeFixture) => void;
  onRunUpstream: (node: Node) => void;
  onCaptureFixtureForNode: (node: Node) => void;
  onDryRunFixtureForNode: (node: Node, fixture?: WorkflowNodeFixture) => void;
  onPinFixtureForNode: (node: Node, fixture: WorkflowNodeFixture) => void;
  onAddTestFromOutput: (node: Node) => void;
}) {
  const [railSearchQuery, setRailSearchQuery] = useState("");
  const [unitTestSearchQuery, setUnitTestSearchQuery] = useState("");
  const [runSearchQuery, setRunSearchQuery] = useState("");
  const [runStatusFilter, setRunStatusFilter] = useState<string>("all");
  const [bindingCheckResults, setBindingCheckResults] = useState<
    Record<string, WorkflowBindingCheckResult>
  >({});
  const normalizedRailSearch = railSearchQuery.trim().toLowerCase();
  const normalizedUnitTestSearch = unitTestSearchQuery.trim().toLowerCase();
  const normalizedRunSearch = runSearchQuery.trim().toLowerCase();
  const outputNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "output");
  const workflowSearchResults = workflowRailSearchResults(workflow, tests, normalizedRailSearch);
  const sourceAndTriggerNodes = workflow.nodes.filter(
    (nodeItem) => nodeItem.type === "source" || nodeItem.type === "trigger",
  );
  const triggerNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "trigger");
  const fileBundleItems = workflowFileBundleItems(
    workflow,
    tests,
    proposals,
    runs,
    portablePackage,
    bindingManifest,
  );
  const testResultById = new Map((testResult?.results ?? []).map((result) => [result.testId, result]));
  const filteredUnitTests = tests.filter((test) => {
    if (!normalizedUnitTestSearch) return true;
    return [
      test.id,
      test.name,
      test.status,
      test.lastMessage,
      test.assertion.kind,
      ...test.targetNodeIds,
    ].join(" ").toLowerCase().includes(normalizedUnitTestSearch);
  });
  const coveredNodeIds = new Set(tests.flatMap((test) => test.targetNodeIds));
  const uncoveredNodes = workflow.nodes.filter((nodeItem) => !coveredNodeIds.has(nodeItem.id));
  const testStatusCounts = tests.reduce(
    (counts, test) => {
      const status = test.status ?? "idle";
      counts[status] = (counts[status] ?? 0) + 1;
      return counts;
    },
    {} as Record<string, number>,
  );
  const modelBindingItems = Object.entries(workflow.global_config.modelBindings ?? {});
  const requiredCapabilityItems = Object.entries(workflow.global_config.requiredCapabilities ?? {}).filter(
    ([, requirement]) => requirement.required,
  );
  const workflowPolicy = workflow.global_config.policy;
  const productionProfile = workflow.global_config.production ?? {};
  const workflowReadOnly = workflow.metadata.readOnly === true;
  const harnessWorkflow = workflowIsHarness(workflow);
  const blessedHarnessWorkflow = workflowIsBlessedHarness(workflow);
  const harnessForkWorkflow = workflowIsHarnessFork(workflow);
  const harnessSlots = harnessSlotsForWorkflow(workflow);
  const harnessWorkerBinding = harnessWorkflow ? workflowHarnessWorkerBinding(workflow) : null;
  const boundHarnessSlotIds = new Set(workflow.nodes.flatMap((node) => node.runtimeBinding?.slotIds ?? []));
  const environmentProfile = workflowEnvironmentProfile(workflow);
  const bindingRegistryRows = workflowBindingRegistryRows(workflow);
  const bindingRegistrySummary = workflowBindingRegistrySummary(bindingRegistryRows);
  const handleCheckBinding = async (
    row: ReturnType<typeof workflowBindingRegistryRows>[number],
  ) => {
    let result: WorkflowBindingCheckResult;
    try {
      result = onCheckBinding
        ? await onCheckBinding(row)
        : workflowBindingCheckResult(row, environmentProfile);
    } catch (error) {
      const fallback = workflowBindingCheckResult(row, environmentProfile);
      result = {
        ...fallback,
        status: "blocked",
        summary: "Binding check could not run",
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    setBindingCheckResults((current) => ({
      ...current,
      [row.id]: result,
    }));
  };
  const hasErrorOrRetryPath =
    Boolean(productionProfile.errorWorkflowPath?.trim()) ||
    workflow.edges.some((edge) => {
      const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
      return edgeClass === "error" || edgeClass === "retry" || edge.fromPort === "error" || edge.fromPort === "retry";
    });
  const operationalSideEffectNodes = workflow.nodes.filter((nodeItem) => {
    const logic = nodeItem.config?.logic ?? {};
    if (nodeItem.type === "adapter") {
      const sideEffectClass = logic.connectorBinding?.sideEffectClass ?? "none";
      return !["none", "read"].includes(sideEffectClass);
    }
    if (nodeItem.type === "plugin_tool") {
      const sideEffectClass = logic.toolBinding?.sideEffectClass ?? "none";
      return !["none", "read"].includes(sideEffectClass);
    }
    if (nodeItem.type === "output") {
      const targetKind = logic.deliveryTarget?.targetKind ?? "none";
      return logic.materialization?.enabled === true || ["local_file", "repo_patch", "connector_write", "deploy"].includes(targetKind);
    }
    return false;
  });
  const criticalAiNodeIds = workflow.nodes.filter((nodeItem) => nodeItem.type === "model_call").map((nodeItem) => nodeItem.id);
  const mcpToolNodes = workflow.nodes.filter(
    (nodeItem) => nodeItem.type === "plugin_tool" && nodeItem.config?.logic?.toolBinding?.bindingKind === "mcp_tool",
  );
  if (panel === "unit_tests") {
    return (
      <>
        <h3>Unit tests</h3>
        <input
          data-testid="workflow-unit-test-search-input"
          placeholder="Search tests, assertions, targets..."
          value={unitTestSearchQuery}
          onChange={(event) => setUnitTestSearchQuery(event.target.value)}
        />
        <dl className="workflow-rail-stats" data-testid="workflow-unit-test-summary">
          <div>
            <dt>Total</dt>
            <dd>{tests.length}</dd>
          </div>
          <div>
            <dt>Covered</dt>
            <dd>{coveredNodeIds.size}</dd>
          </div>
          <div>
            <dt>Uncovered</dt>
            <dd>{uncoveredNodes.length}</dd>
          </div>
          <div>
            <dt>Last run</dt>
            <dd>{testResult?.status ?? "none"}</dd>
          </div>
        </dl>
        <p data-testid="workflow-unit-test-status-counts">
          Passed {testStatusCounts.passed ?? 0} · Failed {testStatusCounts.failed ?? 0} · Blocked {testStatusCounts.blocked ?? 0}
        </p>
        <div className="workflow-rail-list" data-testid="workflow-unit-test-list">
          {filteredUnitTests.map((test) => {
            const latestResult = testResultById.get(test.id);
            const targetNode = test.targetNodeIds[0]
              ? workflow.nodes.find((nodeItem) => nodeItem.id === test.targetNodeIds[0]) ?? null
              : null;
            return (
              <article key={test.id} className={`workflow-test-row is-${latestResult?.status ?? test.status ?? "idle"}`} data-testid={`workflow-unit-test-${test.id}`}>
                <strong>{test.name}</strong>
                <span>{latestResult?.message || test.lastMessage || `${test.targetNodeIds.length} covered targets`}</span>
                <small>{test.assertion.kind}</small>
                {targetNode ? (
                  <button
                    type="button"
                    className="workflow-inline-link"
                    data-testid={`workflow-unit-test-target-${test.id}`}
                    onClick={() => onInspectNode(targetNode.id)}
                  >
                    {targetNode.name}
                  </button>
                ) : null}
              </article>
            );
          })}
          {filteredUnitTests.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No matching tests</strong>
              <span>Try a test name, assertion kind, status, or target node id.</span>
            </article>
          ) : null}
        </div>
        {uncoveredNodes.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-unit-test-uncovered">
            <h4>Untested nodes</h4>
            {uncoveredNodes.slice(0, 6).map((nodeItem) => (
              <button
                key={nodeItem.id}
                type="button"
                className="workflow-search-result"
                data-testid={`workflow-unit-test-uncovered-${nodeItem.id}`}
                onClick={() => onInspectNode(nodeItem.id)}
              >
                <strong>{nodeItem.name}</strong>
                <span>{nodeItem.type} · {nodeItem.status ?? "idle"}</span>
              </button>
            ))}
          </section>
        ) : null}
      </>
    );
  }
  if (panel === "changes") {
    return (
      <>
        <h3>Changes</h3>
        <p>{proposals.length === 0 ? "No proposals for this workflow." : `${proposals.length} proposal${proposals.length === 1 ? "" : "s"} with bounded targets.`}</p>
        <div className="workflow-rail-list" data-testid="workflow-changes-list">
          {proposals.map((proposal) => (
            <button
              key={proposal.id}
              type="button"
              className={`workflow-proposal-card is-${proposal.status}`}
              data-testid={`workflow-change-proposal-${proposal.id}`}
              onClick={() => onSelectProposal(proposal)}
            >
              <strong>{proposal.title}</strong>
              <span>{proposal.status} · {proposal.boundedTargets.length} target{proposal.boundedTargets.length === 1 ? "" : "s"}</span>
              <small>{proposal.summary}</small>
              {proposal.boundedTargets.length > 0 ? (
                <code>{proposal.boundedTargets.slice(0, 4).join(", ")}</code>
              ) : null}
            </button>
          ))}
          {proposals.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No proposed changes</strong>
              <span>Create a proposal from validation blockers or the proposal node when a graph or code change should be reviewed.</span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "runs") {
    const selectedRun = lastRunResult?.summary.id === selectedRunId ? lastRunResult : null;
    const comparison =
      selectedRun && compareRunResult && compareRunResult.summary.id !== selectedRun.summary.id
        ? compareRunRecords(workflow, selectedRun, compareRunResult)
        : null;
    const defaultCompareRun = runs.find((run) => run.id !== selectedRunId);
    const timelineEvents = selectedRun?.events ?? runEvents;
    const interruptPreview = workflowInterruptPreview(lastRunResult);
    const runStatuses = Array.from(new Set(runs.map((run) => run.status))).sort();
    const filteredRuns = runs.filter((run) => {
      const matchesStatus = runStatusFilter === "all" || run.status === runStatusFilter;
      const matchesSearch =
        !normalizedRunSearch ||
        [run.id, run.status, run.summary]
          .join(" ")
          .toLowerCase()
          .includes(normalizedRunSearch);
      return matchesStatus && matchesSearch;
    });
    const visibleRuns = filteredRuns.slice(0, 8);
    return (
      <>
        <h3>Runs</h3>
        <p>
          {runs.length === 0
            ? "No runs yet."
            : `Showing ${visibleRuns.length} of ${filteredRuns.length} matching runs. Select one to inspect attempts and state changes.`}
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
        {runs.length > 0 ? (
          <div className="workflow-run-filters" data-testid="workflow-run-filters">
            <input
              data-testid="workflow-run-search-input"
              placeholder="Search runs..."
              value={runSearchQuery}
              onChange={(event) => setRunSearchQuery(event.target.value)}
            />
            <div className="workflow-node-group-filter" data-testid="workflow-run-status-filter">
              {["all", ...runStatuses].map((status) => (
                <button
                  key={status}
                  type="button"
                  className={runStatusFilter === status ? "is-active" : ""}
                  data-testid={`workflow-run-status-${status}`}
                  onClick={() => setRunStatusFilter(status)}
                >
                  {status}
                  <small>
                    {status === "all"
                      ? runs.length
                      : runs.filter((run) => run.status === status).length}
                  </small>
                </button>
              ))}
            </div>
          </div>
        ) : null}
        <div className="workflow-run-list" data-testid="workflow-runs-list">
          {visibleRuns.map((run) => (
            <button
              key={run.id}
              type="button"
              className={`workflow-run-card is-${run.status} ${selectedRunId === run.id ? "is-active" : ""} ${compareRunId === run.id ? "is-compare" : ""}`}
              data-testid={`workflow-run-${run.id}`}
              onClick={() => onSelectRun(run)}
            >
              <strong>{run.status}</strong>
              <span>{run.summary}</span>
              <small>
                {workflowDurationLabel(run.startedAtMs, run.finishedAtMs)} · {run.checkpointCount ?? 0} checkpoints
              </small>
            </button>
          ))}
          {runs.length > 0 && visibleRuns.length === 0 ? (
            <article className="workflow-output-row" data-testid="workflow-runs-empty-filtered">
              <strong>No matching runs</strong>
              <span>Adjust the status filter or search by run summary, status, or id.</span>
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
          <article className="workflow-run-comparison" data-testid="workflow-run-compare">
            <strong>Run comparison</strong>
            <span>
              {comparison.baselineStatus} to {comparison.targetStatus} · {comparison.changedNodes.length} node changes
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
                <dd>{comparison.checkpointDelta >= 0 ? "+" : ""}{comparison.checkpointDelta}</dd>
              </div>
              <div>
                <dt>Events</dt>
                <dd>{comparison.eventDelta >= 0 ? "+" : ""}{comparison.eventDelta}</dd>
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
                <span>{change.before}{" -> "}{change.after}</span>
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
        {lastRunResult?.interrupt ? (
          <article className="workflow-output-row" data-testid="workflow-run-interrupt">
            <strong>Paused at human input</strong>
            <span>{lastRunResult.interrupt.prompt}</span>
            {interruptPreview?.binding ? (
              <small data-testid="workflow-interrupt-preview">
                {interruptPreview.binding.bindingKind ?? "action"} · {interruptPreview.binding.ref ?? "configured node"} · {interruptPreview.binding.sideEffectClass ?? "side effect"}
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
                  onClick={() => onInspectNode(nodeRun.nodeId)}
                >
                  <strong>{workflowNodeName(workflow, nodeRun.nodeId)}</strong>
                  <span>{nodeRun.status} · attempt {nodeRun.attempt}</span>
                  <small>
                    {workflowDurationLabel(nodeRun.startedAtMs, nodeRun.finishedAtMs)}
                    {" · "}
                    {nodeRun.input === undefined ? "input not captured" : "input captured"}
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
                      Child run {childLineage.childRunStatus} · {childLineage.childRunId}
                    </small>
                  ) : null}
                </button>
              );
            })}
            <h4>Timeline</h4>
            <ol className="workflow-run-timeline" data-testid="workflow-run-timeline">
              {timelineEvents.slice(-10).map((event) => (
                <li key={event.id} className={`is-${event.status ?? event.kind}`}>
                  <strong>{workflowEventLabel(event)}</strong>
                  <span>{event.message ?? workflowNodeName(workflow, event.nodeId)}</span>
                  <small>{workflowTimeLabel(event.createdAtMs)}</small>
                </li>
              ))}
            </ol>
          </div>
        ) : null}
        {checkpoints.slice(0, 4).map((checkpoint) => (
          <article key={checkpoint.id} className="workflow-output-row" data-testid={`workflow-checkpoint-${checkpoint.id}`}>
            <strong>{checkpoint.status}</strong>
            <span>{checkpoint.summary}</span>
          </article>
        ))}
        {dogfoodRun ? (
          <article className="workflow-output-row" data-testid="workflow-dogfood-result">
            <strong>{workflowWorkbenchCheckTitle(dogfoodRun.status)}</strong>
            <span>{workflowWorkbenchCheckSummary(dogfoodRun.workflowPaths.length)}</span>
          </article>
        ) : null}
      </>
    );
  }
  if (panel === "readiness") {
    const result = readinessResult ?? validationResult;
    const blockers = result
      ? [
          ...result.errors,
          ...(result.executionReadinessIssues ?? []),
          ...result.missingConfig,
          ...result.connectorBindingIssues,
          ...(result.verificationIssues ?? []),
        ]
      : [];
    const readinessWarnings = result?.warnings ?? [];
    const policyRequiredNodeIds = result?.policyRequiredNodes ?? [];
    const hasIncomingConnectionClass = (nodeId: string, connectionClass: WorkflowConnectionClass) =>
      workflow.edges.some((edge) => {
        if (edge.to !== nodeId) return false;
        const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
        return edgeClass === connectionClass || edge.toPort === connectionClass;
      });
    const readinessItems = [
      { label: "Trigger or source", ready: workflow.nodes.some((node) => node.type === "trigger" || node.type === "source") },
      { label: "Model binding", ready: !workflow.nodes.some((node) => {
        if (node.type !== "model_call") return false;
        const modelRef = String(node.config?.logic?.modelRef ?? "");
        return !workflow.global_config.modelBindings?.[modelRef]?.modelId && !hasIncomingConnectionClass(node.id, "model");
      }) },
      { label: "Mock/live mode explicit", ready: !workflow.nodes.some((node) => {
        const logic = node.config?.logic ?? {};
        const binding = logic.toolBinding ?? logic.connectorBinding ?? logic.modelBinding ?? logic.parserBinding;
        return binding && typeof binding.mockBinding !== "boolean";
      }) },
      { label: "Live bindings for activation", ready: !workflow.nodes.some((node) => {
        const logic = node.config?.logic ?? {};
        const binding = logic.toolBinding ?? logic.connectorBinding ?? logic.modelBinding ?? logic.parserBinding;
        return binding?.mockBinding === true;
      }) },
      { label: "Error handling", ready: operationalSideEffectNodes.length === 0 || hasErrorOrRetryPath },
      { label: "Evaluation coverage", ready: criticalAiNodeIds.length === 0 || Boolean(productionProfile.evaluationSetPath?.trim()) || criticalAiNodeIds.every((nodeId) => coveredNodeIds.has(nodeId)) },
      { label: "Replay samples", ready: !readinessWarnings.some((issue: any) => issue.code === "missing_replay_fixture") },
      { label: "MCP access reviewed", ready: mcpToolNodes.length === 0 || productionProfile.mcpAccessReviewed === true },
      { label: "Value estimate", ready: Number(productionProfile.expectedTimeSavedMinutes ?? 0) > 0 },
      { label: "Outputs defined", ready: workflow.nodes.some((node) => node.type === "output") },
      { label: "Tests present", ready: tests.length > 0 },
      { label: "Harness slots", ready: !harnessWorkflow || harnessSlots.every((slot) => boundHarnessSlotIds.has(slot.slotId)) },
      { label: "Harness activation", ready: !harnessForkWorkflow || Boolean(workflow.metadata.harness?.activationId && workflow.metadata.harness?.activationState === "validated") },
      { label: "Readiness checked", ready: readinessResult !== null },
      { label: "No blockers", ready: blockers.length === 0 && result?.status !== "blocked" },
    ];
    const passedReadinessChecks = readinessItems.filter((item) => item.ready).length;
    const attentionIssues = [
      ...blockers.map((issue) => ({ issue, status: "blocked" as const })),
      ...readinessWarnings.map((issue) => ({ issue, status: "warning" as const })),
    ];
    return (
      <>
        <h3>Readiness</h3>
        <dl className="workflow-rail-stats" data-testid="workflow-readiness-summary">
          <div>
            <dt>Status</dt>
            <dd>{workflowReadinessStatusLabel(result)}</dd>
          </div>
          <div>
            <dt>Checks</dt>
            <dd>{passedReadinessChecks}/{readinessItems.length}</dd>
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
          <section className="workflow-rail-section" data-testid="workflow-readiness-attention">
            <h4>Needs attention</h4>
            {attentionIssues.slice(0, 4).map(({ issue, status }, index) => {
              const nodeName = issue.nodeId ? workflowNodeName(workflow, issue.nodeId) : "Workflow";
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
        <div className="workflow-rail-list" data-testid="workflow-readiness-checklist">
          {readinessItems.map((item) => (
            <article key={item.label} className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}>
              <strong>{item.label}</strong>
              <span>{item.ready ? "Ready" : "Needs attention"}</span>
            </article>
          ))}
        </div>
        {blockers.length > 0 ? (
          <section className="workflow-rail-section" data-testid="workflow-readiness-blockers">
            <h4>Blockers</h4>
            {blockers.slice(0, 8).map((issue: WorkflowValidationIssue, index) => {
              const nodeName = issue.nodeId ? workflowNodeName(workflow, issue.nodeId) : "Workflow";
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
          <section className="workflow-rail-section" data-testid="workflow-readiness-warnings">
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
          <section className="workflow-rail-section" data-testid="workflow-readiness-policy-nodes">
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
        <section className="workflow-package-readiness" data-testid="workflow-portable-package">
          <h4>Portable package</h4>
          <p>Export graph, tests, fixtures, functions, bindings, policies, and output definitions for another checkout.</p>
          <div className="workflow-package-actions">
            <button type="button" data-testid="workflow-export-package" onClick={onExportPackage}>Export package</button>
            <button type="button" data-testid="workflow-import-package-open" onClick={onOpenImportPackage}>Import package</button>
          </div>
          {portablePackage ? (
            <article className={`workflow-test-row is-${portablePackage.manifest.portable ? "passed" : "blocked"}`} data-testid="workflow-package-summary">
              <strong>{portablePackage.manifest.portable ? "Portable" : "Exported with blockers"}</strong>
              <span>{portablePackage.manifest.files.length} files, readiness {portablePackage.manifest.readinessStatus}</span>
            </article>
          ) : null}
        </section>
      </>
    );
  }
  if (panel === "search") {
    return (
      <>
        <h3>Search</h3>
        <input
          data-testid="workflow-rail-search-input"
          placeholder="Search nodes, tests, outputs..."
          value={railSearchQuery}
          onChange={(event) => setRailSearchQuery(event.target.value)}
        />
        <p>{workflow.nodes.length} nodes, {tests.length} tests, and {outputNodes.length} outputs indexed.</p>
        <div className="workflow-search-results" data-testid="workflow-rail-search-results">
          {workflowSearchResults.slice(0, 18).map((item) => (
            <button
              key={item.id}
              type="button"
              className="workflow-search-result"
              data-testid={`workflow-rail-search-result-${item.id}`}
              disabled={!item.nodeId}
              onClick={() => item.nodeId && onInspectNode(item.nodeId)}
            >
              <strong>{item.title}</strong>
              <span>{item.resultKind} · {item.subtitle}</span>
              {item.detail ? <small>{item.detail}</small> : null}
            </button>
          ))}
          {workflowSearchResults.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No matches</strong>
              <span>Try a node name, binding, test id, status, or output format.</span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "sources") {
    return (
      <>
        <h3>Sources</h3>
        <p>{sourceAndTriggerNodes.length === 0 ? "No start points configured." : `${sourceAndTriggerNodes.length} start point${sourceAndTriggerNodes.length === 1 ? "" : "s"} in this workflow.`}</p>
        <div className="workflow-rail-list" data-testid="workflow-sources-list">
          {sourceAndTriggerNodes.map((nodeItem) => {
            const logic = nodeItem.config?.logic ?? {};
            const sourceStatus =
              nodeItem.type === "trigger"
                ? logic.triggerKind === "scheduled"
                  ? logic.cronSchedule
                    ? "scheduled"
                    : "needs schedule"
                  : logic.triggerKind === "event"
                    ? logic.eventSourceRef
                      ? "event"
                      : "needs event source"
                    : "manual"
                : logic.payload === undefined
                  ? "needs payload"
                  : "payload ready";
            return (
              <button
                key={nodeItem.id}
                type="button"
                className="workflow-search-result"
                data-testid={`workflow-source-node-${nodeItem.id}`}
                onClick={() => onInspectNode(nodeItem.id)}
              >
                <strong>{nodeItem.name}</strong>
                <span>{nodeItem.type} · {sourceStatus}</span>
                <small>
                  {nodeItem.type === "trigger"
                    ? String(logic.eventSourceRef ?? logic.cronSchedule ?? logic.triggerKind ?? "manual")
                    : typeof logic.payload === "string"
                      ? logic.payload
                      : logic.payload === undefined
                        ? "No payload configured"
                        : "Structured payload configured"}
                </small>
              </button>
            );
          })}
        </div>
      </>
    );
  }
  if (panel === "files") {
    return (
      <>
        <h3>Files</h3>
        <p>Git-backed bundle surfaces stay separate from run state and local UI state.</p>
        <div className="workflow-rail-list" data-testid="workflow-files-list">
          {fileBundleItems.map((item) => (
            <article key={item.label} className="workflow-file-row">
              <strong>{item.label}</strong>
              <code>{item.path}</code>
              <span>{item.status}</span>
            </article>
          ))}
        </div>
      </>
    );
  }
  if (panel === "schedules") {
    return (
      <>
        <h3>Schedules</h3>
        <p>{triggerNodes.length === 0 ? "No trigger nodes configured." : `${triggerNodes.length} trigger node${triggerNodes.length === 1 ? "" : "s"} configured.`}</p>
        <div className="workflow-rail-list" data-testid="workflow-schedules-list">
          {triggerNodes.map((nodeItem) => {
            const logic = nodeItem.config?.logic ?? {};
            const triggerKind = logic.triggerKind ?? "manual";
            const ready =
              triggerKind === "scheduled"
                ? Boolean(logic.cronSchedule)
                : triggerKind === "event"
                  ? Boolean(logic.eventSourceRef)
                  : true;
            return (
              <button
                key={nodeItem.id}
                type="button"
                className={`workflow-search-result is-${ready ? "ready" : "blocked"}`}
                data-testid={`workflow-schedule-node-${nodeItem.id}`}
                onClick={() => onInspectNode(nodeItem.id)}
              >
                <strong>{nodeItem.name}</strong>
                <span>{triggerKind} · {ready ? "ready" : "needs configuration"}</span>
                <small>
                  {triggerKind === "scheduled"
                    ? String(logic.cronSchedule ?? "No schedule")
                    : triggerKind === "event"
                      ? String(logic.eventSourceRef ?? "No event source")
                      : "Manual invocation"}
                </small>
              </button>
            );
          })}
          {triggerNodes.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No trigger</strong>
              <span>Add a Trigger primitive when this workflow needs scheduled or event-driven execution.</span>
            </article>
          ) : null}
        </div>
      </>
    );
  }
  if (panel === "settings") {
    return (
      <>
        <h3>Settings</h3>
        <dl className="workflow-rail-stats" data-testid="workflow-settings-summary">
          <div>
            <dt>Kind</dt>
            <dd>{workflow.metadata.workflowKind}</dd>
          </div>
          <div>
            <dt>Mode</dt>
            <dd>{workflow.metadata.executionMode}</dd>
          </div>
          <div>
            <dt>Validation</dt>
            <dd>{validationResult?.status ?? "not run"}</dd>
          </div>
          <div>
            <dt>Readiness</dt>
            <dd>{readinessResult?.status ?? "not run"}</dd>
          </div>
        </dl>
        <section className="workflow-rail-section" data-testid="workflow-settings-metadata">
          <h4>Workflow</h4>
          <article className="workflow-file-row">
            <strong>{workflow.metadata.name}</strong>
            <code>{workflow.metadata.gitLocation || `.agents/workflows/${workflow.metadata.slug}.workflow.json`}</code>
            <span>{workflow.metadata.branch ?? "main"} · {workflow.metadata.dirty ? "modified" : "saved"}</span>
          </article>
        </section>
        {harnessWorkflow ? (
          <section className="workflow-rail-section" data-testid="workflow-settings-harness-summary">
            <h4>Harness</h4>
            <dl className="workflow-rail-stats">
              <div>
                <dt>Template</dt>
                <dd>{blessedHarnessWorkflow ? "blessed" : "fork"}</dd>
              </div>
              <div>
                <dt>Activation</dt>
                <dd>{workflow.metadata.harness?.activationId ?? workflow.metadata.harness?.activationState ?? "blocked"}</dd>
              </div>
              <div>
                <dt>Components</dt>
                <dd>{workflow.metadata.harness?.componentIds?.length ?? 0}</dd>
              </div>
              <div>
                <dt>Slots</dt>
                <dd>{harnessSlots.filter((slot) => boundHarnessSlotIds.has(slot.slotId)).length}/{harnessSlots.length}</dd>
              </div>
            </dl>
            {harnessWorkerBinding ? (
              <article className="workflow-output-row" data-testid="workflow-harness-worker-identity">
                <strong>{harnessWorkerBinding.harnessWorkflowId}</strong>
                <span>{harnessWorkerBinding.harnessActivationId ?? "activation blocked"}</span>
                <small>{harnessWorkerBinding.harnessHash}</small>
              </article>
            ) : null}
            {workflow.metadata.harness?.forkedFrom ? (
              <article className="workflow-output-row" data-testid="workflow-harness-lineage">
                <strong>Fork lineage</strong>
                <span>{workflow.metadata.harness.forkedFrom.harnessWorkflowId}</span>
                <small>{workflow.metadata.harness.forkedFrom.harnessHash}</small>
              </article>
            ) : null}
            <div className="workflow-rail-list" data-testid="workflow-harness-slots">
              {harnessSlots.map((slot) => {
                const ready = boundHarnessSlotIds.has(slot.slotId);
                return (
                  <article key={slot.slotId} className={`workflow-test-row is-${ready ? "passed" : "blocked"}`}>
                    <strong>{slot.label}</strong>
                    <span>{ready ? "bound" : "unbound"} · {slot.kind}</span>
                    <small>{slot.description}</small>
                  </article>
                );
              })}
            </div>
            {harnessForkWorkflow ? (
              <article className="workflow-output-row" data-testid="workflow-harness-activation-blockers">
                <strong>Activation blockers</strong>
                <span>
                  Blocked until validation passes, required slots stay bound,
                  replay evidence is present, and an activation id is minted.
                </span>
                <small>{workflow.metadata.harness?.activationState ?? "blocked"}</small>
              </article>
            ) : null}
          </section>
        ) : null}
        <section className="workflow-rail-section" data-testid="workflow-environment-profile">
          <h4>Environment</h4>
          <dl className="workflow-rail-stats">
            <div>
              <dt>Target</dt>
              <dd>{environmentProfile.target}</dd>
            </div>
            <div>
              <dt>Credentials</dt>
              <dd>{environmentProfile.credentialScope || "local"}</dd>
            </div>
            <div>
              <dt>Mock policy</dt>
              <dd>{environmentProfile.mockBindingPolicy || "warn"}</dd>
            </div>
            <div>
              <dt>Bindings</dt>
              <dd>{bindingRegistrySummary.ready}/{bindingRegistrySummary.total}</dd>
            </div>
          </dl>
          <div className="workflow-settings-production-editor">
            <label>
              Target
              <select
                data-testid="workflow-environment-target"
                value={environmentProfile.target}
                disabled={workflowReadOnly}
                onChange={(event) =>
                  onUpdateEnvironmentProfile({
                    target: event.target.value as NonNullable<GraphGlobalConfig["environmentProfile"]>["target"],
                  })
                }
              >
                <option value="local">Local</option>
                <option value="sandbox">Sandbox</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
              </select>
            </label>
            <label>
              Credential scope
              <input
                data-testid="workflow-environment-credential-scope"
                value={environmentProfile.credentialScope ?? ""}
                disabled={workflowReadOnly}
                placeholder="local, sandbox, staging, production"
                onChange={(event) => onUpdateEnvironmentProfile({ credentialScope: event.target.value })}
              />
            </label>
            <label>
              Mock bindings
              <select
                data-testid="workflow-environment-mock-policy"
                value={environmentProfile.mockBindingPolicy ?? "warn"}
                disabled={workflowReadOnly}
                onChange={(event) =>
                  onUpdateEnvironmentProfile({
                    mockBindingPolicy: event.target.value as NonNullable<GraphGlobalConfig["environmentProfile"]>["mockBindingPolicy"],
                  })
                }
              >
                <option value="allow">Allow in this environment</option>
                <option value="warn">Warn before activation</option>
                <option value="block">Block activation</option>
              </select>
            </label>
          </div>
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-binding-registry">
          <h4>Binding registry</h4>
          <dl className="workflow-rail-stats" data-testid="workflow-binding-registry-summary">
            <div>
              <dt>Total</dt>
              <dd>{bindingRegistrySummary.total}</dd>
            </div>
            <div>
              <dt>Ready</dt>
              <dd>{bindingRegistrySummary.ready}</dd>
            </div>
            <div>
              <dt>Mock</dt>
              <dd>{bindingRegistrySummary.mock}</dd>
            </div>
            <div>
              <dt>Approvals</dt>
              <dd>{bindingRegistrySummary.approval}</dd>
            </div>
          </dl>
          <div className="workflow-rail-list">
            {bindingRegistryRows.map((row) => (
              <article
                key={row.id}
                className={`workflow-binding-row is-${
                  bindingCheckResults[row.id]?.status ?? (row.ready ? "ready" : "blocked")
                }`}
                data-testid={`workflow-binding-registry-row-${row.nodeItem.id}`}
              >
                <header>
                  <div>
                    <strong>{row.nodeItem.name}</strong>
                    <span>
                      {row.bindingKind} · {row.mode} · {row.ready ? "ready" : "needs setup"}
                    </span>
                  </div>
                  <div className="workflow-binding-actions">
                    <button
                      type="button"
                      data-testid={`workflow-binding-check-${row.id}`}
                      onClick={() => void handleCheckBinding(row)}
                    >
                      Check
                    </button>
                    <button
                      type="button"
                      data-testid={`workflow-binding-inspect-${row.nodeItem.id}`}
                      onClick={() => onInspectNode(row.nodeItem.id)}
                    >
                      Configure
                    </button>
                  </div>
                </header>
                <dl>
                  <div>
                    <dt>Ref</dt>
                    <dd>{row.ref || "not set"}</dd>
                  </div>
                  <div>
                    <dt>Scope</dt>
                    <dd>{row.scope}</dd>
                  </div>
                  <div>
                    <dt>Side effect</dt>
                    <dd>{row.sideEffectClass}</dd>
                  </div>
                  <div>
                    <dt>Approval</dt>
                    <dd>{row.approval}</dd>
                  </div>
                </dl>
                {bindingCheckResults[row.id] ? (
                  <p
                    className="workflow-binding-check-result"
                    data-testid={`workflow-binding-check-result-${row.id}`}
                    data-status={bindingCheckResults[row.id].status}
                  >
                    <strong>{bindingCheckResults[row.id].summary}</strong>
                    <span>{bindingCheckResults[row.id].detail}</span>
                  </p>
                ) : null}
              </article>
            ))}
            {bindingRegistryRows.length === 0 ? (
              <article className="workflow-output-row">
                <strong>No bindings</strong>
                <span>Add model, connector, parser, or tool primitives to populate this registry.</span>
              </article>
            ) : null}
          </div>
        </section>
        <section className="workflow-rail-section" data-testid="workflow-binding-manifest">
          <h4>Binding manifest</h4>
          <div className="workflow-package-actions">
            <button
              type="button"
              data-testid="workflow-generate-binding-manifest"
              onClick={onGenerateBindingManifest}
            >
              Refresh manifest
            </button>
          </div>
          {bindingManifest ? (
            <>
              <dl className="workflow-rail-stats" data-testid="workflow-binding-manifest-summary">
                <div>
                  <dt>Total</dt>
                  <dd>{bindingManifest.summary.total}</dd>
                </div>
                <div>
                  <dt>Ready</dt>
                  <dd>{bindingManifest.summary.ready}</dd>
                </div>
                <div>
                  <dt>Blocked</dt>
                  <dd>{bindingManifest.summary.blocked}</dd>
                </div>
                <div>
                  <dt>Approvals</dt>
                  <dd>{bindingManifest.summary.approvalRequired}</dd>
                </div>
              </dl>
              <p data-testid="workflow-binding-manifest-environment">
                {bindingManifest.environmentProfile.target} · {bindingManifest.environmentProfile.credentialScope ?? "local"} · mocks {bindingManifest.environmentProfile.mockBindingPolicy ?? "block"}
              </p>
            </>
          ) : (
            <article className="workflow-output-row">
              <strong>No manifest generated</strong>
              <span>Refresh after binding changes to capture environment readiness for packaging.</span>
            </article>
          )}
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-model-bindings">
          <h4>Model bindings</h4>
          {modelBindingItems.map(([bindingKey, binding]) => (
            <article key={bindingKey} className={`workflow-test-row is-${binding.modelId ? "passed" : binding.required ? "blocked" : "idle"}`}>
              <strong>{bindingKey}</strong>
              <span>{binding.modelId || (binding.required ? "required" : "optional")}</span>
            </article>
          ))}
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-capabilities">
          <h4>Required capabilities</h4>
          {requiredCapabilityItems.length > 0 ? (
            requiredCapabilityItems.map(([capability, requirement]) => (
              <article key={capability} className="workflow-output-row">
                <strong>{capability}</strong>
                <span>{requirement.bindingKey ? `binding: ${requirement.bindingKey}` : requirement.notes ?? "required"}</span>
              </article>
            ))
          ) : (
            <article className="workflow-output-row">
              <strong>No required capabilities</strong>
              <span>Nodes can still declare their own binding requirements.</span>
            </article>
          )}
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-policy">
          <h4>Run policy</h4>
          <dl className="workflow-rail-stats">
            <div>
              <dt>Budget</dt>
              <dd>{workflowPolicy.maxBudget}</dd>
            </div>
            <div>
              <dt>Steps</dt>
              <dd>{workflowPolicy.maxSteps}</dd>
            </div>
            <div>
              <dt>Timeout</dt>
              <dd>{workflowPolicy.timeoutMs} ms</dd>
            </div>
            <div>
              <dt>Package</dt>
              <dd>{portablePackage ? portablePackage.manifest.readinessStatus : "not exported"}</dd>
            </div>
          </dl>
        </section>
        <section className="workflow-rail-section" data-testid="workflow-settings-production-profile">
          <h4>Production checklist</h4>
          <dl className="workflow-rail-stats">
            <div>
              <dt>Error path</dt>
              <dd>{productionProfile.errorWorkflowPath || (hasErrorOrRetryPath ? "graph path" : "not set")}</dd>
            </div>
            <div>
              <dt>Evaluations</dt>
              <dd>{productionProfile.evaluationSetPath || `${criticalAiNodeIds.length} model node${criticalAiNodeIds.length === 1 ? "" : "s"}`}</dd>
            </div>
            <div>
              <dt>Value estimate</dt>
              <dd>{productionProfile.expectedTimeSavedMinutes ? `${productionProfile.expectedTimeSavedMinutes} min/run` : "not set"}</dd>
            </div>
            <div>
              <dt>MCP access</dt>
              <dd>{mcpToolNodes.length === 0 ? "not used" : productionProfile.mcpAccessReviewed ? "reviewed" : "needs review"}</dd>
            </div>
          </dl>
          <div className="workflow-settings-production-editor" data-testid="workflow-production-profile-editor">
            <label>
              Error workflow path
              <input
                data-testid="workflow-production-error-path"
                value={productionProfile.errorWorkflowPath ?? ""}
                disabled={workflowReadOnly}
                placeholder=".agents/workflows/error-handler.workflow.json"
                onChange={(event) => onUpdateProductionProfile({ errorWorkflowPath: event.target.value })}
              />
            </label>
            <label>
              Evaluation set path
              <input
                data-testid="workflow-production-evaluation-path"
                value={productionProfile.evaluationSetPath ?? ""}
                disabled={workflowReadOnly}
                placeholder=".agents/workflows/evaluations/reporting.tests.json"
                onChange={(event) => onUpdateProductionProfile({ evaluationSetPath: event.target.value })}
              />
            </label>
            <label>
              Expected time saved per run
              <input
                data-testid="workflow-production-time-saved"
                type="number"
                min={0}
                step={1}
                value={productionProfile.expectedTimeSavedMinutes ?? 0}
                disabled={workflowReadOnly}
                onChange={(event) =>
                  onUpdateProductionProfile({
                    expectedTimeSavedMinutes: Number(event.target.value || 0),
                  })
                }
              />
            </label>
            <label className="workflow-config-checkbox">
              <input
                data-testid="workflow-production-mcp-reviewed"
                type="checkbox"
                checked={productionProfile.mcpAccessReviewed === true}
                disabled={workflowReadOnly}
                onChange={(event) => onUpdateProductionProfile({ mcpAccessReviewed: event.target.checked })}
              />
              MCP access reviewed
            </label>
          </div>
        </section>
      </>
    );
  }
  const selectedNodeRun = selectedNode
    ? lastRunResult?.nodeRuns.find((nodeRun) => nodeRun.nodeId === selectedNode.id) ?? null
    : null;
  const selectedNodeIssues = selectedNode
    ? [
        ...(validationResult?.errors ?? []),
        ...(validationResult?.warnings ?? []),
        ...(validationResult?.missingConfig ?? []),
        ...(validationResult?.connectorBindingIssues ?? []),
        ...(validationResult?.executionReadinessIssues ?? []),
        ...(validationResult?.verificationIssues ?? []),
        ...(readinessResult?.errors ?? []),
        ...(readinessResult?.warnings ?? []),
        ...(readinessResult?.missingConfig ?? []),
        ...(readinessResult?.connectorBindingIssues ?? []),
        ...(readinessResult?.executionReadinessIssues ?? []),
        ...(readinessResult?.verificationIssues ?? []),
      ].filter((issue) => issue.nodeId === selectedNode.id)
    : [];
  const selectedNodeTests = selectedNode
    ? tests.filter((test) => test.targetNodeIds.includes(selectedNode.id))
    : [];
  const selectedInputPorts = selectedNode?.ports?.filter((port) => port.direction === "input") ?? [];
  const selectedOutputPorts = selectedNode?.ports?.filter((port) => port.direction === "output") ?? [];
  const selectedLogic = selectedNode?.config?.logic ?? {};
  const bindingSummary = selectedNode ? workflowSelectedNodeBindingSummary(selectedNode, selectedLogic) : [];
  const selectedHarnessEvidence = selectedNode ? harnessNodeEvidenceSummary(selectedNode) : [];
  const selectedPinnedFixture =
    selectedNodeFixtures.find((fixture) => fixture.pinned) ??
    selectedNodeFixtures[0] ??
    null;
  const selectedStaleFixtureCount = selectedNodeFixtures.filter(
    (fixture) => fixture.stale || fixture.validationStatus === "stale",
  ).length;
  const selectedInputPreview = workflowValuePreview(
    selectedNodeRun?.input ?? selectedPinnedFixture?.input ?? selectedLogic.payload ?? null,
  );
  const selectedOutputPreview = workflowValuePreview(
    selectedNodeRun?.output ?? selectedPinnedFixture?.output ?? null,
  );
  const selectedErrorPreview = workflowValuePreview(selectedNodeRun?.error ?? null);
  const selectedAttachmentEdges = selectedNode
    ? workflow.edges.filter((edge) => {
        if (edge.to !== selectedNode.id) return false;
        const edgeClass = edge.connectionClass ?? edge.data?.connectionClass;
        return ["model", "memory", "tool", "parser", "approval"].includes(String(edgeClass));
      })
    : [];
  const selectedAttachmentNodeById = new Map(workflow.nodes.map((nodeItem) => [nodeItem.id, nodeItem]));
  const selectedAttachmentRows = selectedAttachmentEdges.map((edge) => {
    const edgeClass = String(edge.connectionClass ?? edge.data?.connectionClass ?? edge.toPort ?? "data");
    const sourceNode = selectedAttachmentNodeById.get(edge.from);
    return {
      id: edge.id,
      edgeClass,
      nodeId: sourceNode?.id ?? edge.from,
      nodeName: sourceNode?.name ?? edge.from,
      nodeType: sourceNode?.type ?? "node",
    };
  });
  const showAiCluster =
    selectedNode?.type === "model_call" ||
    selectedNode?.config?.logic?.viewMacro?.expandedFrom === "agent_loop_macro" ||
    selectedAttachmentRows.length > 0;
  const hasAttachmentClass = (connectionClass: string) =>
    selectedAttachmentRows.some((row) => row.edgeClass === connectionClass);
  const modelBindingReady =
    bindingSummary.find((item) => item.label === "Model")?.ready ??
    hasAttachmentClass("model");
  const parserReady =
    hasAttachmentClass("parser") ||
    Boolean(selectedLogic.parserBinding?.resultSchema || selectedLogic.outputSchema);
  const toolRows = selectedAttachmentRows.filter((row) => row.edgeClass === "tool");
  const approvalRows = selectedAttachmentRows.filter((row) => row.edgeClass === "approval");
  const memoryReady = hasAttachmentClass("memory") || hasAttachmentClass("state");
  return (
    <>
      <h3>Outputs</h3>
      {selectedNode ? (
        <section className="workflow-node-inspector" data-testid="workflow-selected-node-inspector">
          <header>
            <div>
              <strong>{selectedNode.name}</strong>
              <span>{selectedNode.type} · {selectedNodeRun?.status ?? selectedNode.status ?? "idle"}</span>
            </div>
            <button
              type="button"
              data-testid="workflow-rail-configure-node"
              disabled={workflowReadOnly}
              onClick={onConfigureNode}
            >
              Configure
            </button>
          </header>
          <section
            className="workflow-node-inspector-lifecycle"
            data-testid="workflow-selected-node-quick-actions"
          >
            <button
              type="button"
              data-testid="workflow-inspector-run-node"
              disabled={workflowReadOnly}
              onClick={() => onRunNode(selectedNode, selectedPinnedFixture ?? undefined)}
            >
              Execute node
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-run-upstream"
              disabled={workflowReadOnly}
              onClick={() => onRunUpstream(selectedNode)}
            >
              Execute upstream
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-replay-fixture"
              disabled={workflowReadOnly || !selectedPinnedFixture}
              onClick={() =>
                onDryRunFixtureForNode(selectedNode, selectedPinnedFixture ?? undefined)
              }
            >
              Replay fixture
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-capture-fixture"
              disabled={workflowReadOnly}
              onClick={() => onCaptureFixtureForNode(selectedNode)}
            >
              Capture fixture
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-pin-fixture"
              disabled={workflowReadOnly || !selectedPinnedFixture || selectedPinnedFixture.pinned === true}
              onClick={() => {
                if (selectedPinnedFixture) {
                  onPinFixtureForNode(selectedNode, selectedPinnedFixture);
                }
              }}
            >
              Pin fixture
            </button>
            <button
              type="button"
              data-testid="workflow-inspector-add-test-from-output"
              disabled={workflowReadOnly}
              onClick={() => onAddTestFromOutput(selectedNode)}
            >
              Add test from output
            </button>
          </section>
          <dl className="workflow-node-inspector-stats" data-testid="workflow-selected-node-status">
            <div>
              <dt>Run</dt>
              <dd>{selectedNodeRun?.status ?? "not run"}</dd>
            </div>
            <div>
              <dt>Attempt</dt>
              <dd>{selectedNodeRun?.attempt ?? "none"}</dd>
            </div>
            <div>
              <dt>Tests</dt>
              <dd>{selectedNodeTests.length}</dd>
            </div>
            <div>
              <dt>Issues</dt>
              <dd>{selectedNodeIssues.length}</dd>
            </div>
          </dl>
          {selectedHarnessEvidence.length > 0 ? (
            <section
              className="workflow-node-inspector-section"
              data-testid="workflow-selected-node-harness-component"
            >
              <h4>Harness component</h4>
              <div className="workflow-rail-list" data-testid="workflow-selected-node-harness-receipts">
                {selectedHarnessEvidence.map((item) => (
                  <article key={item.label} className="workflow-output-row">
                    <strong>{item.label}</strong>
                    <span>{item.value}</span>
                  </article>
                ))}
              </div>
              {selectedNode.runtimeBinding ? (
                <article className="workflow-output-row" data-testid="workflow-selected-node-replay-binding">
                  <strong>Replay envelope</strong>
                  <span>
                    {selectedNode.runtimeBinding.replay.deterministicEnvelope ? "deterministic" : "best effort"}
                    {" · "}
                    {selectedNode.runtimeBinding.slotIds?.join(", ") || "no slots"}
                  </span>
                  <small>
                    {selectedNode.runtimeBinding.evidenceEventKinds.join(", ")}
                  </small>
                </article>
              ) : null}
            </section>
          ) : null}
          <section
            className="workflow-node-inspector-zones"
            data-testid="workflow-selected-node-io-workbench"
          >
            <article data-testid="workflow-selected-node-input-zone">
              <header>
                <strong>Input</strong>
                <span>
                  {selectedNodeRun
                    ? "latest run"
                    : selectedPinnedFixture
                      ? "pinned fixture"
                      : "empty"}
                </span>
              </header>
              <span>{selectedInputPreview.summary}</span>
              <small>{selectedInputPreview.detail}</small>
            </article>
            <article data-testid="workflow-selected-node-config-zone">
              <header>
                <strong>Config</strong>
                <span>
                  {bindingSummary.every((item) => item.ready)
                    ? "ready"
                    : "needs setup"}
                </span>
              </header>
              <span>
                {bindingSummary
                  .map((item) => `${item.label}: ${item.value}`)
                  .join(" · ") || "basic settings"}
              </span>
              <small>
                {selectedNodeFixtures.length} fixture
                {selectedNodeFixtures.length === 1 ? "" : "s"}
                {selectedStaleFixtureCount > 0
                  ? ` · ${selectedStaleFixtureCount} stale`
                  : ""}
              </small>
            </article>
            <article data-testid="workflow-selected-node-output-zone">
              <header>
                <strong>Output</strong>
                <span>{selectedNodeRun?.status ?? "not run"}</span>
              </header>
              <span>{selectedOutputPreview.summary}</span>
              <small>
                {selectedNodeRun?.error
                  ? selectedErrorPreview.summary
                  : selectedOutputPreview.detail}
              </small>
            </article>
          </section>
          {showAiCluster ? (
            <section
              className="workflow-node-inspector-section workflow-node-ai-cluster"
              data-testid="workflow-selected-node-ai-cluster"
            >
              <h4>AI cluster</h4>
              <dl className="workflow-node-inspector-ai-grid">
                <div data-status={modelBindingReady ? "ready" : "blocked"}>
                  <dt>Model</dt>
                  <dd>{modelBindingReady ? "ready" : "missing"}</dd>
                </div>
                <div data-status={memoryReady ? "ready" : "idle"}>
                  <dt>Memory</dt>
                  <dd>{memoryReady ? "connected" : "none"}</dd>
                </div>
                <div data-status={toolRows.length > 0 ? "ready" : "idle"}>
                  <dt>Tools</dt>
                  <dd>
                    {toolRows.length}
                    {approvalRows.length > 0 ? " · approval" : ""}
                  </dd>
                </div>
                <div data-status={parserReady ? "ready" : "idle"}>
                  <dt>Parser</dt>
                  <dd>{parserReady ? "schema ready" : "none"}</dd>
                </div>
              </dl>
              {selectedAttachmentRows.length > 0 ? (
                <div className="workflow-node-ai-attachments">
                  {selectedAttachmentRows.map((row) => (
                    <button
                      key={row.id}
                      type="button"
                      data-testid="workflow-selected-node-ai-attachment"
                      data-connection-class={row.edgeClass}
                      onClick={() => onInspectNode(row.nodeId)}
                    >
                      <strong>{row.nodeName}</strong>
                      <span>{row.edgeClass} · {row.nodeType}</span>
                    </button>
                  ))}
                </div>
              ) : null}
            </section>
          ) : null}
          <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-ports">
            <h4>Ports</h4>
            <div className="workflow-node-inspector-port-groups">
              <div>
                <span>Inputs</span>
                {selectedInputPorts.length > 0
                  ? selectedInputPorts.map((port) => (
                      <em key={`input-${port.id}`} data-connection-class={port.connectionClass}>
                        {port.label} · {port.connectionClass}
                      </em>
                    ))
                  : <small>none</small>}
              </div>
              <div>
                <span>Outputs</span>
                {selectedOutputPorts.length > 0
                  ? selectedOutputPorts.map((port) => (
                      <em key={`output-${port.id}`} data-connection-class={port.connectionClass}>
                        {port.label} · {port.connectionClass}
                      </em>
                    ))
                  : <small>none</small>}
              </div>
            </div>
          </section>
          <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-bindings">
            <h4>Configuration</h4>
            {bindingSummary.map((item) => (
              <article key={item.label} className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}>
                <strong>{item.label}</strong>
                <span>{item.value}</span>
              </article>
            ))}
          </section>
          {selectedNodeIssues.length > 0 ? (
            <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-blockers">
              <h4>Needs attention</h4>
              {selectedNodeIssues.slice(0, 5).map((issue, index) => (
                <button
                  key={`${issue.code}-${index}`}
                  type="button"
                  className="workflow-search-result is-blocked"
                  data-testid={`workflow-selected-node-issue-${index}`}
                  onClick={() => onResolveIssue(issue)}
                >
                  <strong>{workflowIssueTitle(issue)}</strong>
                  <span>{issue.message}</span>
                  <small>{workflowIssueActionLabel(issue)}</small>
                </button>
              ))}
            </section>
          ) : null}
          {selectedNodeRun?.output !== undefined ? (
            <section className="workflow-node-inspector-section" data-testid="workflow-selected-node-latest-output">
              <h4>Latest output</h4>
              {(() => {
                const preview = workflowValuePreview(selectedNodeRun.output);
                return (
                  <article className="workflow-output-row" data-testid="workflow-selected-node-latest-output-preview">
                    <strong>{preview.kind}</strong>
                    <span>{preview.summary}</span>
                    <small>{preview.detail}</small>
                  </article>
                );
              })()}
            </section>
          ) : null}
        </section>
      ) : (
        <>
          <p>{outputNodes.length === 0 ? "No output nodes configured." : `${outputNodes.length} workflow output${outputNodes.length === 1 ? "" : "s"} configured.`}</p>
          <div className="workflow-rail-list" data-testid="workflow-output-node-list">
            {outputNodes.map((nodeItem) => {
              const logic = nodeItem.config?.logic ?? {};
              return (
                <button
                  key={nodeItem.id}
                  type="button"
                  className="workflow-search-result"
                  data-testid={`workflow-output-node-${nodeItem.id}`}
                  onClick={() => onInspectNode(nodeItem.id)}
                >
                  <strong>{nodeItem.name}</strong>
                  <span>{String(logic.format ?? "output")} · {String(logic.deliveryTarget?.targetKind ?? "no delivery")}</span>
                  <small>
                    {logic.materialization?.enabled
                      ? `asset: ${logic.materialization.assetPath ?? "configured"}`
                      : "renderer-only until materialization or delivery is configured"}
                  </small>
                </button>
              );
            })}
            {outputNodes.length === 0 ? (
              <article className="workflow-output-row">
                <strong>No outputs</strong>
                <span>Add an Output primitive to define what the workflow produces.</span>
              </article>
            ) : null}
          </div>
        </>
      )}
    </>
  );
}
