import type {
  Node,
  WorkflowBottomPanel,
  WorkflowCheckpoint,
  WorkflowDogfoodRun,
  WorkflowNodeFixture,
  WorkflowNodeRun,
  WorkflowProject,
  WorkflowProposal,
  WorkflowResumeRequest,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowValidationResult,
} from "../../types/graph";
import {
  workflowBottomSuggestions,
  workflowBottomValidationIssueItems,
  workflowInterruptPreview,
  workflowSelectedNodeValidationIssues,
} from "../../runtime/workflow-bottom-panel-model";
import { workflowFunctionDryRunView } from "../../runtime/workflow-composer-model";
import { workflowFixtureSourceLabel } from "../../runtime/workflow-fixture-model";
import {
  compareRunRecords,
  workflowDurationLabel,
  workflowEventLabel,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeRunChildLineage,
  workflowNodeName,
  workflowWorkbenchCheckSummary,
  workflowWorkbenchCheckTitle,
  workflowTimeLabel,
} from "../../runtime/workflow-rail-model";
import {
  workflowNodeHasDeclaredOutputSchema,
  workflowNodeDeclaredInputSchema,
  workflowNodeDeclaredOutputSchema,
} from "../../runtime/workflow-schema";
import {
  workflowConfiguredFieldNames,
  workflowValuePreview,
} from "../../runtime/workflow-value-preview";

export function WorkflowBottomShelf({
  panel,
  selectedNode,
  selectedNodeRun,
  tests,
  proposals,
  testResult,
  validationResult,
  runs,
  lastRunResult,
  runDetailLoading,
  compareRunResult,
  workflow,
  functionDryRunResult,
  dogfoodRun,
  fixtures,
  runEvents,
  checkpoints,
  logs,
  onCaptureFixture,
  onPinFixture,
  onDryRunFixture,
  onResumeRun,
  onInspectNode,
}: {
  panel: WorkflowBottomPanel;
  selectedNode: Node | null;
  selectedNodeRun: WorkflowNodeRun | null;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  testResult: WorkflowTestRunResult | null;
  validationResult: WorkflowValidationResult | null;
  runs: WorkflowRunSummary[];
  lastRunResult: WorkflowRunResult | null;
  runDetailLoading: boolean;
  compareRunResult: WorkflowRunResult | null;
  workflow: WorkflowProject;
  functionDryRunResult: WorkflowRunResult | null;
  dogfoodRun: WorkflowDogfoodRun | null;
  fixtures: WorkflowNodeFixture[];
  runEvents: WorkflowStreamEvent[];
  checkpoints: WorkflowCheckpoint[];
  logs: any[];
  onCaptureFixture: () => void | undefined;
  onPinFixture: (fixture: WorkflowNodeFixture) => void | undefined;
  onDryRunFixture: (fixture?: WorkflowNodeFixture) => void | undefined;
  onResumeRun: (outcome: WorkflowResumeRequest["outcome"]) => void;
  onInspectNode: (nodeId: string) => void;
}) {
  const interruptPreview = workflowInterruptPreview(lastRunResult);
  const selectedInputPorts = selectedNode?.ports?.filter((port) => port.direction === "input") ?? [];
  const selectedOutputPorts = selectedNode?.ports?.filter((port) => port.direction === "output") ?? [];
  const selectedIncomingEdges = selectedNode ? workflow.edges.filter((edge) => edge.to === selectedNode.id) : [];
  const selectedOutgoingEdges = selectedNode ? workflow.edges.filter((edge) => edge.from === selectedNode.id) : [];
  const selectedCoverage = selectedNode ? validationResult?.coverageByNodeId[selectedNode.id] ?? [] : [];
  const validationIssueItems = workflowBottomValidationIssueItems(validationResult);
  const validationIssuesForSelectedNode = workflowSelectedNodeValidationIssues(
    selectedNodeRun,
    selectedNode?.id,
    validationIssueItems,
  );
  const outputNodes = workflow.nodes.filter((nodeItem) => nodeItem.type === "output");
  const bottomSuggestions = workflowBottomSuggestions({
    workflow,
    tests,
    proposals,
    validationResult,
    validationIssueItems,
  });
  if (panel === "selection") {
    const configuredFields = workflowConfiguredFieldNames(selectedNode?.config?.logic ?? {});
    const latestInputPreview = workflowValuePreview(selectedNodeRun?.input);
    const latestOutputPreview = workflowValuePreview(selectedNodeRun?.output);
    return selectedNode ? (
      <div className="workflow-bottom-grid" data-testid="workflow-selection-preview">
        <dl data-testid="workflow-selection-summary">
          <dt>Node</dt>
          <dd>{selectedNode.name}</dd>
          <dt>Type</dt>
          <dd>{selectedNode.type}</dd>
          <dt>Status</dt>
          <dd>{selectedNodeRun?.status || selectedNode.status || "idle"}</dd>
          <dt>Attempt</dt>
          <dd>{selectedNodeRun?.attempt ?? "not run"}</dd>
          <dt>Started</dt>
          <dd>{selectedNodeRun?.startedAtMs ? new Date(selectedNodeRun.startedAtMs).toLocaleTimeString() : "none"}</dd>
          <dt>Ports</dt>
          <dd>{selectedInputPorts.length} in / {selectedOutputPorts.length} out</dd>
          <dt>Tests</dt>
          <dd>{selectedCoverage.length}</dd>
          <dt>Issues</dt>
          <dd>{validationIssuesForSelectedNode.length}</dd>
        </dl>
        <div className="workflow-selection-detail-list" data-testid="workflow-selection-detail-list">
          <article className="workflow-output-row" data-testid="workflow-selection-config">
            <strong>Configuration</strong>
            <span>
              {configuredFields.length > 0
                ? `${configuredFields.length} configured field${configuredFields.length === 1 ? "" : "s"}`
                : "Using default configuration for this primitive."}
            </span>
            {configuredFields.length > 0 ? (
              <small>{configuredFields.slice(0, 10).join(", ")}</small>
            ) : null}
          </article>
          <article
            className={`workflow-test-row is-${selectedNodeRun?.status ?? "idle"}`}
            data-testid="workflow-selection-run-card"
          >
            <strong>Recent run</strong>
            <span>
              {selectedNodeRun
                ? `${selectedNodeRun.status} · attempt ${selectedNodeRun.attempt} · ${workflowDurationLabel(
                    selectedNodeRun.startedAtMs,
                    selectedNodeRun.finishedAtMs,
                  )}`
                : "This node has not run in the current session."}
            </span>
            <small>{selectedNodeRun?.error ?? latestInputPreview.detail}</small>
          </article>
          {selectedNodeRun?.output !== undefined ? (
            <article className="workflow-output-row" data-testid="workflow-selection-output-preview">
              <strong>Latest output</strong>
              <span>{latestOutputPreview.summary}</span>
              <small>{latestOutputPreview.detail}</small>
            </article>
          ) : null}
          {validationIssuesForSelectedNode.length > 0 ? (
            <article className="workflow-output-row is-warning" data-testid="workflow-selection-issue-preview">
              <strong>Needs attention</strong>
              <span>{validationIssuesForSelectedNode[0]?.issue.message}</span>
              <small>
                {validationIssuesForSelectedNode.length} issue{validationIssuesForSelectedNode.length === 1 ? "" : "s"} on this node
              </small>
            </article>
          ) : null}
        </div>
      </div>
    ) : (
      <p>Select a single node to preview configuration, schema, sample data, and recent status.</p>
    );
  }
  if (panel === "data") {
    const latestInputPreview = workflowValuePreview(selectedNodeRun?.input);
    const latestOutputPreview = workflowValuePreview(selectedNodeRun?.output);
    const latestPayloadSnapshot = selectedNode
      ? {
          inputSchema: workflowNodeDeclaredInputSchema(selectedNode),
          outputSchema: workflowNodeDeclaredOutputSchema(selectedNode, selectedNodeRun?.output),
          incomingEdges: selectedIncomingEdges.map((edge) => ({
            from: edge.from,
            fromPort: edge.fromPort,
            toPort: edge.toPort,
            connectionClass: edge.connectionClass ?? edge.type,
          })),
          outgoingEdges: selectedOutgoingEdges.map((edge) => ({
            to: edge.to,
            fromPort: edge.fromPort,
            toPort: edge.toPort,
            connectionClass: edge.connectionClass ?? edge.type,
          })),
          input: selectedNodeRun?.input ?? null,
          output: selectedNodeRun?.output ?? null,
          error: selectedNodeRun?.error ?? null,
        }
      : null;
    return selectedNode ? (
      <div className="workflow-bottom-grid workflow-bottom-data-grid" data-testid="workflow-bottom-data-preview">
        <dl data-testid="workflow-bottom-data-summary">
          <dt>Latest output</dt>
          <dd>{selectedNodeRun?.output !== undefined ? "available" : "not run"}</dd>
          <dt>Error</dt>
          <dd>{selectedNodeRun?.error ?? "none"}</dd>
          <dt>Incoming</dt>
          <dd>{selectedIncomingEdges.length}</dd>
          <dt>Outgoing</dt>
          <dd>{selectedOutgoingEdges.length}</dd>
          <dt>Input schema</dt>
          <dd>{workflowNodeDeclaredInputSchema(selectedNode) ? "declared" : "none"}</dd>
          <dt>Output schema</dt>
          <dd>{workflowNodeDeclaredOutputSchema(selectedNode, selectedNodeRun?.output) ? "declared" : "none"}</dd>
        </dl>
        <div className="workflow-bottom-stack">
          <section data-testid="workflow-bottom-port-map">
            <h4>Port map</h4>
            <div className="workflow-bottom-port-grid">
              <div>
                <strong>Inputs</strong>
                {selectedInputPorts.length > 0 ? (
                  selectedInputPorts.map((port) => (
                    <span key={`input-${port.id}`} data-connection-class={port.connectionClass}>
                      {port.label} · {port.connectionClass}
                    </span>
                  ))
                ) : (
                  <small>none</small>
                )}
              </div>
              <div>
                <strong>Outputs</strong>
                {selectedOutputPorts.length > 0 ? (
                  selectedOutputPorts.map((port) => (
                    <span key={`output-${port.id}`} data-connection-class={port.connectionClass}>
                      {port.label} · {port.connectionClass}
                    </span>
                  ))
                ) : (
                  <small>none</small>
                )}
              </div>
            </div>
          </section>
          <section data-testid="workflow-bottom-latest-payload">
            <h4>Latest values</h4>
            <div className="workflow-selection-detail-list">
              <article className="workflow-output-row" data-testid="workflow-bottom-latest-input-preview">
                <strong>Input</strong>
                <span>{latestInputPreview.summary}</span>
                <small>{latestInputPreview.detail}</small>
              </article>
              <article className="workflow-output-row" data-testid="workflow-bottom-latest-output-preview">
                <strong>Output</strong>
                <span>{latestOutputPreview.summary}</span>
                <small>{latestOutputPreview.detail}</small>
              </article>
            </div>
            <details className="workflow-config-json-details">
              <summary>Raw payload snapshot</summary>
              <pre>{JSON.stringify(latestPayloadSnapshot, null, 2)}</pre>
            </details>
          </section>
        </div>
      </div>
    ) : (
      <p>Select a node to preview its latest payload.</p>
    );
  }
  if (panel === "test_output") {
    return testResult ? (
      <div className="workflow-bottom-grid" data-testid="workflow-bottom-test-output">
        <dl>
          <dt>Passed</dt>
          <dd>{testResult.passed}</dd>
          <dt>Failed</dt>
          <dd>{testResult.failed}</dd>
          <dt>Blocked</dt>
          <dd>{testResult.blocked}</dd>
          <dt>Skipped</dt>
          <dd>{testResult.skipped}</dd>
        </dl>
        <div className="workflow-bottom-test-list" data-testid="workflow-bottom-test-list">
          {testResult.results.map((result) => {
            const test = tests.find((item) => item.id === result.testId);
            return (
              <article
                key={result.testId}
                className={`workflow-test-row is-${result.status}`}
                data-testid="workflow-bottom-test-row"
              >
                <strong>{test?.name ?? result.testId}</strong>
                <span>{result.message}</span>
                <small>{test?.assertion.kind ?? "assertion"} · {result.status}</small>
                {result.coveredNodeIds.length > 0 ? (
                  <div className="workflow-test-targets" data-testid="workflow-bottom-test-targets">
                    {result.coveredNodeIds.slice(0, 6).map((nodeId) => (
                      <button key={nodeId} type="button" onClick={() => onInspectNode(nodeId)}>
                        {workflowNodeName(workflow, nodeId)}
                      </button>
                    ))}
                  </div>
                ) : null}
              </article>
            );
          })}
        </div>
      </div>
    ) : (
      <p>{tests.length} unit tests are ready to run.</p>
    );
  }
  if (panel === "fixtures") {
    const staleFixtureCount = fixtures.filter((fixture) => fixture.stale).length;
    const currentFixtureCount = fixtures.length - staleFixtureCount;
    const hasDeclaredOutputSchema = selectedNode ? workflowNodeHasDeclaredOutputSchema(selectedNode) : false;
    const schemaStatus =
      currentFixtureCount > 0
        ? hasDeclaredOutputSchema ? "declared" : "not declared"
        : staleFixtureCount > 0
          ? `${staleFixtureCount} stale`
          : hasDeclaredOutputSchema ? "declared" : "not declared";
    const replayPosture =
      currentFixtureCount > 0
        ? "ready"
        : staleFixtureCount > 0 ? "refresh recommended" : "needs sample";
    return selectedNode ? (
      <div className="workflow-bottom-grid" data-testid="workflow-fixtures-panel">
        <dl>
          <dt>Node</dt>
          <dd>{selectedNode.name}</dd>
          <dt>Fixtures</dt>
          <dd>{fixtures.length}</dd>
          <dt>Fixture source</dt>
          <dd>{fixtures[0]?.sourceRunId ? "captured from run" : selectedNode.config?.logic?.testInput ? "configured" : "not captured"}</dd>
          <dt>Schema status</dt>
          <dd>{schemaStatus}</dd>
          <dt>Replay posture</dt>
          <dd>{replayPosture}</dd>
        </dl>
        <div>
          {staleFixtureCount > 0 && currentFixtureCount === 0 ? (
            <p className="workflow-fixture-stale" data-testid="workflow-bottom-fixture-stale">
              Captured samples no longer match this node's saved schema or configuration hash.
            </p>
          ) : staleFixtureCount > 0 ? (
            <p className="workflow-fixture-note" data-testid="workflow-bottom-fixture-stale">
              {staleFixtureCount} older sample{staleFixtureCount === 1 ? "" : "s"} need refresh; the selected sample is current.
            </p>
          ) : null}
          <div className="workflow-fixture-actions">
            <button type="button" data-testid="workflow-bottom-capture-fixture" onClick={onCaptureFixture}>
              Capture latest sample
            </button>
            <button
              type="button"
              data-testid="workflow-bottom-replay-fixture"
              disabled={fixtures.length === 0}
              onClick={() => onDryRunFixture(fixtures[0])}
            >
              Replay selected node
            </button>
          </div>
          <div className="workflow-bottom-fixture-list" data-testid="workflow-bottom-fixture-list">
            {fixtures.length > 0 ? (
              fixtures.slice(0, 4).map((fixture) => (
                <article
                  key={fixture.id}
                  className={`workflow-fixture-card${fixture.stale ? " is-stale" : ""}`}
                  data-testid="workflow-bottom-fixture-card"
                >
                  <div>
                    <strong>{fixture.name}</strong>
                    <span>
                      {fixture.pinned ? "pinned · " : ""}
                      {workflowFixtureSourceLabel(fixture)} · {workflowTimeLabel(fixture.createdAtMs)}
                    </span>
                    <small data-testid="workflow-bottom-fixture-validation">
                      {fixture.validationStatus ?? "not_declared"}
                      {fixture.validationMessage ? ` · ${fixture.validationMessage}` : ""}
                    </small>
                  </div>
                  <div className="workflow-fixture-card-actions">
                    <button type="button" data-testid="workflow-bottom-fixture-pin" disabled={fixture.pinned === true} onClick={() => onPinFixture(fixture)}>
                      {fixture.pinned ? "Pinned" : "Pin"}
                    </button>
                    <button type="button" data-testid="workflow-bottom-fixture-replay" onClick={() => onDryRunFixture(fixture)}>
                      Replay
                    </button>
                  </div>
                  <pre data-testid="workflow-bottom-fixture-input">{JSON.stringify(fixture.input ?? null, null, 2)}</pre>
                  <pre data-testid="workflow-bottom-fixture-output">{JSON.stringify(fixture.output ?? null, null, 2)}</pre>
                </article>
              ))
            ) : (
              <div className="workflow-fixture-card" data-testid="workflow-bottom-fixture-empty">
                <div>
                  <strong>No fixture sample</strong>
                  <span>Capture the latest run sample or import JSON from node configuration.</span>
                </div>
                <pre>{JSON.stringify({
                  configuredInput: selectedNode.config?.logic?.testInput ?? selectedNode.config?.logic?.functionBinding?.testInput ?? null,
                  latestOutput: selectedNodeRun?.output ?? null,
                }, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      </div>
    ) : (
      <p>Select a node to inspect fixture input, captured output, and stale schema status.</p>
    );
  }
  if (panel === "checkpoints") {
    return checkpoints.length > 0 ? (
      <div className="workflow-bottom-grid" data-testid="workflow-checkpoints-panel">
        <dl>
          <dt>Checkpoints</dt>
          <dd>{checkpoints.length}</dd>
          <dt>Latest</dt>
          <dd>{checkpoints[0]?.status ?? "none"}</dd>
          <dt>Thread</dt>
          <dd>{checkpoints[0]?.threadId ?? "none"}</dd>
        </dl>
        <div className="workflow-checkpoint-list" data-testid="workflow-checkpoint-history">
          {checkpoints.slice(0, 8).map((checkpoint) => (
            <article
              key={checkpoint.id}
              className={`workflow-checkpoint-card is-${checkpoint.status}`}
              data-testid="workflow-checkpoint-card"
            >
              <div>
                <strong>{checkpoint.summary}</strong>
                <span>
                  Step {checkpoint.stepIndex} · {workflowNodeName(workflow, checkpoint.nodeId)}
                </span>
              </div>
              <dl>
                <div>
                  <dt>Status</dt>
                  <dd>{checkpoint.status}</dd>
                </div>
                <div>
                  <dt>Run</dt>
                  <dd>{checkpoint.runId}</dd>
                </div>
                <div>
                  <dt>Saved</dt>
                  <dd>{workflowTimeLabel(checkpoint.createdAtMs)}</dd>
                </div>
              </dl>
            </article>
          ))}
        </div>
      </div>
    ) : (
      <p>Checkpoints appear here after a run starts.</p>
    );
  }
  if (panel === "proposal_diff") {
    const latestProposal = proposals[0] ?? null;
    const graphDiff = latestProposal?.graphDiff ?? {};
    const configDiff = latestProposal?.configDiff ?? {};
    const sidecarDiff = latestProposal?.sidecarDiff ?? {};
    const graphChangeCount =
      (graphDiff.addedNodeIds?.length ?? 0) +
      (graphDiff.removedNodeIds?.length ?? 0) +
      (graphDiff.changedNodeIds?.length ?? 0);
    const configChangeCount =
      (configDiff.changedNodeIds?.length ?? 0) +
      (configDiff.changedGlobalKeys?.length ?? 0) +
      (configDiff.changedMetadataKeys?.length ?? 0);
    const sidecarRoles = sidecarDiff.changedRoles ?? [];
    const changedNodeIds = Array.from(new Set([
      ...(graphDiff.addedNodeIds ?? []),
      ...(graphDiff.removedNodeIds ?? []),
      ...(graphDiff.changedNodeIds ?? []),
      ...(configDiff.changedNodeIds ?? []),
    ]));
    return (
      <div className="workflow-bottom-grid" data-testid="workflow-proposal-diff-panel">
        <dl>
          <dt>Open proposals</dt>
          <dd>{proposals.length}</dd>
          <dt>Latest</dt>
          <dd>{latestProposal?.status ?? "none"}</dd>
          <dt>Bounds</dt>
          <dd>{latestProposal?.boundedTargets.length ?? 0}</dd>
        </dl>
        {latestProposal ? (
          <article
            className={`workflow-proposal-review-card is-${latestProposal.status}`}
            data-testid="workflow-bottom-proposal-card"
          >
            <header>
              <div>
                <strong>{latestProposal.title}</strong>
                <span>{latestProposal.summary}</span>
              </div>
              <em>{latestProposal.status}</em>
            </header>
            <dl data-testid="workflow-bottom-proposal-impact">
              <div>
                <dt>Graph</dt>
                <dd>{graphChangeCount} changes</dd>
              </div>
              <div>
                <dt>Config</dt>
                <dd>{configChangeCount} changes</dd>
              </div>
              <div>
                <dt>Sidecars</dt>
                <dd>{sidecarRoles.length} roles</dd>
              </div>
            </dl>
            <div className="workflow-proposal-targets" data-testid="workflow-bottom-proposal-targets">
              {latestProposal.boundedTargets.slice(0, 8).map((target) => (
                <code key={target}>{target}</code>
              ))}
              {latestProposal.boundedTargets.length > 8 ? (
                <code>+{latestProposal.boundedTargets.length - 8}</code>
              ) : null}
            </div>
            {changedNodeIds.length > 0 ? (
              <div className="workflow-proposal-node-list" data-testid="workflow-bottom-proposal-nodes">
                {changedNodeIds.slice(0, 8).map((nodeId) => (
                  <button key={nodeId} type="button" onClick={() => onInspectNode(nodeId)}>
                    <strong>{workflowNodeName(workflow, nodeId)}</strong>
                    <span>{nodeId}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p>No node-level changes declared.</p>
            )}
            {latestProposal.codeDiff ? (
              <section data-testid="workflow-bottom-proposal-code-summary">
                <strong>Code or function diff</strong>
                <span>{latestProposal.codeDiff}</span>
              </section>
            ) : null}
          </article>
        ) : (
          <p>No proposals are open.</p>
        )}
      </div>
    );
  }
  if (panel === "run_output") {
    const dryRunView = workflowFunctionDryRunView(functionDryRunResult);
    const dryRunPayloadPreview = workflowValuePreview(dryRunView?.resultPayload);
    const comparison =
      lastRunResult && compareRunResult && compareRunResult.summary.id !== lastRunResult.summary.id
        ? compareRunRecords(workflow, lastRunResult, compareRunResult)
        : null;
    const latestRun = runs[0]
      ? {
          id: runs[0].id,
          threadId: runs[0].threadId,
          status: runs[0].status,
          startedAtMs: runs[0].startedAtMs,
          finishedAtMs: runs[0].finishedAtMs,
          nodeCount: runs[0].nodeCount,
          testCount: runs[0].testCount,
          checkpointCount: runs[0].checkpointCount,
          interruptId: runs[0].interruptId,
          summary: runs[0].summary,
        }
      : null;
    const showRuntimeLogs = logs.length > 0 && !latestRun;
    const showWorkflowChecks = dogfoodRun && !latestRun && logs.length === 0;
    return dryRunView ? (
      <div className="workflow-bottom-grid workflow-function-dry-run-report" data-testid="workflow-function-dry-run-bottom">
        <dl>
          <dt>Status</dt>
          <dd>{dryRunView.status}</dd>
          <dt>Node</dt>
          <dd>{dryRunView.nodeRun?.nodeId ?? "function"}</dd>
          <dt>Attempt</dt>
          <dd>{dryRunView.nodeRun?.attempt ?? 1}</dd>
          <dt>Sandbox</dt>
          <dd>{Object.keys(dryRunView.sandbox).length > 0 ? "configured" : "default"}</dd>
        </dl>
        <div className="workflow-function-dry-run-result">
          <section data-testid="workflow-bottom-dry-run-payload">
            <strong>Result</strong>
            <div className="workflow-node-value-preview" data-testid="workflow-bottom-dry-run-payload-preview">
              <span>{dryRunPayloadPreview.summary}</span>
              <small>{dryRunPayloadPreview.detail}</small>
            </div>
            <details className="workflow-config-json-details">
              <summary>Raw result payload</summary>
              <pre>{JSON.stringify(dryRunView.resultPayload, null, 2)}</pre>
            </details>
          </section>
          <section data-testid="workflow-bottom-dry-run-stdout">
            <strong>Stdout</strong>
            <pre>{dryRunView.stdout || "No stdout captured."}</pre>
          </section>
          <section data-testid="workflow-bottom-dry-run-stderr">
            <strong>Stderr</strong>
            <pre>{dryRunView.stderr || dryRunView.error || "No stderr captured."}</pre>
          </section>
        </div>
      </div>
    ) : showWorkflowChecks ? (
      <div className="workflow-bottom-grid" data-testid="workflow-dogfood-bottom">
        <dl>
          <dt>Status</dt>
          <dd>{dogfoodRun.status}</dd>
          <dt>Workflows</dt>
          <dd>{dogfoodRun.workflowPaths.length}</dd>
        </dl>
        <article className={`workflow-output-row is-${dogfoodRun.status}`} data-testid="workflow-validation-suite-summary">
          <strong>{workflowWorkbenchCheckTitle(dogfoodRun.status)}</strong>
          <span>
            {workflowWorkbenchCheckSummary(dogfoodRun.workflowPaths.length)}
          </span>
        </article>
      </div>
    ) : showRuntimeLogs ? (
      <div className="workflow-bottom-list" data-testid="workflow-bottom-runtime-log-list">
        {logs.slice(-6).map((entry, index) => {
          const preview = workflowValuePreview(entry);
          return (
            <article key={`runtime-log-${index}`} className="workflow-output-row" data-testid="workflow-bottom-runtime-log-row">
              <strong>{preview.kind}</strong>
              <span>{preview.summary}</span>
              <small>{preview.detail}</small>
            </article>
          );
        })}
      </div>
    ) : latestRun ? (
      <div className="workflow-bottom-grid workflow-run-detail-grid" data-testid="workflow-run-detail">
        <dl>
          <dt>Status</dt>
          <dd>{latestRun.status}</dd>
          <dt>Summary</dt>
          <dd>{latestRun.summary}</dd>
          <dt>Checkpoints</dt>
          <dd>{latestRun.checkpointCount ?? checkpoints.length}</dd>
          <dt>Events</dt>
          <dd>{runEvents.length}</dd>
          <dt>Duration</dt>
          <dd>{workflowDurationLabel(latestRun.startedAtMs, latestRun.finishedAtMs)}</dd>
        </dl>
        <div className="workflow-run-detail">
          {lastRunResult?.interrupt ? (
            <div className="workflow-run-actions" data-testid="workflow-run-interrupt-actions">
              <strong>{lastRunResult.interrupt.prompt}</strong>
              {interruptPreview?.binding ? (
                <span data-testid="workflow-run-action-preview">
                  {interruptPreview.binding.bindingKind ?? "action"} · {interruptPreview.binding.ref ?? "configured node"} · {interruptPreview.binding.sideEffectClass ?? "side effect"}
                </span>
              ) : null}
              <button type="button" data-testid="workflow-approve-resume" onClick={() => onResumeRun("approve")}>Approve and resume</button>
              <button type="button" data-testid="workflow-reject-run" onClick={() => onResumeRun("reject")}>Reject</button>
            </div>
          ) : null}
          {lastRunResult ? (
            <>
              {comparison ? (
                <section className="workflow-run-comparison workflow-run-comparison--bottom" data-testid="workflow-bottom-run-compare">
                  <strong>Compared with {comparison.baselineRunId}</strong>
                  <dl>
                    <div>
                      <dt>Status</dt>
                      <dd>{comparison.baselineStatus}{" -> "}{comparison.targetStatus}</dd>
                    </div>
                    <div>
                      <dt>Node changes</dt>
                      <dd>{comparison.changedNodes.length}</dd>
                    </div>
                    <div>
                      <dt>State changes</dt>
                      <dd>{comparison.stateChanges.length}</dd>
                    </div>
                    <div>
                      <dt>Events</dt>
                      <dd>{comparison.eventDelta >= 0 ? "+" : ""}{comparison.eventDelta}</dd>
                    </div>
                  </dl>
                  <div className="workflow-run-comparison-list" data-testid="workflow-bottom-run-compare-nodes">
                    {comparison.changedNodes.length > 0 ? (
                      comparison.changedNodes.slice(0, 6).map((change) => (
                        <button
                          key={change.nodeId}
                          type="button"
                          className="workflow-run-comparison-node"
                          data-testid={`workflow-bottom-run-compare-node-${change.nodeId}`}
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
                      ))
                    ) : (
                      <article className="workflow-run-comparison-node">
                        <strong>No node changes</strong>
                        <span>Node status, input, output, and error fingerprints match.</span>
                      </article>
                    )}
                  </div>
                  <div className="workflow-run-comparison-list" data-testid="workflow-bottom-run-compare-state">
                    {comparison.stateChanges.length > 0 ? (
                      comparison.stateChanges.slice(0, 8).map((change) => (
                        <article key={change.key} className="workflow-run-comparison-node">
                          <strong>{change.key}</strong>
                          <span>{change.change}</span>
                        </article>
                      ))
                    ) : (
                      <article className="workflow-run-comparison-node">
                        <strong>No state changes</strong>
                        <span>Final state keys match between the selected runs.</span>
                      </article>
                    )}
                  </div>
                </section>
              ) : null}
              <div className="workflow-run-attempt-grid" data-testid="workflow-run-node-attempts">
                {lastRunResult.nodeRuns.map((nodeRun) => {
                  const childLineage = workflowNodeRunChildLineage(nodeRun);
                  return (
                    <button
                      key={`${nodeRun.nodeId}-${nodeRun.attempt}-${nodeRun.startedAtMs}`}
                      type="button"
                      className={`workflow-run-attempt is-${nodeRun.status}`}
                      onClick={() => onInspectNode(nodeRun.nodeId)}
                    >
                      <strong>{workflowNodeName(workflow, nodeRun.nodeId)}</strong>
                      <span>{nodeRun.status} · attempt {nodeRun.attempt}</span>
                      <small>
                        {nodeRun.error ?? workflowDurationLabel(nodeRun.startedAtMs, nodeRun.finishedAtMs)}
                        {" · "}
                        {nodeRun.input === undefined ? "input not captured" : "input captured"}
                      </small>
                      {childLineage ? (
                        <small
                          className="workflow-run-child-lineage"
                          data-testid="workflow-bottom-child-lineage"
                          data-node-id={nodeRun.nodeId}
                        >
                          Child run {childLineage.childRunStatus} · {childLineage.childRunId}
                        </small>
                      ) : null}
                    </button>
                  );
                })}
              </div>
              <ol className="workflow-run-timeline" data-testid="workflow-bottom-run-timeline">
                {lastRunResult.events.map((event) => (
                  <li key={event.id} className={`is-${event.status ?? event.kind}`}>
                    <strong>{workflowEventLabel(event)}</strong>
                    <span>{event.message ?? workflowNodeName(workflow, event.nodeId)}</span>
                    <small>{workflowTimeLabel(event.createdAtMs)}</small>
                  </li>
                ))}
              </ol>
              <details className="workflow-run-payload" data-testid="workflow-run-payload">
                <summary>State and node outputs</summary>
                <pre>{JSON.stringify({
                  completedNodes: lastRunResult.finalState.completedNodeIds,
                  blockedNodes: lastRunResult.finalState.blockedNodeIds,
                  interruptedNodes: lastRunResult.finalState.interruptedNodeIds,
                  branchDecisions: lastRunResult.finalState.branchDecisions,
                  nodeOutputs: lastRunResult.finalState.nodeOutputs,
                }, null, 2)}</pre>
              </details>
            </>
          ) : (
            <div className="workflow-bottom-stack" data-testid="workflow-run-summary-fallback">
              <article className={`workflow-output-row is-${latestRun.status}`}>
                <strong>Run {latestRun.status}</strong>
                <span>{latestRun.summary}</span>
                <small>
                  {latestRun.nodeCount} node{latestRun.nodeCount === 1 ? "" : "s"} · {workflowDurationLabel(latestRun.startedAtMs, latestRun.finishedAtMs)}
                </small>
              </article>
              {runEvents.slice(-8).length > 0 ? (
                <ol className="workflow-run-timeline" data-testid="workflow-run-event-snapshot">
                  {runEvents.slice(-8).map((event) => (
                    <li key={event.id} className={`is-${event.status ?? event.kind}`}>
                      <strong>{workflowEventLabel(event)}</strong>
                      <span>{event.message ?? workflowNodeName(workflow, event.nodeId)}</span>
                      <small>{workflowTimeLabel(event.createdAtMs)}</small>
                    </li>
                  ))}
                </ol>
              ) : (
                <article className="workflow-output-row">
                  <strong>{runDetailLoading ? "Loading run details" : "Run details not loaded"}</strong>
                  <span>
                    {runDetailLoading
                      ? "Loading attempts, timeline events, and outputs from the saved run."
                      : "Select a run from the Runs rail or Executions to load attempts, timeline events, and outputs."}
                  </span>
                </article>
              )}
            </div>
          )}
        </div>
      </div>
    ) : (
      <p>Run output appears here after execution starts.</p>
    );
  }
  if (panel === "warnings") {
    return validationResult ? (
      <div className="workflow-bottom-grid workflow-bottom-issue-grid" data-testid="workflow-bottom-warnings-detail">
        <dl data-testid="workflow-bottom-warnings-summary">
          <dt>Status</dt>
          <dd>{validationResult.status}</dd>
          <dt>Blocked</dt>
          <dd>{validationResult.blockedNodes.length}</dd>
          <dt>Coverage</dt>
          <dd>{Object.keys(validationResult.coverageByNodeId).length} nodes</dd>
          <dt>Issues</dt>
          <dd>{validationIssueItems.length}</dd>
        </dl>
        <div className="workflow-bottom-list" data-testid="workflow-bottom-warnings-list">
          {validationIssueItems.length > 0 ? (
            validationIssueItems.map(({ category, issue, status }, index) =>
              issue.nodeId ? (
                <button
                  key={`${category}-${issue.code}-${index}`}
                  type="button"
                  className={`workflow-search-result is-${status}`}
                  data-testid={`workflow-bottom-warning-${index}`}
                  onClick={() => onInspectNode(issue.nodeId!)}
                >
                  <strong>{category} · {workflowIssueTitle(issue)}</strong>
                  <span>{issue.message}</span>
                  <small>{workflowNodeName(workflow, issue.nodeId)}</small>
                  <small>{workflowIssueActionLabel(issue)}</small>
                </button>
              ) : (
                <article key={`${category}-${issue.code}-${index}`} className={`workflow-output-row is-${status}`}>
                  <strong>{category} · {workflowIssueTitle(issue)}</strong>
                  <span>{issue.message}</span>
                  <small>{workflowIssueActionLabel(issue)}</small>
                </article>
              ),
            )
          ) : (
            <article className="workflow-output-row is-ready">
              <strong>No validation issues</strong>
              <span>The last validation pass did not report blockers or warnings.</span>
            </article>
          )}
        </div>
      </div>
    ) : (
      <p>Warnings from model bindings, connectors, stale nodes, and invalid graph state appear here.</p>
    );
  }
  if (panel === "suggestions") {
    return (
      <div className="workflow-bottom-grid workflow-bottom-issue-grid" data-testid="workflow-bottom-suggestions-detail">
        <dl data-testid="workflow-bottom-suggestions-summary">
          <dt>Suggestions</dt>
          <dd>{bottomSuggestions.length}</dd>
          <dt>Validation</dt>
          <dd>{validationResult?.status ?? "not run"}</dd>
          <dt>Tests</dt>
          <dd>{tests.length}</dd>
          <dt>Outputs</dt>
          <dd>{outputNodes.length}</dd>
        </dl>
        <div className="workflow-bottom-list" data-testid="workflow-bottom-suggestions-list">
          {bottomSuggestions.map((suggestion) =>
            suggestion.nodeId ? (
              <button
                key={suggestion.id}
                type="button"
                className={`workflow-search-result is-${suggestion.status}`}
                data-testid={`workflow-bottom-suggestion-${suggestion.id}`}
                onClick={() => onInspectNode(suggestion.nodeId!)}
              >
                <strong>{suggestion.title}</strong>
                <span>{suggestion.message}</span>
                <small>Open related node</small>
              </button>
            ) : (
              <article key={suggestion.id} className={`workflow-output-row is-${suggestion.status}`}>
                <strong>{suggestion.title}</strong>
                <span>{suggestion.message}</span>
              </article>
            ),
          )}
        </div>
      </div>
    );
  }
  return <p>Preview data for the selected node appears here.</p>;
}
