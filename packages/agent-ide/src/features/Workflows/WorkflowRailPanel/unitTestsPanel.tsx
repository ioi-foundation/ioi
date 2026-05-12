import type { WorkflowTestReadinessModel } from "../../../runtime/workflow-test-readiness-model";

type WorkflowUnitTestsPanelProps = {
  model: WorkflowTestReadinessModel;
  searchQuery: string;
  lastRunStatus: string;
  onSearchQueryChange: (query: string) => void;
  onInspectNode: (nodeId: string) => void;
};

export function WorkflowUnitTestsPanel({
  model,
  searchQuery,
  lastRunStatus,
  onSearchQueryChange,
  onInspectNode,
}: WorkflowUnitTestsPanelProps) {
  const { coveredNodeIds, uncoveredNodes, statusCounts, rows, totalTests } =
    model;

  return (
    <>
      <h3>Unit tests</h3>
      <input
        data-testid="workflow-unit-test-search-input"
        placeholder="Search tests, assertions, targets..."
        value={searchQuery}
        onChange={(event) => onSearchQueryChange(event.target.value)}
      />
      <dl className="workflow-rail-stats" data-testid="workflow-unit-test-summary">
        <div>
          <dt>Total</dt>
          <dd>{totalTests}</dd>
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
          <dd>{lastRunStatus}</dd>
        </div>
      </dl>
      <p data-testid="workflow-unit-test-status-counts">
        Passed {statusCounts.passed ?? 0} · Failed {statusCounts.failed ?? 0} ·
        Blocked {statusCounts.blocked ?? 0}
      </p>
      <div className="workflow-rail-list" data-testid="workflow-unit-test-list">
        {rows.map(({ test, targetNode, status, message }) => (
          <article
            key={test.id}
            className={`workflow-test-row is-${status}`}
            data-testid={`workflow-unit-test-${test.id}`}
          >
            <strong>{test.name}</strong>
            <span>{message}</span>
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
        ))}
        {rows.length === 0 ? (
          <article className="workflow-output-row">
            <strong>No matching tests</strong>
            <span>Try a test name, assertion kind, status, or target node id.</span>
          </article>
        ) : null}
      </div>
      {uncoveredNodes.length > 0 ? (
        <section
          className="workflow-rail-section"
          data-testid="workflow-unit-test-uncovered"
        >
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
              <span>
                {nodeItem.type} · {nodeItem.status ?? "idle"}
              </span>
            </button>
          ))}
        </section>
      ) : null}
    </>
  );
}
