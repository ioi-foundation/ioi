import type { WorkflowRailSearchModel } from "../../../runtime/workflow-rail-search-model";

type WorkflowSearchPanelProps = {
  model: WorkflowRailSearchModel;
  searchQuery: string;
  onSearchQueryChange: (query: string) => void;
  onInspectNode: (nodeId: string) => void;
};

export function WorkflowSearchPanel({
  model,
  searchQuery,
  onSearchQueryChange,
  onInspectNode,
}: WorkflowSearchPanelProps) {
  return (
    <>
      <h3>Search</h3>
      <input
        data-testid="workflow-rail-search-input"
        placeholder="Search nodes, tests, outputs..."
        value={searchQuery}
        onChange={(event) => onSearchQueryChange(event.target.value)}
      />
      <p data-testid="workflow-rail-search-index-summary">
        {model.totalNodes} nodes, {model.totalTests} tests, and{" "}
        {model.outputCount} outputs indexed.
      </p>
      <div
        className="workflow-search-results"
        data-testid="workflow-rail-search-results"
        data-total-indexed={model.totalIndexed}
        data-result-count={model.results.length}
        data-hidden-result-count={model.hiddenResultCount}
      >
        {model.visibleResults.map((item) => (
          <button
            key={item.id}
            type="button"
            className="workflow-search-result"
            data-testid={`workflow-rail-search-result-${item.id}`}
            data-result-kind={item.resultKind}
            data-actionable={String(item.actionable)}
            disabled={!item.nodeId}
            onClick={() => item.nodeId && onInspectNode(item.nodeId)}
          >
            <strong>{item.title}</strong>
            <span>
              {item.resultKind} · {item.subtitle}
            </span>
            {item.detail ? <small>{item.detail}</small> : null}
          </button>
        ))}
        {model.results.length === 0 ? (
          <article className="workflow-output-row">
            <strong>{model.emptyTitle}</strong>
            <span>{model.emptyDescription}</span>
          </article>
        ) : null}
      </div>
    </>
  );
}
