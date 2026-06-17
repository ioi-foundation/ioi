import type { WorkflowEntrypointsModel } from "../../../runtime/workflow-entrypoints-model";

type WorkflowEntrypointsPanelProps = {
  mode: "sources" | "schedules";
  model: WorkflowEntrypointsModel;
  onInspectNode: (nodeId: string) => void;
};

export function WorkflowEntrypointsPanel({
  mode,
  model,
  onInspectNode,
}: WorkflowEntrypointsPanelProps) {
  if (mode === "sources") {
    return (
      <>
        <h3>Sources</h3>
        <p>
          {model.totalStartPoints === 0
            ? "No start points configured."
            : `${model.totalStartPoints} start point${model.totalStartPoints === 1 ? "" : "s"} in this workflow.`}
        </p>
        <div
          className="workflow-rail-list"
          data-testid="workflow-sources-list"
          data-ready-count={model.readyStartPoints}
          data-blocked-count={model.blockedStartPoints}
        >
          {model.sourceRows.map((row) => (
            <button
              key={row.node.id}
              type="button"
              className="workflow-search-result"
              data-testid={`workflow-source-node-${row.node.id}`}
              data-entrypoint-kind={row.kind}
              data-entrypoint-ready={String(row.ready)}
              onClick={() => onInspectNode(row.node.id)}
            >
              <strong>{row.node.name}</strong>
              <span>
                {row.node.type} · {row.status}
              </span>
              <small>{row.detail}</small>
            </button>
          ))}
          {model.totalStartPoints === 0 ? (
            <article className="workflow-output-row">
              <strong>No start point</strong>
              <span>
                Add a Source or Trigger primitive before activating this workflow.
              </span>
            </article>
          ) : null}
        </div>
      </>
    );
  }

  return (
    <>
      <h3>Schedules</h3>
      <p>
        {model.totalTriggers === 0
          ? "No trigger nodes configured."
          : `${model.totalTriggers} trigger node${model.totalTriggers === 1 ? "" : "s"} configured.`}
      </p>
      <div
        className="workflow-rail-list"
        data-testid="workflow-schedules-list"
        data-ready-count={model.readyTriggers}
        data-blocked-count={model.blockedTriggers}
      >
        {model.triggerRows.map((row) => (
          <button
            key={row.node.id}
            type="button"
            className={`workflow-search-result is-${row.status}`}
            data-testid={`workflow-schedule-node-${row.node.id}`}
            data-trigger-kind={row.triggerKind}
            data-entrypoint-ready={String(row.ready)}
            onClick={() => onInspectNode(row.node.id)}
          >
            <strong>{row.node.name}</strong>
            <span>
              {row.triggerKind} · {row.ready ? "ready" : "needs configuration"}
            </span>
            <small>{row.detail}</small>
          </button>
        ))}
        {model.totalTriggers === 0 ? (
          <article className="workflow-output-row">
            <strong>No trigger</strong>
            <span>
              Add a Trigger primitive when this workflow needs scheduled or
              event-driven execution.
            </span>
          </article>
        ) : null}
      </div>
    </>
  );
}
