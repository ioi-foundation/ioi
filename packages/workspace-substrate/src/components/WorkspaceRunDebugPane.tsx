import clsx from "clsx";
import type { WorkspaceRunDebugPaneProps } from "../types";

function labelForStatus(status: NonNullable<WorkspaceRunDebugPaneProps["model"]>["entries"][number]["status"]) {
  switch (status) {
    case "running":
      return "Running";
    case "attention":
      return "Attention";
    case "completed":
      return "Completed";
    case "ready":
      return "Ready";
    case "idle":
      return "Idle";
    default:
      return "Unknown";
  }
}

export function WorkspaceRunDebugPane({ model = null }: WorkspaceRunDebugPaneProps) {
  const entries = model?.entries ?? [];

  return (
    <section className="workspace-pane">
      <header className="workspace-pane-header">
        <div className="workspace-pane-header-leading">
          <div>
            <span className="workspace-pane-eyebrow">Workspace</span>
            <h3>Run and Debug</h3>
          </div>
        </div>
        <div className="workspace-pane-header-actions">
          {model?.onOpenRunsSurface ? (
            <button type="button" className="workspace-pane-button" onClick={model.onOpenRunsSurface}>
              Open Runs
            </button>
          ) : null}
        </div>
      </header>

      <div className="workspace-pane-action-row">
        {model?.onOpenTerminal ? (
          <button type="button" className="workspace-pane-button" onClick={model.onOpenTerminal}>
            Terminal
          </button>
        ) : null}
        {model?.onOpenOutput ? (
          <button type="button" className="workspace-pane-button" onClick={model.onOpenOutput}>
            Output
          </button>
        ) : null}
      </div>

      {entries.length === 0 ? (
        <p className="workspace-pane-message">
          No active runtime runs yet. This container is now wired, and it will populate as runs
          and debug evidence appear.
        </p>
      ) : (
        <div className="workspace-inspection-list">
          {entries.map((entry) => (
            <article key={entry.id} className="workspace-inspection-card">
              <button
                type="button"
                className={clsx("workspace-inspection-card-main", entry.onSelect && "is-interactive")}
                onClick={entry.onSelect}
                disabled={!entry.onSelect}
              >
                <div className="workspace-inspection-card-header">
                  <strong>{entry.title}</strong>
                  <span className={clsx("workspace-inspection-status", `is-${entry.status}`)}>
                    {labelForStatus(entry.status)}
                  </span>
                </div>
                <p>{entry.summary}</p>
                {entry.detail ? <span>{entry.detail}</span> : null}
              </button>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
