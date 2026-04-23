import clsx from "clsx";
import type { WorkspaceExtensionsPaneProps } from "../types";

function statusLabel(status: NonNullable<WorkspaceExtensionsPaneProps["model"]>["entries"][number]["status"]) {
  switch (status) {
    case "enabled":
      return "Enabled";
    case "attention":
      return "Attention";
    default:
      return "Available";
  }
}

export function WorkspaceExtensionsPane({ model = null }: WorkspaceExtensionsPaneProps) {
  const entries = model?.entries ?? [];

  return (
    <section className="workspace-pane">
      <header className="workspace-pane-header">
        <div className="workspace-pane-header-leading">
          <div>
            <span className="workspace-pane-eyebrow">Workspace</span>
            <h3>Extensions</h3>
          </div>
        </div>
        <div className="workspace-pane-header-actions">
          {model?.onOpenConnections ? (
            <button type="button" className="workspace-pane-button" onClick={model.onOpenConnections}>
              Connections
            </button>
          ) : null}
          {model?.onOpenPolicies ? (
            <button type="button" className="workspace-pane-button" onClick={model.onOpenPolicies}>
              Policy
            </button>
          ) : null}
        </div>
      </header>

      {entries.length === 0 ? (
        <p className="workspace-pane-message">
          No extension metadata is available yet. This pane is now live and ready to surface the
          direct-host extension inventory.
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
                  <strong>{entry.name}</strong>
                  <span className={clsx("workspace-inspection-status", `is-${entry.status}`)}>
                    {statusLabel(entry.status)}
                  </span>
                </div>
                <p>{entry.description}</p>
                {entry.detail ? <span>{entry.detail}</span> : null}
              </button>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
