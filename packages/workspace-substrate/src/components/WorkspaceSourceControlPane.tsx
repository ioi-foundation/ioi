import clsx from "clsx";
import type {
  WorkspaceSourceControlEntry,
  WorkspaceSourceControlPaneProps,
} from "../types";

function statusLabel(entry: WorkspaceSourceControlEntry): string {
  return `${entry.x}${entry.y}`.trim() || "??";
}

export function WorkspaceSourceControlPane({
  state,
  loading,
  error,
  onRefresh,
  onOpenDiff,
  onOpenFile,
  onStage,
  onUnstage,
  onDiscard,
}: WorkspaceSourceControlPaneProps) {
  return (
    <section className="workspace-pane">
      <header className="workspace-pane-header">
        <div>
          <span className="workspace-pane-eyebrow">Workspace</span>
          <h3>Source Control</h3>
        </div>
        <div className="workspace-pane-header-actions">
          <button type="button" className="workspace-pane-button" onClick={onRefresh}>
            Refresh
          </button>
        </div>
      </header>

      {state ? (
        <div className="workspace-pane-meta">
          <span className="workspace-chip">{state.git.branch || "detached"}</span>
          <span className="workspace-chip">
            {state.git.dirty ? `${state.entries.length} changes` : "No changes"}
          </span>
        </div>
      ) : null}

      {loading ? <p className="workspace-pane-message">Loading source control...</p> : null}
      {error ? <p className="workspace-pane-message">{error}</p> : null}

      {state ? (
        <div className="workspace-scm-list">
          {state.entries.length === 0 ? (
            <p className="workspace-pane-message">Working tree is clean.</p>
          ) : (
            state.entries.map((entry) => (
              <article key={`${entry.path}:${entry.x}:${entry.y}`} className="workspace-scm-entry">
                <div className="workspace-scm-entry-header">
                  <button
                    type="button"
                    className="workspace-scm-entry-main"
                    onClick={() => onOpenFile(entry.path)}
                  >
                    <span className={clsx("workspace-scm-status", entry.x !== " " && "is-staged")}>
                      {statusLabel(entry)}
                    </span>
                    <span className="workspace-scm-path-group">
                      <strong>{entry.path}</strong>
                      {entry.originalPath ? <span>{entry.originalPath}</span> : null}
                    </span>
                  </button>
                </div>

                <div className="workspace-scm-actions">
                  <button
                    type="button"
                    className="workspace-pane-button"
                    onClick={() => onOpenDiff(entry.path, false)}
                  >
                    Diff
                  </button>
                  {entry.x !== " " ? (
                    <button
                      type="button"
                      className="workspace-pane-button"
                      onClick={() => onOpenDiff(entry.path, true)}
                    >
                      Staged
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="workspace-pane-button"
                    onClick={() => onStage(entry.path)}
                  >
                    Stage
                  </button>
                  {entry.x !== " " ? (
                    <button
                      type="button"
                      className="workspace-pane-button"
                      onClick={() => onUnstage(entry.path)}
                    >
                      Unstage
                    </button>
                  ) : null}
                  {entry.y !== " " || entry.x === "?" ? (
                    <button
                      type="button"
                      className="workspace-pane-button is-danger"
                      onClick={() => onDiscard(entry.path)}
                    >
                      Discard
                    </button>
                  ) : null}
                </div>
              </article>
            ))
          )}
        </div>
      ) : null}
    </section>
  );
}
