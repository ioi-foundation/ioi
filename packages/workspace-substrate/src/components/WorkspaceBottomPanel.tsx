import clsx from "clsx";
import { WorkspaceTerminalView } from "./WorkspaceTerminalView";
import type {
  WorkspaceActivityEntry,
  WorkspaceBottomPanel as WorkspaceBottomPanelType,
  WorkspaceBottomPanelProps,
} from "../types";

const panelCopy: Record<
  WorkspaceBottomPanelType,
  { label: string; eyebrow: string; empty: string }
> = {
  terminal: {
    label: "Terminal",
    eyebrow: "Workspace terminal",
    empty: "Terminal history will appear here when a PTY-backed runtime is attached.",
  },
  problems: {
    label: "Problems",
    eyebrow: "Workspace diagnostics",
    empty: "No workspace issues are currently surfaced.",
  },
  output: {
    label: "Output",
    eyebrow: "Workspace activity",
    empty: "Workspace activity will stream here as you inspect, save, and diff files.",
  },
  ports: {
    label: "Ports",
    eyebrow: "Workspace networking",
    empty: "No forwarded ports are attached to this workspace yet.",
  },
};

function formatTime(timestampMs: number): string {
  return new Date(timestampMs).toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
  });
}

function renderActivityRows(
  entries: WorkspaceActivityEntry[],
  onOpenRequest: WorkspaceBottomPanelProps["onOpenRequest"],
  options?: { terminalTone?: boolean },
) {
  if (entries.length === 0) {
    return null;
  }

  return entries.map((entry) => (
    <div
      key={entry.id}
      className={clsx(
        "workspace-bottom-entry",
        `workspace-bottom-entry--${entry.kind}`,
        options?.terminalTone ? "is-terminal" : null,
      )}
    >
      <div className="workspace-bottom-entry-header">
        <span className={clsx("workspace-bottom-badge", `is-${entry.kind}`)}>
          {entry.source}
        </span>
        <strong>{entry.title}</strong>
        <span className="workspace-bottom-entry-time">{formatTime(entry.timestampMs)}</span>
      </div>
      {entry.detail ? <p>{entry.detail}</p> : null}
      {entry.path ? (
        <button
          type="button"
          className="workspace-bottom-link"
          onClick={() =>
            onOpenRequest({
              path: entry.path!,
              line: entry.line,
              column: entry.column,
            })
          }
        >
          {entry.line ? `${entry.path}:${entry.line}${entry.column ? `:${entry.column}` : ""}` : entry.path}
        </button>
      ) : null}
    </div>
  ));
}

export function WorkspaceBottomPanel({
  terminal,
  rootPath,
  visiblePanels,
  activePanel,
  isOpen,
  outputEntries,
  problems,
  ports,
  onSelectPanel,
  onToggleOpen,
  onOpenRequest,
}: WorkspaceBottomPanelProps) {
  return (
    <section className={clsx("workspace-bottom-panel", !isOpen && "is-collapsed")}>
      <header className="workspace-bottom-panel-header">
        <div
          className="workspace-bottom-panel-tabs"
          role="tablist"
          aria-label="Workspace bottom panels"
        >
          {visiblePanels.map((panel) => (
            <button
              key={panel}
              type="button"
              role="tab"
              aria-selected={activePanel === panel}
              className={clsx(
                "workspace-bottom-panel-tab",
                activePanel === panel && "is-active",
              )}
              onClick={() => onSelectPanel(panel)}
            >
              {panelCopy[panel].label}
            </button>
          ))}
        </div>

        <button
          type="button"
          className="workspace-bottom-panel-toggle"
          onClick={onToggleOpen}
          aria-expanded={isOpen}
        >
          {isOpen ? "Hide panel" : "Show panel"}
        </button>
      </header>

      {isOpen ? (
        <div className="workspace-bottom-panel-body" role="tabpanel">
          <div className="workspace-bottom-panel-copy">
            <span className="workspace-pane-eyebrow">{panelCopy[activePanel].eyebrow}</span>
            <p>{rootPath}</p>
          </div>

          {activePanel === "terminal" ? (
            <div className="workspace-terminal-panel">
              <WorkspaceTerminalView controller={terminal} />
            </div>
          ) : null}

          {activePanel === "problems" ? (
            problems.length > 0 ? (
              <div className="workspace-bottom-list">
                {problems.map((problem) => (
                  <div
                    key={problem.id}
                    className={clsx(
                      "workspace-bottom-entry",
                      `workspace-bottom-entry--${problem.severity}`,
                    )}
                  >
                    <div className="workspace-bottom-entry-header">
                      <span className={clsx("workspace-bottom-badge", `is-${problem.severity}`)}>
                        {problem.source}
                      </span>
                      <strong>{problem.title}</strong>
                    </div>
                    <p>{problem.detail}</p>
                    {problem.path ? (
                      <button
                        type="button"
                        className="workspace-bottom-link"
                        onClick={() =>
                          onOpenRequest({
                            path: problem.path!,
                            line: problem.line,
                            column: problem.column,
                          })
                        }
                      >
                        Open{" "}
                        {problem.line
                          ? `${problem.path}:${problem.line}${problem.column ? `:${problem.column}` : ""}`
                          : problem.path}
                      </button>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : (
              <div className="workspace-bottom-panel-empty">{panelCopy.problems.empty}</div>
            )
          ) : null}

          {activePanel === "output" ? (
            outputEntries.length > 0 ? (
              <div className="workspace-bottom-list">
                {renderActivityRows(outputEntries, onOpenRequest)}
              </div>
            ) : (
              <div className="workspace-bottom-panel-empty">{panelCopy.output.empty}</div>
            )
          ) : null}

          {activePanel === "ports" ? (
            ports.length > 0 ? (
              <div className="workspace-bottom-list">
                {ports.map((port) => (
                  <div key={port.id} className="workspace-bottom-entry">
                    <div className="workspace-bottom-entry-header">
                      <span className={clsx("workspace-bottom-badge", `is-${port.status}`)}>
                        {port.status}
                      </span>
                      <strong>{port.label}</strong>
                    </div>
                    <p>{port.description}</p>
                    {port.value ? <code>{port.value}</code> : null}
                  </div>
                ))}
              </div>
            ) : (
              <div className="workspace-bottom-panel-empty">{panelCopy.ports.empty}</div>
            )
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
