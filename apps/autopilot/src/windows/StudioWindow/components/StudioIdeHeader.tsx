import { useEffect, useState, type MouseEvent } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { AutopilotIcon } from "./ActivityBarIcons";
import type { PrimaryView } from "../studioWindowModel";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface StudioIdeHeaderProps {
  workspaceName: string;
  currentProject: ProjectScope;
  projects: ProjectScope[];
  activeView: PrimaryView;
  workflowSurface: "home" | "canvas" | "agents" | "catalog";
  chatVisible: boolean;
  notificationCount: number;
  onSelectProject: (projectId: string) => void;
  onToggleChat: () => void;
  onOpenCommandPalette: () => void;
  onOpenNewTerminal: () => void;
}

const MENU_ITEMS = ["Studio", "Artifact", "Run", "Window"];

function isTauriRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    "__TAURI_INTERNALS__" in window
  );
}

function isInteractiveElement(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  return target.closest("button, input, select, textarea, a, [role='button']") !== null;
}

function prettyPrimaryView(view: PrimaryView): string {
  return view[0].toUpperCase() + view.slice(1);
}

function surfaceDetail(
  view: PrimaryView,
  workflowSurface: StudioIdeHeaderProps["workflowSurface"],
): string {
  if (view === "studio") return "Outcome control plane";
  if (view === "workflows") {
    if (workflowSurface === "home") return "Internal";
    if (workflowSurface === "agents") return "Agent roster";
    if (workflowSurface === "catalog") return "Catalog";
    return "Canvas";
  }
  if (view === "runs") return "Supervision";
  if (view === "inbox") return "Decision queue";
  if (view === "capabilities") return "Capability surface";
  if (view === "policy") return "Governance";
  return "System profile";
}

export function StudioIdeHeader({
  workspaceName,
  currentProject,
  projects,
  activeView,
  workflowSurface,
  chatVisible,
  notificationCount,
  onSelectProject,
  onToggleChat,
  onOpenCommandPalette,
  onOpenNewTerminal,
}: StudioIdeHeaderProps) {
  const inboxCount = notificationCount > 9 ? "9+" : String(notificationCount);
  const [windowMaximized, setWindowMaximized] = useState(false);
  const [terminalMenuOpen, setTerminalMenuOpen] = useState(false);
  const windowControlsVisible = isTauriRuntime();
  const shellTerminalAllowed = activeView === "workflows";

  useEffect(() => {
    if (!windowControlsVisible) return;

    const appWindow = getCurrentWindow();
    let cancelled = false;

    const syncWindowState = async () => {
      try {
        const maximized = await appWindow.isMaximized();
        if (!cancelled) {
          setWindowMaximized(maximized);
        }
      } catch {
        // Best-effort window state sync only.
      }
    };

    void appWindow.setDecorations(false).catch(() => {
      // Best-effort runtime alignment with the static config.
    });
    void syncWindowState();

    const unlistenPromise = appWindow.onResized(() => {
      void syncWindowState();
    });

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [windowControlsVisible]);

  useEffect(() => {
    if (!shellTerminalAllowed) {
      setTerminalMenuOpen(false);
      return;
    }

    if (!terminalMenuOpen) {
      return;
    }

    const closeMenu = (event: globalThis.MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent) {
        if (event.key === "Escape") {
          setTerminalMenuOpen(false);
        }
        return;
      }

      if (event.target instanceof Element) {
        const insideMenu = event.target.closest(".studio-ide-menu-group");
        if (!insideMenu) {
          setTerminalMenuOpen(false);
        }
      }
    };

    window.addEventListener("mousedown", closeMenu);
    window.addEventListener("keydown", closeMenu);
    return () => {
      window.removeEventListener("mousedown", closeMenu);
      window.removeEventListener("keydown", closeMenu);
    };
  }, [shellTerminalAllowed, terminalMenuOpen]);

  useEffect(() => {
    if (!shellTerminalAllowed) {
      return;
    }

    const handler = (event: KeyboardEvent) => {
      if (isInteractiveElement(event.target)) return;
      if (!event.shiftKey) return;
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.key.toLowerCase() !== "t") return;
      event.preventDefault();
      setTerminalMenuOpen(false);
      onOpenNewTerminal();
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onOpenNewTerminal, shellTerminalAllowed]);

  const toggleWindowMaximize = async () => {
    if (!windowControlsVisible) return;
    try {
      const appWindow = getCurrentWindow();
      await appWindow.toggleMaximize();
      setWindowMaximized(await appWindow.isMaximized());
    } catch {
      // Window controls are best-effort in non-Tauri environments.
    }
  };

  const minimizeWindow = async () => {
    if (!windowControlsVisible) return;
    try {
      await getCurrentWindow().minimize();
    } catch {
      // Ignore non-Tauri environments.
    }
  };

  const closeWindow = async () => {
    if (!windowControlsVisible) return;
    try {
      await getCurrentWindow().close();
    } catch {
      // Ignore non-Tauri environments.
    }
  };

  const handleHeaderDoubleClick = (event: MouseEvent<HTMLElement>) => {
    if (!windowControlsVisible) return;
    if (isInteractiveElement(event.target)) return;
    void toggleWindowMaximize();
  };

  return (
    <header className="studio-ide-header" onDoubleClick={handleHeaderDoubleClick}>
      <div
        className="studio-ide-menu-bar"
        aria-label="Studio menu"
        data-tauri-drag-region
      >
        {MENU_ITEMS.map((item) => (
          <span key={item} className="studio-ide-menu-item">
            {item}
          </span>
        ))}
        {shellTerminalAllowed ? (
          <div className="studio-ide-menu-group">
            <button
              type="button"
              className={`studio-ide-menu-item studio-ide-menu-button ${
                terminalMenuOpen ? "is-active" : ""
              }`}
              aria-haspopup="menu"
              aria-expanded={terminalMenuOpen}
              onClick={() => setTerminalMenuOpen((open) => !open)}
            >
              Terminal
            </button>
            {terminalMenuOpen ? (
              <div className="studio-ide-menu-popover" role="menu" aria-label="Terminal menu">
                <button
                  type="button"
                  className="studio-ide-menu-popover-item"
                  role="menuitem"
                  onClick={() => {
                    setTerminalMenuOpen(false);
                    onOpenNewTerminal();
                  }}
                >
                  New Terminal
                </button>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      <div className="studio-ide-command-cluster">
        <button
          type="button"
          className="studio-ide-command-button"
          onClick={onOpenCommandPalette}
          aria-haspopup="dialog"
        >
          <svg
            className="studio-ide-command-icon"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="m20 20-3.5-3.5" />
          </svg>
          <span>Search commands, workers, and receipts</span>
          <kbd>⌘K</kbd>
        </button>

        {activeView !== "studio" ? (
          <button
            type="button"
            className={`studio-ide-chat-toggle ${
              chatVisible ? "is-active" : ""
            }`}
            onClick={onToggleChat}
            aria-label={chatVisible ? "Hide Autopilot chat" : "Show Autopilot chat"}
            aria-pressed={chatVisible}
            title={chatVisible ? "Hide Autopilot chat" : "Show Autopilot chat"}
          >
            <AutopilotIcon />
          </button>
        ) : null}
      </div>

      <div className="studio-ide-toolbar" data-tauri-drag-region>
        <div
          className="studio-ide-toolbar-segment studio-ide-toolbar-segment--scope"
          title={`${workspaceName} / ${currentProject.name}`}
        >
          <span className="studio-ide-toolbar-label">{workspaceName}</span>
          <label className="studio-ide-project-select">
            <span className="studio-ide-project-select-label">Project</span>
            <select
              value={currentProject.id}
              onChange={(event) => onSelectProject(event.target.value)}
              aria-label="Current project"
            >
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </label>
          <span className="studio-ide-toolbar-meta">
            {currentProject.environment}
          </span>
        </div>

        <div className="studio-ide-toolbar-segment">
          <span className="studio-ide-toolbar-label">Surface</span>
          <strong>{prettyPrimaryView(activeView)}</strong>
          <span className="studio-ide-toolbar-meta">
            {surfaceDetail(activeView, workflowSurface)}
          </span>
        </div>

        <div className="studio-ide-toolbar-segment">
          <span className="studio-ide-toolbar-label">Inbox</span>
          <strong>{inboxCount}</strong>
          <span className="studio-ide-toolbar-meta">
            {notificationCount === 1 ? "Pending review" : "Pending reviews"}
          </span>
        </div>
      </div>

      {windowControlsVisible ? (
        <div className="studio-ide-window-controls" aria-label="Window controls">
          <button
            type="button"
            className="studio-ide-window-button"
            onClick={() => {
              void minimizeWindow();
            }}
            aria-label="Minimize window"
            title="Minimize"
          >
            <svg
              width="12"
              height="12"
              viewBox="0 0 12 12"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M2 6h8" />
            </svg>
          </button>

          <button
            type="button"
            className="studio-ide-window-button"
            onClick={() => {
              void toggleWindowMaximize();
            }}
            aria-label={windowMaximized ? "Restore window" : "Maximize window"}
            title={windowMaximized ? "Restore" : "Maximize"}
          >
            {windowMaximized ? (
              <svg
                width="12"
                height="12"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M4 2.5h5.5V8" />
                <path d="M2.5 4H8v5.5H2.5z" />
              </svg>
            ) : (
              <svg
                width="12"
                height="12"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <rect x="2.5" y="2.5" width="7" height="7" />
              </svg>
            )}
          </button>

          <button
            type="button"
            className="studio-ide-window-button studio-ide-window-button--close"
            onClick={() => {
              void closeWindow();
            }}
            aria-label="Close window"
            title="Close"
          >
            <svg
              width="12"
              height="12"
              viewBox="0 0 12 12"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M2.5 2.5 9.5 9.5" />
              <path d="M9.5 2.5 2.5 9.5" />
            </svg>
          </button>
        </div>
      ) : null}
    </header>
  );
}
