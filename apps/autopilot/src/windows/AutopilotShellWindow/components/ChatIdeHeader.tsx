import { useEffect, useState, type MouseEvent } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { safelyDisposeTauriListener } from "../../../services/tauriListeners";
import {
  isInteractiveWindowTarget,
  isTauriRuntime,
  startTauriWindowDrag,
} from "../../shared/tauriWindowDrag";
import type { PrimaryView } from "../autopilotShellModel";
import type { OperatorCommandCenterModel } from "../operatorSubstrateModel";

interface ChatIdeHeaderProps {
  activeView: PrimaryView;
  workflowSurface: "home" | "canvas" | "agents" | "catalog";
  commandCenter: OperatorCommandCenterModel;
  onOpenCommandPalette: () => void;
}

function windowSurfaceTitle(
  view: PrimaryView,
  workflowSurface: ChatIdeHeaderProps["workflowSurface"],
): string {
  if (view === "workflows") {
    if (workflowSurface === "home") return "Workflows";
    if (workflowSurface === "agents") return "Agents";
    if (workflowSurface === "catalog") return "Catalog";
    return "Canvas";
  }
  if (view === "workspace") return "Workspace";
  if (view === "home") return "Home";
  if (view === "policy") return "Governance";
  if (view === "runs") return "Runs";
  if (view === "mounts") return "Model Mounts";
  if (view === "inbox") return "Inbox";
  if (view === "capabilities") return "Capabilities";
  if (view === "settings") return "Settings";
  return "Chat";
}

export function ChatIdeHeader({
  activeView,
  workflowSurface,
  commandCenter,
  onOpenCommandPalette,
}: ChatIdeHeaderProps) {
  const [windowMaximized, setWindowMaximized] = useState(false);
  const windowControlsVisible = isTauriRuntime();
  const resolvedWindowTitle = `Autopilot Chat · ${windowSurfaceTitle(
    activeView,
    workflowSurface,
  )}`;

  useEffect(() => {
    document.title = resolvedWindowTitle;

    if (!windowControlsVisible) {
      return;
    }

    void getCurrentWindow().setTitle(resolvedWindowTitle).catch(() => {
      // Window title updates are best-effort in non-standard shells.
    });
  }, [resolvedWindowTitle, windowControlsVisible]);

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
      safelyDisposeTauriListener(unlistenPromise);
    };
  }, [windowControlsVisible]);

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
    if (isInteractiveWindowTarget(event.target)) return;
    void toggleWindowMaximize();
  };

  return (
    <header className="chat-ide-header" onDoubleClick={handleHeaderDoubleClick}>
      <div
        className="chat-ide-drag-surface"
        data-tauri-drag-region
        onMouseDown={startTauriWindowDrag}
        aria-hidden="true"
      />

      <div className="chat-ide-command-shell">
        <button
          type="button"
          className="chat-ide-command-center"
          data-operator-command-center={commandCenter.projectionId}
          data-operator-route-kind={commandCenter.activeRoute.kind}
          aria-label={commandCenter.placeholder}
          title={`${commandCenter.placeholder} (${commandCenter.shortcutLabel})`}
          onClick={onOpenCommandPalette}
        >
          <span className="chat-ide-command-center-icon" aria-hidden="true">
            <svg
              width="15"
              height="15"
              viewBox="0 0 20 20"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="8.5" cy="8.5" r="5.5" />
              <path d="m12.6 12.6 4 4" />
            </svg>
          </span>
          <span className="chat-ide-command-center-scope">
            {commandCenter.scopeLabel}
          </span>
          <span className="chat-ide-command-center-placeholder">
            {commandCenter.placeholder}
          </span>
          <kbd>{commandCenter.shortcutLabel}</kbd>
        </button>
      </div>

      {windowControlsVisible ? (
        <div className="chat-ide-window-controls" aria-label="Window controls">
          <button
            type="button"
            className="chat-ide-window-button"
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
            className="chat-ide-window-button"
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
            className="chat-ide-window-button chat-ide-window-button--close"
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
