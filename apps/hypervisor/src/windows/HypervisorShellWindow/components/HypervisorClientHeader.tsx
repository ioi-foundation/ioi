import { useEffect, useState, type MouseEvent } from "react";
import { getCurrentWindow } from "../../../services/hypervisorHostBridge";
import { safelyDisposeHostListener } from "../../../services/hostListeners";
import {
  isInteractiveWindowTarget,
  isHypervisorClientRuntime,
  startHostWindowDrag,
} from "../../shared/hostWindowDrag";
import type { PrimaryView } from "../hypervisorShellModel";
import { getHypervisorSurfaceById } from "../hypervisorShellNavigationModel";

interface HypervisorClientHeaderProps {
  activeView: PrimaryView;
}

function windowSurfaceTitle(view: PrimaryView): string {
  return getHypervisorSurfaceById(view).label;
}

export function HypervisorClientHeader({
  activeView,
}: HypervisorClientHeaderProps) {
  const [windowMaximized, setWindowMaximized] = useState(false);
  const windowControlsVisible = isHypervisorClientRuntime();
  const resolvedWindowTitle = `Hypervisor · ${windowSurfaceTitle(activeView)}`;

  useEffect(() => {
    document.title = resolvedWindowTitle;

    if (!windowControlsVisible) {
      return;
    }

    void getCurrentWindow()
      .setTitle(resolvedWindowTitle)
      .catch(() => {
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
      safelyDisposeHostListener(unlistenPromise);
    };
  }, [windowControlsVisible]);

  const toggleWindowMaximize = async () => {
    if (!windowControlsVisible) return;
    try {
      const appWindow = getCurrentWindow();
      await appWindow.toggleMaximize();
      setWindowMaximized(await appWindow.isMaximized());
    } catch {
      // Window controls are best-effort in non-host-bridge environments.
    }
  };

  const minimizeWindow = async () => {
    if (!windowControlsVisible) return;
    try {
      await getCurrentWindow().minimize();
    } catch {
      // Ignore non-host-bridge environments.
    }
  };

  const closeWindow = async () => {
    if (!windowControlsVisible) return;
    try {
      await getCurrentWindow().close();
    } catch {
      // Ignore non-host-bridge environments.
    }
  };

  const handleHeaderDoubleClick = (event: MouseEvent<HTMLElement>) => {
    if (!windowControlsVisible) return;
    if (isInteractiveWindowTarget(event.target)) return;
    void toggleWindowMaximize();
  };

  return (
    <header
      className="hypervisor-client-header"
      onDoubleClick={handleHeaderDoubleClick}
    >
      <div
        className="hypervisor-client-drag-surface"
        data-host-drag-region
        onMouseDown={startHostWindowDrag}
        aria-hidden="true"
      />

      {windowControlsVisible ? (
        <div
          className="hypervisor-client-window-controls"
          aria-label="Window controls"
        >
          <button
            type="button"
            className="hypervisor-client-window-button"
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
            className="hypervisor-client-window-button"
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
            className="hypervisor-client-window-button hypervisor-client-window-button--close"
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
