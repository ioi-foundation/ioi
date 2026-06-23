import React, {
  useEffect,
  useState,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { CommandPalette } from "../../components/CommandPalette";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
  subscribeHypervisorAppearance,
} from "../../services/hypervisorAppearance";
import { HypervisorClientRuntime } from "../../services/HypervisorClientRuntime";
import { isBenignHostListenerCleanupError } from "../../services/hostListeners";
import { markHypervisorMetric } from "../../services/workspacePerf";
import { HypervisorShellContent } from "./components/HypervisorShellContent";
import { HypervisorNewSessionModal } from "./components/HypervisorNewSessionModal";
import {
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  type HypervisorModelMountInventorySnapshot,
} from "../../domain/harnessAdapterModel";
import { shouldAttemptHypervisorDaemonProjectionFetch } from "./hypervisorDaemonEndpoint";
import {
  HYPERVISOR_MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY,
  loadHypervisorModelMountInventorySnapshot,
} from "../../domain/modelMountInventoryModel";
import { useHypervisorShellController } from "./useHypervisorShellController";

import "@ioi/hypervisor-workbench/dist/style.css";
import "../shared/AssistantWorkbench.css";
import "./HypervisorShellWindow.css";

const runtime = new HypervisorClientRuntime("hypervisor");

type HypervisorCrashReport = {
  source: "render" | "runtime";
  message: string;
  detail: string | null;
};

function describeHypervisorError(
  value: unknown,
  source: HypervisorCrashReport["source"],
  fallbackMessage: string,
): HypervisorCrashReport {
  if (value instanceof Error) {
    return {
      source,
      message: value.message || fallbackMessage,
      detail: value.stack || null,
    };
  }

  if (typeof value === "string" && value.trim().length > 0) {
    return {
      source,
      message: value.trim(),
      detail: null,
    };
  }

  if (typeof ErrorEvent !== "undefined" && value instanceof ErrorEvent) {
    return {
      source,
      message: value.message || fallbackMessage,
      detail: value.filename
        ? `${value.filename}:${value.lineno}:${value.colno}`
        : null,
    };
  }

  if (typeof Event !== "undefined" && value instanceof Event) {
    const target = value.target as HTMLScriptElement | null;
    const sourceUrl =
      target?.getAttribute?.("src") ||
      (target && "src" in target ? String((target as { src?: string }).src || "") : "");
    return {
      source,
      message: sourceUrl
        ? `Hypervisor render asset failed to load from ${sourceUrl}.`
        : fallbackMessage,
      detail: value.type ? `Event type: ${value.type}` : null,
    };
  }

  if (
    value &&
    typeof value === "object" &&
    "message" in value &&
    typeof (value as { message?: unknown }).message === "string"
  ) {
    return {
      source,
      message: ((value as { message: string }).message || "").trim() || fallbackMessage,
      detail: null,
    };
  }

  return {
    source,
    message: fallbackMessage,
    detail: null,
  };
}

function shouldIgnoreHypervisorRuntimeError(value: unknown): boolean {
  return isBenignHostListenerCleanupError(value);
}

function HypervisorShellWindowCrashScreen({
  error,
}: {
  error: HypervisorCrashReport;
}) {
  return (
    <div className="hypervisor-window hypervisor-window--crashed">
      <section className="hypervisor-window-crash-card" aria-live="polite">
        <p className="hypervisor-window-crash-kicker">Hypervisor render blocked</p>
        <h1>{error.message}</h1>
        <p>
          Hypervisor hit a native render failure instead of opening a usable
          main app surface. Reload this window and, if needed, continue from
          Sessions while we fix the underlying path.
        </p>
        <div className="hypervisor-window-crash-meta">
          <span>{error.source === "render" ? "React render error" : "Runtime error"}</span>
          {error.detail ? <span>Stack captured</span> : <span>No stack available</span>}
        </div>
        {error.detail ? (
          <pre className="hypervisor-window-crash-detail">{error.detail}</pre>
        ) : null}
        <div className="hypervisor-window-crash-actions">
          <button
            type="button"
            className="hypervisor-window-crash-button"
            onClick={() => window.location.reload()}
          >
            Reload Hypervisor
          </button>
          <button
            type="button"
            className="hypervisor-window-crash-button secondary"
            onClick={() => window.location.replace("/sessions")}
          >
            Open Sessions
          </button>
        </div>
      </section>
    </div>
  );
}

class HypervisorShellWindowRenderBoundary extends React.Component<
  {
    children: ReactNode;
    externalError: HypervisorCrashReport | null;
  },
  {
    renderError: HypervisorCrashReport | null;
  }
> {
  state = {
    renderError: null,
  };

  static getDerivedStateFromError(error: Error) {
    return {
      renderError: describeHypervisorError(
        error,
        "render",
        "Hypervisor failed to render.",
      ),
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const base = describeHypervisorError(
      error,
      "render",
      "Hypervisor failed to render.",
    );
    this.setState({
      renderError: {
        ...base,
        detail: errorInfo.componentStack?.trim() || base.detail,
      },
    });
  }

  render() {
    const crash = this.state.renderError || this.props.externalError;
    if (crash) {
      return <HypervisorShellWindowCrashScreen error={crash} />;
    }
    return this.props.children;
  }
}

function HypervisorShellWindowCrashGuard({
  children,
}: {
  children: ReactNode;
}) {
  const [runtimeError, setRuntimeError] = useState<HypervisorCrashReport | null>(null);

  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      if (shouldIgnoreHypervisorRuntimeError(event.error ?? event.message)) {
        return;
      }
      setRuntimeError(
        describeHypervisorError(
          event.error ?? event.message,
          "runtime",
          "Hypervisor hit a runtime error.",
        ),
      );
    };
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      if (shouldIgnoreHypervisorRuntimeError(event.reason)) {
        return;
      }
      setRuntimeError(
        describeHypervisorError(
          event.reason,
          "runtime",
          "Hypervisor hit an unhandled runtime rejection.",
        ),
      );
    };

    window.addEventListener("error", handleError);
    window.addEventListener("unhandledrejection", handleUnhandledRejection);
    return () => {
      window.removeEventListener("error", handleError);
      window.removeEventListener("unhandledrejection", handleUnhandledRejection);
    };
  }, []);

  return (
    <HypervisorShellWindowRenderBoundary externalError={runtimeError}>
      {children}
    </HypervisorShellWindowRenderBoundary>
  );
}

function HypervisorShellWindowLoaded() {
  const controller = useHypervisorShellController();
  const [modelMountInventory, setModelMountInventory] =
    useState<HypervisorModelMountInventorySnapshot>(
      HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
    );

  useEffect(() => {
    markHypervisorMetric("hypervisor_window_loaded");
  }, []);

  useEffect(() => {
    if (
      !shouldAttemptHypervisorDaemonProjectionFetch(
        HYPERVISOR_MODEL_MOUNT_DAEMON_ENDPOINT_STORAGE_KEY,
      )
    ) {
      return;
    }
    let cancelled = false;
    loadHypervisorModelMountInventorySnapshot()
      .then((snapshot) => {
        if (!cancelled) {
          setModelMountInventory(snapshot);
        }
      })
      .catch((error) => {
        console.warn(
          "[Hypervisor][NewSession] model-mount inventory unavailable",
          error,
        );
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    applyHypervisorAppearance(loadHypervisorAppearance());
    return subscribeHypervisorAppearance(applyHypervisorAppearance);
  }, []);

  return (
    <div className="hypervisor-window">
      <HypervisorShellContent controller={controller} runtime={runtime} />

      {controller.modals.commandPaletteOpen ? (
        <CommandPalette
          mode={controller.modals.commandPaletteMode}
          initialQuery={controller.modals.commandPaletteInitialQuery}
          activeView={controller.activeView}
          currentProjectId={controller.currentProject.id}
          notificationCount={controller.notificationBadgeCount}
          onClose={controller.modals.closeCommandPalette}
          onOpenPrimaryView={controller.changePrimaryView}
          onSelectProject={controller.workflow.selectProject}
          projects={controller.projects}
        />
      ) : null}

      {controller.modals.newSessionModalOpen ? (
        <HypervisorNewSessionModal
          isOpen={controller.modals.newSessionModalOpen}
          currentProject={controller.currentProject}
          projects={controller.projects}
          modelMountInventory={modelMountInventory}
          initialSeedIntent={controller.modals.newSessionSeedIntent}
          initialRecipeId={controller.modals.newSessionRecipeId}
          onClose={controller.modals.closeNewSessionModal}
          onLaunch={controller.modals.launchNewSession}
        />
      ) : null}
    </div>
  );
}

export function HypervisorShellWindow() {
  return (
    <HypervisorShellWindowCrashGuard>
      <HypervisorShellWindowLoaded />
    </HypervisorShellWindowCrashGuard>
  );
}
