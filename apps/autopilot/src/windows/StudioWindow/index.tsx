import React, {
  useEffect,
  useState,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { RuntimeCatalogStageModal } from "../../components/RuntimeCatalogStageModal";
import { CommandPalette } from "../../components/CommandPalette";
import { TauriRuntime } from "../../services/TauriRuntime";
import { isBenignTauriListenerCleanupError } from "../../services/tauriListeners";
import { StudioWindowMainContent } from "./components/StudioWindowMainContent";
import { useStudioWindowController } from "./useStudioWindowController";

import "@ioi/agent-ide/dist/style.css";
import "../shared/AssistantWorkbench.css";
import "./StudioWindow.css";

const runtime = new TauriRuntime("studio");

type StudioCrashReport = {
  source: "render" | "runtime";
  message: string;
  detail: string | null;
};

function describeStudioError(
  value: unknown,
  source: StudioCrashReport["source"],
  fallbackMessage: string,
): StudioCrashReport {
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
        ? `Studio render asset failed to load from ${sourceUrl}.`
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

function shouldIgnoreStudioRuntimeError(value: unknown): boolean {
  return isBenignTauriListenerCleanupError(value);
}

function StudioWindowCrashScreen({
  error,
}: {
  error: StudioCrashReport;
}) {
  return (
    <div className="studio-window studio-window--crashed">
      <section className="studio-window-crash-card" aria-live="polite">
        <p className="studio-window-crash-kicker">Studio render blocked</p>
        <h1>{error.message}</h1>
        <p>
          Studio hit a native render failure instead of opening a usable main
          app surface. Reload this window and, if needed, continue from
          Spotlight while we fix the underlying seam.
        </p>
        <div className="studio-window-crash-meta">
          <span>{error.source === "render" ? "React render error" : "Runtime error"}</span>
          {error.detail ? <span>Stack captured</span> : <span>No stack available</span>}
        </div>
        {error.detail ? (
          <pre className="studio-window-crash-detail">{error.detail}</pre>
        ) : null}
        <div className="studio-window-crash-actions">
          <button
            type="button"
            className="studio-window-crash-button"
            onClick={() => window.location.reload()}
          >
            Reload Studio
          </button>
          <button
            type="button"
            className="studio-window-crash-button secondary"
            onClick={() => window.location.replace("/spotlight")}
          >
            Open Spotlight Route
          </button>
        </div>
      </section>
    </div>
  );
}

class StudioWindowRenderBoundary extends React.Component<
  {
    children: ReactNode;
    externalError: StudioCrashReport | null;
  },
  {
    renderError: StudioCrashReport | null;
  }
> {
  state = {
    renderError: null,
  };

  static getDerivedStateFromError(error: Error) {
    return {
      renderError: describeStudioError(
        error,
        "render",
        "Studio failed to render.",
      ),
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const base = describeStudioError(
      error,
      "render",
      "Studio failed to render.",
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
      return <StudioWindowCrashScreen error={crash} />;
    }
    return this.props.children;
  }
}

function StudioWindowCrashGuard({
  children,
}: {
  children: ReactNode;
}) {
  const [runtimeError, setRuntimeError] = useState<StudioCrashReport | null>(null);

  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      if (shouldIgnoreStudioRuntimeError(event.error ?? event.message)) {
        return;
      }
      setRuntimeError(
        describeStudioError(
          event.error ?? event.message,
          "runtime",
          "Studio hit a runtime error.",
        ),
      );
    };
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      if (shouldIgnoreStudioRuntimeError(event.reason)) {
        return;
      }
      setRuntimeError(
        describeStudioError(
          event.reason,
          "runtime",
          "Studio hit an unhandled runtime rejection.",
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
    <StudioWindowRenderBoundary externalError={runtimeError}>
      {children}
    </StudioWindowRenderBoundary>
  );
}

function StudioWindowLoaded() {
  const controller = useStudioWindowController();
  const handleStageCatalogEntry = async (entry: {
    id: string;
    name: string;
    description: string;
    ownerLabel: string;
    entryKind: string;
    runtimeNotes: string;
    statusLabel?: string;
    image: string;
  }, notes: string) => {
    const baseNote = `Stage ${entry.entryKind.toLowerCase()} ${entry.name} from the Studio runtime catalog into the Local Engine queue.`;
    await runtime.stageRuntimeCatalogEntry(
      entry.id,
      notes.trim() || `${baseNote} ${entry.runtimeNotes}`.trim(),
    );
  };

  return (
    <div className="studio-window">
      <StudioWindowMainContent controller={controller} runtime={runtime} />

      {controller.modals.commandPaletteOpen ? (
        <CommandPalette
          activeView={controller.activeView}
          workflowSurface={controller.workflow.surface}
          currentProjectId={controller.currentProject.id}
          notificationCount={controller.notificationBadgeCount}
          onClose={controller.modals.closeCommandPalette}
          onOpenPrimaryView={controller.changePrimaryView}
          onOpenWorkflowSurface={controller.workflow.openSurface}
          onSelectProject={controller.workflow.selectProject}
          projects={controller.projects}
        />
      ) : null}

      {controller.modals.catalogStageModalOpen &&
      controller.catalog.selectedCatalogEntry ? (
        <RuntimeCatalogStageModal
          isOpen={controller.modals.catalogStageModalOpen}
          onClose={controller.modals.closeCatalogStageModal}
          onStageEntry={handleStageCatalogEntry}
          onOpenCapabilities={() => {
            controller.modals.closeCatalogStageModal();
            controller.capabilities.openSurface("engine");
          }}
          entry={controller.catalog.selectedCatalogEntry}
        />
      ) : null}
    </div>
  );
}

export function StudioWindow() {
  return (
    <StudioWindowCrashGuard>
      <StudioWindowLoaded />
    </StudioWindowCrashGuard>
  );
}
