import React, {
  useEffect,
  useState,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { RuntimeCatalogStageModal } from "../../components/RuntimeCatalogStageModal";
import { CommandPalette } from "../../components/CommandPalette";
import {
  applyAutopilotAppearance,
  loadAutopilotAppearance,
  subscribeAutopilotAppearance,
} from "../../services/autopilotAppearance";
import { TauriRuntime } from "../../services/TauriRuntime";
import { isBenignTauriListenerCleanupError } from "../../services/tauriListeners";
import { markAutopilotMetric } from "../../services/workspacePerf";
import { ChatWindowMainContent } from "./components/ChatWindowMainContent";
import { useChatWindowController } from "./useChatWindowController";

import "@ioi/agent-ide/dist/style.css";
import "../shared/AssistantWorkbench.css";
import "./ChatWindow.css";

const runtime = new TauriRuntime("chat");

type ChatCrashReport = {
  source: "render" | "runtime";
  message: string;
  detail: string | null;
};

function describeChatError(
  value: unknown,
  source: ChatCrashReport["source"],
  fallbackMessage: string,
): ChatCrashReport {
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
        ? `Chat render asset failed to load from ${sourceUrl}.`
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

function shouldIgnoreChatRuntimeError(value: unknown): boolean {
  return isBenignTauriListenerCleanupError(value);
}

function ChatWindowCrashScreen({
  error,
}: {
  error: ChatCrashReport;
}) {
  return (
    <div className="chat-window chat-window--crashed">
      <section className="chat-window-crash-card" aria-live="polite">
        <p className="chat-window-crash-kicker">Chat render blocked</p>
        <h1>{error.message}</h1>
        <p>
          Chat hit a native render failure instead of opening a usable main
          app surface. Reload this window and, if needed, continue from
          Chat while we fix the underlying seam.
        </p>
        <div className="chat-window-crash-meta">
          <span>{error.source === "render" ? "React render error" : "Runtime error"}</span>
          {error.detail ? <span>Stack captured</span> : <span>No stack available</span>}
        </div>
        {error.detail ? (
          <pre className="chat-window-crash-detail">{error.detail}</pre>
        ) : null}
        <div className="chat-window-crash-actions">
          <button
            type="button"
            className="chat-window-crash-button"
            onClick={() => window.location.reload()}
          >
            Reload Chat
          </button>
          <button
            type="button"
            className="chat-window-crash-button secondary"
            onClick={() => window.location.replace("/chat-session")}
          >
            Open Chat Route
          </button>
        </div>
      </section>
    </div>
  );
}

class ChatWindowRenderBoundary extends React.Component<
  {
    children: ReactNode;
    externalError: ChatCrashReport | null;
  },
  {
    renderError: ChatCrashReport | null;
  }
> {
  state = {
    renderError: null,
  };

  static getDerivedStateFromError(error: Error) {
    return {
      renderError: describeChatError(
        error,
        "render",
        "Chat failed to render.",
      ),
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const base = describeChatError(
      error,
      "render",
      "Chat failed to render.",
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
      return <ChatWindowCrashScreen error={crash} />;
    }
    return this.props.children;
  }
}

function ChatWindowCrashGuard({
  children,
}: {
  children: ReactNode;
}) {
  const [runtimeError, setRuntimeError] = useState<ChatCrashReport | null>(null);

  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      if (shouldIgnoreChatRuntimeError(event.error ?? event.message)) {
        return;
      }
      setRuntimeError(
        describeChatError(
          event.error ?? event.message,
          "runtime",
          "Chat hit a runtime error.",
        ),
      );
    };
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      if (shouldIgnoreChatRuntimeError(event.reason)) {
        return;
      }
      setRuntimeError(
        describeChatError(
          event.reason,
          "runtime",
          "Chat hit an unhandled runtime rejection.",
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
    <ChatWindowRenderBoundary externalError={runtimeError}>
      {children}
    </ChatWindowRenderBoundary>
  );
}

function ChatWindowLoaded() {
  const controller = useChatWindowController();

  useEffect(() => {
    markAutopilotMetric("chat_window_loaded");
  }, []);

  useEffect(() => {
    applyAutopilotAppearance(loadAutopilotAppearance());
    return subscribeAutopilotAppearance(applyAutopilotAppearance);
  }, []);

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
    const baseNote = `Stage ${entry.entryKind.toLowerCase()} ${entry.name} from the Chat runtime catalog into the Local Engine queue.`;
    await runtime.stageRuntimeCatalogEntry(
      entry.id,
      notes.trim() || `${baseNote} ${entry.runtimeNotes}`.trim(),
    );
  };

  return (
    <div className="chat-window">
      <ChatWindowMainContent controller={controller} runtime={runtime} />

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

export function ChatWindow() {
  return (
    <ChatWindowCrashGuard>
      <ChatWindowLoaded />
    </ChatWindowCrashGuard>
  );
}
