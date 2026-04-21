import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import { ArtifactLogicalSurface } from "./ArtifactLogicalSurface";
import {
  collectAvailableArtifacts,
  deriveRendererSessionForChatSession,
  extractChatArtifactSessionFromEvent,
} from "./artifactConversationModel";
import { ArtifactMenuSurface } from "./ArtifactMenuSurface";
import {
  mirrorBuildSession,
  type ChatArtifactSurfaceProps,
} from "./artifactSurfaceShared";
import { resolveChatExecutionPreview } from "./chatExecutionPreview";
import { ArtifactWorkspaceSurface } from "./ArtifactWorkspaceSurface";

export function ChatArtifactSurface({
  task,
  events = [],
  selectedChatSessionId = null,
  onSelectChatSession,
  onCollapse,
  onSeedIntent,
}: ChatArtifactSurfaceProps) {
  const activeChatSession = task?.chat_session ?? null;
  const availableArtifacts = useMemo(
    () => collectAvailableArtifacts(events, activeChatSession),
    [activeChatSession, events],
  );
  const historicalChatSessions = useMemo(() => {
    const sessions = new Map<string, NonNullable<typeof activeChatSession>>();

    for (const event of events) {
      const session = extractChatArtifactSessionFromEvent(event);
      if (!session || session.outcomeRequest.outcomeKind !== "artifact") {
        continue;
      }
      sessions.set(session.sessionId, session);
    }

    return sessions;
  }, [events]);
  const chatSession = selectedChatSessionId
    ? selectedChatSessionId === activeChatSession?.sessionId
      ? activeChatSession
      : historicalChatSessions.get(selectedChatSessionId) ?? null
    : null;
  const rendererSession =
    chatSession?.sessionId === activeChatSession?.sessionId
      ? task?.renderer_session ?? mirrorBuildSession(task?.build_session ?? null)
      : chatSession
        ? deriveRendererSessionForChatSession(
            chatSession,
            task?.renderer_session ?? null,
            task?.build_session ?? null,
          )
        : null;
  const manifest = chatSession?.artifactManifest ?? null;
  const executionEnvelope = chatSession?.materialization?.executionEnvelope ?? null;
  const swarmExecution =
    chatSession?.materialization?.swarmExecution ??
    executionEnvelope?.executionSummary ??
    null;
  const livePreview = resolveChatExecutionPreview({
    executionEnvelope,
    workerReceipts: chatSession?.materialization?.swarmWorkerReceipts,
    changeReceipts: chatSession?.materialization?.swarmChangeReceipts,
  });
  const [retrying, setRetrying] = useState(false);
  const handleBrowseArtifacts =
    availableArtifacts.length > 0
      ? () => onSelectChatSession(null)
      : null;

  if (
    availableArtifacts.length > 0 &&
    (selectedChatSessionId === null || !chatSession)
  ) {
    return (
      <ArtifactMenuSurface
        artifacts={availableArtifacts}
        activeChatSessionId={activeChatSession?.sessionId ?? null}
        onOpenChatSession={onSelectChatSession}
        onCollapse={onCollapse}
      />
    );
  }

  if (!chatSession) {
    return (
      <section className="chat-artifact-surface chat-artifact-surface--empty">
        <div className="chat-artifact-empty-copy">
          <span className="chat-artifact-kicker">Chat</span>
          <h2>Artifact-first creation starts here.</h2>
          <p>
            Conversation stays in control. Chat only opens an artifact stage when
            the query outcome should become a real work product with its own
            renderer, evidence, and verification state.
          </p>
        </div>

        <div className="chat-artifact-empty-actions">
          <button
            type="button"
            onClick={() => onSeedIntent("Create a markdown artifact that documents our release checklist")}
          >
            Create a document artifact
          </button>
          <button
            type="button"
            onClick={() => onSeedIntent("Create an SVG hero concept for an AI tools brand")}
          >
            Create a visual artifact
          </button>
          <button
            type="button"
            onClick={() => onSeedIntent("Create a workspace project for a billing settings surface")}
          >
            Create a workspace artifact
          </button>
        </div>
      </section>
    );
  }

  if (!manifest) {
    return (
      <section className="chat-artifact-surface chat-artifact-surface--empty">
        <div className="chat-artifact-empty-copy">
          <span className="chat-artifact-kicker">Artifact stage</span>
          <h2>Materializing the artifact surface.</h2>
          <p>
            Chat has already committed this request to an artifact route. The
            renderer shell opens early so you can follow the work while files,
            verification, and preview state are still landing.
          </p>
          {swarmExecution ? (
            <p>
              {swarmExecution.completedWorkItems}/{swarmExecution.totalWorkItems} work items
              completed · {swarmExecution.currentStage}
            </p>
          ) : null}
        </div>

        {livePreview?.content ? (
          <div className="chat-artifact-renderer-empty">
            <strong>{livePreview.label || "Live artifact output"}</strong>
            <pre>{livePreview.content}</pre>
          </div>
        ) : null}
      </section>
    );
  }

  const handleRetry = rendererSession
    ? async () => {
        setRetrying(true);
        try {
          await invoke("chat_retry_renderer_session", {
            sessionId: rendererSession.sessionId,
          });
        } finally {
          setRetrying(false);
        }
      }
    : null;

  if (manifest.renderer === "workspace_surface" && rendererSession?.workspaceRoot) {
    return (
      <ArtifactWorkspaceSurface
        manifest={manifest}
        chatSession={chatSession}
        rendererSession={rendererSession}
        retrying={retrying}
        onRetry={handleRetry}
        onBrowseArtifacts={handleBrowseArtifacts}
        onCollapse={onCollapse}
        onSeedIntent={onSeedIntent}
      />
    );
  }

  return (
    <ArtifactLogicalSurface
      manifest={manifest}
      chatSession={chatSession}
      rendererSession={rendererSession}
      retrying={retrying}
      onRetry={handleRetry}
      onBrowseArtifacts={handleBrowseArtifacts}
      onCollapse={onCollapse}
      onSeedIntent={onSeedIntent}
    />
  );
}
