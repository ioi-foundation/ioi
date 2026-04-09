import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import { StudioArtifactLogicalSurface } from "./StudioArtifactLogicalSurface";
import {
  collectAvailableStudioArtifacts,
  deriveRendererSessionForStudioSession,
  extractStudioArtifactSessionFromEvent,
} from "./studioArtifactConversationModel";
import { StudioArtifactMenuSurface } from "./StudioArtifactMenuSurface";
import {
  mirrorBuildSession,
  type StudioArtifactSurfaceProps,
} from "./studioArtifactSurfaceShared";
import { resolveStudioExecutionPreview } from "./studioExecutionPreview";
import { StudioArtifactWorkspaceSurface } from "./StudioArtifactWorkspaceSurface";

export function StudioArtifactSurface({
  task,
  events = [],
  selectedStudioSessionId = null,
  onSelectStudioSession,
  onCollapse,
  onSeedIntent,
}: StudioArtifactSurfaceProps) {
  const activeStudioSession = task?.studio_session ?? null;
  const availableArtifacts = useMemo(
    () => collectAvailableStudioArtifacts(events, activeStudioSession),
    [activeStudioSession, events],
  );
  const historicalStudioSessions = useMemo(() => {
    const sessions = new Map<string, NonNullable<typeof activeStudioSession>>();

    for (const event of events) {
      const session = extractStudioArtifactSessionFromEvent(event);
      if (!session || session.outcomeRequest.outcomeKind !== "artifact") {
        continue;
      }
      sessions.set(session.sessionId, session);
    }

    return sessions;
  }, [events]);
  const studioSession = selectedStudioSessionId
    ? selectedStudioSessionId === activeStudioSession?.sessionId
      ? activeStudioSession
      : historicalStudioSessions.get(selectedStudioSessionId) ?? null
    : null;
  const rendererSession =
    studioSession?.sessionId === activeStudioSession?.sessionId
      ? task?.renderer_session ?? mirrorBuildSession(task?.build_session ?? null)
      : studioSession
        ? deriveRendererSessionForStudioSession(
            studioSession,
            task?.renderer_session ?? null,
            task?.build_session ?? null,
          )
        : null;
  const manifest = studioSession?.artifactManifest ?? null;
  const executionEnvelope = studioSession?.materialization?.executionEnvelope ?? null;
  const swarmExecution =
    studioSession?.materialization?.swarmExecution ??
    executionEnvelope?.executionSummary ??
    null;
  const livePreview = resolveStudioExecutionPreview({
    executionEnvelope,
    workerReceipts: studioSession?.materialization?.swarmWorkerReceipts,
    changeReceipts: studioSession?.materialization?.swarmChangeReceipts,
  });
  const [retrying, setRetrying] = useState(false);
  const handleBrowseArtifacts =
    availableArtifacts.length > 0
      ? () => onSelectStudioSession(null)
      : null;

  if (
    availableArtifacts.length > 0 &&
    (selectedStudioSessionId === null || !studioSession)
  ) {
    return (
      <StudioArtifactMenuSurface
        artifacts={availableArtifacts}
        activeStudioSessionId={activeStudioSession?.sessionId ?? null}
        onOpenStudioSession={onSelectStudioSession}
        onCollapse={onCollapse}
      />
    );
  }

  if (!studioSession) {
    return (
      <section className="studio-artifact-surface studio-artifact-surface--empty">
        <div className="studio-artifact-empty-copy">
          <span className="studio-artifact-kicker">Studio</span>
          <h2>Artifact-first creation starts here.</h2>
          <p>
            Conversation stays in control. Studio only opens an artifact stage when
            the query outcome should become a real work product with its own
            renderer, evidence, and verification state.
          </p>
        </div>

        <div className="studio-artifact-empty-actions">
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
      <section className="studio-artifact-surface studio-artifact-surface--empty">
        <div className="studio-artifact-empty-copy">
          <span className="studio-artifact-kicker">Artifact stage</span>
          <h2>Materializing the artifact surface.</h2>
          <p>
            Studio has already committed this request to an artifact route. The
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
          <div className="studio-artifact-renderer-empty">
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
          await invoke("studio_retry_renderer_session", {
            sessionId: rendererSession.sessionId,
          });
        } finally {
          setRetrying(false);
        }
      }
    : null;

  if (manifest.renderer === "workspace_surface" && rendererSession?.workspaceRoot) {
    return (
      <StudioArtifactWorkspaceSurface
        manifest={manifest}
        studioSession={studioSession}
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
    <StudioArtifactLogicalSurface
      manifest={manifest}
      studioSession={studioSession}
      rendererSession={rendererSession}
      retrying={retrying}
      onRetry={handleRetry}
      onBrowseArtifacts={handleBrowseArtifacts}
      onCollapse={onCollapse}
      onSeedIntent={onSeedIntent}
    />
  );
}
