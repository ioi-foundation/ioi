import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import { StudioArtifactLogicalSurface } from "./StudioArtifactLogicalSurface";
import {
  mirrorBuildSession,
  type StudioArtifactSurfaceProps,
} from "./studioArtifactSurfaceShared";
import { StudioArtifactWorkspaceSurface } from "./StudioArtifactWorkspaceSurface";

export function StudioArtifactSurface({
  task,
  onCollapse,
  onSeedIntent,
}: StudioArtifactSurfaceProps) {
  const studioSession = task?.studio_session ?? null;
  const rendererSession =
    task?.renderer_session ?? mirrorBuildSession(task?.build_session ?? null);
  const manifest = studioSession?.artifactManifest ?? null;
  const [retrying, setRetrying] = useState(false);

  if (!studioSession || !manifest) {
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
      onCollapse={onCollapse}
      onSeedIntent={onSeedIntent}
    />
  );
}
