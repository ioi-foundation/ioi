import type { StudioConversationArtifactEntry } from "./studioArtifactConversationModel";
import {
  displayArtifactClassLabel,
  displayRendererLabel,
  formatStatusLabel,
} from "./studioArtifactSurfaceShared";

type StudioArtifactMenuSurfaceProps = {
  artifacts: StudioConversationArtifactEntry[];
  activeStudioSessionId?: string | null;
  onOpenStudioSession: (studioSessionId: string) => void;
  onCollapse?: (() => void) | null;
};

function artifactMenuSummary(artifact: StudioConversationArtifactEntry): string {
  const verifiedSummary = artifact.studioSession.verifiedReply.summary.trim();
  if (verifiedSummary.length > 0) {
    return verifiedSummary;
  }

  const summary = artifact.summary.trim();
  if (summary.length > 0) {
    return summary;
  }

  return `Open ${artifact.title} to inspect its explorer, source, and render stages.`;
}

function artifactMenuTimestamp(artifact: StudioConversationArtifactEntry): string | null {
  const raw = artifact.studioSession.updatedAt || artifact.timestamp;
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) {
    return null;
  }

  return new Date(parsed).toLocaleString();
}

export function StudioArtifactMenuSurface({
  artifacts,
  activeStudioSessionId = null,
  onOpenStudioSession,
  onCollapse = null,
}: StudioArtifactMenuSurfaceProps) {
  return (
    <section
      className="studio-artifact-surface studio-artifact-surface--menu"
      aria-label="Studio artifact menu"
    >
      <div className="studio-artifact-menu">
        <header className="studio-artifact-menu-header">
          <div className="studio-artifact-menu-copy">
            <span className="studio-artifact-kicker">Artifacts</span>
          </div>

          {onCollapse ? (
            <button
              type="button"
              className="studio-artifact-stage-button"
              onClick={onCollapse}
            >
              Collapse artifact
            </button>
          ) : null}
        </header>

        <div className="studio-artifact-menu-list" role="list">
          {artifacts.map((artifact) => {
            const isLive = artifact.sessionId === activeStudioSessionId;
            const timestampLabel = artifactMenuTimestamp(artifact);

            return (
              <button
                key={artifact.key}
                type="button"
                className={`studio-artifact-menu-item ${isLive ? "is-live" : ""}`}
                onClick={() => onOpenStudioSession(artifact.sessionId)}
              >
                <div className="studio-artifact-menu-item-head">
                  <div className="studio-artifact-menu-item-title-row">
                    <strong>{artifact.title}</strong>
                    {isLive ? (
                      <span className="studio-artifact-badge">Live</span>
                    ) : null}
                  </div>
                  {timestampLabel ? (
                    <time
                      className="studio-artifact-menu-item-time"
                      dateTime={artifact.studioSession.updatedAt || artifact.timestamp}
                    >
                      {timestampLabel}
                    </time>
                  ) : null}
                </div>

                <p>{artifactMenuSummary(artifact)}</p>

                <div className="studio-artifact-menu-item-meta">
                  <span>{displayArtifactClassLabel(artifact.artifactClass)}</span>
                  <span>{displayRendererLabel(artifact.renderer)}</span>
                  <span>
                    {artifact.fileCount} {artifact.fileCount === 1 ? "file" : "files"}
                  </span>
                  <span>{formatStatusLabel(artifact.status)}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
