import type { ConversationArtifactEntry } from "./artifactConversationModel";
import {
  displayArtifactClassLabel,
  displayRendererLabel,
  formatStatusLabel,
} from "./artifactSurfaceShared";

type ArtifactMenuSurfaceProps = {
  artifacts: ConversationArtifactEntry[];
  activeChatSessionId?: string | null;
  onOpenChatSession: (chatSessionId: string) => void;
  onCollapse?: (() => void) | null;
};

function artifactMenuBadge(
  artifact: ConversationArtifactEntry,
  isActive: boolean,
): { label: string; muted?: boolean } | null {
  const lifecycleState = String(artifact.lifecycleState || "").trim().toLowerCase();
  if (
    lifecycleState === "ready" ||
    lifecycleState === "partial" ||
    lifecycleState === "blocked" ||
    lifecycleState === "failed"
  ) {
    return { label: formatStatusLabel(artifact.lifecycleState || artifact.status) };
  }

  if (isActive) {
    return { label: "Live" };
  }

  return null;
}

function artifactMenuSummary(artifact: ConversationArtifactEntry): string {
  const verifiedSummary = artifact.chatSession.verifiedReply.summary.trim();
  if (verifiedSummary.length > 0) {
    return verifiedSummary;
  }

  const summary = artifact.summary.trim();
  if (summary.length > 0) {
    return summary;
  }

  return `Open ${artifact.title} to inspect its explorer, source, and render stages.`;
}

function artifactMenuTimestamp(artifact: ConversationArtifactEntry): string | null {
  const raw = artifact.chatSession.updatedAt || artifact.timestamp;
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) {
    return null;
  }

  return new Date(parsed).toLocaleString();
}

export function ArtifactMenuSurface({
  artifacts,
  activeChatSessionId = null,
  onOpenChatSession,
  onCollapse = null,
}: ArtifactMenuSurfaceProps) {
  return (
    <section
      className="chat-artifact-surface chat-artifact-surface--menu"
      aria-label="Chat artifact menu"
    >
      <div className="chat-artifact-menu">
        <header className="chat-artifact-menu-header">
          <div className="chat-artifact-menu-copy">
            <span className="chat-artifact-kicker">Artifacts</span>
          </div>

          {onCollapse ? (
            <button
              type="button"
              className="chat-artifact-stage-button"
              onClick={onCollapse}
            >
              Collapse artifact
            </button>
          ) : null}
        </header>

        <div className="chat-artifact-menu-list" role="list">
          {artifacts.map((artifact) => {
            const isLive = artifact.sessionId === activeChatSessionId;
            const lifecycleState = String(artifact.lifecycleState || "").trim().toLowerCase();
            const showLiveStyling =
              isLive && lifecycleState !== "blocked" && lifecycleState !== "failed";
            const timestampLabel = artifactMenuTimestamp(artifact);
            const badge = artifactMenuBadge(artifact, isLive);

            return (
              <button
                key={artifact.key}
                type="button"
                className={`chat-artifact-menu-item ${showLiveStyling ? "is-live" : ""}`}
                onClick={() => onOpenChatSession(artifact.sessionId)}
              >
                <div className="chat-artifact-menu-item-head">
                  <div className="chat-artifact-menu-item-title-row">
                    <strong>{artifact.title}</strong>
                    {badge ? (
                      <span
                        className={`chat-artifact-badge ${badge.muted ? "is-muted" : ""}`.trim()}
                      >
                        {badge.label}
                      </span>
                    ) : null}
                  </div>
                  {timestampLabel ? (
                    <time
                      className="chat-artifact-menu-item-time"
                      dateTime={artifact.chatSession.updatedAt || artifact.timestamp}
                    >
                      {timestampLabel}
                    </time>
                  ) : null}
                </div>

                <p>{artifactMenuSummary(artifact)}</p>

                <div className="chat-artifact-menu-item-meta">
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
