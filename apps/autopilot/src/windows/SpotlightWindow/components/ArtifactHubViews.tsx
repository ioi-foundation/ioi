import type {
  Artifact,
  ArtifactHubViewKey,
  SourceBrowseRow,
  SourceSearchRow,
  ThoughtAgentSummary,
} from "../../../types";
import { icons } from "./Icons";
import { VisualEvidenceCard } from "./VisualEvidenceCard";
import type { ScreenshotReceiptEvidence } from "../utils/screenshotEvidence";

export interface KernelLogRow {
  eventId: string;
  timestamp: string;
  title: string;
  eventType: string;
  status: string;
  toolName: string;
  summary: string;
}

export interface SecurityPolicyRow {
  eventId: string;
  timestamp: string;
  decision: string;
  toolName: string;
  stage: string;
  resolution: string;
  summary: string;
  reportArtifactId: string | null;
}

function clipText(value: string, maxChars: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

interface ArtifactHubDetailViewProps {
  activeView: ArtifactHubViewKey;
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
  thoughtAgents: ThoughtAgentSummary[];
  visibleSourceCount: number;
  kernelLogs: KernelLogRow[];
  securityRows: SecurityPolicyRow[];
  fileArtifacts: Artifact[];
  revisionArtifacts: Artifact[];
  screenshotReceipts: ScreenshotReceiptEvidence[];
  onOpenArtifact?: (artifactId: string) => void;
  openExternalUrl: (url: string) => Promise<void>;
  extractArtifactUrl: (artifact: Artifact) => string | null;
  formatTimestamp: (value: string) => string;
}

function ThoughtsView({
  searches,
  browses,
  thoughtAgents,
  openExternalUrl,
}: {
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
  thoughtAgents: ThoughtAgentSummary[];
  openExternalUrl: (url: string) => Promise<void>;
}) {
  const hasContent = searches.length > 0 || browses.length > 0 || thoughtAgents.length > 0;
  if (!hasContent) {
    return <p className="artifact-hub-empty">No structured thought activity was captured.</p>;
  }

  return (
    <div className="artifact-hub-thoughts">
      {searches.length > 0 && (
        <section className="thoughts-section">
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">Agent</span>
            <span className="thoughts-agent-role">Leader</span>
          </div>
          <div className="thoughts-items thoughts-items-linked">
            {searches.map((entry, index) => (
              <div className="thoughts-item thoughts-item-search" key={`thought-search-${index}`}>
                <span className="thoughts-item-icon">{icons.search}</span>
                <div className="thoughts-item-main">
                  <span className="thoughts-item-kind">Searched web</span>
                  <span className="thoughts-item-query">{entry.query}</span>
                </div>
                <span className="thoughts-item-count">{entry.resultCount}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {browses.length > 0 && (
        <section className="thoughts-section">
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">Agent</span>
            <span className="thoughts-agent-role">Leader</span>
          </div>
          <div className="thoughts-items thoughts-items-linked">
            {browses.map((entry, index) => (
              <div className="thoughts-item" key={`thought-browse-${index}`}>
                <span className="thoughts-item-icon">{icons.globe}</span>
                <div className="thoughts-item-main">
                  <span className="thoughts-item-kind">Browsed</span>
                  <button
                    className="thoughts-item-link"
                    onClick={() => void openExternalUrl(entry.url)}
                    type="button"
                    title={entry.url}
                  >
                    {entry.url}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {thoughtAgents.map((agent, index) => (
        <section className="thoughts-section" key={`thought-agent-${agent.stepIndex}-${index}`}>
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">{agent.agentLabel}</span>
          </div>
          <div className="thoughts-notes">
            {agent.notes.map((note, noteIndex) => (
              <div className="thoughts-note" key={`thought-note-${agent.stepIndex}-${noteIndex}`}>
                {note}
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function SourcesView({
  searches,
  browses,
  visibleSourceCount,
  openExternalUrl,
}: {
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
  visibleSourceCount: number;
  openExternalUrl: (url: string) => Promise<void>;
}) {
  if (searches.length === 0 && browses.length === 0) {
    return <p className="artifact-hub-empty">No web sources captured for this run.</p>;
  }

  return (
    <div className="source-artifact-content">
      <div className="source-agent-header">
        <span className="source-agent-title">Sources</span>
        <span className="source-agent-count">{visibleSourceCount}</span>
      </div>

      {searches.map((entry, index) => (
        <div className="source-row" key={`source-search-${index}`}>
          <span className="source-row-icon">{icons.search}</span>
          <div className="source-row-content">
            <span className="source-row-kind">Searched web</span>
            <span className="source-row-primary source-row-query">{entry.query}</span>
          </div>
          <span className="source-row-badge">{entry.resultCount}</span>
        </div>
      ))}

      {browses.map((entry, index) => (
        <div className="source-row" key={`source-browse-${index}`}>
          <span className="source-row-icon">{icons.globe}</span>
          <div className="source-row-content">
            <span className="source-row-kind">Browsed</span>
            <button
              className="source-row-link"
              onClick={() => void openExternalUrl(entry.url)}
              type="button"
              title={entry.url}
            >
              {entry.url}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function KernelView({ kernelLogs }: { kernelLogs: KernelLogRow[] }) {
  if (kernelLogs.length === 0) {
    return <p className="artifact-hub-empty">No kernel events available.</p>;
  }

  return (
    <div className="artifact-hub-log-list">
      {kernelLogs.map((row) => (
        <article className={`artifact-hub-log-row status-${row.status}`} key={row.eventId}>
          <div className="artifact-hub-log-meta">
            <span>{row.timestamp}</span>
            <span>{row.eventType}</span>
            <span>{row.toolName || "system"}</span>
          </div>
          <div className="artifact-hub-log-title">{row.title}</div>
          {row.summary && <p className="artifact-hub-log-summary">{row.summary}</p>}
        </article>
      ))}
    </div>
  );
}

function SecurityView({
  securityRows,
  onOpenArtifact,
}: {
  securityRows: SecurityPolicyRow[];
  onOpenArtifact?: (artifactId: string) => void;
}) {
  if (securityRows.length === 0) {
    return <p className="artifact-hub-empty">No security policy receipts were captured.</p>;
  }

  return (
    <div className="artifact-hub-policy-list">
      {securityRows.map((row) => (
        <article className="artifact-hub-policy-row" key={row.eventId}>
          <div className="artifact-hub-policy-meta">
            <span className="artifact-hub-policy-pill">{row.decision}</span>
            <span>{row.timestamp}</span>
            <span>{row.toolName}</span>
          </div>
          <div className="artifact-hub-policy-body">
            <span>stage={row.stage}</span>
            <span>resolution={row.resolution}</span>
          </div>
          {row.summary && <p className="artifact-hub-policy-summary">{row.summary}</p>}
          {row.reportArtifactId && onOpenArtifact && (
            <button
              className="artifact-hub-open-btn"
              onClick={() => onOpenArtifact(row.reportArtifactId!)}
              type="button"
            >
              Open report artifact
            </button>
          )}
        </article>
      ))}
    </div>
  );
}

function ArtifactListView({
  items,
  label,
  onOpenArtifact,
  openExternalUrl,
  extractArtifactUrl,
  formatTimestamp,
}: {
  items: Artifact[];
  label: string;
  onOpenArtifact?: (artifactId: string) => void;
  openExternalUrl: (url: string) => Promise<void>;
  extractArtifactUrl: (artifact: Artifact) => string | null;
  formatTimestamp: (value: string) => string;
}) {
  if (items.length === 0) {
    return <p className="artifact-hub-empty">No {label.toLowerCase()} available.</p>;
  }

  return (
    <div className="artifact-hub-generic-list">
      {items.map((artifact) => {
        const url = extractArtifactUrl(artifact);
        return (
            <article className="artifact-hub-generic-row" key={artifact.artifact_id}>
              <div className="artifact-hub-generic-meta">
                <span>{artifact.artifact_type}</span>
                <span>{formatTimestamp(artifact.created_at)}</span>
              </div>
            <div className="artifact-hub-generic-title">{artifact.title}</div>
            {artifact.description && (
              <p className="artifact-hub-generic-summary">{clipText(artifact.description, 180)}</p>
            )}
            <div className="artifact-hub-generic-actions">
              {onOpenArtifact && (
                <button
                  className="artifact-hub-open-btn"
                  onClick={() => onOpenArtifact(artifact.artifact_id)}
                  type="button"
                >
                  Open artifact
                </button>
              )}
              {url && (
                <button
                  className="artifact-hub-open-btn secondary"
                  onClick={() => void openExternalUrl(url)}
                  type="button"
                >
                  Open URL
                </button>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function ScreenshotsView({
  screenshotReceipts,
  formatTimestamp,
}: {
  screenshotReceipts: ScreenshotReceiptEvidence[];
  formatTimestamp: (value: string) => string;
}) {
  if (screenshotReceipts.length === 0) {
    return <p className="artifact-hub-empty">No screenshots captured for this run.</p>;
  }

  return (
    <div className="artifact-hub-screenshot-list">
      {screenshotReceipts.map((receipt) => (
        <article className="artifact-hub-screenshot-row" key={receipt.id}>
          <div className="artifact-hub-generic-meta">
            <span>{formatTimestamp(receipt.timestamp)}</span>
            <span>{receipt.source}</span>
            <span>step {receipt.stepIndex}</span>
          </div>
          {!receipt.hasBlob && (
            <p className="artifact-hub-generic-summary">
              Screenshot action receipt captured, but no retrievable blob hash was emitted.
            </p>
          )}
          <VisualEvidenceCard
            hash={receipt.hash}
            timestamp={receipt.timestamp}
            stepIndex={receipt.stepIndex}
            title={receipt.hasBlob ? "Screenshot receipt" : "Screenshot receipt (metadata-only)"}
            compact={true}
          />
          {!!receipt.summary && (
            <p className="artifact-hub-generic-summary">{clipText(receipt.summary, 180)}</p>
          )}
        </article>
      ))}
    </div>
  );
}

export function ArtifactHubDetailView({
  activeView,
  searches,
  browses,
  thoughtAgents,
  visibleSourceCount,
  kernelLogs,
  securityRows,
  fileArtifacts,
  revisionArtifacts,
  screenshotReceipts,
  onOpenArtifact,
  openExternalUrl,
  extractArtifactUrl,
  formatTimestamp,
}: ArtifactHubDetailViewProps) {
  switch (activeView) {
    case "thoughts":
      return (
        <ThoughtsView
          searches={searches}
          browses={browses}
          thoughtAgents={thoughtAgents}
          openExternalUrl={openExternalUrl}
        />
      );
    case "sources":
      return (
        <SourcesView
          searches={searches}
          browses={browses}
          visibleSourceCount={visibleSourceCount}
          openExternalUrl={openExternalUrl}
        />
      );
    case "kernel_logs":
      return <KernelView kernelLogs={kernelLogs} />;
    case "security_policy":
      return <SecurityView securityRows={securityRows} onOpenArtifact={onOpenArtifact} />;
    case "files":
      return (
        <ArtifactListView
          items={fileArtifacts}
          label="Files"
          onOpenArtifact={onOpenArtifact}
          openExternalUrl={openExternalUrl}
          extractArtifactUrl={extractArtifactUrl}
          formatTimestamp={formatTimestamp}
        />
      );
    case "revisions":
      return (
        <ArtifactListView
          items={revisionArtifacts}
          label="Revisions"
          onOpenArtifact={onOpenArtifact}
          openExternalUrl={openExternalUrl}
          extractArtifactUrl={extractArtifactUrl}
          formatTimestamp={formatTimestamp}
        />
      );
    case "screenshots":
      return (
        <ScreenshotsView
          screenshotReceipts={screenshotReceipts}
          formatTimestamp={formatTimestamp}
        />
      );
    default:
      return null;
  }
}
