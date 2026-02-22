import { useCallback, useEffect, useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type {
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import { icons } from "./Icons";

interface ArtifactHubSidebarProps {
  initialView?: ArtifactHubViewKey;
  events: AgentEvent[];
  artifacts: Artifact[];
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  onOpenArtifact?: (artifactId: string) => void;
  onClose: () => void;
}

interface HubSection {
  key: ArtifactHubViewKey;
  label: string;
  count: number;
}

interface KernelLogRow {
  eventId: string;
  timestamp: string;
  title: string;
  eventType: string;
  status: string;
  toolName: string;
  summary: string;
}

interface SecurityPolicyRow {
  eventId: string;
  timestamp: string;
  decision: string;
  toolName: string;
  stage: string;
  resolution: string;
  summary: string;
  reportArtifactId: string | null;
}

const MAX_KERNEL_LOG_ROWS = 240;
const MAX_SUMMARY_CHARS = 220;

function safeString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function clipText(value: string, maxChars: number = MAX_SUMMARY_CHARS): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function eventToolName(event: AgentEvent): string {
  const digest = event.digest || {};
  const details = event.details || {};
  return (
    safeString(digest.tool_name).trim() ||
    safeString(digest.tool).trim() ||
    safeString(details.tool_name).trim() ||
    safeString(details.tool).trim()
  );
}

function eventSummary(event: AgentEvent): string {
  const details = event.details || {};
  const digest = event.digest || {};
  const raw =
    safeString(details.output).trim() ||
    safeString(details.chunk).trim() ||
    safeString(details.content).trim() ||
    safeString(digest.output_snippet).trim();
  return clipText(raw);
}

function formatTimestamp(value: string): string {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return value;
  return new Date(ms).toISOString();
}

function eventHasPolicyDigest(event: AgentEvent): boolean {
  const digest = event.digest || {};
  const policyKeys = [
    "policy_decision",
    "gate_state",
    "resolution_action",
    "incident_stage",
    "strategy_node",
  ];
  return policyKeys.some((key) => safeString(digest[key as keyof typeof digest]).trim().length > 0);
}

function extractArtifactUrl(artifact: Artifact): string | null {
  const metadata = artifact.metadata || {};
  const candidates = [metadata.url, metadata.source_url, metadata.screenshot_url];
  for (const candidate of candidates) {
    const text = safeString(candidate).trim();
    if (text.startsWith("https://") || text.startsWith("http://")) {
      return text;
    }
  }
  return null;
}

function sectionLabel(key: ArtifactHubViewKey): string {
  switch (key) {
    case "thoughts":
      return "Thoughts";
    case "sources":
      return "Sources";
    case "kernel_logs":
      return "Kernel Logs";
    case "security_policy":
      return "Security Policy";
    case "files":
      return "Files";
    case "revisions":
      return "Revisions";
    case "screenshots":
      return "Screenshots";
    default:
      return "Artifacts";
  }
}

function defaultViewForSections(sections: HubSection[]): ArtifactHubViewKey {
  return sections.find((section) => section.count > 0)?.key || "kernel_logs";
}

export function ArtifactHubSidebar({
  initialView,
  events,
  artifacts,
  sourceSummary,
  thoughtSummary,
  onOpenArtifact,
  onClose,
}: ArtifactHubSidebarProps) {
  const searches = useMemo(
    () => [...(sourceSummary?.searches || [])].sort((a, b) => a.stepIndex - b.stepIndex),
    [sourceSummary?.searches],
  );
  const browses = useMemo(
    () => [...(sourceSummary?.browses || [])].sort((a, b) => a.stepIndex - b.stepIndex),
    [sourceSummary?.browses],
  );
  const thoughtAgents = thoughtSummary?.agents || [];

  const kernelLogs = useMemo<KernelLogRow[]>(() => {
    const rows = events
      .slice()
      .reverse()
      .slice(0, MAX_KERNEL_LOG_ROWS)
      .map((event) => ({
        eventId: event.event_id,
        timestamp: formatTimestamp(event.timestamp),
        title: event.title,
        eventType: event.event_type,
        status: event.status.toLowerCase(),
        toolName: eventToolName(event),
        summary: eventSummary(event),
      }));
    return rows;
  }, [events]);

  const securityRows = useMemo<SecurityPolicyRow[]>(() => {
    const rows: SecurityPolicyRow[] = [];
    for (const event of events) {
      const title = event.title.toLowerCase();
      if (
        event.event_type !== "RECEIPT" &&
        !eventHasPolicyDigest(event) &&
        !title.includes("routingreceipt") &&
        !title.includes("restricted action")
      ) {
        continue;
      }

      const digest = event.digest || {};
      const decision =
        safeString(digest.policy_decision).trim() ||
        (event.event_type === "RECEIPT" ? "receipt" : "policy");
      const stage = safeString(digest.incident_stage).trim() || "n/a";
      const resolution = safeString(digest.resolution_action).trim() || "n/a";
      const reportArtifactId =
        event.artifact_refs?.find((ref) => ref.artifact_type === "REPORT")?.artifact_id || null;

      rows.push({
        eventId: event.event_id,
        timestamp: formatTimestamp(event.timestamp),
        decision,
        toolName: eventToolName(event) || "system",
        stage,
        resolution,
        summary: eventSummary(event),
        reportArtifactId,
      });
    }
    return rows.reverse();
  }, [events]);

  const fileArtifacts = useMemo(
    () => artifacts.filter((artifact) => artifact.artifact_type === "FILE" || artifact.artifact_type === "DIFF"),
    [artifacts],
  );
  const revisionArtifacts = useMemo(
    () =>
      artifacts.filter(
        (artifact) =>
          artifact.artifact_type === "RUN_BUNDLE" || artifact.artifact_type === "REPORT",
      ),
    [artifacts],
  );
  const screenshotArtifacts = useMemo(
    () => artifacts.filter((artifact) => artifact.artifact_type === "WEB"),
    [artifacts],
  );

  const sections = useMemo<HubSection[]>(
    () => [
      { key: "thoughts", label: sectionLabel("thoughts"), count: thoughtAgents.length },
      { key: "sources", label: sectionLabel("sources"), count: sourceSummary?.totalSources || 0 },
      { key: "kernel_logs", label: sectionLabel("kernel_logs"), count: kernelLogs.length },
      { key: "security_policy", label: sectionLabel("security_policy"), count: securityRows.length },
      { key: "files", label: sectionLabel("files"), count: fileArtifacts.length },
      { key: "revisions", label: sectionLabel("revisions"), count: revisionArtifacts.length },
      { key: "screenshots", label: sectionLabel("screenshots"), count: screenshotArtifacts.length },
    ],
    [
      fileArtifacts.length,
      kernelLogs.length,
      revisionArtifacts.length,
      screenshotArtifacts.length,
      securityRows.length,
      sourceSummary?.totalSources,
      thoughtAgents.length,
    ],
  );

  const derivedDefaultView = useMemo(() => defaultViewForSections(sections), [sections]);
  const [activeView, setActiveView] = useState<ArtifactHubViewKey>(initialView || derivedDefaultView);

  useEffect(() => {
    if (initialView) {
      setActiveView(initialView);
    }
  }, [initialView]);

  const openExternalUrl = useCallback(async (url: string) => {
    try {
      await openUrl(url);
    } catch {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }, []);

  const renderThoughtsView = () => {
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
  };

  const renderSourcesView = () => {
    if (!sourceSummary || sourceSummary.totalSources === 0) {
      return <p className="artifact-hub-empty">No web sources captured for this run.</p>;
    }

    return (
      <div className="source-artifact-content">
        <div className="source-agent-header">
          <span className="source-agent-title">Sources</span>
          <span className="source-agent-count">{sourceSummary.totalSources}</span>
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
  };

  const renderKernelView = () => {
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
  };

  const renderSecurityView = () => {
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
  };

  const renderArtifactList = (items: Artifact[], label: string) => {
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
  };

  const detailView = (() => {
    switch (activeView) {
      case "thoughts":
        return renderThoughtsView();
      case "sources":
        return renderSourcesView();
      case "kernel_logs":
        return renderKernelView();
      case "security_policy":
        return renderSecurityView();
      case "files":
        return renderArtifactList(fileArtifacts, "Files");
      case "revisions":
        return renderArtifactList(revisionArtifacts, "Revisions");
      case "screenshots":
        return renderArtifactList(screenshotArtifacts, "Screenshots");
      default:
        return null;
    }
  })();

  return (
    <div className="artifact-panel artifact-hub-panel">
      <div className="artifact-header">
        <div className="artifact-meta">
          <div className="artifact-icon">{icons.sidebar}</div>
          <span className="artifact-filename">Artifacts</span>
          <span className="artifact-tag">HUB</span>
        </div>
        <div className="artifact-actions">
          <button className="artifact-action-btn close" onClick={onClose} title="Close panel">
            {icons.close}
          </button>
        </div>
      </div>

      <div className="artifact-content artifact-hub-layout">
        <aside className="artifact-hub-nav" aria-label="Artifact sections">
          {sections.map((section) => (
            <button
              key={section.key}
              className={`artifact-hub-nav-item ${activeView === section.key ? "active" : ""}`}
              onClick={() => setActiveView(section.key)}
              type="button"
            >
              <span className="artifact-hub-nav-label">{section.label}</span>
              <span className="artifact-hub-nav-count">{section.count}</span>
            </button>
          ))}
        </aside>
        <section className="artifact-hub-detail" aria-label={sectionLabel(activeView)}>
          {detailView}
        </section>
      </div>
    </div>
  );
}
