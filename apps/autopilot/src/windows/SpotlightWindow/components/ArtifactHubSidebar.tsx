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
  initialTurnId?: string | null;
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

interface TurnWindow {
  id: string;
  index: number;
  prompt: string;
  startAtMs: number | null;
  endAtMs: number | null;
}

type TurnSelection = "all" | string;

const MAX_KERNEL_LOG_ROWS = 240;
const MAX_SUMMARY_CHARS = 220;
const TURN_FILTER_VIEWS = new Set<ArtifactHubViewKey>([
  "thoughts",
  "sources",
  "kernel_logs",
  "security_policy",
  "files",
  "revisions",
  "screenshots",
]);

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

function parseTimestampMs(value: string): number | null {
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

function isUserRequestEvent(event: AgentEvent): boolean {
  const details = event.details || {};
  const title = event.title.toLowerCase();
  return safeString(details.kind).trim().toLowerCase() === "user_input" || title === "user request";
}

function eventPromptText(event: AgentEvent): string {
  const details = event.details || {};
  const digest = event.digest || {};
  return safeString(details.text).trim() || safeString(digest.query).trim();
}

function buildTurnWindows(events: AgentEvent[]): TurnWindow[] {
  const ordered = events
    .slice()
    .sort(
      (a, b) =>
        a.timestamp.localeCompare(b.timestamp) ||
        a.step_index - b.step_index ||
        a.event_id.localeCompare(b.event_id),
    );
  const userEvents = ordered.filter((event) => isUserRequestEvent(event));
  return userEvents.map((event, idx) => {
    const next = userEvents[idx + 1];
    return {
      id: event.event_id,
      index: idx + 1,
      prompt: eventPromptText(event),
      startAtMs: parseTimestampMs(event.timestamp),
      endAtMs: next ? parseTimestampMs(next.timestamp) : null,
    };
  });
}

function eventBelongsToTurn(event: AgentEvent, turn: TurnWindow): boolean {
  const eventAtMs = parseTimestampMs(event.timestamp);
  if (turn.startAtMs !== null && eventAtMs !== null && eventAtMs < turn.startAtMs) {
    return false;
  }
  if (turn.endAtMs !== null && eventAtMs !== null && eventAtMs >= turn.endAtMs) {
    return false;
  }
  return true;
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
  initialTurnId,
  events,
  artifacts,
  sourceSummary,
  thoughtSummary,
  onOpenArtifact,
  onClose,
}: ArtifactHubSidebarProps) {
  const turnWindows = useMemo(() => buildTurnWindows(events), [events]);
  const latestTurn = turnWindows.length > 0 ? turnWindows[turnWindows.length - 1] : null;
  const [turnSelection, setTurnSelection] = useState<TurnSelection>("all");

  useEffect(() => {
    if (turnWindows.length === 0) {
      setTurnSelection("all");
      return;
    }

    const requested = (initialTurnId || "").trim();
    if (requested && turnWindows.some((turn) => turn.id === requested)) {
      setTurnSelection(requested);
      return;
    }

    setTurnSelection((previous) => {
      if (previous === "all") {
        return latestTurn?.id || "all";
      }
      if (turnWindows.some((turn) => turn.id === previous)) {
        return previous;
      }
      return latestTurn?.id || "all";
    });
  }, [initialTurnId, latestTurn?.id, turnWindows]);

  const selectedTurn = useMemo(() => {
    if (turnSelection === "all") return null;
    return turnWindows.find((turn) => turn.id === turnSelection) || null;
  }, [turnSelection, turnWindows]);

  const scopedEvents = useMemo(() => {
    if (!selectedTurn) return events;
    return events.filter((event) => eventBelongsToTurn(event, selectedTurn));
  }, [events, selectedTurn]);
  const scopedArtifacts = useMemo(() => {
    if (!selectedTurn) return artifacts;
    return artifacts.filter((artifact) => {
      const createdAtMs = parseTimestampMs(artifact.created_at);
      if (selectedTurn.startAtMs !== null && createdAtMs !== null && createdAtMs < selectedTurn.startAtMs) {
        return false;
      }
      if (selectedTurn.endAtMs !== null && createdAtMs !== null && createdAtMs >= selectedTurn.endAtMs) {
        return false;
      }
      return true;
    });
  }, [artifacts, selectedTurn]);
  const visibleStepIndexes = useMemo(() => {
    if (!selectedTurn) return null;
    return new Set(scopedEvents.map((event) => event.step_index));
  }, [scopedEvents, selectedTurn]);

  const isStepVisible = useCallback(
    (stepIndex: number) => {
      if (!visibleStepIndexes) return true;
      return visibleStepIndexes.has(stepIndex);
    },
    [visibleStepIndexes],
  );

  const searches = useMemo(
    () =>
      [...(sourceSummary?.searches || [])]
        .filter((entry) => isStepVisible(entry.stepIndex))
        .sort((a, b) => a.stepIndex - b.stepIndex),
    [isStepVisible, sourceSummary?.searches],
  );
  const browses = useMemo(
    () =>
      [...(sourceSummary?.browses || [])]
        .filter((entry) => isStepVisible(entry.stepIndex))
        .sort((a, b) => a.stepIndex - b.stepIndex),
    [isStepVisible, sourceSummary?.browses],
  );
  const thoughtAgents = useMemo(
    () => (thoughtSummary?.agents || []).filter((agent) => isStepVisible(agent.stepIndex)),
    [isStepVisible, thoughtSummary?.agents],
  );
  const visibleSourceCount = useMemo(() => {
    if (!selectedTurn) {
      return sourceSummary?.totalSources || 0;
    }
    const searchTotal = searches.reduce((sum, row) => sum + Math.max(0, row.resultCount), 0);
    return Math.max(searchTotal, browses.length);
  }, [browses.length, searches, selectedTurn, sourceSummary?.totalSources]);

  const kernelLogs = useMemo<KernelLogRow[]>(() => {
    const rows = scopedEvents
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
  }, [scopedEvents]);

  const securityRows = useMemo<SecurityPolicyRow[]>(() => {
    const rows: SecurityPolicyRow[] = [];
    for (const event of scopedEvents) {
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
  }, [scopedEvents]);

  const fileArtifacts = useMemo(
    () =>
      scopedArtifacts.filter(
        (artifact) => artifact.artifact_type === "FILE" || artifact.artifact_type === "DIFF",
      ),
    [scopedArtifacts],
  );
  const revisionArtifacts = useMemo(
    () =>
      scopedArtifacts.filter(
        (artifact) =>
          artifact.artifact_type === "RUN_BUNDLE" || artifact.artifact_type === "REPORT",
      ),
    [scopedArtifacts],
  );
  const screenshotArtifacts = useMemo(
    () => scopedArtifacts.filter((artifact) => artifact.artifact_type === "WEB"),
    [scopedArtifacts],
  );

  const sections = useMemo<HubSection[]>(
    () => [
      { key: "thoughts", label: sectionLabel("thoughts"), count: thoughtAgents.length },
      { key: "sources", label: sectionLabel("sources"), count: visibleSourceCount },
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
      visibleSourceCount,
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

  const showTurnScopeControls =
    turnWindows.length > 0 && TURN_FILTER_VIEWS.has(activeView);
  const selectedTurnPrompt = selectedTurn?.prompt ? clipText(selectedTurn.prompt, 88) : "";

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
          {showTurnScopeControls && (
            <div className="artifact-hub-turn-scope">
              <div className="artifact-hub-turn-meta">
                <span className="artifact-hub-turn-label">
                  {selectedTurn ? `Turn ${selectedTurn.index}` : "All turns"}
                </span>
                {selectedTurnPrompt && (
                  <span className="artifact-hub-turn-prompt">{selectedTurnPrompt}</span>
                )}
              </div>
              <div className="artifact-hub-turn-actions">
                <label className="artifact-hub-turn-select-wrap">
                  <span className="artifact-hub-turn-select-label">View</span>
                  <select
                    className="artifact-hub-turn-select"
                    value={turnSelection}
                    onChange={(event) => setTurnSelection(event.target.value)}
                  >
                    {latestTurn && <option value={latestTurn.id}>Latest turn</option>}
                    {turnWindows
                      .slice()
                      .reverse()
                      .map((turn) => (
                        <option key={turn.id} value={turn.id}>
                          {`Turn ${turn.index}`}
                        </option>
                      ))}
                    <option value="all">All turns</option>
                  </select>
                </label>
              </div>
            </div>
          )}
          {detailView}
        </section>
      </div>
    </div>
  );
}
