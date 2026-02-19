import { useMemo, useState } from "react";
import type { ActivityKind, AgentEvent, EventType } from "../../../types";

interface MicroEventCardProps {
  event: AgentEvent;
  onOpenArtifact: (artifactId: string) => void;
  kind?: ActivityKind;
  toolName?: string;
}

const EVENT_ICONS: Record<EventType, string> = {
  COMMAND_RUN: "⌘",
  COMMAND_STREAM: "⋯",
  CODE_SEARCH: "⌕",
  FILE_READ: "📄",
  FILE_EDIT: "✎",
  DIFF_CREATED: "Δ",
  TEST_RUN: "✓",
  BROWSER_NAVIGATE: "🌐",
  BROWSER_EXTRACT: "⇣",
  RECEIPT: "🧾",
  INFO_NOTE: "ℹ",
  WARNING: "⚠",
  ERROR: "⛔",
};

const KIND_LABELS: Record<ActivityKind, string> = {
  primary_answer_event: "Answer",
  receipt_event: "Receipt",
  reasoning_event: "Reasoning",
  workload_event: "Workload",
  system_event: "System",
};

function safeString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function outputSnippet(event: AgentEvent): string {
  const details = event.details || {};
  const candidates = [details.output, details.chunk, details.content];
  for (const candidate of candidates) {
    const value = safeString(candidate).trim();
    if (value.length > 0) {
      return value.slice(0, 200);
    }
  }
  return "";
}

function toDigestLine(event: AgentEvent, toolName?: string): string {
  const digest = (event.digest || {}) as Record<string, unknown>;
  const ordered = [
    "tool_name",
    "decision",
    "incident_stage",
    "routing_reason_code",
    "channel",
    "seq",
    "is_final",
    "exit_code",
  ];

  const entries = ordered
    .filter((key) => digest[key] !== undefined && safeString(digest[key]).trim().length > 0)
    .slice(0, 5)
    .map((key) => `${key}: ${safeString(digest[key])}`);

  if (entries.length > 0) {
    return entries.join(" · ");
  }

  if (toolName) {
    return `tool: ${toolName}`;
  }

  return "No digest metadata";
}

function readableTimestamp(timestamp: string): string {
  const millis = Date.parse(timestamp);
  if (Number.isNaN(millis)) {
    return timestamp;
  }
  return new Date(millis).toISOString();
}

export function MicroEventCard({
  event,
  onOpenArtifact,
  kind = "system_event",
  toolName,
}: MicroEventCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  const digestLine = useMemo(() => toDigestLine(event, toolName), [event, toolName]);
  const snippet = useMemo(() => outputSnippet(event), [event]);
  const statusClass = event.status.toLowerCase();

  return (
    <article className={`micro-event-card status-${statusClass}`}>
      <div className="micro-event-topline">
        <span className="micro-event-icon">{EVENT_ICONS[event.event_type] || "•"}</span>
        <h5 className="micro-event-title">{event.title}</h5>
        <span className="micro-event-step">#{event.step_index}</span>
      </div>

      <div className="micro-event-badges">
        <span className="micro-event-badge">{KIND_LABELS[kind]}</span>
        <span className="micro-event-badge">{event.event_type}</span>
        {toolName && <span className="micro-event-badge">{toolName}</span>}
      </div>

      <p className="micro-event-digest">{digestLine}</p>
      {snippet && <p className="micro-event-snippet">{snippet}</p>}

      {event.artifact_refs?.length > 0 && (
        <div className="micro-event-links">
          {event.artifact_refs.map((ref) => (
            <button
              key={ref.artifact_id}
              className="micro-event-link-btn"
              onClick={() => onOpenArtifact(ref.artifact_id)}
              type="button"
            >
              {ref.artifact_type}:{ref.artifact_id.slice(0, 8)}
            </button>
          ))}
        </div>
      )}

      <div className="micro-event-actions-row">
        <button
          className="micro-event-toggle"
          onClick={() => setExpanded((value) => !value)}
          type="button"
        >
          {expanded ? "Hide details" : "Show details"}
        </button>
        {expanded && (
          <button
            className="micro-event-toggle"
            onClick={() => setShowRaw((value) => !value)}
            type="button"
          >
            {showRaw ? "Hide raw" : "Show raw"}
          </button>
        )}
      </div>

      {expanded && (
        <div className="micro-event-details">
          <div className="micro-event-footnote">
            <span>timestamp={readableTimestamp(event.timestamp)}</span>
            <span>event_id={event.event_id}</span>
            <span>receipt={event.receipt_ref || "none"}</span>
          </div>
          {showRaw && <pre>{JSON.stringify(event, null, 2)}</pre>}
        </div>
      )}
    </article>
  );
}
