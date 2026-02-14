import { useMemo, useState } from "react";
import type { AgentEvent, EventType } from "../../../types";

interface MicroEventCardProps {
  event: AgentEvent;
  onOpenArtifact: (artifactId: string) => void;
}

const ICONS: Record<EventType, string> = {
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

function toDigestLine(event: AgentEvent): string {
  const digest = (event.digest || {}) as Record<string, unknown>;
  if (event.event_type === "RECEIPT") {
    const ordered = [
      "intent_class",
      "incident_stage",
      "strategy_node",
      "gate_state",
      "resolution_action",
      "tool_name",
      "decision",
    ];
    const lines = ordered
      .filter((k) => digest[k] !== undefined && String(digest[k]).length > 0)
      .slice(0, 5)
      .map((k) => `${k}: ${String(digest[k])}`);
    if (lines.length > 0) return lines.join(" · ");
  }
  if (event.event_type === "COMMAND_STREAM") {
    const ordered = ["tool_name", "channel", "seq", "is_final", "exit_code"];
    return ordered
      .filter((k) => digest[k] !== undefined && String(digest[k]).length > 0)
      .map((k) => `${k}: ${String(digest[k])}`)
      .join(" · ");
  }
  const keys = Object.keys(digest || {});
  if (keys.length === 0) return "";
  const lines = keys.slice(0, 3).map((k) => `${k}: ${String(digest[k])}`);
  return lines.join(" · ");
}

export function MicroEventCard({ event, onOpenArtifact }: MicroEventCardProps) {
  const [expanded, setExpanded] = useState(false);
  const digestLine = useMemo(() => toDigestLine(event), [event]);
  const statusClass = event.status.toLowerCase();

  return (
    <div className={`micro-event-card status-${statusClass}`}>
      <button className="micro-event-header" onClick={() => setExpanded((v) => !v)} type="button">
        <span className="micro-event-icon">{ICONS[event.event_type] || "•"}</span>
        <span className="micro-event-title">{event.title}</span>
        <span className="micro-event-meta">#{event.step_index}</span>
      </button>

      {digestLine && <div className="micro-event-digest">{digestLine}</div>}

      <div className="micro-event-links">
        {event.artifact_refs?.map((ref) => (
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

      {expanded && (
        <div className="micro-event-details">
          <pre>{JSON.stringify(event.details || {}, null, 2)}</pre>
          <div className="micro-event-footnote">
            event_id={event.event_id} · receipt={event.receipt_ref || "none"}
          </div>
        </div>
      )}
    </div>
  );
}
