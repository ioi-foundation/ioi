// apps/autopilot/src/windows/SpotlightWindow/components/ThoughtChain.tsx

import { useMemo, useState } from "react";
import { AgentEvent, ChatMessage } from "../../../types";

interface ThoughtChainProps {
  messages: ChatMessage[];
  activeStep?: string | null;
  agentName?: string;
  generation?: number;
  progress?: number;
  totalSteps?: number;
  events?: AgentEvent[];
  onOpenArtifact?: (artifactId: string) => void;
}

const MAX_STREAM_CHARS = 16 * 1024;
const MAX_STREAM_LINES = 200;

const ChevronIcon = () => (
  <svg
    width="12"
    height="12"
    viewBox="0 0 20 20"
    fill="currentColor"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M14.128 7.16482C14.3126 6.95983 14.6298 6.94336 14.835 7.12771C15.0402 7.31242 15.0567 7.62952 14.8721 7.83477L10.372 12.835L10.2939 12.9053C10.2093 12.9667 10.1063 13 9.99995 13C9.85833 12.9999 9.72264 12.9402 9.62788 12.835L5.12778 7.83477L5.0682 7.75273C4.95072 7.55225 4.98544 7.28926 5.16489 7.12771C5.34445 6.96617 5.60969 6.95939 5.79674 7.09744L5.87193 7.16482L9.99995 11.7519L14.128 7.16482Z" />
  </svg>
);

const PulsingDot = () => <span className="thought-pulse" />;

function summarizeEventMode(events: AgentEvent[], activeStep?: string | null): string {
  if (activeStep) return activeStep;
  const receipt = [...events].reverse().find((e) => e.event_type === "RECEIPT");
  if (receipt) {
    const digest = receipt.digest || {};
    const stage = String(digest.incident_stage || "").trim();
    const tool = String(digest.tool_name || "").trim();
    if (stage || tool) return `Thinking... ${stage}${stage && tool ? " · " : ""}${tool}`;
  }
  const firstTitle = events[0]?.title;
  if (firstTitle) return firstTitle;
  return "Thinking...";
}

function summarizeMessageMode(messages: ChatMessage[], activeStep?: string | null): string {
  if (activeStep) return activeStep;
  if (messages.length === 0) return "Processing...";
  const toolCalls = messages.filter((m) => m.role === "tool");
  if (toolCalls.length > 0) return `Completed ${toolCalls.length} step(s)`;
  return `Processed ${messages.length} operation(s)`;
}

export function ThoughtChain({
  messages,
  activeStep,
  agentName,
  generation,
  progress,
  totalSteps,
  events,
  onOpenArtifact,
}: ThoughtChainProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const isActive = !!activeStep;
  const hasEventMode = !!events && events.length > 0;

  const streamData = useMemo(() => {
    if (!events) return { text: "", truncated: false, hasFinal: false };
    const streamEvents = events.filter((e) => e.event_type === "COMMAND_STREAM");
    const sorted = [...streamEvents].sort((a, b) => {
      const left = Number((a.digest as any)?.seq ?? 0);
      const right = Number((b.digest as any)?.seq ?? 0);
      return left - right;
    });
    const merged = sorted
      .map((e) => String((e.details as any)?.chunk ?? ""))
      .join("");
    const lines = merged.split("\n");
    const byLine = lines.slice(0, MAX_STREAM_LINES).join("\n");
    const capped = byLine.slice(0, MAX_STREAM_CHARS);
    const truncated =
      merged.length > capped.length || lines.length > MAX_STREAM_LINES;
    const hasFinal = sorted.some((e) => Boolean((e.digest as any)?.is_final));
    return { text: capped, truncated, hasFinal };
  }, [events]);

  const summary = hasEventMode
    ? summarizeEventMode(events || [], activeStep)
    : summarizeMessageMode(messages, activeStep);

  const metadata = [
    agentName || "Agent",
    generation !== undefined ? `Gen ${generation}` : null,
    totalSteps ? `${progress || 0}/${totalSteps}` : null,
  ]
    .filter(Boolean)
    .join(" · ");

  const receiptDigest = useMemo(() => {
    if (!events) return null;
    const receipt = [...events].reverse().find((e) => e.event_type === "RECEIPT");
    if (!receipt) return null;
    const digest = receipt.digest || {};
    const ordered = [
      "intent_class",
      "incident_stage",
      "strategy_node",
      "gate_state",
      "resolution_action",
    ];
    return ordered
      .map((k) => {
        const v = (digest as Record<string, unknown>)[k];
        if (v === undefined || String(v).trim().length === 0) return null;
        return `${k}: ${String(v)}`;
      })
      .filter(Boolean)
      .join(" · ");
  }, [events]);

  const eventLines = useMemo(() => {
    if (!events) return [];
    return events
      .filter((event) => event.event_type !== "COMMAND_STREAM")
      .map((event) => event.title)
      .filter((title) => title.trim().length > 0)
      .slice(0, 8);
  }, [events]);

  const fallbackArtifact = useMemo(() => {
    if (!events) return null;
    for (const event of events) {
      const artifact = (event.artifact_refs || []).find(
        (ref) => ref.artifact_type === "LOG" || ref.artifact_type === "REPORT",
      );
      if (artifact) return artifact.artifact_id;
    }
    return null;
  }, [events]);

  return (
    <div className="thought-chain">
      <button
        className="thought-header"
        onClick={() => setIsExpanded(!isExpanded)}
        type="button"
      >
        <div className="thought-header-inner">
          {isActive && <PulsingDot />}
          <span className={`thought-summary ${isActive ? "active" : ""}`}>
            {summary}
          </span>
          <span className={`thought-chevron ${isExpanded ? "expanded" : ""}`}>
            <ChevronIcon />
          </span>
        </div>
      </button>

      <div className={`thought-content ${isExpanded ? "open" : ""}`}>
        <div className="thought-meta">{metadata}</div>

        {hasEventMode ? (
          <div className="thought-steps">
            {eventLines.map((line, idx) => (
              <div className="thought-step" key={`evt-line-${idx}`}>
                <span className="thought-step-indicator" />
                <span className="thought-step-text">{line}</span>
              </div>
            ))}
            {receiptDigest && (
              <div className="thought-step">
                <span className="thought-step-indicator" />
                <span className="thought-step-text">{receiptDigest}</span>
              </div>
            )}
            <div className="thought-stream-panel">
              <div className="thought-stream-header">
                <span>Command Stream</span>
                <span>{streamData.hasFinal ? "finalized" : "live"}</span>
              </div>
              <pre className="thought-stream-output">{streamData.text || "(no stream output yet)"}</pre>
              {streamData.truncated && (
                <div className="thought-stream-note">
                  Stream truncated. Open full output artifact for complete logs.
                </div>
              )}
              {streamData.truncated && fallbackArtifact && onOpenArtifact && (
                <button
                  className="thought-artifact-link"
                  onClick={() => onOpenArtifact(fallbackArtifact)}
                  type="button"
                >
                  Open full log artifact
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="thought-steps">
            {messages.map((msg, i) => (
              <div key={i} className="thought-step">
                <span className="thought-step-indicator" />
                <span className="thought-step-text">{msg.text || `Step ${i + 1}`}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
