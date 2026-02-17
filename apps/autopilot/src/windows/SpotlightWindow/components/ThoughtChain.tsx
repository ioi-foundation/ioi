// apps/autopilot/src/windows/SpotlightWindow/components/ThoughtChain.tsx

import { useMemo, useState, useCallback, useRef, useEffect } from "react";
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

// Limits
const MAX_STREAM_CHARS = 16 * 1024;
const MAX_STREAM_LINES = 200;
const MAX_EVENT_LINES = 12;

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

const TerminalIcon = () => (
  <svg
    width="13"
    height="13"
    viewBox="0 0 16 16"
    fill="currentColor"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M2.146 4.854a.5.5 0 0 1 .708-.708l3 3a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708-.708L4.793 7.5 2.146 4.854ZM7.5 10.5a.5.5 0 0 0 0 1h4a.5.5 0 0 0 0-1h-4Z" />
  </svg>
);

const CopyIcon = () => (
  <svg
    width="12"
    height="12"
    viewBox="0 0 16 16"
    fill="currentColor"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M4 2a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2Zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6Z" />
    <path d="M2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2Z" />
  </svg>
);

const CheckIcon = () => (
  <svg
    width="12"
    height="12"
    viewBox="0 0 16 16"
    fill="currentColor"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M13.485 1.85a.75.75 0 0 1 .165 1.05l-8 11a.75.75 0 0 1-1.156.085l-4.5-4.5a.75.75 0 1 1 1.06-1.06l3.88 3.88L12.435 2.015a.75.75 0 0 1 1.05-.165Z" />
  </svg>
);

const ExternalIcon = () => (
  <svg
    width="11"
    height="11"
    viewBox="0 0 16 16"
    fill="currentColor"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5Z" />
    <path d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5Z" />
  </svg>
);

const PulsingDot = () => <span className="thought-pulse" />;

interface StreamCard {
  streamId: string;
  stepIndex: number;
  toolName: string;
  commandPreview: string;
  stdoutChunks: string[];
  stderrChunks: string[];
  allChunks: string[];
  isFinal: boolean;
  exitCode: number | null;
  hasExitCode: boolean;
  artifactId: string | null;
}

interface FinalRunOutput {
  stepIndex: number;
  toolName: string;
  output: string;
  lineCount: number;
  artifactId: string | null;
}

function capText(raw: string): { text: string; truncated: boolean } {
  const lines = raw.split("\n");
  const byLine = lines.slice(0, MAX_STREAM_LINES).join("\n");
  const capped = byLine.slice(0, MAX_STREAM_CHARS);
  const truncated = raw.length > capped.length || lines.length > MAX_STREAM_LINES;
  return { text: capped, truncated };
}

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

function exitCodeLabel(code: number | null): string {
  if (code === null) return "";
  return code === 0 ? "exit 0" : `exit ${code}`;
}

function exitCodeClass(code: number | null): string {
  if (code === null) return "";
  return code === 0 ? "sc-exit-ok" : "sc-exit-err";
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleCopy = useCallback(() => {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopied(true);
        if (timerRef.current) clearTimeout(timerRef.current);
        timerRef.current = setTimeout(() => setCopied(false), 1800);
      })
      .catch(() => {});
  }, [text]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  return (
    <button
      className={`sc-action-btn ${copied ? "sc-copied" : ""}`}
      onClick={handleCopy}
      title={copied ? "Copied!" : "Copy output"}
      type="button"
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
    </button>
  );
}

function StreamCardView({
  card,
  isLive,
  fallbackArtifactId,
  onOpenArtifact,
}: {
  card: StreamCard;
  isLive: boolean;
  fallbackArtifactId: string | null;
  onOpenArtifact?: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const [activeChannel, setActiveChannel] = useState<"all" | "stdout" | "stderr">(
    "all",
  );

  const hasStdout = card.stdoutChunks.length > 0;
  const hasStderr = card.stderrChunks.length > 0;
  const hasBothChannels = hasStdout && hasStderr;

  const rawAll = card.allChunks.join("");
  const rawStdout = card.stdoutChunks.join("");
  const rawStderr = card.stderrChunks.join("");

  const displayText = useMemo(() => {
    let raw: string;
    if (activeChannel === "stdout") raw = rawStdout;
    else if (activeChannel === "stderr") raw = rawStderr;
    else raw = rawAll;
    return capText(raw);
  }, [activeChannel, rawAll, rawStdout, rawStderr]);

  const resolvedArtifactId = card.artifactId || fallbackArtifactId;

  const statusLabel = card.isFinal
    ? card.hasExitCode
      ? exitCodeLabel(card.exitCode)
      : "done"
    : isLive
      ? "running"
      : "streaming";

  const statusClass = card.isFinal
    ? card.hasExitCode
      ? exitCodeClass(card.exitCode)
      : "sc-exit-ok"
    : "sc-status-live";

  const headerTitle = (card.commandPreview || card.toolName || "command").trim();

  return (
    <div className={`sc-card ${card.isFinal ? "" : "sc-card-live"}`}>
      <div className="sc-header">
        <button
          className="sc-header-toggle"
          onClick={() => setExpanded(!expanded)}
          type="button"
        >
          <span className={`sc-chevron ${expanded ? "expanded" : ""}`}>
            <ChevronIcon />
          </span>
          <TerminalIcon />
          <span className="sc-command-preview" title={headerTitle}>
            {headerTitle}
          </span>
        </button>

        <div className="sc-header-right">
          {!card.isFinal && isLive && <span className="sc-live-dot" />}
          <span className={`sc-status-badge ${statusClass}`}>{statusLabel}</span>
          {displayText.text && <CopyButton text={displayText.text} />}
        </div>
      </div>

      {expanded && (
        <div className="sc-body">
          {hasBothChannels && (
            <div className="sc-channel-tabs">
              {(["all", "stdout", "stderr"] as const).map((ch) => (
                <button
                  key={ch}
                  className={`sc-channel-tab ${activeChannel === ch ? "active" : ""} ${ch === "stderr" ? "sc-tab-stderr" : ""}`}
                  onClick={() => setActiveChannel(ch)}
                  type="button"
                >
                  {ch}
                </button>
              ))}
            </div>
          )}

          <pre
            className={`sc-output ${activeChannel === "stderr" ? "sc-output-stderr" : ""}`}
          >
            {displayText.text ||
              (card.isFinal ? "(no output)" : "(waiting for output...)")}
          </pre>

          {displayText.truncated && (
            <div className="sc-truncation-bar">
              <span className="sc-truncation-text">Output truncated</span>
              {resolvedArtifactId && onOpenArtifact && (
                <button
                  className="sc-artifact-btn"
                  onClick={() => onOpenArtifact(resolvedArtifactId)}
                  type="button"
                >
                  <ExternalIcon />
                  <span>View full log</span>
                </button>
              )}
            </div>
          )}

          {!displayText.truncated && resolvedArtifactId && onOpenArtifact && (
            <div className="sc-truncation-bar sc-truncation-bar-subtle">
              <button
                className="sc-artifact-btn"
                onClick={() => onOpenArtifact(resolvedArtifactId)}
                type="button"
              >
                <ExternalIcon />
                <span>Open log artifact</span>
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FinalRunCard({
  run,
  fallbackArtifactId,
  onOpenArtifact,
}: {
  run: FinalRunOutput;
  fallbackArtifactId: string | null;
  onOpenArtifact?: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const displayText = useMemo(() => capText(run.output), [run.output]);

  const resolvedArtifactId = run.artifactId || fallbackArtifactId;

  return (
    <div className="sc-card">
      <div className="sc-header">
        <button
          className="sc-header-toggle"
          onClick={() => setExpanded(!expanded)}
          type="button"
        >
          <span className={`sc-chevron ${expanded ? "expanded" : ""}`}>
            <ChevronIcon />
          </span>
          <TerminalIcon />
          <span className="sc-command-preview">{run.toolName}</span>
        </button>
        <div className="sc-header-right">
          <span className="sc-status-badge sc-exit-ok">done</span>
          {displayText.text && <CopyButton text={displayText.text} />}
        </div>
      </div>
      {expanded && (
        <div className="sc-body">
          <pre className="sc-output">{displayText.text || "(no output)"}</pre>

          {displayText.truncated && (
            <div className="sc-truncation-bar">
              <span className="sc-truncation-text">
                Output truncated ({run.lineCount} lines)
              </span>
              {resolvedArtifactId && onOpenArtifact && (
                <button
                  className="sc-artifact-btn"
                  onClick={() => onOpenArtifact(resolvedArtifactId)}
                  type="button"
                >
                  <ExternalIcon />
                  <span>View full log</span>
                </button>
              )}
            </div>
          )}

          {!displayText.truncated && resolvedArtifactId && onOpenArtifact && (
            <div className="sc-truncation-bar sc-truncation-bar-subtle">
              <button
                className="sc-artifact-btn"
                onClick={() => onOpenArtifact(resolvedArtifactId)}
                type="button"
              >
                <ExternalIcon />
                <span>Open log artifact</span>
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
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

  const artifactByStepTool = useMemo(() => {
    const map = new Map<string, string>();
    if (!events) return map;

    for (const evt of events) {
      const toolName = String((evt.digest as any)?.tool_name ?? "");
      if (!toolName) continue;

      const refs = evt.artifact_refs || [];
      if (!refs.length) continue;

      const key = `${evt.step_index}:${toolName}`;
      const log = refs.find((r) => r.artifact_type === "LOG");
      const report = refs.find((r) => r.artifact_type === "REPORT");

      if (log) {
        map.set(key, log.artifact_id);
      } else if (report && !map.has(key)) {
        map.set(key, report.artifact_id);
      }
    }

    return map;
  }, [events]);

  const fallbackArtifactId = useMemo(() => {
    if (!events) return null;

    const logs = new Set<string>();
    const reports = new Set<string>();
    for (const evt of events) {
      for (const ref of evt.artifact_refs || []) {
        if (ref.artifact_type === "LOG") logs.add(ref.artifact_id);
        if (ref.artifact_type === "REPORT") reports.add(ref.artifact_id);
      }
    }

    if (logs.size === 1) return Array.from(logs)[0] || null;
    if (reports.size === 1) return Array.from(reports)[0] || null;
    return null;
  }, [events]);

  const streamCards = useMemo<StreamCard[]>(() => {
    if (!events) return [];
    const streamEvents = events.filter((e) => e.event_type === "COMMAND_STREAM");
    if (streamEvents.length === 0) return [];

    const byStream = new Map<string, AgentEvent[]>();
    for (const evt of streamEvents) {
      const sid = String((evt.digest as any)?.stream_id ?? "default");
      const list = byStream.get(sid) || [];
      list.push(evt);
      byStream.set(sid, list);
    }

    const cards: StreamCard[] = [];
    for (const [streamId, evts] of byStream) {
      const sorted = [...evts].sort((a, b) => {
        return (
          Number((a.digest as any)?.seq ?? 0) - Number((b.digest as any)?.seq ?? 0)
        );
      });

      const stdoutChunks: string[] = [];
      const stderrChunks: string[] = [];
      const allChunks: string[] = [];
      let isFinal = false;
      let exitCode: number | null = null;
      let hasExitCode = false;
      let toolName = "";
      let commandPreview = "";

      const stepIndex = sorted[0]?.step_index ?? 0;

      for (const evt of sorted) {
        const d = evt.digest as any;
        const channel = String(d?.channel ?? "stdout");
        const chunk = String((evt.details as any)?.chunk ?? "");

        if (!toolName && d?.tool_name) toolName = String(d.tool_name);
        if (!commandPreview && d?.command_preview) {
          commandPreview = String(d.command_preview);
        }

        if (d?.is_final) {
          isFinal = true;
          if (d?.exit_code !== undefined && d?.exit_code !== null) {
            exitCode = Number(d.exit_code);
            hasExitCode = true;
          }
        }

        if (channel !== "status") {
          allChunks.push(chunk);
        }
        if (channel === "stderr") {
          stderrChunks.push(chunk);
        } else if (channel !== "status") {
          stdoutChunks.push(chunk);
        }
      }

      const artifactKey = toolName ? `${stepIndex}:${toolName}` : null;
      const artifactId = artifactKey ? artifactByStepTool.get(artifactKey) || null : null;

      cards.push({
        streamId,
        stepIndex,
        toolName,
        commandPreview,
        stdoutChunks,
        stderrChunks,
        allChunks,
        isFinal,
        exitCode,
        hasExitCode,
        artifactId,
      });
    }

    cards.sort(
      (a, b) => a.stepIndex - b.stepIndex || a.streamId.localeCompare(b.streamId),
    );
    return cards;
  }, [artifactByStepTool, events]);

  const streamKeys = useMemo(() => {
    const keys = new Set<string>();
    for (const card of streamCards) {
      if (!card.toolName) continue;
      keys.add(`${card.stepIndex}:${card.toolName}`);
    }
    return keys;
  }, [streamCards]);

  const finalRuns = useMemo<FinalRunOutput[]>(() => {
    if (!events) return [];
    const runEvents = events.filter((e) => e.event_type === "COMMAND_RUN");

    const out: FinalRunOutput[] = [];
    for (const evt of runEvents) {
      const toolName = String((evt.digest as any)?.tool_name ?? "command");
      const key = toolName ? `${evt.step_index}:${toolName}` : "";
      if (key && streamKeys.has(key)) {
        continue;
      }

      const refs = evt.artifact_refs || [];
      const log = refs.find((r) => r.artifact_type === "LOG");
      const report = refs.find((r) => r.artifact_type === "REPORT");
      const artifactId = log?.artifact_id || report?.artifact_id || null;

      out.push({
        stepIndex: evt.step_index,
        toolName,
        output: String((evt.details as any)?.output ?? ""),
        lineCount: Number((evt.digest as any)?.line_count ?? 0),
        artifactId,
      });
    }

    return out;
  }, [events, streamKeys]);

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
      "escalation_path",
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
      .filter(
        (event) =>
          event.event_type !== "COMMAND_STREAM" && event.event_type !== "COMMAND_RUN",
      )
      .map((event) => event.title)
      .filter((title) => title.trim().length > 0)
      .slice(0, MAX_EVENT_LINES);
  }, [events]);

  const hasStreamContent = streamCards.length > 0 || finalRuns.length > 0;

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

            {streamCards.map((card) => (
              <StreamCardView
                key={`${card.stepIndex}:${card.streamId}`}
                card={card}
                isLive={isActive}
                fallbackArtifactId={fallbackArtifactId}
                onOpenArtifact={onOpenArtifact}
              />
            ))}

            {finalRuns.map((run, idx) => (
              <FinalRunCard
                key={`run-${run.stepIndex}-${idx}`}
                run={run}
                fallbackArtifactId={fallbackArtifactId}
                onOpenArtifact={onOpenArtifact}
              />
            ))}

            {!hasStreamContent && eventLines.length === 0 && !receiptDigest && (
              <div className="sc-empty-state">(no command output yet)</div>
            )}
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
