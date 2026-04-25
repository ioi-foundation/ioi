import { startTransition, useMemo } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { toneForRuntimeStatus } from "../../../services/runtimeInspection";
import type {
  BenchmarkTraceCaseView,
  BenchmarkTraceFeed,
  BenchmarkTraceLane,
  BenchmarkTraceSpan,
} from "../../../types";

type TraceDeckMode = "trace" | "receipts";

interface ChatBenchmarkTraceDeckProps {
  mode: TraceDeckMode;
  feed: BenchmarkTraceFeed | null;
  loading: boolean;
  error: string | null;
  selectedCaseId: string | null;
  selectedSpanId: string | null;
  onSelectCase: (caseId: string) => void;
  onSelectSpan: (spanId: string) => void;
}

function formatCaseLabel(caseId: string): string {
  return caseId
    .replace(/^miniwob_catalog_/, "")
    .replace(/^miniwob_/, "")
    .replace(/_/g, " ");
}

function formatTimestamp(value?: string | null): string {
  if (!value) return "Local traces";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      });
}

function formatDuration(durationMs?: number | null): string {
  if (typeof durationMs !== "number" || Number.isNaN(durationMs)) return "n/a";
  if (durationMs >= 1000) return `${(durationMs / 1000).toFixed(durationMs >= 10_000 ? 0 : 1)}s`;
  return `${durationMs}ms`;
}

function formatOffset(baseMs: number, pointMs: number): string {
  const delta = Math.max(0, pointMs - baseMs);
  if (delta >= 1000) return `t+${(delta / 1000).toFixed(delta >= 10_000 ? 0 : 1)}s`;
  return `t+${delta}ms`;
}

function groupTraceLanes(caseView: BenchmarkTraceCaseView | null): BenchmarkTraceLane[] {
  const trace = caseView?.trace;
  if (!trace) return [];

  const lanes = new Map<string, Map<string, BenchmarkTraceSpan>>();
  for (const entry of trace.lanes) {
    const spans = lanes.get(entry.lane) ?? new Map<string, BenchmarkTraceSpan>();
    for (const span of entry.spans) {
      spans.set(span.id, span);
    }
    lanes.set(entry.lane, spans);
  }

  return Array.from(lanes.entries())
    .map(([lane, spans]) => ({
      lane,
      spans: Array.from(spans.values()).sort((left, right) => left.startMs - right.startMs),
    }))
    .sort((left, right) => {
      const leftStart = left.spans[0]?.startMs ?? 0;
      const rightStart = right.spans[0]?.startMs ?? 0;
      return leftStart - rightStart;
    });
}

function flattenSpans(
  trace: BenchmarkTraceCaseView["trace"] | undefined,
): BenchmarkTraceSpan[] {
  if (!trace) return [];
  const spans = new Map<string, BenchmarkTraceSpan>();
  for (const lane of trace.lanes) {
    for (const span of lane.spans) {
      spans.set(span.id, span);
    }
  }
  return Array.from(spans.values()).sort((left, right) => left.startMs - right.startMs);
}

function receiptSpans(caseView: BenchmarkTraceCaseView | null): BenchmarkTraceSpan[] {
  return flattenSpans(caseView?.trace).filter((span) => span.id.startsWith("receipt:"));
}

async function openArtifactLink(href: string) {
  try {
    await openUrl(href);
  } catch {
    if (typeof window !== "undefined") {
      window.open(href, "_blank", "noopener,noreferrer");
    }
  }
}

export function ChatBenchmarkTraceDeck({
  mode,
  feed,
  loading,
  error,
  selectedCaseId,
  selectedSpanId,
  onSelectCase,
  onSelectSpan,
}: ChatBenchmarkTraceDeckProps) {
  const cases = feed?.cases ?? [];
  const selectedCase = useMemo(
    () => cases.find((entry) => entry.caseId === selectedCaseId) ?? cases[0] ?? null,
    [cases, selectedCaseId],
  );
  const groupedLanes = useMemo(() => groupTraceLanes(selectedCase), [selectedCase]);
  const selectedTrace = selectedCase?.trace ?? null;
  const allSpans = useMemo(() => flattenSpans(selectedTrace), [selectedTrace]);
  const selectedSpan = useMemo(
    () => allSpans.find((span) => span.id === selectedSpanId) ?? allSpans[0] ?? null,
    [allSpans, selectedSpanId],
  );
  const receipts = useMemo(() => receiptSpans(selectedCase), [selectedCase]);

  if (loading) {
    return (
      <div className="chat-trace-deck chat-trace-deck--empty">
        <p>Loading local benchmark replay data…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="chat-trace-deck chat-trace-deck--empty">
        <p>{error}</p>
      </div>
    );
  }

  if (!selectedCase || !selectedTrace) {
    return (
      <div className="chat-trace-deck chat-trace-deck--empty">
        <p>No local benchmark traces are available yet.</p>
      </div>
    );
  }

  const totalDuration = Math.max(1, selectedTrace.rangeEndMs - selectedTrace.rangeStartMs);

  return (
    <div className="chat-trace-deck">
      <div className="chat-trace-deck-head">
        <div>
          <span className="chat-trace-deck-kicker">
            {mode === "trace" ? "Replay" : "Evidence"}
          </span>
          <strong>{formatCaseLabel(selectedCase.caseId)}</strong>
        </div>
        <span className="chat-trace-deck-generated">
          {formatTimestamp(feed?.generatedAt ?? null)}
        </span>
      </div>

      <div className="chat-trace-case-switcher" role="tablist" aria-label="Trace cases">
        {cases.map((entry) => (
          <button
            key={entry.caseId}
            type="button"
            role="tab"
            aria-selected={entry.caseId === selectedCase.caseId}
            className={`chat-trace-case-chip ${
              entry.caseId === selectedCase.caseId ? "is-active" : ""
            }`}
            onClick={() => {
              startTransition(() => onSelectCase(entry.caseId));
            }}
          >
            <span>{formatCaseLabel(entry.caseId)}</span>
            <strong className={`is-${toneForRuntimeStatus(entry.result)}`}>{entry.result}</strong>
          </button>
        ))}
      </div>

      <article className="chat-trace-summary-card">
        <div className="chat-trace-summary-head">
          <div>
            <span className="chat-trace-summary-suite">{selectedCase.suite}</span>
            <h3>{selectedCase.summary.query_text || selectedCase.caseId}</h3>
          </div>
          <div className="chat-trace-summary-meta">
            <span>{selectedCase.runId}</span>
            <span>{selectedCase.summary.model ?? "model n/a"}</span>
            <span>{selectedCase.summary.env_id || "env n/a"}</span>
          </div>
        </div>
        <p className="chat-trace-summary-finding">
          {selectedCase.findings[0] ??
            `reward=${selectedCase.summary.reward} · provider_calls=${selectedCase.summary.provider_calls}`}
        </p>
      </article>

      <div className="chat-trace-metrics">
        {selectedCase.traceMetrics.map((metric) => {
          const metricSelected = metric.supportingSpanIds.includes(selectedSpan?.id ?? "");
          return (
            <button
              key={metric.metricId}
              type="button"
              className={`chat-trace-metric chat-trace-metric--${toneForRuntimeStatus(metric.status)} ${
                metricSelected ? "is-selected" : ""
              }`}
              onClick={() => {
                const target = metric.supportingSpanIds[0];
                if (!target) return;
                startTransition(() => onSelectSpan(target));
              }}
            >
              <span>{metric.label}</span>
              <strong>{metric.status}</strong>
              <p>{metric.summary}</p>
            </button>
          );
        })}
      </div>

      {mode === "trace" ? (
        <>
          <div className="chat-trace-bookmarks">
            {selectedTrace.bookmarks.map((bookmark) => (
              <button
                key={bookmark.id}
                type="button"
                className={`chat-trace-bookmark chat-trace-bookmark--${bookmark.kind}`}
                onClick={() => {
                  startTransition(() => onSelectSpan(bookmark.spanId));
                }}
              >
                {bookmark.label}
              </button>
            ))}
          </div>

          <div className="chat-trace-lanes">
            {groupedLanes.map((lane) => (
              <div key={lane.lane} className="chat-trace-lane-row">
                <div className="chat-trace-lane-meta">
                  <strong>{lane.lane}</strong>
                  <span>{lane.spans.length}</span>
                </div>
                <div className="chat-trace-lane-track">
                  {lane.spans.map((span) => {
                    const left = ((span.startMs - selectedTrace.rangeStartMs) / totalDuration) * 100;
                    const rawWidth =
                      ((Math.max(span.endMs, span.startMs + 1) - span.startMs) / totalDuration) * 100;
                    const width = Math.max(rawWidth, 1.75);
                    return (
                      <button
                        key={span.id}
                        type="button"
                        className={`chat-trace-lane-span chat-trace-lane-span--${toneForRuntimeStatus(
                          span.status,
                        )} ${selectedSpan?.id === span.id ? "is-selected" : ""}`}
                        style={{ left: `${left}%`, width: `${width}%` }}
                        title={span.summary}
                        onClick={() => {
                          startTransition(() => onSelectSpan(span.id));
                        }}
                      >
                        <span>{span.summary}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          {receipts.length > 0 ? (
            <div className="chat-trace-receipts">
              {receipts.map((receipt) => (
                <button
                  key={receipt.id}
                  type="button"
                  className={`chat-trace-receipt chat-trace-receipt--${toneForRuntimeStatus(
                    receipt.status,
                  )} ${selectedSpan?.id === receipt.id ? "is-selected" : ""}`}
                  onClick={() => {
                    startTransition(() => onSelectSpan(receipt.id));
                  }}
                >
                  <div className="chat-trace-receipt-head">
                    <span>{receipt.lane}</span>
                    <strong>{formatDuration(receipt.durationMs)}</strong>
                  </div>
                  <p>{receipt.summary}</p>
                </button>
              ))}
            </div>
          ) : (
            <div className="chat-trace-inline-empty">
              <p>No receipt spans were emitted for this trace.</p>
            </div>
          )}
        </>
      )}

      {selectedSpan ? (
        <article className="chat-trace-inspector">
          <div className="chat-trace-inspector-head">
            <div>
              <span className={`chat-trace-inspector-status is-${toneForRuntimeStatus(selectedSpan.status)}`}>
                {selectedSpan.status}
              </span>
              <strong>{selectedSpan.summary}</strong>
            </div>
            <div className="chat-trace-inspector-timing">
              <span>{formatOffset(selectedTrace.rangeStartMs, selectedSpan.startMs)}</span>
              <span>{formatDuration(selectedSpan.durationMs)}</span>
            </div>
          </div>
          <div className="chat-trace-inspector-meta">
            <span>{selectedSpan.lane}</span>
            {selectedSpan.stepIndex != null ? <span>step {selectedSpan.stepIndex}</span> : null}
            {selectedSpan.capabilityTags.slice(0, 3).map((tag) => (
              <span key={tag}>{tag}</span>
            ))}
          </div>
          <p className="chat-trace-inspector-attrs">
            {selectedSpan.attributesSummary || "No additional attributes were captured."}
          </p>
          <div className="chat-trace-artifacts">
            {selectedSpan.artifactLinks.map((link) => (
              <button
                key={`${selectedSpan.id}:${link.path}`}
                type="button"
                className="chat-trace-artifact"
                onClick={() => {
                  void openArtifactLink(link.href);
                }}
              >
                <span>{link.label}</span>
                <code>{link.path}</code>
              </button>
            ))}
          </div>
        </article>
      ) : null}
    </div>
  );
}
