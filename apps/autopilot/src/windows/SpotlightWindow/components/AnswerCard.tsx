import { useCallback, useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { AnswerPresentation, PlanSummary, SourceSummary } from "../../../types";
import { icons } from "./Icons";
import { MarkdownMessage } from "./MarkdownMessage";

interface AnswerCardProps {
  answer: AnswerPresentation;
  sourceSummary: SourceSummary | null;
  planSummary?: PlanSummary | null;
  sourceDurationLabel?: string;
  onDownloadContext: () => Promise<void> | void;
  onOpenArtifacts?: () => void;
  onOpenSources?: (summary: SourceSummary) => void;
}

const MAX_CITATION_PILLS = 8;

export function AnswerCard({
  answer,
  sourceSummary,
  planSummary,
  sourceDurationLabel,
  onDownloadContext,
  onOpenArtifacts,
  onOpenSources,
}: AnswerCardProps) {
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const citations = useMemo(
    () => answer.citations.slice(0, MAX_CITATION_PILLS),
    [answer.citations],
  );

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(answer.message.text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }, [answer.message.text]);

  const handleOpenCitation = useCallback(async (url: string) => {
    try {
      await openUrl(url);
    } catch {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }, []);

  const handleDownload = useCallback(async () => {
    setDownloading(true);
    try {
      await onDownloadContext();
    } finally {
      setDownloading(false);
    }
  }, [onDownloadContext]);

  const handleOpenArtifacts = useCallback(() => {
    onOpenArtifacts?.();
  }, [onOpenArtifacts]);

  const sourcePreviewDomains = useMemo(
    () => sourceSummary?.domains.slice(0, 4) || [],
    [sourceSummary],
  );
  const canOpenSources = !!sourceSummary && sourceSummary.totalSources > 0 && !!onOpenSources;

  return (
    <section className="answer-card" aria-label="Final answer">
      <div className="answer-card-header">
        <div className="answer-card-title-wrap">
          <div className="answer-card-eyebrow">Final Answer</div>
          <h3 className="answer-card-title">Autopilot</h3>
        </div>
        <div className="answer-card-actions">
          <button
            className={`answer-action-btn ${copied ? "success" : ""}`}
            onClick={handleCopy}
            title="Copy answer"
            type="button"
          >
            {copied ? icons.check : icons.copy}
            <span>{copied ? "Copied" : "Copy"}</span>
          </button>
          <button
            className="answer-action-btn"
            onClick={() => void handleDownload()}
            type="button"
            disabled={downloading}
            title="Download full context"
          >
            {icons.code}
            <span>{downloading ? "Exporting..." : "Download Context"}</span>
          </button>
          <button
            className="answer-action-btn"
            onClick={handleOpenArtifacts}
            type="button"
            disabled={!onOpenArtifacts}
            title="Open artifacts hub"
          >
            {icons.externalLink}
            <span>Artifacts</span>
          </button>
        </div>
      </div>

      <div className="answer-card-body">
        <MarkdownMessage text={answer.message.text} />
      </div>

      {citations.length > 0 && (
        <div className="answer-citations" aria-label="Citations">
          {citations.map((citation, idx) => (
            <button
              key={`${citation}-${idx}`}
              className="answer-citation-pill"
              onClick={() => void handleOpenCitation(citation)}
              type="button"
              title={citation}
            >
              <span className="citation-index">[{idx + 1}]</span>
              <span className="citation-url">{citation}</span>
            </button>
          ))}
        </div>
      )}

      <div className="answer-metadata-strip">
        <span>
          Run UTC: <strong>{answer.runTimestampUtc || "Unavailable"}</strong>
        </span>
        <span>
          Confidence: <strong>{answer.confidence || "n/a"}</strong>
        </span>
        <span>
          Completion: <strong>{answer.completionReason || "n/a"}</strong>
        </span>
      </div>

      {planSummary && (
        <div className="answer-metadata-strip">
          <span>
            Route: <strong>{planSummary.selectedRoute}</strong>
          </span>
          <span>
            Plan: <strong>{planSummary.status}</strong>
          </span>
          <span>
            Workers: <strong>{planSummary.workerCount}</strong>
          </span>
        </div>
      )}

      {sourceSummary && sourceSummary.totalSources > 0 && (
        <div className="answer-source-strip">
          <button
            className="answer-source-chip"
            type="button"
            onClick={() => sourceSummary && onOpenSources?.(sourceSummary)}
            aria-label={`${sourceSummary.totalSources} sources`}
            title="Open source activity"
            disabled={!canOpenSources}
          >
            {sourceDurationLabel && (
              <span className="answer-source-latency">{sourceDurationLabel}</span>
            )}
            <span className="answer-source-favicon-stack">
              {sourcePreviewDomains.map((entry, index) => (
                <span
                  key={`${entry.domain}-${index}`}
                  className="answer-source-favicon-wrap"
                  style={{
                    zIndex: sourcePreviewDomains.length - index,
                    marginLeft: index === 0 ? 0 : -10,
                  }}
                >
                  <img
                    className="answer-source-favicon"
                    src={entry.faviconUrl}
                    alt={`${entry.domain} favicon`}
                    loading="lazy"
                  />
                </span>
              ))}
            </span>
            <span className="answer-source-chip-label">
              {sourceSummary.totalSources}{" "}
              {sourceSummary.totalSources === 1 ? "source" : "sources"}
            </span>
          </button>
        </div>
      )}
    </section>
  );
}
