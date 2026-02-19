import { useCallback, useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { AnswerPresentation, ArtifactRef } from "../../../types";
import { icons } from "./Icons";
import { MarkdownMessage } from "./MarkdownMessage";

interface AnswerCardProps {
  answer: AnswerPresentation;
  artifactRefs: ArtifactRef[];
  onDownloadContext: () => Promise<void> | void;
  onOpenArtifact?: (artifactId: string) => void;
}

const MAX_CITATION_PILLS = 8;

export function AnswerCard({
  answer,
  artifactRefs,
  onDownloadContext,
  onOpenArtifact,
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

  const handleOpenArtifact = useCallback(() => {
    if (!onOpenArtifact) return;
    const first = artifactRefs[0];
    if (!first) return;
    onOpenArtifact(first.artifact_id);
  }, [artifactRefs, onOpenArtifact]);

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
            onClick={handleOpenArtifact}
            type="button"
            disabled={artifactRefs.length === 0}
            title="Open artifact inspector"
          >
            {icons.externalLink}
            <span>Open Artifacts</span>
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
    </section>
  );
}
