import { useMemo, useState, useRef, useEffect, useCallback } from "react";

interface LogArtifactViewProps {
  content: string;
}

const MAX_RENDER_LINES = 5000;

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
      className="log-copy-btn"
      onClick={handleCopy}
      title={copied ? "Copied!" : "Copy all"}
      type="button"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function LogArtifactView({ content }: LogArtifactViewProps) {
  const { visibleLines, totalLines } = useMemo(() => {
    if (!content) return { visibleLines: [] as string[], totalLines: 0 };
    const all = content.split("\n");
    return {
      visibleLines: all.length > MAX_RENDER_LINES ? all.slice(0, MAX_RENDER_LINES) : all,
      totalLines: all.length,
    };
  }, [content]);

  const truncated = totalLines > MAX_RENDER_LINES;

  if (!content) {
    return (
      <div className="artifact-view artifact-view-log">
        <pre className="log-empty">No log output available.</pre>
      </div>
    );
  }

  return (
    <div className="artifact-view artifact-view-log">
      <div className="log-toolbar">
        <span className="log-line-count">{totalLines.toLocaleString()} lines</span>
        <CopyButton text={content} />
      </div>

      <div className="log-content">
        {visibleLines.map((line, i) => (
          <div key={i} className="log-line">
            <span className="log-line-number">{i + 1}</span>
            <span className="log-line-text">{line}</span>
          </div>
        ))}

        {truncated && (
          <div className="log-line log-truncation-line">
            <span className="log-line-number">...</span>
            <span className="log-line-text">
              ({(totalLines - MAX_RENDER_LINES).toLocaleString()} more lines not rendered)
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
