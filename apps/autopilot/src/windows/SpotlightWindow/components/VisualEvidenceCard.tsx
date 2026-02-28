import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { normalizeVisualHash } from "../utils/visualHash";

interface ContextBlob {
  data_base64: string;
  mime_type: string;
}

const CONTEXT_BLOB_UNAVAILABLE_MIME = "application/x-ioi-context-unavailable";

interface VisualEvidenceCardProps {
  hash: string;
  timestamp?: string | null;
  stepIndex?: number | null;
  title?: string;
  compact?: boolean;
  className?: string;
}

function formatTimestamp(value?: string | null): string {
  if (!value) return "unknown time";
  const millis = Date.parse(value);
  if (Number.isNaN(millis)) return value;
  return new Date(millis).toISOString();
}

export function VisualEvidenceCard({
  hash,
  timestamp,
  stepIndex,
  title = "Visual evidence",
  compact = false,
  className = "",
}: VisualEvidenceCardProps) {
  const normalizedHash = useMemo(() => normalizeVisualHash(hash), [hash]);
  const [blob, setBlob] = useState<ContextBlob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!normalizedHash) {
      setBlob(null);
      setError(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    void invoke<ContextBlob>("get_context_blob", { hash: normalizedHash })
      .then((next) => {
        if (cancelled) return;
        setBlob(next);
      })
      .catch((err) => {
        if (cancelled) return;
        setBlob(null);
        setError(String(err || "Failed to load context blob"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [normalizedHash]);

  const imageSrc = useMemo(() => {
    if (!blob) return "";
    if (blob.mime_type === CONTEXT_BLOB_UNAVAILABLE_MIME) return "";
    if (!blob.mime_type.toLowerCase().startsWith("image/")) return "";
    if (!blob.data_base64) return "";
    return `data:${blob.mime_type};base64,${blob.data_base64}`;
  }, [blob]);

  const contextUnavailable = useMemo(
    () => !!blob && blob.mime_type === CONTEXT_BLOB_UNAVAILABLE_MIME,
    [blob],
  );

  return (
    <article
      className={`visual-evidence-card ${compact ? "compact" : ""} ${className}`.trim()}
    >
      <div className="visual-evidence-meta">
        <span className="visual-evidence-title">{title}</span>
        {stepIndex !== null && stepIndex !== undefined && (
          <span className="visual-evidence-pill">step {stepIndex}</span>
        )}
        <span className="visual-evidence-time">{formatTimestamp(timestamp)}</span>
      </div>

      <div className="visual-evidence-preview">
        {!loading && !error && !normalizedHash && (
          <div className="visual-evidence-status">
            No retrievable screenshot evidence was recorded for this step.
          </div>
        )}
        {loading && <div className="visual-evidence-status">Loading screenshot…</div>}
        {!loading && error && <div className="visual-evidence-status error">{error}</div>}
        {!loading && !error && contextUnavailable && (
          <div className="visual-evidence-status">
            Visual context is not currently available for this step.
          </div>
        )}
        {!loading && !error && !!normalizedHash && !contextUnavailable && !imageSrc && (
          <div className="visual-evidence-status">
            Visual blob is available but not an image payload.
          </div>
        )}
        {!loading && !error && !!normalizedHash && imageSrc && (
          <img
            src={imageSrc}
            alt="Captured visual context"
            className="visual-evidence-image"
            loading="lazy"
          />
        )}
      </div>

      {!!normalizedHash && <div className="visual-evidence-hash">{normalizedHash}</div>}
    </article>
  );
}
