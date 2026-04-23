import { useMemo, useState } from "react";
import type { CanonicalTraceBundle } from "../../../types";
import type { ReplayTimelineRow } from "./ArtifactHubReplayModel";

type ReplayFilter = "all" | "policy" | "receipt" | "artifact" | "action";

interface ArtifactHubReplayViewProps {
  loading: boolean;
  error: string | null;
  bundle: CanonicalTraceBundle | null;
  rows: ReplayTimelineRow[];
  onOpenArtifact?: (artifactId: string) => void;
}

const FILTER_OPTIONS: Array<{ key: ReplayFilter; label: string }> = [
  { key: "all", label: "All" },
  { key: "policy", label: "Policy" },
  { key: "receipt", label: "Receipts" },
  { key: "artifact", label: "Artifacts" },
  { key: "action", label: "Actions" },
];

function formatReplayTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    return value || "Unknown time";
  }
  return new Date(timestamp).toLocaleString();
}

export function ArtifactHubReplayView({
  loading,
  error,
  bundle,
  rows,
  onOpenArtifact,
}: ArtifactHubReplayViewProps) {
  const [filter, setFilter] = useState<ReplayFilter>("all");

  const filteredRows = useMemo(() => {
    if (filter === "all") return rows;
    return rows.filter((row) => row.kind === filter);
  }, [filter, rows]);

  const policyCount = bundle?.stats.interventionCount ?? 0;
  const artifactCount = bundle?.stats.artifactCount ?? 0;
  const receiptCount = bundle?.stats.receiptCount ?? 0;
  const eventCount = bundle?.stats.eventCount ?? 0;

  if (loading && !bundle) {
    return (
      <p className="artifact-hub-empty">
        Loading the canonical trace bundle for this session.
      </p>
    );
  }

  if (error && !bundle) {
    return <p className="artifact-hub-error">{error}</p>;
  }

  if (!bundle || rows.length === 0) {
    return (
      <p className="artifact-hub-empty">
        No canonical replay rows were retained for this session.
      </p>
    );
  }

  return (
    <div className="artifact-hub-replay">
      <section className="artifact-hub-replay-hero">
        <div className="artifact-hub-replay-hero-copy">
          <span className="artifact-hub-replay-eyebrow">Canonical replay</span>
          <h3>
            {bundle.sessionSummary?.title?.trim() || "Chronological retained run"}
          </h3>
          <p>
            Review one runtime-owned trace bundle with prompts, governed
            interventions, retained receipts, and artifacts inline.
          </p>
        </div>
        <div className="artifact-hub-replay-stats">
          <article className="artifact-hub-replay-stat">
            <span className="artifact-hub-replay-stat-label">Policy spans</span>
            <strong>{policyCount}</strong>
          </article>
          <article className="artifact-hub-replay-stat">
            <span className="artifact-hub-replay-stat-label">Receipts</span>
            <strong>{receiptCount}</strong>
          </article>
          <article className="artifact-hub-replay-stat">
            <span className="artifact-hub-replay-stat-label">Artifacts</span>
            <strong>{artifactCount}</strong>
          </article>
          <article className="artifact-hub-replay-stat">
            <span className="artifact-hub-replay-stat-label">Events</span>
            <strong>{eventCount}</strong>
          </article>
        </div>
      </section>

      {error ? <p className="artifact-hub-error">{error}</p> : null}

      <section className="artifact-hub-replay-filters" aria-label="Replay filters">
        {FILTER_OPTIONS.map((option) => (
          <button
            key={option.key}
            type="button"
            className={`artifact-hub-replay-filter ${
              option.key === filter ? "is-active" : ""
            }`}
            onClick={() => setFilter(option.key)}
          >
            {option.label}
          </button>
        ))}
      </section>

      <section className="artifact-hub-replay-list">
        {filteredRows.map((row) => (
          <article
            className={`artifact-hub-replay-row is-${row.kind}`}
            key={row.id}
          >
            <div className="artifact-hub-replay-row-meta">
              <span className="artifact-hub-replay-kind">{row.kindLabel}</span>
              <time>{formatReplayTimestamp(row.timestamp)}</time>
            </div>
            <div className="artifact-hub-replay-row-body">
              <div>
                <h4>{row.title}</h4>
                <p>{row.summary}</p>
              </div>
              {row.meta.length > 0 ? (
                <div className="artifact-hub-replay-row-tags">
                  {row.meta.map((meta) => (
                    <span className="artifact-hub-replay-tag" key={`${row.id}-${meta}`}>
                      {meta}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
            {row.artifactId && onOpenArtifact ? (
              <button
                className="artifact-hub-open-btn secondary"
                type="button"
                onClick={() => onOpenArtifact(row.artifactId!)}
              >
                {row.artifactLabel || "Open artifact"}
              </button>
            ) : null}
          </article>
        ))}
      </section>
    </div>
  );
}
