import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import type { SessionSummary, TraceBundleDiffResult } from "../../../types";

interface ArtifactHubCompareViewProps {
  activeSessionId?: string | null;
  sessions: SessionSummary[];
  compareTargetId?: string | null;
  onCompareTargetChange?: (sessionId: string | null) => void;
  onLoadSession?: (sessionId: string) => void;
}

function formatSessionTimestamp(timestamp: number): string {
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    return "Unknown time";
  }
  return new Date(timestamp).toLocaleString();
}

function formatSessionLabel(session: SessionSummary): string {
  const title = session.title?.trim() || session.session_id.slice(0, 8);
  return `${title} · ${formatSessionTimestamp(session.timestamp)}`;
}

function sessionHeadline(session: SessionSummary | null | undefined): string {
  if (!session) return "Unknown retained run";
  return session.title?.trim() || session.session_id.slice(0, 8);
}

export function ArtifactHubCompareView({
  activeSessionId,
  sessions,
  compareTargetId,
  onCompareTargetChange,
  onLoadSession,
}: ArtifactHubCompareViewProps) {
  const orderedSessions = useMemo(
    () => [...sessions].sort((left, right) => right.timestamp - left.timestamp),
    [sessions],
  );
  const activeSession = useMemo(
    () =>
      orderedSessions.find((session) => session.session_id === activeSessionId) ||
      null,
    [activeSessionId, orderedSessions],
  );
  const compareCandidates = useMemo(
    () =>
      orderedSessions.filter((session) => session.session_id !== activeSessionId),
    [activeSessionId, orderedSessions],
  );

  const [diff, setDiff] = useState<TraceBundleDiffResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (compareCandidates.length === 0) {
      onCompareTargetChange?.(null);
      return;
    }

    if (
      compareTargetId &&
      compareTargetId !== activeSessionId &&
      compareCandidates.some((session) => session.session_id === compareTargetId)
    ) {
      return;
    }

    onCompareTargetChange?.(compareCandidates[0].session_id);
  }, [activeSessionId, compareCandidates, compareTargetId, onCompareTargetChange]);

  useEffect(() => {
    if (!activeSessionId || !compareTargetId) {
      setDiff(null);
      setError(null);
      setLoading(false);
      return;
    }

    let disposed = false;
    setLoading(true);
    setError(null);

    void invoke<TraceBundleDiffResult>("compare_trace_bundles", {
      leftThreadId: activeSessionId,
      left_thread_id: activeSessionId,
      rightThreadId: compareTargetId,
      right_thread_id: compareTargetId,
    })
      .then((result) => {
        if (!disposed) {
          setDiff(result);
        }
      })
      .catch((reason) => {
        if (!disposed) {
          setDiff(null);
          setError(reason instanceof Error ? reason.message : String(reason));
        }
      })
      .finally(() => {
        if (!disposed) {
          setLoading(false);
        }
      });

    return () => {
      disposed = true;
    };
  }, [activeSessionId, compareTargetId]);

  const compareTarget =
    compareCandidates.find((session) => session.session_id === compareTargetId) ||
    null;

  if (!activeSessionId || !activeSession) {
    return (
      <p className="artifact-hub-empty">
        Open a retained session before comparing run traces.
      </p>
    );
  }

  if (compareCandidates.length === 0) {
    return (
      <p className="artifact-hub-empty">
        Compare becomes available once there is another retained run in session
        history.
      </p>
    );
  }

  return (
    <div className="artifact-hub-compare">
      <section className="artifact-hub-compare-hero">
        <div className="artifact-hub-compare-hero-copy">
          <span className="artifact-hub-compare-eyebrow">Run compare</span>
          <h3>{sessionHeadline(activeSession)}</h3>
          <p>
            Compare the current retained run against another session without
            reconstructing evidence by hand.
          </p>
        </div>
        <div className="artifact-hub-compare-controls">
          <label className="artifact-hub-turn-select-wrap">
            <span className="artifact-hub-turn-select-label">Compared run</span>
            <select
              className="artifact-hub-turn-select"
              value={compareTargetId || ""}
              onChange={(event) => onCompareTargetChange?.(event.target.value)}
            >
              {compareCandidates.map((session) => (
                <option key={session.session_id} value={session.session_id}>
                  {formatSessionLabel(session)}
                </option>
              ))}
            </select>
          </label>
          {compareTarget && onLoadSession ? (
            <button
              className="artifact-hub-open-btn"
              onClick={() => onLoadSession(compareTarget.session_id)}
              type="button"
            >
              Open compared session
            </button>
          ) : null}
        </div>
      </section>

      <section
        className={`artifact-hub-compare-callout ${
          diff?.changedSectionCount ? "is-changed" : "is-matched"
        }`}
      >
        <span className="artifact-hub-compare-eyebrow">First divergence</span>
        <strong>
          {loading
            ? "Comparing retained traces..."
            : diff?.firstDivergenceSummary ||
              "No operator-visible divergence detected."}
        </strong>
        <p>
          {loading
            ? "The runtime is assembling canonical traces for both runs."
            : diff
              ? `${diff.changedSectionCount} sections changed between ${sessionHeadline(
                  diff.leftSessionSummary || activeSession,
                )} and ${sessionHeadline(diff.rightSessionSummary || compareTarget)}.`
              : "The canonical trace diff is ready once both retained runs load."}
        </p>
      </section>

      {error ? (
        <p className="artifact-hub-error">{error}</p>
      ) : null}

      {diff ? (
        <>
          <section className="artifact-hub-compare-stats">
            {diff.stats.map((stat) => (
              <article className="artifact-hub-compare-stat" key={stat.label}>
                <span className="artifact-hub-compare-stat-label">
                  {stat.label}
                </span>
                <div className="artifact-hub-compare-stat-values">
                  <span>{stat.leftValue}</span>
                  <span>{stat.rightValue}</span>
                </div>
              </article>
            ))}
          </section>

          <section className="artifact-hub-compare-section-list">
            {diff.sections.map((section) => (
              <article
                className={`artifact-hub-compare-section ${
                  section.changed ? "is-changed" : "is-matched"
                }`}
                key={section.key}
              >
                <div className="artifact-hub-compare-section-header">
                  <div>
                    <h4>{section.label}</h4>
                    <p>{section.summary}</p>
                  </div>
                  <span className="artifact-hub-compare-badge">
                    {section.changed ? "Changed" : "Matched"}
                  </span>
                </div>

                <div className="artifact-hub-compare-values">
                  <div className="artifact-hub-compare-value-card">
                    <span className="artifact-hub-compare-value-label">
                      Current run
                    </span>
                    <strong>{section.leftValue || "No retained value"}</strong>
                    <small>{formatSessionLabel(activeSession)}</small>
                  </div>
                  <div className="artifact-hub-compare-value-card">
                    <span className="artifact-hub-compare-value-label">
                      Compared run
                    </span>
                    <strong>{section.rightValue || "No retained value"}</strong>
                    <small>
                      {compareTarget
                        ? formatSessionLabel(compareTarget)
                        : "No compared run selected"}
                    </small>
                  </div>
                </div>

                {section.details.length > 0 ? (
                  <div className="artifact-hub-compare-detail-list">
                    {section.details.map((detail) => (
                      <div
                        className="artifact-hub-compare-detail"
                        key={`${section.key}-${detail}`}
                      >
                        {detail}
                      </div>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </section>
        </>
      ) : null}
    </div>
  );
}
