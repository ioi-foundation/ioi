import type { KernelLogRow } from "../ArtifactHubViewModels";
import { ArtifactHubEmptyState } from "./shared/ArtifactHubEmptyState";

export function KernelLogsView({
  kernelLogs,
}: {
  kernelLogs: KernelLogRow[];
}) {
  if (kernelLogs.length === 0) {
    return (
      <ArtifactHubEmptyState message="No activity events were captured for this scope." />
    );
  }

  return (
    <div className="artifact-hub-log-list">
      {kernelLogs.map((row) => (
        <article
          className={`artifact-hub-log-row status-${row.status}`}
          key={row.eventId}
        >
          <div className="artifact-hub-log-meta">
            <span>{row.timestamp}</span>
            <span>{row.eventType}</span>
            <span>{row.toolName || "system"}</span>
          </div>
          <div className="artifact-hub-log-title">{row.title}</div>
          {row.summary ? (
            <p className="artifact-hub-log-summary">{row.summary}</p>
          ) : null}
        </article>
      ))}
    </div>
  );
}

