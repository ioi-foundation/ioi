import type { LocalEngineStagedOperation } from "../../../types";
import { formatRuntimeStatusLabel } from "../../../services/runtimeInspection";

type LiveStagedOperationsSectionProps = {
  operations: LocalEngineStagedOperation[];
  loading: boolean;
  busyOperationId: string | null;
  message: string | null;
  error: string | null;
  onPromoteOperation?: (operationId: string) => void;
  onRemoveOperation?: (operationId: string) => void;
};

function humanizeStatus(value: string | null | undefined): string {
  return formatRuntimeStatusLabel(value);
}

function formatTimestampMs(value: number | null | undefined): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return new Date(value).toLocaleString();
}

export function LiveStagedOperationsSection({
  operations,
  loading,
  busyOperationId,
  message,
  error,
  onPromoteOperation,
  onRemoveOperation,
}: LiveStagedOperationsSectionProps) {
  if (!loading && !message && !error && operations.length === 0) {
    return null;
  }

  return (
    <section className="thoughts-section">
      <div className="thoughts-agent-header">
        <span className="thoughts-agent-dot" />
        <span className="thoughts-agent-name">Staged promotions</span>
        <span className="thoughts-agent-role">
          {operations.length > 0
            ? `${operations.length} queued operations`
            : "Syncing Local Engine queue"}
        </span>
      </div>

      {message ? <p className="thoughts-note">{message}</p> : null}
      {error ? <p className="thoughts-note thoughts-note--error">{error}</p> : null}
      {loading && operations.length === 0 ? (
        <p className="thoughts-empty-state">
          Loading staged Local Engine operations.
        </p>
      ) : null}

      {operations.map((operation) => {
        const operationBusy = busyOperationId === operation.operationId;
        return (
          <article
            key={operation.operationId}
            className={`worker-card live-staged-operation status-${operation.status}`}
          >
            <div className="thoughts-agent-header">
              <span className="thoughts-agent-dot" />
              <span className="thoughts-agent-name">{operation.title}</span>
              <span className="thoughts-agent-role">
                {humanizeStatus(operation.status)}
              </span>
            </div>

            <div className="worker-card-meta">
              <span className="worker-card-chip">
                {humanizeStatus(operation.subjectKind)}
              </span>
              <span className="worker-card-chip is-emphasis">
                {humanizeStatus(operation.operation)}
              </span>
              {operation.subjectId ? (
                <span className="worker-card-chip">{operation.subjectId}</span>
              ) : null}
            </div>

            <div className="worker-card-grid">
              <div className="worker-card-block is-emphasis">
                <span>Notes</span>
                <p>{operation.notes?.trim() || "No operator note captured."}</p>
              </div>
              <div className="worker-card-block">
                <span>Source</span>
                <p>{operation.sourceUri?.trim() || "Queued directly from Chat."}</p>
              </div>
              <div className="worker-card-block">
                <span>Created</span>
                <p>{formatTimestampMs(operation.createdAtMs) || "Unknown"}</p>
              </div>
              <div className="worker-card-block">
                <span>Action</span>
                <p>Promote into the live Local Engine queue or remove from staging.</p>
              </div>
            </div>

            <div className="live-playbook-run__actions">
              {onPromoteOperation ? (
                <button
                  type="button"
                  className="live-playbook-run__action is-primary"
                  disabled={operationBusy}
                  onClick={() => onPromoteOperation(operation.operationId)}
                >
                  Promote
                </button>
              ) : null}
              {onRemoveOperation ? (
                <button
                  type="button"
                  className="live-playbook-run__action"
                  disabled={operationBusy}
                  onClick={() => onRemoveOperation(operation.operationId)}
                >
                  Remove
                </button>
              ) : null}
            </div>
          </article>
        );
      })}
    </section>
  );
}
