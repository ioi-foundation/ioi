import { SubstrateGlassBox } from "./SubstrateGlassBox";
import { VisualEvidenceCard } from "./VisualEvidenceCard";
import type { ScreenshotReceiptEvidence } from "../utils/screenshotEvidence";
import type {
  SecurityPolicyRow,
  SubstrateReceiptRow,
} from "./ArtifactHubViewModels";
import { KernelLogsView } from "./views/KernelLogsView";
import { ArtifactHubEmptyState } from "./views/shared/ArtifactHubEmptyState";

function clipText(value: string, maxChars: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

export { KernelLogsView as KernelView };

export function SecurityView({
  verificationNotes,
  selectedRoute,
  securityRows,
  onOpenArtifact,
}: {
  verificationNotes: string[];
  selectedRoute?: string | null;
  securityRows: SecurityPolicyRow[];
  onOpenArtifact?: (artifactId: string) => void;
}) {
  if (securityRows.length === 0 && verificationNotes.length === 0) {
    return (
      <ArtifactHubEmptyState message="No verification evidence was captured for this scope." />
    );
  }

  return (
    <div className="artifact-hub-thoughts">
      {verificationNotes.length > 0 && (
        <section className="thoughts-section">
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">Verifier</span>
            {selectedRoute ? (
              <span className="thoughts-agent-role">{selectedRoute}</span>
            ) : null}
          </div>
          <div className="thoughts-notes">
            {verificationNotes.map((note) => (
              <div className="thoughts-note" key={note}>
                {note}
              </div>
            ))}
          </div>
        </section>
      )}

      {securityRows.length > 0 && (
        <div className="artifact-hub-policy-list">
          {securityRows.map((row) => (
            <article className="artifact-hub-policy-row" key={row.eventId}>
              <div className="artifact-hub-policy-meta">
                <span className="artifact-hub-policy-pill">{row.decision}</span>
                <span>{row.timestamp}</span>
                <span>{row.toolName}</span>
              </div>
              <div className="artifact-hub-policy-body">
                <span>stage={row.stage}</span>
                <span>resolution={row.resolution}</span>
              </div>
              {row.summary && (
                <p className="artifact-hub-policy-summary">{row.summary}</p>
              )}
              {row.reportArtifactId && onOpenArtifact ? (
                <button
                  className="artifact-hub-open-btn"
                  onClick={() => onOpenArtifact(row.reportArtifactId!)}
                  type="button"
                >
                  Open report artifact
                </button>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

export function ScreenshotsView({
  screenshotReceipts,
  formatTimestamp,
}: {
  screenshotReceipts: ScreenshotReceiptEvidence[];
  formatTimestamp: (value: string) => string;
}) {
  if (screenshotReceipts.length === 0) {
    return (
      <ArtifactHubEmptyState message="No visual evidence was captured for this run." />
    );
  }

  return (
    <div className="artifact-hub-screenshot-list">
      {screenshotReceipts.map((receipt) => (
        <article className="artifact-hub-screenshot-row" key={receipt.id}>
          <div className="artifact-hub-generic-meta">
            <span>{formatTimestamp(receipt.timestamp)}</span>
            <span>{receipt.source}</span>
            <span>step {receipt.stepIndex}</span>
          </div>
          {!receipt.hasBlob && (
            <p className="artifact-hub-generic-summary">
              Screenshot action receipt captured, but no retrievable blob hash
              was emitted.
            </p>
          )}
          <VisualEvidenceCard
            hash={receipt.hash}
            timestamp={receipt.timestamp}
            stepIndex={receipt.stepIndex}
            title={
              receipt.hasBlob
                ? "Visual evidence"
                : "Visual evidence (metadata-only)"
            }
            compact={true}
          />
          {!!receipt.summary && (
            <p className="artifact-hub-generic-summary">
              {clipText(receipt.summary, 180)}
            </p>
          )}
        </article>
      ))}
    </div>
  );
}

export function SubstrateView({
  substrateReceipts,
}: {
  substrateReceipts: SubstrateReceiptRow[];
}) {
  if (substrateReceipts.length === 0) {
    return (
      <ArtifactHubEmptyState message="No runtime introspection receipts were captured for this scope." />
    );
  }

  return (
    <div className="artifact-hub-substrate">
      <SubstrateGlassBox receipts={substrateReceipts} maxReceipts={24} />
      <div className="artifact-hub-substrate-list">
        {substrateReceipts.map((receipt) => (
          <article className="artifact-hub-substrate-row" key={receipt.eventId}>
            <div className="artifact-hub-generic-meta">
              <span>{receipt.timestamp}</span>
              <span>step {receipt.stepIndex}</span>
              <span>{receipt.success ? "success" : "failure"}</span>
            </div>
            <div className="artifact-hub-generic-title">
              {receipt.toolName || "memory_retrieve"} · k={receipt.k} · ef=
              {receipt.efSearch}
            </div>
            <p className="artifact-hub-generic-summary">
              candidates={receipt.candidateReranked}/{receipt.candidateTotal}{" "}
              (limit {receipt.candidateLimit}) · truncated=
              {receipt.candidateTruncated ? "true" : "false"} · metric=
              {receipt.distanceMetric}
              {receipt.embeddingNormalized ? " (normalized)" : ""}
            </p>
            <div className="artifact-hub-substrate-meta">
              <span title={receipt.queryHash}>
                query={clipText(receipt.queryHash, 16)}
              </span>
              <span title={receipt.indexRoot}>
                index={clipText(receipt.indexRoot, 16)}
              </span>
              {!!receipt.proofHash && (
                <span title={receipt.proofHash}>
                  proof={clipText(receipt.proofHash, 16)}
                </span>
              )}
              {!!receipt.certificateMode && (
                <span>certificate={receipt.certificateMode}</span>
              )}
            </div>
            {!!receipt.errorClass && (
              <p className="artifact-hub-generic-summary">
                error={receipt.errorClass}
              </p>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}
