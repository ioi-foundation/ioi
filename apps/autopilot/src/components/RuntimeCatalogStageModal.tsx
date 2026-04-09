import { useState } from "react";
import "./RuntimeCatalogStageModal.css";

interface RuntimeCatalogStageModalProps {
  isOpen: boolean;
  onClose: () => void;
  onStageEntry: (
    entry: {
      id: string;
      name: string;
      description: string;
      ownerLabel: string;
      entryKind: string;
      runtimeNotes: string;
      statusLabel?: string;
      image: string;
    },
    notes: string,
  ) => Promise<void>;
  onOpenCapabilities: () => void;
  entry: {
    id: string;
    name: string;
    description: string;
    ownerLabel: string;
    entryKind: string;
    runtimeNotes: string;
    statusLabel?: string;
    image: string;
  };
}

function stageCopy(entryId: string): {
  actionLabel: string;
  runtimeAction: string;
  entryLabel: string;
} {
  if (entryId.startsWith("gallery:")) {
    return {
      actionLabel: "Stage sync",
      runtimeAction: "sync",
      entryLabel: "gallery catalog",
    };
  }

  if (entryId.startsWith("playbook:") || entryId.startsWith("worker:")) {
    return {
      actionLabel: "Stage promotion",
      runtimeAction: "promote",
      entryLabel: entryId.startsWith("playbook:")
        ? "playbook"
        : "worker template",
    };
  }

  return {
    actionLabel: "Stage entry",
    runtimeAction: "stage",
    entryLabel: "catalog entry",
  };
}

export function RuntimeCatalogStageModal({
  isOpen,
  onClose,
  onStageEntry,
  onOpenCapabilities,
  entry,
}: RuntimeCatalogStageModalProps) {
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { actionLabel, runtimeAction, entryLabel } = stageCopy(entry.id);

  if (!isOpen) return null;

  const handleStage = async () => {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await onStageEntry(entry, notes);
      setMessage(
        `${actionLabel} queued in the Local Engine staging list. Review or promote it from the runtime queue.`,
      );
      setNotes("");
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="catalog-stage-modal-overlay" onClick={onClose}>
      <div className="catalog-stage-modal" onClick={(e) => e.stopPropagation()}>
        <div className="catalog-stage-header">
          <div className="catalog-entry-preview">
            <div className="catalog-entry-icon-large" style={{ background: entry.image }}>
              {entry.name[0]}
            </div>
            <div>
              <h2>{actionLabel} for {entry.name}</h2>
              <p className="subtext">
                Queue a governed runtime operation with receipts instead of
                changing the catalog out of band.
              </p>
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="catalog-stage-content">
          <div className="catalog-runtime-banner">
            <span className="catalog-runtime-icon">⚡</span>
            <span>
              Runtime notes: <strong>{entry.runtimeNotes}</strong>
            </span>
          </div>

          <article className="catalog-stage-plan-card">
            <div className="catalog-stage-plan-card-head">
              <strong>Governed runtime action</strong>
              <span>{runtimeAction}</span>
            </div>
            <p>{entry.description}</p>
            <div className="catalog-stage-tags">
              <span>{entry.ownerLabel}</span>
              <span>{entry.entryKind}</span>
              {entry.statusLabel ? <span>{entry.statusLabel}</span> : null}
              <span>{entry.id}</span>
            </div>
            <p className="catalog-stage-plan-note">
              This stages a Local Engine operation so the action stays visible,
              reviewable, and promotable from the runtime queue.
            </p>
          </article>

          <label className="catalog-stage-notes-field">
            <span>Operator notes</span>
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder={`Why this ${entryLabel} should be staged, who owns it, or what runtime profile it belongs to.`}
              rows={4}
            />
          </label>

          {message ? (
            <p className="catalog-stage-status catalog-stage-status-success">
              {message}
            </p>
          ) : null}
          {error ? (
            <p className="catalog-stage-status catalog-stage-status-error">
              {error}
            </p>
          ) : null}

          <div className="policy-mini">
            <h3>Why staged first</h3>
            <div className="catalog-stage-tags">
              <span>Visible in runtime queue</span>
              <span>Promotable with receipts</span>
              <span>Preserves governed execution</span>
            </div>
          </div>
        </div>

        <div className="catalog-stage-footer">
          <button
            className="catalog-stage-secondary-btn"
            onClick={onOpenCapabilities}
          >
            Open runtime queue
          </button>
          <button
            className="catalog-stage-btn"
            onClick={() => void handleStage()}
            disabled={saving}
          >
            {saving ? "Staging…" : actionLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
