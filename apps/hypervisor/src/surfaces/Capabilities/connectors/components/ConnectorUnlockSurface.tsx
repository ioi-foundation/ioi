import type { ReactNode } from "react";
import { WorkspaceModal } from "./googleWorkspaceConnectorPanelParts";

export type ConnectorUnlockPreviewAction = {
  id: string;
  categoryLabel: string;
  title: string;
  description: string;
  hint: string;
  ariaLabel?: string;
};

export function ConnectorActionPreviewStage({
  kicker = "Preview",
  title,
  summary,
  statusLabel = "Connect required",
  actions,
  onSelectAction,
}: {
  kicker?: string;
  title: string;
  summary: string;
  statusLabel?: string;
  actions: ConnectorUnlockPreviewAction[];
  onSelectAction: (actionId: string) => void;
}) {
  if (actions.length === 0) {
    return null;
  }

  return (
    <section className="workspace-auth-stage workspace-preview-stage">
      <div className="workspace-auth-stage-head">
        <div>
          <span className="workspace-hero-kicker">{kicker}</span>
          <h4>{title}</h4>
          <p>{summary}</p>
        </div>
        <span className="workspace-health-pill tone-setup">{statusLabel}</span>
      </div>
      <div className="workspace-preview-grid">
        {actions.map((action) => (
          <button
            key={action.id}
            type="button"
            className="workspace-preview-card workspace-preview-card-button"
            onClick={() => onSelectAction(action.id)}
            aria-label={
              action.ariaLabel ??
              `Unlock ${action.title}. Open action setup details.`
            }
          >
            <span>{action.categoryLabel}</span>
            <strong>{action.title}</strong>
            <span className="workspace-preview-card-description">
              {action.description}
            </span>
            <span className="workspace-preview-card-hint">{action.hint}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

export function ConnectorActionUnlockModal({
  open,
  title,
  description,
  summaryCategory,
  summaryTitle,
  summaryDescription,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  summaryCategory: string;
  summaryTitle: string;
  summaryDescription: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <WorkspaceModal
      open={open}
      title={title}
      description={description}
      onClose={onClose}
    >
      <div className="workspace-unlock-modal">
        <article className="workspace-stat-card workspace-summary-card">
          <span>{summaryCategory}</span>
          <strong>{summaryTitle}</strong>
          <p>{summaryDescription}</p>
        </article>
        {children}
      </div>
    </WorkspaceModal>
  );
}
