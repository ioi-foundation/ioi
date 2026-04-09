import type { ReactNode } from "react";

export function ConnectorActionWorkbench({
  title,
  summary,
  shortcuts,
  actionLabel,
  browser,
  sidebar,
  children,
  composer,
  className,
}: {
  title: string;
  summary: string;
  shortcuts: ReactNode;
  actionLabel: string | null;
  browser?: ReactNode;
  sidebar?: ReactNode;
  children?: ReactNode;
  composer?: ReactNode;
  className?: string;
}) {
  const browserContent = browser ?? children;
  const sidebarContent = sidebar ?? composer;
  return (
    <section
      className={
        className
          ? `workspace-action-workbench ${className}`
          : "workspace-action-workbench"
      }
    >
      <div className="workspace-action-browser">{browserContent}</div>
      <aside className="workspace-action-sidebar">
        <article className="workspace-stat-card workspace-summary-card">
          <span>{title}</span>
          <strong>{actionLabel ?? "Choose an action"}</strong>
          <p>{summary}</p>
          <div className="workspace-action-shortcuts">{shortcuts}</div>
        </article>
        {sidebarContent}
      </aside>
    </section>
  );
}

export function ConnectorFocusedFormCard({
  actionLabel,
  description,
  onReturn,
}: {
  actionLabel: string | null;
  description: string;
  onReturn: () => void;
}) {
  return (
    <article className="workspace-stat-card workspace-summary-card">
      <span>Focused form</span>
      <strong>{actionLabel ?? "No action selected"}</strong>
      <p>{description}</p>
      <div className="workspace-card-actions">
        <button type="button" className="btn-secondary" onClick={onReturn}>
          Return to inline form
        </button>
      </div>
    </article>
  );
}

export function ConnectorExecutionMeta({
  children,
}: {
  children: ReactNode;
}) {
  return <div className="workspace-storage-list">{children}</div>;
}

export function ConnectorInlineResultCard({
  summary,
  details,
}: {
  summary: string;
  details?: string[];
}) {
  return (
    <div className="workspace-inline-result" role="status" aria-live="polite">
      <strong>{summary}</strong>
      {details && details.length > 0 ? (
        <ul>
          {details.map((detail) => (
            <li key={detail}>{detail}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
