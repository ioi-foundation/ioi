import type { ReactNode } from "react";

interface StudioLeftSidebarShellProps {
  ariaLabel: string;
  title: ReactNode;
  actions?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}

function joinClassNames(...values: Array<string | undefined>) {
  return values.filter(Boolean).join(" ");
}

export function StudioLeftSidebarShell({
  ariaLabel,
  title,
  actions,
  className,
  bodyClassName,
  children,
}: StudioLeftSidebarShellProps) {
  return (
    <aside
      className={joinClassNames("studio-left-sidebar", className)}
      aria-label={ariaLabel}
    >
      <div className="studio-left-sidebar-header">
        <span className="studio-left-sidebar-title">{title}</span>
        {actions ? <div className="studio-left-sidebar-actions">{actions}</div> : null}
      </div>

      <div className={joinClassNames("studio-left-sidebar-body", bodyClassName)}>
        {children}
      </div>
    </aside>
  );
}
