import type { ReactNode } from "react";

interface HypervisorLeftSidebarShellProps {
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

export function HypervisorLeftSidebarShell({
  ariaLabel,
  title,
  actions,
  className,
  bodyClassName,
  children,
}: HypervisorLeftSidebarShellProps) {
  return (
    <aside
      className={joinClassNames("hypervisor-left-sidebar", className)}
      aria-label={ariaLabel}
    >
      <div className="hypervisor-left-sidebar-header">
        <span className="hypervisor-left-sidebar-title">{title}</span>
        {actions ? <div className="hypervisor-left-sidebar-actions">{actions}</div> : null}
      </div>

      <div className={joinClassNames("hypervisor-left-sidebar-body", bodyClassName)}>
        {children}
      </div>
    </aside>
  );
}
