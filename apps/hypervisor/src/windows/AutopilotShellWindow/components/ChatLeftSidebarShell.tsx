import type { ReactNode } from "react";

interface ChatLeftSidebarShellProps {
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

export function ChatLeftSidebarShell({
  ariaLabel,
  title,
  actions,
  className,
  bodyClassName,
  children,
}: ChatLeftSidebarShellProps) {
  return (
    <aside
      className={joinClassNames("chat-left-sidebar", className)}
      aria-label={ariaLabel}
    >
      <div className="chat-left-sidebar-header">
        <span className="chat-left-sidebar-title">{title}</span>
        {actions ? <div className="chat-left-sidebar-actions">{actions}</div> : null}
      </div>

      <div className={joinClassNames("chat-left-sidebar-body", bodyClassName)}>
        {children}
      </div>
    </aside>
  );
}
