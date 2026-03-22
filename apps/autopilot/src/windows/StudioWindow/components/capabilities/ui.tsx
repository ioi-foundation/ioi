import type { ReactNode } from "react";

export function IconBase({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {children}
    </svg>
  );
}

export function SparklesIcon() {
  return (
    <IconBase>
      <path d="m12 3 1.8 4.2L18 9l-4.2 1.8L12 15l-1.8-4.2L6 9l4.2-1.8Z" />
      <path d="m5 16 .9 2.1L8 19l-2.1.9L5 22l-.9-2.1L2 19l2.1-.9Z" />
      <path d="m19 13 .8 1.8L22 16l-2.2 1.2L19 19l-.8-1.8L16 16l2.2-1.2Z" />
    </IconBase>
  );
}

export function CableIcon() {
  return (
    <IconBase>
      <path d="M8 7V5a2 2 0 1 1 4 0v2" />
      <path d="M12 7h4a2 2 0 0 1 2 2v3a4 4 0 0 1-4 4h-2v3" />
      <path d="M6 11h4" />
      <path d="M16 7V5a2 2 0 1 1 4 0v2" />
    </IconBase>
  );
}

export function BlocksIcon() {
  return (
    <IconBase>
      <rect x="3" y="3" width="8" height="8" rx="2" />
      <rect x="13" y="3" width="8" height="8" rx="2" />
      <rect x="8" y="13" width="8" height="8" rx="2" />
    </IconBase>
  );
}

export function SearchIcon() {
  return (
    <IconBase>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4 4" />
    </IconBase>
  );
}

export function PlusIcon() {
  return (
    <IconBase>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </IconBase>
  );
}

export function CheckCircleIcon() {
  return (
    <IconBase>
      <circle cx="12" cy="12" r="9" />
      <path d="m8.8 12.2 2.1 2.1 4.4-4.5" />
    </IconBase>
  );
}

export function XIcon() {
  return (
    <IconBase>
      <path d="m6 6 12 12" />
      <path d="m18 6-12 12" />
    </IconBase>
  );
}

export function ChevronRightIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <path d="m9 6 6 6-6 6" />
    </IconBase>
  );
}

export function ArrowLeftIcon() {
  return (
    <IconBase>
      <path d="m15 18-6-6 6-6" />
      <path d="M9 12h10" />
    </IconBase>
  );
}

export function DetailDocument({
  title,
  summary,
  meta,
  children,
}: {
  title: string;
  summary: string;
  meta?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="capabilities-detail-document">
      <div className="capabilities-detail-document-toolbar">
        <div className="capabilities-detail-document-title">
          <strong>{title}</strong>
          <span>{summary}</span>
        </div>
        {meta ? (
          <div className="capabilities-detail-document-meta">{meta}</div>
        ) : null}
      </div>
      <div className="capabilities-detail-document-body">{children}</div>
    </section>
  );
}

export function MenuButton({
  active,
  icon,
  label,
  onClick,
}: {
  active: boolean;
  icon: ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`capabilities-nav-button ${active ? "is-active" : ""}`}
      onClick={onClick}
    >
      <span className="capabilities-nav-icon">{icon}</span>
      <span className="capabilities-nav-label">{label}</span>
    </button>
  );
}
