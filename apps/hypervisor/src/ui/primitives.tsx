// Hypervisor UX kit — Layer 2 primitives. Thin typed wrappers over kit.css classes. Token-pure:
// no hex, no raw colors; all styling resolves to var(--…) via kit.css.
import { useEffect, useRef, useState } from "react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { IconChevronDown } from "./icons";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const cx = (...c: Array<string | false | undefined>) => c.filter(Boolean).join(" ");

// layout
export const Row = ({ children, wrap, className }: { children: ReactNode; wrap?: boolean; className?: string }) => (
  <div className={cx("hv-row", wrap && "hv-wrap", className)}>{children}</div>
);
export const Col = ({ children, className }: { children: ReactNode; className?: string }) => <div className={cx("hv-col", className)}>{children}</div>;
export const Spacer = () => <span className="hv-spacer" />;

// typography
export const Heading = ({ level = 1, children }: { level?: 1 | 2; children: ReactNode }) =>
  level === 1 ? <h1 className="hv-h1">{children}</h1> : <h2 className="hv-h2">{children}</h2>;
export const Muted = ({ children }: { children: ReactNode }) => <span className="hv-muted">{children}</span>;
export const Tertiary = ({ children }: { children: ReactNode }) => <span className="hv-tertiary">{children}</span>;
export const Mono = ({ children }: { children: ReactNode }) => <span className="hv-mono">{children}</span>;

// button
export function Button({ variant = "default", size, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "primary" | "ghost" | "danger"; size?: "sm" }) {
  return <button {...rest} className={cx("hv-btn", variant !== "default" && `hv-btn--${variant}`, size === "sm" && "hv-btn--sm", rest.className)} />;
}

// containers
export const Card = ({ children, className, testId }: { children: ReactNode; className?: string; testId?: string }) => <div className={cx("hv-card", className)} data-testid={testId}>{children}</div>;
export const Panel = ({ children, className, testId }: { children: ReactNode; className?: string; testId?: string }) => <div className={cx("hv-panel", className)} data-testid={testId}>{children}</div>;
export const Toolbar = ({ children }: { children: ReactNode }) => <div className="hv-toolbar">{children}</div>;

// badge / status
export const Badge = ({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) => <span className={cx("hv-badge", `hv-badge--${tone}`)}>{children}</span>;
export const StatusDot = ({ tone = "neutral" }: { tone?: Tone }) => <span className={cx("hv-dot", `hv-dot--${tone}`)} />;

// field / input
export const Field = ({ label, hint, children }: { label?: string; hint?: string; children: ReactNode }) => (
  <label className="hv-field">
    {label && <span className="hv-field__label">{label}</span>}
    {children}
    {hint && <span className="hv-field__hint">{hint}</span>}
  </label>
);
export const TextInput = (p: InputHTMLAttributes<HTMLInputElement>) => <input {...p} className={cx("hv-input", p.className)} />;
export const TextArea = (p: InputHTMLAttributes<HTMLTextAreaElement>) => <textarea {...(p as object)} className={cx("hv-textarea", p.className)} />;
export const Select = (p: SelectHTMLAttributes<HTMLSelectElement>) => <select {...p} className={cx("hv-select", p.className)} />;

// dropdown — a real selector with a popover menu (click-outside to close).
export function Dropdown({ label, value, options, onChange, icon, testId }: {
  label?: string; value: string; options: Array<{ value: string; label: string }>; onChange: (v: string) => void; icon?: ReactNode; testId?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const current = options.find((o) => o.value === value);
  return (
    <div className="hv-menu" ref={ref}>
      <button className="hv-selector" type="button" onClick={() => setOpen((o) => !o)} data-testid={testId}>
        {icon}
        {label && <span className="hv-tertiary">{label}</span>}
        <span className="hv-selector__value">{current?.label ?? value}</span>
        <IconChevronDown size={13} />
      </button>
      {open && (
        <div className="hv-menu__pop" role="listbox">
          {options.length === 0 && <span className="hv-menu__empty">No options</span>}
          {options.map((o) => (
            <button key={o.value} type="button" className={cx("hv-menu__item", o.value === value && "hv-menu__item--active")} onClick={() => { onChange(o.value); setOpen(false); }}>
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// modal
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="hv-modal__scrim" onClick={onClose}>
      <div className="hv-modal" onClick={(e) => e.stopPropagation()}>
        <div className="hv-modal__head">
          <Heading level={2}>{title}</Heading>
          <Spacer />
          <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
        </div>
        <div className="hv-modal__body">{children}</div>
      </div>
    </div>
  );
}
