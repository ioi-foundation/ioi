import { useEffect, useId, useRef, useState } from "react";

import type {
  HypervisorAgentSelectorOption,
  HypervisorModelOption,
} from "../harnessAdapterModel";

interface CompositorSelectOption {
  ref: string;
  /** Stable id surfaced as a data attribute for tests/automation. */
  key: string;
  label: string;
  sublabel: string;
  description: string;
}

interface CompositorSelectProps {
  heading: string;
  options: readonly CompositorSelectOption[];
  selectedRef: string;
  onSelect: (ref: string) => void;
  align?: "left" | "right";
  surface?: string;
  kind?: string;
  disabled?: boolean;
}

function AgentGlyphIcon() {
  return (
    <svg
      className="hypervisor-agent-selector__glyph"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M22.282 9.821a5.985 5.985 0 0 0-.516-4.911 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.182a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.096 5.98 5.98 0 0 0 .511 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.989 5.989 0 0 0 3.998-2.9 6.056 6.056 0 0 0-.748-7.073Zm-9.022 12.608a4.476 4.476 0 0 1-2.877-1.041l.142-.08 4.778-2.758a.795.795 0 0 0 .393-.681v-6.737l2.02 1.169a.071.071 0 0 1 .038.052v5.582a4.504 4.504 0 0 1-4.494 4.494Zm-9.661-4.125a4.471 4.471 0 0 1-.535-3.014l.142.085 4.783 2.758a.771.771 0 0 0 .781 0l5.843-3.368v2.332a.08.08 0 0 1-.033.062L9.74 19.95a4.499 4.499 0 0 1-6.141-1.646ZM2.341 7.896a4.485 4.485 0 0 1 2.365-1.973V11.6a.766.766 0 0 0 .388.676l5.814 3.355-2.02 1.168a.076.076 0 0 1-.071 0l-4.83-2.786a4.504 4.504 0 0 1-1.646-6.117Zm16.596 3.855-5.833-3.387 2.02-1.164a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105v-5.678a.79.79 0 0 0-.412-.687Zm2.011-3.023-.142-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061l4.83-2.787a4.499 4.499 0 0 1 6.681 4.66ZM8.306 12.863l-2.02-1.164a.08.08 0 0 1-.038-.057V6.074a4.499 4.499 0 0 1 7.376-3.453l-.142.08-4.778 2.758a.795.795 0 0 0-.393.681Zm1.098-2.362 2.603-1.506 2.603 1.506v3.012l-2.603 1.506-2.603-1.506Z"
        fill="currentColor"
      />
    </svg>
  );
}

function ModelGlyphIcon() {
  return (
    <svg
      className="hypervisor-agent-selector__glyph"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 2.5 3 7v10l9 4.5 9-4.5V7l-9-4.5Zm0 2.18L18.2 7.8 12 11.1 5.8 7.8 12 4.68ZM5 9.62l6 3.2v6.36l-6-3V9.62Zm14 0v6.56l-6 3V12.82l6-3.2Z"
        fill="currentColor"
      />
    </svg>
  );
}

function SelectorChevronIcon() {
  return (
    <svg
      className="hypervisor-agent-selector__chevron"
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="m4 6 4 4 4-4"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SelectorCheckIcon() {
  return (
    <svg
      className="hypervisor-agent-selector__check"
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="m3.5 8.5 3 3 6-7"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CompositorSelect({
  heading,
  options,
  selectedRef,
  onSelect,
  align = "right",
  surface = "session",
  kind = "agent",
  disabled = false,
}: CompositorSelectProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const menuId = useId();
  const selected =
    options.find((option) => option.ref === selectedRef) ?? options[0] ?? null;

  useEffect(() => {
    if (!open) {
      return;
    }
    const handlePointer = (event: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(event.target as Node)
      ) {
        setOpen(false);
      }
    };
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handlePointer);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handlePointer);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  if (!selected) {
    return null;
  }

  return (
    <div
      ref={containerRef}
      className="hypervisor-agent-selector"
      data-agent-selector-surface={surface}
      data-agent-selector-kind={kind}
      data-agent-selector-open={open ? "true" : "false"}
      data-agent-selector-selected={selected.ref}
    >
      <button
        type="button"
        className="hypervisor-agent-selector__trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={`${heading}: ${selected.label}`}
        disabled={disabled}
        onClick={() => setOpen((value) => !value)}
      >
        {kind === "model" ? <ModelGlyphIcon /> : <AgentGlyphIcon />}
        <span className="hypervisor-agent-selector__label">{selected.label}</span>
        <SelectorChevronIcon />
      </button>
      {open ? (
        <div
          id={menuId}
          role="listbox"
          aria-label={heading}
          className="hypervisor-agent-selector__menu"
          data-agent-selector-align={align}
        >
          <p className="hypervisor-agent-selector__menu-heading">{heading}</p>
          {options.map((option) => {
            const isSelected = option.ref === selected.ref;
            return (
              <button
                type="button"
                role="option"
                aria-selected={isSelected}
                key={option.ref}
                className="hypervisor-agent-selector__option"
                data-agent-selector-option={option.key}
                data-agent-selector-option-selected={isSelected ? "true" : "false"}
                onClick={() => {
                  onSelect(option.ref);
                  setOpen(false);
                }}
              >
                <span className="hypervisor-agent-selector__option-body">
                  <span className="hypervisor-agent-selector__option-head">
                    <strong>{option.label}</strong>
                    <em>{option.sublabel}</em>
                  </span>
                  <small>{option.description}</small>
                </span>
                {isSelected ? <SelectorCheckIcon /> : null}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

interface AgentModelSelectorProps {
  options: readonly HypervisorAgentSelectorOption[];
  selectedRef: string;
  onSelect: (selectionRef: string) => void;
  align?: "left" | "right";
  surface?: string;
  disabled?: boolean;
}

export function AgentModelSelector({
  options,
  selectedRef,
  onSelect,
  align = "right",
  surface = "session",
  disabled = false,
}: AgentModelSelectorProps) {
  return (
    <CompositorSelect
      heading="Agent harness"
      kind="agent"
      align={align}
      surface={surface}
      disabled={disabled}
      selectedRef={selectedRef}
      onSelect={onSelect}
      options={options.map((option) => ({
        ref: option.selection_ref,
        key: option.adapter_id,
        label: option.label,
        sublabel: option.model_label,
        description: option.description,
      }))}
    />
  );
}

interface ModelRouteSelectorProps {
  options: readonly HypervisorModelOption[];
  selectedRef: string;
  onSelect: (modelRef: string) => void;
  align?: "left" | "right";
  surface?: string;
  disabled?: boolean;
}

export function ModelRouteSelector({
  options,
  selectedRef,
  onSelect,
  align = "right",
  surface = "session",
  disabled = false,
}: ModelRouteSelectorProps) {
  return (
    <CompositorSelect
      heading="Model"
      kind="model"
      align={align}
      surface={surface}
      disabled={disabled}
      selectedRef={selectedRef}
      onSelect={onSelect}
      options={options.map((option) => ({
        ref: option.model_ref,
        key: option.model_name,
        label: option.label,
        sublabel: option.detail,
        description: `${option.label} on ${option.model_route_ref.replace(
          /^model-route:/,
          "",
        )}`,
      }))}
    />
  );
}
