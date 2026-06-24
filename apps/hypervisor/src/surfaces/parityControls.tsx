// Shared interactive controls for parity surfaces. ToggleSwitch is a controlled
// switch that reproduces the reference's role="switch" button + sliding knob; the
// owner holds the checked state so adjacent labels can react to it.
import type { ReactNode } from "react";

const ToggleKnob = () => (
  <svg width="25" height="25" viewBox="0 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg" className="size-5">
    <circle cx="12.5" cy="12.5" r="10" className="fill-[rgb(var(--ona-white))]" />
  </svg>
);

export function ToggleSwitch({
  checked,
  onChange,
  ariaLabel,
  testid,
  trackingId,
  id,
  value,
  className,
  knobClassName,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  ariaLabel?: string;
  testid?: string;
  trackingId?: string;
  id?: string;
  value?: string;
  className: string;
  knobClassName: string;
}): ReactNode {
  const state = checked ? "checked" : "unchecked";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      data-state={state}
      aria-label={ariaLabel}
      id={id}
      value={value}
      data-testid={testid}
      data-tracking-id={trackingId}
      className={className}
      onClick={(e) => {
        // The switch may live inside a card <a> link (e.g. the project home prebuilds
        // card); don't let the toggle trigger that navigation.
        e.preventDefault();
        e.stopPropagation();
        onChange(!checked);
      }}
    >
      <span data-state={state} className={knobClassName}>
        <ToggleKnob />
      </span>
    </button>
  );
}
