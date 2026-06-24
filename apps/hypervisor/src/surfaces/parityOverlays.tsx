// Shared overlay primitives for parity surfaces (no Radix dependency).
// - ReferenceModal: a centered modal with a dimmed backdrop, for the reference's
//   dialog content (which is `position: relative`, so we center it ourselves).
// - AnchoredPopover: a dropdown positioned from its trigger's rect, portaled to body
//   so the surface's overflow never clips it.
// - CollapsibleContent: an accordion body that measures itself and feeds the Radix
//   height var so the vendored slideDown/slideUp keyframes can run.
// All dismiss on Escape / outside click and play enter + exit transitions to match
// the reference's Radix lifecycle (instead of mounting / unmounting instantly).
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { CSSProperties, ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";

// Convenience for a single anchored dropdown: open state + a typed trigger ref.
export function useMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  return { open, ref, toggle: () => setOpen((o) => !o), close: () => setOpen(false) };
}

function useEscapeToClose(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
}

// Keep an element mounted for `ms` after `open` flips false, so an exit animation
// can play before unmount. `closing` is true during that exit window. This mirrors
// Radix's Presence: render with data-state="open" on mount, flip to "closed" for the
// exit, then unmount.
export function useExitDelay(open: boolean, ms = 150) {
  const [mounted, setMounted] = useState(open);
  const [closing, setClosing] = useState(false);
  const mountedRef = useRef(open);
  mountedRef.current = mounted;
  useEffect(() => {
    if (open) {
      setMounted(true);
      setClosing(false);
      return;
    }
    if (!mountedRef.current) return;
    setClosing(true);
    const t = window.setTimeout(() => {
      setMounted(false);
      setClosing(false);
    }, ms);
    return () => window.clearTimeout(t);
  }, [open, ms]);
  return { mounted, closing };
}

export function ReferenceModal({
  open,
  onClose,
  children,
  maxWidth = "600px",
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  maxWidth?: string;
}) {
  useEscapeToClose(open, onClose);
  const { mounted, closing } = useExitDelay(open);
  if (!mounted) return null;
  // The backdrop has no captured equivalent, so it owns its enter+exit fade. The
  // captured dialog content carries its own data-[state=open]:animate-in, so we drive
  // only its exit on close (adding enter here would double the zoom/fade).
  const overlayAnim = closing
    ? "animate-out fade-out-0 duration-150"
    : "animate-in fade-in-0 duration-150";
  const contentAnim = closing ? "animate-out fade-out-0 zoom-out-95 duration-150" : "";
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" role="presentation">
      <div className={`absolute inset-0 bg-black/50 ${overlayAnim}`} onClick={onClose} aria-hidden="true" />
      <div className={`relative z-10 flex max-h-full w-full justify-center ${contentAnim}`} style={{ maxWidth }}>
        {children}
      </div>
    </div>,
    document.body,
  );
}

export function AnchoredPopover({
  open,
  onClose,
  anchorRef,
  side = "bottom",
  align = "end",
  children,
}: {
  open: boolean;
  onClose: () => void;
  anchorRef: RefObject<HTMLElement | null>;
  side?: "top" | "bottom";
  align?: "start" | "end";
  children: ReactNode;
}) {
  const { mounted, closing } = useExitDelay(open);
  const [rect, setRect] = useState<DOMRect | null>(null);
  useLayoutEffect(() => {
    if (open && anchorRef.current) setRect(anchorRef.current.getBoundingClientRect());
  }, [open, anchorRef]);
  useEscapeToClose(open, onClose);
  if (!mounted || !rect) return null;
  const gap = 4;
  const style: CSSProperties = {
    position: "fixed",
    zIndex: 100,
    ...(align === "end" ? { right: window.innerWidth - rect.right } : { left: rect.left }),
    ...(side === "top" ? { bottom: window.innerHeight - rect.top + gap } : { top: rect.bottom + gap }),
  };
  // The captured menu carries its own data-[state=open]:animate-in, so enter plays on
  // mount; on close we drive an animate-out on the wrapper before unmounting. The
  // backdrop only intercepts clicks while genuinely open (not during the exit window).
  const exitAnim = closing
    ? `animate-out fade-out-0 zoom-out-95 duration-150 ${side === "top" ? "slide-out-to-bottom-2" : "slide-out-to-top-2"}`
    : "";
  return createPortal(
    <>
      {!closing && <div className="fixed inset-0 z-[99]" onClick={onClose} aria-hidden="true" />}
      <div style={style} data-state={closing ? "closed" : "open"} className={exitAnim}>
        {children}
      </div>
    </>,
    document.body,
  );
}

// Accordion body that animates open/closed using the reference's slideDown/slideUp
// keyframes. Those keyframes read `--radix-collapsible-content-height`, which Radix
// normally sets from a measurement; we measure the content ourselves and set it so
// the height animation actually has a target.
export function CollapsibleContent({
  open,
  children,
  className = "",
}: {
  open: boolean;
  children?: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const { mounted, closing } = useExitDelay(open);
  useLayoutEffect(() => {
    const el = ref.current;
    if (el) el.style.setProperty("--radix-collapsible-content-height", `${el.scrollHeight}px`);
  });
  if (!mounted) return null;
  const state = open && !closing ? "open" : "closed";
  return (
    <div
      ref={ref}
      data-state={state}
      className={`overflow-hidden data-[state=closed]:animate-slideUp data-[state=open]:animate-slideDown ${className}`}
    >
      {children}
    </div>
  );
}
