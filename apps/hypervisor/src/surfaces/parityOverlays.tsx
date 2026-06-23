// Shared overlay primitives for parity surfaces (no Radix dependency).
// - ReferenceModal: a centered modal with a dimmed backdrop, for the reference's
//   dialog content (which is `position: relative`, so we center it ourselves).
// - AnchoredPopover: a dropdown positioned from its trigger's rect, portaled to body
//   so the surface's overflow never clips it.
// Both dismiss on Escape and on backdrop / outside click.
import { useEffect, useLayoutEffect, useState } from "react";
import type { CSSProperties, ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";

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
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" role="presentation">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden="true" />
      <div className="relative z-10 flex max-h-full w-full justify-center" style={{ maxWidth }}>
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
  const [rect, setRect] = useState<DOMRect | null>(null);
  useLayoutEffect(() => {
    setRect(open && anchorRef.current ? anchorRef.current.getBoundingClientRect() : null);
  }, [open, anchorRef]);
  useEscapeToClose(open, onClose);
  if (!open || !rect) return null;
  const gap = 4;
  const style: CSSProperties = {
    position: "fixed",
    zIndex: 100,
    ...(align === "end" ? { right: window.innerWidth - rect.right } : { left: rect.left }),
    ...(side === "top" ? { bottom: window.innerHeight - rect.top + gap } : { top: rect.bottom + gap }),
  };
  return createPortal(
    <>
      <div className="fixed inset-0 z-[99]" onClick={onClose} aria-hidden="true" />
      <div style={style}>{children}</div>
    </>,
    document.body,
  );
}
