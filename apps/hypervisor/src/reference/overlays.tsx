// Overlay islands for verbatim routes.
//
// The captured DOM contains menu/dialog *triggers* but not their open content (the
// reference renders those in Radix portals only when open). We reuse the hand-ported
// menu components as React islands: a delegated listener on the route root detects a
// trigger click and opens the matching component in an AnchoredPopover anchored to the
// trigger element. This preserves the JSX overlay work while the static chrome comes
// from the verbatim capture.
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { AnchoredPopover } from "../surfaces/parityOverlays";
import { OrgSwitcherMenu, SessionsFilterMenu } from "../surfaces/Home/HypervisorReferenceSidebarMenus";
import { AgentModeMenu, WorkInProjectMenu, AddToPromptMenu } from "../surfaces/Home/HypervisorReferenceHomeMenus";

interface OverlaySpec {
  /** Match a trigger element (button) to this overlay. */
  match: (el: HTMLElement) => boolean;
  render: () => ReactNode;
  side?: "top" | "bottom";
  align?: "start" | "end";
}

const label = (el: HTMLElement) => el.getAttribute("aria-label") || "";
const text = (el: HTMLElement) => (el.textContent || "").trim();

// Shared shell + home-composer overlays. Triggers only exist on the routes that render
// them, so a single registry is safe across routes.
const OVERLAYS: OverlaySpec[] = [
  { match: (el) => label(el).startsWith("Switch organization"), render: () => <OrgSwitcherMenu />, side: "top", align: "start" },
  { match: (el) => label(el) === "Filter sessions", render: () => <SessionsFilterMenu />, side: "bottom", align: "end" },
  { match: (el) => label(el) === "Change agent mode", render: () => <AgentModeMenu />, side: "top", align: "end" },
  { match: (el) => label(el) === "Add to prompt", render: () => <AddToPromptMenu />, side: "top", align: "start" },
  { match: (el) => text(el).startsWith("Work in a project"), render: () => <WorkInProjectMenu />, side: "top", align: "start" },
];

export function ReferenceOverlays({ root }: { root: HTMLElement }) {
  const [open, setOpen] = useState<{ spec: OverlaySpec; anchor: HTMLElement } | null>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      const trigger = (e.target as HTMLElement).closest<HTMLElement>('button, [role="button"]');
      if (!trigger) return;
      const spec = OVERLAYS.find((s) => s.match(trigger));
      if (!spec) return;
      e.preventDefault();
      e.stopPropagation();
      // Toggle: clicking the open trigger closes it.
      setOpen((cur) => (cur && cur.anchor === trigger ? null : { spec, anchor: trigger }));
    };
    // Capture phase so we win over the verbatim DOM's own (inert) handlers and the
    // shell wiring's bubble-phase listener.
    root.addEventListener("click", onClick, true);
    return () => root.removeEventListener("click", onClick, true);
  }, [root]);

  if (!open) return null;
  const { spec, anchor } = open;
  return (
    <AnchoredPopover open anchorRef={{ current: anchor }} side={spec.side} align={spec.align} onClose={() => setOpen(null)}>
      {spec.render()}
    </AnchoredPopover>
  );
}
