// Overlay islands for verbatim routes.
//
// The captured DOM contains menu/dialog *triggers* but not their open content (the
// reference renders those in Radix portals only when open). We reuse the hand-ported
// menu/dialog components as React islands: a delegated listener on the route root detects
// a trigger click and opens the matching component — menus in an AnchoredPopover anchored
// to the trigger, dialogs in a centered ReferenceModal. This preserves the JSX overlay
// work while the static chrome comes from the verbatim capture.
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { AnchoredPopover, ReferenceModal } from "../surfaces/parityOverlays";
import { OrgSwitcherMenu, SessionsFilterMenu } from "../surfaces/Home/HypervisorReferenceSidebarMenus";
import { AgentModeMenu, WorkInProjectMenu, AddToPromptMenu } from "../surfaces/Home/HypervisorReferenceHomeMenus";
import { ProjectActionsMenu, NewProjectDialog, ShareProjectDialog, CreateEnvironmentDialog } from "../surfaces/Projects/HypervisorReferenceProjectDialogs";

interface OverlaySpec {
  /** Match a trigger element (button/anchor) to this overlay. */
  match: (el: HTMLElement) => boolean;
  render: () => ReactNode;
  kind?: "menu" | "modal";
  side?: "top" | "bottom";
  align?: "start" | "end";
  maxWidth?: string;
}

const label = (el: HTMLElement) => el.getAttribute("aria-label") || "";
const testid = (el: HTMLElement) => el.getAttribute("data-testid") || "";
const text = (el: HTMLElement) => (el.textContent || "").trim();

// Shared shell + per-route overlays. Triggers only exist on the routes that render them,
// so a single registry is safe across routes.
const OVERLAYS: OverlaySpec[] = [
  // --- shell / sidebar ---
  { match: (el) => label(el).startsWith("Switch organization"), render: () => <OrgSwitcherMenu />, side: "top", align: "start" },
  { match: (el) => label(el) === "Filter sessions", render: () => <SessionsFilterMenu />, side: "bottom", align: "end" },
  // --- home composer ---
  { match: (el) => label(el) === "Change agent mode", render: () => <AgentModeMenu />, side: "top", align: "end" },
  { match: (el) => label(el) === "Add to prompt", render: () => <AddToPromptMenu />, side: "top", align: "start" },
  { match: (el) => text(el).startsWith("Work in a project"), render: () => <WorkInProjectMenu />, side: "top", align: "start" },
  // --- projects / project-detail ---
  { match: (el) => testid(el).startsWith("project-actions-dropdown-trigger") || label(el) === "More actions", render: () => <ProjectActionsMenu />, side: "bottom", align: "end" },
  { match: (el) => text(el).startsWith("New project"), render: () => <NewProjectDialog />, kind: "modal", maxWidth: "640px" },
  { match: (el) => testid(el) === "share-project-button", render: () => <ShareProjectDialog />, kind: "modal" },
  { match: (el) => testid(el).startsWith("create-environment-from-project-button"), render: () => <CreateEnvironmentDialog />, kind: "modal", maxWidth: "520px" },
];

export function ReferenceOverlays({ root, routeKey }: { root: HTMLElement; routeKey?: string }) {
  const [open, setOpen] = useState<{ spec: OverlaySpec; anchor: HTMLElement } | null>(null);

  // Close any open overlay when the route changes (the anchor may be morphed away).
  useEffect(() => {
    setOpen(null);
  }, [routeKey]);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      const trigger = (e.target as HTMLElement).closest<HTMLElement>('button, [role="button"], a');
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
  const close = () => setOpen(null);
  if (spec.kind === "modal") {
    return (
      <ReferenceModal open onClose={close} maxWidth={spec.maxWidth}>
        {spec.render()}
      </ReferenceModal>
    );
  }
  return (
    <AnchoredPopover open anchorRef={{ current: anchor }} side={spec.side} align={spec.align} onClose={close}>
      {spec.render()}
    </AnchoredPopover>
  );
}
