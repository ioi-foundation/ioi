// Client-side behavior for verbatim reference routes.
//
// The captured DOM is static (the reference's own JS is stripped). We attach behavior
// imperatively via event delegation on the route container — one listener, matched by
// the reference's own selectors (href / aria / data-testid). This is the "wire it up"
// half of the verbatim approach; it reuses the reference's markup contracts so it stays
// robust to layout changes.
//
// Shared shell behavior (nav, accordions, sidebar collapse) lives here so every route
// gets it for free; route-specific behavior composes on top.

export interface WireShellOptions {
  /** SPA navigate (react-router). */
  navigate: (to: string) => void;
  /** Map a captured href to an app route. Return null to ignore (leave default). */
  mapHref?: (href: string) => string | null;
}

// Toggle a session-group / collapsible accordion the way Radix Collapsible does:
// flip aria-expanded + data-state on the trigger and its sibling content region, and
// show/hide the content. The reference keeps the content in the DOM (data-state=closed),
// so we only need to flip state + the `hidden` attribute.
function toggleAccordion(trigger: HTMLElement) {
  const expanded = trigger.getAttribute("aria-expanded") === "true";
  const next = !expanded;
  trigger.setAttribute("aria-expanded", String(next));
  // The collapsible root is the nearest ancestor carrying data-state; its content is the
  // last child region (data-state sibling). Flip both, plus the chevron rotation class.
  const container = trigger.closest<HTMLElement>('[data-state]') || trigger.parentElement;
  const setState = (el: Element | null) => el?.setAttribute("data-state", next ? "open" : "closed");
  setState(container);
  if (container) {
    container.querySelectorAll(':scope > [data-state]').forEach((el) => {
      el.setAttribute("data-state", next ? "open" : "closed");
      if (next) el.removeAttribute("hidden");
      else el.setAttribute("hidden", "");
    });
  }
  // Chevron: the reference rotates a glyph wrapper via rotate-90 when open.
  const chevron = trigger.querySelector<HTMLElement>(".rotate-0, .rotate-90");
  if (chevron) {
    chevron.classList.toggle("rotate-90", next);
    chevron.classList.toggle("rotate-0", !next);
  }
}

export function wireReferenceShell(root: HTMLElement, opts: WireShellOptions): () => void {
  const onClick = (e: MouseEvent) => {
    const target = e.target as HTMLElement;

    // 1) SPA navigation: intercept internal anchors.
    const anchor = target.closest<HTMLAnchorElement>("a[href]");
    if (anchor) {
      const href = anchor.getAttribute("href") || "";
      const internal = href.startsWith("/") && !href.startsWith("//");
      if (internal) {
        const to = opts.mapHref ? opts.mapHref(href) : href;
        if (to) {
          e.preventDefault();
          opts.navigate(to);
          return;
        }
      }
    }

    // 2) Session-group / collapsible accordions.
    const groupBtn = target.closest<HTMLElement>('button[aria-expanded][aria-label*="Group"], button[aria-expanded][data-testid*="accordion"]');
    if (groupBtn) {
      e.preventDefault();
      toggleAccordion(groupBtn);
      return;
    }
  };
  root.addEventListener("click", onClick);
  return () => root.removeEventListener("click", onClick);
}
