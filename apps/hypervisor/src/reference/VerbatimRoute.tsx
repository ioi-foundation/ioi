// The live verbatim app. Renders the captured reference DOM and navigates between routes
// by MORPHING the live DOM toward the target capture (see morph.ts) rather than
// remounting — so the sidebar and persistent chrome keep their identity across navigation
// (no flash), exactly like the reference SPA. Shell behavior (SPA nav, accordions) and
// overlay islands (menus/dialogs) are attached once to the persistent root.
import { useLayoutEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ReferenceOverlays } from "./overlays";
import { resolveCapture, hasCapture } from "./captures";
import { wireReferenceShell } from "./wiring";
import { morphInto } from "./morph";
import { useReferenceTheme } from "../surfaces/Home/HypervisorReferenceShell";

export function VerbatimRoute() {
  useReferenceTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const rootRef = useRef<HTMLDivElement>(null);
  const [root, setRoot] = useState<HTMLDivElement | null>(null);
  const navRef = useRef(navigate);
  navRef.current = navigate;

  // Mount the root once, inject the first capture, and wire shell behavior. The root
  // persists for the app's lifetime; navigation morphs its contents.
  useLayoutEffect(() => {
    const el = rootRef.current;
    if (!el) return;
    const html = resolveCapture(location.pathname);
    el.innerHTML = html ?? NOT_FOUND_HTML;
    setRoot(el);
    const cleanup = wireReferenceShell(el, {
      navigate: (to) => navRef.current(to),
      mapHref: (href) => (hasCapture(href) ? href : null),
    });
    return cleanup;
    // Mount only — route changes are handled by the morph effect below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // On route change, morph the live DOM toward the new capture (persistent shell).
  const firstRender = useRef(true);
  useLayoutEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    const el = rootRef.current;
    if (!el) return;
    const html = resolveCapture(location.pathname);
    morphInto(el, html ?? NOT_FOUND_HTML);
    el.scrollTop = 0;
  }, [location.pathname]);

  return (
    <>
      <div ref={rootRef} className="size-full" />
      {root && <ReferenceOverlays root={root} routeKey={location.pathname} />}
    </>
  );
}

// Reference-style not-found body for routes without a capture (kept minimal; the common
// routes all resolve).
const NOT_FOUND_HTML = `
<div class="app-background flex size-full flex-col items-center justify-center gap-2 text-content-primary">
  <div class="text-2xl font-medium">Page not found</div>
  <a href="/" class="text-content-link">Back to Home</a>
</div>`;
