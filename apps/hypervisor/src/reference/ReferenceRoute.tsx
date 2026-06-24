// Verbatim reference-route renderer.
//
// Renders the captured, brand-transformed reference DOM exactly as harvested from the
// running reference (#root inner HTML, scripts stripped), styled by the CSS already
// vendored in main.tsx. This is the "swap the UX, then wire it" substrate: the markup
// is pixel-perfect by construction (no DOM->JSX conversion), and client-side behavior
// is attached imperatively via a delegation controller passed as `onMount`.
//
// `onMount` receives the live container element after the HTML is injected; return a
// cleanup function to remove listeners. Wiring lives in per-route controller modules so
// this renderer stays dumb.
import { useEffect, useRef } from "react";

export interface ReferenceRouteProps {
  /** Captured #root inner HTML (import `./html/<slug>.html?raw`). */
  html: string;
  /** Class list to apply to the wrapper (the reference's #root carried `size-full`). */
  className?: string;
  /** Attach behavior once the DOM is live; return a cleanup. */
  onMount?: (root: HTMLDivElement) => void | (() => void);
}

export function ReferenceRoute({ html, className = "size-full", onMount }: ReferenceRouteProps) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const root = ref.current;
    if (!root || !onMount) return;
    const cleanup = onMount(root);
    return typeof cleanup === "function" ? cleanup : undefined;
    // Re-run if the captured markup changes (route swap reuses this component).
  }, [html, onMount]);
  return <div ref={ref} className={className} dangerouslySetInnerHTML={{ __html: html }} />;
}
