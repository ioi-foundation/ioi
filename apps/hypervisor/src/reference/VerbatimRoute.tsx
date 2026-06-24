// The live verbatim route: resolves the current path to a captured reference DOM,
// renders it under the reference theme scope, and attaches shell behavior (SPA nav,
// accordions). Overlay islands (menus/dialogs) compose on top in a later pass.
import { useCallback, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ReferenceRoute } from "./ReferenceRoute";
import { ReferenceOverlays } from "./overlays";
import { resolveCapture, hasCapture } from "./captures";
import { wireReferenceShell } from "./wiring";
import { useReferenceTheme } from "../surfaces/Home/HypervisorReferenceShell";
import { HypervisorReferenceNotFound } from "../surfaces/NotFound/HypervisorReferenceNotFound";

export function VerbatimRoute() {
  useReferenceTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const html = resolveCapture(location.pathname);
  const [root, setRoot] = useState<HTMLDivElement | null>(null);
  const onMount = useCallback(
    (el: HTMLDivElement) => {
      setRoot(el);
      const cleanup = wireReferenceShell(el, {
        navigate,
        // Intercept every internal link we can render; leave the rest to the browser.
        mapHref: (href) => (hasCapture(href) ? href : null),
      });
      return () => {
        setRoot(null);
        cleanup();
      };
    },
    [navigate],
  );
  if (!html) return <HypervisorReferenceNotFound />;
  // key on the path so a route change cleanly re-injects the DOM and re-wires.
  return (
    <>
      <ReferenceRoute key={location.pathname} html={html} onMount={onMount} />
      {root && <ReferenceOverlays root={root} />}
    </>
  );
}
