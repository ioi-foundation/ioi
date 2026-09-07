import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SURFACES, DEFAULT_SURFACE, surfaceFromHash, hashForSurface, searchSurfaces } from "./logic/surfaces.mjs";
import { forget } from "./logic/read.mjs";
import { capabilitySentences } from "./logic/capability.mjs";
import Topbar from "./components/Topbar.jsx";
import Rail from "./components/Rail.jsx";
import Catalog from "./surfaces/Catalog.jsx";
import Candidates from "./surfaces/Candidates.jsx";
import Sources from "./surfaces/Sources.jsx";
import Placement from "./surfaces/Placement.jsx";
import Job from "./surfaces/Job.jsx";
import Redundancy from "./surfaces/Redundancy.jsx";
import Receipts from "./surfaces/Receipts.jsx";
import Api from "./surfaces/Api.jsx";
import Spend from "./surfaces/Spend.jsx";
import Iam from "./surfaces/Iam.jsx";
import Supply from "./surfaces/Supply.jsx";
import Settings from "./surfaces/Settings.jsx";

const CAPABILITY = capabilitySentences();

const VIEWS = {
  catalog: Catalog,
  candidates: Candidates,
  sources: Sources,
  placement: Placement,
  job: Job,
  redundancy: Redundancy,
  receipts: Receipts,
  api: Api,
  spend: Spend,
  iam: Iam,
  supply: Supply,
  settings: Settings,
};

// THE CONSOLE SHELL: a top bar, a product rail down the left, and the surface.
//
// The shape is the one a stranger from another cloud console already knows — the
// rail is where the products are, the top bar is where search, the principal and the
// placement posture are — and the substance is this daemon's: every entry in the rail
// is a surface that reads the daemon or says on its own page that it does not.
export default function App() {
  const [surface, setSurface] = useState(() =>
    typeof location === "undefined" ? DEFAULT_SURFACE : surfaceFromHash(location.hash)
  );
  const [announcement, setAnnouncement] = useState("");
  const [query, setQuery] = useState("");
  const mainRef = useRef(null);

  // Back and Forward move between surfaces rather than out of the app. `hashchange`
  // fires for both, and for someone pasting a link into an already-open tab.
  useEffect(() => {
    const onHash = () => setSurface(surfaceFromHash(location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Leaving Candidates drops its stale-paint handle: a batch rendered before the
  // reader navigated away must not reappear under a later refresh as though it had
  // just been read. Sources keeps its cache deliberately — a revisit there should show
  // the previous answer at once rather than a minute of blank page — and the two are
  // different rules for the same reason, which is that "stale" means different things
  // to a price and to a source's health.
  const go = useCallback((name) => {
    if (name !== "candidates") forget("candidates:paint");
    if (surfaceFromHash(location.hash) !== name) location.hash = hashForSurface(name);
    setSurface(name);
  }, []);

  // The search filters the rail. Every surface matches an empty query, so the rail is
  // whole whenever nothing is typed; a query that matches nothing leaves the rail empty
  // and the scope line says "0 surfaces match" rather than pretending.
  const matches = useMemo(() => new Set(searchSurfaces(query).map((s) => s.id)), [query]);
  const onSearchEnter = useCallback(() => {
    const first = searchSurfaces(query)[0];
    if (!first) return;
    setQuery("");
    go(first.id);
    mainRef.current?.focus();
  }, [query, go]);

  const View = VIEWS[surface] || VIEWS[DEFAULT_SURFACE];
  const meta = SURFACES.find((s) => s.id === surface);

  return (
    <>
      {/* The rail is twelve tab stops on every surface, so a keyboard reader gets a
          way past them. */}
      <a className="skip" href="#surface">Skip to the surface</a>

      <div className="console">
        <Topbar
          query={query}
          setQuery={setQuery}
          onSearchEnter={onSearchEnter}
          matchCount={matches.size}
        />

        <Rail
          surface={surface}
          go={go}
          matches={query.trim() ? matches : null}
          daemonHost={typeof location === "undefined" ? "—" : location.host}
          capabilityChip={CAPABILITY.chip}
        />

        {/* Announce WHAT CHANGED, not the document. `aria-live` used to sit on <main>,
            so every surface swap re-announced the whole page. */}
        <p id="surface-status" className="sr-only" role="status" aria-live="polite">
          {announcement}
        </p>

        {/* `tabIndex={-1}` because the skip link above is inert without it: a browser
            will not move focus to an element that cannot receive it. */}
        <main id="surface" tabIndex={-1} ref={mainRef}>
          <View key={surface} announce={setAnnouncement} wired={meta?.wired !== false} />
        </main>
      </div>
    </>
  );
}
