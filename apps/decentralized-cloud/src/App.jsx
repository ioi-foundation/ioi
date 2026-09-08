import { useCallback, useEffect, useRef, useState } from "react";
import { SURFACES, DEFAULT_SURFACE, surfaceFromHash, hashForSurface, catalogCategoryFromHash, unknownFromHash, jobIdFromHash } from "./logic/surfaces.mjs";
import NotFound from "./surfaces/NotFound.jsx";
import { forget } from "./logic/read.mjs";
import { capabilitySentences } from "./logic/capability.mjs";
import Topbar from "./components/Topbar.jsx";
import Rail from "./components/Rail.jsx";
import Footbar from "./components/Footbar.jsx";
import DaemonBanner from "./components/DaemonBanner.jsx";
import { IconMenu, IconInfo } from "./components/Icons.jsx";
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
import Home from "./surfaces/Home.jsx";
import Storage from "./surfaces/Storage.jsx";
import Network from "./surfaces/Network.jsx";
import { recordVisit } from "./logic/visited.mjs";

const CAPABILITY = capabilitySentences();

const VIEWS = {
  home: Home,
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
  storage: Storage,
  network: Network,
};

// The navigation panel is open by default where there is room for it and closed on
// a phone; the hamburger in the bar under the top bar toggles it at every width.
const PHONE = 700;
const startOpen = () => (typeof window === "undefined" ? true : window.innerWidth > PHONE);

// THE CONSOLE SHELL: a top bar, a thin bar under it with the hamburger and the info
// door, the navigation panel down the left, the surface, and a foot bar.
//
// The shape is the one a stranger from another cloud console already knows, and the
// substance is this daemon's: every entry in the panel is a surface that reads the
// daemon or says on its own page that it does not. Between the bars and the surface
// sits the one fact every read shares: whether the daemon answered the last one. It
// is drawn once, by the shell, when it did not.
export default function App() {
  const [surface, setSurface] = useState(() =>
    typeof location === "undefined" ? DEFAULT_SURFACE : surfaceFromHash(location.hash)
  );
  const [announcement, setAnnouncement] = useState("");
  const [category, setCategory] = useState(() =>
    typeof location === "undefined" ? null : catalogCategoryFromHash(location.hash)
  );
  const [missing, setMissing] = useState(() =>
    typeof location === "undefined" ? null : unknownFromHash(location.hash)
  );
  const [jobId, setJobId] = useState(() =>
    typeof location === "undefined" ? null : jobIdFromHash(location.hash)
  );
  const [railOpen, setRailOpen] = useState(startOpen);
  const mainRef = useRef(null);

  useEffect(() => {
    const onHash = () => {
      setSurface(surfaceFromHash(location.hash));
      setCategory(catalogCategoryFromHash(location.hash));
      setMissing(unknownFromHash(location.hash));
      setJobId(jobIdFromHash(location.hash));
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Leaving Candidates drops its stale-paint handle: a batch rendered before the
  // reader navigated away must not reappear under a later refresh as though it had
  // just been read.
  const go = useCallback((name) => {
    if (name !== "candidates") forget("candidates:paint");
    if (location.hash !== hashForSurface(name)) location.hash = hashForSurface(name);
    setSurface(name);
    setCategory(null);
    setMissing(null);
    setJobId(null);
    // On a phone, choosing a surface closes the panel it was chosen from.
    if (typeof window !== "undefined" && window.innerWidth <= PHONE) setRailOpen(false);
  }, []);

  useEffect(() => { recordVisit(surface); }, [surface]);

  const View = VIEWS[surface] || VIEWS[DEFAULT_SURFACE];
  const meta = SURFACES.find((s) => s.id === surface);
  const host = typeof location === "undefined" ? "—" : location.host;

  return (
    <>
      <a className="skip" href="#surface">Skip to the surface</a>

      <div className={`console${railOpen ? "" : " rail-closed"}`}>
        <Topbar go={go} announce={setAnnouncement} surface={surface} />

        {/* The thin bar under the top bar: the hamburger that opens and closes the
            navigation panel, and the info door on the right (the API surface, which
            says exactly what this console may ask). */}
        <div className="subbar">
          <button
            type="button"
            id="rail-toggle"
            className="bar-btn subbar-btn"
            aria-label={railOpen ? "Close the navigation panel" : "Open the navigation panel"}
            aria-expanded={railOpen}
            aria-controls="console-rail"
            onClick={() => setRailOpen((v) => !v)}
          >
            <IconMenu />
            <span className="subbar-current">{meta?.label || "Home"}</span>
          </button>
          <a className="bar-btn subbar-btn" href={hashForSurface("api")} aria-label="About this console — what it may ask the daemon" title="Info"><IconInfo /></a>
        </div>

        <Rail surface={surface} go={go} category={category} open={railOpen} />

        <p id="surface-status" className="sr-only" role="status" aria-live="polite">
          {announcement}
        </p>

        {/* THE SHEET. On the grey canvas a surface's tables and panels sit on one white
            sheet, the way a console's resource pages do; Home is a grid of widgets and
            the catalogue opens on its full-bleed hero, so neither takes it. */}
        <main id="surface" tabIndex={-1} ref={mainRef}>
          <DaemonBanner host={host} />
          <div className={missing || !["home", "catalog"].includes(surface) ? "sheet" : "sheet-none"}>
            {missing
              ? <NotFound address={missing} announce={setAnnouncement} />
              : <View key={surface} announce={setAnnouncement} wired={meta?.wired !== false} category={category} jobId={jobId} />}
          </div>
        </main>

        <Footbar daemonHost={host} capabilityChip={CAPABILITY.chip} />
      </div>
    </>
  );
}
