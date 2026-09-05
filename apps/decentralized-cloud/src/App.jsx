import { useCallback, useEffect, useRef, useState } from "react";
import { SURFACES, DEFAULT_SURFACE, surfaceFromHash, hashForSurface } from "./logic/surfaces.mjs";
import { forget } from "./logic/read.mjs";
import { capabilitySentences } from "./logic/capability.mjs";
import Lockup from "./components/Lockup.jsx";
import Candidates from "./surfaces/Candidates.jsx";
import Sources from "./surfaces/Sources.jsx";
import Placement from "./surfaces/Placement.jsx";
import Job from "./surfaces/Job.jsx";
import Redundancy from "./surfaces/Redundancy.jsx";
import Receipts from "./surfaces/Receipts.jsx";
import Api from "./surfaces/Api.jsx";

const CAPABILITY = capabilitySentences();

const VIEWS = {
  candidates: Candidates,
  sources: Sources,
  placement: Placement,
  job: Job,
  redundancy: Redundancy,
  receipts: Receipts,
  api: Api,
};

export default function App() {
  const [surface, setSurface] = useState(() =>
    typeof location === "undefined" ? DEFAULT_SURFACE : surfaceFromHash(location.hash)
  );
  const [announcement, setAnnouncement] = useState("");
  const mainRef = useRef(null);

  // Back and Forward move between surfaces rather than out of the app. `hashchange`
  // fires for both, and for someone pasting a link into an already-open tab. Without
  // this the page had one address for seven views: Back left the app entirely, and a
  // reload always landed on Candidates, re-paying a read measured at up to 60 seconds
  // to get back where you were.
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

  const View = VIEWS[surface] || VIEWS[DEFAULT_SURFACE];
  const meta = SURFACES.find((s) => s.id === surface);

  return (
    <>
      {/* The first seven tab stops on every surface are the nav, so a keyboard reader
          walks them again on each one. */}
      <a className="skip" href="#surface">Skip to the surface</a>

      <header className="topbar">
        <div className="topbar-left">
          <Lockup />
          <nav className="nav" aria-label="Surfaces">
            {SURFACES.map((s) => (
              <button
                key={s.id}
                type="button"
                data-surface={s.id}
                {...(s.id === surface ? { "aria-current": "page" } : {})}
                onClick={() => go(s.id)}
              >
                {s.label}
              </button>
            ))}
          </nav>
        </div>
        <div className="topbar-status">
          <span className="meta" id="daemon-label">
            daemon {typeof location === "undefined" ? "—" : location.host}
          </span>
          {/* This chip said "read-only surface" until the job door was wired, and for
              one build after it — a false claim standing in the header of the one page
              whose entire subject is not making false claims. The screenshot caught it.
              Then it said "two writes, neither spends", hand-counted, which is the same
              defect with a longer fuse: correct today, and maintained by nobody. It is
              now GENERATED from the route table the proxy dispatches from, so adding a
              write changes the header in the same edit. */}
          <span className="chip muted" id="refresh-chip">
            <span className="dot" />{CAPABILITY.chip}
          </span>
        </div>
      </header>

      {/* Announce WHAT CHANGED, not the document. `aria-live` used to sit on <main>,
          so every surface swap re-announced the whole page — and on Placement that was
          13.66 MB of text before that surface was rewritten. Shrinking Placement
          removed the magnitude but not the fault: a live region that reads the
          document is a live region nobody leaves switched on. */}
      <p id="surface-status" className="sr-only" role="status" aria-live="polite">
        {announcement}
      </p>

      {/* `tabIndex={-1}` because the skip link above is inert without it: a browser
          will not move focus to an element that cannot receive it, so pressing Enter
          on the link left activeElement on BODY and the reader walked the same seven
          nav stops again. A review found the mitigation broken while the comment
          explaining why it existed sat directly above it. */}
      <main id="surface" tabIndex={-1} ref={mainRef}>
        <View key={surface} announce={setAnnouncement} wired={meta?.wired !== false} />
      </main>
    </>
  );
}
