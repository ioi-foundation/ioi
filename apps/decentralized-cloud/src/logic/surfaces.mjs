// THE SURFACE REGISTRY AND THE ROUTE NAMES — one source, framework-free.
//
// Every surface is a URL. Without routing the page had one address for seven views:
// you could not link anyone to Sources, Back left the app entirely rather than
// returning to the previous surface, and a reload always landed on Candidates,
// re-paying a read measured at up to 60 seconds to get back where you were.
//
// The HASH is used rather than pushState because this surface is served as static
// files with no server-side routing: a deep path would 404 on reload, which turns
// "linkable" into "linkable once". The hash always resolves to the same shell.
//
// WIRED says whether the surface reads the daemon. It is not decoration and it is not
// a label a component may override: an unwired surface must say so in its own words,
// on screen, and the face gate asserts that against the SERVED BYTES. A stub a reader
// cannot tell from truth is refused; a labelled stub is a design deliverable.

// `wired` is a claim about THIS BRANCH at THIS COMMIT, not about what the daemon can
// do. The daemon's cloud-job routes exist and are green on m15; this surface has not
// been connected to them yet, so job/receipts stay FALSE until Phase C actually wires
// them and the gate proves it. Marking a surface wired before wiring it is the exact
// dishonesty this page exists to refuse — and I set these three to true from the
// daemon's capabilities rather than from my own code, which is the same error one
// level up.
export const SURFACES = [
  { id: "candidates", label: "Candidates", wired: true },
  { id: "sources", label: "Sources", wired: true },
  { id: "placement", label: "Placement", wired: true },
  { id: "job", label: "Submit a job", wired: false },
  { id: "redundancy", label: "Redundancy", wired: false },
  { id: "receipts", label: "Receipts", wired: false },
  { id: "api", label: "API", wired: true },
];

export const SURFACE_IDS = SURFACES.map((s) => s.id);
export const DEFAULT_SURFACE = "candidates";

export const isSurface = (name) => SURFACE_IDS.includes(name);

export const surfaceFromHash = (hash) => {
  const name = String(hash || "").replace(/^#\/?/, "");
  return isSurface(name) ? name : DEFAULT_SURFACE;
};

export const hashForSurface = (name) => `#/${isSurface(name) ? name : DEFAULT_SURFACE}`;
