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
// do. I once set job and receipts to true from the daemon's capabilities rather than
// from my own code — the daemon's routes were green while this surface called none of
// them — which is the same dishonesty this page exists to refuse, one level up.
//
// They are true NOW because the door exists and the gate proves it against the running
// daemon: a job admitted through this surface appears in GET /v1/hypervisor/cloud-jobs,
// and its refusals and receipts are rendered from the daemon's own bodies.
//
// REDUNDANCY STAYS FALSE. The daemon accepts only the `none` posture and refuses the
// other two by name — replica placement, a per-replica exposure set and a switch
// policy are not built yet. A posture surface that could not set a posture would
// be wired in name only.
// (No milestone identifier here. This module is BUNDLED AND SERVED, comments included,
// and the gate's absence check reads served bytes — it caught this line. The identifier
// belongs in the programme's records, not in a stranger's browser.)
export const SURFACES = [
  // The landing. Every resource class the router can be asked for, by category, and
  // every venue that can supply it, with its state read from the daemon on every
  // render — the decentralized counterpart of a console's "all services" page. It is
  // wired: it reads candidate-sources and the latest candidates batch.
  { id: "catalog", label: "All resources", wired: true },
  { id: "candidates", label: "Candidates", wired: true },
  { id: "sources", label: "Sources", wired: true },
  { id: "placement", label: "Placement", wired: true },
  { id: "job", label: "Submit a job", wired: true },
  { id: "redundancy", label: "Redundancy", wired: false },
  { id: "receipts", label: "Receipts", wired: true },
  { id: "api", label: "API", wired: true },
];

export const SURFACE_IDS = SURFACES.map((s) => s.id);
export const DEFAULT_SURFACE = "catalog";

export const isSurface = (name) => SURFACE_IDS.includes(name);

export const surfaceFromHash = (hash) => {
  const name = String(hash || "").replace(/^#\/?/, "");
  return isSurface(name) ? name : DEFAULT_SURFACE;
};

export const hashForSurface = (name) => `#/${isSurface(name) ? name : DEFAULT_SURFACE}`;
