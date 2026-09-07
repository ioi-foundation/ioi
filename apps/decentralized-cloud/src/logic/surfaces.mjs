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
//
// GROUP is the console rail's section. The rail is the shape a stranger from another
// console reads first: a product list down the left, in the order they would look for
// things — the catalogue, then obtaining capacity, then running it, then the account
// and the surface itself. The group names are product words, not the estate's.
//
// IAM AND SUPPLY REGISTRY ARE UNWIRED. Each is drawn in full and says so on its own
// surface: no route on the capability table reads a wallet principal's leases or the
// supply registry, and this surface will not invent one. Registering them unwired is
// what puts them in the rail honestly — a console with no IAM entry hides the
// question; one with an IAM entry that reads nothing and says nothing would be lying.
// SPEND reads the daemon's budgets and draws settled spend as a labelled door;
// SETTINGS renders the surface's own configuration route, which never leaves the
// process.
export const SURFACES = [
  // The landing. Every resource class the router can be asked for, by category, and
  // every venue that can supply it, with its state read from the daemon on every
  // render — the decentralized counterpart of a console's "all services" page. It is
  // wired: it reads candidate-sources and the latest candidates batch.
  // The console's welcome page and default surface: quick actions and widgets that
  // read candidate-sources, jobs, budgets and the latest candidates batch.
  { id: "home", label: "Home", group: "console", wired: true },
  { id: "catalog", label: "All resources", group: "console", wired: true },
  { id: "candidates", label: "Candidates", group: "obtain", wired: true },
  { id: "placement", label: "Placement", group: "obtain", wired: true },
  { id: "job", label: "Submit a job", group: "obtain", wired: true },
  { id: "receipts", label: "Receipts", group: "run", wired: true },
  { id: "redundancy", label: "Redundancy", group: "run", wired: false },
  // Spend reads the daemon's budgets; settled spend stays a labelled door on the page.
  { id: "spend", label: "Spend", group: "account", wired: true },
  { id: "sources", label: "Sources & health", group: "account", wired: true },
  { id: "iam", label: "IAM · leases", group: "account", wired: false },
  { id: "supply", label: "Supply registry", group: "account", wired: false },
  { id: "api", label: "API", group: "surface", wired: true },
  { id: "settings", label: "Settings", group: "surface", wired: true },
];

// The rail's sections, in rail order, with the words a reader sees. A group named
// here and carried by no surface is not drawn.
export const GROUPS = [
  { id: "console", label: "" },
  { id: "obtain", label: "Obtain capacity" },
  { id: "run", label: "Run" },
  { id: "account", label: "Account" },
  { id: "surface", label: "This surface" },
];

export const SURFACE_IDS = SURFACES.map((s) => s.id);
export const DEFAULT_SURFACE = "home";

export const isSurface = (name) => SURFACE_IDS.includes(name);

export const surfaceFromHash = (hash) => {
  const name = String(hash || "").replace(/^#\/?/, "");
  return isSurface(name) ? name : DEFAULT_SURFACE;
};

export const hashForSurface = (name) => `#/${isSurface(name) ? name : DEFAULT_SURFACE}`;

// The rail's search. It matches a surface by label or id, case-insensitively, and
// returns the registry order — a filter, not a ranking, because a ranking of twelve
// names would be a scorer of nothing. It searches SURFACES ONLY: resources and
// records are not indexed on this branch and the box says so.
export const searchSurfaces = (query) => {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return SURFACES;
  return SURFACES.filter((s) => s.label.toLowerCase().includes(q) || s.id.includes(q));
};
