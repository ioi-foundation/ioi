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
// THE RAIL IS ORGANISED BY WHAT A PERSON WANTS, NOT BY WHICH NETWORK SUPPLIES IT.
// Home; Deploy (the front door: one envelope, the field of quotes beside it);
// Workloads (what is running or finished, and its posture); Resources (the catalogue,
// live prices, where work would be placed, storage custody, network); Marketplace (the
// supply side made visible, and whether it is answering); Account (money and
// authority); and this surface itself. A provider name never appears in the rail: the
// venue is a detail a reader inspects from a workload, never a menu they browse first.
//
// STORAGE AND NETWORK ARE UNWIRED. Each is drawn in full — the shape a console user
// opens the tab for — and says on its own page that no route on the capability table
// returns a custody plan, a storage lease, an ingress, a name or a certificate. Their
// resource classes are canon and are already rows in the catalogue; the pages link
// there for what the daemon can say today.
export const SURFACES = [
  // The console's welcome page and default surface: a status strip and widgets that
  // read candidate-sources, jobs, budgets and the latest candidates batch.
  { id: "home", label: "Home", group: "console", wired: true },
  // The front door. One CloudJobRequest, human or agent, with the live field of
  // quotes for the intent drawn beside the form — candidates before commitment.
  { id: "job", label: "Deploy", group: "console", wired: true },
  { id: "receipts", label: "Jobs & receipts", group: "workloads", wired: true },
  { id: "redundancy", label: "Redundancy", group: "workloads", wired: false },
  // Every resource class the router can be asked for, by category, and every venue
  // that can supply it, with its state read from the daemon on every render.
  { id: "catalog", label: "All resources", group: "resources", wired: true },
  { id: "candidates", label: "Live prices", group: "resources", wired: true },
  { id: "placement", label: "Placement", group: "resources", wired: true },
  { id: "storage", label: "Storage", group: "resources", wired: false },
  { id: "network", label: "Network", group: "resources", wired: false },
  { id: "supply", label: "Supply registry", group: "marketplace", wired: false },
  { id: "sources", label: "Sources & health", group: "marketplace", wired: true },
  // Spend reads the daemon's budgets; settled spend stays a labelled door on the page.
  { id: "spend", label: "Spend", group: "account", wired: true },
  { id: "iam", label: "IAM · leases", group: "account", wired: false },
  { id: "api", label: "API", group: "surface", wired: true },
  { id: "settings", label: "Settings", group: "surface", wired: true },
];

// The rail's sections, in rail order, with the words a reader sees. A group named
// here and carried by no surface is not drawn.
export const GROUPS = [
  { id: "console", label: "" },
  { id: "workloads", label: "Workloads" },
  { id: "resources", label: "Resources" },
  { id: "marketplace", label: "Marketplace" },
  { id: "account", label: "Account" },
  { id: "surface", label: "This surface" },
];

// The group a surface sits in, by the word the rail shows — the page header's eyebrow,
// so the crumb a reader sees over a heading is the same word they clicked in the rail.
export const groupLabel = (id) => {
  const s = SURFACES.find((x) => x.id === id);
  const g = s && GROUPS.find((x) => x.id === s.group);
  return (g && g.label) || "Console";
};

export const SURFACE_IDS = SURFACES.map((s) => s.id);
export const DEFAULT_SURFACE = "home";

export const isSurface = (name) => SURFACE_IDS.includes(name);

// CATALOGUE ANCHORS. A console's rail lists its product families under "all
// products"; here they are the canon's resource categories, and each is an address
// of the form #/catalog/<category> that opens the catalogue at that category alone.
// The anchors are not surfaces — they are views of one surface — so the registry
// stays twelve entries and the rail's buttons stay the gate's sweep. Only the four
// families a console user looks for first are anchored; the rest stay in the full
// catalogue.
export const CATALOG_ANCHORS = [
  { id: "compute", label: "Compute" },
  { id: "storage", label: "Storage" },
  { id: "network", label: "Networking" },
  { id: "runtime", label: "Runtime" },
];
const isAnchor = (id) => CATALOG_ANCHORS.some((a) => a.id === id);

const parts = (hash) => String(hash || "").replace(/^#\/?/, "").split("/");

export const surfaceFromHash = (hash) => {
  const name = parts(hash)[0];
  return isSurface(name) ? name : DEFAULT_SURFACE;
};

// The category an address opens the catalogue at, or null for the whole catalogue.
export const catalogCategoryFromHash = (hash) => {
  const [name, sub] = parts(hash);
  return name === "catalog" && isAnchor(sub) ? sub : null;
};

// AN ADDRESS THAT IS NOT A SURFACE is reported, not swallowed. An empty hash is Home
// by design; anything else that resolves to nothing is returned so the shell can
// show the 404 composition with the address on it — a mistyped or stale link that
// silently lands on Home teaches a reader that the link worked.
export const unknownFromHash = (hash) => {
  const raw = String(hash || "").replace(/^#\/?/, "");
  if (!raw) return null;
  const [name, sub] = raw.split("/");
  if (!isSurface(name)) return raw;
  if (name === "catalog" && sub && !isAnchor(sub)) return raw;
  if (name === "receipts" && sub && !isJobId(sub)) return raw;
  return null;
};

// A JOB RECORD HAS AN ADDRESS: #/receipts/<job id>. It is a view of the Jobs &
// receipts surface (not a surface: no rail button, the gate's sweep is unchanged)
// that reads the one record by id through the route already on the capability table.
// The id is bounded the way the proxy bounds its path parameter, so an address that
// could not be a job id is a 404 rather than a request.
const JOB_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const isJobId = (s) => JOB_ID.test(String(s || ""));
export const jobIdFromHash = (hash) => {
  const [name, sub] = parts(hash);
  return name === "receipts" && isJobId(sub) ? sub : null;
};

export const hashForSurface = (name) => `#/${isSurface(name) ? name : DEFAULT_SURFACE}`;
export const hashForCategory = (id) => (isAnchor(id) ? `#/catalog/${id}` : hashForSurface("catalog"));
export const hashForJob = (id) => (isJobId(id) ? `#/receipts/${id}` : hashForSurface("receipts"));

// The rail's search. It matches a surface by label or id, case-insensitively, and
// returns the registry order — a filter, not a ranking, because a ranking of twelve
// names would be a scorer of nothing. It searches SURFACES ONLY: resources and
// records are not indexed on this branch and the box says so.
export const searchSurfaces = (query) => {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return SURFACES;
  return SURFACES.filter((s) => s.label.toLowerCase().includes(q) || s.id.includes(q));
};
