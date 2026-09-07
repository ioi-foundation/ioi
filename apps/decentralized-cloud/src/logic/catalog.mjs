// THE CATALOG — every resource class this router can be asked for, by category, and
// every venue or network that can supply it, with the state the daemon last persisted
// for that supply. Framework-free.
//
// The SHAPE of the catalog is canon: the resource classes are the ones cloud.md
// declares, in the order it declares them, and the venues under each are the provider
// lanes the byo-provider-plane table names. That part is static and is allowed to be,
// because it is a list of names the estate has committed to, not a claim about what
// answers today.
//
// The STATE of every entry is not static and is not allowed to be. It is read from the
// daemon's candidate-sources body and from the latest candidates batch on every
// render. An entry with no daemon source says so by name — "not yet a source" — rather
// than being left off, because a directory that lists only what works is a brochure,
// and one that lists what is planned without saying so is a lie. Both fail the same
// test: a reader cannot tell what they would get.
//
// COLOUR carries one meaning here, as everywhere on this surface: green is live
// evidence — a venue quoting real prices right now — and nothing else is green.

export const CATEGORIES = [
  {
    id: "compute",
    title: "Compute",
    classes: [
      {
        id: "compute.vm",
        label: "Virtual machines",
        entries: [
          { name: "Local host", source: "customer_inventory", kind: "local" },
          { name: "Bare metal over SSH", source: "customer_inventory", kind: "local" },
          { name: "AWS EC2", source: "aws", kind: "hyperscaler" },
          { name: "Google Compute Engine", source: "gcp", kind: "hyperscaler" },
          { name: "Azure Virtual Machines", source: "azure", kind: "hyperscaler" },
          { name: "Lambda GPU VM", source: "lambda_cloud", kind: "gpu cloud" },
        ],
      },
      {
        id: "compute.microvm",
        label: "MicroVMs",
        entries: [
          { name: "Local KVM microVM", source: "customer_inventory", kind: "local" },
        ],
      },
      {
        id: "compute.container",
        label: "Containers and clusters",
        entries: [
          { name: "Kubernetes and KubeVirt clusters", source: "k8s", kind: "cluster" },
          { name: "Akash Network", source: "depin_market", kind: "DePIN" },
        ],
      },
      {
        id: "compute.gpu_runtime",
        label: "GPU runtime",
        entries: [
          { name: "Vast.ai marketplace", source: "vast", kind: "GPU marketplace", venue: "vast" },
          { name: "RunPod", source: "runpod", kind: "GPU cloud", venue: "runpod" },
          { name: "Akash GPU", source: "depin_market", kind: "DePIN" },
          { name: "Lambda", source: "lambda_cloud", kind: "GPU cloud" },
        ],
      },
    ],
  },
  {
    id: "storage",
    title: "Storage",
    classes: [
      {
        id: "storage.object",
        label: "Object",
        entries: [
          { name: "Object stores (S3-class)", source: "storage_network", kind: "storage" },
        ],
      },
      {
        id: "storage.block",
        label: "Block",
        entries: [{ name: "Local disk", source: "customer_inventory", kind: "local" }],
      },
      {
        id: "storage.archive",
        label: "Archive",
        entries: [
          { name: "Encrypted archives", source: "storage_network", kind: "storage" },
        ],
      },
      {
        id: "storage.cas",
        label: "Content-addressed",
        entries: [
          { name: "Filecoin / CAS", source: "storage_network", kind: "decentralized storage" },
        ],
      },
    ],
  },
  {
    id: "network",
    title: "Networking",
    classes: [
      {
        id: "network.ip_lease",
        label: "IP leases",
        entries: [{ name: "Akash IP lease", source: "depin_market", kind: "DePIN" }],
      },
      {
        id: "network.ingress",
        label: "Ingress",
        entries: [
          { name: "Hypervisor route bindings", source: "customer_inventory", kind: "local" },
        ],
      },
      { id: "network.dns", label: "DNS", entries: [{ name: "DNS", source: null, kind: "planned" }] },
      { id: "network.tls", label: "TLS", entries: [{ name: "TLS", source: null, kind: "planned" }] },
    ],
  },
  {
    id: "runtime",
    title: "Runtime",
    classes: [
      {
        id: "runtime.model_server",
        label: "Model servers",
        entries: [
          { name: "RunPod", source: "runpod", kind: "GPU cloud", venue: "runpod" },
          { name: "Vast.ai marketplace", source: "vast", kind: "GPU marketplace", venue: "vast" },
          { name: "Akash Network", source: "depin_market", kind: "DePIN" },
        ],
      },
      {
        id: "runtime.browser",
        label: "Browsers",
        entries: [{ name: "Hypervisor environments", source: "customer_inventory", kind: "local" }],
      },
      {
        id: "runtime.workbench",
        label: "Workbenches",
        entries: [{ name: "Hypervisor environments", source: "customer_inventory", kind: "local" }],
      },
    ],
  },
  {
    id: "security",
    title: "Confidential compute",
    classes: [
      { id: "security.tee", label: "TEE", entries: [{ name: "TEE lanes", source: null, kind: "planned" }] },
      { id: "security.ctee", label: "cTEE", entries: [{ name: "cTEE lanes", source: null, kind: "planned" }] },
    ],
  },
  {
    id: "supply",
    title: "First-party supply",
    classes: [
      {
        id: "supply.managed",
        label: "Managed capacity",
        entries: [{ name: "IOI managed capacity", source: "managed_capacity", kind: "provider of record" }],
      },
      {
        id: "supply.contributed",
        label: "Contributed supply",
        entries: [{ name: "decentralized.cloud registry", source: "decentralized.cloud", kind: "registry" }],
      },
    ],
  },
];

// ── State, read from the daemon ─────────────────────────────────────────────
//
// `sources` is the candidate-sources body's array; `liveByVenue` is a map of
// provider_kind → { count, cheapest } built from the latest candidates batch by the
// caller through the ONE live rule (classify) — this module does not decide liveness
// and must not, because a second definition of "live" is a second spine.

export const STATES = {
  quoting: { chip: "live", word: "quoting" },
  available: { chip: "muted", word: "available" },
  engaged: { chip: "muted", word: "engaged" },
  connected: { chip: "muted", word: "connected, no adapter" },
  // An account is verified for this venue and the latest read returned no supply from
  // it. Distinct from "no source", where the daemon has no account at all.
  //
  // THE WORD WAS "connected, not quoting", AND IT CLAIMED TOO MUCH. The daemon's own
  // state here is `candidate_source_unavailable`, which does NOT distinguish "we
  // reached it and it had nothing" from "we could not reach it". Saying "connected"
  // resolves that ambiguity in the product's favour: it tells a stranger the link is
  // healthy and the venue merely declined to quote, when the evidence supports only
  // that an account is verified — possibly from an earlier check — and that this read
  // produced no supply.
  //
  // On a surface whose whole discipline is that a state means one thing, inferring a
  // live connection from a stored account is the same move as inferring liveness from
  // a cached price. The two facts now sit beside each other with no conclusion drawn
  // across them: the chip reports the read, the evidence line reports the account.
  // Rendered grey, never green.
  // "no supply this read" was the first wording and it wrapped to four lines in a 30%
  // column at 390px, turning the pill into a distorted oval. "now" carries the same
  // momentary framing — which is the load-bearing part, since the alternative reading
  // is "this venue never has supply" — in a third of the width.
  connectedNotQuoting: { chip: "muted", word: "no supply now" },
  unavailable: { chip: "absent", word: "no source" },
  planned: { chip: "absent", word: "not yet a source" },
  unread: { chip: "absent", word: "not in this read" },
};

const short = (v) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : null);

// How many accounts the daemon reports as connected for this source, from whichever
// `*_accounts` key it sent. Null when it sent none.
export function accountsFor(src) {
  const ev = src?.evidence && typeof src.evidence === "object" ? src.evidence : {};
  let n = null;
  for (const [k, v] of Object.entries(ev)) {
    if (/_accounts$/.test(k) && typeof v === "number") n = (n ?? 0) + v;
  }
  return n;
}

// One sentence of evidence per entry, taken from what the daemon sent for the source.
// Nothing is inferred: if the body carries a count of connected accounts it is shown,
// and if it carries nothing but a basis, the basis is shown. Each fact is said ONCE —
// a first version printed "verified ssh accounts 1 · 1 account connected", one number
// under two names, which reads as two facts.
export function evidenceFor(src) {
  if (!src) return null;
  const ev = src.evidence && typeof src.evidence === "object" ? src.evidence : {};
  const bits = [];
  for (const k of ["offers_seen", "gpu_types_priced", "verified_backends"]) {
    if (k in ev && ev[k] !== null && ev[k] !== undefined) bits.push(`${k.replace(/_/g, " ")} ${ev[k]}`);
  }
  const accounts = accountsFor(src);
  if (accounts !== null) {
    bits.push(accounts === 0 ? "no account connected" : `${accounts} account${accounts === 1 ? "" : "s"} connected`);
  }
  if (bits.length === 0 && ev.basis) bits.push(short(ev.basis));
  if (bits.length === 0 && src.coverage) bits.push(short(src.coverage));
  return bits.length ? bits.join(" · ") : null;
}

export function stateOf(entry, sourcesByName, liveByVenue) {
  if (!entry.source) return { ...STATES.planned, evidence: null, live: null };
  const src = sourcesByName.get(entry.source);
  if (!src) return { ...STATES.unread, evidence: null, live: null };
  const live = entry.venue && liveByVenue ? liveByVenue.get(entry.venue) || null : null;
  const evidence = evidenceFor(src);
  switch (src.state) {
    case "live_quote_source":
      return { ...STATES.quoting, evidence, live };
    case "available":
      return { ...STATES.available, evidence, live };
    case "storage_backends_engaged":
      return { ...STATES.engaged, evidence, live };
    case "credential_preflight_only":
      return { ...STATES.connected, evidence, live };
    case "candidate_source_unavailable": {
      // "no source · 1 account connected" contradicted itself on the first render.
      // The daemon's state is unavailable AND its evidence says an account is
      // verified: that is a venue it can ask which returned no supply this read.
      const accounts = accountsFor(src);
      return accounts !== null && accounts > 0
        ? { ...STATES.connectedNotQuoting, evidence, live }
        : { ...STATES.unavailable, evidence, live };
    }
    default:
      return { chip: "muted", word: src.state || "state absent", evidence, live };
  }
}

// The catalog resolved against one read: every category, every class, every entry
// with its state — plus the counts the header states, derived here once so the header
// and the rows cannot disagree.
export function resolveCatalog(sources, liveByVenue) {
  const byName = new Map((Array.isArray(sources) ? sources : []).map((s) => [s.source, s]));
  let entries = 0, quoting = 0, answering = 0, planned = 0;
  const categories = CATEGORIES.map((cat) => ({
    ...cat,
    classes: cat.classes.map((cls) => ({
      ...cls,
      entries: cls.entries.map((e) => {
        const st = stateOf(e, byName, liveByVenue);
        entries += 1;
        if (st.word === STATES.quoting.word) quoting += 1;
        else if (st.chip === "muted") answering += 1;
        else if (st.word === STATES.planned.word) planned += 1;
        return { ...e, state: st };
      }),
    })),
  }));
  return { categories, counts: { entries, quoting, answering, planned, sources: byName.size } };
}
