// Estate messaging spine — hypervisor.com side.
//
// SINGLE OWNER of shared public statements is the ioi-ai repo:
//   ioi-ai/src/config/canonicalMessaging.js  (meaning governed by the
//   architecture canon in this repo, docs/architecture/ + whitepaper v1.10.0).
// Both blocks below are pinned snapshots of that file's exports and must only
// change by re-vendoring from the owner (the estate extensions were
// upstreamed into it on 2026-07-21).
// tools/audit-estate.mjs enforces banned phrases and required literals at
// build time (wired into `npm run build` via prebuild).

/* ------------------------- VENDORED (owner: ioi-ai) ------------------------- */

export const CATEGORY_LINE =
  "IOI is the open operating stack for bounded autonomous systems.";

export const CATEGORY_SUBTITLE =
  "The open operating stack for autonomous systems that prove what they did.";

export const ACTION_LINE =
  "You declare what a system may do, run it where you choose, and get back a signed record of everything it did.";

export const HYPERVISOR_SUMMARY =
  "Hypervisor is the operating environment and control plane for autonomous systems: build agents and workflows, grant them bounded authority, run them on local or cloud compute, and get a verifiable record of everything they do.";

export const STATUS_SUMMARY =
  "IOI is under active implementation. The architecture is published in the v1.10.0 technical whitepaper; Hypervisor runs as a local private preview; marketplace, cross-system AIIP federation, embodied fleets, and IOI L1 services follow the evidence gates on the public roadmap.";

export const LAYER_SUMMARIES = {
  l0: "IOI L0 lets one governed system distribute useful work across models, services, people, compute, and devices — many machines, one accountable system, one history.",
  aiip: "AIIP is the interop protocol between independently owned autonomous systems. Cooperation happens only under terms both sides accept; discovery alone creates no authority and no obligation.",
  l1: "IOI L1 is an optional shared trust layer for the few commitments that need public settlement. It is never required to run an IOI system.",
};

/* ------------- ESTATE EXTENSIONS (vendored; owner: ioi-ai) ----------------- */

// The canonical runtime doctrine pipeline, rendered on hypervisor.com Home.
export const DOCTRINE_PIPELINE = [
  ["Daemon", "executes"],
  ["wallet.network", "authorizes"],
  ["Agentgres", "remembers"],
  ["IOI L1", "settles"],
];

// Hypervisor-type lineage. Type 3 is the public master frame for the product
// story: hardware (T1) and operating systems (T2) virtualized before;
// Hypervisor governs the autonomous-work layer above both.
export const TYPE_LINEAGE = {
  t1: {
    label: "Type 1 · Bare metal",
    governs: "Hardware",
    peers: "ESXi · Xen · KVM",
  },
  t2: {
    label: "Type 2 · Hosted",
    governs: "Operating systems",
    peers: "VMware · VirtualBox · Parallels",
  },
  t3: {
    label: "Type 3 · Hypervisor",
    governs: "Autonomous work",
    line: "Isolation, scheduling, policy, receipts, and replay across every machine, model, and tool.",
  },
};

// The two product lanes. Run-on: systems built on the substrate — effects
// exist only through capability exits, leases, and receipts. Attach: the
// Authority Gateway mediates agents you already run — audit, hold, approve,
// and receipt the control points it can actually see (never a total-
// interception claim; see daemon-runtime/doctrine.md).
export const TWO_LANES = {
  runOn:
    "Build and operate autonomous systems on the substrate. Effects only exist through capability exits, leases, and receipts.",
  attach:
    "Attach the Authority Gateway to agents you already run. Audit, hold for exact-action approval, and receipt their consequential actions.",
};

const ESTATE_MESSAGING = {
  CATEGORY_LINE,
  CATEGORY_SUBTITLE,
  ACTION_LINE,
  HYPERVISOR_SUMMARY,
  STATUS_SUMMARY,
  LAYER_SUMMARIES,
  DOCTRINE_PIPELINE,
  TYPE_LINEAGE,
  TWO_LANES,
};

if (typeof window !== "undefined") window.ESTATE_MESSAGING = ESTATE_MESSAGING;
export default ESTATE_MESSAGING;
