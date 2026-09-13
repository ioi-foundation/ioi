// W0.2 product-surface compiler v1 (bring-to-life run) — ONE projection on the client estate
// feeding nav / catalog / palette / contextual / launch state from registration records.
//
// M08.8: THE PALETTE AND CONTEXTUAL PROJECTIONS ARE REAL NOW. This header claimed to feed palette
// state from the day it was written while the module returned workspaces and applications only, so
// every palette and contextual launcher downstream kept a list of its own — the hard-coded catalog
// ACC-10 clause 2 forbids, moved rather than removed. Both now come back from the daemon, derived
// there from `launch_modes` and `supported_context_kinds` on the registration, and this module
// passes them through without re-deciding membership.
//
// Source of truth: the daemon. Membership and launchability come ONLY from
// POST /v1/hypervisor/product-surface-projections (lifecycle_routes.rs handle_product_surface_projection),
// which joins registration → admitted+active release → installed+enabled installation (request
// org) → serving binding and emits per-row `launchable` + honest `disabled_reason_codes`, plus
// `workspace_entries` for the six core workspaces (canon: core-clients-surfaces.md
// § Product-Surface Compiler — policy filtering happens daemon-side, BEFORE aggregation; this
// module never re-implements policy and never caches identity-bound output).
//
// This module replaces the three hand-maintained catalogs as catalog authorities:
//   #1 `IOI_APPS` (augmentation/30-shell.js)            → deleted; the launcher fetches this projection
//   #2 SUITE/SUBSTRATE arrays (serve-product-ui.mjs)    → deleted; the readout renders this projection
//   #3 app-catalog.mjs / surface-registry.mjs SURFACES  → REHOMED (M08.8). The `apps` band was
//      demoted to "implementation evidence" while its membership was still read from
//      `shell_pixel_certified` in the harvest parity matrix — a label, not a boundary. The
//      fourteen ported tool surfaces are registrations now (`surface_class: tool_surface`) and
//      the band is a view over this projection. surface-registry.mjs keeps presentation.
//
// SURFACE_REGISTRATION_INPUT below is the compiler's DECLARED STATIC REGISTRATION-RECORD INPUT —
// the one place that keeps the registration data the daemon does not serve yet (presentation
// icon, one-line description, and the legacy serving lane that carries the surface today). It is
// NOT a parallel catalog: rows that the daemon does not return are never shown as members while
// the daemon is reachable, and nothing here fabricates launchability. On daemon failure the
// compiler preserves the safe static first-party inventory (canon :1985-1988) with
// `launchable:false` + `disabled_reason_codes:["daemon_unavailable"]` and a top-level
// `daemon.available:false` so every consumer renders a named "daemon unavailable" state —
// never a frozen fake catalog.
import { SURFACES } from "./surface-registry.mjs";

const DEFAULT_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DEFAULT_TIMEOUT_MS = 3_500;

export const COMPILED_SURFACES_SCHEMA = "ioi.hypervisor.compiled-product-surfaces.v1";

// Declared static registration-record input (see header). Keyed by the daemon registration's
// surface_key / the taxonomy's workspace_key. `open_today` names the legacy lane that serves the
// surface today (kept until that surface's rehome/cutover); it is presentation/serving
// decoration, never membership.
export const SURFACE_REGISTRATION_INPUT = {
  workspaces: {
    // GRE-2 LAUNCHER RE-POINT (owner go 2026-08-20): seeded families open their DESIGNATED click
    // targets (canonical routes → the seed shells). Greenfield lanes stay pending GRE-1 impl.
    home: { icon: "⌂", desc: "Estate cockpit — governed work, recents, launch.", open_today: { href: "/ai", label: "Explorer Home" } },
    systems: { icon: "⬡", desc: "The live institution at the center — honest read models only.", open_today: { href: "/__ioi/systems", label: "Systems readout" } },
    projects: { icon: "🗂", desc: "Project context, preserved end to end.", open_today: null },
    applications: { icon: "◳", desc: "The catalog/compiler projection — this very surface.", open_today: { href: "/__ioi/applications", label: "Applications readout" } },
    work: { icon: "⚑", desc: "Typed Work views; Sessions is /work/sessions.", open_today: { href: "/__ioi/missions", label: "Jobs readout" } },
    settings: { icon: "⚙", desc: "Projection-only core workspace; writes through owners.", open_today: null },
  },
  applications: {
    studio: { icon: "🎨", desc: "Compose systems & agents — agent lens live; typed canvas and blueprints arrive by wave.", open_today: { href: "/studio", label: "Studio (family landing)" } },
    automations: { icon: "⚡", desc: "Durable triggers, schedules, monitors, services — condition → governed effect.", open_today: { href: "/automations", label: "Automate" } },
    ontology: { icon: "🧬", desc: "The semantic world-model — Ontology Manager over the typed COM; Explorer + ODK substrate.", open_today: { href: "/ontology", label: "Ontology (family landing)" } },
    data: { icon: "🌐", desc: "Supply the world-model — sources, syncs, recipes, pipelines, consent posture.", open_today: { href: "/data", label: "Data (family landing)" } },
    governance: { icon: "🛡", desc: "Authority — approvals, leases, release gates, kill switches, budgets, gaps.", open_today: { href: "/governance", label: "Approvals" } },
    provenance: { icon: "📒", desc: "Proof plane — receipts stream, state roots, timelines, lineage.", open_today: { href: "/provenance", label: "Data Lineage (Monocle)" } },
    evaluations: { icon: "🧪", desc: "Eval-suite library over real subjects and consent; scoring lands by wave.", open_today: { href: "/evaluations", label: "AIP Evals" } },
    improvement: { icon: "📈", desc: "Proposals, what-if simulation, apply-under-gates — change inbox over daemon truth.", open_today: { href: "/__ioi/improvement/changes", label: "Upgrade Assistant" } },
    foundry: { icon: "🏗", desc: "Model substrate — catalog, routes, draft specs, run plans, promotion previews.", open_today: { href: "/foundry", label: "Model Catalog" } },
    packages: { icon: "📦", desc: "Registry of packages and releases; Marketplace is the optional mode at /packages/marketplace.", open_today: { href: "/__ioi/marketplace", label: "Marketplace readout" } },
    "developer-workspace": { icon: "🧰", desc: "Enter an environment's live console — files, terminal, ports, tasks, repos.", open_today: { href: "/developer-workspace", label: "Workbench (family landing)" } },
    "developer-console": { icon: "🔌", desc: "Extend the environment — connectors, MCP, sealed credentials, SDK on-ramps.", open_today: { href: "/__ioi/developer-console", label: "Developer Console" } },
    environments: { icon: "🖥", desc: "Substrate — lifecycle, readiness, services/ports/tasks, kernel boundary.", open_today: { href: "/__ioi/environments", label: "Environments readout" } },
    operations: { icon: "⛭", desc: "Substrate — scheduler health, providers, placement/failover, custody, spend.", open_today: { href: "/__ioi/operations", label: "Operations readout" } },
    "embodied-systems": { icon: "🤖", desc: "Conditional owner application — planned and nonlaunchable until built.", open_today: null },
  },
};

// THE LANE IS READ FROM THE REGISTERED CLASS, NOT RE-DERIVED (M08.8, 2026-09-12).
//
// This was a hard-coded `Set(["environments","operations"])` — a second, client-side derivation of
// `surface_class`, which the daemon has held as a registered field all along and simply did not
// project. Two places deciding the same fact is the defect Non-Negotiable 36 names: a registration
// that does not reach its projections gets re-invented at every consumer, and the copies drift.
// The daemon now emits `surface_class`, so the lane is a read.
//
// The fallback is the STATIC INVENTORY path only, where by construction there is no daemon answer
// to read; it is kept beside the keys it serves rather than as a live classifier.
const SUBSTRATE_FALLBACK_KEYS = new Set(["environments", "operations"]);
const laneForClass = (surfaceClass, key) => {
  if (surfaceClass === "substrate_application") return "substrate";
  if (surfaceClass === "owner_application") return "owner";
  // A registered class, so it gets its lane rather than the unclassified bucket. The fourteen
  // ported tool surfaces used to arrive with no class at all — their membership came from a parity
  // matrix — and "unclassified" was the honest reading of that. They are registrations now.
  if (surfaceClass === "tool_surface") return "tool";
  if (surfaceClass === "extension_application") return "extension";
  // No registered class reached this consumer. Say so rather than guessing a lane: an unknown
  // class rendered as "owner" is the same invisible re-derivation this change removes.
  return surfaceClass ? "unclassified" : (SUBSTRATE_FALLBACK_KEYS.has(key) ? "substrate" : "owner");
};

function keyFromRef(ref) {
  // "surface://hypervisor/studio" → "studio" · "hypervisor-workspace://home" → "home"
  return String(ref || "").split("/").filter(Boolean).pop() || "";
}

function decorateWorkspace(entry) {
  const key = keyFromRef(entry.identity_ref);
  const reg = SURFACE_REGISTRATION_INPUT.workspaces[key] || {};
  return {
    key,
    name: entry.display_name || key,
    route: entry.canonical_route || null,
    launch_route: entry.resolved_launch_route || entry.canonical_route || null,
    launchable: entry.launchable === true,
    disabled_reason_codes: Array.isArray(entry.disabled_reason_codes) ? entry.disabled_reason_codes : [],
    icon: reg.icon || "◳",
    desc: reg.desc || "",
    open_today: reg.open_today || null,
  };
}

function decorateApplication(entry) {
  const key = keyFromRef(entry.identity_ref);
  const reg = SURFACE_REGISTRATION_INPUT.applications[key] || {};
  return {
    key,
    name: entry.display_name || key,
    lane: laneForClass(entry.surface_class, key),
    surface_class: entry.surface_class || null,
    route: entry.canonical_route || null,
    launch_route: entry.resolved_launch_route || null,
    launchable: entry.launchable === true,
    disabled_reason_codes: Array.isArray(entry.disabled_reason_codes) ? entry.disabled_reason_codes : [],
    capability_depth: entry.surface_capability_depth || null,
    operational_state: entry.surface_operational_state || null,
    origin: entry.surface_origin || null,
    creation_method: entry.surface_creation_method || null,
    supported_placements: Array.isArray(entry.supported_placements) ? entry.supported_placements : [],
    launch_modes: Array.isArray(entry.launch_modes) ? entry.launch_modes : [],
    supported_context_kinds: Array.isArray(entry.supported_context_kinds) ? entry.supported_context_kinds : [],
    icon: reg.icon || "◳",
    desc: reg.desc || "",
    open_today: reg.open_today || null,
  };
}

// Safe static first-party inventory for daemon failure (canon :1985-1988): names + canonical
// routes only, launch state honestly absent — every row disabled with the named reason.
function staticFirstPartyInventory(reasonCode) {
  const title = (key) => key.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  const workspaces = Object.entries(SURFACE_REGISTRATION_INPUT.workspaces).map(([key, reg]) => ({
    key,
    name: title(key),
    route: `/${key}`,
    launch_route: null,
    launchable: false,
    disabled_reason_codes: [reasonCode],
    icon: reg.icon,
    desc: reg.desc,
    open_today: reg.open_today || null,
  }));
  const applications = Object.entries(SURFACE_REGISTRATION_INPUT.applications).map(([key, reg]) => ({
    key,
    name: title(key),
    lane: laneForClass(null, key),
    route: `/${key}`,
    launch_route: null,
    launchable: false,
    disabled_reason_codes: [reasonCode],
    capability_depth: null,
    operational_state: null,
    icon: reg.icon,
    desc: reg.desc,
    open_today: reg.open_today || null,
  }));
  // NO STATIC PALETTE AND NO STATIC CONTEXTUAL LANE. The safe static inventory canon permits is
  // first-party NAMES and routes with launch honestly absent; a palette is a list of things you can
  // DO, and offering one while the daemon is unreachable would invite exactly the launches that
  // cannot be authorized. Empty with the reason on it, so a consumer renders "unavailable" rather
  // than "none".
  return {
    workspaces,
    applications,
    palette: [],
    contextual: { requested_context_kind: null, absence_code: reasonCode, entries: [] },
  };
}

// The palette and contextual entries are PASSED THROUGH, not recomputed. Membership was decided
// daemon-side after policy filtering; re-deriving it here from `launch_modes` would be a second
// path to launch with its own idea of who may see what.
function decoratePaletteEntry(entry) {
  const key = keyFromRef(entry.identity_ref);
  const reg = SURFACE_REGISTRATION_INPUT.applications[key] || {};
  return {
    key,
    name: entry.display_name || key,
    route: entry.canonical_route || null,
    launch_route: entry.resolved_launch_route || null,
    launchable: entry.launchable === true,
    disabled_reason_codes: Array.isArray(entry.disabled_reason_codes) ? entry.disabled_reason_codes : [],
    surface_class: entry.surface_class || null,
    icon: reg.icon || "◳",
  };
}

function decorateContextualEntry(entry) {
  const key = keyFromRef(entry.identity_ref);
  const reg = SURFACE_REGISTRATION_INPUT.applications[key] || {};
  return {
    key,
    name: entry.display_name || key,
    route: entry.canonical_route || null,
    launch_route: entry.resolved_launch_route || null,
    launchable: entry.launchable === true,
    disabled_reason_codes: Array.isArray(entry.disabled_reason_codes) ? entry.disabled_reason_codes : [],
    matched_context_kind: entry.matched_context_kind || null,
    icon: reg.icon || "◳",
  };
}

// THE `apps` BAND, REHOMED (M08.8). It used to be built by app-catalog.mjs from
// `shell_pixel_certified` rows of the harvest parity matrix — that is, a screenshot comparison
// decided which surfaces appeared in a rendered lane. Canon is explicit that capture provenance,
// screenshots, pixel certificates and parity matrices "have zero authority over registration class,
// catalog membership, owner, capability, or maturity" (core-clients-surfaces.md :2006-2008), and
// the band was labelled `catalog_authority: false` while its MEMBERSHIP was still parity-derived.
// A label is not a boundary.
//
// The fourteen are registrations now — `surface_class: tool_surface`, all eleven axes, admitted and
// served through the same daemon join as everything else — so the band is a VIEW over the compiled
// projection. The parity matrix keeps its real job (is the port faithful?) and decides membership
// in nothing. Presentation still comes from the surface registry, which is what it was always for.
function toolSurfaceBand(applications) {
  let presentation = new Map();
  try {
    presentation = new Map(SURFACES.map((surface) => [surface.slug, surface]));
  } catch {
    presentation = new Map();
  }
  return applications
    .filter((entry) => entry.surface_class === "tool_surface")
    .map((entry) => {
      const reg = presentation.get(entry.key) || {};
      return {
        slug: entry.key,
        title: entry.name,
        family: reg.owner || "",
        route: entry.route,
        icon: reg.icon || null,
        launchable: entry.launchable,
        disabled_reason_codes: entry.disabled_reason_codes,
      };
    })
    .sort((a, b) => a.family.localeCompare(b.family) || a.title.localeCompare(b.title));
}

// THE one entry function. Every consumer of nav / catalog / palette / launch state calls this
// (directly server-side, or via GET /__ioi/api/applications from the browser) and renders the
// result — never a hand list.
export async function compileProductSurfaces({
  headers = {},
  daemonUrl = DEFAULT_DAEMON,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  context = {},
} = {}) {
  let daemon;
  let workspaces;
  let applications;
  let palette;
  let contextual;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    let payload;
    try {
      response = await fetchImpl(`${daemonUrl}/v1/hypervisor/product-surface-projections`, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ context }),
        signal: controller.signal,
      });
      payload = await response.json().catch(() => null);
    } finally {
      clearTimeout(timer);
    }
    // A projection missing either of the two new lanes is a projection from a daemon that predates
    // them, and reading it as an empty palette would report "no commands" for what is really "this
    // daemon cannot say". It falls to the static inventory with a named reason like any other
    // unusable answer.
    if (response.ok && payload && Array.isArray(payload.workspace_entries) && Array.isArray(payload.application_entries)
      && Array.isArray(payload.command_palette_entries) && Array.isArray(payload.contextual_entries)) {
      daemon = {
        available: true,
        status: response.status,
        projection_id: payload.projection_id || null,
        request_context_hash: payload.request_context_hash || null,
        policy_decision_refs: payload.policy_decision_refs || [],
        read_model_only: payload.read_model_only === true,
      };
      workspaces = payload.workspace_entries.map(decorateWorkspace);
      applications = payload.application_entries.map(decorateApplication);
      palette = payload.command_palette_entries.map(decoratePaletteEntry);
      contextual = {
        requested_context_kind: payload.requested_context_kind ?? null,
        absence_code: payload.contextual_absence_code ?? null,
        entries: payload.contextual_entries.map(decorateContextualEntry),
      };
    } else {
      const code = payload?.code || payload?.error?.code || `http_${response.status}`;
      daemon = { available: false, status: response.status, code };
      ({ workspaces, applications, palette, contextual } = staticFirstPartyInventory(code));
    }
  } catch (error) {
    const code = error?.name === "AbortError" ? "plane_timeout" : "daemon_unavailable";
    daemon = { available: false, status: 0, code };
    ({ workspaces, applications, palette, contextual } = staticFirstPartyInventory(code));
  }
  return {
    schema: COMPILED_SURFACES_SCHEMA,
    compiled_from: "POST /v1/hypervisor/product-surface-projections + declared static registration-record input (surface-compiler.mjs)",
    projections: ["shell", "catalog", "command_palette", "contextual", "api"],
    daemon,
    workspaces,
    applications,
    // The two projections ACC-10 clause 2 names that this compiler never had.
    palette,
    contextual,
    // The ported tool surfaces — a view over the projection above, not a second catalog.
    apps: toolSurfaceBand(applications),
    evidence: {
      role: "implementation_evidence_only",
      catalog_authority: false,
      source: "registration plane (surface_class: tool_surface) — the parity matrix decides no membership",
    },
  };
}
