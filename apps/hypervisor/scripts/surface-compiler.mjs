// W0.2 product-surface compiler v1 (bring-to-life run) — ONE projection on the client estate
// feeding nav / catalog / palette / launch state from registration records.
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
//   #3 app-catalog.mjs / surface-registry.mjs SURFACES  → demoted to implementation evidence
//      (zero catalog authority per canon :2006-2008); carried on the projection as the
//      `apps` evidence band so the legacy tool-surface lanes stay reachable until their
//      per-app Wave 1 rehome / Wave 4 cutover.
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
import { appCatalog } from "./app-catalog.mjs";

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

// The substrate lane keys (canon first-party set: 12 owners + Environments/Operations substrate).
const SUBSTRATE_KEYS = new Set(["environments", "operations"]);

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
    lane: SUBSTRATE_KEYS.has(key) ? "substrate" : "owner",
    route: entry.canonical_route || null,
    launch_route: entry.resolved_launch_route || null,
    launchable: entry.launchable === true,
    disabled_reason_codes: Array.isArray(entry.disabled_reason_codes) ? entry.disabled_reason_codes : [],
    capability_depth: entry.surface_capability_depth || null,
    operational_state: entry.surface_operational_state || null,
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
    lane: SUBSTRATE_KEYS.has(key) ? "substrate" : "owner",
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
  return { workspaces, applications };
}

function evidenceBand() {
  // Catalog #3, demoted: parity-matrix + operational-depth contract evidence over the ported
  // tool surfaces. Implementation evidence only — zero catalog authority (canon :2006-2008).
  try {
    return appCatalog().apps || [];
  } catch {
    return [];
  }
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
    if (response.ok && payload && Array.isArray(payload.workspace_entries) && Array.isArray(payload.application_entries)) {
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
    } else {
      const code = payload?.code || payload?.error?.code || `http_${response.status}`;
      daemon = { available: false, status: response.status, code };
      ({ workspaces, applications } = staticFirstPartyInventory("daemon_unavailable"));
    }
  } catch (error) {
    const code = error?.name === "AbortError" ? "plane_timeout" : "daemon_unavailable";
    daemon = { available: false, status: 0, code };
    ({ workspaces, applications } = staticFirstPartyInventory("daemon_unavailable"));
  }
  return {
    schema: COMPILED_SURFACES_SCHEMA,
    compiled_from: "POST /v1/hypervisor/product-surface-projections + declared static registration-record input (surface-compiler.mjs)",
    daemon,
    workspaces,
    applications,
    // Evidence band (catalog #3 demoted): ported tool surfaces, implementation evidence only.
    apps: evidenceBand(),
    evidence: {
      role: "implementation_evidence_only",
      catalog_authority: false,
      source: "app-catalog.mjs (parity matrix + operational-depth contract evidence)",
    },
  };
}
