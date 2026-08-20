// The surface registry — the explicit table of ported application surfaces (functional-runtime
// wave). Each entry is the CODE-side identity of one certified port: slug (joins the parity
// matrix + pixel certification, the EVIDENCE side), owner family, display title + app tile icon
// (presentation truth — app-catalog.mjs reads it from here), canonical route, and the paths of
// its verifier + certification artifact.
//
// W0.2 role note: SURFACES is serving-mount + evidence truth for the ported tool surfaces, NOT
// a product catalog. Catalog/nav/palette/launch truth is the compiled product-surface
// projection (scripts/surface-compiler.mjs over the daemon's registration records); the
// evidence band it carries derives from app-catalog.mjs, which reads presentation from here.
//
// Implementations bind under the surface-module contract { meta, load(ctx), render(model, ctx),
// actions } — extracted modules (surfaces/<slug>/index.mjs) are imported and bound HERE, so the
// registry is the single mount point; a surface whose code still lives in the serve file may
// bind at serve startup the same way. An entry with no binding is metadata-only: it lists in
// the catalog but keeps its flat-branch handler until it is deliberately migrated. Registration
// is additive and behavior-preserving.
import { ONTOLOGY_APP_ICON_URI, APPROVALS_APP_ICON_URI, PIPELINE_APP_ICON_URI, ISSUES_APP_ICON_URI, EXPLORER_APP_ICON_URI, MODELS_APP_ICON_URI } from "./bp-icons.mjs";
import { MARKETPLACE_APP_ICON_URI } from "./marketplace-assets.mjs";
import { DSG_APP_TILE_URI } from "./designer-assets.mjs";
import { MCH_APP_TILE_URI } from "./machinery-assets.mjs";
import { MON_APP_TILE_URI } from "./monitors-assets.mjs";
import { SRC_APP_TILE_URI } from "./sources-assets.mjs";
import { CHG_APP_TILE_URI } from "./changes-assets.mjs";
import { EVL_APP_TILE_URI } from "./evalsuites-assets.mjs";
import * as pipelineModule from "../surfaces/pipeline/index.mjs";
import * as ontologyManagerModule from "../surfaces/ontology-manager/index.mjs";
import * as objectExplorerModule from "../surfaces/object-explorer/index.mjs";
import * as approvalsModule from "../surfaces/approvals/index.mjs";
import * as sourcesModule from "../surfaces/sources/index.mjs";
import * as missionsModule from "../surfaces/missions/index.mjs";
import * as studioModule from "../surfaces/studio/index.mjs";
import * as packagesModule from "../surfaces/packages/index.mjs";
import * as automationsModule from "../surfaces/automations/index.mjs";
import * as applicationsModule from "../surfaces/applications/index.mjs";
import * as systemsModule from "../surfaces/systems/index.mjs";
import * as workModule from "../surfaces/work/index.mjs";
import * as homeModule from "../surfaces/home/index.mjs";
import * as operationsModule from "../surfaces/operations/index.mjs";

// Capability model (operational wave): `capabilities` is the AUTHORITY-derived set of acts the
// surface genuinely supports today (never inferred from pixel certification or daemon_wired);
// `operational_state` places the surface on the shell → browse → inspect → act →
// workflow_complete ladder (read_only_by_contract marks a complete read-only app). Both advance
// only when a PR lands the behavior with its verifier — parity fields stay untouched beside them.
export const CAPABILITIES = ["browse", "filter", "select", "inspect", "create", "update", "transition", "execute", "proof"];
export const OPERATIONAL_STATES = ["shell", "browse", "inspect", "act", "workflow_complete", "read_only_by_contract"];
// Native container contract (#65): `embedded_shell_state` declares how the surface renders inside
// the Open Application slot. "native_single_rail" = embed=1 removes the ported global rail
// STRUCTURALLY and the native IOI rail is the one platform rail; "ported_rail_only" = the surface
// still ships its reference rail when embedded (NOT admissible for an operational application —
// the invariant below fails the boot).
export const EMBEDDED_SHELL_STATES = ["ported_rail_only", "native_single_rail"];
// Interaction-fidelity wave (#66): `interaction_parity_state` records whether the surface's
// interaction breadth has been verified against a recorded reference state atlas.
// "atlas_verified" = a checked-in control matrix covers every reference control with one of four
// outcomes AND the interaction verifier replays the atlas against reference + IOI per state;
// "none" = only the static shell is certified. Pipeline earns atlas_verified in #66 while its
// operational_state stays "inspect" (Build remains the governed ladder, wired in #67).
export const INTERACTION_PARITY_STATES = ["none", "atlas_verified"];

export const SURFACES = [
  { slug: "missions", owner: "Missions", title: "Missions", icon: missionsModule.MISSIONS_APP_ICON_URI, route: "/__ioi/missions", verifier: "scripts/verify-hypervisor-app-parity-missions.mjs", certification: "n/a", catalog_evidence: { schema: "ioi.hypervisor.catalog-contract-evidence.v1", artifact: "application-operational-depth.json", evidence_key: "missions", module: "surfaces/missions/index.mjs", verifier: "scripts/verify-hypervisor-app-parity-missions.mjs" }, capabilities: ["browse", "filter", "select", "inspect", "proof"], operational_state: "read_only_by_contract", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "pipeline", owner: "Data", title: "Pipeline Builder", icon: PIPELINE_APP_ICON_URI, route: "/__ioi/pipeline", canonical_route: "/data/recipes", verifier: "scripts/verify-hypervisor-app-parity-pipeline.mjs", certification: "pixel-certifications/pipeline.json", capabilities: ["browse", "select", "inspect", "create", "transition", "execute", "proof"], operational_state: "workflow_complete", embedded_shell_state: "native_single_rail", interaction_parity_state: "atlas_verified" },
  { slug: "sources", owner: "Data", title: "Data Connection", icon: SRC_APP_TILE_URI, route: "/__ioi/data/sources", canonical_route: "/data/sources", verifier: "scripts/verify-hypervisor-app-parity-sources.mjs", certification: "pixel-certifications/sources.json", capabilities: ["browse", "select", "create"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "schema", owner: "Ontology", title: "Ontology Manager", icon: ONTOLOGY_APP_ICON_URI, route: "/__ioi/ontology/manager", canonical_route: "/ontology/schema", verifier: "scripts/verify-hypervisor-app-parity-ontology-manager.mjs", certification: "pixel-certifications/schema.json", capabilities: ["browse", "filter", "select", "inspect", "create", "update", "proof"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "explorer", owner: "Ontology", title: "Object Explorer", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/ontology/explorer", canonical_route: "/ontology/explore", verifier: "scripts/verify-hypervisor-app-parity-object-explorer.mjs", certification: "pixel-certifications/explorer.json", capabilities: ["browse", "filter", "select", "inspect", "proof", "create"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "approvals", owner: "Governance", title: "Approvals", icon: APPROVALS_APP_ICON_URI, route: "/__ioi/governance/approvals", canonical_route: "/governance/approvals", verifier: "scripts/verify-hypervisor-app-parity-approvals.mjs", certification: "pixel-certifications/approvals.json", capabilities: ["browse", "filter", "select", "inspect", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "incidents", owner: "Missions", title: "Issues", icon: ISSUES_APP_ICON_URI, route: "/__ioi/missions/incidents", verifier: "scripts/verify-hypervisor-app-parity-incidents.mjs", certification: "pixel-certifications/incidents.json", capabilities: ["browse", "filter", "proof"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "models", owner: "Foundry", title: "Model Catalog", icon: MODELS_APP_ICON_URI, route: "/__ioi/foundry/models", verifier: "scripts/verify-hypervisor-app-parity-foundry-models.mjs", certification: "pixel-certifications/models.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "listings", owner: "Marketplace", title: "Marketplace", icon: MARKETPLACE_APP_ICON_URI, route: "/__ioi/marketplace/listings", verifier: "scripts/verify-hypervisor-app-parity-listings.mjs", certification: "pixel-certifications/listings.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "designer", owner: "Studio", title: "Solution Designer", icon: DSG_APP_TILE_URI, route: "/__ioi/studio/designer", verifier: "scripts/verify-hypervisor-app-parity-studio-designer.mjs", certification: "pixel-certifications/designer.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs II Leg 1b: the Studio surface packet. A FRESH legacy action lane
  // (/__ioi/studio/workbench) — the /__ioi/agent-studio flat readout keeps serving untouched
  // until the W4 cutover (seed preservation) — plus the canonical /studio mount, where the module
  // rehomes the agent-estate lens read-first and adds blueprint/descriptor authoring over the
  // shared owner-scoped admission contract. Its evidence is the studio journey verifier (an
  // end-to-end live journey), not a pixel certification.
  { slug: "studio-home", owner: "Studio", title: "Studio", icon: DSG_APP_TILE_URI, route: "/__ioi/studio/workbench", canonical_route: "/studio", verifier: "scripts/verify-hypervisor-studio-journey.mjs", certification: "n/a", capabilities: ["browse", "select", "inspect", "create", "update", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // STU-1/STU-2 (remediation v2): the D6 combined-seed Workshop port (donor: module) — I-4 splash
  // grammar over the real domain-app + ODK surface-descriptor planes; atlas-backed, read-first.
  { slug: "workshop", owner: "Studio", title: "Workshop", icon: DSG_APP_TILE_URI, route: "/__ioi/studio/workshop", verifier: "scripts/verify-hypervisor-app-parity-workshop.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // DOM-1 (remediation v2): origin-aligned I-4 landings over typed-absent bodies.
  { slug: "logic", owner: "Domain Apps", title: "Logic", icon: DSG_APP_TILE_URI, route: "/__ioi/domain-apps/logic", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "contour", owner: "Domain Apps", title: "Contour", icon: DSG_APP_TILE_URI, route: "/__ioi/domain-apps/contour", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "widgets", owner: "Developer Console", title: "Custom Widgets", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-console/widgets", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "workspaces", owner: "Workbench", title: "Code Workspaces", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-workspace/workspaces", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "notepad", owner: "Workbench", title: "Notepad", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-workspace/notepad", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "devconsole", owner: "Developer Console", title: "Developer Console", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-console", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "machinery", owner: "Studio", title: "Machinery", icon: MCH_APP_TILE_URI, route: "/__ioi/studio/machinery", verifier: "scripts/verify-hypervisor-app-parity-studio-machinery.mjs", certification: "pixel-certifications/machinery.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.3 (next-legs II Leg 2): the Packages surface packet — ONE module, two mounts, over the
  // CLOSED /v1/hypervisor/packages daemon family. A FRESH legacy action lane
  // (/__ioi/packages/registry — the /__ioi/marketplace* seed lanes keep serving untouched until
  // their W4 cutover) plus the canonical /packages mount. The second row is the OPTIONAL
  // Marketplace mode at its canonical /packages/marketplace route (canon: "Packages /
  // Marketplace" — a mode of the Packages owner, never a second package owner; owner stays
  // "Packages", the module is the same, and the row exists so the canonical mode route is
  // module-served with truthful ownership markers). Evidence: the packages journey verifier.
  { slug: "packages", owner: "Packages", title: "Packages", icon: MARKETPLACE_APP_ICON_URI, route: "/__ioi/packages/registry", canonical_route: "/packages", verifier: "scripts/verify-hypervisor-packages-journey.mjs", certification: "n/a", capabilities: ["browse", "select", "inspect", "create", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "packages-marketplace", owner: "Packages", title: "Packages / Marketplace", icon: MARKETPLACE_APP_ICON_URI, route: "/__ioi/packages/marketplace", canonical_route: "/packages/marketplace", verifier: "scripts/verify-hypervisor-packages-journey.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs III Leg 3: the Applications greenfield launcher — canonical /applications
  // plus a FRESH legacy lane /__ioi/applications-launcher (the /__ioi/applications T2 readout
  // keeps serving untouched until the W4 cutover). GREENFIELD, typed non-parity
  // (seed-ux-provenance.v1.json: no provenance-qualified seed exists; the owner-authorized
  // greenfield lane is the only open path — this row claims no seed preservation and no
  // parity). The module is READ-ONLY BY CONTRACT: launch is navigation over the compiled
  // product-surface projection joined live with the package registry; it declares zero
  // actions because every admission-class verb belongs to its owner surface. Evidence: the
  // applications journey verifier.
  { slug: "applications", owner: "Applications", title: "Applications", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/applications-launcher", canonical_route: "/applications", verifier: "scripts/verify-hypervisor-applications-journey.mjs", certification: "n/a", capabilities: ["browse", "inspect"], operational_state: "read_only_by_contract", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs III Leg 4: the Systems greenfield workspace — canonical /systems plus a
  // FRESH legacy lane /__ioi/systems-workspace (the M1.6/M1.7 /__ioi/systems* genesis cockpit
  // keeps serving untouched until the W4 cutover). GREENFIELD, typed non-parity
  // (seed-ux-provenance.v1.json: no provenance-qualified seed exists; the owner-authorized
  // greenfield lane is the only open path — this row claims no seed preservation and no
  // parity). Inventory + detail render the daemon's autonomous-system read projection VERBATIM
  // (honest_empty and the fail-closed source-incomplete stop included); exactly TWO authority
  // verbs (genesis compose, sequence-zero) cross through the shared CapabilityLease client;
  // every other family verb is read-first or disabled with a named reason, and Interfaces is
  // the OQ-9 disabled named gap. Evidence: the systems journey verifier.
  { slug: "systems", owner: "Systems", title: "Systems", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/systems-workspace", canonical_route: "/systems", verifier: "scripts/verify-hypervisor-systems-journey.mjs", certification: "n/a", capabilities: ["browse", "inspect", "create", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "monitors", owner: "Automations", title: "Automate", icon: MON_APP_TILE_URI, route: "/__ioi/automations/monitors", verifier: "scripts/verify-hypervisor-app-parity-monitors.mjs", certification: "pixel-certifications/monitors.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs II Leg 4: the Automations surface packet — canonical /automations plus a
  // FRESH legacy lane /__ioi/automations-cockpit (deliberately NOT nested under
  // /__ioi/automations/, whose flat :id dispatch would shadow it; every seed lane there keeps
  // serving untouched until the W4 cutover). The module rehomes the T2 cockpit grammar
  // READ-FIRST over the shared read client; the daemon-owned verbs (create/patch/delete/run/
  // webhook-rotate) stay wired through the seed cockpit's own action lanes because the family
  // returns NO admission receipts yet (the brief's named W2 defect) — so the module declares no
  // receipted actions and its operational_state stays "inspect" honestly. Evidence: the
  // automations journey verifier.
  { slug: "automations", owner: "Automations", title: "Automations", icon: MON_APP_TILE_URI, route: "/__ioi/automations-cockpit", canonical_route: "/automations", verifier: "scripts/verify-hypervisor-automations-journey.mjs", certification: "n/a", capabilities: ["browse", "filter", "select", "inspect"], operational_state: "inspect", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs IV Leg 3: the Work PARTIAL PRE-W3 COCKPIT SLICE — NOT Work completion (W3.1
  // owns the admission→harness→run→events/receipts→stop/archive/recovery/replay chain; SURF-work
  // and W3.1 remain open). ONE module, three mounts, on FRESH non-colliding legacy lanes
  // (/__ioi/work-cockpit, /__ioi/work-sessions, /__ioi/work-new-session — deliberately NOT
  // /__ioi/sessions, whose T2 readout keeps serving untouched, and NOT nested under
  // /__ioi/work-ledger's branch). The landing rehomes the jobs/incidents cockpit grammar
  // READ-FIRST (rows link to the protected seeds /__ioi/missions + /__ioi/missions/incidents,
  // which keep serving untouched — seed-preservation invariant; the registry owner rename for
  // those seed rows is deferred to the full Work packet per the seed-ux-provenance
  // owner_mapping_note). Sessions renders lifecycle facts + the ADMITTED harness binding as
  // session truth; New Session owns the create mutation (202 + provision receipt) with NO subject
  // input — subject_attachments is EXACTLY [] AT CREATE (no masquerade at create). The C-1 subject
  // attachment now MATERIALIZES at LAUNCH via the W3.1 producer (POST harness-session-launches),
  // not at create; the launch-chain + work-cockpit verifiers both prove the [] → daemon-resolved
  // flip. Evidence: check:work-cockpit, check:launch-chain.
  { slug: "work", owner: "Work", title: "Work", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/work-cockpit", canonical_route: "/work", verifier: "scripts/verify-hypervisor-work-cockpit.mjs", certification: "n/a", capabilities: ["browse", "inspect"], operational_state: "inspect", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "work-sessions", owner: "Work", title: "Work / Sessions", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/work-sessions", canonical_route: "/work/sessions", verifier: "scripts/verify-hypervisor-work-cockpit.mjs", certification: "n/a", capabilities: ["browse", "filter", "select", "inspect", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "work-new-session", owner: "Work", title: "Work / New Session", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/work-new-session", canonical_route: "/work/new-session", verifier: "scripts/verify-hypervisor-work-cockpit.mjs", certification: "n/a", capabilities: ["browse", "create"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs IV Leg 4: the Home PARTIAL PRE-W3 COCKPIT SLICE — canonical /home plus a
  // FRESH legacy lane /__ioi/home-cockpit. NOT Home completion: SURF-home and W3.1 remain open;
  // the home-cockpit projection route (GET /v1/hypervisor/home-cockpit) is a typed W3 absence,
  // so the slice composes the same per-family reads the live /ai explorer composes — which
  // keeps serving untouched as a CURRENT LIVE ENTRY, never a substitute seed. Greenfield
  // canon-first on the typed non-parity lane (seed-ux-provenance.v1.json home record): no seed
  // preservation, no parity claims. Read-only by contract: Home launches, owns no object and
  // declares zero actions (New Session is Work's affordance advertised by navigation);
  // parked/failed-run rows render real counts with LIVE Operations deep-links (the
  // operations-mount named gap was re-ruled the day /operations landed). Evidence:
  // check:home-cockpit.
  { slug: "home", owner: "Home", title: "Home", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/home-cockpit", canonical_route: "/home", verifier: "scripts/verify-hypervisor-home-cockpit.mjs", certification: "n/a", capabilities: ["browse", "inspect"], operational_state: "inspect", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // W2.1 next-legs V Leg 4: the Operations PARTIAL PRE-W3 COCKPIT SLICE — canonical /operations
  // plus a FRESH legacy lane /__ioi/operations-cockpit. NOT Operations completion:
  // SURF-operations remains open — its full acceptance (injected-fault detection, typed
  // incident open, remediation/failover execution, restart/rollback/support export) is
  // W3.2/W3.3-owned, and its seed gate carries the typed-blocked scheduler residual (a block
  // record never opens work). Read-first by contract: eleven per-family daemon reads that
  // exist TODAY (scheduler health, execution health, failover runs/plans, environment
  // incidents/recovery, providers, spend reconciliation, storage backends/incidents,
  // substrate status); every W3.2/W3.3-owned verb is a typed disabled-named-gap naming its
  // owning unit; the W3 rollup projections (infrastructure-jobs, RPO/RTO, capacity overview)
  // are typed route-missing absences, never simulated. The T2 readout /__ioi/operations is
  // the rehome source and keeps serving untouched. Evidence: check:operations-cockpit.
  { slug: "operations", owner: "Operations", title: "Operations", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/operations-cockpit", canonical_route: "/operations", verifier: "scripts/verify-hypervisor-operations-cockpit.mjs", certification: "n/a", capabilities: ["browse", "inspect"], operational_state: "inspect", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "changes", owner: "Improvement", title: "Upgrade Assistant", icon: CHG_APP_TILE_URI, route: "/__ioi/improvement/changes", verifier: "scripts/verify-hypervisor-app-parity-changes.mjs", certification: "pixel-certifications/changes.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "evalsuites", owner: "Evaluations", title: "AIP Evals", icon: EVL_APP_TILE_URI, route: "/__ioi/evaluations/evalsuites", verifier: "scripts/verify-hypervisor-app-parity-evalsuites.mjs", certification: "pixel-certifications/evalsuites.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
];

// Fail-fast registry invariants: a typo'd capability or state is a boot error, not a silent lie.
for (const s of SURFACES) {
  if (!Array.isArray(s.capabilities) || s.capabilities.length === 0 || !s.capabilities.every((c) => CAPABILITIES.includes(c))) throw new Error(`surface-registry: '${s.slug}' has an invalid capabilities declaration`);
  if (!OPERATIONAL_STATES.includes(s.operational_state)) throw new Error(`surface-registry: '${s.slug}' has an invalid operational_state`);
  if (!EMBEDDED_SHELL_STATES.includes(s.embedded_shell_state)) throw new Error(`surface-registry: '${s.slug}' has an invalid embedded_shell_state`);
  // An application may be called operational inside Hypervisor only when the native rail is the
  // single platform rail in embedded mode (double-rail shells never advance past "shell").
  if (s.operational_state !== "shell" && s.embedded_shell_state !== "native_single_rail") throw new Error(`surface-registry: '${s.slug}' is ${s.operational_state} but not native_single_rail when embedded`);
  if (!INTERACTION_PARITY_STATES.includes(s.interaction_parity_state)) throw new Error(`surface-registry: '${s.slug}' has an invalid interaction_parity_state`);
}

export function surfaceBySlug(slug) {
  return SURFACES.find((s) => s.slug === slug) || null;
}

// slug -> { loaders?: async (url) => data, render: (data, url) => html, actions?: [...] }
const bound = new Map();

export function bindSurface(slug, impl) {
  const s = surfaceBySlug(slug);
  if (!s) throw new Error(`bindSurface: unknown surface '${slug}' — add it to SURFACES first`);
  if (typeof impl.render !== "function") throw new Error(`bindSurface('${slug}'): impl.render must be a function`);
  bound.set(slug, impl);
}

export function boundSurface(pathname, method) {
  if (method !== "GET") return null;
  for (const s of SURFACES) {
    const impl = bound.get(s.slug);
    // W2.1 rehome: a bound module may ALSO serve at its canonical v2 route. Same module, same
    // contract — the canonical mount is the rehome, the legacy /__ioi/* route keeps serving
    // untouched until the surface's W4 cutover (seed-preservation invariant).
    if (impl && (pathname === s.route || (s.canonical_route && pathname === s.canonical_route))) {
      return { surface: s, impl };
    }
  }
  return null;
}

// The v2 shell dispatch consults this to YIELD canonical paths a bound module owns: the shell
// page must never shadow a rehomed surface, and an UNBOUND canonical route falls back to the
// honest shell rather than a 404 — registration stays additive.
export function canonicalSurfaceRoute(pathname) {
  for (const s of SURFACES) {
    if (s.canonical_route && s.canonical_route === pathname && bound.get(s.slug)) return s;
  }
  return null;
}

// Routes that support the embedded render mode (`embed=1`) — EVERY registry surface (native
// container contract #65: flat handlers render embedded through the serve choke point, modules
// through ctx.embed) plus the non-registry estate surfaces that cross-application journeys
// traverse (they ship no ported rail; threading embed through them keeps a chain that re-enters
// a registry surface embedded). The embed rewrite threads the flag only through links that land
// on one of these routes.
export const EMBED_THREAD_ROUTES = ["/__ioi/lineage", "/__ioi/vertex", "/__ioi/work-ledger", "/__ioi/operations"];
export function embeddableRoutes() {
  return new Set([...SURFACES.map((s) => s.route), ...SURFACES.filter((s) => s.canonical_route).map((s) => s.canonical_route), ...EMBED_THREAD_ROUTES]);
}

// ---- Action routes (operational wave #62) — a module's DECLARED mutations, matched beneath its
// own surface route (e.g. actions with route "/:id/transition" own POST <route>/<id>/transition).
// Several descriptors may share one route (discriminated by the posted transition vocabulary);
// the runtime picks among the returned candidates. Anything undeclared fails closed upstream.
function actionRouteMatch(pattern, tail) {
  const ps = pattern.split("/").filter(Boolean);
  const ts = tail.split("/").filter(Boolean);
  if (ps.length !== ts.length) return false;
  return ps.every((seg, i) => (seg.startsWith(":") ? ts[i].length > 0 : seg === ts[i]));
}
// A ROW'S DECLARED TIER GATES ITS ACTION ROUTES.
//
// One module may serve several mounts — packages/marketplace, and work landing/sessions/new-session
// — and this resolver matched beneath EVERY row bound to that module, so the module's whole action
// list was reachable under a mount the registry declares read-tier. `packages-marketplace` is
// `browse` and exposed all FIVE of the module's actions — `admit-candidate`, `cut-release`,
// `recall-release`, `install-release` and `uninstall` (an earlier count of this said four and
// dropped `admit-candidate`, which is the admission verb and the one that matters most);
// `work` is `inspect` and
// exposed `create-session` and the launch verbs. The registry said one thing and the dispatch did
// another, and the check that would have caught it had been crashing for months.
//
// The product's own forms already target the acting mounts (`LEGACY_ROUTE`, `LEGACY_SESSIONS`,
// `LEGACY_NEW_SESSION`), so this closes a hole nothing was walking through — but "nothing walks
// through it" is not a boundary. The declared tier is.
const ACTING_STATES = new Set(["act", "workflow_complete"]);
export function boundActionRoute(pathname, method) {
  for (const s of SURFACES) {
    const impl = bound.get(s.slug);
    if (!impl || typeof impl.handleAction !== "function" || !Array.isArray(impl.actions) || !impl.actions.length) continue;
    if (!ACTING_STATES.has(s.operational_state)) continue;
    if (!pathname.startsWith(s.route + "/")) continue;
    const tail = pathname.slice(s.route.length);
    const candidates = impl.actions.filter((a) => a.method === method && a.route && actionRouteMatch(a.route, tail));
    if (candidates.length) {
      let recordId = tail.split("/").filter(Boolean)[0] || "";
      try { recordId = decodeURIComponent(recordId); } catch { /* keep raw — the daemon lookup fails closed */ }
      return { surface: s, impl, actions: candidates, recordId };
    }
  }
  return null;
}

// ---- Extracted surface modules — imported and bound here (the registry IS the mount point).
bindSurface("pipeline", pipelineModule);
bindSurface("schema", ontologyManagerModule);
bindSurface("explorer", objectExplorerModule);
bindSurface("approvals", approvalsModule);
bindSurface("sources", sourcesModule);
bindSurface("missions", missionsModule);
bindSurface("studio-home", studioModule);
// Packages: BOTH rows bind the one module — the module branches on the served pathname (the
// marketplace mounts render the read-first mode); ownership markers stay per-row truthful.
bindSurface("packages", packagesModule);
bindSurface("packages-marketplace", packagesModule);
bindSurface("automations", automationsModule);
bindSurface("applications", applicationsModule);
bindSurface("systems", systemsModule);
// Work: ALL THREE rows bind the one module — the module branches on the served pathname
// (landing / sessions / new-session); ownership markers stay per-row truthful. Only the
// new-session row is "act": it declares the single receipted create action.
bindSurface("work", workModule);
bindSurface("work-sessions", workModule);
bindSurface("work-new-session", workModule);
// Home: one row, one module — the partial pre-W3 cockpit slice (read-only, zero actions).
bindSurface("home", homeModule);
// Operations: one row, one module — the partial pre-W3 cockpit slice (read-first, zero actions).
bindSurface("operations", operationsModule);

// Test-only fault surface (NEVER without the runtime-test flag): gives the action-runtime
// verifier a module whose action THROWS (route isolation proof) and one that claims success
// WITHOUT a receipt (fail-closed proof). Carries no daemon authority and mutates nothing.
//
// `act`, NOT `browse`, and the tier gate below is why. This row declares two receipted POST
// actions and exists so `verify-hypervisor-action-runtime.mjs` can prove route-local containment
// and receipt-fail-closed against them. Declared `browse`, the tier gate skipped it,
// `boundActionRoute` returned null, both POSTs fell through to the SPA catch-all as 200, and the
// estate's only proof of those two properties died — silently, because that verifier has no npm
// script, no CI job and no floor row. The row satisfies the `act` boot invariant on its own terms:
// a bound module with `handleAction` and receipted, authority-carrying mutations.
if (process.env.IOI_APP_RUNTIME_TEST_ROUTE === "1") {
  SURFACES.push({ slug: "__test_action", owner: "Test", title: "Action Runtime Test", icon: "data:,x", route: "/__ioi/__test/action-surface", verifier: "n/a", certification: "n/a", capabilities: ["browse", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" });
  bindSurface("__test_action", {
    meta: { slug: "__test_action", route: "/__ioi/__test/action-surface" },
    load: async () => ({}),
    render: () => "<!doctype html><title>action test</title><body>ok</body>",
    actions: [
      { id: "boom", method: "POST", route: "/:id/transition", transition: "boom", fields: [], context: ["id"], authority: { plane: "test", operation: "none" }, receipt: "test.v1", confirm: false, success: "return-to-surface", refusal: "typed-banner" },
      { id: "no-receipt", method: "POST", route: "/:id/transition", transition: "no-receipt", fields: [], context: ["id"], authority: { plane: "test", operation: "none" }, receipt: "test.v1", confirm: false, success: "return-to-surface", refusal: "typed-banner" },
    ],
    handleAction: async ({ action }) => {
      if (action.transition === "boom") throw new Error("intentional action fault (action-runtime verifier)");
      return { kind: "success", status: "done" }; // deliberately NO receipt_ref — must fail closed
    },
  });
}

// Operational invariants (#62): `act` is EARNED by a bound module with declared receipted
// mutations — never by raw POST routes outside a module, and never by pixel certification.
for (const s of SURFACES) {
  const impl = bound.get(s.slug);
  const mutations = impl && Array.isArray(impl.actions) ? impl.actions.filter((a) => a.method && a.method !== "GET") : [];
  if (s.operational_state === "act" || s.operational_state === "workflow_complete") {
    if (!impl || typeof impl.handleAction !== "function" || mutations.length === 0) throw new Error(`surface-registry: '${s.slug}' claims operational_state '${s.operational_state}' without a bound module declaring receipted actions`);
    if (!mutations.every((a) => a.id && a.authority && a.authority.operation && a.receipt)) throw new Error(`surface-registry: '${s.slug}' declares an action without authority + receipt metadata`);
  }
  if (s.operational_state === "read_only_by_contract" && mutations.length > 0) throw new Error(`surface-registry: '${s.slug}' is read_only_by_contract but registers mutation actions`);
}
