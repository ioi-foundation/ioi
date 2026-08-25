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
  // FUS-1 (remediation v2): the live-tenant-sourced Fusion port — the reference click target
  // resolves to a PROJECTS-&-FILES browser (4 tabs), not a spreadsheet; All files = the real
  // projects plane, Data Catalog > Files = the real data-asset planes, the rest typed absences.
  { slug: "fusion", owner: "Domain Apps", title: "Fusion", icon: DSG_APP_TILE_URI, route: "/__ioi/domain-apps/fusion", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // MAP-1 (remediation v2): the live-tenant-sourced Map port — CANVAS grammar over a canvas the
  // estate cannot honestly render. No geospatial plane exists in the daemon's 753 routes, so the
  // canvas region is a TYPED ABSENCE (missing, not empty) and the one live lane is deliberately
  // NOT a map: the placement plane's region/location/zone/az strings, rendered verbatim.
  { slug: "map", owner: "Environments", title: "Map", icon: DSG_APP_TILE_URI, route: "/__ioi/environments/map", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // REG-1 (remediation v2): the live-tenant-sourced Artifacts port — a READ-ONLY projection
  // of the estate's registry LADDER (packages · marketplace publish ladder · release controls
  // · SCM publication), classified live into four states (LIVE / EMPTY / REFUSED / NO READ
  // ROUTE). The verbs stay on the Packages + Marketplace owner surfaces and are linked, never
  // duplicated here.
  { slug: "registry", owner: "Marketplace", title: "Artifacts", icon: MARKETPLACE_APP_ICON_URI, route: "/__ioi/marketplace/artifacts", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // JOB-1 (remediation v2): the live-tenant-sourced Builds port — a READ-ONLY projection of the
  // estate's build plane (the work ledger's `run` lane, the exact UNION of the transcript and
  // per-automation projections and the only plane carrying both the acting authority and the
  // state root). Sixteen run/build planes are classified live into four states. The build VERBS
  // stay on Automations and are linked, never duplicated; /__ioi/missions — the read_only_by_contract
  // substrate — is untouched and this is a sibling lane beside it, not a replacement.
  { slug: "jobs", owner: "Missions", title: "Builds", icon: missionsModule.MISSIONS_APP_ICON_URI, route: "/__ioi/missions/builds", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // SCH-1 (remediation v2): the live-tenant-sourced Build Schedules port — a READ-ONLY projection
  // of the estate's ONLY cadence: the automation records carrying a schedule_spec. Fifteen
  // schedule/cadence-adjacent planes are classified live into four states (and three shapes: a
  // collection, a status singleton, a pure computation). The schedule VERBS stay on Automations
  // (a schedule is a FIELD on an automation, so "create a schedule" is create/patch an automation)
  // and the fires themselves stay on Builds — both linked, neither re-rendered here.
  { slug: "scheduler", owner: "Missions", title: "Build Schedules", icon: missionsModule.MISSIONS_APP_ICON_URI, route: "/__ioi/missions/schedules", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // ING-1 (remediation v2): the live-tenant-sourced HyperAuto port — a READ-ONLY projection of the
  // estate's ingestion CHAIN, joined end to end from the keys the records themselves carry
  // (connector_mapping_id · data_source_id · materializing_run_id · ontology_projection_id). Twenty-one
  // ingestion-chain and adjacent planes are classified live into four states. The chain VERBS stay
  // on Pipeline Builder and the Connections lease gate; the source plane and its Syncs lane stay on
  // Data Connection and the extracted objects stay on the Object Explorer — all linked, none re-rendered.
  { slug: "ingest", owner: "Data", title: "HyperAuto", icon: SRC_APP_TILE_URI, route: "/__ioi/data/ingest", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // MS-1 (remediation v2): the live-tenant-sourced Model Studio port — the seed whose live ROOT is
  // a CREATION-ENTRY DIALOG ("Choose file location": a pre-filled File name, a Location folder
  // dropdown, Browse/Cancel/Save) over rows:0, not an editor canvas and not a list. The dialog IS
  // the landing grammar, rendered over the estate's REAL location plane (projects) and its REAL
  // file plane (foundry draft specs), with twenty-two file/location/binding/adjacent planes
  // classified live into four states. THE FINDING: a verb whose route exists is still a GAP when
  // the form's fields and the route's required fields do not intersect — POST foundry/specs is
  // published and real, carries no location field at all, and demands a model-route/provider
  // binding the dialog never asks for, so Save is a typed absence and no second spine is minted.
  { slug: "modelstudio", owner: "Foundry", title: "Model Studio", icon: MODELS_APP_ICON_URI, route: "/__ioi/foundry/model-studio", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  // INF-1 (remediation v2): the live-tenant-sourced Inference port, and the LAST leg of the
  // live-tenant port backlog. The seed's live ROOT is a SPACE GATE — heading "Please select a
  // space" over ONE app control, "Select a space…", rows 0, no space picked — and the capture's
  // second heading (a platform news dialog) plus the rail's last-visited-app entry are named as
  // EXCLUDED JUNK EVIDENCE rather than ported. The gate renders over the estate's REAL space plane
  // (projects) with twenty-seven space/invocation/model/adjacent planes classified live into four
  // states. THE FINDING: a SELECTION THE ROUTE ACCEPTS is still a GAP when the key it filters on is
  // never written by the records it is meant to scope — the work ledger accepts ?project= and
  // applies it, and 0 of the ledger rows that name a model carry the key it retains on, so a wired
  // chooser would drop every recorded invocation and print the loss as an empty space.
  { slug: "inference", owner: "Foundry", title: "Inference", icon: MODELS_APP_ICON_URI, route: "/__ioi/foundry/inference", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "widgets", owner: "Developer Console", title: "Custom Widgets", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-console/widgets", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "workspaces", owner: "Workbench", title: "Code Workspaces", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-workspace/workspaces", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "notepad", owner: "Workbench", title: "Notepad", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-workspace/notepad", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "devconsole", owner: "Developer Console", title: "Developer Console", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-console", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "insight", owner: "Evaluations", title: "Insight", icon: EVL_APP_TILE_URI, route: "/__ioi/evaluations/insight", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "repositories", owner: "Workbench", title: "Code Repositories", icon: DSG_APP_TILE_URI, route: "/__ioi/developer-workspace/repositories", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "quiver", owner: "Evaluations", title: "Quiver", icon: EVL_APP_TILE_URI, route: "/__ioi/evaluations/quiver", verifier: "scripts/verify-hypervisor-app-parity-domain-landings.mjs", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
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
  // E7 COCKPIT RETIREMENT (2026-08-20, owner go recorded in reference-remediation-ledger.v1.json):
  // the eight legacy daemon-projection cockpit rows that used to sit here — applications ·
  // systems · automations · work · work-sessions · work-new-session · home · operations, on the
  // /__ioi/*-cockpit / -launcher / -workspace / -sessions lanes — are GONE, with their modules
  // (surfaces/{applications,systems,automations,work,home,operations}/index.mjs) and their
  // dedicated verifiers. The E7 end-state ruling is that clicking an application shows ONLY the
  // designated modified seed; the retirement was realized at the navigation layer first (nothing
  // in the served shell linked them and the native-shell reachability gate proved it), and this
  // is the code removal that made the two named E7 exclusion lists inert and deletable. The LIVE
  // siblings those modules were rehomed FROM keep serving untouched: /__ioi/applications ·
  // /__ioi/systems · /__ioi/automations · /__ioi/missions · /__ioi/missions/incidents ·
  // /__ioi/sessions · /__ioi/home · /__ioi/operations · /__ioi/work-ledger. The canonical nav
  // routes (/applications · /systems · /work · /work/sessions · /work/new-session · /home ·
  // /operations) fall back to the honest v2 route-shell page, which names what serves them today
  // — they stay GRE in landing-designations.v1.json pending the GRE-1 owner ruling.
  { slug: "monitors", owner: "Automations", title: "Automate", icon: MON_APP_TILE_URI, route: "/__ioi/automations/monitors", canonical_route: "/automations", verifier: "scripts/verify-hypervisor-app-parity-monitors.mjs", certification: "pixel-certifications/monitors.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
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
// E7 (2026-08-20): the eight legacy cockpit bindings were removed with their rows and modules.

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
