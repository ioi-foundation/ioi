// The surface registry — the explicit table of ported application surfaces (functional-runtime
// wave). Each entry is the CODE-side identity of one certified port: slug (joins the parity
// matrix + pixel certification, the EVIDENCE side), owner family, display title + app tile icon
// (presentation truth — app-catalog.mjs reads it from here), canonical route, and the paths of
// its verifier + certification artifact.
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
  { slug: "pipeline", owner: "Data", title: "Pipeline Builder", icon: PIPELINE_APP_ICON_URI, route: "/__ioi/pipeline", verifier: "scripts/verify-hypervisor-app-parity-pipeline.mjs", certification: "pixel-certifications/pipeline.json", capabilities: ["browse", "select", "inspect", "proof"], operational_state: "inspect", embedded_shell_state: "native_single_rail", interaction_parity_state: "atlas_verified" },
  { slug: "sources", owner: "Data", title: "Data Connection", icon: SRC_APP_TILE_URI, route: "/__ioi/data/sources", verifier: "scripts/verify-hypervisor-app-parity-sources.mjs", certification: "pixel-certifications/sources.json", capabilities: ["browse", "select"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "schema", owner: "Ontology", title: "Ontology Manager", icon: ONTOLOGY_APP_ICON_URI, route: "/__ioi/ontology/manager", verifier: "scripts/verify-hypervisor-app-parity-ontology-manager.mjs", certification: "pixel-certifications/schema.json", capabilities: ["browse", "filter", "select", "inspect", "create", "update", "proof"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "explorer", owner: "Ontology", title: "Object Explorer", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/ontology/explorer", verifier: "scripts/verify-hypervisor-app-parity-object-explorer.mjs", certification: "pixel-certifications/explorer.json", capabilities: ["browse", "filter", "select", "inspect", "proof"], operational_state: "inspect", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "approvals", owner: "Governance", title: "Approvals", icon: APPROVALS_APP_ICON_URI, route: "/__ioi/governance/approvals", verifier: "scripts/verify-hypervisor-app-parity-approvals.mjs", certification: "pixel-certifications/approvals.json", capabilities: ["browse", "filter", "select", "inspect", "transition"], operational_state: "act", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "incidents", owner: "Missions", title: "Issues", icon: ISSUES_APP_ICON_URI, route: "/__ioi/missions/incidents", verifier: "scripts/verify-hypervisor-app-parity-incidents.mjs", certification: "pixel-certifications/incidents.json", capabilities: ["browse", "filter", "proof"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "models", owner: "Foundry", title: "Model Catalog", icon: MODELS_APP_ICON_URI, route: "/__ioi/foundry/models", verifier: "scripts/verify-hypervisor-app-parity-foundry-models.mjs", certification: "pixel-certifications/models.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "listings", owner: "Marketplace", title: "Marketplace", icon: MARKETPLACE_APP_ICON_URI, route: "/__ioi/marketplace/listings", verifier: "scripts/verify-hypervisor-app-parity-listings.mjs", certification: "pixel-certifications/listings.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "designer", owner: "Studio", title: "Solution Designer", icon: DSG_APP_TILE_URI, route: "/__ioi/studio/designer", verifier: "scripts/verify-hypervisor-app-parity-studio-designer.mjs", certification: "pixel-certifications/designer.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "machinery", owner: "Studio", title: "Machinery", icon: MCH_APP_TILE_URI, route: "/__ioi/studio/machinery", verifier: "scripts/verify-hypervisor-app-parity-studio-machinery.mjs", certification: "pixel-certifications/machinery.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
  { slug: "monitors", owner: "Automations", title: "Automate", icon: MON_APP_TILE_URI, route: "/__ioi/automations/monitors", verifier: "scripts/verify-hypervisor-app-parity-monitors.mjs", certification: "pixel-certifications/monitors.json", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" },
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
    if (impl && pathname === s.route) return { surface: s, impl };
  }
  return null;
}

// Routes that support the embedded render mode (`embed=1`) — EVERY registry surface (native
// container contract #65: flat handlers render embedded through the serve choke point, modules
// through ctx.embed) plus the native semantic-plane surfaces the cross-application journey
// traverses (they ship no ported rail; threading embed through them keeps a chain that re-enters
// a registry surface embedded). The embed rewrite threads the flag only through links that land
// on one of these routes.
export const EMBED_THREAD_ROUTES = ["/__ioi/lineage", "/__ioi/vertex", "/__ioi/work-ledger"];
export function embeddableRoutes() {
  return new Set([...SURFACES.map((s) => s.route), ...EMBED_THREAD_ROUTES]);
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
export function boundActionRoute(pathname, method) {
  for (const s of SURFACES) {
    const impl = bound.get(s.slug);
    if (!impl || typeof impl.handleAction !== "function" || !Array.isArray(impl.actions) || !impl.actions.length) continue;
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

// Test-only fault surface (NEVER without the runtime-test flag): gives the action-runtime
// verifier a module whose action THROWS (route isolation proof) and one that claims success
// WITHOUT a receipt (fail-closed proof). Carries no daemon authority and mutates nothing.
if (process.env.IOI_APP_RUNTIME_TEST_ROUTE === "1") {
  SURFACES.push({ slug: "__test_action", owner: "Test", title: "Action Runtime Test", icon: "data:,x", route: "/__ioi/__test/action-surface", verifier: "n/a", certification: "n/a", capabilities: ["browse"], operational_state: "browse", embedded_shell_state: "native_single_rail", interaction_parity_state: "none" });
  bindSurface("__test_action", {
    meta: { slug: "__test_action", route: "/__ioi/__test/action-surface" },
    load: async () => ({}),
    render: () => "<!doctype html><title>action test</title>ok",
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
  if (s.operational_state === "act") {
    if (!impl || typeof impl.handleAction !== "function" || mutations.length === 0) throw new Error(`surface-registry: '${s.slug}' claims operational_state 'act' without a bound module declaring receipted actions`);
    if (!mutations.every((a) => a.id && a.authority && a.authority.operation && a.receipt)) throw new Error(`surface-registry: '${s.slug}' declares an action without authority + receipt metadata`);
  }
  if (s.operational_state === "read_only_by_contract" && mutations.length > 0) throw new Error(`surface-registry: '${s.slug}' is read_only_by_contract but registers mutation actions`);
}
