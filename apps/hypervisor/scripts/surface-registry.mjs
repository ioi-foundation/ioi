// The surface registry — the explicit table of ported application surfaces (functional-runtime
// wave). Each entry is the CODE-side identity of one certified port: slug (joins the parity
// matrix + pixel certification, the EVIDENCE side), owner family, display title + app tile icon
// (presentation truth — app-catalog.mjs reads it from here), canonical route, and the paths of
// its verifier + certification artifact.
//
// Implementations bind at runtime: serve-product-ui.mjs calls bindSurface(slug, { loaders,
// render, actions }) for surfaces whose code still lives in the serve file, and the serve's
// registry dispatch mounts whatever is bound. As apps extract into their own modules (next PRs),
// the module itself becomes the binding — the table stays the single mount point either way.
// An entry with no binding is metadata-only: it lists in the catalog but keeps its flat-branch
// handler until it is deliberately migrated. Registration is additive and behavior-preserving.
import { ONTOLOGY_APP_ICON_URI, APPROVALS_APP_ICON_URI, PIPELINE_APP_ICON_URI, ISSUES_APP_ICON_URI, EXPLORER_APP_ICON_URI, MODELS_APP_ICON_URI } from "./bp-icons.mjs";
import { MARKETPLACE_APP_ICON_URI } from "./marketplace-assets.mjs";
import { DSG_APP_TILE_URI } from "./designer-assets.mjs";
import { MCH_APP_TILE_URI } from "./machinery-assets.mjs";
import { MON_APP_TILE_URI } from "./monitors-assets.mjs";
import { SRC_APP_TILE_URI } from "./sources-assets.mjs";
import { CHG_APP_TILE_URI } from "./changes-assets.mjs";
import { EVL_APP_TILE_URI } from "./evalsuites-assets.mjs";

export const SURFACES = [
  { slug: "pipeline", owner: "Data", title: "Pipeline Builder", icon: PIPELINE_APP_ICON_URI, route: "/__ioi/pipeline", verifier: "scripts/verify-hypervisor-app-parity-pipeline.mjs", certification: "pixel-certifications/pipeline.json" },
  { slug: "sources", owner: "Data", title: "Data Connection", icon: SRC_APP_TILE_URI, route: "/__ioi/data/sources", verifier: "scripts/verify-hypervisor-app-parity-sources.mjs", certification: "pixel-certifications/sources.json" },
  { slug: "schema", owner: "Ontology", title: "Ontology Manager", icon: ONTOLOGY_APP_ICON_URI, route: "/__ioi/ontology/manager", verifier: "scripts/verify-hypervisor-app-parity-ontology-manager.mjs", certification: "pixel-certifications/schema.json" },
  { slug: "explorer", owner: "Ontology", title: "Object Explorer", icon: EXPLORER_APP_ICON_URI, route: "/__ioi/ontology/explorer", verifier: "scripts/verify-hypervisor-app-parity-object-explorer.mjs", certification: "pixel-certifications/explorer.json" },
  { slug: "approvals", owner: "Governance", title: "Approvals", icon: APPROVALS_APP_ICON_URI, route: "/__ioi/governance/approvals", verifier: "scripts/verify-hypervisor-app-parity-approvals.mjs", certification: "pixel-certifications/approvals.json" },
  { slug: "incidents", owner: "Missions", title: "Issues", icon: ISSUES_APP_ICON_URI, route: "/__ioi/missions/incidents", verifier: "scripts/verify-hypervisor-app-parity-incidents.mjs", certification: "pixel-certifications/incidents.json" },
  { slug: "models", owner: "Foundry", title: "Model Catalog", icon: MODELS_APP_ICON_URI, route: "/__ioi/foundry/models", verifier: "scripts/verify-hypervisor-app-parity-foundry-models.mjs", certification: "pixel-certifications/models.json" },
  { slug: "listings", owner: "Marketplace", title: "Marketplace", icon: MARKETPLACE_APP_ICON_URI, route: "/__ioi/marketplace/listings", verifier: "scripts/verify-hypervisor-app-parity-listings.mjs", certification: "pixel-certifications/listings.json" },
  { slug: "designer", owner: "Studio", title: "Solution Designer", icon: DSG_APP_TILE_URI, route: "/__ioi/studio/designer", verifier: "scripts/verify-hypervisor-app-parity-studio-designer.mjs", certification: "pixel-certifications/designer.json" },
  { slug: "machinery", owner: "Studio", title: "Machinery", icon: MCH_APP_TILE_URI, route: "/__ioi/studio/machinery", verifier: "scripts/verify-hypervisor-app-parity-studio-machinery.mjs", certification: "pixel-certifications/machinery.json" },
  { slug: "monitors", owner: "Automations", title: "Automate", icon: MON_APP_TILE_URI, route: "/__ioi/automations/monitors", verifier: "scripts/verify-hypervisor-app-parity-monitors.mjs", certification: "pixel-certifications/monitors.json" },
  { slug: "changes", owner: "Improvement", title: "Upgrade Assistant", icon: CHG_APP_TILE_URI, route: "/__ioi/improvement/changes", verifier: "scripts/verify-hypervisor-app-parity-changes.mjs", certification: "pixel-certifications/changes.json" },
  { slug: "evalsuites", owner: "Evaluations", title: "AIP Evals", icon: EVL_APP_TILE_URI, route: "/__ioi/evaluations/evalsuites", verifier: "scripts/verify-hypervisor-app-parity-evalsuites.mjs", certification: "pixel-certifications/evalsuites.json" },
];

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
