#!/usr/bin/env node
// Product-surface catalog verifier — taxonomy-v2 membership and certified-tool rebase.
//
// Proves that typed registrations, not capture/parity/pixel evidence, create applications and
// workspaces; every certified runtime surface has one explicit contextual placement; stale
// Missions/Marketplace/Workbench ownership is retired; and planned surfaces remain nonlaunchable.

import { readFileSync } from "node:fs";
import vm from "node:vm";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { compileApplicationCatalog } from "./app-catalog.mjs";
import { SURFACES } from "./surface-registry.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const results = [];
const ok = (name, condition, detail = "") => results.push({ name, pass: Boolean(condition), detail });

const EXPECTED = {
  pipeline: ["tool_surface", "application:data", "Data / Recipes"],
  sources: ["tool_surface", "application:data", "Data / Sources"],
  schema: ["tool_surface", "application:ontology", "Ontology / Schema"],
  explorer: ["tool_surface", "application:ontology", "Ontology / Explore"],
  approvals: ["tool_surface", "application:governance", "Governance / Approvals"],
  incidents: ["workspace_view", "workspace:work", "Work / Incidents"],
  models: ["tool_surface", "application:foundry", "Foundry / Models"],
  listings: ["tool_surface", "application:packages", "Packages / Marketplace"],
  designer: ["tool_surface", "application:studio", "Studio / System Design"],
  machinery: ["tool_surface", "application:automations", "Automations / Process Graphs"],
  monitors: ["tool_surface", "application:automations", "Automations / Monitors"],
  changes: ["tool_surface", "application:improvement", "Improvement / Changes"],
  evalsuites: ["tool_surface", "application:evaluations", "Evaluations / Suites"],
};

async function run() {
  const catalog = compileApplicationCatalog();
  const contextual = [...catalog.tools, ...catalog.workspace_views];
  const owners = catalog.applications.filter((entry) => entry.registration_kind === "owner_application" && entry.owner_cohort === "enduring");
  const substrate = catalog.applications.filter((entry) => entry.registration_kind === "substrate_application");
  const conditional = catalog.applications.filter((entry) => entry.registration_kind === "owner_application" && entry.owner_cohort === "conditional");

  ok("catalog schema and taxonomy version are v2", catalog.schema === "ioi.hypervisor.application-catalog.v2" && /\.v2$/.test(catalog.taxonomy_version));
  ok("membership source is typed registration and evidence-independent", catalog.membership_source === "typed_product_registration" && catalog.evidence_membership_independent === true);
  ok("shadow projection names its unconnected policy and extension-inventory boundaries", catalog.projection_state === "transitional_static" && catalog.policy_filtering_state === "not_connected" && catalog.extension_inventory_state === "not_connected");
  ok("target census is 21 rows: 5 workspaces + 12 owners + 2 substrate + 1 conditional + 1 extension class", catalog.core_workspaces.length === 5 && owners.length === 12 && substrate.length === 2 && conditional.length === 1 && Boolean(catalog.extension_application_contract));
  ok("no legacy flattened apps projection survives", !Object.prototype.hasOwnProperty.call(catalog, "apps"));

  const appNames = new Set(catalog.applications.map((entry) => entry.name));
  ok("retired peer identities are absent", !appNames.has("Missions") && !appNames.has("Marketplace") && !appNames.has("Workbench"));
  ok("replacement identities are registered", appNames.has("Packages") && appNames.has("Developer Workspace"));
  const embodied = catalog.applications.find((entry) => entry.name === "Embodied Systems");
  ok("Embodied Systems stays an owner_application; conditionality is availability/placement posture", embodied?.registration_kind === "owner_application" && embodied?.owner_cohort === "conditional" && embodied?.availability === "planned" && embodied?.launchable === false && embodied?.launch_route === null);
  ok("extension contract keeps origin, creation, and distribution axes independent while inventory stays unconnected", catalog.extension_applications.length === 0 && catalog.extension_application_contract.surface_class === "extension_application" && catalog.extension_application_contract.inventory_state === "not_connected" && catalog.extension_application_contract.surface_origins.includes("organization") && catalog.extension_application_contract.surface_creation_methods.includes("studio_generated") && catalog.extension_application_contract.surface_distribution_channels.includes("marketplace") && !Object.prototype.hasOwnProperty.call(catalog.extension_application_contract, "supported_origins"));

  ok("all 13 certified runtime surfaces have exactly one contextual placement", contextual.length === 13 && new Set(contextual.map((entry) => entry.slug)).size === 13);
  ok("twelve are tools and Issues is the one Work view", catalog.tools.length === 12 && catalog.workspace_views.length === 1 && catalog.workspace_views[0]?.slug === "incidents");
  ok("no certified surface is a peer application", contextual.every((entry) => entry.peer_application === false) && !catalog.applications.some((entry) => contextual.some((surface) => surface.ref === entry.ref)));
  ok("every contextual surface resolves to a registered owner", contextual.every((entry) => [...catalog.applications, ...catalog.core_workspaces].some((owner) => owner.ref === entry.placement_owner_ref)));
  ok("every contextual serving route remains honest and launchable", contextual.every((entry) => entry.launchable && entry.launch_route.startsWith("/__ioi/") && entry.route_posture === "compatibility_alias" && entry.canonical_target_route.startsWith("/")));
  ok("contextual refs and launch routes are unique", new Set(contextual.map((entry) => entry.ref)).size === contextual.length && new Set(contextual.map((entry) => entry.launch_route)).size === contextual.length);

  for (const [slug, expected] of Object.entries(EXPECTED)) {
    const entry = contextual.find((surface) => surface.slug === slug);
    ok(`${slug} has its exact taxonomy-v2 placement`, entry?.registration_kind === expected[0] && entry?.placement_owner_ref === expected[1] && entry?.placement === expected[2], entry ? `${entry.registration_kind} · ${entry.placement_owner_ref} · ${entry.placement}` : "missing");
  }

  const source = readFileSync(join(HERE, "app-catalog.mjs"), "utf8");
  ok("catalog compiler does not read parity or pixel membership inputs", !source.includes("harvest-app-parity-matrix") && !source.includes("shell_pixel_certified"));
  const evidenceChanged = compileApplicationCatalog({
    surfaceRegistrations: SURFACES.map((entry) => ({ ...entry, certification: null, verifier: "changed-evidence-only" })),
  });
  ok("changing certification evidence cannot change product membership or placement", JSON.stringify({
    workspaces: evidenceChanged.core_workspaces.map((entry) => entry.ref),
    applications: evidenceChanged.applications.map((entry) => entry.ref),
    contextual: [...evidenceChanged.tools, ...evidenceChanged.workspace_views].map((entry) => [entry.ref, entry.placement_owner_ref, entry.placement]),
  }) === JSON.stringify({
    workspaces: catalog.core_workspaces.map((entry) => entry.ref),
    applications: catalog.applications.map((entry) => entry.ref),
    contextual: contextual.map((entry) => [entry.ref, entry.placement_owner_ref, entry.placement]),
  }));

  const explicit = {
    ...SURFACES[0],
    slug: "catalog-explicit-fixture",
    title: "Explicit Fixture",
    served_title: "Explicit Fixture",
    placement: "Data / Explicit Fixture",
    route: "/__ioi/__test/explicit-fixture",
    canonical_target_route: "/data/explicit-fixture",
    certification: null,
    verifier: "none",
  };
  const withExplicit = compileApplicationCatalog({ surfaceRegistrations: [...SURFACES, explicit] });
  ok("an explicit contextual registration can list without pixel certification", withExplicit.tools.some((entry) => entry.slug === explicit.slug) && withExplicit.applications.length === catalog.applications.length);

  const childMaturityChanged = compileApplicationCatalog({
    surfaceRegistrations: SURFACES.map((entry) => entry.slug === "machinery"
      ? { ...entry, operational_state: "workflow_complete", capabilities: ["browse", "execute", "proof"] }
      : entry),
  });
  ok("child-tool maturity cannot inflate its parent application registration", JSON.stringify(childMaturityChanged.applications) === JSON.stringify(catalog.applications));

  const validExtension = compileApplicationCatalog({
    extensionApplications: [{
      ref: "surface://test-extension",
      surface_key: "test-extension",
      registration_kind: "extension_application",
      name: "Test Extension",
      canonical_route: "/applications/test-extension",
      launch_route: null,
      route_posture: "unavailable",
      launchable: false,
      surface_origin: "organization",
      surface_creation_method: "studio_generated",
      surface_distribution: "organization_catalog",
      surface_availability: "preview",
      surface_admission_state: "admitted",
      surface_installation_state: "installed",
      surface_enablement_state: "disabled",
    }],
  });
  ok("the future extension input seam accepts an explicit typed eligible projection", validExtension.extension_applications.length === 1 && validExtension.extension_applications[0].registration_kind === "extension_application");
  let invalidKindRefused = false;
  try {
    compileApplicationCatalog({
      applicationRegistrations: [{ ref: "application:invalid", registration_kind: "conditional_owner_application" }],
    });
  } catch (error) {
    invalidKindRefused = /invalid application registration kind/.test(String(error));
  }
  ok("noncanonical application kinds fail closed", invalidKindRefused);
  let invalidContextualRefused = false;
  try {
    compileApplicationCatalog({
      surfaceRegistrations: [{ ...SURFACES[0], slug: "bad-contextual", surface_class: "peer_application" }],
    });
  } catch (error) {
    invalidContextualRefused = /invalid contextual surface class/.test(String(error));
  }
  ok("unknown contextual surface classes fail closed instead of disappearing", invalidContextualRefused);
  let invalidExtensionRefused = false;
  try {
    compileApplicationCatalog({ extensionApplications: [{ ref: "surface://wrong-kind", registration_kind: "tool_surface" }] });
  } catch (error) {
    invalidExtensionRefused = /extension inventory accepts only/.test(String(error));
  }
  ok("untyped or wrong-kind extension inventory fails closed", invalidExtensionRefused);

  let missingApplicationIdentityRefused = false;
  try {
    compileApplicationCatalog({
      applicationRegistrations: catalog.applications.map((entry) => entry.ref === "application:developer-console" ? { ...entry, ref: undefined } : entry),
    });
  } catch (error) {
    missingApplicationIdentityRefused = /requires an application: ref/.test(String(error));
  }
  ok("applications with missing stable identity fail closed", missingApplicationIdentityRefused);

  let duplicateSurfaceKeyRefused = false;
  try {
    compileApplicationCatalog({
      applicationRegistrations: catalog.applications.map((entry) => entry.ref === "application:developer-console" ? { ...entry, surface_key: "studio" } : entry),
    });
  } catch (error) {
    duplicateSurfaceKeyRefused = /duplicate or missing product-surface surface_key/.test(String(error));
  }
  ok("duplicate product-surface keys fail closed", duplicateSurfaceKeyRefused);

  let duplicateContextualRouteRefused = false;
  try {
    compileApplicationCatalog({
      surfaceRegistrations: SURFACES.map((entry) => entry.slug === "sources" ? { ...entry, route: SURFACES[0].route } : entry),
    });
  } catch (error) {
    duplicateContextualRouteRefused = /duplicate or missing contextual launch route/.test(String(error));
  }
  ok("duplicate contextual serving routes fail closed", duplicateContextualRouteRefused);

  let duplicateCoreRouteRefused = false;
  try {
    compileApplicationCatalog({
      coreWorkspaces: catalog.core_workspaces.map((entry) => entry.ref === "workspace:projects" ? { ...entry, launch_route: "/ai", route_posture: "compatibility_alias" } : entry),
    });
  } catch (error) {
    duplicateCoreRouteRefused = /duplicate or missing core\/application launch route/.test(String(error));
  }
  ok("core-workspace and application launch-route collisions fail closed", duplicateCoreRouteRefused);

  let skeletalExtensionRefused = false;
  try {
    compileApplicationCatalog({
      extensionApplications: [{ ref: "surface://skeletal-extension", registration_kind: "extension_application" }],
    });
  } catch (error) {
    skeletalExtensionRefused = /incomplete identity/.test(String(error));
  }
  ok("skeletal extension registrations fail closed", skeletalExtensionRefused);

  const augmentationSource = readFileSync(join(HERE, "augmentation", "35-app-catalog.js"), "utf8");
  async function evaluateOverlay(candidate) {
    const sandbox = {
      window: { __ioiStaticProductSurfaceCatalog: catalog },
      document: { getElementById: () => null },
      renderExplorer: () => {},
      appsModal: () => {},
      fetch: async () => ({ json: async () => candidate }),
      Date,
      Promise,
      setTimeout,
      clearTimeout,
    };
    vm.runInNewContext(`(function () {${augmentationSource}
window.__catalogVerifier = {
  fetch: fetchAppCatalog,
  current: function () { return appCatalogData; },
  resolved: function () { return appCatalogResolved; }
};
}());`, sandbox);
    sandbox.window.__catalogVerifier.fetch();
    await new Promise((resolve) => setTimeout(resolve, 0));
    return {
      baselinePreserved: JSON.stringify(sandbox.window.__catalogVerifier.current()) === JSON.stringify(catalog),
      resolved: sandbox.window.__catalogVerifier.resolved(),
    };
  }

  const emptyOverlay = {
    schema: "ioi.hypervisor.application-catalog.v2",
    taxonomy_version: catalog.taxonomy_version,
    projection_state: "transitional_static",
    membership_source: "typed_product_registration",
    evidence_membership_independent: true,
    policy_filtering_state: "not_connected",
    extension_inventory_state: "not_connected",
    applications: [],
    core_workspaces: [],
    tools: [],
    workspace_views: [],
    extension_applications: [],
  };
  const emptyResult = await evaluateOverlay(emptyOverlay);
  ok("shape-valid empty API data cannot erase the bundled first-party catalog", emptyResult.baselinePreserved && emptyResult.resolved === false);

  const duplicateRouteOverlay = JSON.parse(JSON.stringify(catalog));
  duplicateRouteOverlay.applications.find((entry) => entry.ref === "application:developer-console").launch_route =
    duplicateRouteOverlay.applications.find((entry) => entry.ref === "application:studio").launch_route;
  const duplicateRouteResult = await evaluateOverlay(duplicateRouteOverlay);
  ok("a full-census overlay with duplicate launch identity cannot replace the baseline", duplicateRouteResult.baselinePreserved && duplicateRouteResult.resolved === false);

  const missingCohortOverlay = JSON.parse(JSON.stringify(catalog));
  delete missingCohortOverlay.applications.find((entry) => entry.ref === "application:studio").owner_cohort;
  const missingCohortResult = await evaluateOverlay(missingCohortOverlay);
  ok("a full-census overlay with a reclassified owner cannot replace the baseline", missingCohortResult.baselinePreserved && missingCohortResult.resolved === false);

  const skeletalExtensionOverlay = JSON.parse(JSON.stringify(catalog));
  skeletalExtensionOverlay.extension_applications = [{
    ref: "surface://skeletal-extension",
    surface_key: "skeletal-extension",
    registration_kind: "extension_application",
    name: "Skeletal Extension",
    canonical_route: "/applications/skeletal-extension",
    launch_route: null,
    launchable: false,
  }];
  const skeletalExtensionResult = await evaluateOverlay(skeletalExtensionOverlay);
  ok("an extension row cannot appear while inventory is declared unconnected", skeletalExtensionResult.baselinePreserved && skeletalExtensionResult.resolved === false);
}

await run();
const failures = results.filter((result) => !result.pass);
for (const result of results) console.log(`${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail}` : ""}`);
console.log(`\n${results.length - failures.length}/${results.length} passed`);
if (failures.length) process.exit(1);
console.log("product-surface catalog: OK");
