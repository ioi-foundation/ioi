// Machine-readable Hypervisor product-surface catalog.
//
// Peer application/workspace membership is compiled only from typed product registrations.
// Certified runtime surfaces attach as owner-bound tools or workspace views. Capture, parity,
// pixel certification, and runtime-module state are evidence; none can create membership.
import { SURFACES, SURFACE_CLASSES } from "./surface-registry.mjs";
import {
  APPLICATION_REGISTRATIONS,
  CORE_WORKSPACES,
  EXTENSION_APPLICATION_CONTRACT,
  PRODUCT_TAXONOMY_VERSION,
} from "./product-surface-registry.mjs";

const ROUTE_POSTURES = new Set(["canonical", "compatibility_alias", "unavailable"]);
const APPLICATION_KINDS = new Set(["owner_application", "substrate_application"]);
const EXTENSION_ORIGINS = new Set(EXTENSION_APPLICATION_CONTRACT.surface_origins);
const EXTENSION_CREATION_METHODS = new Set(EXTENSION_APPLICATION_CONTRACT.surface_creation_methods);
const EXTENSION_DISTRIBUTION_CHANNELS = new Set(EXTENSION_APPLICATION_CONTRACT.surface_distribution_channels);
const EXTENSION_AVAILABILITY = new Set(["planned", "preview", "limited", "available", "deprecated", "unavailable"]);
const EXTENSION_ADMISSION = new Set(["not_applicable", "candidate", "under_review", "admitted", "rejected", "revoked"]);
const EXTENSION_INSTALLATION = new Set(["not_applicable", "not_installed", "installing", "installed", "update_available", "uninstalling", "uninstalled"]);
const EXTENSION_ENABLEMENT = new Set(["not_applicable", "enabled", "disabled"]);

function nonempty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function surfaceKey(value) {
  return nonempty(value) && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value);
}

function route(value) {
  return nonempty(value) && value.startsWith("/") && !/\s/.test(value);
}

function validateLaunch(entry, label) {
  if (typeof entry.launchable !== "boolean") throw new Error(`app-catalog: ${label} requires boolean launchable`);
  if (!ROUTE_POSTURES.has(entry.route_posture)) throw new Error(`app-catalog: ${label} has invalid route_posture`);
  if (entry.launchable && !route(entry.launch_route)) throw new Error(`app-catalog: ${label} is launchable without a valid launch_route`);
  if (!entry.launchable && entry.launch_route != null) throw new Error(`app-catalog: ${label} is nonlaunchable but still declares launch_route`);
}

function validateCoreWorkspace(entry) {
  if (!nonempty(entry.ref) || !entry.ref.startsWith("workspace:")) throw new Error("app-catalog: core workspace requires a workspace: ref");
  if (!surfaceKey(entry.surface_key) || !nonempty(entry.name) || !route(entry.canonical_route)) throw new Error(`app-catalog: core workspace '${entry.ref}' has incomplete identity`);
  if (entry.registration_kind !== "core_workspace") throw new Error(`app-catalog: core workspace '${entry.ref}' has invalid registration kind`);
  validateLaunch(entry, `core workspace '${entry.ref}'`);
}

function validateApplication(entry) {
  if (!APPLICATION_KINDS.has(entry.registration_kind)) throw new Error(`app-catalog: invalid application registration kind: ${entry.registration_kind || "missing"}`);
  if (!nonempty(entry.ref) || !entry.ref.startsWith("application:")) throw new Error("app-catalog: application registration requires an application: ref");
  if (!surfaceKey(entry.surface_key) || !nonempty(entry.name) || !route(entry.canonical_route)) throw new Error(`app-catalog: application '${entry.ref}' has incomplete identity`);
  if (entry.registration_kind === "owner_application" && !["enduring", "conditional"].includes(entry.owner_cohort)) throw new Error(`app-catalog: owner application '${entry.ref}' requires an owner_cohort`);
  if (entry.registration_kind === "substrate_application" && entry.owner_cohort != null) throw new Error(`app-catalog: substrate application '${entry.ref}' cannot declare owner_cohort`);
  validateLaunch(entry, `application '${entry.ref}'`);
}

function validateContextualSurface(entry) {
  if (!SURFACE_CLASSES.includes(entry.surface_class)) throw new Error(`app-catalog: invalid contextual surface class: ${entry.surface_class || "missing"}`);
  if (!surfaceKey(entry.slug) || !nonempty(entry.title) || !nonempty(entry.served_title)) throw new Error("app-catalog: contextual surface has incomplete identity");
  if (!nonempty(entry.placement_owner_ref) || !nonempty(entry.placement)) throw new Error(`app-catalog: contextual surface '${entry.slug}' has incomplete placement`);
  if (!route(entry.route) || !route(entry.canonical_target_route)) throw new Error(`app-catalog: contextual surface '${entry.slug}' has invalid routes`);
  if (!ROUTE_POSTURES.has(entry.route_posture)) throw new Error(`app-catalog: contextual surface '${entry.slug}' has invalid route_posture`);
  if (!Array.isArray(entry.capabilities) || !nonempty(entry.operational_state)) throw new Error(`app-catalog: contextual surface '${entry.slug}' has incomplete capability posture`);
}

function validateExtension(entry) {
  if (entry.registration_kind !== "extension_application") throw new Error("app-catalog: extension inventory accepts only typed extension_application projection entries");
  if (!nonempty(entry.ref) || !entry.ref.startsWith("surface://")) throw new Error("app-catalog: extension inventory requires a stable surface:// ref");
  if (!surfaceKey(entry.surface_key) || !nonempty(entry.name) || !route(entry.canonical_route)) throw new Error(`app-catalog: extension '${entry.ref}' has incomplete identity`);
  if (!EXTENSION_ORIGINS.has(entry.surface_origin) || !EXTENSION_CREATION_METHODS.has(entry.surface_creation_method) || !EXTENSION_DISTRIBUTION_CHANNELS.has(entry.surface_distribution)) throw new Error(`app-catalog: extension '${entry.ref}' has incomplete origin, creation, or distribution dimensions`);
  if (!EXTENSION_AVAILABILITY.has(entry.surface_availability) || !EXTENSION_ADMISSION.has(entry.surface_admission_state) || !EXTENSION_INSTALLATION.has(entry.surface_installation_state) || !EXTENSION_ENABLEMENT.has(entry.surface_enablement_state)) throw new Error(`app-catalog: extension '${entry.ref}' has incomplete lifecycle dimensions`);
  validateLaunch(entry, `extension '${entry.ref}'`);
}

function assertUnique(entries, field, label, { nullable = false } = {}) {
  const values = entries.map((entry) => entry[field]).filter((value) => nullable ? value != null : true);
  if (values.some((value) => !nonempty(value)) || new Set(values).size !== values.length) throw new Error(`app-catalog: duplicate or missing ${label}`);
}

function contextualSurface(registration) {
  return {
    ref: `${registration.surface_class}:${registration.slug}`,
    surface_key: registration.slug,
    slug: registration.slug,
    title: registration.title,
    served_title: registration.served_title,
    registration_kind: registration.surface_class,
    placement_owner_ref: registration.placement_owner_ref,
    placement: registration.placement,
    canonical_target_route: registration.canonical_target_route,
    launch_route: registration.route,
    route_posture: registration.route_posture,
    availability: "available",
    implementation_state: registration.operational_state,
    launchable: true,
    peer_application: false,
    icon: registration.icon || null,
    capabilities: [...registration.capabilities],
    ux_evidence: {
      evidence_kind: "certified_runtime_surface",
      certification_ref: registration.certification,
      verifier_ref: registration.verifier,
      served_title: registration.served_title,
    },
  };
}

export function compileApplicationCatalog({
  coreWorkspaces = CORE_WORKSPACES,
  applicationRegistrations = APPLICATION_REGISTRATIONS,
  surfaceRegistrations = SURFACES,
  extensionApplications = [],
} = {}) {
  const core_workspaces = coreWorkspaces.map((entry) => ({ registration_kind: "core_workspace", ...entry }));
  const applications = applicationRegistrations.map((entry) => ({ ...entry }));
  core_workspaces.forEach(validateCoreWorkspace);
  applications.forEach(validateApplication);
  // These are already-normalized eligible projection rows joined from the stable registration
  // and its release/install/enablement bindings. The catalog never stores those live lifecycle
  // dimensions back into HypervisorApplicationSurfaceRegistration.
  const extension_applications = extensionApplications.map((entry) => ({
    ...entry,
    registration_kind: entry.registration_kind || entry.surface_class,
  }));
  extension_applications.forEach(validateExtension);
  const invalidSurfaces = surfaceRegistrations.filter((entry) => !entry.runtime_test_only && !SURFACE_CLASSES.includes(entry.surface_class));
  if (invalidSurfaces.length) throw new Error(`app-catalog: invalid contextual surface class: ${invalidSurfaces.map((entry) => entry.surface_class || "missing").join(", ")}`);
  const explicitSurfaces = surfaceRegistrations.filter((entry) => SURFACE_CLASSES.includes(entry.surface_class));
  explicitSurfaces.forEach(validateContextualSurface);
  const contextual = explicitSurfaces.map(contextualSurface);
  const tools = contextual.filter((entry) => entry.registration_kind === "tool_surface");
  const workspace_views = contextual.filter((entry) => entry.registration_kind === "workspace_view");

  const owners = new Set([...core_workspaces, ...applications].map((entry) => entry.ref));
  const orphaned = contextual.filter((entry) => !owners.has(entry.placement_owner_ref));
  if (orphaned.length) throw new Error(`app-catalog: contextual surfaces have unknown owners: ${orphaned.map((entry) => entry.surface_key).join(", ")}`);
  const all = [...core_workspaces, ...applications, ...contextual, ...extension_applications];
  assertUnique(all, "ref", "product-surface ref");
  assertUnique(all, "surface_key", "product-surface surface_key");
  const canonicalRoutes = [
    ...core_workspaces.map((entry) => entry.canonical_route),
    ...applications.map((entry) => entry.canonical_route),
    ...contextual.map((entry) => entry.canonical_target_route),
    ...extension_applications.map((entry) => entry.canonical_route),
  ];
  if (canonicalRoutes.some((value) => !route(value)) || new Set(canonicalRoutes).size !== canonicalRoutes.length) throw new Error("app-catalog: duplicate or missing canonical route");
  assertUnique([...core_workspaces, ...applications].filter((entry) => entry.launchable), "launch_route", "core/application launch route");
  assertUnique(contextual, "launch_route", "contextual launch route");
  assertUnique(extension_applications.filter((entry) => entry.launchable), "launch_route", "extension launch route");

  return {
    schema: "ioi.hypervisor.application-catalog.v2",
    taxonomy_version: PRODUCT_TAXONOMY_VERSION,
    projection_state: "transitional_static",
    membership_source: "typed_product_registration",
    evidence_membership_independent: true,
    policy_filtering_state: "not_connected",
    extension_inventory_state: "not_connected",
    core_workspaces,
    applications,
    tools,
    workspace_views,
    extension_applications,
    extension_application_contract: { ...EXTENSION_APPLICATION_CONTRACT },
  };
}

const catalog = compileApplicationCatalog();
export function appCatalog() {
  return catalog;
}
