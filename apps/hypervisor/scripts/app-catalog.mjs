// CONTRACT-EVIDENCE ADMISSION for ported surfaces — and nothing about catalog membership.
//
// WHAT THIS FILE USED TO BE, and why it is not that any more (M08.8). It built the app catalog by
// reading `shell_pixel_certified` out of the harvest parity matrix: a screenshot comparison against
// a reference estate decided which surfaces appeared in a rendered lane. Canon could not be more
// direct about that — capture provenance, screenshots, pixel certificates and parity matrices
// "have zero authority over registration class, catalog membership, owner, capability, or
// maturity" (core-clients-surfaces.md :2006-2008) — and the band had even been LABELLED
// `catalog_authority: false` while its membership stayed parity-derived. A label is not a boundary,
// and a verifier downstream had hardened the arrangement into an acceptance test that asserted
// "catalog membership equals certified surfaces".
//
// The fourteen ported surfaces are registrations now (`surface_class: tool_surface`, all eleven
// axes), and membership comes from the compiled product-surface projection like every other
// surface's. `buildAppCatalog` is gone rather than corrected: a function whose whole job was to
// join membership to parity evidence has no smaller honest version.
//
// WHAT SURVIVES: `contractCatalogAdmission`, which asks whether a surface's OPERATIONAL-DEPTH
// CONTRACT EVIDENCE is exact and committed — coordinates, record, module shape and route all
// agreeing. That is evidence quality, not membership, and it stays useful for exactly the question
// it answers: has this port proved what it claims about itself?
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { boundSurface } from "./surface-registry.mjs";

const ATLAS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "application-operational-depth.json");
const CATALOG_EVIDENCE_SCHEMA = "ioi.hypervisor.catalog-contract-evidence.v1";

export function contractCatalogAdmission(surface, atlas, resolveBinding = (route) => boundSurface(route, "GET")) {
  const pointer = surface?.catalog_evidence;
  if (!pointer || pointer.schema !== CATALOG_EVIDENCE_SCHEMA) return { admitted: false, reason: "catalog_evidence_missing" };
  if (pointer.artifact !== "application-operational-depth.json" || pointer.evidence_key !== surface.slug) {
    return { admitted: false, reason: "catalog_evidence_coordinate_mismatch" };
  }
  const evidence = atlas?.surfaces?.[pointer.evidence_key];
  if (!evidence || evidence.catalog_evidence?.status !== "verified") {
    return { admitted: false, reason: "catalog_evidence_unverified" };
  }
  const evidenceCoordinates = ["schema", "artifact", "evidence_key", "module", "verifier"];
  if (!evidenceCoordinates.every((key) => evidence.catalog_evidence[key] === pointer[key])) {
    return { admitted: false, reason: "catalog_evidence_record_mismatch" };
  }
  if (evidence.slug !== surface.slug || evidence.ioi_route !== surface.route || evidence.is_operational !== true
    || evidence.current?.operational_state !== "read_only_by_contract"
    || surface.operational_state !== "read_only_by_contract"
    || JSON.stringify(evidence.current?.capabilities || []) !== JSON.stringify(surface.capabilities || [])) {
    return { admitted: false, reason: "catalog_evidence_contract_mismatch" };
  }
  const hit = resolveBinding(surface.route);
  const implementation = hit?.impl;
  if (!implementation || typeof implementation.load !== "function" || typeof implementation.render !== "function"
    || !Array.isArray(implementation.actions) || implementation.actions.length !== 0
    || typeof implementation.handleAction !== "undefined"
    || implementation.meta?.slug !== surface.slug || implementation.meta?.route !== surface.route
    || implementation.meta?.verifier !== pointer.verifier || implementation.meta?.certification !== surface.certification) {
    return { admitted: false, reason: "catalog_evidence_module_mismatch" };
  }
  return { admitted: true, reason: "" };
}

// The operational-depth atlas, read once. It is the evidence record `contractCatalogAdmission`
// checks against; nothing here assembles a catalog.
export function operationalDepthAtlas() {
  return JSON.parse(readFileSync(ATLAS_PATH, "utf8"));
}
