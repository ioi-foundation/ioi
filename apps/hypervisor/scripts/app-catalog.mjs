// The app catalog — the machine-readable JOIN of the two truths about ported application
// surfaces: MEMBERSHIP is parity-matrix evidence (every shell-pixel-certified candidate) plus an
// explicit registry declaration for a read_only_by_contract surface whose completeness comes from
// its product contract rather than a reference-shell certification. PRESENTATION is registry code
// truth (display title + app tile icon). This module decides neither.
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, boundSurface } from "./surface-registry.mjs";

const MATRIX_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "harvest-app-parity-matrix.json");
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

export function buildAppCatalog({ matrix, atlas, surfaces = SURFACES, resolveBinding } = {}) {
  const bySlug = new Map(surfaces.map((surface) => [surface.slug, surface]));
  const certified = (matrix.seeds || [])
    .filter((s) => s.shell_pixel_certified && s.candidate_surface)
    .map((s) => {
      const reg = bySlug.get(s.slug) || {};
      return {
        slug: s.slug,
        title: reg.title || s.slug.charAt(0).toUpperCase() + s.slug.slice(1),
        family: s.owner || "",
        route: s.candidate_surface.split("?")[0],
        icon: reg.icon || null,
      };
    });
  const certifiedSlugs = new Set(certified.map((app) => app.slug));
  const contractComplete = surfaces
    .filter((surface) => !certifiedSlugs.has(surface.slug)
      && contractCatalogAdmission(surface, atlas, resolveBinding).admitted)
    .map((surface) => ({
      slug: surface.slug,
      title: surface.title,
      family: surface.owner,
      route: surface.route,
      icon: surface.icon || null,
    }));
  const apps = [...certified, ...contractComplete]
    .sort((a, b) => a.family.localeCompare(b.family) || a.title.localeCompare(b.title));
  return {
    schema: "ioi.hypervisor.app-catalog.v1",
    generated_from: "harvest-app-parity-matrix.json + verified operational-depth contract evidence",
    apps,
  };
}

let cached = null, cachedMatrixMtime = 0, cachedAtlasMtime = 0;
export function appCatalog() {
  const matrixMtime = statSync(MATRIX_PATH).mtimeMs;
  const atlasMtime = statSync(ATLAS_PATH).mtimeMs;
  if (cached && matrixMtime === cachedMatrixMtime && atlasMtime === cachedAtlasMtime) return cached;
  const matrix = JSON.parse(readFileSync(MATRIX_PATH, "utf8"));
  const atlas = JSON.parse(readFileSync(ATLAS_PATH, "utf8"));
  cached = buildAppCatalog({ matrix, atlas });
  cachedMatrixMtime = matrixMtime;
  cachedAtlasMtime = atlasMtime;
  return cached;
}
