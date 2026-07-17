// The app catalog — the machine-readable JOIN of the two truths about ported application
// surfaces: MEMBERSHIP is parity-matrix evidence (every shell-pixel-certified candidate) plus an
// explicit registry declaration for a read_only_by_contract surface whose completeness comes from
// its product contract rather than a reference-shell certification. PRESENTATION is registry code
// truth (display title + app tile icon). This module decides neither.
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, surfaceBySlug } from "./surface-registry.mjs";

const MATRIX_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "harvest-app-parity-matrix.json");

let cached = null, cachedMtime = 0;
export function appCatalog() {
  const mtime = statSync(MATRIX_PATH).mtimeMs;
  if (cached && mtime === cachedMtime) return cached;
  const matrix = JSON.parse(readFileSync(MATRIX_PATH, "utf8"));
  const certified = (matrix.seeds || [])
    .filter((s) => s.shell_pixel_certified && s.candidate_surface)
    .map((s) => {
      const reg = surfaceBySlug(s.slug) || {};
      return {
        slug: s.slug,
        title: reg.title || s.slug.charAt(0).toUpperCase() + s.slug.slice(1),
        family: s.owner || "",
        route: s.candidate_surface.split("?")[0],
        icon: reg.icon || null,
      };
    });
  const certifiedSlugs = new Set(certified.map((app) => app.slug));
  const contractComplete = SURFACES
    .filter((surface) => surface.operational_state === "read_only_by_contract" && !certifiedSlugs.has(surface.slug))
    .map((surface) => ({
      slug: surface.slug,
      title: surface.title,
      family: surface.owner,
      route: surface.route,
      icon: surface.icon || null,
    }));
  const apps = [...certified, ...contractComplete]
    .sort((a, b) => a.family.localeCompare(b.family) || a.title.localeCompare(b.title));
  cached = {
    schema: "ioi.hypervisor.app-catalog.v1",
    generated_from: "harvest-app-parity-matrix.json + read_only_by_contract registry surfaces",
    apps,
  };
  cachedMtime = mtime;
  return cached;
}
