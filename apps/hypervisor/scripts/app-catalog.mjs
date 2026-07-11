// The app catalog — the machine-readable JOIN of the two truths about ported application
// surfaces: MEMBERSHIP is parity-matrix evidence (every seed in harvest-app-parity-matrix.json
// with shell_pixel_certified: true lists, keyed by its candidate_surface route) and
// PRESENTATION is registry code truth (display title + app tile icon from surface-registry.mjs).
// This module decides neither: a newly certified port surfaces in every launcher lane
// (/ai explorer grid, launcher modal, /__ioi/applications estate page) once its matrix seed
// flips, with a slug-derived title until its registry entry lands.
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { surfaceBySlug } from "./surface-registry.mjs";

const MATRIX_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "harvest-app-parity-matrix.json");

let cached = null, cachedMtime = 0;
export function appCatalog() {
  const mtime = statSync(MATRIX_PATH).mtimeMs;
  if (cached && mtime === cachedMtime) return cached;
  const matrix = JSON.parse(readFileSync(MATRIX_PATH, "utf8"));
  const apps = (matrix.seeds || [])
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
    })
    .sort((a, b) => a.family.localeCompare(b.family) || a.title.localeCompare(b.title));
  cached = { schema: "ioi.hypervisor.app-catalog.v1", generated_from: "harvest-app-parity-matrix.json", apps };
  cachedMtime = mtime;
  return cached;
}
