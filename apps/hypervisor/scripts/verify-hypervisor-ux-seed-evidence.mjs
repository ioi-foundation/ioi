#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { SURFACES, boundSurface } from "./surface-registry.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const SEED_ROOT = path.join(ROOT, "ux-seeds");
const manifest = JSON.parse(fs.readFileSync(path.join(SEED_ROOT, "manifest.json"), "utf8"));
const matrix = JSON.parse(fs.readFileSync(path.join(ROOT, "harvest-app-parity-matrix.json"), "utf8"));
const registrySource = fs.readFileSync(path.join(HERE, "surface-registry.mjs"), "utf8");
const serveSource = fs.readFileSync(path.join(HERE, "serve-product-ui.mjs"), "utf8");

let checks = 0;
const check = (condition, message) => {
  assert.ok(condition, message);
  checks += 1;
};

check(manifest.schema_version === "ioi.hypervisor.ux-seed-evidence.v1", "manifest schema is pinned");
check(manifest.state === "dormant_seed_evidence_only", "manifest state is dormant");
check(Array.isArray(manifest.seeds) && manifest.seeds.length === 3, "exactly three historical seeds are absorbed");
check(!registrySource.includes("ux-seeds/"), "surface registry imports no dormant seed");
check(!serveSource.includes("ux-seeds/"), "route dispatcher imports no dormant seed");

const slugs = new Set();
for (const seed of manifest.seeds) {
  check(!slugs.has(seed.slug), `${seed.slug}: slug is unique`);
  slugs.add(seed.slug);
  check(seed.active_registration === "none", `${seed.slug}: no active registration is claimed`);
  check(Array.isArray(seed.first_meaningful_pull) && seed.first_meaningful_pull.length > 0, `${seed.slug}: owning M-stage pull is named`);
  check(Array.isArray(seed.activation_requirements) && seed.activation_requirements.length >= 3, `${seed.slug}: promotion requirements are explicit`);
  check(!SURFACES.some((surface) => surface.slug === seed.slug), `${seed.slug}: absent from active surface registry`);
  check(boundSurface(seed.proposed_route, "GET") === null, `${seed.slug}: proposed route is not mounted`);

  const matrixRow = matrix.seeds.find((row) => row.slug === seed.slug);
  check(matrixRow?.parity_class === seed.active_parity_class, `${seed.slug}: active parity class was not promoted`);
  check(!fs.existsSync(path.join(ROOT, "pixel-certifications", `${seed.slug}.json`)), `${seed.slug}: no active certificate exists`);

  const surfacePath = path.join(SEED_ROOT, seed.surface);
  const surfaceSource = fs.readFileSync(surfacePath, "utf8");
  const module = await import(pathToFileURL(surfacePath).href);
  check(module.meta?.slug === seed.slug, `${seed.slug}: module identity matches manifest`);
  check(module.meta?.seed_state === "dormant_ux_seed", `${seed.slug}: module declares dormant seed state`);
  check(module.meta?.canonical_owner === seed.canonical_owner, `${seed.slug}: current canonical owner is pinned`);
  check(!Object.hasOwn(module.meta, "route"), `${seed.slug}: module exports no active route`);
  check(Array.isArray(module.actions) && module.actions.length === 0, `${seed.slug}: module declares no actions`);
  check(typeof module.handleAction === "undefined", `${seed.slug}: module has no mutation handler`);
  check(!/method\s*:\s*["']POST["']/.test(surfaceSource), `${seed.slug}: module contains no POST request`);

  if (seed.assets) check(fs.existsSync(path.join(SEED_ROOT, seed.assets)), `${seed.slug}: captured assets are retained`);
  if (seed.pixel_evidence) {
    const evidence = JSON.parse(fs.readFileSync(path.join(SEED_ROOT, seed.pixel_evidence), "utf8"));
    check(evidence.viewports?.length === 2, `${seed.slug}: two historical desktop viewport results are retained`);
    check(evidence.viewports.every((viewport) => viewport.certified === true), `${seed.slug}: retained historical viewport results are internally complete`);
  }
}

check(slugs.size === manifest.seeds.length, "manifest slug census is exact");
console.log(`verify-hypervisor-ux-seed-evidence: ${checks}/${checks} checks passed`);
