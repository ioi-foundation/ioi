#!/usr/bin/env node
// Fail-closed seed-provenance gate for the twenty Hypervisor surfaces (AUD-WS-002,
// 2026-08-09 audit). Promoted from the audit-pack prototype
// (internal-docs/audits/2026-08-09-hypervisor-live-ux-workstream-coverage/logs/
// validate-seed-ux-manifest.mjs) onto tracked inputs only, so a fresh clone and CI
// validate the same truth.
//
// What it enforces, before any browser navigation is trusted:
//   - exactly twenty surface entries, exact id set, canonical routes;
//   - every /__ioi seed baseline exactly matches ported-seed-preservation.v1.json;
//   - every /__apps slug exists in the harvest inventory and parity matrix and
//     carries exactly one estate disposition from the fixed vocabulary;
//   - dormant references exactly match ux-seeds/manifest.json;
//   - a canonical shell is never a baseline (no source route equals a canonical route);
//   - owner drift is rejected (typed exception: an owner_mapping_note recording an
//     open dual-owner ruling, e.g. machinery / OQ-2);
//   - seed_graph_ready_for_rehome derives strictly from per-source
//     complete_interaction_route_graph; a block record never satisfies the gate;
//   - a claimed-complete graph must exist under seed-graphs/, parse, match its
//     surface/slug/route, verify its content address, attest quarantine, and have
//     been replay-walked with zero blockers;
//   - a no-seed surface carries either its recovery record or a typed
//     greenfield-authorized-non-parity authorization — nothing else opens work;
//   - no secret-shaped token anywhere in the manifest or graphs.
//
//   node scripts/verify-hypervisor-seed-provenance.mjs            # full tracked gate
//   node scripts/verify-hypervisor-seed-provenance.mjs --surface work
//   node scripts/verify-hypervisor-seed-provenance.mjs --shared   # wiring check only (W2.1)

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const fail = (msg) => failures.push(msg);

const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(appRoot, rel), "utf8"));
const readText = (rel) => fs.readFileSync(path.join(appRoot, rel), "utf8");

const args = process.argv.slice(2);
const sharedOnly = args.includes("--shared");
const surfaceFilter = args.includes("--surface") ? args[args.indexOf("--surface") + 1] : null;
// --require-ready: consistency alone is not readiness. With this flag the named
// surface must have an OPEN seed gate — every source graph replay-complete, or
// the typed greenfield-authorized-non-parity record. This is the command a
// surface packet runs before rehome work starts.
const requireReady = args.includes("--require-ready");
if (requireReady && !surfaceFilter) {
  console.error("seed-provenance: --require-ready needs --surface <id>");
  process.exit(2);
}

const MANIFEST = "seed-ux-provenance.v1.json";
const EXPECTED_IDS = [
  "home", "systems", "projects", "applications", "work", "settings", "studio",
  "automations", "ontology", "data", "governance", "provenance", "evaluations",
  "improvement", "foundry", "packages", "developer-workspace", "developer-console",
  "environments", "operations",
];
const SOURCE_KINDS = new Set([
  "protected-executable-seed", "retained-harvest-capture", "explicit-dormant-reference",
]);
const DISPOSITIONS = new Set([
  "pattern-harvest", "rebind", "rehome", "retire-at-cutover",
  "blocked-missing-route", "blocked-missing-capture",
]);
const SECRET = /ioi_(?:bootstrap|session)_[A-Za-z0-9._-]+|"session_token"\s*:/u;

const manifest = readJson(MANIFEST);
if (manifest.schema_version !== "ioi.hypervisor.seed-ux-provenance.v1") {
  fail(`${MANIFEST}: unsupported schema_version ${manifest.schema_version}`);
}

const seenProtected = new Map();
const seenRetained = new Map();
const seenDormant = new Map();

if (sharedOnly) {
  // W2.1 wiring check: the gate is invokable and its tracked inputs exist.
  for (const rel of [
    MANIFEST, "ported-seed-preservation.v1.json", "harvest-app-parity-matrix.json",
    "ux-seeds/manifest.json", "scripts/harvest-seed-inventory.mjs",
    "scripts/capture-hypervisor-seed-route-graph.mjs",
  ]) {
    if (!fs.existsSync(path.join(appRoot, rel))) fail(`--shared: missing tracked input ${rel}`);
  }
  finish("shared wiring");
}

// ---------------------------------------------------------------- tracked inputs
const preservation = readJson("ported-seed-preservation.v1.json");
const parityMatrix = readJson("harvest-app-parity-matrix.json");
const dormant = readJson("ux-seeds/manifest.json");
const inventorySlugs = new Set(
  [...readText("scripts/harvest-seed-inventory.mjs").matchAll(/\bslug:\s*"([^"]+)"/gu)].map((m) => m[1]),
);
const registryOwners = new Map(
  [...readText("scripts/surface-registry.mjs").matchAll(
    /slug:\s*"([^"]+)",\s*owner:\s*"([^"]+)"[\s\S]*?route:\s*"([^"]+)"/gu,
  )].map((m) => [m[3], { slug: m[1], owner: m[2] }]),
);

// ---------------------------------------------------------------- surfaces
const surfaces = manifest.surfaces ?? [];
const ids = surfaces.map((s) => s.id);
if (ids.length !== 20) fail(`${MANIFEST}: expected 20 surfaces, found ${ids.length}`);
for (const id of EXPECTED_IDS) if (!ids.includes(id)) fail(`${MANIFEST}: missing surface ${id}`);
for (const id of ids) if (!EXPECTED_IDS.includes(id)) fail(`${MANIFEST}: unknown surface ${id}`);
if (new Set(ids).size !== ids.length) fail(`${MANIFEST}: duplicate surface ids`);
if (surfaceFilter && !ids.includes(surfaceFilter)) {
  fail(`--surface ${surfaceFilter}: no such surface`);
}

const canonicalRoutes = new Set(surfaces.map((s) => s.canonical_route));

for (const surface of surfaces) {
  const at = `surface ${surface.id}`;
  if (!surface.canonical_route?.startsWith("/")) fail(`${at}: canonical_route must start with /`);
  if (surface.owner !== undefined && typeof surface.owner !== "string") fail(`${at}: owner must be a string`);

  const sources = surface.sources ?? [];
  // Seed roles (OQ-12 owner ruling, 2026-08-09): the protected executable ports
  // are the baseline seed; retained captures and dormant references corroborate.
  // The kind⇒role lock means tooling can never demote a baseline (or promote a
  // corroborating source) — only a recorded owner ruling that changes this lock.
  const ROLE_BY_KIND = {
    "protected-executable-seed": "baseline",
    "retained-harvest-capture": "corroborating",
    "explicit-dormant-reference": "corroborating",
  };
  for (const src of sources) {
    const required = ROLE_BY_KIND[src.kind];
    if (required && src.seed_role !== required) {
      fail(`${at} source ${src.slug}: seed_role "${src.seed_role}" violates the kind lock (${src.kind} => ${required}) — roles change only by recorded owner ruling, never by tooling`);
    }
  }
  const complete = (src) => src.graph?.complete_interaction_route_graph === true;
  const baseline = sources.filter((src) => src.seed_role === "baseline");
  const allComplete = sources.length > 0 && sources.every(complete);
  const derivedReady = baseline.length > 0 && baseline.every(complete);

  const status = surface.graph_mapping_status ?? "";
  if (status === "complete-interaction-route-graphs-present") {
    if (!allComplete) fail(`${at}: status claims every graph complete but some are not`);
  } else if (status === "baseline-graphs-complete-corroborating-typed") {
    if (!derivedReady) fail(`${at}: status claims baseline completeness that does not derive`);
    if (allComplete) fail(`${at}: every graph is complete — use the full terminal status`);
  } else if (!status.startsWith("blocked-")) {
    fail(`${at}: graph_mapping_status must start with "blocked-" or be a terminal value, got "${status}"`);
  }

  if (Boolean(surface.seed_graph_ready_for_rehome) !== derivedReady) {
    fail(`${at}: seed_graph_ready_for_rehome=${surface.seed_graph_ready_for_rehome} does not derive from its baseline sources (derived ${derivedReady}) — the gate is fail-closed, never asserted`);
  }
  if (derivedReady && status.startsWith("blocked-")) {
    fail(`${at}: baseline graphs are complete but graph_mapping_status is still "${status}"`);
  }

  const green = surface.greenfield_authorization;
  if (sources.length === 0) {
    if (!green && !surface.graph_recovery_status) {
      fail(`${at}: a no-seed surface must carry its exhausted-recovery record or a typed greenfield authorization`);
    }
    if (surface.baseline_status !== "blocked-no-valid-seed") {
      fail(`${at}: zero sources requires baseline_status blocked-no-valid-seed, got "${surface.baseline_status}"`);
    }
  }
  if (green) {
    if (green.type !== "greenfield-authorized-non-parity") {
      fail(`${at}: greenfield_authorization.type must be "greenfield-authorized-non-parity"`);
    }
    if (!green.authorized_by || !green.authorized_on) {
      fail(`${at}: greenfield_authorization requires authorized_by and authorized_on`);
    }
    if (!/seed preservation/u.test(green.limits ?? "") || !/parity/u.test(green.limits ?? "")) {
      fail(`${at}: greenfield_authorization.limits must state it can never claim seed preservation or parity`);
    }
    if (sources.length > 0) {
      fail(`${at}: greenfield authorization coexists with ${sources.length} seed sources — recover the seed instead`);
    }
  }

  for (const src of sources) {
    const sat = `${at} source ${src.slug}`;
    if (!SOURCE_KINDS.has(src.kind)) fail(`${sat}: unknown kind ${src.kind}`);
    if (src.canonical_owner !== surface.owner) {
      fail(`${sat}: canonical_owner "${src.canonical_owner}" != surface owner "${surface.owner}"`);
    }
    if (src.starting_route && canonicalRoutes.has(src.starting_route)) {
      fail(`${sat}: starting_route ${src.starting_route} is a canonical route — a shell is never a baseline`);
    }
    const level = src.graph?.evidence_level;
    if (!["summary_only", "explored_control_graph", "complete_interaction_route_graph"].includes(level)) {
      fail(`${sat}: unknown graph.evidence_level ${level}`);
    }
    const complete = src.graph?.complete_interaction_route_graph === true;
    if (complete && level !== "complete_interaction_route_graph") {
      fail(`${sat}: claims a complete graph at evidence_level ${level}`);
    }

    if (src.kind === "protected-executable-seed") {
      if (seenProtected.has(src.starting_route)) fail(`${sat}: protected route ${src.starting_route} claimed twice`);
      seenProtected.set(src.starting_route, src);
    } else if (src.kind === "retained-harvest-capture") {
      if (src.starting_route !== `/__apps/${src.slug}`) {
        fail(`${sat}: retained starting_route must be /__apps/${src.slug}, got ${src.starting_route}`);
      }
      if (!DISPOSITIONS.has(src.disposition)) {
        fail(`${sat}: disposition "${src.disposition}" is not in the fixed vocabulary`);
      }
      if (seenRetained.has(src.slug)) fail(`${sat}: retained slug claimed twice`);
      seenRetained.set(src.slug, src);
      if (!inventorySlugs.has(src.slug)) fail(`${sat}: slug absent from harvest-seed-inventory.mjs`);
    } else {
      seenDormant.set(src.slug, src);
      if (src.starting_route !== null && src.starting_route !== undefined) {
        fail(`${sat}: a dormant reference has no starting route`);
      }
    }

    // Owner drift vs the live surface registry — typed exception only.
    const reg = src.starting_route ? registryOwners.get(src.starting_route) : null;
    if (reg && reg.owner !== src.canonical_owner && !src.owner_mapping_note) {
      fail(`${sat}: surface-registry.mjs says owner "${reg.owner}" but manifest says "${src.canonical_owner}" with no owner_mapping_note recording the open ruling`);
    }

    // Graph-file gate.
    if (complete) {
      if (!src.graph_file) {
        fail(`${sat}: complete_interaction_route_graph=true without a graph_file`);
      } else {
        verifyGraphFile(src, sat);
      }
    } else if (src.graph_file) {
      verifyGraphFile(src, sat, { allowIncomplete: true });
    }
  }
}

// Exact protected-set equality with ported-seed-preservation.v1.json.
const preservedRoutes = new Map((preservation.protected_routes ?? []).map((p) => [p.route, p]));
for (const [route, p] of preservedRoutes) {
  const src = seenProtected.get(route);
  if (!src) fail(`protected route ${route} (${p.slug}) is missing from the provenance manifest`);
  else {
    if (src.slug !== p.slug) fail(`protected route ${route}: slug ${src.slug} != preservation record ${p.slug}`);
    if (src.class !== p.class) fail(`protected route ${route}: class ${src.class} != preservation record ${p.class}`);
  }
}
for (const route of seenProtected.keys()) {
  if (!preservedRoutes.has(route)) fail(`protected source ${route} is not in ported-seed-preservation.v1.json — the /__ioi prefix is not a seed namespace`);
}

// Exact retained-set equality with the parity matrix + inventory.
const matrixSlugs = new Set((parityMatrix.seeds ?? []).map((s) => s.slug));
for (const slug of matrixSlugs) {
  if (!seenRetained.has(slug)) fail(`retained slug ${slug} (harvest-app-parity-matrix.json) missing from the provenance manifest`);
}
for (const slug of seenRetained.keys()) {
  if (!matrixSlugs.has(slug)) fail(`retained slug ${slug} is not in harvest-app-parity-matrix.json`);
}

// Exact dormant-set equality with ux-seeds/manifest.json.
for (const seed of dormant.seeds ?? []) {
  const src = seenDormant.get(seed.slug);
  if (!src) fail(`dormant seed ${seed.slug} (ux-seeds/manifest.json) missing from the provenance manifest`);
  else if (src.canonical_owner !== seed.canonical_owner) {
    fail(`dormant seed ${seed.slug}: owner ${src.canonical_owner} != ux-seeds record ${seed.canonical_owner}`);
  }
}
for (const slug of seenDormant.keys()) {
  if (![...(dormant.seeds ?? [])].some((s) => s.slug === slug)) {
    fail(`dormant source ${slug} is not in ux-seeds/manifest.json`);
  }
}

// Secret-leak gate over the manifest and every graph file.
if (SECRET.test(readText(MANIFEST))) fail(`${MANIFEST}: secret-shaped token present`);
const graphDir = path.join(appRoot, "seed-graphs");
if (fs.existsSync(graphDir)) {
  for (const entry of fs.readdirSync(graphDir, { recursive: true })) {
    const full = path.join(graphDir, String(entry));
    if (fs.statSync(full).isFile() && SECRET.test(fs.readFileSync(full, "utf8"))) {
      fail(`seed-graphs/${entry}: secret-shaped token present`);
    }
  }
}

function verifyGraphFile(src, sat, { allowIncomplete = false } = {}) {
  const rel = src.graph_file;
  if (!rel.startsWith("seed-graphs/")) {
    fail(`${sat}: graph_file must live under seed-graphs/, got ${rel}`);
    return;
  }
  const full = path.join(appRoot, rel);
  if (!fs.existsSync(full)) {
    fail(`${sat}: graph_file ${rel} does not exist`);
    return;
  }
  let g;
  try {
    g = JSON.parse(fs.readFileSync(full, "utf8"));
  } catch {
    fail(`${sat}: graph_file ${rel} is not valid JSON`);
    return;
  }
  if (g.schema_version !== "ioi.hypervisor.seed-interaction-route-graph.v1") {
    fail(`${sat}: graph ${rel} has schema_version ${g.schema_version}`);
  }
  if (g.slug !== src.slug) fail(`${sat}: graph ${rel} is for slug ${g.slug}`);
  if (src.starting_route && g.owned_route !== src.starting_route) {
    fail(`${sat}: graph ${rel} owned_route ${g.owned_route} != source route ${src.starting_route}`);
  }
  // Attestation-bearing address (closure phase): binds nodes, edges, blockers,
  // quarantine, replay and the completeness verdict. Legacy nodes/edges-only
  // addresses are rejected — re-replay under interaction semantics to migrate.
  const address = crypto.createHash("sha256")
    .update(JSON.stringify({
      surface: g.surface, slug: g.slug, owned_route: g.owned_route,
      nodes: g.nodes, edges: g.edges, blockers: g.blockers,
      quarantine: g.quarantine, replay: g.replay,
      complete_interaction_route_graph: g.complete_interaction_route_graph,
    }))
    .digest("hex");
  if (g.content_address !== address) {
    fail(`${sat}: graph ${rel} content_address does not verify against the attestation-bearing scheme (recorded ${String(g.content_address).slice(0, 12)}…, computed ${address.slice(0, 12)}…) — hand edits and legacy addresses are both rejected`);
  }
  if (g.replay?.mode !== "interaction" && g.complete_interaction_route_graph === true) {
    fail(`${sat}: graph ${rel} claims completeness without an interaction-mode replay`);
  }
  // Visual evidence identity: screenshot bytes stay untracked, but their sha256s
  // are inside the address; when the local shots directory exists, the bytes
  // must hash-match what the graph records.
  if (g.shots_dir) {
    const shotsDir = path.resolve(appRoot, "..", "..", g.shots_dir);
    if (fs.existsSync(shotsDir)) {
      for (const node of g.nodes ?? []) {
        for (const shot of [node.screenshot, ...(node.posture_matrix ?? [])].filter(Boolean)) {
          const file = path.join(shotsDir, `${node.id}-${shot.sha256.slice(0, 12)}.png`);
          if (!fs.existsSync(file)) continue;
          const digest = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
          if (digest !== shot.sha256) {
            fail(`${sat}: shot ${path.basename(file)} does not hash-match the addressed record`);
          }
        }
      }
    }
  }
  const q = g.quarantine ?? {};
  if (q.network_policy !== "local-only" || q.corpus_mutation !== "denied" ||
      q.html_injection !== "denied" || q.spa_fallback !== "denied") {
    fail(`${sat}: graph ${rel} lacks the full quarantine attestation (AUD-WS-005)`);
  }
  if ((q.violations ?? []).length > 0) {
    fail(`${sat}: graph ${rel} records ${q.violations.length} quarantine violations — the capture is inadmissible`);
  }
  const complete = g.complete_interaction_route_graph === true;
  const blockers = g.blockers ?? [];
  if (complete && blockers.length > 0) {
    fail(`${sat}: graph ${rel} claims complete with ${blockers.length} blockers`);
  }
  if (complete && g.replay?.walked_all_edges !== true) {
    fail(`${sat}: graph ${rel} claims complete without a replay walk of every edge`);
  }
  if (!allowIncomplete && !complete) {
    fail(`${sat}: manifest claims a complete graph but ${rel} records complete_interaction_route_graph=${g.complete_interaction_route_graph}`);
  }
  if (allowIncomplete && complete && src.graph.complete_interaction_route_graph !== true) {
    fail(`${sat}: graph ${rel} is complete but the manifest still records it incomplete — update the manifest in the same change`);
  }
}

if (requireReady) {
  const s = surfaces.find((x) => x.id === surfaceFilter);
  if (s && !(s.seed_graph_ready_for_rehome === true || s.greenfield_authorization)) {
    const gaps = (s.sources ?? [])
      .filter((src) => src.seed_role === "baseline" && src.graph?.complete_interaction_route_graph !== true)
      .map((src) => `${src.slug}${src.graph_capture_note ? " (typed capture note)" : ""}`);
    fail(`surface ${surfaceFilter}: seed gate CLOSED — not ready for rehome; ${gaps.length ? `incomplete baseline sources: ${gaps.join(", ")}` : "no baseline seed exists (corroborating-only surface; a ruling must name its baseline or the greenfield lane must be opened)"}. A block record never opens work.`);
  }
  if (s) {
    const pending = (s.sources ?? [])
      .filter((src) => src.seed_role === "corroborating" && src.graph?.complete_interaction_route_graph !== true)
      .map((src) => src.slug);
    if (pending.length > 0) {
      console.log(`seed-provenance: surface ${surfaceFilter} corroborating context — ${pending.length} corroborating source(s) not interaction-complete (${pending.join(", ")}); typed states preserved, never gate inputs.`);
    }
  }
}

finish(requireReady ? `require-ready ${surfaceFilter}` : surfaceFilter ? `surface ${surfaceFilter}` : "full tracked gate");

function finish(mode) {
  if (failures.length > 0) {
    for (const f of failures) console.error(`seed-provenance: ${f}`);
    console.error(`\nseed-provenance FAIL (${mode}) — ${failures.length} failures`);
    process.exit(1);
  }
  const total = (manifest.surfaces ?? []).reduce((n, s) => n + (s.sources?.length ?? 0), 0);
  console.log(
    `seed-provenance OK (${mode}) — ${manifest.surfaces?.length ?? 0} surfaces, ${total} sources ` +
      `(${seenProtected.size} protected, ${seenRetained.size} retained, ${seenDormant.size} dormant), fail-closed graph gate armed.`,
  );
  process.exit(0);
}
