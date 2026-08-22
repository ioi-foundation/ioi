#!/usr/bin/env node
// REFERENCE SUB-ROUTE CENSUS (R0 recon) — the in-app routes and tab lanes the seed inventory
// never captured.
//
// WHY THIS EXISTS: harvest-seed-inventory.mjs derives its 39 seeds from capture workspace ROOTS
// (`/workspace/<dir>/`) — a filesystem unit — and the port program set its done-bar at the
// LANDING STATE of each root. A reference app is not a route: its tabs and authoring entries are
// real in-app paths one segment away. This recorder enumerates them so the port program can be
// re-based on the owner family's IA instead of the capture mount.
//
// Classification of each discovered path:
//   authoring    — a create/new entry (…/create, …/new, …/create-new, …/quickCreate). The certified
//                  ports uniformly declare authoring a "named gap disabled in place"; that gap was
//                  never tested against the reference IA that exists at these paths.
//   tab_lane     — a sibling list/detail lane of the same app (the missed port unit)
//   instance     — a concrete record/store instance (example data, never estate truth)
//   splash_alias — the app's own splash re-entry (not a distinct surface)
//
// Usage: node apps/hypervisor/scripts/record-reference-subroute-census.mjs
// Requires the reference mirror on http://localhost:9225.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ORIGIN = process.env.IOI_REFERENCE_ORIGIN || "http://localhost:9225";

export function classify(path, base) {
  if (/\/(create|new|create-new|create-pipeline|create-template|create-new-from-template|quickCreate|onboarding)(\/|$)/.test(path)) return "authoring";
  if (/\/splash$/.test(path)) return "splash_alias";
  if (/\/ri\.[a-z0-9-]+\./i.test(path) || /\/store\//.test(path)) return "instance";
  return "tab_lane";
}

const M = JSON.parse(readFileSync(join(ROOT, "harvest-app-parity-matrix.json"), "utf8"));

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { chromium } = await import("playwright");
  const b = await chromium.launch();
  const seeds = [];
  for (const s of M.seeds) {
    const base = s.capture_base;
    const pg = await b.newPage({ viewport: { width: 1440, height: 900 } });
    const rec = { owner: s.owner, slug: s.slug, capture_base: base, reference_clean_state: s.reference_clean_state, parity_class: s.parity_class };
    try {
      const resp = await pg.goto(ORIGIN + base, { waitUntil: "domcontentloaded", timeout: 25000 });
      rec.status = resp ? resp.status() : null;
      await pg.waitForTimeout(3000);
      const r = await pg.evaluate((bs) => {
        const norm = (h) => { try { return new URL(h, location.href).pathname; } catch { return null; } };
        const seen = new Map();
        for (const a of document.querySelectorAll("a[href]")) {
          const p = norm(a.getAttribute("href"));
          if (!p || !p.startsWith(bs) || p === bs || p === bs.replace(/\/$/, "")) continue;
          if (!seen.has(p)) seen.set(p, (a.textContent || "").trim().replace(/\s+/g, " ").slice(0, 48));
        }
        return {
          title: document.title,
          tab_lanes: [...new Set([...document.querySelectorAll('[role="tab"]')].map((t) => (t.textContent || "").trim().replace(/\s+/g, " ")).filter(Boolean))].slice(0, 12),
          paths: [...seen].map(([p, label]) => ({ path: p, label })),
        };
      }, base);
      rec.title = r.title;
      rec.tab_lanes = r.tab_lanes;
      rec.subroutes = r.paths.map((x) => ({ ...x, kind: classify(x.path, base) }));
    } catch (e) {
      rec.error = String(e).slice(0, 160);
      rec.tab_lanes = []; rec.subroutes = [];
    }
    await pg.close();
    seeds.push(rec);
  }
  await b.close();

  const tally = {};
  for (const s of seeds) for (const x of s.subroutes) tally[x.kind] = (tally[x.kind] || 0) + 1;
  const artifact = {
    schema: "ioi.hypervisor.reference-subroute-census.v1",
    origin: ORIGIN,
    recorded_at: new Date().toISOString(),
    doctrine: "recon only — no ports, no promotions, parity_class untouched. Records the in-app IA the workspace-root seed inventory never enumerated.",
    total_seeds: seeds.length,
    total_subroutes: Object.values(tally).reduce((a, b2) => a + b2, 0),
    total_tab_lanes: seeds.reduce((a, s) => a + s.tab_lanes.length, 0),
    seeds_with_uncaptured_ia: seeds.filter((s) => s.subroutes.length || s.tab_lanes.length).length,
    by_kind: tally,
    download_blocked: seeds.filter((s) => /Download is starting/.test(s.error || "")).map((s) => `${s.owner}/${s.slug}`),
    seeds,
  };
  writeFileSync(join(ROOT, "reference-subroute-census.v1.json"), JSON.stringify(artifact, null, 2) + "\n");
  console.log(`census → apps/hypervisor/reference-subroute-census.v1.json`);
  console.log(`  ${artifact.total_subroutes} in-app routes · ${artifact.total_tab_lanes} tab lanes · ${artifact.seeds_with_uncaptured_ia}/${seeds.length} seeds carry uncaptured IA`);
  console.log(`  by kind: ${JSON.stringify(tally)}`);
}
