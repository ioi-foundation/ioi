#!/usr/bin/env node
// I-3 — FAMILY REFERENCE ATLAS RECORDER (Reference-UX Remediation Program v2, W0).
//
// Generalizes the pipeline-reference-atlas discipline to every seed: for each seed with a usable
// reference, record its interaction states — LANDING + one state per TAB LANE (clicked live) +
// one per in-app SUB-ROUTE (navigated directly; kinds tab_lane|authoring from the census) — and
// census each state's EXPRESSED IA (facets, table columns, rows, cards, empty-state copy). This
// supplies the §3.2 test ("does the empty state express the IA") as recorded evidence, replacing
// the landing-only verdicts that produced the shell_clean_only misclassifications.
//
// The pipeline atlas's 1:1 join discipline is preserved at the artifact layer: every state this
// recorder emits names how it was reached (goto path or clicked tab label), and downstream
// adjudications/ports must cite a recorded state — a lane with no atlas state is not shippable
// (plan §8 invariant).
//
// Usage: node apps/hypervisor/scripts/record-family-reference-atlas.mjs <slug> [slug...]
//        node apps/hypervisor/scripts/record-family-reference-atlas.mjs --all
// Output: screenshots → apps/hypervisor/.artifacts/family-atlas/<slug>/ (untracked evidence pack)
//         manifest    → apps/hypervisor/reference-family-atlas.v1.json (TRACKED; merged per slug)
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ORIGIN = process.env.IOI_REFERENCE_ORIGIN || "http://localhost:9225";
const MANIFEST = join(ROOT, "reference-family-atlas.v1.json");
const EVIDENCE = join(ROOT, ".artifacts", "family-atlas");

const matrix = JSON.parse(readFileSync(join(ROOT, "harvest-app-parity-matrix.json"), "utf8"));
const census = JSON.parse(readFileSync(join(ROOT, "reference-subroute-census.v1.json"), "utf8"));
const censusBySlug = Object.fromEntries(census.seeds.map((s) => [s.slug, s]));

// The per-state IA census — the recorded answer to §3.2.
const CENSUS_FN = () => {
  const t = (el) => (el.textContent || "").trim().replace(/\s+/g, " ");
  const cols = [...document.querySelectorAll("th")].map(t).filter(Boolean);
  // facet-group heuristic: short ALL-CAPS lines in the body (the reference's filter sidebars
  // label facet groups in caps: STATUS, CONDITION, OWNER, …)
  const caps = (document.body.innerText || "").split("\n").map((x) => x.trim())
    .filter((x) => x.length >= 3 && x.length <= 26 && /^[A-Z][A-Z0-9 ()/&-]+$/.test(x) && /[A-Z]{3}/.test(x));
  const empty = (document.body.innerText || "").match(/\bNo [a-z][a-z ]{2,40}\b|Get started[^\n]{0,80}/i);
  return {
    title: document.title,
    headings: [...document.querySelectorAll("h1,h2,h3")].map(t).filter(Boolean).slice(0, 10),
    tabs: [...new Set([...document.querySelectorAll('[role="tab"]')].map(t).filter(Boolean))].slice(0, 14),
    columns: [...new Set(cols)].slice(0, 14),
    facet_groups: [...new Set(caps)].slice(0, 16),
    rows: document.querySelectorAll("tbody tr").length,
    cards: document.querySelectorAll("[class*='card'],.bp6-card").length,
    empty_copy: empty ? empty[0] : "",
    text_len: (document.body.innerText || "").length,
  };
};
const expressesIa = (c) => (c.columns.length > 0 || c.facet_groups.length > 1 || c.tabs.length > 0 || c.rows > 0);

async function recordSeed(browser, slug) {
  const row = matrix.seeds.find((s) => s.slug === slug);
  const cen = censusBySlug[slug];
  if (!row) return { slug, error: "no matrix row" };
  const base = row.reference_url_override || ORIGIN + row.capture_base;
  const baseOrigin = new URL(base).origin;
  const out = { slug, owner: row.owner, reference_base: base, recorded_states: [], errors: [] };
  const dir = join(EVIDENCE, slug);
  mkdirSync(dir, { recursive: true });

  const states = [{ key: "landing", reach: { goto: base } }];
  for (const lane of cen?.tab_lanes || []) states.push({ key: `tab:${lane}`, reach: { goto: base, clickTab: lane } });
  for (const sr of cen?.subroutes || []) {
    if (sr.kind === "tab_lane" || sr.kind === "authoring" || sr.kind === "splash_alias") states.push({ key: `${sr.kind}:${sr.path}`, reach: { goto: baseOrigin + sr.path } });
  }

  for (const st of states) {
    const pg = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const httpErrs = [];
    pg.on("response", (r) => { if (r.status() >= 400) httpErrs.push(`${r.status()} ${r.url().slice(0, 80)}`); });
    try {
      await pg.goto(st.reach.goto, { waitUntil: "domcontentloaded", timeout: 25000 });
      await pg.waitForTimeout(3200);
      if (st.reach.clickTab) {
        const hit = await pg.evaluate((label) => {
          const els = [...document.querySelectorAll('[role="tab"], a, button')];
          const el = els.find((x) => (x.textContent || "").trim().replace(/\s+/g, " ").startsWith(label));
          if (el) { el.click(); return true; } return false;
        }, st.reach.clickTab);
        if (!hit) throw new Error(`tab "${st.reach.clickTab}" not found`);
        await pg.waitForTimeout(2500);
      }
      const ia = await pg.evaluate(CENSUS_FN);
      const shot = join(dir, st.key.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 80) + ".png");
      await pg.screenshot({ path: shot });
      out.recorded_states.push({
        key: st.key, reach: st.reach, url: pg.url(), ia, expresses_ia: expressesIa(ia),
        http_errors: [...new Set(httpErrs)].slice(0, 6), screenshot: shot.replace(ROOT + "/", ""),
      });
      console.log(`  ${slug} · ${st.key} → ia=${expressesIa(ia)} (cols=${ia.columns.length} facets=${ia.facet_groups.length} tabs=${ia.tabs.length} rows=${ia.rows})`);
    } catch (e) {
      out.errors.push({ state: st.key, error: String(e).slice(0, 140) });
      console.error(`  ${slug} · ${st.key} FAILED: ${String(e).slice(0, 90)}`);
    } finally { await pg.close(); }
  }
  return out;
}

const args = process.argv.slice(2);
if (!args.length) { console.error("usage: record-family-reference-atlas.mjs <slug…>|--all"); process.exit(2); }
const slugs = args[0] === "--all" ? matrix.seeds.map((s) => s.slug) : args;
const { chromium } = await import("playwright");
const browser = await chromium.launch();
const prev = existsSync(MANIFEST) ? JSON.parse(readFileSync(MANIFEST, "utf8")) : { schema: "ioi.hypervisor.reference-family-atlas.v1", doctrine: "recorded reference interaction states per seed — landing + tab lanes + in-app sub-routes, each with its expressed-IA census (§3.2 evidence). A lane with no recorded state is not shippable.", origin: ORIGIN, seeds: {} };
for (const slug of slugs) prev.seeds[slug] = await recordSeed(browser, slug);
prev.recorded_at = new Date().toISOString();
writeFileSync(MANIFEST, JSON.stringify(prev, null, 2) + "\n");
await browser.close();
const tot = Object.values(prev.seeds).reduce((a, s) => a + (s.recorded_states?.length || 0), 0);
console.log(`atlas manifest → apps/hypervisor/reference-family-atlas.v1.json (${Object.keys(prev.seeds).length} seeds · ${tot} states)`);
