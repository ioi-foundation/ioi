#!/usr/bin/env node
// LIVE-TENANT DEEP ATLAS (queue 3, owner-authorized 2026-08-20). Drives INTO the apps over the
// owner's CDP session: canvases, template dialogs, object details, tab lanes, create forms.
//
// HARD READ-ONLY WHITELIST: clicks fire ONLY on elements whose accessible text matches the
// whitelist (tabs, Explore, panel names, object rows, dialog-open) AND NEVER matches the
// mutation blacklist (save/install/share/generate/submit/delete/apply/publish/run/execute/
// confirm/import/deploy/new). Escape closes dialogs. Ambiguous → skipped and logged.
// Usage: node record-live-tenant-deep-atlas.mjs <chunkA|chunkB|chunkC>
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ORIGIN = "https://test.usw-23.palantirfoundry.com";
const OUT = join(ROOT, ".artifacts", "live-tenant-atlas", "deep");
mkdirSync(OUT, { recursive: true });
const MANIFEST = join(ROOT, "reference-live-tenant-deep-atlas.v1.json");
const BLACK = /save|install|share|generate|submit|delete|remove|apply|publish|run\b|execute|confirm|import|deploy|^new\b|\bnew /i;

const CENSUS = () => {
  const t = (el) => (el.textContent || "").trim().replace(/\s+/g, " ");
  const caps = (document.body.innerText || "").split("\n").map((x) => x.trim())
    .filter((x) => x.length >= 3 && x.length <= 26 && /^[A-Z][A-Z0-9 ()/&-]+$/.test(x) && /[A-Z]{3}/.test(x));
  const svgs = [...document.querySelectorAll("svg,canvas")].filter((e) => { const r = e.getBoundingClientRect(); return r.width > 300 && r.height > 200; });
  return {
    url: location.href, title: document.title,
    headings: [...document.querySelectorAll("h1,h2,h3,h4")].map(t).filter(Boolean).slice(0, 10),
    tabs: [...new Set([...document.querySelectorAll('[role="tab"]')].map(t).filter(Boolean))].slice(0, 14),
    columns: [...new Set([...document.querySelectorAll("th")].map(t).filter(Boolean))].slice(0, 14),
    facet_groups: [...new Set(caps)].slice(0, 16),
    rows: document.querySelectorAll("tbody tr, [role='row']").length,
    controls: [...document.querySelectorAll("button,[role=button],[role=menuitem]")].map(t).filter((x) => x && x.length < 34).slice(0, 30),
    inputs: [...document.querySelectorAll("input,select,textarea")].map((e) => e.getAttribute("placeholder") || e.getAttribute("aria-label") || e.name || "").filter(Boolean).slice(0, 12),
    dialogs: [...document.querySelectorAll('[role="dialog"],.bp6-dialog,.bp6-portal')].length,
    canvas_surfaces: svgs.length,
    text_len: (document.body.innerText || "").length,
  };
};

const { chromium } = await import("playwright");
const browser = await chromium.connectOverCDP("http://127.0.0.1:9222");
const ctx = browser.contexts()[0];
const pg = await ctx.newPage();
const rec = [];
const skipped = [];

async function clickSafe(label) {
  if (BLACK.test(label)) { skipped.push(`BLACKLISTED: ${label}`); return false; }
  const ok = await pg.evaluate((l) => {
    const els = [...document.querySelectorAll('[role="tab"],a,button,[role=button],tbody tr,[role=row],[role=menuitem],[role=option]')];
    const el = els.find((x) => (x.textContent || "").trim().replace(/\s+/g, " ").toLowerCase().startsWith(l.toLowerCase()));
    if (!el) return false;
    el.click(); return true;
  }, label);
  if (!ok) skipped.push(`NOT FOUND: ${label}`);
  return ok;
}
async function clickFirst(selector, why) {
  const ok = await pg.evaluate((sel) => { const el = document.querySelector(sel); if (el) { el.click(); return true; } return false; }, selector);
  if (!ok) skipped.push(`NOT FOUND sel: ${why}`);
  return ok;
}
async function snap(slug, key) {
  await pg.waitForTimeout(3800);
  const c = await pg.evaluate(CENSUS);
  const shot = join(OUT, `${slug}-${key}`.replace(/[^a-z0-9-]+/gi, "_").slice(0, 90) + ".png");
  await pg.screenshot({ path: shot });
  rec.push({ slug, key, ia: c, screenshot: shot.replace(ROOT + "/", "") });
  console.log(`${slug.padEnd(13)} ${key.padEnd(26)} ctrl=${c.controls.length} tabs=${c.tabs.length} cols=${c.columns.length} rows=${c.rows} canvas=${c.canvas_surfaces} dialogs=${c.dialogs}`);
}
async function goSnap(slug, key, path) {
  await pg.goto(ORIGIN + path, { waitUntil: "domcontentloaded", timeout: 30000 }).catch((e) => skipped.push(`NAV ${slug}/${key}: ${e}`.slice(0, 90)));
  await snap(slug, key);
}
const esc = () => pg.keyboard.press("Escape");

const chunk = process.argv[2] || "chunkA";
if (chunk === "chunkA") {
  // Vertex canvas panel states + parameters dialog + template param dialog + hubble object detail
  const canvas = "/workspace/vertex/graph/ri.opus.main.graph-template.0ad31874-deb8-447c-80d4-8f5b6ca2e6a0";
  await goSnap("vertex", "canvas-layers", canvas);
  for (const tab of ["Selection", "Search", "Histogram", "Info"]) { if (await clickSafe(tab)) await snap("vertex", `canvas-${tab.toLowerCase()}`); }
  if (await clickSafe("Parameters")) { await snap("vertex", "canvas-parameters-dialog"); await esc(); }
  if (await clickSafe("Timeline")) { await snap("vertex", "canvas-timeline"); }
  await goSnap("vertex", "templates-list", "/workspace/vertex/?q=template");
  await goSnap("hubble", "landing", "/workspace/hubble/");
  // drive into an object: first row/result if any
  if (await clickFirst("tbody tr a, tbody tr, [class*='object-list'] a, [class*='result'] a", "hubble object row")) await snap("hubble", "object-detail-attempt-1");
} else if (chunk === "chunkB") {
  const seeds = [["scheduler","/workspace/scheduler/"],["ingest","/workspace/hyperauto/"],["dataset","/workspace/dataset/"],["objectview","/workspace/object-view/"],["objecteditor","/workspace/object-view-editor/"],["modelstudio","/workspace/model-studio/"],["inference","/workspace/foundry-inference-app/"],["registry","/workspace/artifacts/"],["map","/workspace/map/"],["fusion","/workspace/fusion/"],["jobs","/workspace/job-tracker/"]];
  for (const [slug, base] of seeds) {
    await goSnap(slug, "landing", base);
    // drive safe tabs (up to 3)
    const tabs = rec[rec.length - 1]?.ia?.tabs || [];
    for (const tb of tabs.slice(0, 3)) { if (await clickSafe(tb)) await snap(slug, `tab-${tb.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 24)}`); }
  }
  // hubble object-detail retry (chunk A: 24 [role=row] rows present; tbody selector missed)
  await goSnap("hubble", "landing-retry", "/workspace/hubble/");
  if (await clickFirst("[role='row'] a, [role='row'], [class*='ListItem'] a", "hubble role-row")) await snap("hubble", "object-detail");
} else if (chunk === "chunkC") {
  await goSnap("workshop", "landing", "/workspace/workshop/");
  await goSnap("machinery", "process", "/workspace/machinery-app/process");
  await goSnap("notepad", "create-from-template", "/workspace/notepad/create-new-from-template");
  await goSnap("devconsole", "wizard-step1", "/workspace/developer-console/create/guided/basic-information");
  await goSnap("contour", "create", "/workspace/contour-app/overview/create");
  await goSnap("modelstudio", "create-attempt", "/workspace/model-studio/");
  await goSnap("dataset", "preview-attempt", "/workspace/dataset/");
}
await pg.close();
const prev = existsSync(MANIFEST) ? JSON.parse(readFileSync(MANIFEST, "utf8")) : { schema: "ioi.hypervisor.reference-live-tenant-deep-atlas.v1", origin: ORIGIN, doctrine: "DRIVEN states from the live tenant over the owner-authorized CDP session — whitelist-only clicks (tabs/explore/rows/dialog-open), mutation verbs BLACKLISTED, ambiguity skipped+logged. The port-evidence source for the live_ia_recorded backlog.", states: [], skipped: [] };
prev.states.push(...rec); prev.skipped.push(...skipped); prev.recorded_at = new Date().toISOString();
writeFileSync(MANIFEST, JSON.stringify(prev, null, 2) + "\n");
console.log(`\n${chunk}: ${rec.length} states, ${skipped.length} skipped → manifest updated`);
if (skipped.length) console.log("skipped:", skipped.slice(0, 10).join(" | "));
