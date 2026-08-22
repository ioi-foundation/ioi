#!/usr/bin/env node
// LIVE-TENANT ATLAS RECORDER (remediation v2, 2026-08-20). Attaches over CDP to the OWNER'S
// authenticated Chrome (127.0.0.1:9222) and records reference states from the LIVE Foundry
// tenant — a richer source than the static mirror (whose dead lanes produced mirror-scoped
// verdicts). STRICTLY READ-ONLY: navigate + census + screenshot in a NEW page; ZERO clicks,
// zero form submissions, zero installs/saves; the owner's tabs are never touched.
//
// CANVAS-AWARE census (the #vertex-canvas-correction fix): expressed-IA also counts toolbar
// controls, canvas/svg surfaces, and panel tabs — a booting canvas no longer scores dead.
// Usage: node apps/hypervisor/scripts/record-live-tenant-atlas.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ORIGIN = "https://test.usw-23.palantirfoundry.com";
const OUT = join(ROOT, ".artifacts", "live-tenant-atlas");
mkdirSync(OUT, { recursive: true });
const matrix = JSON.parse(readFileSync(join(ROOT, "harvest-app-parity-matrix.json"), "utf8"));

const CENSUS = () => {
  const t = (el) => (el.textContent || "").trim().replace(/\s+/g, " ");
  const caps = (document.body.innerText || "").split("\n").map((x) => x.trim())
    .filter((x) => x.length >= 3 && x.length <= 26 && /^[A-Z][A-Z0-9 ()/&-]+$/.test(x) && /[A-Z]{3}/.test(x));
  const svgs = [...document.querySelectorAll("svg,canvas")].filter((e) => { const r = e.getBoundingClientRect(); return r.width > 300 && r.height > 200; });
  return {
    url: location.href, title: document.title,
    headings: [...document.querySelectorAll("h1,h2,h3")].map(t).filter(Boolean).slice(0, 8),
    tabs: [...new Set([...document.querySelectorAll('[role="tab"]')].map(t).filter(Boolean))].slice(0, 12),
    columns: [...new Set([...document.querySelectorAll("th")].map(t).filter(Boolean))].slice(0, 12),
    facet_groups: [...new Set(caps)].slice(0, 14),
    rows: document.querySelectorAll("tbody tr").length,
    toolbar_controls: [...document.querySelectorAll("button,[role=button]")].map(t).filter((x) => x && x.length < 30).slice(0, 24),
    canvas_surfaces: svgs.length,
    text_len: (document.body.innerText || "").length,
    login_wall: /sign in|log in|multipass/i.test(document.title) && location.pathname.includes("login"),
  };
};
const expressesIa = (c) => c.columns.length > 0 || c.facet_groups.length > 1 || c.tabs.length > 0 || c.rows > 0
  || c.toolbar_controls.length >= 6 || c.canvas_surfaces > 0;

const EXTRA = [
  { slug: "vertex", key: "search-page", path: "/workspace/vertex/?q=graph" },
  { slug: "vertex", key: "template-canvas", path: "/workspace/vertex/graph/ri.opus.main.graph-template.0ad31874-deb8-447c-80d4-8f5b6ca2e6a0" },
  { slug: "explorer", key: "hubble-landing", path: "/workspace/hubble/" },
  { slug: "designer", key: "create", path: "/workspace/solution-design/create" },
  { slug: "notepad", key: "create", path: "/workspace/notepad/create" },
  { slug: "logic", key: "create", path: "/workspace/logic-app/create-new" },
  { slug: "widgets", key: "create", path: "/workspace/custom-widgets/new" },
  { slug: "evalsuites", key: "create", path: "/workspace/evals/create-new" },
];

const { chromium } = await import("playwright");
const browser = await chromium.connectOverCDP("http://127.0.0.1:9222");
const ctx = browser.contexts()[0];
const pg = await ctx.newPage();
const seeds = {};
const states = [...matrix.seeds.map((s) => ({ slug: s.slug, key: "landing", path: s.capture_base })), ...EXTRA];
for (const st of states) {
  try {
    await pg.goto(ORIGIN + st.path, { waitUntil: "domcontentloaded", timeout: 30000 });
    await pg.waitForTimeout(4500);
    const c = await pg.evaluate(CENSUS);
    const shot = join(OUT, `${st.slug}-${st.key}`.replace(/[^a-z0-9-]+/gi, "_") + ".png");
    await pg.screenshot({ path: shot });
    (seeds[st.slug] ||= []).push({ key: st.key, path: st.path, ia: c, expresses_ia: expressesIa(c), screenshot: shot.replace(ROOT + "/", "") });
    console.log(`${st.slug.padEnd(14)} ${st.key.padEnd(16)} ia=${expressesIa(c)} (cols=${c.columns.length} facets=${c.facet_groups.length} tabs=${c.tabs.length} rows=${c.rows} ctrl=${c.toolbar_controls.length} canvas=${c.canvas_surfaces})${c.login_wall ? " LOGIN-WALL" : ""}`);
  } catch (e) {
    (seeds[st.slug] ||= []).push({ key: st.key, path: st.path, error: String(e).slice(0, 120) });
    console.error(`${st.slug.padEnd(14)} ${st.key.padEnd(16)} ERR ${String(e).slice(0, 70)}`);
  }
}
await pg.close();
writeFileSync(join(ROOT, "reference-live-tenant-atlas.v1.json"), JSON.stringify({
  schema: "ioi.hypervisor.reference-live-tenant-atlas.v1",
  origin: ORIGIN,
  doctrine: "READ-ONLY states recorded from the LIVE authenticated tenant over CDP (owner session, owner-authorized 2026-08-20). Canvas-aware expressed-IA (toolbar/canvas/panel detection — the #vertex-canvas-correction fix). Live verdicts SUPERSEDE mirror-scoped dead-lane verdicts per seed; screenshots under .artifacts/live-tenant-atlas/.",
  recorded_at: new Date().toISOString(),
  seeds,
}, null, 2) + "\n");
console.log("\nmanifest → apps/hypervisor/reference-live-tenant-atlas.v1.json");
