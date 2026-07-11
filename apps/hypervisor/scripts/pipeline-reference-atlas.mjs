#!/usr/bin/env node
// Pipeline Builder REFERENCE STATE ATLAS (#66) — the recorded interaction states of the live
// reference workspace (the :9225 mirror boots the real Blueprint SPA: menus, tabs, zoom, pan,
// selection all genuinely fire; only data-backed panels hit dead XHRs). The atlas is the single
// source of state definitions for BOTH sides: verify-hypervisor-pipeline-interaction.mjs replays
// every state against the reference AND against /__ioi/pipeline and compares the certified
// chrome per state (data masks only over daemon/session values). Run this file directly to
// (re)record the reference evidence pack under .artifacts/ref-atlas/.
//
// Usage: node apps/hypervisor/scripts/pipeline-reference-atlas.mjs   (records evidence pack)
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const REFERENCE_URL = "http://localhost:9225/workspace/builder/ri.eddie.main.pipeline.e73d6ae7-f6fe-4ac5-82a2-320d9f188590/sandbox/a082bef2-8826-4e6c-8925-871bcdb56c44";

// Reference boot: the What's-New modal opens on load; dismiss it and let the SPA settle (same
// discipline as the pixel harness's pipeline preCapture hook).
export async function refReady(page) {
  await page.waitForTimeout(3500);
  await page.evaluate(() => {
    for (const p of document.querySelectorAll(".bp6-portal")) {
      if (/what'?s new|whats-new/i.test(p.textContent || "")) p.remove();
    }
    const close = [...document.querySelectorAll("button")].find((b) => /^close$/i.test((b.textContent || "").trim()));
    if (close) close.click();
  });
  await page.waitForTimeout(400);
}

const refClickTab = async (page, label) => {
  await page.evaluate((l) => {
    const tabs = [...document.querySelectorAll('[class*="pipeline-builder-components__tab"]')];
    const t = tabs.find((x) => (x.textContent || "").trim().startsWith(l));
    if (t) t.click();
  }, label);
  await page.waitForTimeout(500);
};

// ---- THE ATLAS — every state names how the reference reaches it (live clicks) and how IOI
// reaches it (URL params; the URL is IOI's interaction truth). `compareIslands` picks which
// certified chrome regions are pixel-compared in that state; `extraMasks` (CSS-px rect factories
// over the viewport) exclude regions that are BY DESIGN different content (real IOI truth vs the
// reference's session data) — never controls, geometry, menus, or interaction states.
export const ATLAS_STATES = [
  {
    key: "initial",
    description: "workspace at rest — 3 tray tabs, Selection preview active, outputs panel",
    ref: async (page) => { await refReady(page); },
    ioiQuery: "",
    compareIslands: ["header", "toolbar", "floatbtns", "legend", "zoom", "tray", "right"],
    extraMasks: () => [],
  },
  {
    key: "node-selected",
    description: "a graph node selected — selection ring, Preview tab inserted, tray shows the node",
    ref: async (page) => {
      await refReady(page);
      await page.evaluate(() => { const n = document.querySelector("svg g[data-nodeid]"); if (n) { const r = n.getBoundingClientRect(); const ev = new MouseEvent("click", { bubbles: true, clientX: r.x + r.width / 2, clientY: r.y + r.height / 2 }); n.dispatchEvent(ev); } });
      await page.waitForTimeout(700);
    },
    ioiQuery: "&node=transform",
    // RECORDED DIVERGENCE: on selection the reference ENABLES its authoring strip (Transform/
    // Join/Union/... colorize); IOI keeps authoring disabled-with-reason (no authoring authority)
    // — so the toolcard is excluded here BY RECORD, not silently.
    compareIslands: ["header", "floatbtns", "legend", "zoom", "tray"],
    // The right panel differs BY REFERENCE BEHAVIOR here: the reference keeps outputs (as does
    // IOI post-#66) but its card gains hover affordances — masked by the standing outcard masks.
    extraMasks: (vw) => [{ left: vw - 386, top: 51, w: 386, h: 2000, why: "right-main content — ref session outputs vs real IOI projection (values, not geometry)" }],
  },
  {
    key: "tab-suggestions",
    description: "Suggestions tray tab active",
    ref: async (page) => { await refReady(page); await refClickTab(page, "Suggestions"); },
    ioiQuery: "&tab=suggestions",
    compareIslands: ["header", "toolbar", "floatbtns", "legend", "zoom", "tray"],
    extraMasks: () => [],
  },
  {
    key: "tab-warnings",
    description: "Pipeline warnings tray tab active",
    ref: async (page) => { await refReady(page); await refClickTab(page, "Pipeline warnings"); },
    ioiQuery: "&tab=warnings",
    compareIslands: ["header", "toolbar", "floatbtns", "legend", "zoom", "tray"],
    extraMasks: () => [],
  },
  {
    key: "tray-collapsed",
    description: "bottom bar collapsed via the chevron",
    ref: async (page) => {
      await refReady(page);
      await page.evaluate(() => { const b = document.querySelector('a[aria-label="Toggle bottom bar"], [aria-label="Toggle bottom bar"]'); if (b) b.click(); });
      await page.waitForTimeout(500);
    },
    ioiQuery: "&tray=0",
    // The collapsed tab row sits at the bottom edge on both sides; the tray island template
    // assumes the expanded position, so compare the stable islands only and let the verifier
    // assert the collapsed geometry structurally on both sides.
    compareIslands: ["header", "toolbar", "floatbtns", "legend"],
    extraMasks: () => [],
    refProbe: async (page) => page.evaluate(() => { const b = document.querySelector('[aria-label="Toggle bottom bar"]'); return b ? b.getAttribute("aria-expanded") : null; }),
  },
  {
    key: "panel-search",
    description: "right panel swapped to pipeline search",
    ref: async (page) => {
      await refReady(page);
      await page.evaluate(() => { const b = document.querySelector('[aria-label="Search pipeline"]'); if (b) b.click(); });
      await page.waitForTimeout(600);
    },
    ioiQuery: "&panel=search",
    // RECORDED DIVERGENCE: reference search-mode restructures the canvas chrome (toolcard
    // reflows, Legend becomes "Legend (search)" with a results row); IOI's search panel keeps the
    // standard canvas chrome and ports the FUNCTIONAL lane (the real record census). Toolcard +
    // legend excluded here by record.
    compareIslands: ["header", "floatbtns", "zoom", "tray"],
    extraMasks: (vw) => [{ left: vw - 386, top: 51, w: 336, h: 2000, why: "right-main — ref empty search session vs IOI's real record census (content, not chrome; the 50px icon strip stays compared)" }],
  },
  {
    key: "zoomed",
    description: "zoom-in applied twice from the zoom stack",
    ref: async (page) => {
      await refReady(page);
      await page.evaluate(() => { const b = document.querySelector('[aria-label="Zoom in"]'); if (b) { b.click(); b.click(); } });
      await page.waitForTimeout(500);
    },
    ioiQuery: "",
    ioiDrive: async (page) => { await page.click("#pb-zin"); await page.click("#pb-zin"); await page.waitForTimeout(200); },
    compareIslands: ["header", "toolbar", "floatbtns", "legend", "zoom", "tray", "right"],
    extraMasks: () => [],
  },
];

// The atlas CONTROL CENSUS — every reference control the recon atlas inventoried, by the SAME id
// the control matrix uses. The interaction verifier asserts a 1:1 join: no census control may be
// missing from the matrix (silently omitted) and no matrix entry may claim a control the census
// never saw (invented).
export const ATLAS_CONTROLS = [
  "hdr.file-menu", "hdr.settings-menu", "hdr.help-menu", "hdr.favorite-star", "hdr.batch-badge",
  "hdr.tabs-mode", "hdr.undo", "hdr.redo", "hdr.branch-selector", "hdr.branch-actions",
  "hdr.saved", "hdr.propose", "hdr.deploy-icon", "hdr.build-settings-icon", "hdr.actions",
  "hdr.share", "hdr.panel-toggle",
  "cmd.build", "cmd.preview", "cmd.schedule", "cmd.deploy", "cmd.lineage", "cmd.ontology-manager",
  "tool.pan-mode", "tool.select-mode", "tool.marquee", "tool.graph-remove", "tool.layout",
  "tool.grid-snap", "tool.text-box", "tool.canvas-search", "tool.collapse-colors",
  "tool.add-data", "tool.reusables", "tool.transform", "tool.join", "tool.union", "tool.split",
  "tool.import-model", "tool.use-llm", "tool.aip-generate", "tool.aip-explain", "tool.edit",
  "legend.toggle", "legend.eye", "legend.add-color",
  "canvas.node-select", "canvas.node-keyboard", "canvas.pan", "canvas.ctrl-wheel-zoom",
  "canvas.zoom-in", "canvas.zoom-out", "canvas.zoom-fit", "canvas.node-context-open",
  "canvas.node-context-copy-ref", "canvas.node-context-authoring", "canvas.quick-strip",
  "canvas.snapshot-pill", "canvas.edge-insert",
  "tray.tab-selection", "tray.tab-preview", "tray.tab-suggestions", "tray.tab-warnings",
  "tray.collapse", "tray.node-subtabs",
  "out.search", "out.card-select", "out.gear", "out.panel-table-icon", "out.add",
  "out.lineage-btn", "out.more-options", "out.edit-settings",
  "rail.outputs", "rail.search", "rail.changes", "rail.deploy", "rail.build-settings",
  "rail.schedules", "rail.file-tree", "rail.unit-tests", "rail.sources",
  "ioi.pipeline-picker",
];

// ---- Evidence-pack recorder (run directly) -----------------------------------------------------
const HERE = dirname(fileURLToPath(import.meta.url));
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { chromium } = await import("playwright");
  const OUT = join(HERE, "..", ".artifacts", "ref-atlas");
  mkdirSync(OUT, { recursive: true });
  const b = await chromium.launch();
  const results = [];
  for (const vp of [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    for (const st of ATLAS_STATES) {
      const pg = await b.newPage({ viewport: vp });
      try {
        await pg.goto(REFERENCE_URL, { waitUntil: "domcontentloaded", timeout: 30000 });
        await st.ref(pg);
        const shot = join(OUT, `state-${st.key}-${vp.width}.png`);
        await pg.screenshot({ path: shot });
        results.push({ state: st.key, viewport: `${vp.width}x${vp.height}`, screenshot: shot, description: st.description });
        console.log(`recorded ${st.key} @ ${vp.width}`);
      } catch (e) {
        results.push({ state: st.key, viewport: `${vp.width}x${vp.height}`, error: String(e).slice(0, 200) });
        console.error(`FAILED ${st.key} @ ${vp.width}: ${e}`);
      } finally {
        await pg.close();
      }
    }
  }
  writeFileSync(join(OUT, "atlas-manifest.json"), JSON.stringify({ reference_url: REFERENCE_URL, recorded_at: new Date().toISOString(), states: results, controls: ATLAS_CONTROLS }, null, 2));
  await b.close();
  console.log(`atlas evidence pack → ${OUT}`);
}
