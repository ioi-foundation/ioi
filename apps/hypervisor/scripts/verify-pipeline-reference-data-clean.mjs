#!/usr/bin/env node
// PIPELINE REFERENCE — DATA-CLEAN PREFLIGHT (#37 re-harvest infrastructure).
//
// Answers ONE question honestly, from the LIVE local mirror (not prose): "Can the mirror now render a
// real, data-clean Pipeline Builder reference — the builder canvas with graph nodes, toolbar, right
// output panel, and preview/data lanes — with no error and no failed/blank data?"
//
// It renders THREE lanes in a real browser and classifies each:
//   1. PROXY landing   — /__apps/pipeline            (the path the hardened parity harness opens)
//   2. DIRECT landing  — :9225/workspace/builder/     (the pipeline-list landing on the raw mirror)
//   3. DIRECT canvas   — :9225/workspace/builder/<RID> (a specific pipeline → the graph editor canvas)
//      RID(s): IOI_BUILDER_EXAMPLE_RID (comma list) or the recorded example RIDs below.
//
// data_clean = TRUE only when: the proxy landing renders builder IA (non-blank, non-errored) AND the
// direct landing renders builder IA with NO data-lane failure AND at least one canvas lane renders the
// graph (nodes present) + a toolbar + a right output panel + a bottom tray, with NO error. Anything
// else → data_clean=false with an EXACT per-lane blocking reason. Blank-body / global-chrome-only never
// passes (a content-area-text floor is enforced). This gate is what a re-harvest must flip to true
// before /__ioi/pipeline may be promoted reference_ported → daemon_wired.
//
// Emits (IOI_HARNESS_ARTIFACT_DIR, default apps/hypervisor/.artifacts/pipeline-reharvest):
//   result.json  ·  screens/<lane>.png (reference screenshots + direct-vs-proxy evidence)
//
// Usage: node apps/hypervisor/scripts/verify-pipeline-reference-data-clean.mjs
// Exit: 0 always writes the artifact; exit 2 = BLOCKED (mirror/serve unreachable). data_clean is read
// from result.json by callers (the pipeline verifier + the promotion gate) — a non-zero exit is NOT
// used to signal "dirty" (a dirty reference is the honest, expected result today).

import { chromium } from "playwright";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const MIRROR = (process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const ARTIFACT_DIR = process.env.IOI_HARNESS_ARTIFACT_DIR || path.join(appRoot, ".artifacts", "pipeline-reharvest");
const VW = 1440, VH = 900;

// Recorded example builder CANVAS sub-paths (RID + sandbox → the graph editor). The bare RID renders
// the landing; the /sandbox/ path opens the canvas. Override via IOI_BUILDER_EXAMPLE_RID (comma list of
// sub-paths appended to /workspace/builder/).
const DEFAULT_RIDS = [
  "ri.eddie.main.pipeline.e73d6ae7-f6fe-4ac5-82a2-320d9f188590/sandbox/a082bef2-8826-4e6c-8925-871bcdb56c44",
  "ri.eddie.main.pipeline.5ef60976-74bb-4b67-b119-a4b6af284f09",
];
const RIDS = (process.env.IOI_BUILDER_EXAMPLE_RID || "").split(",").map((s) => s.trim()).filter(Boolean);
const CANVAS_RIDS = RIDS.length ? RIDS : DEFAULT_RIDS;

// A page is ERRORED if any of these appear; a DATA lane FAILED if any of these appear. Broadened to
// catch React error-boundary / RID / init strings (review #37) — the dangerous direction is a crashed
// canvas reading as non-errored.
const PAGE_ERR = /an error occurred|something went wrong|went wrong|failed to initiali[sz]e|unable to (?:initiali[sz]e|render|display)|invalid resource identifier|not found|forbidden|unauthori[sz]ed|\bTypeError\b|cannot read propert/i;
const DATA_FAIL = /failed to load|unable to load|couldn'?t load|no results found|loading\s*(?:\.\.\.|…)/i;

async function capture(ctx, url, pngPath) {
  const page = await ctx.newPage();
  // Intercept the webpack frontend chunks: a MISSING lazy chunk is served by the mirror as a tiny empty
  // STUB (server.js registers the chunk id with no module code). The canvas is a lazy chunk, so the
  // first stubbed chunk crashes it ("Failed to initialize"). Record the stubbed hashes — the exact
  // blocker a re-harvest must backfill (download_missing_assets after refresh_auth).
  const stubbedChunks = [];
  page.on("response", async (r) => {
    const u = r.url();
    if (/\/assets\/content-addressable-storage\/frontend\/[a-f0-9]+\.js(\?|$)/.test(u)) {
      try { const body = await r.body(); if (body.length < 400) { const h = (u.match(/frontend\/([a-f0-9]+)\.js/) || [])[1]; if (h && !stubbedChunks.includes(h)) stubbedChunks.push(h); } } catch { /* */ }
    }
  });
  let loaded = true;
  try { await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25000 }); await page.waitForTimeout(5000); }
  catch { loaded = false; }
  let info = { url, loaded, theme: "?", railLen: 0, contentLen: 0, bodyLen: 0, regions: [], canvasNodes: 0, canvasBody: false, toolbar: false, outputPanel: false, tray: false, pageErr: false, dataFail: false, sample: "", full: "", stubbedChunks };
  try {
    const res = await page.evaluate(({ VW, VH }) => {
      const lumOf = (el) => { const m = (el && getComputedStyle(el).backgroundColor || "").match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(",").map(Number); if (p.length >= 4 && p[3] === 0) return null; return (0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]) / 255; };
      const effLum = (x, y) => { let el = document.elementFromPoint(x, y); let n = 0; while (el && n++ < 30) { const r = el.getBoundingClientRect(); if (r.width * r.height >= VW * VH * 0.02) { const l = lumOf(el); if (l != null) return l; } el = el.parentElement; } return 1; };
      const pts = []; for (const fx of [0.5, 0.64, 0.78, 0.9]) for (const fy of [0.3, 0.5, 0.7]) pts.push([fx, fy]);
      const lums = pts.map(([fx, fy]) => effLum(VW * fx, VH * fy)).sort((a, b) => a - b);
      const theme = lums[Math.floor(lums.length / 2)] >= 0.5 ? "light" : "dark";
      // visible in-viewport text: rail (x<0.16·VW) vs content (x>=0.16·VW) vs BODY (content AND below the
      // header/toolbar band, top>=0.2·VH). The landing gate uses bodyLen so full-width header chrome
      // (breadcrumb/tabs/search/title) can't alone satisfy the "renders builder IA" floor (review #37).
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      let railLen = 0, contentLen = 0, bodyLen = 0, all = ""; let tn;
      while ((tn = walker.nextNode())) {
        const txt = (tn.textContent || "").trim(); if (!txt) continue;
        const par = tn.parentElement; if (!par) continue;
        const cs = getComputedStyle(par); if (cs.visibility === "hidden" || cs.display === "none" || cs.opacity === "0") continue;
        const rng = document.createRange(); rng.selectNodeContents(tn); const r = rng.getBoundingClientRect();
        if (r.width > 3 && r.height > 3 && r.right > 0 && r.bottom > 0 && r.left < VW && r.top < VH) { all += " " + txt; if (r.left < VW * 0.16) railLen += txt.length; else { contentLen += txt.length; if (r.top >= VH * 0.2) bodyLen += txt.length; } }
      }
      const vis = (q) => Array.from(document.querySelectorAll(q)).filter((el) => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 24 && r.height > 20 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0"; });
      const boxes = (q) => vis(q).map((el) => el.getBoundingClientRect());
      const geom = { rail: (b) => b.left < VW * 0.15 && b.height > VH * 0.4, header: (b) => b.top < VH * 0.15 && b.width > VW * 0.5 && b.height < VH * 0.28, toolbar: (b) => b.top < VH * 0.45 && b.width > VW * 0.25 && b.height < VH * 0.22, body: (b) => b.width > VW * 0.4 && b.height > VH * 0.35, right: (b) => b.right > VW * 0.8 && b.height > VH * 0.3 && b.width < VW * 0.6, tray: (b) => b.bottom > VH * 0.8 && b.width > VW * 0.4 && b.height < VH * 0.4 };
      const SEL = { rail: 'nav,[class*="rail" i],[class*="sidebar" i]', header: 'header,[class*="header" i],[class*="topbar" i]', toolbar: '[role="toolbar"],[class*="toolbar" i]', body: 'main,[class*="canvas" i],[class*="graph" i],table', right: 'aside,[class*="rightpanel" i],[class*="right-panel" i],[class*="outputpanel" i],[class*="inspector" i]', tray: 'footer,[class*="tray" i],[class*="bottompanel" i],[class*="previewpanel" i],[class*="statusbar" i]' };
      const regions = Object.keys(SEL).filter((k) => boxes(SEL[k]).some(geom[k]));
      // canvas graph NODES: scoped to a canvas/GRAPH ANCESTOR (not any element whose class contains
      // 'node'/'board' — that matches TreeNode / dashboard chrome), node-sized, in the content column.
      const nodeEls = vis('[class*="canvas" i] [class*="node" i],[class*="graph" i] [class*="node" i],[class*="canvas" i] [data-node],[class*="graph" i] [data-node],[class*="vertex" i],[class*="pipelinenode" i],[class*="pipelineboard" i] [class*="card" i],[class*="graph" i] [class*="card" i]').filter((el) => { const r = el.getBoundingClientRect(); return r.left > VW * 0.16 && r.width > 60 && r.width < VW * 0.5 && r.height > 30; });
      const canvasNodes = nodeEls.length;
      // The pipeline GRAPH BODY must actually be present (a canvas/graph container filling the body) —
      // so a shell rendering a nodes list + toolbar/aside/footer chrome but no graph fails canvasClean.
      const canvasBody = boxes('[class*="canvas" i],[class*="graph" i],[class*="board" i]').some(geom.body);
      const toolbar = boxes(SEL.toolbar).some(geom.toolbar);
      const outputPanel = boxes(SEL.right).some(geom.right);
      const tray = boxes(SEL.tray).some(geom.tray);
      const clean = all.replace(/\s+/g, " ").trim();
      return { theme, railLen, contentLen, bodyLen, regions, canvasNodes, canvasBody, toolbar, outputPanel, tray, sample: clean.slice(0, 200), full: clean.slice(0, 4000), title: document.title };
    }, { VW, VH });
    Object.assign(info, res);
    info.pageErr = PAGE_ERR.test(info.full || "");
    info.dataFail = DATA_FAIL.test(info.full || "");
  } catch (e) { info.err = String(e.message || e).slice(0, 120); }
  let screenshotBytes = 0;
  try { const buf = await page.screenshot({ path: pngPath, fullPage: false }); screenshotBytes = buf ? buf.length : 0; } catch { /* */ }
  await page.close();
  info.screenshotBytes = screenshotBytes;
  info.title = info.title || "";
  const fullText = info.full || ""; delete info.full;
  info.error_reason = info.pageErr ? (fullText.match(PAGE_ERR) || [""])[0] : info.dataFail ? (fullText.match(DATA_FAIL) || [""])[0] : "";
  return info;
}

async function run() {
  const up = await fetch(`${MIRROR}/workspace/builder/`).then((r) => r.ok).catch(() => false);
  const serveUp = await fetch(`${SERVE}/__apps/pipeline`).then((r) => r.ok).catch(() => false);
  if (!up || !serveUp) { console.error(`BLOCKED: mirror(${MIRROR})=${up} serve(${SERVE})=${serveUp}`); process.exit(2); }
  mkdirSync(path.join(ARTIFACT_DIR, "screens"), { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: VW, height: VH } });

  const lanes = [];
  const add = async (lane, kind, url) => { const png = path.join(ARTIFACT_DIR, "screens", `${lane}.png`); const c = await capture(ctx, url, png); lanes.push({ lane, kind, ...c, screenshot: `screens/${lane}.png` }); return lanes[lanes.length - 1]; };

  const proxyLanding = await add("proxy-landing", "proxy_landing", `${SERVE}/__apps/pipeline`);
  const directLanding = await add("direct-landing", "direct_landing", `${MIRROR}/workspace/builder/`);
  const canvasLanes = [];
  for (let i = 0; i < CANVAS_RIDS.length; i++) canvasLanes.push(await add(`direct-canvas-${i + 1}`, "direct_canvas", `${MIRROR}/workspace/builder/${CANVAS_RIDS[i]}`));

  await browser.close();

  // Per-lane data-clean judgement. iaOk uses BODY-region text (not header chrome). A landing must also
  // carry a builder-specific IA marker (not merely be a non-error page). A canvas must present a real
  // graph BODY + nodes + toolbar + output panel + tray. The dangerous direction is a false PASS.
  const contentFloor = 120; // body-region text beyond global chrome
  const BUILDER_MARK = /pipeline|builder|datasource|transform|dataset|output/i;
  const iaOk = (l) => (l.bodyLen || 0) >= contentFloor && !l.pageErr;
  const builderIa = (l) => BUILDER_MARK.test(l.title || "") || BUILDER_MARK.test(l.sample || "");
  const landingClean = (l) => iaOk(l) && !l.dataFail && builderIa(l);
  const canvasClean = (l) => iaOk(l) && !l.dataFail && l.canvasBody && l.canvasNodes >= 2 && l.toolbar && l.outputPanel && l.tray;

  const proxyOk = landingClean(proxyLanding);
  const directLandingOk = landingClean(directLanding);
  const cleanCanvas = canvasLanes.find(canvasClean) || null;
  const data_clean = proxyOk && directLandingOk && !!cleanCanvas;

  // Exact blocking reason (first failing gate).
  const reasons = [];
  const landingWhy = (l) => l.pageErr ? `errored: "${l.error_reason}"` : l.dataFail ? `data lane failed: "${l.error_reason}"` : (l.bodyLen || 0) < contentFloor ? `blank/global-chrome-only body=${l.bodyLen}` : !builderIa(l) ? `no builder IA marker (title/sample lack pipeline/builder/datasource/…)` : "ok?";
  if (!proxyOk) reasons.push(`proxy /__apps/pipeline not data-clean (${landingWhy(proxyLanding)})`);
  if (!directLandingOk) reasons.push(`direct landing /workspace/builder/ not data-clean (${landingWhy(directLanding)})`);
  if (!cleanCanvas) reasons.push(`no data-clean canvas among ${CANVAS_RIDS.length} target(s): ${canvasLanes.map((l) => `${l.lane}(${l.pageErr ? `err:"${l.error_reason}"` : l.dataFail ? `data-fail:"${l.error_reason}"` : `graphBody=${l.canvasBody} nodes=${l.canvasNodes} toolbar=${l.toolbar} output=${l.outputPanel} tray=${l.tray}`}${(l.stubbedChunks || []).length ? `; missing lazy chunk(s): ${l.stubbedChunks.join(",")}` : ""})`).join(" · ")}`);
  const blocking_reason = data_clean ? "" : reasons.join("  |  ");

  const result = {
    schema: "ioi.hypervisor.pipeline-reference-data-clean.v1",
    generated_for: "#37 Pipeline reference re-harvest — data-clean preflight",
    surface: "pipeline", proxy_route: "/__apps/pipeline", direct_route: "/workspace/builder/", canvas_rids: CANVAS_RIDS,
    data_clean, blocking_reason,
    gate: "data_clean requires: proxy landing IA (non-blank, non-errored) + direct landing IA with no data-fail + a canvas with >=2 graph nodes + toolbar + right output panel + bottom tray, no error/data-fail. Blank/global-chrome-only never passes.",
    lanes: lanes.map((l) => ({ lane: l.lane, kind: l.kind, url: l.url, title: l.title, theme: l.theme, contentLen: l.contentLen, bodyLen: l.bodyLen, regions: l.regions, canvasBody: l.canvasBody, canvasNodes: l.canvasNodes, toolbar: l.toolbar, outputPanel: l.outputPanel, tray: l.tray, pageErr: l.pageErr, dataFail: l.dataFail, error_reason: l.error_reason, missing_lazy_chunks: l.stubbedChunks || [], screenshotBytes: l.screenshotBytes, screenshot: l.screenshot, sample: l.sample })),
  };
  writeFileSync(path.join(ARTIFACT_DIR, "result.json"), JSON.stringify(result, null, 2) + "\n");

  console.log(`\nPipeline reference data-clean preflight → ${data_clean ? "DATA-CLEAN ✓" : "NOT data-clean ✗"}`);
  for (const l of result.lanes) console.log(`  ${l.lane.padEnd(16)} ${l.kind.padEnd(15)} err=${l.pageErr ? "Y" : "·"} dataFail=${l.dataFail ? "Y" : "·"} body=${String(l.bodyLen).padStart(4)} graph=${l.canvasBody ? "Y" : "·"} nodes=${l.canvasNodes} tb=${l.toolbar ? "Y" : "·"} out=${l.outputPanel ? "Y" : "·"} tray=${l.tray ? "Y" : "·"}${l.error_reason ? `  [${l.error_reason}]` : ""}${(l.missing_lazy_chunks || []).length ? `  {missing chunk: ${l.missing_lazy_chunks.join(",")}}` : ""}`);
  if (!data_clean) console.log(`\nBLOCKING REASON: ${blocking_reason}`);
  console.log(`\nartifact: ${path.relative(process.cwd(), ARTIFACT_DIR)}/ (result.json + screens/)`);
  return result;
}

run().catch((e) => { console.error("preflight crashed:", e); process.exit(1); });
