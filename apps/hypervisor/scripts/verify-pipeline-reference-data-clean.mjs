#!/usr/bin/env node
// PIPELINE REFERENCE — DATA-CLEAN PREFLIGHT (#37 infra; DIAGNOSIS RE-BASELINED in #38).
//
// Answers, from the LIVE local mirror (not prose): what is the true state of the Pipeline Builder
// reference, and WHY is it (not) data-clean? #37 concluded "missing lazy chunks → needs a fresh Foundry
// re-harvest." That was WRONG: a <400b size heuristic mis-classified genuinely-small REAL chunks (e.g.
// the 364b `splitPathsBySizeLoader`) as absent. The real blocker is a CORS ORIGIN MISMATCH — the app's
// captured absolute fetch URLs use `localhost:9225`, so loading the mirror from `127.0.0.1:9225` makes
// every eddie/graphql/session fetch cross-origin → CORS-blocked → "Failed to fetch" → "Failed to
// initialize." The captured data is COMPLETE: from the MATCHING origin the canvas renders a full
// data-clean pipeline graph — no re-harvest, no fresh auth.
//
// This gate now (a) detects a MISSING chunk by the server's GENERATED-STUB SIGNATURE (an IIFE that
// registers the chunk id with an EMPTY module map / logs "[STUB CHUNK LOADER]"), NOT by size; and
// (b) is ORIGIN-AWARE — it renders three lanes and classifies the outcome:
//   - proxy_landing      : SERVE /__apps/pipeline            (the hardened-harness reference path)
//   - matchorigin_canvas : localhost:9225 /workspace/builder/<rid>/sandbox/<id>  (the app's own origin)
//   - crossorigin_canvas : 127.0.0.1:9225 /workspace/builder/<rid>/sandbox/<id>  (the mismatched origin)
//
// DIAGNOSIS ∈ { data_clean, cors_origin_mismatch, missing_chunk, app_data_failure }. `data_clean` (bool)
// is the harness/promotion signal = the harness-path (proxy) reference is certifiable. It stays FALSE
// today (the proxy/landing path is origin-blocked / is a list not a canvas) — but the blocking_reason is
// now the TRUE cause, and `reference_data_complete` records that the matching-origin canvas is clean.
//
// Emits (IOI_HARNESS_ARTIFACT_DIR, default apps/hypervisor/.artifacts/pipeline-reharvest):
//   result.json  ·  screens/<lane>.png
//
// Usage: node apps/hypervisor/scripts/verify-pipeline-reference-data-clean.mjs
// Exit: 0 writes the artifact; 2 = BLOCKED (mirror/serve unreachable). data_clean is read from
// result.json by callers (the pipeline verifier); a non-zero exit is NOT used to signal "dirty".

import { chromium } from "playwright";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
// The mirror's captured absolute fetch URLs use `localhost` — that is the MATCHING origin. The hardened
// harness (and IOI_HARVEST_MIRROR_URL) use `127.0.0.1`, which is the MISMATCHED origin.
const MATCH_ORIGIN = (process.env.IOI_MIRROR_MATCH_ORIGIN || "http://localhost:9225").replace(/\/$/, "");
const CROSS_ORIGIN = (process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const ARTIFACT_DIR = process.env.IOI_HARNESS_ARTIFACT_DIR || path.join(appRoot, ".artifacts", "pipeline-reharvest");
const VW = 1440, VH = 900;

// A recorded example builder CANVAS sub-path (RID + sandbox → the graph editor). Override via
// IOI_BUILDER_EXAMPLE_RID (a sub-path appended to /workspace/builder/).
const CANVAS_SUBPATH = process.env.IOI_BUILDER_EXAMPLE_RID || "ri.eddie.main.pipeline.e73d6ae7-f6fe-4ac5-82a2-320d9f188590/sandbox/a082bef2-8826-4e6c-8925-871bcdb56c44";

// ---- STUB DETECTION (exported for the regression unit test) ---------------------------------------
// The mirror (server.js) serves an ABSENT frontend chunk as a GENERATED stub: a self-invoking IIFE that
// registers the webpack chunk id with an EMPTY module map (`self[key].push([[chunkId], {}])`) and logs
// "[STUB CHUNK LOADER]". A REAL chunk is a webpack push with actual module code (`{<n>: function...}`),
// even when it is only a few hundred bytes. Detection MUST key on this signature, NEVER on size.
//
// Two alternations: (1) the literal log marker — the PRIMARY signal, emitted unconditionally by the
// server for every JS stub; (2) the STRUCTURAL empty-module-map IIFE push — a backstop that must still
// fire if the marker were ever reworded. The real served template has ~1014 chars between `(function() {`
// and the `.push([[…],{}])` (it carries a currentScript/data-webpack fallback block), so the `{0,1600}`
// window comfortably covers the real shape with margin (regression-tested with the marker REMOVED). Note
// a real chunk is `(self.X=self.X||[]).push(...)` with a NON-empty map, not an `(function(){…` IIFE, so
// the structural alternation does not match genuine Foundry chunks (accepted residual: a hand-written
// IIFE chunk with a legitimately empty map would false-positive — not a shape the mirror or Foundry emits).
export const GENERATED_STUB_SIG = /\[STUB CHUNK LOADER\]|\(\s*function\s*\(\s*\)\s*\{[\s\S]{0,1600}?\.push\(\s*\[\s*\[[^\]]*\]\s*,\s*\{\s*\}\s*\]\s*\)/;
export const CSS_STUB_SIG = /^\s*\/\*\s*Stub CSS Chunk\s*\*\/\s*$/;
export function isGeneratedStub(body) {
  const t = typeof body === "string" ? body : (body ? body.toString("utf8") : "");
  if (!t) return false;
  return GENERATED_STUB_SIG.test(t) || CSS_STUB_SIG.test(t);
}

const PAGE_ERR = /an error occurred|something went wrong|went wrong|failed to initiali[sz]e|unable to (?:initiali[sz]e|render|display)|invalid resource identifier|not found|forbidden|unauthori[sz]ed|\bTypeError\b|cannot read propert/i;
const DATA_FAIL = /failed to load|unable to load|couldn'?t load|no results found|loading\s*(?:\.\.\.|…)/i;
const CORS_SIG = /blocked by CORS policy|Failed to fetch|net::ERR_FAILED|Access to fetch at/i;

async function capture(ctx, url, pngPath) {
  const page = await ctx.newPage();
  const pageOrigin = new URL(url).origin;
  const stubChunks = [], corsHits = [], crossOriginFails = [];
  page.on("response", async (r) => {
    const u = r.url();
    if (/\/assets\/content-addressable-storage\/frontend\/[a-f0-9]+\.(?:js|css)(?:\?|$)/.test(u)) {
      try { const body = await r.body(); if (isGeneratedStub(body)) { const h = (u.match(/frontend\/([a-f0-9]+)\./) || [])[1]; if (h && !stubChunks.includes(h)) stubChunks.push(h); } } catch { /* */ }
    }
  });
  page.on("console", (m) => { const t = m.text(); if (m.type() === "error" && CORS_SIG.test(t)) corsHits.push(t.slice(0, 120)); });
  page.on("requestfailed", (r) => { try { const ru = new URL(r.url()); if (ru.origin !== pageOrigin) crossOriginFails.push(`${ru.origin}${ru.pathname}`.slice(0, 90)); } catch { /* */ } });
  let loaded = true;
  try { await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25000 }); await page.waitForTimeout(6000); }
  catch { loaded = false; }
  let info = { url, pageOrigin, loaded, theme: "?", bodyLen: 0, regions: [], canvasNodes: 0, canvasBody: false, toolbar: false, outputPanel: false, panelPresent: false, tray: false, pageErr: false, dataFail: false, sample: "", title: "", full: "" };
  try {
    const res = await page.evaluate(({ VW, VH }) => {
      const lumOf = (el) => { const m = (el && getComputedStyle(el).backgroundColor || "").match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(",").map(Number); if (p.length >= 4 && p[3] === 0) return null; return (0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]) / 255; };
      const effLum = (x, y) => { let el = document.elementFromPoint(x, y); let n = 0; while (el && n++ < 30) { const r = el.getBoundingClientRect(); if (r.width * r.height >= VW * VH * 0.02) { const l = lumOf(el); if (l != null) return l; } el = el.parentElement; } return 1; };
      const pts = []; for (const fx of [0.5, 0.64, 0.78, 0.9]) for (const fy of [0.3, 0.5, 0.7]) pts.push([fx, fy]);
      const lums = pts.map(([fx, fy]) => effLum(VW * fx, VH * fy)).sort((a, b) => a - b);
      const theme = lums[Math.floor(lums.length / 2)] >= 0.5 ? "light" : "dark";
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      let bodyLen = 0, all = ""; let tn;
      while ((tn = walker.nextNode())) {
        const txt = (tn.textContent || "").trim(); if (!txt) continue;
        const par = tn.parentElement; if (!par) continue;
        const cs = getComputedStyle(par); if (cs.visibility === "hidden" || cs.display === "none" || cs.opacity === "0") continue;
        const rng = document.createRange(); rng.selectNodeContents(tn); const r = rng.getBoundingClientRect();
        if (r.width > 3 && r.height > 3 && r.right > 0 && r.bottom > 0 && r.left < VW && r.top < VH) { all += " " + txt; if (r.left >= VW * 0.16 && r.top >= VH * 0.2) bodyLen += txt.length; }
      }
      const vis = (q) => Array.from(document.querySelectorAll(q)).filter((el) => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 24 && r.height > 20 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0"; });
      const boxes = (q) => vis(q).map((el) => el.getBoundingClientRect());
      const geom = { rail: (b) => b.left < VW * 0.15 && b.height > VH * 0.4, header: (b) => b.top < VH * 0.15 && b.width > VW * 0.5 && b.height < VH * 0.28, toolbar: (b) => b.top < VH * 0.45 && b.width > VW * 0.25 && b.height < VH * 0.22, body: (b) => b.width > VW * 0.4 && b.height > VH * 0.35, right: (b) => b.right > VW * 0.8 && b.height > VH * 0.25 && b.width < VW * 0.6, tray: (b) => b.bottom > VH * 0.7 && b.width > VW * 0.3 && b.height < VH * 0.5 };
      const SEL = { rail: 'nav,[class*="rail" i],[class*="sidebar" i]', header: 'header,[class*="header" i],[class*="topbar" i]', toolbar: '[role="toolbar"],[class*="toolbar" i]', body: 'main,[class*="canvas" i],[class*="graph" i],[class*="pipeline-builder-core__content" i],table', right: 'aside,[class*="rightpanel" i],[class*="right-panel" i],[class*="outputpanel" i],[class*="inspector" i],[class*="side-bar" i],[class*="sidebar" i]', tray: 'footer,[class*="tray" i],[class*="bottompanel" i],[class*="previewpanel" i],[class*="statusbar" i],[class*="bottom-bar" i],[class*="components" i],[class*="draggable-container" i]' };
      const regions = Object.keys(SEL).filter((k) => boxes(SEL[k]).some(geom[k]));
      // Graph nodes in THIS builder are SVG labels (~70x21, className is an SVGAnimatedString, so route
      // them past `vis`'s h>20 floor with a lighter check). Several SVG spans overlay one pipeline node,
      // so DEDUP by a coarse position bucket to count DISTINCT nodes, not label fragments.
      const visEl = (el) => { const s = getComputedStyle(el); const r = el.getBoundingClientRect(); return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0" && r.width > 6 && r.height > 6; };
      const nodeRaw = Array.from(document.querySelectorAll('[class*="graph" i] [class*="node" i],[class*="pipeline-builder" i] [class*="node" i],[class*="canvas" i] [class*="node" i],[class*="reactflow" i] [class*="node" i],[class*="vertex" i],[data-node]')).filter((el) => { if (!visEl(el)) return false; const r = el.getBoundingClientRect(); return r.left > VW * 0.16 && r.top > VH * 0.18 && r.width > 20 && r.width < VW * 0.5 && r.height > 8 && r.height < VH * 0.4; });
      const nodeBuckets = new Set(nodeRaw.map((el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.left / 48)}:${Math.round(r.top / 48)}`; }));
      const canvasBody = boxes('[class*="canvas" i],[class*="graph" i],[class*="reactflow" i],[class*="board" i],[class*="pipeline-builder-core__content" i]').some(geom.body);
      // "output/side panel present" — a right inspector OR a bottom components/palette bar (this builder
      // uses a bottom bar rather than a right panel).
      const panelPresent = boxes(SEL.right).some(geom.right) || boxes(SEL.tray).some(geom.tray);
      const clean = all.replace(/\s+/g, " ").trim();
      return { theme, bodyLen, regions, canvasNodes: nodeBuckets.size, canvasBody, toolbar: boxes(SEL.toolbar).some(geom.toolbar), outputPanel: boxes(SEL.right).some(geom.right), panelPresent, tray: boxes(SEL.tray).some(geom.tray), sample: clean.slice(0, 220), full: clean.slice(0, 4000), title: document.title };
    }, { VW, VH });
    Object.assign(info, res);
    info.pageErr = PAGE_ERR.test(info.full || "");
    info.dataFail = DATA_FAIL.test(info.full || "");
  } catch (e) { info.err = String(e.message || e).slice(0, 120); }
  let screenshotBytes = 0;
  try { const buf = await page.screenshot({ path: pngPath, fullPage: false }); screenshotBytes = buf ? buf.length : 0; } catch { /* */ }
  await page.close();
  const fullText = info.full || ""; delete info.full;
  info.screenshotBytes = screenshotBytes;
  info.generatedStubChunks = stubChunks;
  info.corsBlocked = corsHits.length > 0;
  info.corsHitCount = corsHits.length;
  info.crossOriginFetchFails = [...new Set(crossOriginFails)].length;
  info.error_reason = info.pageErr ? (fullText.match(PAGE_ERR) || [""])[0] : info.dataFail ? (fullText.match(DATA_FAIL) || [""])[0] : "";
  return info;
}

const BUILDER_MARK = /pipeline|builder|datasource|transform|dataset|output/i;
const contentFloor = 120;
export const builderIa = (l) => BUILDER_MARK.test(l.title || "") || BUILDER_MARK.test(l.sample || "");
export const iaOk = (l) => (l.bodyLen || 0) >= contentFloor && !l.pageErr;
// A canvas is DATA-CLEAN when the pipeline graph actually renders: a graph body + ≥3 distinct nodes +
// a toolbar + a side/bottom panel, with no page error / data-fail / CORS block and no generated-stub
// chunk. (This builder draws SVG nodes and uses a bottom components bar instead of a right panel.)
export const canvasClean = (l) => iaOk(l) && !l.dataFail && !l.corsBlocked && ((l.generatedStubChunks || []).length === 0) && l.canvasBody && l.canvasNodes >= 3 && l.toolbar && l.panelPresent;

// PURE diagnosis over the three captured lanes (exported for the regression unit test — deterministic,
// no browser). Distinguishes: data_clean (the proxy/harness lane is certifiable) / missing_chunk (a
// generated STUB is served on any lane — signature, not size) / cors_origin_mismatch (the matching-origin
// canvas is clean but the cross-origin lane is CORS-blocked) / app_data_failure.
export function diagnose({ proxyLanding, matchCanvas, crossCanvas, matchOrigin = MATCH_ORIGIN, crossOrigin = CROSS_ORIGIN }) {
  // A genuine missing chunk is decided ONLY from the promotion-gating lanes (the harness/proxy path + the
  // matching-origin canvas) — NOT the deliberately-broken cross-origin lane, which can lazy-load a stub
  // during its CORS failure cascade and would otherwise resurrect the exact #37 "missing chunk" misdiagnosis
  // even when the matching-origin data is complete. (A truly absent chunk is stubbed on BOTH origins, so it
  // still shows on proxy/match.)
  const reference_data_complete = canvasClean(matchCanvas);
  const stubbed = [...new Set([proxyLanding, matchCanvas].filter(Boolean).flatMap((l) => l.generatedStubChunks || []))];
  const missing_chunk = stubbed.length > 0;
  // A CORS/origin mismatch needs POSITIVE cross-origin evidence: an explicit "blocked by CORS policy"
  // console error, or ≥2 failed cross-origin fetches (one benign beacon/analytics failure is not enough).
  const cors_origin_mismatch = reference_data_complete && (crossCanvas.corsBlocked || (crossCanvas.crossOriginFetchFails || 0) >= 2) && !canvasClean(crossCanvas);
  const data_clean = canvasClean(proxyLanding);
  let diagnosis, blocking_reason;
  if (data_clean) { diagnosis = "data_clean"; blocking_reason = ""; }
  else if (missing_chunk) { diagnosis = "missing_chunk"; blocking_reason = `genuinely MISSING frontend chunk(s) served as generated stubs (signature-detected): ${stubbed.join(", ")} — backfill required`; }
  else if (cors_origin_mismatch) { diagnosis = "cors_origin_mismatch"; blocking_reason = `the captured data is COMPLETE (the matching-origin canvas ${matchOrigin} renders a clean pipeline graph: nodes=${matchCanvas.canvasNodes} toolbar=${matchCanvas.toolbar} output=${matchCanvas.outputPanel}). The failure is a CORS/ORIGIN MISMATCH — the app's captured fetch URLs use ${new URL(matchOrigin).host} but the cross-origin lane (${new URL(crossOrigin).host}) is CORS-blocked (corsHits=${crossCanvas.corsHitCount} crossOriginFetchFails=${crossCanvas.crossOriginFetchFails}) → "${crossCanvas.error_reason}". The proxy/harness lane /__apps/pipeline is not yet certifiable (${proxyLanding.pageErr ? `errored: "${proxyLanding.error_reason}"` : proxyLanding.dataFail ? `data lane failed: "${proxyLanding.error_reason}"` : "renders the landing list, not a canvas"}). NO re-harvest and NO fresh Foundry auth are required — the fix is an ORIGIN/SERVING alignment (same-origin serving or CORS) + pointing the harness reference at a data-clean canvas.`; }
  else { diagnosis = reference_data_complete ? "app_or_data_partial" : "app_data_failure"; blocking_reason = `proxy/harness reference not data-clean (${proxyLanding.pageErr ? `errored: "${proxyLanding.error_reason}"` : proxyLanding.dataFail ? `data-fail: "${proxyLanding.error_reason}"` : `body=${proxyLanding.bodyLen}`}); matching-origin canvas clean=${reference_data_complete}; no generated-stub chunk detected.`; }
  return { data_clean, diagnosis, reference_data_complete, missing_chunk, cors_origin_mismatch, generated_stub_chunks: stubbed, blocking_reason };
}

async function run() {
  const mirrorUp = await fetch(`${MATCH_ORIGIN}/workspace/builder/`).then((r) => r.ok).catch(() => false);
  const serveUp = await fetch(`${SERVE}/__apps/pipeline`).then((r) => r.ok).catch(() => false);
  if (!mirrorUp || !serveUp) { console.error(`BLOCKED: mirror(${MATCH_ORIGIN})=${mirrorUp} serve(${SERVE})=${serveUp}`); process.exit(2); }
  mkdirSync(path.join(ARTIFACT_DIR, "screens"), { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: VW, height: VH } });
  const cap = async (lane, url) => { const c = await capture(ctx, url, path.join(ARTIFACT_DIR, "screens", `${lane}.png`)); return { lane, ...c, screenshot: `screens/${lane}.png` }; };

  const proxyLanding = await cap("proxy-landing", `${SERVE}/__apps/pipeline`);
  const matchCanvas = await cap("matchorigin-canvas", `${MATCH_ORIGIN}/workspace/builder/${CANVAS_SUBPATH}`);
  const crossCanvas = await cap("crossorigin-canvas", `${CROSS_ORIGIN}/workspace/builder/${CANVAS_SUBPATH}`);
  await browser.close();
  const lanes = [proxyLanding, matchCanvas, crossCanvas];

  const { data_clean, diagnosis, reference_data_complete, missing_chunk, cors_origin_mismatch, generated_stub_chunks: stubbed, blocking_reason } = diagnose({ proxyLanding, matchCanvas, crossCanvas, matchOrigin: MATCH_ORIGIN, crossOrigin: CROSS_ORIGIN });

  const result = {
    schema: "ioi.hypervisor.pipeline-reference-data-clean.v2",
    generated_for: "#38 Pipeline reference data-clean preflight — origin-aware, signature stub detection",
    surface: "pipeline", proxy_route: "/__apps/pipeline", match_origin: MATCH_ORIGIN, cross_origin: CROSS_ORIGIN, canvas_subpath: CANVAS_SUBPATH,
    data_clean, diagnosis, reference_data_complete, missing_chunk, cors_origin_mismatch, generated_stub_chunks: stubbed, blocking_reason,
    gate: "data_clean = the hardened-harness (proxy /__apps/pipeline) reference is certifiable. diagnosis distinguishes data_clean / cors_origin_mismatch / missing_chunk / app_data_failure. A MISSING chunk is detected by the server's generated-stub SIGNATURE, never by size. reference_data_complete = the matching-origin canvas renders a clean pipeline graph.",
    lanes: lanes.map((l) => ({ lane: l.lane, url: l.url, page_origin: l.pageOrigin, title: l.title, theme: l.theme, bodyLen: l.bodyLen, regions: l.regions, canvasBody: l.canvasBody, canvasNodes: l.canvasNodes, toolbar: l.toolbar, outputPanel: l.outputPanel, panelPresent: l.panelPresent, tray: l.tray, pageErr: l.pageErr, dataFail: l.dataFail, corsBlocked: l.corsBlocked, corsHitCount: l.corsHitCount, crossOriginFetchFails: l.crossOriginFetchFails, generatedStubChunks: l.generatedStubChunks, error_reason: l.error_reason, clean: l === proxyLanding ? data_clean : (l === matchCanvas ? reference_data_complete : canvasClean(l)), screenshotBytes: l.screenshotBytes, screenshot: l.screenshot, sample: l.sample })),
  };
  writeFileSync(path.join(ARTIFACT_DIR, "result.json"), JSON.stringify(result, null, 2) + "\n");

  console.log(`\nPipeline reference preflight → data_clean=${data_clean} · diagnosis=${diagnosis}`);
  for (const l of result.lanes) console.log(`  ${l.lane.padEnd(19)} err=${l.pageErr ? "Y" : "·"} dataFail=${l.dataFail ? "Y" : "·"} cors=${l.corsBlocked ? "Y" : "·"}(${l.crossOriginFetchFails}) stub=${(l.generatedStubChunks || []).length} body=${String(l.bodyLen).padStart(4)} graph=${l.canvasBody ? "Y" : "·"} nodes=${l.canvasNodes} tb=${l.toolbar ? "Y" : "·"} out=${l.outputPanel ? "Y" : "·"} clean=${l.clean ? "Y" : "·"}${l.error_reason ? `  [${l.error_reason}]` : ""}`);
  console.log(`\nreference_data_complete (matching-origin canvas renders clean): ${reference_data_complete}`);
  console.log(`BLOCKING REASON: ${blocking_reason || "(data-clean)"}`);
  console.log(`\nartifact: ${path.relative(process.cwd(), ARTIFACT_DIR)}/ (result.json + screens/)`);
  return result;
}

// Only run when invoked directly (so the unit test can import isGeneratedStub without launching a browser).
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch((e) => { console.error("preflight crashed:", e); process.exit(1); });
}
