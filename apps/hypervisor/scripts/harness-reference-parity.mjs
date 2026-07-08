#!/usr/bin/env node
// Reference UX Port — the Playwright visual + structural parity harness (PR #31 infrastructure).
//
// The reset's done-bar: a surface is only TRUE reference UX parity (`daemon_wired`) when its ported
// shell structurally matches the reference workspace. This harness opens the reference capture and
// the IOI candidate SIDE BY SIDE in a real browser, screenshots both, detects the reference shell
// REGIONS (global rail · header · toolbar · body · right panel · bottom tray) in each, and computes a
// structural-parity verdict. It proves nothing by prose — it looks at the rendered DOM.
//
// It is deliberately honest about the current estate: the dark IOI substrate surfaces (custom
// automationsShell) render NONE of the reference shell regions, so their structural parity fails —
// which is exactly why they are `substrate_bound`, not `daemon_wired`.
//
// Reference is loaded via serve's token-injected proxy /__apps/<slug> (== :9225<capture_base>).
//
// Output (artifact dir): screens/*.png + contact-sheet.html + result.json.
// Env: IOI_HYPERVISOR_SERVE_URL (default http://127.0.0.1:4173)
//      IOI_HARNESS_SURFACES=pipeline,lineage  (comma list; default = every substrate_bound + port seed)
//      IOI_HARNESS_ARTIFACT_DIR (default apps/hypervisor/.artifacts/reference-parity)
//
// Usage: node apps/hypervisor/scripts/harness-reference-parity.mjs

import { chromium } from "playwright";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const ARTIFACT_DIR = process.env.IOI_HARNESS_ARTIFACT_DIR || path.join(appRoot, ".artifacts", "reference-parity");

// The reference shell regions the game plan requires structural parity on. Each is a set of tolerant
// selectors (reference SPAs use hashed class names, so we match on role + class substrings).
const REGIONS = {
  rail: `nav, [role="navigation"], [class*="rail" i], [class*="sidebar" i], [class*="leftpanel" i], [class*="left-panel" i]`,
  header: `header, [role="banner"], [class*="header" i], [class*="topbar" i], [class*="top-bar" i], [class*="appbar" i]`,
  toolbar: `[role="toolbar"], [class*="toolbar" i], [class*="tool-bar" i], [class*="toolgroup" i]`,
  body: `main, [role="main"], [class*="canvas" i], [class*="workspace" i], table, [role="grid"], [class*="datagrid" i], [class*="objecttable" i]`,
  right: `aside, [class*="rightpanel" i], [class*="right-panel" i], [class*="inspector" i], [class*="detailspanel" i], [class*="details-panel" i], [class*="outputpanel" i]`,
  tray: `footer, [role="contentinfo"], [class*="tray" i], [class*="bottompanel" i], [class*="bottom-panel" i], [class*="previewpanel" i], [class*="statusbar" i]`,
};
const REGION_KEYS = Object.keys(REGIONS);
// Structural parity (daemon_wired) requires the load-bearing regions AND a strong overall overlap.
const CORE_REGIONS = ["rail", "header", "body"];
const PARITY_THRESHOLD = 0.8;

async function capture(ctx, url, pngPath) {
  const page = await ctx.newPage();
  const VW = 1440, VH = 900;
  let loaded = true, err = "";
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25000 });
    await page.waitForTimeout(2800); // let the reference SPA hydrate
  } catch (e) { loaded = false; err = String(e.message || e).slice(0, 100); }
  let regions = [], title = "", divCount = 0, errored = false, visibleText = "";
  try {
    // A region counts as PRESENT only when a visible element matching its selectors ALSO satisfies a
    // LAYOUT (bounding-box) predicate — a left-anchored tall rail, a top-anchored wide header, etc.
    // Selector-spoofing (a hidden or wrongly-placed div with class "rail") does NOT satisfy geometry.
    const res = await page.evaluate(({ sel, VW, VH }) => {
      const boxes = (q) => Array.from(document.querySelectorAll(q)).map((el) => {
        const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
        const vis = r.width > 24 && r.height > 24 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
        return { vis, left: r.left, top: r.top, right: r.right, bottom: r.bottom, w: r.width, h: r.height };
      }).filter((b) => b.vis);
      const geom = {
        rail: (b) => b.left < VW * 0.15 && b.h > VH * 0.4,
        header: (b) => b.top < VH * 0.15 && b.w > VW * 0.5 && b.h < VH * 0.28,
        toolbar: (b) => b.top < VH * 0.4 && b.w > VW * 0.25 && b.h < VH * 0.22,
        body: (b) => b.w > VW * 0.4 && b.h > VH * 0.35,
        right: (b) => b.right > VW * 0.8 && b.h > VH * 0.3 && b.w < VW * 0.6,
        tray: (b) => b.bottom > VH * 0.8 && b.w > VW * 0.4 && b.h < VH * 0.4,
      };
      const present = {};
      for (const [k, q] of Object.entries(sel)) present[k] = boxes(q).some(geom[k]);
      const vt = (document.body && document.body.innerText || "").replace(/\s+/g, " ").trim();
      return { present, title: document.title, divCount: document.querySelectorAll("div").length, visibleText: vt.slice(0, 400) };
    }, { sel: REGIONS, VW, VH });
    regions = Object.keys(res.present).filter((k) => res.present[k]);
    title = res.title; divCount = res.divCount; visibleText = res.visibleText;
    // A reference/candidate showing an ERROR page is NOT a valid parity surface — its shell chrome
    // (global nav rail, body) still renders, so region-matching would falsely score parity. Detect it.
    errored = /an error occurred|something went wrong|failed to load|page not found|not found|forbidden|unauthori[sz]ed/i.test(visibleText);
  } catch (e) { err = err || String(e.message || e).slice(0, 100); }
  // Screenshot capture is MANDATORY evidence — a surface with no screenshot is a harness failure, not
  // best-effort. Record its byte size so it can never be a 0-byte placeholder.
  let screenshotOk = false, screenshotBytes = 0;
  try {
    const buf = await page.screenshot({ path: pngPath, fullPage: false });
    screenshotOk = buf && buf.length > 1000; screenshotBytes = buf ? buf.length : 0;
  } catch (e) { err = err || `screenshot failed: ${String(e.message || e).slice(0, 60)}`; }
  await page.close();
  return { url, loaded, err, title, divCount, regions, screenshotOk, screenshotBytes, errored, visibleText };
}

function parityOf(refRegions, ioiRegions) {
  const refSet = new Set(refRegions), ioiSet = new Set(ioiRegions);
  const shared = refRegions.filter((r) => ioiSet.has(r));
  const score = refRegions.length ? shared.length / refRegions.length : 0;
  const coreOk = CORE_REGIONS.every((r) => !refSet.has(r) || ioiSet.has(r));
  return { shared, score: Math.round(score * 100) / 100, structural_parity: score >= PARITY_THRESHOLD && coreOk };
}

function surfacesFromMatrix() {
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const filter = (process.env.IOI_HARNESS_SURFACES || "").split(",").map((s) => s.trim()).filter(Boolean);
  // EVERY port-state seed (any non-reference_capture) is included, keyed on the canonical
  // candidate_surface — no port-state row can escape the harness by using a different field name.
  const PORT_STATES = new Set(["substrate_bound", "reference_port_pending", "reference_ported", "daemon_wired"]);
  return (matrix.seeds || [])
    .filter((s) => PORT_STATES.has(s.parity_class))
    .filter((s) => !filter.length || filter.includes(s.slug))
    .map((s) => ({ slug: s.slug, owner: s.owner, matrix_class: s.parity_class, reference_workspace: s.reference_workspace,
      reference_url: `${SERVE}/__apps/${s.slug}`, ioi_url: `${SERVE}${s.candidate_surface || s.substrate_surface || ""}` }));
}

function contactSheet(rows) {
  const cell = (r) => `<section style="border:1px solid #24262d;border-radius:10px;padding:14px;margin:0 0 18px;background:#15171c">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
      <h2 style="margin:0;font-size:16px">${r.slug} <span style="color:#878a93;font-weight:400;font-size:13px">· ${r.owner} · matrix: ${r.matrix_class}</span></h2>
      <span style="padding:3px 10px;border-radius:999px;font-size:12px;background:${r.structural_parity ? "#14361f;color:#7ee0a2" : "#3a1f14;color:#e0a27e"}">${r.structural_parity ? "structural parity ✓ (daemon_wired-eligible)" : "NOT parity — substrate_bound"} · score ${r.parity_score}</span>
    </div>
    <table style="margin:8px 0;border-collapse:collapse;font-size:12px;color:#c7c9d1"><tr><th style="text-align:left;padding:2px 12px 2px 0">region</th>${["rail","header","toolbar","body","right","tray"].map((k)=>`<th style="padding:2px 8px">${k}</th>`).join("")}</tr>
      <tr><td style="padding:2px 12px 2px 0">reference</td>${["rail","header","toolbar","body","right","tray"].map((k)=>`<td style="text-align:center">${r.reference_regions.includes(k)?"●":"·"}</td>`).join("")}</tr>
      <tr><td style="padding:2px 12px 2px 0">IOI</td>${["rail","header","toolbar","body","right","tray"].map((k)=>`<td style="text-align:center">${r.ioi_regions.includes(k)?"●":"·"}</td>`).join("")}</tr></table>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:12px;margin:0 0 4px">reference — <code>${r.reference_url}</code></figcaption><img src="screens/${r.slug}-reference.png" style="width:100%;border:1px solid #2a2c33;border-radius:6px"></figure>
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:12px;margin:0 0 4px">IOI candidate — <code>${r.ioi_url}</code></figcaption><img src="screens/${r.slug}-ioi.png" style="width:100%;border:1px solid #2a2c33;border-radius:6px"></figure>
    </div></section>`;
  return `<!doctype html><meta charset="utf-8"><title>Reference UX Parity — contact sheet</title>
    <body style="font-family:system-ui,sans-serif;background:#0e0f13;color:#e6e7ea;max-width:1100px;margin:0 auto;padding:24px">
    <h1 style="margin:0 0 4px">Reference UX Parity — contact sheet</h1>
    <p style="color:#878a93;margin:0 0 20px">Side-by-side reference workspace vs IOI candidate. Structural parity requires the reference shell regions (rail · header · toolbar · body · right · tray). Only <b>daemon_wired</b> is true parity. ${rows.length} surface(s).</p>
    ${rows.map(cell).join("")}</body>`;
}

async function run() {
  const surfaces = surfacesFromMatrix();
  mkdirSync(path.join(ARTIFACT_DIR, "screens"), { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const rows = [];
  for (const s of surfaces) {
    const refPng = path.join(ARTIFACT_DIR, "screens", `${s.slug}-reference.png`);
    const ioiPng = path.join(ARTIFACT_DIR, "screens", `${s.slug}-ioi.png`);
    const ref = await capture(ctx, s.reference_url, refPng);
    const ioi = await capture(ctx, s.ioi_url, ioiPng);
    const p = parityOf(ref.regions, ioi.regions);
    // GUARDS for a trustworthy parity verdict: (1) BOTH screenshots are real evidence; (2) the
    // REFERENCE is a VALID surface, not an error page (an error page renders only global chrome, so
    // region-matching would falsely score parity). A parity claim requires a valid reference.
    const evidence_ok = ref.screenshotOk && ioi.screenshotOk;
    const reference_valid = !ref.errored && ref.loaded && ref.regions.length > 0;
    const structural_parity = p.structural_parity && evidence_ok && reference_valid;
    rows.push({ slug: s.slug, owner: s.owner, matrix_class: s.matrix_class, reference_workspace: s.reference_workspace,
      reference_url: s.reference_url, ioi_url: s.ioi_url,
      reference_regions: ref.regions, ioi_regions: ioi.regions, shared: p.shared, parity_score: p.score,
      structural_parity, evidence_ok, reference_valid, reference_errored: ref.errored,
      reference_loaded: ref.loaded, ioi_loaded: ioi.loaded,
      reference_screenshot_bytes: ref.screenshotBytes, ioi_screenshot_bytes: ioi.screenshotBytes,
      reference_title: ref.title, ioi_title: ioi.title, reference_visible_text: ref.visibleText });
    console.log(`  ${structural_parity ? "PARITY " : ref.errored ? "REF-ERR " : "substrate"}  ${s.slug.padEnd(12)} ref[${ref.regions.join(",")}]${ref.errored ? "(errored)" : ""} ioi[${ioi.regions.join(",")}] score ${p.score}`);
  }
  await browser.close();
  const result = {
    schema: "ioi.hypervisor.reference-parity-harness.v1",
    parity_threshold: PARITY_THRESHOLD, core_regions: CORE_REGIONS, region_keys: REGION_KEYS,
    rule: "Only daemon_wired = true parity. A surface passes structural parity when it reproduces the reference shell regions (score >= threshold + core regions present).",
    surfaces: rows,
  };
  writeFileSync(path.join(ARTIFACT_DIR, "result.json"), JSON.stringify(result, null, 2) + "\n");
  writeFileSync(path.join(ARTIFACT_DIR, "contact-sheet.html"), contactSheet(rows));
  console.log(`\nartifact: ${path.relative(process.cwd(), ARTIFACT_DIR)}/ (result.json + contact-sheet.html + screens/)`);
  return result;
}

run().then((r) => {
  const parity = r.surfaces.filter((s) => s.structural_parity).length;
  const errored = r.surfaces.filter((s) => s.reference_errored).length;
  console.log(`${r.surfaces.length} surface(s) · ${parity} at structural parity · ${r.surfaces.length - parity} not-yet-parity (${errored} with an errored reference)`);
}).catch((e) => { console.error("harness crashed:", e); process.exit(1); });
