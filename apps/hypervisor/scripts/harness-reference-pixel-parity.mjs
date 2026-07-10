#!/usr/bin/env node
// Reference UX Port — PIXEL-PARITY certification harness (PR #40, the pixel wave foundation).
//
// A STRONGER evidence layer on top of the hardened visual gate — never a replacement for it, and never a
// replacement for daemon truth. `pixel_certified` means: at deterministic viewports the IOI candidate's
// RENDERED PIXELS match the reference within tight budgets, after masking ONLY dynamic data:
//   - full-image normalized diff ≤ 2.5% (after masks)
//   - chrome-only diff ≤ 0.75% (chrome = the global rail strip + the header/toolbar band; masks in chrome
//     are tightly capped — nav/toolbar/branding may NOT be masked away)
//   - canonical region bbox delta ≤ 8px (for regions detected on both sides)
//   - the #34/#39 visual gates must ALSO pass (theme + landmarks + geometry + both sides valid) — pixel
//     similarity of two error pages or two wrong-IA pages certifies nothing.
// Masks are SELECTOR-DRIVEN and resolved in the SAME render as the screenshot (live daemon values, ids,
// timestamps, data rows). An OVER-MASK fails closed: masks may never cover reference landmarks/toolbar
// labels, total mask area is capped, and chrome-zone mask area is capped tighter.
//
// Viewports: 1440×900 + 1920×1080 required; 390×844 required ONLY if the reference supports mobile
// (otherwise recorded `mobile_not_supported` — never silently skipped).
//
// The comparator is dependency-free: both PNGs are decoded and diffed inside headless chromium via
// canvas/getImageData (deterministic; no native image libs). Emits per surface/viewport: screenshots,
// a diff HEATMAP, a mask manifest; plus result.json + contact-sheet.html.
//
// Env: IOI_PIXEL_SURFACES=schema,approvals   (default: every daemon_wired seed)
//      IOI_PIXEL_VIEWPORTS=1440x900          (default: 1440x900,1920x1080 + mobile probe)
//      IOI_HYPERVISOR_SERVE_URL / IOI_PIXEL_ARTIFACT_DIR (default apps/hypervisor/.artifacts/pixel-parity)
//
// Usage: node apps/hypervisor/scripts/harness-reference-pixel-parity.mjs

import { chromium } from "playwright";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { capture, parityOf, surfacesFromMatrix, REFERENCE_PRE_CAPTURE } from "./harness-reference-parity.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const ARTIFACT_DIR = process.env.IOI_PIXEL_ARTIFACT_DIR || path.join(appRoot, ".artifacts", "pixel-parity");

// ---- CERTIFICATION THRESHOLDS (the brief's numbers; exported for the fail-closed verifier) ----------
export const THRESHOLDS = {
  full_diff_pct_max: 2.5,        // % of unmasked pixels differing, whole image
  chrome_diff_pct_max: 0.75,     // % of unmasked pixels differing, chrome zone only
  bbox_delta_px_max: 8,          // max edge delta for canonical regions detected on both sides
  mask_total_fraction_max: 0.35, // masks may cover at most 35% of the image
  mask_chrome_fraction_max: 0.15,// ...and at most 15% of the chrome zone (nav/toolbar can't be masked away)
  landmark_mask_overlap_max: 0.3,// a mask covering >30% of any reference-landmark rect = over-masking
  pixel_delta_threshold: 0.1,    // per-pixel perceptual distance (0..1) above which a pixel counts as diff
  palette_delta_max: 0.05,       // zone avg-RGB drift budget — a UNIFORM whole-page tint ≤25/255 slides
                                 // under the per-pixel threshold (adversarial review); the palette gate
                                 // catches exactly that class (real ports measure ≈0.00–0.01)
};

// The CHROME zone: the global-rail strip + the header/toolbar band. Deterministic in viewport fractions.
export function zonesFor(vw, vh) {
  return { rail_w: Math.round(vw * 0.16), top_h: Math.round(vh * 0.165) };
}
export const inChrome = (x, y, z) => x < z.rail_w || y < z.top_h;

// ---- MASK MANIFESTS — dynamic DATA only (live daemon values / captured example data), NEVER chrome, ----
// nav, toolbar labels, icons, layout regions, or empty-state copy. Selector-driven, resolved at capture
// time on the named side. These are per-surface contracts, reviewed like code; the over-mask guard below
// fails closed if a manifest strays into chrome/landmarks.
export const MASK_MANIFESTS = {
  schema: {
    ref: [{ selector: "td", label: "captured-table-cells" }],
    ioi: [{ selector: "td", label: "live-table-cells" }],
  },
  approvals: {
    ref: [{ selector: "td", label: "captured-request-rows" }, { selector: "time,[datetime]", label: "captured-dates" }],
    ioi: [{ selector: "td", label: "live-request-rows" }, { selector: "time,[datetime]", label: "live-dates" }],
  },
  pipeline: {
    // The reference graph node LABELS are CAPTURED example data (per-pipeline names); the IOI node cards'
    // structural labels (Datasource/Object mapping/…) are the port's own IA vocabulary and are NOT masked
    // — only live VALUES (counts/refs/details/rows) are. A mask must never cover the graph-toolbar
    // "Transform" hint or any other declared landmark (the over-mask guard fails closed on that).
    ref: [{ selector: '[class*="node-body" i]', label: "captured-example-node-labels" }, { selector: "td", label: "captured-table-cells" }],
    ioi: [{ selector: ".pb-ncount,.pb-ndetail,.pb-outcode,.pb-outnum", label: "live-node-values" }, { selector: "td", label: "live-preview-rows" }, { selector: ".pb-pipe", label: "live-pipeline-list" }, { selector: ".pb-crumb", label: "live-breadcrumb-state" }, { selector: ".pb-legrow b", label: "live-legend-counts" }, { selector: ".pb-setrow", label: "live-output-settings-values" }],
  },
};

const VIEWPORTS_DESKTOP = [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }];
const VIEWPORT_MOBILE = { width: 390, height: 844 };

// ---- OVER-MASK GUARD (pure; exported). Mask area via a 4px occupancy grid (exact enough, no rect ------
// union math); landmark rects may not be covered beyond the overlap budget.
export function maskGuard(maskRects, landmarkRects, vw, vh) {
  const z = zonesFor(vw, vh);
  const cell = 4, gw = Math.ceil(vw / cell), gh = Math.ceil(vh / cell);
  const grid = new Uint8Array(gw * gh);
  for (const m of maskRects || []) {
    const x0 = Math.max(0, Math.floor(m.left / cell)), y0 = Math.max(0, Math.floor(m.top / cell));
    const x1 = Math.min(gw - 1, Math.floor((m.left + m.w) / cell)), y1 = Math.min(gh - 1, Math.floor((m.top + m.h) / cell));
    for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) grid[y * gw + x] = 1;
  }
  let total = 0, chrome = 0, chromeCells = 0;
  for (let y = 0; y < gh; y++) for (let x = 0; x < gw; x++) {
    const isChrome = inChrome(x * cell, y * cell, z);
    if (isChrome) chromeCells++;
    if (grid[y * gw + x]) { total++; if (isChrome) chrome++; }
  }
  const total_fraction = total / (gw * gh);
  const chrome_fraction = chromeCells ? chrome / chromeCells : 0;
  const landmarks_masked = [];
  for (const [name, rOrList] of Object.entries(landmarkRects || {})) {
    // A landmark may occur at several rects (chrome affordance + inside masked example data). Masking is
    // a violation ONLY when EVERY occurrence is covered — one unmasked occurrence keeps the IA visible.
    const rects = (Array.isArray(rOrList) ? rOrList : [rOrList]).filter((r) => r && r.w > 0 && r.h > 0);
    if (!rects.length) continue;
    let allCovered = true;
    for (const r of rects) {
      const x0 = Math.max(0, Math.floor(r.left / cell)), y0 = Math.max(0, Math.floor(r.top / cell));
      const x1 = Math.min(gw - 1, Math.floor((r.left + r.w) / cell)), y1 = Math.min(gh - 1, Math.floor((r.top + r.h) / cell));
      let cov = 0, cells = 0;
      for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) { cells++; if (grid[y * gw + x]) cov++; }
      if (!cells || cov / cells <= THRESHOLDS.landmark_mask_overlap_max) { allCovered = false; break; }
    }
    if (allCovered) landmarks_masked.push(name);
  }
  return {
    total_fraction: Math.round(total_fraction * 1000) / 1000,
    chrome_fraction: Math.round(chrome_fraction * 1000) / 1000,
    landmarks_masked,
    ok: total_fraction <= THRESHOLDS.mask_total_fraction_max && chrome_fraction <= THRESHOLDS.mask_chrome_fraction_max && landmarks_masked.length === 0,
  };
}

// ---- BBOX DELTAS (pure; exported): max edge delta per canonical region detected on BOTH sides. -------
export function bboxDeltas(refBoxes, ioiBoxes) {
  const out = {};
  for (const k of Object.keys(refBoxes || {})) {
    const a = refBoxes[k], b = (ioiBoxes || {})[k];
    if (!a || !b) continue;
    out[k] = Math.max(Math.abs(a.left - b.left), Math.abs(a.top - b.top), Math.abs((a.left + a.w) - (b.left + b.w)), Math.abs((a.top + a.h) - (b.top + b.h)));
  }
  return out;
}

// ---- THE CERTIFICATION VERDICT (pure; exported — the fail-closed contract the verifier pins). --------
// Every reason is explicit; missing evidence / an errored side / a spoof / an over-mask can never pass.
export function pixelVerdict(i) {
  const reasons = [];
  if (!i.evidence_ok) reasons.push("missing/undersized screenshot evidence — fail closed");
  if (i.reference_errored) reasons.push("reference is an ERROR page — cannot pixel-certify");
  if (i.ioi_errored) reasons.push("IOI candidate is an ERROR page — cannot pixel-certify");
  if (!i.reference_valid) reasons.push("reference invalid (not loaded / no regions)");
  if (!i.ioi_valid) reasons.push("IOI candidate invalid (not loaded)");
  if (!i.structural_parity) reasons.push("structural (region-geometry) gate failed");
  if (!i.theme_match) reasons.push("theme mismatch — the #34 gate");
  if (!i.landmark_ok) reasons.push("reference IA landmarks not reproduced — the #34 gate");
  if (!i.dims_match) reasons.push("screenshot dimensions differ — fail closed");
  if (!i.mask || !i.mask.ok) {
    if (i.mask && i.mask.landmarks_masked && i.mask.landmarks_masked.length) reasons.push(`OVER-MASK: mask covers reference landmark(s): ${i.mask.landmarks_masked.join(", ")}`);
    if (i.mask && i.mask.total_fraction > THRESHOLDS.mask_total_fraction_max) reasons.push(`OVER-MASK: total mask fraction ${i.mask.total_fraction} > ${THRESHOLDS.mask_total_fraction_max}`);
    if (i.mask && i.mask.chrome_fraction > THRESHOLDS.mask_chrome_fraction_max) reasons.push(`OVER-MASK: chrome-zone mask fraction ${i.mask.chrome_fraction} > ${THRESHOLDS.mask_chrome_fraction_max}`);
    if (!i.mask) reasons.push("mask stats missing — fail closed");
  }
  if (typeof i.full_diff_pct !== "number" || typeof i.chrome_diff_pct !== "number") reasons.push("pixel metrics missing — fail closed");
  else {
    if (i.full_diff_pct > THRESHOLDS.full_diff_pct_max) reasons.push(`full-image diff ${i.full_diff_pct}% > ${THRESHOLDS.full_diff_pct_max}% (geometry/landmark overlap alone is NOT pixel parity)`);
    if (i.chrome_diff_pct > THRESHOLDS.chrome_diff_pct_max) reasons.push(`chrome diff ${i.chrome_diff_pct}% > ${THRESHOLDS.chrome_diff_pct_max}%`);
  }
  // Palette gate: a UNIFORM tint (≤25/255 per channel) is invisible to the per-pixel threshold but shows
  // as zone avg-RGB drift. Fail-closed when palette data is absent (the comparator always emits it).
  if (!i.palette || !i.palette.chrome || !i.palette.body) reasons.push("zone palette data missing — fail closed");
  else {
    for (const zone of ["chrome", "body"]) if (i.palette[zone].delta > THRESHOLDS.palette_delta_max) reasons.push(`${zone}-zone palette drift Δ${i.palette[zone].delta} > ${THRESHOLDS.palette_delta_max} (a uniform tint cannot certify)`);
  }
  const overs = Object.entries(i.bbox_deltas || {}).filter(([, d]) => d > THRESHOLDS.bbox_delta_px_max);
  if (overs.length) reasons.push(`region bbox delta > ${THRESHOLDS.bbox_delta_px_max}px: ${overs.map(([k, d]) => `${k}=${d}px`).join(", ")}`);
  return { certified: reasons.length === 0, reasons };
}

// ---- The in-chromium pixel comparator (dependency-free PNG decode via canvas). -----------------------
async function comparePixels(browser, refPng, ioiPng, maskRects, vw, vh) {
  const page = await browser.newPage();
  const z = zonesFor(vw, vh);
  const res = await page.evaluate(async ({ refB64, ioiB64, masks, z, delta }) => {
    const load = (b64) => new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = rej; im.src = "data:image/png;base64," + b64; });
    const [ri, ii] = await Promise.all([load(refB64), load(ioiB64)]);
    if (ri.width !== ii.width || ri.height !== ii.height) return { dims_match: false, ref_dims: [ri.width, ri.height], ioi_dims: [ii.width, ii.height] };
    const W = ri.width, H = ri.height;
    // Screenshots may be at devicePixelRatio 1 (headless default) — mask rects are CSS px == image px.
    const cv = (im) => { const c = document.createElement("canvas"); c.width = W; c.height = H; const g = c.getContext("2d", { willReadFrequently: true }); g.drawImage(im, 0, 0); return g.getImageData(0, 0, W, H).data; };
    const A = cv(ri), B = cv(ii);
    // Headless screenshots are 1 image px per CSS px (deviceScaleFactor 1) — but derive the scale from
    // the actual image width vs the CSS viewport width so a dpr surprise cannot misplace masks/zones.
    const s = W / (z.vw || W);
    const railW = Math.round(0.16 * W), topH = Math.round(0.165 * H);
    const masked = new Uint8Array(W * H);
    for (const m of masks) {
      const x0 = Math.max(0, Math.round(m.left * s)), y0 = Math.max(0, Math.round(m.top * s));
      const x1 = Math.min(W, Math.round((m.left + m.w) * s)), y1 = Math.min(H, Math.round((m.top + m.h) * s));
      for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) masked[y * W + x] = 1;
    }
    // Diff + zone accounting + heatmap
    const heat = document.createElement("canvas"); heat.width = W; heat.height = H;
    const hg = heat.getContext("2d"); const hd = hg.createImageData(W, H); const HP = hd.data;
    let total = 0, diff = 0, cTotal = 0, cDiff = 0, bTotal = 0, bDiff = 0;
    // palette accumulators per zone
    const acc = { ref: { chrome: [0, 0, 0, 0], body: [0, 0, 0, 0] }, ioi: { chrome: [0, 0, 0, 0], body: [0, 0, 0, 0] } };
    for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
      const idx = y * W + x, p = idx * 4;
      const gray = Math.round(0.6 * (0.299 * A[p] + 0.587 * A[p + 1] + 0.114 * A[p + 2]));
      HP[p] = gray; HP[p + 1] = gray; HP[p + 2] = gray; HP[p + 3] = 255;
      const chrome = x < railW || y < topH;
      const zone = chrome ? "chrome" : "body";
      const ra = acc.ref[zone], ia = acc.ioi[zone];
      ra[0] += A[p]; ra[1] += A[p + 1]; ra[2] += A[p + 2]; ra[3]++;
      ia[0] += B[p]; ia[1] += B[p + 1]; ia[2] += B[p + 2]; ia[3]++;
      if (masked[idx]) { HP[p] = Math.min(255, gray + 60); HP[p + 1] = Math.min(255, gray + 60); HP[p + 2] = 40; continue; }
      total++; if (chrome) cTotal++; else bTotal++;
      const dr = A[p] - B[p], dg = A[p + 1] - B[p + 1], db = A[p + 2] - B[p + 2];
      const dist = Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db) / 255;
      if (dist > delta) { diff++; if (chrome) cDiff++; else bDiff++; HP[p] = 255; HP[p + 1] = 40; HP[p + 2] = 40; }
    }
    hg.putImageData(hd, 0, 0);
    const avg = (a) => a[3] ? [Math.round(a[0] / a[3]), Math.round(a[1] / a[3]), Math.round(a[2] / a[3])] : [0, 0, 0];
    const pd = (a, b) => Math.round(Math.sqrt(0.299 * (a[0] - b[0]) ** 2 + 0.587 * (a[1] - b[1]) ** 2 + 0.114 * (a[2] - b[2]) ** 2) / 2.55) / 100;
    const palette = {};
    for (const zone of ["chrome", "body"]) { const r = avg(acc.ref[zone]), i2 = avg(acc.ioi[zone]); palette[zone] = { ref_avg_rgb: r, ioi_avg_rgb: i2, delta: pd(r, i2) }; }
    return {
      dims_match: true, width: W, height: H,
      full_diff_pct: total ? Math.round((diff / total) * 10000) / 100 : 100,
      chrome_diff_pct: cTotal ? Math.round((cDiff / cTotal) * 10000) / 100 : 100,
      body_diff_pct: bTotal ? Math.round((bDiff / bTotal) * 10000) / 100 : 100,
      unmasked_px: total, diff_px: diff, palette,
      heatmap_b64: heat.toDataURL("image/png").split(",")[1],
    };
  }, { refB64: refPng.toString("base64"), ioiB64: ioiPng.toString("base64"), masks: maskRects.map((m) => ({ left: m.left, top: m.top, w: m.w, h: m.h })), z: { ...z, vw }, delta: THRESHOLDS.pixel_delta_threshold });
  await page.close();
  return res;
}

// Mobile support probe. "Supports mobile" means the reference renders a USABLE mobile layout — not
// merely that a desktop workspace squeezes without horizontal overflow. Two signals, both required:
// (a) no horizontal overflow; (b) no fixed left rail eating > 40% of the phone viewport (a 228px desktop
// rail on a 390px screen is a squeezed desktop app, not a mobile UX). Anything else records
// `mobile_not_supported` — honestly skipped, never silently.
async function mobileSupported(browser, url, preCapture) {
  const ctx = await browser.newContext({ viewport: VIEWPORT_MOBILE });
  const page = await ctx.newPage();
  let supported = false, detail = "";
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25000 });
    await page.waitForTimeout(2500);
    if (preCapture) { try { await preCapture(page); } catch { /* */ } }
    const m = await page.evaluate(() => {
      const iw = window.innerWidth, ih = window.innerHeight;
      let railW = 0;
      for (const el of document.querySelectorAll('nav,[role="navigation"],[class*="rail" i],[class*="sidebar" i]')) {
        const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
        if (s.display === "none" || s.visibility === "hidden") continue;
        if (r.left < iw * 0.15 && r.height > ih * 0.4) railW = Math.max(railW, r.width);
      }
      return { sw: document.documentElement.scrollWidth, iw, railFrac: Math.round((railW / iw) * 100) / 100 };
    });
    supported = m.sw <= m.iw * 1.15 && m.railFrac <= 0.4;
    detail = `scrollWidth=${m.sw} innerWidth=${m.iw} railFrac=${m.railFrac}`;
  } catch (e) { detail = String(e.message || e).slice(0, 80); }
  await ctx.close();
  return { supported, detail };
}

async function runSurface(browser, s, viewports) {
  const dir = path.join(ARTIFACT_DIR, s.slug);
  mkdirSync(dir, { recursive: true });
  const manifest = MASK_MANIFESTS[s.slug] || { ref: [], ioi: [] };
  writeFileSync(path.join(dir, "mask-manifest.json"), JSON.stringify({ slug: s.slug, rule: "masks = dynamic data ONLY (live daemon values / captured example data); never chrome, nav, toolbar labels, icons, layout regions, or empty-state copy; over-mask fails closed", ...manifest }, null, 2) + "\n");
  const rows = [];
  for (const vp of viewports) {
    const tag = `${vp.width}x${vp.height}`;
    const ctx = await browser.newContext({ viewport: vp });
    const refPngPath = path.join(dir, `ref-${tag}.png`), ioiPngPath = path.join(dir, `ioi-${tag}.png`);
    const ref = await capture(ctx, s.reference_url, refPngPath, s.reference_landmarks, s.reference_pre_capture, manifest.ref);
    const ioi = await capture(ctx, s.ioi_url, ioiPngPath, s.reference_landmarks, null, manifest.ioi);
    await ctx.close();
    const p = parityOf(ref, ioi, s.reference_landmarks);
    const evidence_ok = ref.screenshotOk && ioi.screenshotOk;
    const reference_valid = !ref.errored && ref.loaded && ref.regions.length > 0;
    const ioi_valid = !ioi.errored && ioi.loaded;
    // Union of both sides' dynamic rects, applied to BOTH images (dynamic data lives at slightly
    // different coordinates per side; the union masks it on both).
    const unionMasks = [...(ref.maskRects || []), ...(ioi.maskRects || [])].map((m) => ({ ...m, left: m.left - 2, top: m.top - 2, w: m.w + 4, h: m.h + 4 }));
    const mask = maskGuard(unionMasks, ref.landmarkRects || {}, vp.width, vp.height);
    let cmp = { dims_match: false };
    if (evidence_ok) {
      try { cmp = await comparePixels(browser, readFileSync(refPngPath), readFileSync(ioiPngPath), unionMasks, vp.width, vp.height); } catch (e) { cmp = { dims_match: false, error: String(e.message || e).slice(0, 120) }; }
    }
    if (cmp.heatmap_b64) { writeFileSync(path.join(dir, `heatmap-${tag}.png`), Buffer.from(cmp.heatmap_b64, "base64")); delete cmp.heatmap_b64; }
    const deltas = bboxDeltas(ref.regionBoxes, ioi.regionBoxes);
    const verdict = pixelVerdict({
      evidence_ok, reference_errored: ref.errored, ioi_errored: ioi.errored, reference_valid, ioi_valid,
      structural_parity: p.structural_parity, theme_match: p.theme_match,
      landmark_ok: p.landmark_declared >= 5 && p.landmark_applicable >= Math.ceil(p.landmark_declared * 0.6) && p.landmark_coverage >= 0.8,
      dims_match: cmp.dims_match === true, full_diff_pct: cmp.full_diff_pct, chrome_diff_pct: cmp.chrome_diff_pct,
      bbox_deltas: deltas, mask, palette: cmp.palette || null,
    });
    rows.push({
      viewport: tag, reference_url: s.reference_url, ioi_url: s.ioi_url,
      certified: verdict.certified, reasons: verdict.reasons,
      gates: { evidence_ok, reference_errored: ref.errored, ioi_errored: ioi.errored, reference_valid, ioi_valid, structural_parity: p.structural_parity, theme_match: p.theme_match, landmark_coverage: p.landmark_coverage, landmark_covered: p.landmark_covered, landmark_applicable: p.landmark_applicable },
      metrics: { dims_match: cmp.dims_match === true, full_diff_pct: cmp.full_diff_pct ?? null, chrome_diff_pct: cmp.chrome_diff_pct ?? null, body_diff_pct: cmp.body_diff_pct ?? null, palette: cmp.palette || null, bbox_deltas: deltas, cmp_error: cmp.error || null },
      mask,
      screens: { ref: `${s.slug}/ref-${tag}.png`, ioi: `${s.slug}/ioi-${tag}.png`, heatmap: `${s.slug}/heatmap-${tag}.png` },
    });
    console.log(`  ${verdict.certified ? "PIXEL ✓" : "pixel ✗"}  ${s.slug.padEnd(10)} ${tag.padEnd(9)} full ${cmp.full_diff_pct ?? "—"}% chrome ${cmp.chrome_diff_pct ?? "—"}% bboxΔ ${Object.values(deltas).length ? Math.max(...Object.values(deltas)) : "—"}px mask ${mask.total_fraction}${verdict.certified ? "" : `  [${verdict.reasons[0]}]`}`);
  }
  return rows;
}

function contactSheet(surfaces) {
  const cell = (r, slug) => `<section style="border:1px solid #24262d;border-radius:10px;padding:12px;margin:0 0 14px;background:#15171c">
    <h3 style="margin:0 0 6px;font-size:14px">${slug} @ ${r.viewport} — <span style="color:${r.certified ? "#7ee0a2" : "#e0a27e"}">${r.certified ? "PIXEL CERTIFIED ✓" : "not certified"}</span>
      <span style="color:#878a93;font-weight:400;font-size:12px">· full ${r.metrics.full_diff_pct}% · chrome ${r.metrics.chrome_diff_pct}% · mask ${r.mask.total_fraction}</span></h3>
    ${r.reasons.length ? `<div style="color:#e0a27e;font-size:12px;margin:0 0 8px">${r.reasons.join(" · ")}</div>` : ""}
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:11px">reference</figcaption><img src="${r.screens.ref}" style="width:100%;border:1px solid #2a2c33;border-radius:5px"></figure>
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:11px">IOI candidate</figcaption><img src="${r.screens.ioi}" style="width:100%;border:1px solid #2a2c33;border-radius:5px"></figure>
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:11px">diff heatmap (red=diff · yellow=masked)</figcaption><img src="${r.screens.heatmap}" style="width:100%;border:1px solid #2a2c33;border-radius:5px"></figure>
    </div></section>`;
  return `<!doctype html><meta charset="utf-8"><title>Pixel Parity — contact sheet</title>
    <body style="font-family:system-ui,sans-serif;background:#0e0f13;color:#e6e7ea;max-width:1200px;margin:0 auto;padding:22px">
    <h1 style="margin:0 0 4px">Pixel Parity — contact sheet</h1>
    <p style="color:#878a93;margin:0 0 18px">pixel_certified = visual gates (#34/#39) AND full ≤ ${THRESHOLDS.full_diff_pct_max}% AND chrome ≤ ${THRESHOLDS.chrome_diff_pct_max}% AND bboxΔ ≤ ${THRESHOLDS.bbox_delta_px_max}px, after DATA-ONLY masks (over-mask fails closed).</p>
    ${surfaces.flatMap((s) => s.viewports.map((r) => cell(r, s.slug))).join("")}</body>`;
}

async function run() {
  const filter = (process.env.IOI_PIXEL_SURFACES || "").split(",").map((x) => x.trim()).filter(Boolean);
  const all = surfacesFromMatrix();
  // Default = the daemon_wired set (pixel certification is a layer ON TOP of daemon_wired); an explicit
  // IOI_PIXEL_SURFACES may name any port-state seed (e.g. an errored one, to prove fail-closed behavior).
  const surfaces = filter.length ? all.filter((s) => filter.includes(s.slug)) : all.filter((s) => s.matrix_class === "daemon_wired");
  if (!surfaces.length) { console.error("no surfaces selected"); process.exit(2); }
  mkdirSync(ARTIFACT_DIR, { recursive: true });
  const vpEnv = (process.env.IOI_PIXEL_VIEWPORTS || "").split(",").map((x) => x.trim()).filter(Boolean).map((t) => { const [w, h] = t.split("x").map(Number); return { width: w, height: h }; });
  const browser = await chromium.launch({ headless: true });
  const out = [];
  for (const s of surfaces) {
    console.log(`\n${s.slug} (${s.matrix_class}) — reference ${s.reference_url}`);
    const mob = vpEnv.length ? { supported: false, detail: "viewports pinned via env" } : await mobileSupported(browser, s.reference_url, s.reference_pre_capture);
    const viewports = vpEnv.length ? vpEnv : (mob.supported ? [...VIEWPORTS_DESKTOP, VIEWPORT_MOBILE] : VIEWPORTS_DESKTOP);
    const rows = await runSurface(browser, s, viewports);
    // A run with env-PINNED viewports (a debug/CI convenience) can NEVER certify — certification requires
    // the full default viewport set (both desktops + mobile when the reference supports it), so a single
    // easy viewport cannot be cherry-picked.
    const viewports_pinned = vpEnv.length > 0;
    const pixel_certified = !viewports_pinned && rows.length > 0 && rows.every((r) => r.certified);
    const surfaceRow = { slug: s.slug, matrix_class: s.matrix_class, pixel_certified, viewports_pinned, mobile: viewports_pinned ? "viewports_pinned (non-certifying run)" : (mob.supported ? "supported" : `mobile_not_supported (${mob.detail})`), viewports: rows };
    out.push(surfaceRow);
    // A GENUINE certification (full default viewport set, every viewport certified) writes a COMMITTED
    // machine-checkable evidence file — apps/hypervisor/pixel-certifications/<slug>.json. The matrix's
    // PIXEL_CERTIFIED overlay must point at this file; the generator parses it (slug/certified/not-pinned)
    // and the verifier deep-checks its thresholds against THRESHOLDS. .artifacts/ is gitignored, so a
    // certification claim can never rest on an uncommitted pointer (adversarial review).
    if (pixel_certified) {
      const certDir = path.join(appRoot, "pixel-certifications");
      mkdirSync(certDir, { recursive: true });
      writeFileSync(path.join(certDir, `${s.slug}.json`), JSON.stringify({ schema: "ioi.hypervisor.pixel-certification.v1", slug: s.slug, matrix_class: s.matrix_class, pixel_certified: true, viewports_pinned: false, thresholds: THRESHOLDS, reference_url: s.reference_url, ioi_url: s.ioi_url, mobile: surfaceRow.mobile, viewports: rows }, null, 2) + "\n");
      console.log(`  ★ wrote pixel-certifications/${s.slug}.json (commit this — it is the matrix's evidence pointer)`);
    }
    console.log(`  → ${s.slug}: pixel_certified=${pixel_certified}${viewports_pinned ? " (viewports pinned — non-certifying run)" : ""} (${rows.filter((r) => r.certified).length}/${rows.length} viewports)`);
  }
  await browser.close();
  const result = {
    schema: "ioi.hypervisor.pixel-parity-harness.v1",
    thresholds: THRESHOLDS,
    rule: "pixel_certified = a STRONGER evidence layer on top of daemon_wired (visual gates must also pass); masks cover dynamic data ONLY and an over-mask fails closed; an errored side, a missing screenshot, a dims mismatch, or a geometry-only spoof can never certify.",
    surfaces: out,
  };
  writeFileSync(path.join(ARTIFACT_DIR, "result.json"), JSON.stringify(result, null, 2) + "\n");
  writeFileSync(path.join(ARTIFACT_DIR, "contact-sheet.html"), contactSheet(out));
  console.log(`\nartifact: ${path.relative(process.cwd(), ARTIFACT_DIR)}/ (result.json + contact-sheet.html + per-surface screens/heatmaps/mask-manifests)`);
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().then((r) => {
    const c = r.surfaces.filter((s) => s.pixel_certified).length;
    console.log(`${r.surfaces.length} surface(s) · ${c} pixel-certified`);
  }).catch((e) => { console.error("pixel harness crashed:", e); process.exit(1); });
}
