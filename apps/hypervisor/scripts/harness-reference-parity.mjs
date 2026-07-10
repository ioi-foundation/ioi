#!/usr/bin/env node
// Reference UX Port — the Playwright visual + structural parity harness (PR #31 infra; hardened #34).
//
// The reset's done-bar: a surface is only TRUE reference UX parity (`daemon_wired`) when its ported
// shell genuinely reproduces the reference workspace UX. This harness opens the reference capture and
// the IOI candidate SIDE BY SIDE in a real browser, screenshots both, and computes a parity verdict.
// It proves nothing by prose — it looks at the rendered DOM.
//
// #34 HARDENING (review): region-NAME overlap alone is too coarse — a dark 6-box layout scored 1.0
// against a light two-rail reference with completely different IA. `visual_parity` (the daemon_wired
// gate) now additionally requires:
//   - THEME MATCH — the reference and the candidate must render the same light/dark body theme
//     (sampled from the content area's effective background luminance, not the chrome).
//   - REFERENCE LANDMARKS — the surface's reference-specific IA labels (declared on the matrix row as
//     `reference_landmarks`) must appear in BOTH the reference AND the candidate. This ties parity to
//     the actual navigation/information architecture, not just "there is a left box".
//   - CORE REGION GEOMETRY + a strong region-name overlap (as before).
// `structural_parity` is kept as the coarse region-only signal (informational: "has the shell boxes").
// daemon_wired ⇒ visual_parity. An error page on EITHER side (reference OR candidate) can never certify.
//
// Reference is loaded via serve's token-injected proxy /__apps/<slug> (== :9225<capture_base>).
//
// Output (artifact dir): screens/*.png + contact-sheet.html + result.json.
// Env: IOI_HYPERVISOR_SERVE_URL (default http://127.0.0.1:4173)
//      IOI_HARNESS_SURFACES=schema,approvals  (comma list; default = every substrate_bound + port seed)
//      IOI_HARNESS_ARTIFACT_DIR (default apps/hypervisor/.artifacts/reference-parity)
//
// Usage: node apps/hypervisor/scripts/harness-reference-parity.mjs

import { chromium } from "playwright";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const MIRROR = (process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");
// reference_url_override host ALLOWLIST — a per-seed reference override may ONLY point at the LOCAL mirror
// (localhost/127.0.0.1 on the mirror port) or the SERVE proxy. This keeps the reference (the independent
// ground truth) pinned to captured/served artifacts, so a seed can NEVER self-select an author-controlled
// reference URL to fake parity (adversarial review). A disallowed override fails generation loudly.
const ALLOWED_REFERENCE_HOSTS = (() => {
  const hosts = new Set();
  try { hosts.add(new URL(SERVE).host); } catch { /* */ }
  try { const m = new URL(MIRROR); hosts.add(m.host); if (m.port) { hosts.add(`localhost:${m.port}`); hosts.add(`127.0.0.1:${m.port}`); } } catch { /* */ }
  return hosts;
})();
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
// Structural parity (the coarse signal) requires the load-bearing regions AND a strong overlap.
const CORE_REGIONS = ["rail", "header", "body"];
const PARITY_THRESHOLD = 0.8;
// visual_parity (the daemon_wired gate) additionally requires this fraction of the reference's own
// landmarks to be reproduced in the candidate.
const LANDMARK_THRESHOLD = 0.8;

export const ERROR_PAGE_RE = /an error occurred|something went wrong|failed to load|page not found|not found|forbidden|unauthori[sz]ed/i;

// capture(ctx, url, pngPath, landmarks, preCapture, maskSelectors)
// maskSelectors (optional, pixel harness): [{selector, label}] resolved to VISIBLE bounding rects in the
// SAME render as the screenshot (mask rects from a different load could drift vs live data).
export async function capture(ctx, url, pngPath, landmarks, preCapture, maskSelectors) {
  const page = await ctx.newPage();
  const vp = page.viewportSize() || { width: 1440, height: 900 };
  const VW = vp.width, VH = vp.height;
  let loaded = true, err = "", erroredPreHook = false;
  try {
    // Deterministic rendering: complete animations/transitions instantly (duration ≈ 0 jumps to the fill
    // state — NEVER `animation:none`, which freezes entrance animations at their initial opacity-0 frame),
    // hide carets, honor reduced-motion. Strictly stabilizing for screenshots; gates are unaffected.
    await page.emulateMedia({ reducedMotion: "reduce" }).catch(() => {});
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 25000 });
    await page.addStyleTag({ content: "*,*::before,*::after{animation-duration:.001s !important;animation-delay:0s !important;transition-duration:.001s !important;transition-delay:0s !important;caret-color:transparent !important}" }).catch(() => {});
    // fonts.ready is raced against a 3s timeout — a pathological never-settling font load must not hang
    // the capture (a bare await would wait indefinitely; .catch only handles rejection, not non-settlement).
    await page.evaluate(() => Promise.race([
      document.fonts && document.fonts.ready ? document.fonts.ready.then(() => true).catch(() => true) : Promise.resolve(true),
      new Promise((r) => setTimeout(() => r(true), 3000)),
    ])).catch(() => {});
    await page.waitForTimeout(2800); // let the reference SPA hydrate
    // GUARD (adversarial review): read the ERROR signal BEFORE the preCapture hook runs, so a hook that
    // hides DOM (a modal dismisser doing display:none on overlays/portals) can NEVER mask a reference-side
    // error that happens to render inside one. The final `errored` ORs this pre-hook reading with the
    // post-hook body scan — the hook can dismiss an onboarding modal but cannot clear a real error.
    try { const preText = await page.evaluate(() => (document.body && document.body.innerText || "")); erroredPreHook = ERROR_PAGE_RE.test(preText); } catch { /* */ }
    // Optional per-surface pre-capture action (e.g. dismiss an onboarding modal, extra settle for a heavy
    // SPA). Runs AFTER hydrate, BEFORE measurement. Self-guarded so a hook failure never fails the capture.
    if (preCapture) { try { await preCapture(page); } catch { /* hook is best-effort */ } }
  } catch (e) { loaded = false; err = String(e.message || e).slice(0, 100); }
  let regions = [], title = "", divCount = 0, errored = false, visibleText = "", theme = "unknown", bodyLuminance = null, landmarksPresent = [], regionBoxes = {}, landmarkRects = {}, maskRects = [];
  try {
    // A region counts as PRESENT only when a visible element matching its selectors ALSO satisfies a
    // LAYOUT (bounding-box) predicate — a left-anchored tall rail, a top-anchored wide header, etc.
    // Selector-spoofing (a hidden or wrongly-placed div with class "rail") does NOT satisfy geometry.
    const res = await page.evaluate(({ sel, VW, VH, landmarks, maskSelectors }) => {
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
      const present = {}, regionBoxes = {};
      for (const [k, q] of Object.entries(sel)) {
        const hits = boxes(q).filter(geom[k]);
        present[k] = hits.length > 0;
        // The LARGEST geometry-satisfying box is the canonical region bbox (pixel harness: bbox deltas).
        if (hits.length) { const b = hits.reduce((a, c) => (c.w * c.h > a.w * a.h ? c : a)); regionBoxes[k] = { left: Math.round(b.left), top: Math.round(b.top), w: Math.round(b.w), h: Math.round(b.h) }; }
      }
      // THEME — sample effective background luminance across a DENSE grid spanning the CONTENT area (x ≥
      // 0.18·VW, i.e. right of the ≤0.16·VW dark left-hand global nav rail, out to 0.94·VW) and take the
      // MEDIAN. The x-range starts just past the rail (not at 0.5) so a surface cannot read "light" by
      // lighting only the harness-sampled half while leaving the rest of the content dark (adversarial
      // review). Luminance is only read from a SUBSTANTIAL element (≥ 2% of the viewport) — mirroring the
      // region path's size discipline — so a small planted light element cannot flip the theme (review #34).
      const lumOf = (el) => {
        const m = (el && getComputedStyle(el).backgroundColor || "").match(/rgba?\(([^)]+)\)/);
        if (!m) return null;
        const p = m[1].split(",").map((x) => parseFloat(x));
        if (p.length >= 4 && p[3] === 0) return null; // transparent
        return (0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]) / 255;
      };
      const effLum = (x, y) => { let el = document.elementFromPoint(x, y); let n = 0; while (el && n++ < 30) { const r = el.getBoundingClientRect(); if (r.width * r.height >= VW * VH * 0.02) { const l = lumOf(el); if (l != null) return l; } el = el.parentElement; } return 1; };
      const pts = [];
      for (const fx of [0.18, 0.3, 0.42, 0.5, 0.62, 0.74, 0.86, 0.94]) for (const fy of [0.2, 0.35, 0.5, 0.64, 0.8]) pts.push([fx, fy]);
      const lums = pts.map(([fx, fy]) => effLum(VW * fx, VH * fy)).sort((a, b) => a - b);
      const bodyLuminance = lums[Math.floor(lums.length / 2)]; // median resists a handful of planted outliers
      const theme = bodyLuminance >= 0.5 ? "light" : "dark";
      // LANDMARKS — count a reference IA label only when it appears as VISIBLE, IN-VIEWPORT text (checked
      // per text node via its Range rect), so an off-screen (left:-9999px) / hidden / 1px dump of the
      // labels does NOT count as reproducing the IA. Match on WORD/PHRASE boundaries (not raw substring),
      // so 'Health' cannot match 'HealthCheck' and 'New' cannot match 'renew' (review #34).
      const escRe = (s) => String(s).toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const lmRegexes = (landmarks || []).map((l) => ({ l, re: new RegExp("(^|[^a-z0-9])" + escRe(l) + "([^a-z0-9]|$)") }));
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      let visSeen = ""; let tn; const landmarkRects = {};
      while ((tn = walker.nextNode())) {
        const txt = (tn.textContent || "").trim(); if (!txt) continue;
        const par = tn.parentElement; if (!par) continue;
        const cs = getComputedStyle(par); if (cs.visibility === "hidden" || cs.display === "none" || cs.opacity === "0") continue;
        const rng = document.createRange(); rng.selectNodeContents(tn); const rr = rng.getBoundingClientRect();
        if (rr.width > 4 && rr.height > 4 && rr.right > 0 && rr.bottom > 0 && rr.left < VW && rr.top < VH) {
          visSeen += " " + txt;
          // ALL visible rects per landmark (up to 5) — the over-mask guard fails only when EVERY
          // occurrence is covered: a landmark that also appears inside masked example DATA (e.g.
          // "Transform" in a captured node label) is still visibly reproduced by its unmasked chrome
          // occurrence (the graph-toolbar hint).
          const nodeLc = " " + txt.toLowerCase().replace(/\s+/g, " ") + " ";
          for (const { l, re } of lmRegexes) if (re.test(nodeLc)) { (landmarkRects[l] = landmarkRects[l] || []); if (landmarkRects[l].length < 5) landmarkRects[l].push({ left: Math.round(rr.left), top: Math.round(rr.top), w: Math.round(rr.width), h: Math.round(rr.height) }); }
        }
      }
      const visLc = visSeen.toLowerCase().replace(/\s+/g, " ");
      const landmarksPresent = (landmarks || []).filter((l) => new RegExp("(^|[^a-z0-9])" + escRe(l) + "([^a-z0-9]|$)").test(visLc));
      // Resolve dynamic-data MASK entries to rects in THIS render (pixel harness). Two forms:
      //   { selector, label } — resolved to visible element rects (opacity-disciplined), OR
      //   { rect: {x,y,w,h}, label } — a FIXED viewport-anchored rect, for OPAQUE / hash-classed reference
      //     DOM where the dynamic value (e.g. a captured bp6 select's selected state) cannot be selected.
      //     Rect masks are reviewed like code in the shell manifest and still bounded by the over-mask guard.
      const maskRects = [];
      for (const m of (maskSelectors || [])) {
        if (m.rect) { const r = m.rect; if (r.w > 2 && r.h > 2 && r.x < VW && r.y < VH) maskRects.push({ label: m.label, left: Math.max(0, Math.round(r.x)), top: Math.max(0, Math.round(r.y)), w: Math.round(Math.min(r.w, VW - r.x)), h: Math.round(Math.min(r.h, VH - r.y)) }); continue; }
        try {
          let n = 0;
          for (const el of document.querySelectorAll(m.selector)) {
            if (n >= 80) break;
            const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
            // opacity check matches the region-visibility discipline — a port cannot plant INVISIBLE
            // (opacity:0) elements matching its own manifest selectors to steer masks over its divergent
            // areas (adversarial review: the cheapest mask-steering channel).
            if (r.width > 2 && r.height > 2 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0" && r.right > 0 && r.bottom > 0 && r.left < VW && r.top < VH) { maskRects.push({ label: m.label, left: Math.max(0, Math.round(r.left)), top: Math.max(0, Math.round(r.top)), w: Math.round(Math.min(r.width, VW - r.left)), h: Math.round(Math.min(r.height, VH - r.top)) }); n++; }
          }
        } catch { /* bad selector = no rects; the pixel diff then sees the raw difference */ }
      }
      const vt = (document.body && document.body.innerText || "").replace(/\s+/g, " ").trim();
      return { present, regionBoxes, title: document.title, divCount: document.querySelectorAll("div").length, visibleText: vt.slice(0, 600), theme, bodyLuminance, landmarksPresent, landmarkRects, maskRects };
    }, { sel: REGIONS, VW, VH, landmarks: landmarks || [], maskSelectors: maskSelectors || [] });
    regions = Object.keys(res.present).filter((k) => res.present[k]);
    title = res.title; divCount = res.divCount; visibleText = res.visibleText; theme = res.theme; bodyLuminance = res.bodyLuminance; landmarksPresent = res.landmarksPresent;
    regionBoxes = res.regionBoxes || {}; landmarkRects = res.landmarkRects || {}; maskRects = res.maskRects || [];
    // A reference/candidate showing an ERROR page is NOT a valid parity surface — its shell chrome
    // (global nav rail, body) still renders, so region-matching would falsely score parity. Detect it —
    // OR'd with the PRE-HOOK reading so a modal-dismiss hook cannot hide a reference-side error.
    errored = erroredPreHook || ERROR_PAGE_RE.test(visibleText);
  } catch (e) { err = err || String(e.message || e).slice(0, 100); }
  // Screenshot capture is MANDATORY evidence — a surface with no screenshot is a harness failure, not
  // best-effort. Record its byte size so it can never be a 0-byte placeholder.
  let screenshotOk = false, screenshotBytes = 0;
  try {
    const buf = await page.screenshot({ path: pngPath, fullPage: false });
    screenshotOk = buf && buf.length > 1000; screenshotBytes = buf ? buf.length : 0;
  } catch (e) { err = err || `screenshot failed: ${String(e.message || e).slice(0, 60)}`; }
  await page.close();
  return { url, loaded, err, title, divCount, regions, regionBoxes, screenshotOk, screenshotBytes, errored, visibleText, theme, bodyLuminance, landmarksPresent, landmarkRects, maskRects, viewport: { width: VW, height: VH } };
}

// The parity computation. `structural_parity` = coarse region-only signal. `visual_parity` = the
// daemon_wired gate = regions AND theme match AND reference-landmark reproduction.
export function parityOf(ref, ioi, landmarks) {
  const refSet = new Set(ref.regions), ioiSet = new Set(ioi.regions);
  const shared = ref.regions.filter((r) => ioiSet.has(r));
  const regionScore = ref.regions.length ? shared.length / ref.regions.length : 0;
  const coreOk = CORE_REGIONS.every((r) => !refSet.has(r) || ioiSet.has(r));
  const structural_parity = regionScore >= PARITY_THRESHOLD && coreOk;

  const themeMatch = ref.theme === ioi.theme && ref.theme !== "unknown";
  // Landmark coverage is measured over the landmarks that ACTUALLY appear in the reference — a landmark
  // spec that doesn't match the reference is a spec bug (applicable shrinks → coverage can't be gamed).
  const refLm = new Set(ref.landmarksPresent), ioiLm = new Set(ioi.landmarksPresent);
  const declared = Array.isArray(landmarks) ? landmarks : [];
  const applicable = declared.filter((l) => refLm.has(l));
  const covered = applicable.filter((l) => ioiLm.has(l));
  const landmarkCoverage = applicable.length ? covered.length / applicable.length : 0;
  // A trustworthy landmark gate needs a real spec: enough declared landmarks AND most of them present
  // in the reference (so a surface can't pass by declaring one trivially-shared word).
  const landmarkSpecOk = declared.length >= 5 && applicable.length >= Math.ceil(declared.length * 0.6);
  const landmarkOk = landmarkSpecOk && landmarkCoverage >= LANDMARK_THRESHOLD;

  const visual_parity = structural_parity && themeMatch && landmarkOk;
  return {
    shared, region_score: Math.round(regionScore * 100) / 100, structural_parity,
    theme_match: themeMatch, landmark_declared: declared.length, landmark_applicable: applicable.length,
    landmark_covered: covered.length, landmark_coverage: Math.round(landmarkCoverage * 100) / 100,
    landmarks_missing: applicable.filter((l) => !ioiLm.has(l)), visual_parity,
  };
}

// Per-surface REFERENCE pre-capture hooks — run against the reference page ONLY (never the IOI
// candidate), after hydrate, before measurement. Pipeline's reference is the localhost:9225 builder
// CANVAS (a heavy SPA that also shows a "What's new in Pipeline Builder" bp6 onboarding modal on load).
// The hook lets the graph fully render and dismisses the modal so the contact-sheet screenshot shows the
// pipeline, not the overlay. (It does not move the numeric gates — theme/landmarks read the same with the
// modal up — but a legible review surface must show the graph.)
export const REFERENCE_PRE_CAPTURE = {
  pipeline: async (page) => {
    await page.waitForTimeout(3500); // the builder canvas is heavy — let the graph + panels fully render
    await page.addStyleTag({ content: '.bp6-portal,.bp6-overlay,.bp6-overlay-backdrop,[class*="whats-new-dialog"]{display:none !important}' }).catch(() => {});
    await page.keyboard.press("Escape").catch(() => {});
    await page.waitForTimeout(600);
  },
};

export function surfacesFromMatrix() {
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const filter = (process.env.IOI_HARNESS_SURFACES || "").split(",").map((s) => s.trim()).filter(Boolean);
  // EVERY port-state seed (any non-reference_capture) is included, keyed on the canonical
  // candidate_surface — no port-state row can escape the harness by using a different field name.
  const PORT_STATES = new Set(["substrate_bound", "reference_port_pending", "reference_ported", "daemon_wired"]);
  return (matrix.seeds || [])
    .filter((s) => PORT_STATES.has(s.parity_class))
    .filter((s) => !filter.length || filter.includes(s.slug))
    // reference_url: a per-seed override (e.g. pipeline's data-clean matching-origin canvas, which the
    // /__apps proxy can't serve clean because the app fetches an absolute localhost:9225 origin) falls
    // back to the standard token-injected proxy /__apps/<slug>. An override host MUST be allowlisted
    // (local mirror / SERVE proxy) — a seed cannot point the reference at an author-controlled URL.
    .map((s) => {
      let reference_url = `${SERVE}/__apps/${s.slug}`;
      if (s.reference_url_override) {
        let oh = null; try { oh = new URL(s.reference_url_override).host; } catch { /* */ }
        if (!oh || !ALLOWED_REFERENCE_HOSTS.has(oh)) {
          console.error(`FATAL: seed '${s.slug}' reference_url_override host '${oh}' is not allowlisted (allowed: ${[...ALLOWED_REFERENCE_HOSTS].join(", ")}) — a reference override may only point at the local mirror or the SERVE proxy.`);
          process.exit(2);
        }
        reference_url = s.reference_url_override;
      }
      return { slug: s.slug, owner: s.owner, matrix_class: s.parity_class, reference_workspace: s.reference_workspace,
        reference_landmarks: Array.isArray(s.reference_landmarks) ? s.reference_landmarks : [],
        reference_url,
        reference_pre_capture: REFERENCE_PRE_CAPTURE[s.slug] || null,
        ioi_url: `${SERVE}${s.candidate_surface || s.substrate_surface || ""}` };
    });
}

function contactSheet(rows) {
  const cell = (r) => `<section style="border:1px solid #24262d;border-radius:10px;padding:14px;margin:0 0 18px;background:#15171c">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
      <h2 style="margin:0;font-size:16px">${r.slug} <span style="color:#878a93;font-weight:400;font-size:13px">· ${r.owner} · matrix: ${r.matrix_class}</span></h2>
      <span style="padding:3px 10px;border-radius:999px;font-size:12px;background:${r.visual_parity ? "#14361f;color:#7ee0a2" : "#3a1f14;color:#e0a27e"}">${r.visual_parity ? "VISUAL PARITY ✓ (daemon_wired-eligible)" : "NOT visual parity"} · regions ${r.region_score} · theme ${r.reference_theme}/${r.ioi_theme}${r.theme_match ? "✓" : "✗"} · landmarks ${r.landmark_covered}/${r.landmark_applicable}</span>
    </div>
    <table style="margin:8px 0;border-collapse:collapse;font-size:12px;color:#c7c9d1"><tr><th style="text-align:left;padding:2px 12px 2px 0">region</th>${["rail","header","toolbar","body","right","tray"].map((k)=>`<th style="padding:2px 8px">${k}</th>`).join("")}</tr>
      <tr><td style="padding:2px 12px 2px 0">reference</td>${["rail","header","toolbar","body","right","tray"].map((k)=>`<td style="text-align:center">${r.reference_regions.includes(k)?"●":"·"}</td>`).join("")}</tr>
      <tr><td style="padding:2px 12px 2px 0">IOI</td>${["rail","header","toolbar","body","right","tray"].map((k)=>`<td style="text-align:center">${r.ioi_regions.includes(k)?"●":"·"}</td>`).join("")}</tr></table>
    ${r.landmarks_missing && r.landmarks_missing.length ? `<div style="color:#e0a27e;font-size:12px;margin:0 0 6px">landmarks missing in IOI: ${r.landmarks_missing.join(" · ")}</div>` : ""}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:12px;margin:0 0 4px">reference — <code>${r.reference_url}</code></figcaption><img src="screens/${r.slug}-reference.png" style="width:100%;border:1px solid #2a2c33;border-radius:6px"></figure>
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:12px;margin:0 0 4px">IOI candidate — <code>${r.ioi_url}</code></figcaption><img src="screens/${r.slug}-ioi.png" style="width:100%;border:1px solid #2a2c33;border-radius:6px"></figure>
    </div></section>`;
  return `<!doctype html><meta charset="utf-8"><title>Reference UX Parity — contact sheet</title>
    <body style="font-family:system-ui,sans-serif;background:#0e0f13;color:#e6e7ea;max-width:1100px;margin:0 auto;padding:24px">
    <h1 style="margin:0 0 4px">Reference UX Parity — contact sheet</h1>
    <p style="color:#878a93;margin:0 0 20px">Side-by-side reference vs IOI candidate. <b>visual_parity</b> (the daemon_wired gate) requires region geometry + theme match + reproduction of the reference's IA landmarks — not just region-name overlap. ${rows.length} surface(s).</p>
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
    const ref = await capture(ctx, s.reference_url, refPng, s.reference_landmarks, s.reference_pre_capture);
    const ioi = await capture(ctx, s.ioi_url, ioiPng, s.reference_landmarks);
    const p = parityOf(ref, ioi, s.reference_landmarks);
    // GUARDS: (1) BOTH screenshots are real evidence; (2) BOTH sides are VALID surfaces, not error
    // pages — an error page renders only global chrome, so matching would falsely score parity whether
    // it is the REFERENCE or the IOI CANDIDATE that errored. Parity requires both valid.
    const evidence_ok = ref.screenshotOk && ioi.screenshotOk;
    const reference_valid = !ref.errored && ref.loaded && ref.regions.length > 0;
    const ioi_valid = !ioi.errored && ioi.loaded;
    const structural_parity = p.structural_parity && evidence_ok && reference_valid && ioi_valid;
    const visual_parity = p.visual_parity && evidence_ok && reference_valid && ioi_valid;
    rows.push({ slug: s.slug, owner: s.owner, matrix_class: s.matrix_class, reference_workspace: s.reference_workspace,
      reference_url: s.reference_url, ioi_url: s.ioi_url, reference_landmarks: s.reference_landmarks,
      reference_regions: ref.regions, ioi_regions: ioi.regions, shared: p.shared, region_score: p.region_score,
      structural_parity, visual_parity, evidence_ok, reference_valid, reference_errored: ref.errored, ioi_valid, ioi_errored: ioi.errored,
      reference_theme: ref.theme, ioi_theme: ioi.theme, theme_match: p.theme_match,
      reference_body_luminance: ref.bodyLuminance, ioi_body_luminance: ioi.bodyLuminance,
      landmark_declared: p.landmark_declared, landmark_applicable: p.landmark_applicable, landmark_covered: p.landmark_covered, landmark_coverage: p.landmark_coverage, landmarks_missing: p.landmarks_missing,
      reference_loaded: ref.loaded, ioi_loaded: ioi.loaded,
      reference_screenshot_bytes: ref.screenshotBytes, ioi_screenshot_bytes: ioi.screenshotBytes,
      reference_title: ref.title, ioi_title: ioi.title, reference_visible_text: ref.visibleText, ioi_visible_text: ioi.visibleText });
    console.log(`  ${visual_parity ? "PARITY  " : ref.errored ? "REF-ERR " : ioi.errored ? "IOI-ERR " : "no-parity"}  ${s.slug.padEnd(12)} regions ${p.region_score} theme ${ref.theme}/${ioi.theme}${p.theme_match ? "✓" : "✗"} landmarks ${p.landmark_covered}/${p.landmark_applicable}${p.visual_parity ? "" : p.landmarks_missing && p.landmarks_missing.length ? ` [missing: ${p.landmarks_missing.slice(0, 4).join(",")}]` : ""}`);
  }
  await browser.close();
  const result = {
    schema: "ioi.hypervisor.reference-parity-harness.v2",
    parity_threshold: PARITY_THRESHOLD, landmark_threshold: LANDMARK_THRESHOLD, core_regions: CORE_REGIONS, region_keys: REGION_KEYS,
    rule: "Only daemon_wired = true parity. visual_parity (the daemon_wired gate) requires region geometry + theme match + reproduction of the reference's IA landmarks. structural_parity is the coarse region-only signal.",
    surfaces: rows,
  };
  writeFileSync(path.join(ARTIFACT_DIR, "result.json"), JSON.stringify(result, null, 2) + "\n");
  writeFileSync(path.join(ARTIFACT_DIR, "contact-sheet.html"), contactSheet(rows));
  console.log(`\nartifact: ${path.relative(process.cwd(), ARTIFACT_DIR)}/ (result.json + contact-sheet.html + screens/)`);
  return result;
}

// Only run when invoked directly — the pixel harness imports capture/parityOf/surfacesFromMatrix/
// REFERENCE_PRE_CAPTURE without executing a full visual pass.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().then((r) => {
    const parity = r.surfaces.filter((s) => s.visual_parity).length;
    const errored = r.surfaces.filter((s) => s.reference_errored || s.ioi_errored).length;
    console.log(`${r.surfaces.length} surface(s) · ${parity} at VISUAL parity · ${r.surfaces.length - parity} not-yet-parity (${errored} with an errored side)`);
  }).catch((e) => { console.error("harness crashed:", e); process.exit(1); });
}
