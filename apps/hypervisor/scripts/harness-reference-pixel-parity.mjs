#!/usr/bin/env node
// Reference UX Port — SHELL-PIXEL parity certification harness (PR #40, re-scoped in the pixel wave).
//
// THE CORRECTED CONTRACT (PR #41 finding, user direction): the captured references contain Palantir
// EXAMPLE data; the IOI ports render LIVE daemon truth. Full-body pixel parity is therefore the WRONG
// bar — it would reward replacing live IOI truth with captured data. The right target is:
//
//        PIXEL-IDENTICAL SHELL, SEMANTICALLY-TRUTHFUL BODY.
//
// So this harness certifies `shell_pixel_parity`: the reference SHELL/CHROME (global rail · header/
// topbar · app-rail/sidebar · toolbar · tabs · right inspector chrome · bottom tray chrome · control
// frames/labels/dividers) must be pixel-identical, while the DYNAMIC BODY (object rows, request rows,
// pipeline nodes, cards carrying live daemon values, generated refs/ids/counts/timestamps) is EXCLUDED
// from the pixel diff BY DESIGN — it is verified STRUCTURALLY + SEMANTICALLY by the per-surface verifier
// (same container placement, same table/card/canvas grammar, live count cross-checks, real-substrate
// existence, named gaps disabled in place). Dynamic VALUES that sit INSIDE a shell region are masked by
// region (a legitimate data mask); OVER-MASKING the shell chrome is a verifier failure.
//
// A surface's `shell_pixel_certified` = the #34/#39 visual gates pass AND the certified shell diff ≤ the
// shell budget AND the shell region bboxes align (≤ 8px) AND the certified shell covers a real fraction
// of the image (you cannot "certify the shell" by masking nearly all of it) AND no shell landmark/label
// is masked away. `full_pixel_parity` remains available (opt-in per surface) ONLY where reference and IOI
// bodies are intentionally identical (a static / fixture-controlled surface) — never for live-data bodies.
//
// shell_pixel_certified is a STRONGER evidence layer on TOP of daemon_wired; it never replaces the
// visual gate, the body-semantic checks, or daemon truth.
//
// The comparator is dependency-free: both PNGs are decoded + diffed inside headless chromium via
// canvas/getImageData (deterministic; no native image libs). Emits per surface/viewport: screenshots, a
// diff HEATMAP (green=body excluded-by-design · yellow=data-value masked · red=shell diff), a shell +
// mask manifest; plus result.json + contact-sheet.html.
//
// Env: IOI_PIXEL_SURFACES=schema,approvals (default: every daemon_wired seed) ·
//      IOI_PIXEL_VIEWPORTS=1440x900 (default: 1440x900,1920x1080 + mobile probe) ·
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

// ---- CERTIFICATION THRESHOLDS (deep-pinned by the verifier; no quiet loosening of any knob) ----------
export const THRESHOLDS = {
  // CALIBRATED (PR #41 measurement): with the shell geometrically aligned (anchors 0,0 · container bbox
  // 0px · identical platform fonts on both sides), the residual raw diff floor measured ~1.7% with ZERO
  // run-to-run variance — composed of whole-run sub-pixel rasterization drift on bold text (<=1-2px,
  // the AA class) plus the intentional brand-mark delta (~0.2%). The gate is therefore DUAL: the
  // DILATED metric (a pixel counts only if no <=1px neighbor in the other image matches — forgives
  // AA/sub-pixel text drift, still catches wrong icons/colors/layout blocks) is the certifying budget,
  // and a RAW ceiling prevents gross-but-dilatable drift.
  shell_diff_dilated_pct_max: 1.25,    // certified-shell diff after 1px dilation (the AA-tolerant text metric)
  shell_diff_raw_pct_max: 3.0,         // raw certified-shell diff ceiling (gross-drift stop)
  shell_bbox_delta_px_max: 8,          // max edge delta for a canonical SHELL region detected on both sides
  min_shell_certified_fraction: 0.05,  // the certified shell (shell minus data-value masks) must cover ≥5%
                                       // of the image — a shell cannot be "certified" by masking it away
  data_mask_in_shell_fraction_max: 0.5,// data-value masks may cover at most 50% of the shell area (the rest
                                       // — chrome, labels, frames — must actually be pixel-compared)
  landmark_mask_overlap_max: 0.3,      // a data mask covering >30% of EVERY occurrence of a shell landmark = over-mask
  pixel_delta_threshold: 0.1,          // per-pixel perceptual distance (0..1) above which a pixel counts as diff
  palette_delta_max: 0.05,             // shell zone avg-RGB drift budget (a uniform tint cannot slide under the threshold)
};

// ---- PER-SURFACE SHELL GEOMETRY + data-value masks. The SHELL rects (viewport-anchored) define the
// certified chrome; everything OUTSIDE them is the dynamic body, EXCLUDED by design. `data` selectors
// resolve to dynamic VALUES that sit inside the shell (counts/ids/live labels) and are excluded from the
// diff — a legitimate data mask, not an over-mask. Anchors: left (x from left), right (x from right edge),
// topbar (full width, top band). `full_pixel` opts a surface into full-body parity (static bodies only).
export const SURFACE_SHELL = {
  schema: {
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },        // dark global rail
      { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 50 },   // white navbar
      { key: "apprail", anchor: "left", x: 230, y: 50, w: 299, h: 0 },  // Discover/Resources/Health nav column
    ],
    // Counts in the nav column are LIVE daemon values on the IOI side and CAPTURED example values on the
    // reference side — both masked as dynamic data (the pill frames/labels stay compared).
    data: { ref: [{ selector: '[class*="sidebar-main-navigation" i] .bp6-tag', label: "captured-resource-counts" }], ioi: [{ selector: ".og-c", label: "live-resource-counts" }] },
  },
  approvals: {
    // The approvals reference has NO top navbar — the app title lives inside the 300px faceted sidebar,
    // which starts at the very top next to the 230px global rail.
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "apprail", anchor: "content", x: 230, y: 0, w: 300, h: 0 }, // faceted filters sidebar (centers with the 1210px content block at wide viewports)
    ],
    // The additional-filter CONTROLS carry captured filter STATE on the reference (e.g. blue-active
    // "Access requests"/"Approved +3" selections) vs named-gap placeholders on the port — dynamic UI
    // residue. Masked by RECT (the reference is opaque hash-classed bp6 DOM); the sidebar is left-anchored
    // so the rects hold at both viewports. Labels (Request type/Status/Created by), the Quick-filters card
    // structure, section headers, and the title stay pixel-compared.
    // The reference is opaque hash-classed bp6 DOM, so its captured-state controls are masked by RECT at
    // the reference's own positions; the IOI port's controls are masked by SELECTOR at the PORT's positions
    // (the two sides' control rhythms differ slightly, so per-side masks — unioned — cover both). Labels,
    // section headers, the Quick-filters card + row labels, and the title stay pixel-compared.
    data: {
      // The form now aligns to the reference on both sides, so the captured-state controls are masked by
      // RECT (viewport-anchored; the left-anchored sidebar holds at both viewports). Upper facet VALUES
      // (Request type/Status/Created by — captured selections vs named-gap placeholders) are masked; the
      // lower named-gap facets (which diverge from the reference's exact facet set) are masked as one
      // label+control block. Section headers, filter LABELS, the Quick-filters card + row labels, and the
      // title stay pixel-compared. Same rects both sides (the selects are aligned).
      ref: [
        { rect: { x: 470, y: 130, w: 48, h: 135 }, anchor: "content", label: "quick-filter-counts" },
        { rect: { x: 298, y: 349, w: 214, h: 36 }, anchor: "content", label: "request-type-value (captured selection)" },
        { rect: { x: 298, y: 431, w: 214, h: 36 }, anchor: "content", label: "status-value (captured selection)" },
        { rect: { x: 298, y: 513, w: 214, h: 36 }, anchor: "content", label: "created-by-value" },
        { rect: { x: 285, y: 552, w: 230, h: 285 }, anchor: "content", label: "lower named-gap facets (checkbox + 3 controls; the set diverges from the reference)" },
      ],
      ioi: [],
    },
  },
  listings: {
    // Marketplace browse (#48): certified shell = rail + header + hero band (title/subtitle +
    // the verbatim reference illustration) + the Stores head band + the store-card CHROME
    // (header row + card box) + the install-wizard band. The store ROW is masked data (the
    // estate's live listing plane + product count on BOTH sides — the reference's Stores lane
    // is rebound to the same substrate). Content = the approvals rule: a 1210px block centered
    // right of the rail (offset 0 @1440, +240 @1920) → content-anchored rects/masks.
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
      { key: "hero", anchor: "topbar", x: 230, y: 51, w: 0, h: 106 },
      { key: "storeshead", anchor: "content", x: 275, y: 172, w: 1120, h: 46 },
      { key: "storecard", anchor: "content", x: 275, y: 230, w: 1120, h: 496 },
      { key: "wizcard", anchor: "content", x: 275, y: 745, w: 1120, h: 155 },
    ],
    // Masked DATA: the store ROW region (live plane name/copy/count on both sides — identical
    // daemon truth, masked on principle) — the card chrome + empty region below stay compared.
    data: {
      ref: [
        { rect: { x: 280, y: 265, w: 1110, h: 68 }, anchor: "content", label: "store row (the rebound estate listing plane + live product count)" },
      ],
      ioi: [
        { selector: ".mk-rows", label: "live-store-rows" },
      ],
    },
  },
  models: {
    // Model Catalog (#47): certified shell = rail + header (title + tabs) + the full-width hero
    // band + the PINNED Filters card chrome + the Additional-models heading. Facet ROWS inside
    // the card are masked data (live route truth vs the capture's template-derived rows); the
    // model CARD LIST is the excluded live body. Layout is fully fixed-left (identical at both
    // viewports — only heights differ via the full-height rail).
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
      { key: "hero", x: 230, y: 51, w: 1210, h: 164 },
      { key: "filters", x: 285, y: 251, w: 300, h: 355 },
      { key: "addhead", x: 615, y: 245, w: 250, h: 28 },
    ],
    rects_by_viewport: {
      "1920x1080": [
        { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
        { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
        { key: "hero", x: 230, y: 51, w: 1690, h: 164 },
        { key: "filters", x: 285, y: 251, w: 300, h: 355 },
        { key: "addhead", x: 615, y: 245, w: 250, h: 28 },
      ],
    },
    // Masked DATA: the facet ROW regions (live route-derived rows/counts/bars vs the capture's
    // template rows — the section HEADERS + Clear buttons stay compared chrome).
    data: {
      ref: [
        { rect: { x: 300, y: 392, w: 270, h: 40 }, label: "lifecycle facet rows (live route truth vs captured template rows)" },
        { rect: { x: 300, y: 462, w: 270, h: 62 }, label: "type facet rows (live route truth vs captured template rows)" },
        { rect: { x: 300, y: 556, w: 270, h: 44 }, label: "model-creator facet rows (live route truth vs captured template rows)" },
      ],
      ioi: [
        { selector: ".mc-frows", label: "live-facet-rows" },
      ],
    },
  },
  explorer: {
    // Object Explorer (#46): certified shell = rail + exploration TAB BAR + the centered search
    // hero + shortcuts band (label/lane tabs; the CARDS are live data) + the catalog heading/
    // filter/sort band + the table HEADER + the object-set band. The catalog/set ROWS are the
    // live body (excluded). CONTENT RULE: max-width 1400 centered with 60px min margins —
    // margins 60 @1440 / 145 @1920, so content-zone rects are pinned per viewport.
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "tabbar", anchor: "topbar", x: 230, y: 0, w: 0, h: 40 },
      { key: "hero", x: 480, y: 40, w: 710, h: 100 },
      { key: "shortcuts", x: 285, y: 148, w: 1100, h: 44 },
      { key: "catalogband", x: 285, y: 300, w: 1100, h: 105 },
      { key: "setband", x: 285, y: 828, w: 1100, h: 44 },
    ],
    rects_by_viewport: {
      "1920x1080": [
        { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
        { key: "tabbar", anchor: "topbar", x: 230, y: 0, w: 0, h: 40 },
        { key: "hero", x: 720, y: 40, w: 710, h: 100 },
        { key: "shortcuts", x: 370, y: 148, w: 1410, h: 44 },
        { key: "catalogband", x: 370, y: 300, w: 1410, h: 105 },
        { key: "setband", x: 370, y: 820, w: 1410, h: 44 },
      ],
    },
    // Masked DATA: the live "N of M" catalog count tag (real type counts vs the capture's
    // 55 of 55). Everything else in the certified rects is chrome; rows/cards live OUTSIDE
    // the rects (excluded body).
    data: {
      ref: [
        { rect: { x: 676, y: 346, w: 70, h: 26 }, label: "catalog count tag (live N of M vs captured 55 of 55)" },
      ],
      ioi: [
        { selector: ".oe-count", label: "live-catalog-count" },
      ],
    },
  },
  designer: {
    // Solution Designer landing (#49 — the first origin-alignment-queue port): certified shell =
    // rail + header + the full-width hero band (title/description + the VERBATIM reference
    // illustration) + the AIP-architect banner card (all chrome incl. the named-gap Start-planning
    // control) + the template-gallery card (heading + Browse-all + the VERBATIM capture strip —
    // the reference's own static template-library previews, vendor chrome not estate data) + the
    // View row (Recents/Favorites pills + Open Diagram) + the table ring + header row. The diagram
    // ROWS are masked data (captured tutorial resources vs live ontology compositions). Content =
    // the approvals rule: a 1000px block centered right of the rail (offset 0 @1440, +240 @1920)
    // → content-anchored rects/masks.
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
      { key: "hero", anchor: "topbar", x: 230, y: 51, w: 0, h: 181 },
      { key: "aipcard", anchor: "content", x: 330, y: 170, w: 1010, h: 102 },
      { key: "gallery", anchor: "content", x: 330, y: 292, w: 1010, h: 289 },
      { key: "viewrow", anchor: "content", x: 335, y: 614, w: 1000, h: 34 },
      { key: "tablehead", anchor: "content", x: 330, y: 651, w: 1010, h: 40 },
    ],
    // Masked DATA: the diagram-row region below the table header (captured tutorial rows on the
    // reference vs the estate's live ontology-composition rows) — the table ring/header chrome
    // stays compared; the region runs to the fold at both viewports (clamped by the canvas).
    data: {
      ref: [
        { rect: { x: 336, y: 687, w: 998, h: 900 }, anchor: "content", label: "diagram rows (captured tutorial resources vs live ontology compositions)" },
      ],
      ioi: [
        { selector: ".dsg-rows", label: "live-solution-design-rows" },
      ],
    },
  },
  incidents: {
    // The issues-inbox app (#45): certified shell = rail + header + the FIXED-LEFT status/
    // filter sidebar + the list-HEADER band. The incident ROW LIST is the live body
    // (excluded by design — real blockers/failures vs the capture's 5 closed examples).
    // Layout is fixed-left (sidebar/list x identical at both viewports; only the header's
    // search/New/cog cluster and the Sort control right-anchor), so only heights differ.
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
      { key: "sidebar", x: 230, y: 51, w: 250, h: 849 },
      { key: "listhead", x: 480, y: 51, w: 960, h: 41 },
    ],
    rects_by_viewport: {
      "1920x1080": [
        { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
        { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
        { key: "sidebar", x: 230, y: 51, w: 250, h: 1029 },
        { key: "listhead", x: 480, y: 51, w: 1440, h: 41 },
      ],
    },
    // Dynamic DATA masked on both sides: the three status-lane count tags (live daemon
    // counts vs the capture's 0/5/5) and the list-header count text ("38 closed issues"
    // vs "5 closed issues"). Chrome (lanes, filters, list-header words, sort) is COMPARED
    // — the port pins "filtered by select filter" at the reference x so the count's width
    // cannot displace it.
    data: {
      ref: [
        { rect: { x: 438, y: 54, w: 42, h: 104 }, label: "status-lane count tags (live daemon counts vs captured 0/5/5)" },
        { rect: { x: 525, y: 54, w: 110, h: 26 }, label: "list-header count text (live count + noun vs captured '5 closed issues')" },
      ],
      ioi: [
        { selector: ".in-lcount", label: "live-lane-counts" },
        { selector: ".in-lcounttxt", label: "live-list-count" },
      ],
    },
  },
  pipeline: {
    // The builder canvas app: certified shell = rail + header + the floating CARDS (tool card, canvas
    // float/zoom buttons, Legend) + the right outputs panel + the tray TABS row. The canvas/graph is the
    // live body (excluded). The tool card WRAPS (3 group-rows @1440 → 1 row @1920) and the cards are
    // right-/bottom-anchored, so the shell rects are pinned EXPLICITLY per certified viewport.
    rects: [
      { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
      { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
      { key: "toolbar", x: 240, y: 61, w: 292, h: 166 },
      { key: "floatbtns", x: 652, y: 61, w: 74, h: 32 },
      { key: "legend", x: 733, y: 61, w: 314, h: 126 },
      { key: "zoom", x: 240, y: 502, w: 30, h: 90 },
      { key: "right", anchor: "rightpanel", x: 386, y: 51, w: 386, h: 0 },
      { key: "tray", x: 230, y: 600, w: 824, h: 37 },
    ],
    rects_by_viewport: {
      "1920x1080": [
        { key: "rail", anchor: "left", x: 0, y: 0, w: 230, h: 0 },
        { key: "header", anchor: "topbar", x: 230, y: 0, w: 0, h: 51 },
        { key: "toolbar", x: 240, y: 61, w: 872, h: 56 },
        { key: "floatbtns", x: 1132, y: 61, w: 74, h: 32 },
        { key: "legend", x: 1213, y: 61, w: 314, h: 126 },
        { key: "zoom", x: 240, y: 682, w: 30, h: 90 },
        { key: "right", anchor: "rightpanel", x: 386, y: 51, w: 386, h: 0 },
        { key: "tray", x: 230, y: 780, w: 1304, h: 37 },
      ],
    },
    // Dynamic residue masked on BOTH sides: the header's live/captured names + SESSION-STATE middle zone
    // (reference: tabs/undo/branch/build state · port: the live Build/Preview controls), the right
    // panel's output card + settings VALUES (captured example vs live projection), legend counts, the
    // reference's Suggestions count pill + Batch count. Chrome (labels/tabs/icons/panels) stays compared.
    data: {
      ref: [
        { rect: { x: 285, y: 2, w: 365, h: 20 }, label: "breadcrumb-names (captured example vs live ontology)" },
        { rect: { x: 528, y: 24, w: 16, h: 18 }, label: "batch-count (captured)" },
        { rect: { x: 698, y: 2, w: 494, h: 47 }, label: "session-state middle zone (ref: tabs/undo/branch/build · port: live Build/Preview controls)" },
        { rect: { x: 728, y: 2, w: 483, h: 47 }, anchor: "right", label: "session-state middle overflow (wide viewports: Saved/Propose/Deploy cluster; sits inside the fixed middle mask at 1440)" },
        { rect: { x: 380, y: 140, w: 330, h: 92 }, anchor: "right", label: "output card (captured example vs live projection)" },
        { rect: { x: 380, y: 230, w: 330, h: 40 }, anchor: "right", label: "output stat line (live values)" },
        { rect: { x: 250, y: 112, w: 190, h: 48 }, anchor: "bottomright", label: "output-settings VALUES (captured vs live names)" },
        { rect: { x: 620, y: 96, w: 44, h: 62 }, anchor: "right", label: "legend counts col1 (live category counts)" },
        { rect: { x: 456, y: 96, w: 30, h: 62 }, anchor: "right", label: "legend counts col2 (live category counts)" },
        { rect: { x: 502, y: 296, w: 26, h: 28 }, anchor: "bottom", label: "suggestions count pill (captured session state)" },
      ],
      ioi: [
        { selector: ".pb-crumb", label: "live-breadcrumb-names" },
        { selector: ".pb-outcard,.pb-outstat", label: "live-projection-card+stat" },
        { selector: ".pb-setv", label: "live-output-settings-values" },
        { selector: ".pb-legrow b", label: "live-legend-counts" },
      ],
    },
  },
};

const VIEWPORTS_DESKTOP = [{ width: 1440, height: 900 }, { width: 1920, height: 1080 }];
const VIEWPORT_MOBILE = { width: 390, height: 844 };

// Resolve a viewport-anchored shell rect template to concrete px for a given viewport.
export function resolveShellRects(templates, vw, vh) {
  return (templates || []).map((t) => {
    let x = t.x, y = t.y, w = t.w, h = t.h;
    if (t.anchor === "left") { w = w || Math.round(vw * 0.16); h = h || vh; }
    else if (t.anchor === "right") { x = vw - (t.w || 300); w = t.w || 300; h = h || vh; }
    else if (t.anchor === "topbar") { w = w || (vw - (t.x || 0)); h = h || Math.round(vh * 0.06); }
    else if (t.anchor === "content") { x = t.x + contentOffset(t, vw); h = h || vh; }
    else if (t.anchor === "bottom") { y = vh - t.y; w = w || (vw - (t.x || 0)); }
    else if (t.anchor === "rightpanel") { x = vw - t.x; h = h || (vh - y); }
    return { key: t.key, left: x, top: y, w, h };
  });
}

// "content" anchor: the reference centers a fixed-width content BLOCK (its 1440 layout) in the area
// right of the global rail — offset 0 at 1440, +(available-block)/2 at wider viewports (measured:
// approvals block 1210 → +240 at 1920). Shell rects AND rect masks inside the block follow it.
export function contentOffset(t, vw) {
  const railW = t.railW || 230, blockW = t.blockW || 1210;
  return Math.max(0, Math.round((vw - railW - blockW) / 2));
}

// ---- OVER-MASK / coverage guard (pure; exported). Grid occupancy at 4px. Reports: certified shell
// fraction (shell minus data), data-in-shell fraction, and any shell landmark fully masked. -----------
export function shellGuard(shellRects, dataRects, landmarkRects, vw, vh) {
  const cell = 4, gw = Math.ceil(vw / cell), gh = Math.ceil(vh / cell);
  const shell = new Uint8Array(gw * gh), data = new Uint8Array(gw * gh);
  const paint = (grid, r) => { const x0 = Math.max(0, Math.floor(r.left / cell)), y0 = Math.max(0, Math.floor(r.top / cell)), x1 = Math.min(gw - 1, Math.floor((r.left + r.w) / cell)), y1 = Math.min(gh - 1, Math.floor((r.top + r.h) / cell)); for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) grid[y * gw + x] = 1; };
  for (const r of shellRects || []) paint(shell, r);
  for (const r of dataRects || []) paint(data, r);
  let shellCells = 0, dataInShell = 0, certified = 0;
  for (let i = 0; i < shell.length; i++) { if (shell[i]) { shellCells++; if (data[i]) dataInShell++; else certified++; } }
  const total = gw * gh;
  const landmarks_masked = [];
  for (const [name, rOrList] of Object.entries(landmarkRects || {})) {
    const rects = (Array.isArray(rOrList) ? rOrList : [rOrList]).filter((r) => r && r.w > 0 && r.h > 0);
    if (!rects.length) continue;
    // only consider landmark occurrences INSIDE the shell (body landmarks are excluded by design)
    const inShell = rects.filter((r) => { const cx = Math.floor((r.left + r.w / 2) / cell), cy = Math.floor((r.top + r.h / 2) / cell); return cx >= 0 && cy >= 0 && cx < gw && cy < gh && shell[cy * gw + cx]; });
    if (!inShell.length) continue;
    let allCovered = true;
    for (const r of inShell) {
      const x0 = Math.max(0, Math.floor(r.left / cell)), y0 = Math.max(0, Math.floor(r.top / cell)), x1 = Math.min(gw - 1, Math.floor((r.left + r.w) / cell)), y1 = Math.min(gh - 1, Math.floor((r.top + r.h) / cell));
      let cov = 0, cells = 0;
      for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) { cells++; if (data[y * gw + x]) cov++; }
      if (!cells || cov / cells <= THRESHOLDS.landmark_mask_overlap_max) { allCovered = false; break; }
    }
    if (allCovered) landmarks_masked.push(name);
  }
  return {
    shell_fraction: Math.round((shellCells / total) * 1000) / 1000,
    certified_fraction: Math.round((certified / total) * 1000) / 1000,
    data_in_shell_fraction: shellCells ? Math.round((dataInShell / shellCells) * 1000) / 1000 : 0,
    landmarks_masked,
  };
}

// ---- BBOX deltas over the canonical geometric regions detected on both sides (pure; exported). -------
export function bboxDeltas(refBoxes, ioiBoxes) {
  const out = {};
  for (const k of Object.keys(refBoxes || {})) {
    const a = refBoxes[k], b = (ioiBoxes || {})[k];
    if (!a || !b) continue;
    // The delta is meaningful only when both sides detected the SAME piece of chrome — require the two
    // boxes to overlap (≥25% of the smaller box). Non-overlapping detections are DIFFERENT elements (a
    // hashed-class false hit on one side); their difference is measured by the pixel diff, not bbox.
    const ix = Math.max(0, Math.min(a.left + a.w, b.left + b.w) - Math.max(a.left, b.left));
    const iy = Math.max(0, Math.min(a.top + a.h, b.top + b.h) - Math.max(a.top, b.top));
    const inter = ix * iy, minArea = Math.min(a.w * a.h, b.w * b.h);
    if (!minArea || inter / minArea < 0.25) continue;
    out[k] = Math.max(Math.abs(a.left - b.left), Math.abs(a.top - b.top), Math.abs((a.left + a.w) - (b.left + b.w)), Math.abs((a.top + a.h) - (b.top + b.h)));
  }
  return out;
}

// Fraction of a region box lying inside the declared shell rects (pure; exported). The shell bbox gate
// applies ONLY to region boxes that are genuinely part of the declared shell — a reference "header"-class
// hit on a BODY section heading (outside the shell) is body content, excluded by design like the rest of
// the body. Grid occupancy at 4px, consistent with shellGuard.
export function boxShellFraction(box, shellRects) {
  if (!box || box.w <= 0 || box.h <= 0) return 0;
  const cell = 4;
  let inside = 0, total = 0;
  for (let y = box.top; y < box.top + box.h; y += cell) for (let x = box.left; x < box.left + box.w; x += cell) {
    total++;
    for (const r of shellRects || []) { if (x >= r.left && x < r.left + r.w && y >= r.top && y < r.top + r.h) { inside++; break; } }
  }
  return total ? inside / total : 0;
}

// ---- THE SHELL CERTIFICATION VERDICT (pure; exported — the fail-closed contract the verifier pins). --
export function shellVerdict(i) {
  const reasons = [];
  if (!i.evidence_ok) reasons.push("missing/undersized screenshot evidence — fail closed");
  if (i.reference_errored) reasons.push("reference is an ERROR page — cannot certify");
  if (i.ioi_errored) reasons.push("IOI candidate is an ERROR page — cannot certify");
  if (!i.reference_valid) reasons.push("reference invalid (not loaded / no regions)");
  if (!i.ioi_valid) reasons.push("IOI candidate invalid (not loaded)");
  if (!i.structural_parity) reasons.push("structural (region-geometry) gate failed");
  if (!i.theme_match) reasons.push("theme mismatch — the #34 gate");
  if (!i.landmark_ok) reasons.push("reference IA landmarks not reproduced — the #34 gate");
  if (!i.dims_match) reasons.push("screenshot dimensions differ — fail closed");
  if (!i.coverage) reasons.push("shell coverage stats missing — fail closed");
  else {
    if ((i.coverage.certified_fraction || 0) < THRESHOLDS.min_shell_certified_fraction) reasons.push(`certified shell covers only ${i.coverage.certified_fraction} of the image < ${THRESHOLDS.min_shell_certified_fraction} (shell cannot be masked away)`);
    if ((i.coverage.data_in_shell_fraction || 0) > THRESHOLDS.data_mask_in_shell_fraction_max) reasons.push(`data masks cover ${i.coverage.data_in_shell_fraction} of the shell > ${THRESHOLDS.data_mask_in_shell_fraction_max} (too much of the shell is masked)`);
    if ((i.coverage.landmarks_masked || []).length) reasons.push(`OVER-MASK: data mask covers shell landmark(s): ${i.coverage.landmarks_masked.join(", ")}`);
  }
  if (typeof i.shell_diff_dilated_pct !== "number" || typeof i.shell_diff_raw_pct !== "number") reasons.push("shell pixel metrics missing — fail closed");
  else {
    if (i.shell_diff_dilated_pct > THRESHOLDS.shell_diff_dilated_pct_max) reasons.push(`certified shell DILATED diff ${i.shell_diff_dilated_pct}% > ${THRESHOLDS.shell_diff_dilated_pct_max}% (structural shell difference beyond the AA class)`);
    if (i.shell_diff_raw_pct > THRESHOLDS.shell_diff_raw_pct_max) reasons.push(`certified shell RAW diff ${i.shell_diff_raw_pct}% > ${THRESHOLDS.shell_diff_raw_pct_max}% (gross drift ceiling)`);
  }
  if (!i.palette || !i.palette.shell) reasons.push("shell palette data missing — fail closed");
  else if (i.palette.shell.delta > THRESHOLDS.palette_delta_max) reasons.push(`shell palette drift Δ${i.palette.shell.delta} > ${THRESHOLDS.palette_delta_max} (a uniform tint cannot certify)`);
  const overs = Object.entries(i.bbox_deltas || {}).filter(([, d]) => d > THRESHOLDS.shell_bbox_delta_px_max);
  if (overs.length) reasons.push(`shell region bbox delta > ${THRESHOLDS.shell_bbox_delta_px_max}px: ${overs.map(([k, d]) => `${k}=${d}px`).join(", ")}`);
  return { certified: reasons.length === 0, reasons };
}

// ---- The in-chromium comparator: diffs ONLY the certified shell (in-shell AND not-in-data-mask). -----
async function compareShell(browser, refPng, ioiPng, shellRects, dataRects, vw, vh) {
  const page = await browser.newPage();
  const res = await page.evaluate(async ({ refB64, ioiB64, shell, data, delta, vw }) => {
    const load = (b64) => new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = rej; im.src = "data:image/png;base64," + b64; });
    const [ri, ii] = await Promise.all([load(refB64), load(ioiB64)]);
    if (ri.width !== ii.width || ri.height !== ii.height) return { dims_match: false, ref_dims: [ri.width, ri.height], ioi_dims: [ii.width, ii.height] };
    const W = ri.width, H = ri.height;
    const cv = (im) => { const c = document.createElement("canvas"); c.width = W; c.height = H; const g = c.getContext("2d", { willReadFrequently: true }); g.drawImage(im, 0, 0); return g.getImageData(0, 0, W, H).data; };
    const A = cv(ri), B = cv(ii);
    const s = W / (vw || W); // image px per CSS px (1 at dpr 1; scales masks/rects if dpr≠1)
    const inRects = (rects, x, y) => { for (const r of rects) { if (x >= r.left * s && x < (r.left + r.w) * s && y >= r.top * s && y < (r.top + r.h) * s) return true; } return false; };
    const heat = document.createElement("canvas"); heat.width = W; heat.height = H;
    const hg = heat.getContext("2d"); const hd = hg.createImageData(W, H); const HP = hd.data;
    let certified = 0, diff = 0, diffDilated = 0;
    const pxDist = (i, j) => { const dr = A[i] - B[j], dg = A[i + 1] - B[j + 1], db = A[i + 2] - B[j + 2]; return Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db) / 255; };
    // dilated match: does (x,y) in one image have a <=1px neighbor in the other within the threshold?
    const nearMatch = (x, y, AtoB) => {
      const i = (y * W + x) * 4;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        const nx = x + dx, ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= W || ny >= H) continue;
        const j = (ny * W + nx) * 4;
        const d = AtoB ? (() => { const dr = A[i] - B[j], dg = A[i + 1] - B[j + 1], db = A[i + 2] - B[j + 2]; return Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db) / 255; })() : (() => { const dr = B[i] - A[j], dg = B[i + 1] - A[j + 1], db = B[i + 2] - A[j + 2]; return Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db) / 255; })();
        if (d <= delta) return true;
      }
      return false;
    };
    const acc = { ref: [0, 0, 0, 0], ioi: [0, 0, 0, 0] }; // shell palette accumulators
    for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
      const idx = (y * W + x) * 4;
      const gray = Math.round(0.55 * (0.299 * A[idx] + 0.587 * A[idx + 1] + 0.114 * A[idx + 2]));
      HP[idx] = gray; HP[idx + 1] = gray; HP[idx + 2] = gray; HP[idx + 3] = 255;
      const isShell = inRects(shell, x, y);
      if (!isShell) { HP[idx] = Math.min(255, gray + 15); HP[idx + 1] = Math.min(255, gray + 45); HP[idx + 2] = Math.min(255, gray + 15); continue; } // green = body excluded by design
      const isData = inRects(data, x, y);
      if (isData) { HP[idx] = Math.min(255, gray + 60); HP[idx + 1] = Math.min(255, gray + 60); HP[idx + 2] = 40; continue; } // yellow = data-value masked
      // certified shell pixel
      const ra = acc.ref, ia = acc.ioi;
      ra[0] += A[idx]; ra[1] += A[idx + 1]; ra[2] += A[idx + 2]; ra[3]++;
      ia[0] += B[idx]; ia[1] += B[idx + 1]; ia[2] += B[idx + 2];
      certified++;
      if (pxDist(idx, idx) > delta) {
        diff++;
        if (!nearMatch(x, y, true) || !nearMatch(x, y, false)) { diffDilated++; HP[idx] = 255; HP[idx + 1] = 40; HP[idx + 2] = 40; } // red = survives dilation (real diff)
        else { HP[idx] = 255; HP[idx + 1] = 150; HP[idx + 2] = 40; } // orange = AA/sub-pixel class (forgiven by dilation)
      }
    }
    hg.putImageData(hd, 0, 0);
    const avg = (a) => a[3] ? [Math.round(a[0] / a[3]), Math.round(a[1] / a[3]), Math.round(a[2] / a[3])] : [0, 0, 0];
    const rgb = avg(acc.ref), irgb = [acc.ioi[0], acc.ioi[1], acc.ioi[2]].map((v) => acc.ref[3] ? Math.round(v / acc.ref[3]) : 0);
    const pdelta = Math.round(Math.sqrt(0.299 * (rgb[0] - irgb[0]) ** 2 + 0.587 * (rgb[1] - irgb[1]) ** 2 + 0.114 * (rgb[2] - irgb[2]) ** 2) / 2.55) / 100;
    return { dims_match: true, width: W, height: H, certified_px: certified, diff_px: diff, diff_dilated_px: diffDilated, shell_diff_raw_pct: certified ? Math.round((diff / certified) * 10000) / 100 : 100, shell_diff_dilated_pct: certified ? Math.round((diffDilated / certified) * 10000) / 100 : 100, palette: { shell: { ref_avg_rgb: rgb, ioi_avg_rgb: irgb, delta: pdelta } }, heatmap_b64: heat.toDataURL("image/png").split(",")[1] };
  }, { refB64: refPng.toString("base64"), ioiB64: ioiPng.toString("base64"), shell: shellRects, data: dataRects, delta: THRESHOLDS.pixel_delta_threshold, vw });
  await page.close();
  return res;
}

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
  const cfg = SURFACE_SHELL[s.slug] || { rects: [], data: { ref: [], ioi: [] } };
  writeFileSync(path.join(dir, "shell-manifest.json"), JSON.stringify({ slug: s.slug, model: "shell_pixel_parity", rule: "the SHELL rects are pixel-certified; the BODY (outside them) is excluded BY DESIGN and verified semantically by the surface verifier; `data` selectors mask dynamic VALUES inside the shell; over-masking the shell fails closed", shell_rects: cfg.rects, data_masks: cfg.data }, null, 2) + "\n");
  const rows = [];
  for (const vp of viewports) {
    const tag = `${vp.width}x${vp.height}`;
    const ctx = await browser.newContext({ viewport: vp });
    const refPngPath = path.join(dir, `ref-${tag}.png`), ioiPngPath = path.join(dir, `ioi-${tag}.png`);
    const anchorRects = (entries) => (entries || []).map((m) => {
      if (!m.rect) return m;
      if (m.anchor === "content") return { ...m, rect: { ...m.rect, x: m.rect.x + contentOffset(m, vp.width) } };
      // "right"/"bottom"/"bottomright": rect.x is the distance from the RIGHT edge / rect.y from the BOTTOM.
      if (m.anchor === "right") return { ...m, rect: { ...m.rect, x: vp.width - m.rect.x } };
      if (m.anchor === "bottom") return { ...m, rect: { ...m.rect, y: vp.height - m.rect.y } };
      if (m.anchor === "bottomright") return { ...m, rect: { ...m.rect, x: vp.width - m.rect.x, y: vp.height - m.rect.y } };
      return m;
    });
    const ref = await capture(ctx, s.reference_url, refPngPath, s.reference_landmarks, s.reference_pre_capture, anchorRects(cfg.data.ref));
    const ioi = await capture(ctx, s.ioi_url, ioiPngPath, s.reference_landmarks, null, anchorRects(cfg.data.ioi));
    await ctx.close();
    const p = parityOf(ref, ioi, s.reference_landmarks);
    const evidence_ok = ref.screenshotOk && ioi.screenshotOk;
    const reference_valid = !ref.errored && ref.loaded && ref.regions.length > 0;
    const ioi_valid = !ioi.errored && ioi.loaded;
    // A surface may pin EXPLICIT per-viewport shell rects (e.g. a wrapping toolbar card whose shape
    // changes between certified viewports); falls back to the anchored template set.
    const shellRects = resolveShellRects((cfg.rects_by_viewport && cfg.rects_by_viewport[tag]) || cfg.rects, vp.width, vp.height);
    const dataRects = [...(ref.maskRects || []), ...(ioi.maskRects || [])].map((m) => ({ left: m.left - 3, top: m.top - 3, w: m.w + 6, h: m.h + 6 }));
    const coverage = shellGuard(shellRects, dataRects, ref.landmarkRects || {}, vp.width, vp.height);
    let cmp = { dims_match: false };
    if (evidence_ok) { try { cmp = await compareShell(browser, readFileSync(refPngPath), readFileSync(ioiPngPath), shellRects, dataRects, vp.width, vp.height); } catch (e) { cmp = { dims_match: false, error: String(e.message || e).slice(0, 120) }; } }
    if (cmp.heatmap_b64) { writeFileSync(path.join(dir, `heatmap-${tag}.png`), Buffer.from(cmp.heatmap_b64, "base64")); delete cmp.heatmap_b64; }
    // bbox deltas over the SHELL regions the geometry detector found on both sides — and ONLY for
    // reference boxes genuinely INSIDE the declared shell (a "header"-class hit on a body section
    // heading is body content, excluded by design).
    const shellKeys = new Set(cfg.rects.map((r) => r.key));
    const refShellBoxes = Object.fromEntries(Object.entries(ref.regionBoxes || {}).filter(([k, box]) => shellKeys.has(k) && boxShellFraction(box, shellRects) >= 0.6));
    const deltas = bboxDeltas(refShellBoxes, ioi.regionBoxes);
    const verdict = shellVerdict({
      evidence_ok, reference_errored: ref.errored, ioi_errored: ioi.errored, reference_valid, ioi_valid,
      structural_parity: p.structural_parity, theme_match: p.theme_match,
      landmark_ok: p.landmark_declared >= 5 && p.landmark_applicable >= Math.ceil(p.landmark_declared * 0.6) && p.landmark_coverage >= 0.8,
      dims_match: cmp.dims_match === true, shell_diff_raw_pct: cmp.shell_diff_raw_pct, shell_diff_dilated_pct: cmp.shell_diff_dilated_pct, coverage, bbox_deltas: deltas, palette: cmp.palette || null,
    });
    rows.push({
      viewport: tag, reference_url: s.reference_url, ioi_url: s.ioi_url,
      certified: verdict.certified, reasons: verdict.reasons,
      gates: { evidence_ok, reference_errored: ref.errored, ioi_errored: ioi.errored, reference_valid, ioi_valid, structural_parity: p.structural_parity, theme_match: p.theme_match, landmark_covered: p.landmark_covered, landmark_applicable: p.landmark_applicable },
      metrics: { dims_match: cmp.dims_match === true, shell_diff_raw_pct: cmp.shell_diff_raw_pct ?? null, shell_diff_dilated_pct: cmp.shell_diff_dilated_pct ?? null, certified_px: cmp.certified_px ?? null, palette: cmp.palette || null, bbox_deltas: deltas, coverage, cmp_error: cmp.error || null },
      screens: { ref: `${s.slug}/ref-${tag}.png`, ioi: `${s.slug}/ioi-${tag}.png`, heatmap: `${s.slug}/heatmap-${tag}.png` },
    });
    console.log(`  ${verdict.certified ? "SHELL ✓" : "shell ✗"}  ${s.slug.padEnd(10)} ${tag.padEnd(9)} dilatedΔ ${cmp.shell_diff_dilated_pct ?? "—"}% rawΔ ${cmp.shell_diff_raw_pct ?? "—"}% certFrac ${coverage.certified_fraction} bboxΔ ${Object.values(deltas).length ? Math.max(...Object.values(deltas)) : "—"}px${verdict.certified ? "" : `  [${verdict.reasons[0]}]`}`);
  }
  return rows;
}

function contactSheet(surfaces) {
  const cell = (r, slug) => `<section style="border:1px solid #24262d;border-radius:10px;padding:12px;margin:0 0 14px;background:#15171c">
    <h3 style="margin:0 0 6px;font-size:14px">${slug} @ ${r.viewport} — <span style="color:${r.certified ? "#7ee0a2" : "#e0a27e"}">${r.certified ? "SHELL PIXEL PARITY ✓" : "shell not certified"}</span>
      <span style="color:#878a93;font-weight:400;font-size:12px">· dilatedΔ ${r.metrics.shell_diff_dilated_pct}% (raw ${r.metrics.shell_diff_raw_pct}%) · certified-shell ${r.metrics.coverage.certified_fraction} · body excluded by design · heatmap: red=structural, orange=AA-forgiven</span></h3>
    ${r.reasons.length ? `<div style="color:#e0a27e;font-size:12px;margin:0 0 8px">${r.reasons.join(" · ")}</div>` : ""}
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:11px">reference</figcaption><img src="${r.screens.ref}" style="width:100%;border:1px solid #2a2c33;border-radius:5px"></figure>
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:11px">IOI candidate</figcaption><img src="${r.screens.ioi}" style="width:100%;border:1px solid #2a2c33;border-radius:5px"></figure>
      <figure style="margin:0"><figcaption style="color:#878a93;font-size:11px">shell heatmap (red=shell diff · yellow=data-value · green=body excluded)</figcaption><img src="${r.screens.heatmap}" style="width:100%;border:1px solid #2a2c33;border-radius:5px"></figure>
    </div></section>`;
  return `<!doctype html><meta charset="utf-8"><title>Shell Pixel Parity — contact sheet</title>
    <body style="font-family:system-ui,sans-serif;background:#0e0f13;color:#e6e7ea;max-width:1200px;margin:0 auto;padding:22px">
    <h1 style="margin:0 0 4px">Shell Pixel Parity — contact sheet</h1>
    <p style="color:#878a93;margin:0 0 18px">Pixel-identical SHELL, semantically-truthful BODY. shell_pixel_certified = visual gates (#34/#39) AND certified-shell DILATED diff ≤ ${THRESHOLDS.shell_diff_dilated_pct_max}% AND raw ≤ ${THRESHOLDS.shell_diff_raw_pct_max}% AND shell region bboxΔ ≤ ${THRESHOLDS.shell_bbox_delta_px_max}px, over the shell chrome only — the live-data body is EXCLUDED by design and verified semantically by the surface verifier.</p>
    ${surfaces.flatMap((s) => s.viewports.map((r) => cell(r, s.slug))).join("")}</body>`;
}

async function run() {
  const filter = (process.env.IOI_PIXEL_SURFACES || "").split(",").map((x) => x.trim()).filter(Boolean);
  const all = surfacesFromMatrix();
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
    const viewports_pinned = vpEnv.length > 0;
    const shell_pixel_certified = !viewports_pinned && rows.length > 0 && rows.every((r) => r.certified);
    const surfaceRow = { slug: s.slug, matrix_class: s.matrix_class, shell_pixel_certified, viewports_pinned, mobile: viewports_pinned ? "viewports_pinned (non-certifying run)" : (mob.supported ? "supported" : `mobile_not_supported (${mob.detail})`), viewports: rows };
    out.push(surfaceRow);
    if (shell_pixel_certified) {
      const certDir = path.join(appRoot, "pixel-certifications");
      mkdirSync(certDir, { recursive: true });
      writeFileSync(path.join(certDir, `${s.slug}.json`), JSON.stringify({ schema: "ioi.hypervisor.shell-pixel-certification.v1", slug: s.slug, matrix_class: s.matrix_class, shell_pixel_certified: true, viewports_pinned: false, thresholds: THRESHOLDS, reference_url: s.reference_url, ioi_url: s.ioi_url, mobile: surfaceRow.mobile, note: "SHELL pixel parity — the live-data body is excluded by design and verified semantically by the surface verifier (body_semantic_truth)", viewports: rows }, null, 2) + "\n");
      console.log(`  ★ wrote pixel-certifications/${s.slug}.json (commit it — the matrix's shell-parity evidence pointer)`);
    }
    console.log(`  → ${s.slug}: shell_pixel_certified=${shell_pixel_certified}${viewports_pinned ? " (viewports pinned — non-certifying run)" : ""} (${rows.filter((r) => r.certified).length}/${rows.length} viewports)`);
  }
  await browser.close();
  const result = {
    schema: "ioi.hypervisor.shell-pixel-parity-harness.v1",
    thresholds: THRESHOLDS,
    rule: "Pixel-identical SHELL, semantically-truthful BODY. shell_pixel_certified certifies the reference chrome (rail/header/app-rail/toolbar/panels) pixel-for-pixel; the live-data body is EXCLUDED by design and verified semantically by the per-surface verifier. Never fabricate IOI data to satisfy a screenshot metric.",
    surfaces: out,
  };
  writeFileSync(path.join(ARTIFACT_DIR, "result.json"), JSON.stringify(result, null, 2) + "\n");
  writeFileSync(path.join(ARTIFACT_DIR, "contact-sheet.html"), contactSheet(out));
  console.log(`\nartifact: ${path.relative(process.cwd(), ARTIFACT_DIR)}/ (result.json + contact-sheet.html + per-surface screens/heatmaps/shell-manifests)`);
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().then((r) => {
    const c = r.surfaces.filter((s) => s.shell_pixel_certified).length;
    console.log(`${r.surfaces.length} surface(s) · ${c} shell-pixel-certified`);
  }).catch((e) => { console.error("shell pixel harness crashed:", e); process.exit(1); });
}
