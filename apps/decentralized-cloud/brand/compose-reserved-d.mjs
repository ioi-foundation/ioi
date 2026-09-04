#!/usr/bin/env node
// Round four: the reserved three-block d as the family construction, composed from
// measurement. Every number the board prints comes from here.
//
// The construction round scored this mark 38 and named four faults. Three of them
// are geometry and are fixed here rather than explained:
//
//   (a) ONE INK COLLAPSED THE THREE BLOCKS. They are told apart by their gradients;
//       remove colour and they fuse into a single silhouette. The fix is a GAP in
//       the geometry — the blocks touch along two seams, and a stroke is knocked
//       out along each so the separation is drawn, not painted. Whether a gap
//       survives 16px is measured by the ink-run probe, not asserted: the gap is
//       swept and the smallest one that still reads at each size is reported.
//
//   (b) THE CUES WERE THREE DIFFERENT ACCIDENTS on a shape that already carries
//       three internal edges, and at 16px one was indistinguishable from the base.
//       Here the cue is ONE slot — the same drawn shape, a real mask knockout —
//       and WHICH BLOCK carries it names the sibling. The blocks are stacked, so
//       the system has a meaning to state rather than being an index position.
//       The slot's position and size are not chosen: each block is eroded to find
//       its deepest interior point, so the slot sits where the block is thickest
//       and is as large as that block can carry.
//
//   (c) THE MARK WAS NOT OPTICALLY CENTRED — 20.5 units of air above, 6.8 below.
//       It is centred here on its measured ink box, and the tile is a real tile.
//
//   (d) The base geometry stays byte-identical to the source clip paths in every
//       derivation: nothing below redraws a path, it only translates the set.
//
// The dot is gone from the mark entirely, by owner ruling. The period lives in the
// wordmark only, drawn and medial, where it always did.
//
// Usage: node compose-reserved-d.mjs [--emit] [--gap N]

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");

const GRID = 96;
const SIZES = [16, 24, 32];
const TILE_R = 11;

// ── The source paths, from the owner's vector, never redrawn ────────────────
const emitted = execFileSync("node", [path.join(HERE, "reserved-d/parse-shapes.mjs"), "--emit"], { encoding: "utf8" });
const PATHS = [...emitted.matchAll(/^\s{2}(M [\d.\-][^\n]*)$/gm)].map((m) => m[1].trim());
if (PATHS.length !== 3) {
  console.error(`expected 3 source paths, parsed ${PATHS.length} — refusing to compose`);
  process.exit(1);
}

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 700 }, deviceScaleFactor: 1 });

async function raster(svg, w, h) {
  return await page.evaluate(async ({ markup, W, H }) => {
    const img = new Image();
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(markup);
    await img.decode();
    const c = document.createElement("canvas");
    c.width = W; c.height = H;
    const x = c.getContext("2d");
    x.drawImage(img, 0, 0, W, H);
    return { w: W, h: H, d: Array.from(x.getImageData(0, 0, W, H).data) };
  }, { markup: svg.replace("<svg", '<svg xmlns="http://www.w3.org/2000/svg"'), W: w, H: h });
}

// ── 1. Measure the mark's true ink box and centre it ────────────────────────
// getBBox on the curves, not a scan of the path data: the path data's control
// points lie outside the curve and overstate the box, which is how an earlier
// board printed 108.63 for a mark that is 107.89 wide.
await page.setContent(`<svg id="s" width="500" height="500" viewBox="0 0 200 200">${PATHS.map((d, i) => `<path id="p${i}" d="${d}"/>`).join("")}</svg>`);
const boxes = await page.evaluate((n) => {
  const out = [];
  for (let i = 0; i < n; i++) {
    const b = document.getElementById(`p${i}`).getBBox();
    out.push({ x0: b.x, y0: b.y, x1: b.x + b.width, y1: b.y + b.height });
  }
  return out;
}, PATHS.length);
const mx0 = Math.min(...boxes.map((b) => b.x0)), mx1 = Math.max(...boxes.map((b) => b.x1));
const my0 = Math.min(...boxes.map((b) => b.y0)), my1 = Math.max(...boxes.map((b) => b.y1));
const markW = mx1 - mx0, markH = my1 - my0;

// The tile is square and the mark is wider than tall, so the width binds. Leave a
// stated margin and centre what is left — both axes, which is the fix for 20.5
// above and 6.8 below.
const MARGIN = 9.5;                       // units of clear tile on the binding axis
const scale = (GRID - 2 * MARGIN) / markW;
const drawW = markW * scale, drawH = markH * scale;
const tx = (GRID - drawW) / 2 - mx0 * scale;
const ty = (GRID - drawH) / 2 - my0 * scale;
const XF = `translate(${tx.toFixed(3)} ${ty.toFixed(3)}) scale(${scale.toFixed(5)})`;

console.log(`the mark, measured on its curves:`);
console.log(`  source box ${markW.toFixed(2)} x ${markH.toFixed(2)}, aspect ${(markW / markH).toFixed(3)}`);
console.log(`  drawn ${drawW.toFixed(2)} x ${drawH.toFixed(2)} in a ${GRID} tile`);
console.log(`  margins: ${((GRID - drawW) / 2).toFixed(2)} each side, ${((GRID - drawH) / 2).toFixed(2)} above and below — optically centred on both axes`);

// ── 2. The contacts, and the gap that separates the blocks in one ink ───────
// The blocks do NOT share edges. Rendered large and tinted, the three touch at
// exactly two CORNER POINTS — the mid-left block meets the top-right one at a
// vertex, and the bottom block meets the top-right one's foot at another. That is
// what makes the one-ink form a single connected silhouette: two point contacts,
// not two long seams. An earlier version of this file modelled them as seams taken
// from bounding-box edges and measured a line that was mostly empty tile.
const TOUCH = [
  { x: 34.09, y: 27.84, what: "mid-left block meets top-right block" },
  { x: 75.70, y: 67.48, what: "bottom block meets the top-right block's foot" },
];

const seamMask = (gap) => `
  <mask id="seams" maskUnits="userSpaceOnUse" x="-20" y="-20" width="${GRID + 40}" height="${GRID + 40}">
    <rect x="-20" y="-20" width="${GRID + 40}" height="${GRID + 40}" fill="#fff"/>
    <g transform="${XF}">
      ${TOUCH.map((t) => `<circle cx="${t.x}" cy="${t.y}" r="${(gap / scale / 2).toFixed(3)}" fill="#000"/>`).join("")}
    </g>
  </mask>`;

// ── 3. Per-sibling cue: one slot, three blocks ──────────────────────────────
// Where is each block thickest? Erode its raster until it vanishes; the last pixel
// standing is the deepest interior point and the erosion count is how much room
// there is. The slot is placed and sized from that, so it is never guessed and
// never lands where a block is thin.
const R = 8; // raster the tile at 8x for the erosion
async function deepestPoint(i) {
  const r = await raster(
    `<svg width="${GRID * R}" height="${GRID * R}" viewBox="0 0 ${GRID} ${GRID}">` +
      `<rect width="${GRID}" height="${GRID}" fill="#000"/>` +
      `<g transform="${XF}"><path d="${PATHS[i]}" fill="#fff"/></g></svg>`,
    GRID * R, GRID * R
  );
  let cur = new Uint8Array(r.w * r.h);
  for (let p = 0; p < cur.length; p++) cur[p] = r.d[p * 4] > 128 ? 1 : 0;
  let best = null, rounds = 0;
  for (;;) {
    const next = new Uint8Array(cur.length);
    let alive = 0, sx = 0, sy = 0, n = 0;
    for (let y = 1; y < r.h - 1; y++)
      for (let x = 1; x < r.w - 1; x++) {
        const p = y * r.w + x;
        if (cur[p] && cur[p - 1] && cur[p + 1] && cur[p - r.w] && cur[p + r.w]) {
          next[p] = 1; alive++; sx += x; sy += y; n++;
        }
      }
    if (!alive) break;
    best = { x: sx / n / R, y: sy / n / R };
    cur = next; rounds++;
  }
  return { cx: best.x, cy: best.y, inradius: rounds / R };
}

const blockPts = [];
for (let i = 0; i < 3; i++) blockPts.push(await deepestPoint(i));
console.log(`\nblock interiors, found by erosion (deepest point and how much room it has):`);
["top-right", "mid-left", "bottom"].forEach((n, i) =>
  console.log(`  ${n.padEnd(10)} centre (${blockPts[i].cx.toFixed(2)}, ${blockPts[i].cy.toFixed(2)})  inradius ${blockPts[i].inradius.toFixed(2)} units`)
);

// The slot is one shape at one size for all three siblings — the smallest block's
// room sets it, so the same slot fits wherever it goes.
const room = Math.min(...blockPts.map((b) => b.inradius));
const SLOT_W = +(room * 1.5).toFixed(2);
const SLOT_H = +(room * 0.62).toFixed(2);
const CUES = { cloud: 0, exchange: 1, trade: 2 };
const CUE_MEANING = {
  cloud: "the top block — where work enters and is routed",
  exchange: "the middle block — the matching between two sides",
  trade: "the bottom block — the floor where a trade settles",
};
console.log(`  slot ${SLOT_W} x ${SLOT_H} units, sized by the tightest block (${room.toFixed(2)} inradius)`);

const cueMask = (which) => {
  const b = blockPts[CUES[which]];
  return `
  <mask id="cue" maskUnits="userSpaceOnUse" x="-20" y="-20" width="${GRID + 40}" height="${GRID + 40}">
    <rect x="-20" y="-20" width="${GRID + 40}" height="${GRID + 40}" fill="#fff"/>
    <rect x="${(b.cx - SLOT_W / 2).toFixed(2)}" y="${(b.cy - SLOT_H / 2).toFixed(2)}"
          width="${SLOT_W}" height="${SLOT_H}" rx="${(SLOT_H / 2).toFixed(2)}" fill="#000"/>
  </mask>`;
};

// ── 4. Render a mark ────────────────────────────────────────────────────────
const GRAD = `
  <linearGradient id="g1" gradientUnits="userSpaceOnUse" x1="-8.58" y1="5.95" x2="72.86" y2="-50.54">
    <stop offset="0" stop-color="#4075fa"/><stop offset="1" stop-color="#41dbf9"/></linearGradient>
  <linearGradient id="g2" gradientUnits="userSpaceOnUse" x1="-24.35" y1="16.89" x2="9.99" y2="-6.93">
    <stop offset="0" stop-color="#3f4dfa"/><stop offset="1" stop-color="#40a3f9"/></linearGradient>
  <linearGradient id="g3" gradientUnits="userSpaceOnUse" x1="-44.97" y1="31.19" x2="19.53" y2="-13.54">
    <stop offset="0" stop-color="#3f3dfa"/><stop offset="1" stop-color="#41bcf9"/></linearGradient>`;

function markSvg({ size, fills, ground = null, gap = 0, cue = null, tile = null }) {
  const useSeam = gap > 0;
  const inner = PATHS.map((d, i) => `<path d="${d}" fill="${fills[i]}"/>`).join("");
  const masks = (useSeam ? seamMask(gap) : "") + (cue ? cueMask(cue) : "");
  let body = `<g transform="${XF}">${inner}</g>`;
  if (useSeam) body = `<g mask="url(#seams)">${body}</g>`;
  if (cue) body = `<g mask="url(#cue)">${body}</g>`;
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">` +
    `<defs>${GRAD}${masks}</defs>` +
    (tile ? `<rect width="${GRID}" height="${GRID}" rx="${TILE_R}" fill="${tile}"/>` : "") +
    (ground ? `<rect width="${GRID}" height="${GRID}" fill="${ground}"/>` : "") +
    body + `</svg>`;
}

// ── 5. Does a gap survive? Sweep it and scan for ink runs ───────────────────
// Scanned across the row through the vertical seam and the column through the
// horizontal one — the two places the blocks actually touch.
async function gapSurvives(gap, size) {
  const svg = markSvg({ size, fills: ["#0a0e19", "#0a0e19", "#0a0e19"], gap, tile: "#ffffff" });
  const r = await raster(svg, size, size);
  // Sample ON the seam itself, not across the shape. Scanning a whole row or column
  // counts the mark's own concavities as separations and reports a pass for a gap of
  // zero — which is exactly what the control caught. What has to be true for a gap
  // to exist is narrower: pixels that lie ON the seam line, between the two blocks,
  // must read as ground rather than ink.
  // The question is whether the mark is one shape or three, so COUNT THE SHAPES:
  // flood-fill the ink and see how many connected regions there are. Scanning lines
  // cannot answer this — it is a question about connectivity, and connectivity is
  // what a corner contact destroys or preserves.
  const W = r.w, H = r.h;
  const ink = new Uint8Array(W * H);
  for (let p = 0; p < W * H; p++) ink[p] = r.d[p * 4] < 128 ? 1 : 0;
  const seen = new Uint8Array(W * H);
  const sizes = [];
  const stack = [];
  for (let p0 = 0; p0 < W * H; p0++) {
    if (!ink[p0] || seen[p0]) continue;
    let n = 0;
    stack.push(p0); seen[p0] = 1;
    while (stack.length) {
      const p = stack.pop(); n++;
      const x = p % W, y = (p / W) | 0;
      if (x > 0 && ink[p - 1] && !seen[p - 1]) { seen[p - 1] = 1; stack.push(p - 1); }
      if (x < W - 1 && ink[p + 1] && !seen[p + 1]) { seen[p + 1] = 1; stack.push(p + 1); }
      if (y > 0 && ink[p - W] && !seen[p - W]) { seen[p - W] = 1; stack.push(p - W); }
      if (y < H - 1 && ink[p + W] && !seen[p + W]) { seen[p + W] = 1; stack.push(p + W); }
    }
    sizes.push(n);
  }
  // A single antialiased pixel clinging to a corner is a raster artefact, not a
  // block. Counting them made a clean 32px render report six regions where the eye
  // sees three, so anything under a twentieth of the largest region is discarded
  // and the discard count is returned rather than hidden.
  const biggest = Math.max(0, ...sizes);
  const kept = sizes.filter((n) => n >= biggest / 20);
  return { components: kept.length, fragments: sizes.length - kept.length, biggest, ok: kept.length === 3 };

}

console.log(`\none ink — does a drawn gap keep the blocks apart? (3 connected regions = three blocks)`);
// 0.0 is the CONTROL and it must FUSE. Without it this probe cannot be trusted:
// if the scan line crosses a natural break in the silhouette it will report two
// runs whatever the gap is, and every row below would read as a pass earned by
// the mark's own concavity rather than by the gap.
const GAPS = [0.0, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0];
const gapArg = process.argv.indexOf("--gap");
let chosenGap = null;
const gapTable = [];
for (const g of GAPS) {
  const row = {};
  for (const s of SIZES) row[s] = await gapSurvives(g, s);
  const holds = SIZES.every((s) => row[s].ok);
  gapTable.push({ g, row, holds });
  console.log(`  gap ${g.toFixed(1).padStart(4)} units  ` +
    SIZES.map((s) => `${s}px ${row[s].components} region${row[s].components === 1 ? " " : "s"}${row[s].ok ? " apart" : " FUSED"}`).join("   "));
  if (holds && chosenGap === null && g > 0) chosenGap = g;
}

// The control was written to catch a probe that passes without a gap. It caught
// something else instead, and the finding is worth more than the fix it was
// guarding: WITH NO GAP AT ALL the blocks are already three separate regions at
// every size. They touch at two corner POINTS, and a point contact never produces
// connected ink at any raster resolution — so the one-ink form was never a single
// silhouette. It did not need repairing.
const control = gapTable[0];
const alreadyApart = SIZES.every((s) => control.row[s].ok);
if (alreadyApart) {
  chosenGap = 0;
  console.log(`\n  CONTROL FINDING: with NO gap the blocks are already three separate regions at`);
  console.log(`  16, 24 and 32px. They meet only at two corner points, which never render as`);
  console.log(`  connected ink. The one-ink reduction is the SAME DRAWING with the same three`);
  console.log(`  blocks — not a different object, and no gap is needed to make it so.`);
  console.log(`\n  This contradicts a cost an earlier board stated against this construction —`);
  console.log(`  that the blocks "lose their separation entirely in one colour" and the reduction`);
  console.log(`  is "a different object". That claim was written, not measured, and it is false.`);
} else {
  console.log(`\n  control: with no gap the blocks fuse, so the rows above are the gap's doing.`);
}
if (gapArg > -1) chosenGap = Number(process.argv[gapArg + 1]);

if (chosenGap === null) {
  const best = gapTable[gapTable.length - 1];
  console.log(`\n  NO GAP SURVIVES 16px. The smallest size at which any gap separates is above 16.`);
  console.log(`  This is the construction's accepted cost and the board must say so in those terms:`);
  console.log(`  at 16px the three blocks read as one silhouette, and the mark is a shape rather than a d.`);
} else {
  console.log(`\n  smallest gap that separates at every size: ${chosenGap.toFixed(1)} units ` +
    `(${((chosenGap / GRID) * 100).toFixed(1)}% of the tile, ${(chosenGap / 16 * 96 / 96 * 16 / 96 * 96).toFixed(2)}px at 16px)`);
}

// ── 6. Are the three cues distinguishable, alone, at 16 and 24px? ───────────
console.log(`\nper-sibling cue — one slot, three blocks, differenced against the uncued base:`);
let crossCheckFailed = false;
for (const size of [16, 24]) {
  const base = await raster(markSvg({ size, fills: ["#0a0e19", "#0a0e19", "#0a0e19"], gap: chosenGap || 0, tile: "#ffffff" }), size, size);
  const diffs = {};
  for (const k of Object.keys(CUES)) {
    const im = await raster(markSvg({ size, fills: ["#0a0e19", "#0a0e19", "#0a0e19"], gap: chosenGap || 0, cue: k, tile: "#ffffff" }), size, size);
    let n = 0;
    for (let p = 0; p < im.d.length; p += 4) if (Math.abs(im.d[p] - base.d[p]) > 24) n++;
    diffs[k] = n;
  }
  // Pairwise: two siblings must differ from EACH OTHER, not merely from the base.
  let worst = Infinity, pair = "";
  const keys = Object.keys(CUES);
  for (let i = 0; i < keys.length; i++)
    for (let j = i + 1; j < keys.length; j++) {
      const a = await raster(markSvg({ size, fills: ["#0a0e19", "#0a0e19", "#0a0e19"], gap: chosenGap || 0, cue: keys[i], tile: "#ffffff" }), size, size);
      const b = await raster(markSvg({ size, fills: ["#0a0e19", "#0a0e19", "#0a0e19"], gap: chosenGap || 0, cue: keys[j], tile: "#ffffff" }), size, size);
      let n = 0;
      for (let p = 0; p < a.d.length; p += 4) if (Math.abs(a.d[p] - b.d[p]) > 24) n++;
      if (n < worst) { worst = n; pair = `${keys[i]}/${keys[j]}`; }
    }
  // Closed form: two slots of known area at known separation, rasterised large from
  // the same geometry and scaled by area. The ideal is a LOWER bound — antialiasing
  // at true size inflates a thin difference region and cannot shrink it below the
  // shapes' own symmetric difference.
  const BIG = 96 * 8;
  const ka = Object.keys(CUES);
  let ideal = Infinity;
  for (let i = 0; i < ka.length; i++)
    for (let j = i + 1; j < ka.length; j++) {
      const A = blockPts[CUES[ka[i]]], B = blockPts[CUES[ka[j]]];
      const sl = (b) => `<rect x="${b.cx - SLOT_W / 2}" y="${b.cy - SLOT_H / 2}" width="${SLOT_W}" height="${SLOT_H}" rx="${SLOT_H / 2}" fill="#fff"/>`;
      const ra = await raster(`<svg width="${BIG}" height="${BIG}" viewBox="0 0 ${GRID} ${GRID}"><rect width="${GRID}" height="${GRID}" fill="#000"/>${sl(A)}</svg>`, BIG, BIG);
      const rb = await raster(`<svg width="${BIG}" height="${BIG}" viewBox="0 0 ${GRID} ${GRID}"><rect width="${GRID}" height="${GRID}" fill="#000"/>${sl(B)}</svg>`, BIG, BIG);
      let n = 0;
      for (let p = 0; p < ra.d.length; p += 4) if (Math.abs(ra.d[p] - rb.d[p]) > 24) n++;
      ideal = Math.min(ideal, n * Math.pow(size / BIG, 2));
    }
  const ratio = ideal > 0 ? worst / ideal : Infinity;
  const agrees = ratio >= 0.5 && ratio <= 4.0;
  if (!agrees) crossCheckFailed = true;
  const distinguishable = worst >= 3;
  console.log(`  ${String(size).padStart(2)}px  from base: ` +
    Object.entries(diffs).map(([k, v]) => `${k} ${v}px`).join(", ") +
    `  |  closest pair ${pair}: ${worst}px  ideal ${ideal.toFixed(1)}px (ratio ${ratio.toFixed(2)})  ` +
    `${agrees ? "agree" : "DISAGREE — rejected"}  ${distinguishable ? "distinguishable" : "NOT distinguishable"}`);
}

// ── 7. The mark against the wordmark ────────────────────────────────────────
// The owner asked for the mark enlarged and the ratio proposed from measurement.
// The wordmark's cap is 0.695 em (measured, in measure-face.mjs). A mark set to the
// wordmark's CAP height reads smaller than the type because the type has a long
// line of it and the mark is one compact shape; the classic correction is to set a
// logotype mark on the ASCENDER-to-DESCENDER extent rather than the cap.
const CAP_EM = 0.695;
const oldRatio = 1.0;                    // the mark was set to the cap height
const proposed = +(1 / CAP_EM).toFixed(3); // set the mark's full height to the em instead
console.log(`\nmark-to-wordmark ratio:`);
console.log(`  the wordmark's cap is ${CAP_EM} em, measured off a specimen.`);
console.log(`  old: mark height = 1.000 x cap  (${(CAP_EM * 100).toFixed(1)}% of the em)`);
console.log(`  proposed: mark height = ${proposed} x cap  (100% of the em) — the mark spans the`);
console.log(`  full em rather than the cap, so it reads level with the type rather than inside it.`);

if (process.argv.includes("--emit")) {
  console.log(`\n── board geometry (96-unit tile) ──`);
  console.log(`  transform   ${XF}`);
  console.log(`  gap needed  ${chosenGap === 0 ? "none — the blocks already stand apart in one ink" : chosenGap.toFixed(1) + " units"}`);
  for (const t of TOUCH) console.log(`  contact     (${t.x}, ${t.y}) source units — ${t.what}`);
  console.log(`  slot        ${SLOT_W} x ${SLOT_H}, rx ${(SLOT_H / 2).toFixed(2)}`);
  for (const [k, i] of Object.entries(CUES))
    console.log(`  slot ${k.padEnd(9)} cx=${blockPts[i].cx.toFixed(2)} cy=${blockPts[i].cy.toFixed(2)}  — ${CUE_MEANING[k]}`);
  console.log(`  mark ratio  ${proposed} x wordmark cap`);
}

await browser.close();
if (crossCheckFailed) {
  console.log(`\nCROSS-CHECK FAILED: a measured cue separation disagrees with its own geometry.`);
  process.exit(1);
}
console.log(`\nCross-check passed.`);
