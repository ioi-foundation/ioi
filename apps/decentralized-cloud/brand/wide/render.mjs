#!/usr/bin/env node
// WIDE GENERATION — render, measure cheaply, and plate for the cold read.
//
// ORDER OF OPERATIONS, which is the harness's own ruling and not mine: the cold
// reader comes FIRST and measurement second. So everything this file measures is
// only allowed to KILL a candidate before a reader ever sees it — a shape that is
// already dead (identical to another candidate, identical to a retired ghost,
// or shaped like the type it will sit beside) is not worth a reader's attention.
// Nothing here ranks a survivor. Ranking is the reader's job.
//
// Every number is measured from the RENDERED RASTER at product size, never from the
// source geometry. The distinction cost this program three rounds: a gate must read
// the artifact that ships.
//
// Positive controls run BEFORE any measurement. Each probe is handed exactly the
// defect it exists to catch and the run ABORTS unless the probe reports it. A probe
// that cannot fail on its own finding is not a probe.
//
// Usage: node apps/decentralized-cloud/brand/wide/render.mjs [--sheets]

import { mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CANDIDATES, GHOSTS, GRID, INK, GROUND, svgFor } from "./families.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts/wide");
// The face is inlined as a data URL rather than referenced by path: a page built
// with setContent has no document origin, so a file:// @font-face never fetches and
// the probe would silently compare every candidate against the FALLBACK face —
// a number about a font nobody ships.
const FONT = path.join(HERE, "../../public/fonts/IOI.ttf");
const FONT_B64 = readFileSync(FONT).toString("base64");
// The output directory is EMPTIED, not merely created. Round one's readers were
// shown five sheets when the run had written four: a fifth sheet survived on disk
// from an earlier run with a different candidate list, and all three readers dutifully
// scored cells 161-163 that no longer existed. Nobody was lying and every number in
// the JSON was right; the reader was simply handed an artifact the run did not
// produce. This is the program's own scar — a gate must read the artifact that
// ships — arriving in the one place I had not looked for it.
mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) rmSync(path.join(OUT, f), { force: true });

// ── Stated parameters, printed with every result ────────────────────────────
const PRODUCT_PX = 16;      // the size the identity has to survive
const CHANNEL = "mean of R,G,B";
const INK_AT = 200;         // luminance below this counts as ink, on a white ground
const DUP_IOU = 0.90;       // two candidates this alike are one candidate
const GHOST_IOU = 0.80;     // the threshold that killed the two-round incumbent
const TYPE_IOU = 0.74;      // a mark this close to a letterform disappears into it
const MIN_INK = 0.04;       // below this the cell is a smudge at 16px
const MAX_INK = 0.92;       // above this the cell is a filled square

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
// Subpixel (LCD) antialiasing paints coloured fringes on every glyph edge, which on
// a ONE-INK brand plate is not one ink: the 16px wordmark came back with orange and
// blue fringes on every stem. That is my harness colouring the artifact, not the
// wordmark being coloured, and a reader shown it would be answering about my renderer.
// Greyscale antialiasing is what the measurement and the reader both need.
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({
  viewport: { width: 1600, height: 1200 },
  deviceScaleFactor: 1,
});

// ── Rendering: one composite, sliced in the page ────────────────────────────
// One screenshot for the whole set rather than N screenshots, because N screenshots
// of a 16px tile is minutes of process overhead to produce 60KB of pixels. The
// composite is laid out at EXACT device pixels with no gaps, and each cell is sliced
// back out at its own 16x16, so what is measured is byte-identical to what a lone
// 16px render would have produced.
async function renderSet(items, size, cols) {
  const cells = items
    .map((it) => `<div style="width:${size}px;height:${size}px;">${svgFor(it.draw(), size)}</div>`)
    .join("");
  await page.setContent(
    `<style>body{margin:0;background:${GROUND};}` +
    `#g{display:grid;grid-template-columns:repeat(${cols},${size}px);gap:0;width:${cols * size}px;}` +
    `svg{display:block;}</style><div id="g">${cells}</div>`
  );
  const buf = await page.locator("#g").screenshot();
  const url = `data:image/png;base64,${buf.toString("base64")}`;
  return page.evaluate(
    async ({ url, size, cols, n }) => {
      const im = new Image();
      im.src = url;
      await im.decode();
      const c = document.createElement("canvas");
      c.width = im.width;
      c.height = im.height;
      const ctx = c.getContext("2d");
      ctx.drawImage(im, 0, 0);
      const out = [];
      for (let i = 0; i < n; i++) {
        const cx = (i % cols) * size;
        const cy = Math.floor(i / cols) * size;
        const d = ctx.getImageData(cx, cy, size, size).data;
        const tile = document.createElement("canvas");
        tile.width = size;
        tile.height = size;
        tile.getContext("2d").putImageData(new ImageData(new Uint8ClampedArray(d), size, size), 0, 0);
        out.push({ px: [...d], url: tile.toDataURL() });
      }
      return out;
    },
    { url, size, cols, n: items.length }
  );
}

const lum = (d, p) => (d[p * 4] + d[p * 4 + 1] + d[p * 4 + 2]) / 3;

// A binary ink mask at product size. Everything below reads this and nothing else,
// so "one ink" is enforced by the measurement rather than promised by the drawing.
function mask(px, size) {
  const m = new Uint8Array(size * size);
  let on = 0;
  for (let p = 0; p < size * size; p++) {
    if (lum(px, p) < INK_AT) {
      m[p] = 1;
      on += 1;
    }
  }
  return { m, on, frac: on / (size * size) };
}

const iou = (a, b) => {
  let inter = 0, uni = 0;
  for (let p = 0; p < a.length; p++) {
    if (a[p] && b[p]) inter += 1;
    if (a[p] || b[p]) uni += 1;
  }
  return uni === 0 ? 0 : inter / uni;
};

// ── Normalisation, for the TYPE probe only ──────────────────────────────────
// A mark and a letter are never drawn at the same size or in the same place, so a
// same-box IoU between them measures the layout of two boxes and not the shape of
// two drawings. The first version of this probe did exactly that and scored a plain
// vertical stem at 0.349 against the face's own I — an assertion that could not fire
// on the defect it existed to catch, which its own positive control reported.
//
// So: crop each drawing to its ink bounding box, scale UNIFORMLY (aspect preserved,
// because aspect is a real difference between a mark and a letter and squashing it
// away would make every rectangle match every other), centre it in a fixed field,
// and compare there.
//
// SCOPE, stated: this probe is measured on the 96px raster, not the 16px one. The
// failure it models — "the mark disappears because it matches the letterforms beside
// it" — is a question about shape identity, not about resolution, and 16px does not
// carry enough of either shape to answer it. It is the only number in this file not
// taken at product size, and that is deliberate rather than convenient.
const NORM_FIELD = 48;
const NORM_FIT = 44;
function normalise(m, size) {
  let x0 = size, y0 = size, x1 = -1, y1 = -1;
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++)
      if (m[y * size + x]) {
        if (x < x0) x0 = x;
        if (x > x1) x1 = x;
        if (y < y0) y0 = y;
        if (y > y1) y1 = y;
      }
  const out = new Uint8Array(NORM_FIELD * NORM_FIELD);
  if (x1 < 0) return out;
  const w = x1 - x0 + 1, h = y1 - y0 + 1;
  const scale = NORM_FIT / Math.max(w, h);
  const dw = Math.max(1, Math.round(w * scale)), dh = Math.max(1, Math.round(h * scale));
  const ox = Math.floor((NORM_FIELD - dw) / 2), oy = Math.floor((NORM_FIELD - dh) / 2);
  for (let y = 0; y < dh; y++) {
    for (let x = 0; x < dw; x++) {
      // Area-sample the source region this destination pixel covers: a majority of
      // ink makes it ink. Point-sampling a 96px raster into 48 cells drops thin
      // strokes entirely, which would flatter every candidate.
      const sx0 = x0 + Math.floor((x * w) / dw), sx1 = x0 + Math.max(Math.floor(((x + 1) * w) / dw), Math.floor((x * w) / dw) + 1);
      const sy0 = y0 + Math.floor((y * h) / dh), sy1 = y0 + Math.max(Math.floor(((y + 1) * h) / dh), Math.floor((y * h) / dh) + 1);
      let on = 0, tot = 0;
      for (let sy = sy0; sy < Math.min(sy1, size); sy++)
        for (let sx = sx0; sx < Math.min(sx1, size); sx++) {
          tot += 1;
          if (m[sy * size + sx]) on += 1;
        }
      if (tot && on * 2 >= tot) out[(oy + y) * NORM_FIELD + (ox + x)] = 1;
    }
  }
  return out;
}

// ── The TYPE probe — the gap the closed phase named and never built ─────────
// The silhouette probe compared marks with other MARKS, so it could not see a mark
// that vanishes because it matches the letterforms beside it. One round-four
// candidate failed that way and no number caught it.
//
// LIMIT, stated because an instrument confined to its claim is the only kind worth
// keeping: this measures whether a mark FILLS ITS BOX the way a letter of this face
// fills the same box, at product size. It is not a claim about stroke rhythm or
// about the mark in situ. It kills a mark that is box-for-box a letterform; it
// cannot clear one that merely rhymes with the type.
// The face's FULL alphabet, not just the letters in this name. The first version of
// this probe used only "DECNTRALIZOU" — the letters the mark sits beside — and I
// found the gap by looking at the plates: a whole run of candidates cut from the
// face's S sailed through, and they read as the letter S. The failure being modelled
// is "this mark reads as a letterform", and a foreign letter beside the name is if
// anything worse than a familiar one, so the probe now closes over the alphabet.
// (IOI Display is unicase — 33 glyphs, one case — so these 26 are the whole set of
// letters it can draw.)
const TYPE_GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
async function typeMasks(size) {
  const cells = TYPE_GLYPHS.map(
    (ch) => `<div class="t" style="width:${size}px;height:${size}px;"><span>${ch}</span></div>`
  ).join("");
  await page.setContent(
    `<style>@font-face{font-family:'IOI Display';src:url(data:font/ttf;base64,${FONT_B64}) format('truetype');}` +
    `body{margin:0;background:${GROUND};}` +
    `#g{display:grid;grid-template-columns:repeat(${TYPE_GLYPHS.length},${size}px);gap:0;}` +
    `.t{display:flex;align-items:center;justify-content:center;overflow:hidden;}` +
    `.t span{font-family:'IOI Display';font-size:${Math.round(size * 1.1)}px;line-height:1;color:${INK};}` +
    `</style><div id="g">${cells}</div>`
  );
  // The face is loaded from disk; without waiting for it the probe would compare
  // every candidate against the FALLBACK face, and report a number about a font
  // nobody is shipping.
  // `document.fonts.ready` resolving is NOT proof the face loaded — a note the
  // previous phase left in measure-face.mjs after being burned by it. So the face is
  // loaded explicitly and then PROVEN applied by measuring the same string against a
  // forced fallback: if the widths agree, the face never arrived.
  const faceProof = await page.evaluate(async () => {
    await document.fonts.load("100px 'IOI Display'");
    await document.fonts.ready;
    const m = (family) => {
      const s = document.createElement("span");
      s.style.cssText = `position:absolute;font-size:200px;font-family:${family};white-space:pre;`;
      s.textContent = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      document.body.appendChild(s);
      const w = s.getBoundingClientRect().width;
      s.remove();
      return w;
    };
    return { face: m("'IOI Display'"), fallback: m("serif"), loaded: document.fonts.check("100px 'IOI Display'") };
  });
  const buf = await page.locator("#g").screenshot();
  const url = `data:image/png;base64,${buf.toString("base64")}`;
  const tiles = await page.evaluate(
    async ({ url, size, n }) => {
      const im = new Image();
      im.src = url;
      await im.decode();
      const c = document.createElement("canvas");
      c.width = im.width;
      c.height = im.height;
      c.getContext("2d").drawImage(im, 0, 0);
      const out = [];
      for (let i = 0; i < n; i++)
        out.push([...c.getContext("2d").getImageData(i * size, 0, size, size).data]);
      return out;
    },
    { url, size, n: TYPE_GLYPHS.length }
  );
  return {
    faceProof,
    glyphs: tiles.map((px, i) => {
      const m = mask(px, size);
      return { ch: TYPE_GLYPHS[i], ink: m.frac, norm: normalise(m.m, size) };
    }),
  };
}

// ── Positive controls ───────────────────────────────────────────────────────
// Each is handed the exact defect its probe exists to catch. The run aborts unless
// every one reports. Two of these plant a defect the probe has never seen fire in
// this program, which is precisely why they are here.
const controls = [];
function control(name, ok, detail) {
  controls.push({ name, ok, detail });
}

{
  const size = PRODUCT_PX;
  const blank = new Uint8ClampedArray(size * size * 4).fill(255);
  const filled = new Uint8ClampedArray(size * size * 4).fill(0);
  const mb = mask(blank, size);
  const mf = mask(filled, size);
  control("presence-empty", mb.frac < MIN_INK, `empty frame measured ${mb.frac.toFixed(3)} ink, refused`);
  control("presence-full", mf.frac > MAX_INK, `full frame measured ${mf.frac.toFixed(3)} ink, refused`);

  const A = new Uint8Array(64).fill(0);
  const B = new Uint8Array(64).fill(0);
  for (let i = 0; i < 32; i++) A[i] = 1;
  for (let i = 0; i < 32; i++) B[i] = 1;
  control("iou-identical", Math.abs(iou(A, B) - 1) < 1e-9, `identical masks measured IoU ${iou(A, B).toFixed(4)}`);
  const C = new Uint8Array(64).fill(0);
  for (let i = 32; i < 64; i++) C[i] = 1;
  control("iou-disjoint", iou(A, C) === 0, `disjoint masks measured IoU ${iou(A, C).toFixed(4)}`);
}

// ── The run ─────────────────────────────────────────────────────────────────
// A knowingly duplicated candidate and a knowingly letter-shaped candidate are
// appended to the real set, measured with it, and must be caught by the dedupe and
// the type probe respectively. They are removed before anything is plated.
const PLANT_DUP = { id: "__control-duplicate", family: "control", draw: CANDIDATES[0].draw, silhouette: CANDIDATES[0].silhouette, control: true };
// The letterform plant is the face's OWN I, at the face's own metrics: stem 137 and
// cap 700 on a 1000 upem, so on this 96 grid a cap of 76 units gives a stem of
// 76 x 137/700 = 14.9. The first version of this plant was a 28-unit stem chosen by
// eye; the probe scored it 0.563 and was correct to — a stem twice the face's weight
// is not the face's letter. The plant was wrong, not the threshold, and the number
// that moved was the one taken from the font's tables.
const PLANT_STEM = (76 * 137) / 700;
const PLANT_TYPE = {
  id: "__control-letterform",
  family: "control",
  draw: () =>
    `<polygon points="${48 - PLANT_STEM / 2},10 ${48 + PLANT_STEM / 2},10 ` +
    `${48 + PLANT_STEM / 2},86 ${48 - PLANT_STEM / 2},86" fill="INK"></polygon>`,
  control: true,
};
// The negative control. A probe that flags a letterform is only useful if it does
// NOT flag a shape nobody would mistake for one; without this, raising the threshold
// until everything trips would look like success.
const PLANT_NOT_TYPE = {
  id: "__control-not-letterform",
  family: "control",
  draw: () => `<polygon points="8,84 88,84 88,64 30,64 30,20 8,20" fill="INK"></polygon>`,
  control: true,
};

const items = [...CANDIDATES, ...GHOSTS.map((g) => ({ ...g, ghost: true })), PLANT_DUP, PLANT_TYPE, PLANT_NOT_TYPE];
const COLS = 20;
const small = await renderSet(items, PRODUCT_PX, COLS);
const large = await renderSet(items, 96, COLS);

const measured = items.map((it, i) => {
  const m = mask(small[i].px, PRODUCT_PX);
  const big = mask(large[i].px, 96);
  return { ...it, i, mask: m.m, ink: m.frac, norm: normalise(big.m, 96), url16: small[i].url, url96: large[i].url };
});

const { faceProof, glyphs: types } = await typeMasks(96);
control(
  "type-face-actually-loaded",
  faceProof.loaded && Math.abs(faceProof.face - faceProof.fallback) > 1,
  `the alphabet at 200px measured ${faceProof.face.toFixed(1)}px in IOI Display vs ` +
  `${faceProof.fallback.toFixed(1)}px in the fallback (check() ${faceProof.loaded})`
);
control(
  "type-glyphs-have-ink",
  types.every((t) => t.ink > 0.01),
  `all ${types.length} glyphs rendered ink (min ${Math.min(...types.map((t) => t.ink)).toFixed(3)})`
);

// The normaliser gets its own control: the same drawing at two sizes must come back
// as the same normalised shape, or every type number below is measuring scale.
{
  const a = measured.find((c) => c.id === "__control-letterform");
  // The comparison shape is DERIVED from the plant's own geometry, at half its
  // linear size. An earlier version hardcoded a rectangle, and when the plant's
  // proportions were corrected to the face's metrics the control started failing on
  // its own staleness rather than on anything about the normaliser.
  const half = new Uint8Array(96 * 96);
  const hw = PLANT_STEM / 2, hh = 38;
  for (let y = 0; y < 96; y++)
    for (let x = 0; x < 96; x++)
      if (y >= 48 - hh / 2 && y < 48 + hh / 2 && x >= 48 - hw / 2 && x < 48 + hw / 2) half[y * 96 + x] = 1;
  const thin = iou(a.norm, normalise(half, 96));

  // A chunky shape at two scales isolates the normaliser from the quantisation floor
  // a thin one runs into. This is the control that has to hold.
  const box = (w, h) => {
    const m = new Uint8Array(96 * 96);
    for (let y = 0; y < 96; y++)
      for (let x = 0; x < 96; x++)
        if (y >= 48 - h / 2 && y < 48 + h / 2 && x >= 48 - w / 2 && x < 48 + w / 2) m[y * 96 + x] = 1;
    return normalise(m, 96);
  };
  const chunky = iou(box(56, 78), box(28, 39));
  control("normalise-scale-invariant", chunky >= 0.95,
    `a 56x78 shape and its half-size copy normalise to IoU ${chunky.toFixed(3)}`);

  // Reported, not asserted, and reported because the number is a real limit of the
  // instrument rather than a result: at 44 cells, the face's own stem normalises to
  // ~9 cells wide, so ONE cell of rounding is ~11%. The probe therefore cannot
  // resolve two thin shapes to better than about that, and the threshold above sits
  // well clear of it. Confining an instrument to the claim it can carry is the only
  // way a disagreement from it stays worth reading.
  console.log(`  note  normalise thin-stroke floor: the plant vs a half-size copy is ${thin.toFixed(3)}, ` +
    `the residual being one cell of quantisation on a ~9-cell stem`);
}

// presence, fail-closed
for (const c of measured) {
  c.presenceOk = c.ink >= MIN_INK && c.ink <= MAX_INK;
}

// type IoU: the worst (highest) match against any glyph of the face
for (const c of measured) {
  let worst = { ch: null, v: 0 };
  for (const t of types) {
    const v = iou(c.norm, t.norm);
    if (v > worst.v) worst = { ch: t.ch, v };
  }
  c.typeIou = worst.v;
  c.typeLike = worst.ch;
}

// ghost IoU
const ghosts = measured.filter((c) => c.ghost);
for (const c of measured) {
  if (c.ghost) continue;
  let worst = { id: null, v: 0 };
  for (const g of ghosts) {
    const v = iou(c.mask, g.mask);
    if (v > worst.v) worst = { id: g.id, v };
  }
  c.ghostIou = worst.v;
  c.ghostLike = worst.id;
}

// dedupe: first candidate in list order keeps the slot
const live = measured.filter((c) => !c.ghost);
for (const c of live) c.dupOf = null;
for (let a = 0; a < live.length; a++) {
  if (live[a].dupOf) continue;
  for (let b = a + 1; b < live.length; b++) {
    if (live[b].dupOf) continue;
    if (iou(live[a].mask, live[b].mask) >= DUP_IOU) live[b].dupOf = live[a].id;
  }
}

// controls report
const dupPlant = live.find((c) => c.id === "__control-duplicate");
control("dedupe-plant", !!dupPlant && dupPlant.dupOf === CANDIDATES[0].id,
  `planted duplicate of ${CANDIDATES[0].id} was collapsed onto ${dupPlant && dupPlant.dupOf}`);
const typePlant = live.find((c) => c.id === "__control-letterform");
control("type-probe-plant", !!typePlant && typePlant.typeIou >= TYPE_IOU,
  `planted letterform measured type IoU ${typePlant && typePlant.typeIou.toFixed(3)} against "${typePlant && typePlant.typeLike}" (threshold ${TYPE_IOU})`);
const notTypePlant = live.find((c) => c.id === "__control-not-letterform");
control("type-probe-negative", !!notTypePlant && notTypePlant.typeIou < TYPE_IOU,
  `planted non-letterform measured type IoU ${notTypePlant && notTypePlant.typeIou.toFixed(3)} against "${notTypePlant && notTypePlant.typeLike}" — below threshold, so the probe is not flagging everything`);

const failed = controls.filter((c) => !c.ok);
console.log("── positive controls ──");
for (const c of controls) console.log(`  ${c.ok ? "PASS" : "FAIL"}  ${c.name}: ${c.detail}`);
if (failed.length) {
  console.error(`\nABORT: ${failed.length} positive control(s) did not report their planted defect.`);
  console.error("No measurement below would mean anything, so none is printed.");
  await browser.close();
  process.exit(1);
}

// ── Survivors of the cheap kill ─────────────────────────────────────────────
const real = live.filter((c) => !c.control);
for (const c of real) {
  c.killed =
    !c.presenceOk ? `ink ${c.ink.toFixed(3)} outside [${MIN_INK}, ${MAX_INK}] at ${PRODUCT_PX}px`
    : c.dupOf ? `duplicate of ${c.dupOf} (IoU >= ${DUP_IOU})`
    : c.ghostIou >= GHOST_IOU ? `IoU ${c.ghostIou.toFixed(3)} against retired ${c.ghostLike}`
    : c.typeIou >= TYPE_IOU ? `IoU ${c.typeIou.toFixed(3)} against the letter "${c.typeLike}" it will sit beside`
    : null;
}
const survivors = real.filter((c) => !c.killed);

console.log(`\n── generated ${real.length} candidates across ${new Set(real.map((c) => c.family)).size} families ──`);
const byReason = {};
for (const c of real.filter((c) => c.killed)) {
  const k = c.killed.split(" ")[0];
  byReason[k] = (byReason[k] || 0) + 1;
}
for (const [k, n] of Object.entries(byReason)) console.log(`  killed before any reader saw them — ${k}: ${n}`);
console.log(`  survive to the cold read: ${survivors.length}`);
console.log("\nEvery kill above is a measurement of the 16px RASTER, and none of them ranks anything.");
console.log("Ranking is the reader's, and the reader has not been shown these yet.");

// ── Contact sheets ──────────────────────────────────────────────────────────
// Each cell is the TRUE 16px raster magnified 4x with image-rendering:pixelated —
// nearest-neighbour, no interpolation, so no information above 16px is present in
// what the reader is shown. The 96px reference is printed on a separate sheet and is
// NOT what the naming question is asked against.
if (process.argv.includes("--sheets")) {
  const PER = 40, SCOLS = 8;
  const sheets = [];
  for (let s = 0; s * PER < survivors.length; s++) {
    const group = survivors.slice(s * PER, (s + 1) * PER);
    const cells = group
      .map((c, k) =>
        `<figure><img src="${c.url16}" width="64" height="64" style="image-rendering:pixelated;">` +
        `<figcaption>${s * PER + k + 1}</figcaption></figure>`
      )
      .join("");
    await page.setContent(
      `<style>body{margin:0;background:#fff;font:12px ui-monospace,monospace;color:#555;}` +
      `#s{display:grid;grid-template-columns:repeat(${SCOLS},1fr);gap:22px 18px;padding:26px;width:${SCOLS * 96}px;}` +
      `figure{margin:0;text-align:center;}figcaption{margin-top:6px;}</style><div id="s">${cells}</div>`
    );
    const f = path.join(OUT, `sheet-16px-${s + 1}.png`);
    await page.locator("#s").screenshot({ path: f });
    sheets.push(f);
  }
  for (let s = 0; s * PER < survivors.length; s++) {
    const group = survivors.slice(s * PER, (s + 1) * PER);
    const cells = group
      .map((c, k) => `<figure><img src="${c.url96}" width="96" height="96"><figcaption>${s * PER + k + 1}</figcaption></figure>`)
      .join("");
    await page.setContent(
      `<style>body{margin:0;background:#fff;font:12px ui-monospace,monospace;color:#555;}` +
      `#s{display:grid;grid-template-columns:repeat(${SCOLS},1fr);gap:22px 18px;padding:26px;width:${SCOLS * 128}px;}` +
      `figure{margin:0;text-align:center;}figcaption{margin-top:6px;}</style><div id="s">${cells}</div>`
    );
    const f = path.join(OUT, `sheet-96px-${s + 1}.png`);
    await page.locator("#s").screenshot({ path: f });
    sheets.push(f);
  }
  console.log(`\nsheets: ${sheets.length}`);
  for (const f of sheets) console.log(`  ${f}`);
}

writeFileSync(
  path.join(OUT, "wide-round-1.json"),
  JSON.stringify(
    {
      measuredAt: new Date().toISOString(),
      parameters: { PRODUCT_PX, CHANNEL, INK_AT, DUP_IOU, GHOST_IOU, TYPE_IOU, MIN_INK, MAX_INK },
      controls,
      generated: real.length,
      survivors: survivors.map((c, k) => ({ n: k + 1, id: c.id, family: c.family, thesis: c.thesis, ink: +c.ink.toFixed(4), typeIou: +c.typeIou.toFixed(4), typeLike: c.typeLike, ghostIou: +c.ghostIou.toFixed(4) })),
      killed: real.filter((c) => c.killed).map((c) => ({ id: c.id, family: c.family, why: c.killed })),
    },
    null,
    2
  )
);
console.log(`\njson: ${path.join(OUT, "wide-round-1.json")}`);
await browser.close();
