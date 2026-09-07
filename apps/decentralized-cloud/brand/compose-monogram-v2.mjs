#!/usr/bin/env node
// Round four: the three bounded moves on the monogram, each derived rather than
// placed by eye, and each refused if the measurement does not hold.
//
// WHAT CHANGED AND WHY
//
// (a) THE CUE IS A SHAPE, NOT A POSITION. The previous cue was one tick in three
//     horizontal slots. Side by side you could tell the siblings apart; alone in a
//     dock you could not name which one you had, because an index position carries
//     no meaning. The cue here is ONE capsule — the same drawing, cut to the
//     letter's own stroke — at three ORIENTATIONS about the counter's centre:
//       .cloud     flat      a lane: work routed sideways across venues
//       .exchange  upright   a post: standing between two sides
//       .trade     leaning   a slope: a price that moves
//     Orientation survives small sizes better than subdivision does, and because
//     all three are one shape rotated, the base stays byte-identical.
//
// (b) THE PERIOD IS SET ON OPTICAL BEARING, MEASURED AT ITS OWN HEIGHT. The old
//     board claimed a nominal cap/9 bearing "holds throughout". It does not: cap/9
//     is a distance between BOUNDING BOXES, taken at the letter's widest row, and
//     the period sits about twenty units below that row where the letter's ink has
//     already fallen back. The real gap there was ~3x the claim. Here the letter's
//     right edge is measured ON THE PERIOD'S OWN ROWS, and the gap is set to the
//     face's own optical letter gap — measured off the face by rendering a letter
//     pair and finding the tightest row — so the period is spaced like the type
//     rather than like a rectangle.
//
// (c) THE TILE'S SIDE MARGINS ARE OPENED AS FAR AS THE SMALL SIZES ALLOW. Opening
//     them costs cap height, and cap height is what keeps the period and the cue
//     alive at 16px — an earlier draft at 45% fill produced a faint period and a
//     sub-pixel tick. That is a real tension, so the size is not chosen: it is
//     SWEPT. The script walks the font size down, runs the full 16px battery at
//     each step, and reports the largest margin that still passes everything. The
//     frontier is printed, so the number on the board is the edge of what holds.
//
// Usage: node compose-monogram-v2.mjs [--sweep] [--emit] [fontSize]

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");
const b64 = readFileSync(path.join(REPO, "packages/design-system/assets/fonts/IOI.ttf")).toString("base64");

const GRID = 96;
const SIZES = [16, 24, 32];
const S = 10; // 10x the tile, so one tile unit is ten device pixels
const ORIENTATIONS = { cloud: 90, exchange: 0, trade: 45 };

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 500 }, deviceScaleFactor: 1 });

const FONT_CSS = `@font-face { font-family: "IOI Display"; src: url(data:font/ttf;base64,${b64}) format("truetype"); font-weight: 400; }`;

// ── 0. Load the face, and refuse to measure a fallback ──────────────────────
await page.setContent(`<style>${FONT_CSS}</style><div style="font-family:'IOI Display';font-size:20px">d</div>`);
await page.evaluate(() => document.fonts.ready);
await page.evaluate(() => document.fonts.load(`100px "IOI Display"`));
const faceLoaded = await page.evaluate(() => document.fonts.check(`100px "IOI Display"`));
if (!faceLoaded) {
  console.error("REFUSING TO MEASURE: IOI Display did not load; every number below would describe a fallback face.");
  await browser.close();
  process.exit(1);
}

// ── 1. The face's own optical letter gap ────────────────────────────────────
// Rendered as a pair and scanned row by row: the tightest horizontal gap between
// the two glyphs' ink is what this face considers "adjacent". That is the gap a
// period must sit at to read as punctuation rather than as a detached speck.
// It is a property of the TYPE, measured here, not a rule invented for the mark.
const opticalGapPx = await page.evaluate(async ({ css, s }) => {
  const c = document.createElement("canvas");
  c.width = 1400; c.height = 400;
  const x = c.getContext("2d");
  x.fillStyle = "#fff"; x.fillRect(0, 0, c.width, c.height);
  x.fillStyle = "#000";
  x.font = `${10 * s}px "IOI Display"`;
  x.textBaseline = "alphabetic";
  x.fillText("dd", 50, 300);
  const d = x.getImageData(0, 0, c.width, c.height).data;
  const ink = (px, py) => d[(py * c.width + px) * 4] < 128;
  let best = Infinity;
  for (let py = 0; py < c.height; py++) {
    const runs = []; let run = null;
    for (let px = 0; px < c.width; px++) {
      if (ink(px, py)) { if (!run) run = { a: px, b: px }; else run.b = px; }
      else if (run) { runs.push(run); run = null; }
    }
    if (run) runs.push(run);
    for (let k = 1; k < runs.length; k++) best = Math.min(best, runs[k].a - runs[k - 1].b - 1);
  }
  return best === Infinity ? null : best;
}, { css: FONT_CSS, s: S });

if (opticalGapPx === null) {
  console.error("REFUSING TO MEASURE: could not find two ink runs in a letter pair.");
  await browser.close();
  process.exit(1);
}
// Measured at font-size 10*S; express as a fraction of the em so it scales.
const gapPerEm = opticalGapPx / (10 * S);
console.log(`the face's own optical letter gap, scanned across a letter pair:`);
console.log(`  ${opticalGapPx}px at ${10 * S}px em  =  ${gapPerEm.toFixed(4)} em`);

// ── 2. Compose at a given font size, measuring the letter at the PERIOD's rows ──
async function compose(FONT) {
  const g = await page.evaluate(async ({ font, s }) => {
    const c = document.createElement("canvas");
    c.width = 1200; c.height = 600;
    const x = c.getContext("2d");
    x.fillStyle = "#fff"; x.fillRect(0, 0, c.width, c.height);
    x.fillStyle = "#000";
    x.font = `${font * s}px "IOI Display"`;
    x.textBaseline = "alphabetic";
    const penX = 50, penY = 500;
    x.fillText("d", penX, penY);
    const d = x.getImageData(0, 0, c.width, c.height).data;
    const ink = (px, py) => d[(py * c.width + px) * 4] < 128;
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    for (let py = 0; py < c.height; py++)
      for (let px = 0; px < c.width; px++)
        if (ink(px, py)) {
          if (px < x0) x0 = px; if (px > x1) x1 = px;
          if (py < y0) y0 = py; if (py > y1) y1 = py;
        }
    // The stem: the widest solid horizontal run on the row halfway up the cap.
    const mid = Math.round((y0 + y1) / 2);
    let stem = 0, run = 0;
    for (let px = 0; px < c.width; px++) {
      if (ink(px, mid)) { run++; stem = Math.max(stem, run); } else run = 0;
    }
    // rightEdgeAtRow: how far the letter's ink actually reaches on a given row.
    const rightEdgeAtRow = (py) => {
      for (let px = c.width - 1; px >= 0; px--) if (ink(px, py)) return px;
      return null;
    };
    return { x0, x1, y0, y1, stem, penX, penY, rightEdgeAtRow: null,
             rows: Array.from({ length: c.height }, (_, py) => rightEdgeAtRow(py)) };
  }, { font: FONT, s: S });

  const u = (v) => v / S;
  const inkW = u(g.x1 - g.x0 + 1);
  const cap = u(g.y1 - g.y0 + 1);
  const stroke = u(g.stem);
  const leftBearing = u(g.x0) - u(g.penX);
  const periodD = stroke;

  // The period is centred on the baseline, its top at baseline - periodD.
  // Its rows in the measurement raster, relative to the pen baseline:
  const opticalGap = gapPerEm * FONT;

  // Where does the letter's ink actually reach across the period's own rows?
  // Take the furthest right edge over the band the period occupies, so the gap is
  // the true closest approach, not an average.
  const bandTop = Math.round(g.penY - periodD * S);
  const bandBot = Math.round(g.penY);
  let reach = -Infinity;
  for (let py = bandTop; py <= bandBot; py++) {
    const e = g.rows[py];
    if (e !== null && e > reach) reach = e;
  }
  const letterReachAtPeriod = u(reach) - u(g.penX); // relative to the pen
  const inkLeftRel = u(g.x0) - u(g.penX);

  // Compose so the closest approach equals the face's optical gap.
  const markLeft = inkLeftRel;
  const periodLeftRel = letterReachAtPeriod + opticalGap;
  const markRight = periodLeftRel + periodD;
  const totalW = markRight - markLeft;
  const inkX = (GRID - totalW) / 2;
  const penXTile = inkX - markLeft;
  const baselineY = (GRID + cap) / 2;
  const periodCx = penXTile + periodLeftRel + periodD / 2;
  const periodCy = baselineY - periodD / 2;
  const margin = (GRID - totalW) / 2;

  // Counter centre, as measured previously off this face's d.
  const counterCx = penXTile + inkLeftRel + inkW * 0.496;
  const counterCy = baselineY - cap + cap * 0.497;
  const barW = stroke;
  const barH = 0.600 * cap * 0.62;

  return { FONT, inkW, cap, stroke, periodD, opticalGap, letterReachAtPeriod,
           totalW, inkX, penXTile, baselineY, periodCx, periodCy, margin,
           counterCx, counterCy, barW, barH,
           nominalCapOver9: cap / 9 };
}

// ── 3. Render helpers ───────────────────────────────────────────────────────
const cueRect = (m, deg, ink) =>
  `<rect x="${(m.counterCx - m.barW / 2).toFixed(2)}" y="${(m.counterCy - m.barH / 2).toFixed(2)}" ` +
  `width="${m.barW.toFixed(2)}" height="${m.barH.toFixed(2)}" rx="${(m.barW / 2).toFixed(2)}" ` +
  `transform="rotate(${deg} ${m.counterCx.toFixed(2)} ${m.counterCy.toFixed(2)})" fill="${ink}"></rect>`;

const svgFor = (m, size, ink, ground, cue, tag) => `
<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">
  <defs><mask id="k${tag}">
    <rect x="0" y="0" width="${GRID}" height="${GRID}" fill="black"></rect>
    <text x="${m.penXTile.toFixed(2)}" y="${m.baselineY.toFixed(2)}" font-family="IOI Display" font-size="${m.FONT}" fill="white">d</text>
  </mask></defs>
  <rect x="0" y="0" width="${GRID}" height="${GRID}" rx="11" fill="${ground}"></rect>
  <rect x="0" y="0" width="${GRID}" height="${GRID}" fill="${ink}" mask="url(#k${tag})"></rect>
  <circle cx="${m.periodCx.toFixed(2)}" cy="${m.periodCy.toFixed(2)}" r="${(m.periodD / 2).toFixed(2)}" fill="${ink}"></circle>
  ${cue === null ? "" : cueRect(m, cue, ink)}
</svg>`;

// Rasterise one SVG string and hand back its pixels.
async function raster(svg) {
  return await page.evaluate(async (markup) => {
    const img = new Image();
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(markup);
    await img.decode();
    const c = document.createElement("canvas");
    c.width = img.width; c.height = img.height;
    const x = c.getContext("2d");
    x.drawImage(img, 0, 0);
    return { w: c.width, h: c.height, d: Array.from(x.getImageData(0, 0, c.width, c.height).data) };
  }, svg.replace("<svg", '<svg xmlns="http://www.w3.org/2000/svg"'));
}

// ── 4. The battery: does this size hold at 16px? ────────────────────────────
async function battery(m, { verbose = false } = {}) {
  const notes = [];
  let ok = true;

  // 4a. Letter and period must stay separate runs on the period's own row.
  for (const size of SIZES) {
    const r = await raster(svgFor(m, size, "#7bbd97", "#0a0e19", null, `s${size}`));
    const row = Math.min(r.h - 1, Math.round((m.periodCy / GRID) * r.h));
    const runs = []; let run = null;
    for (let px = 0; px < r.w; px++) {
      const p = (row * r.w + px) * 4;
      const on = r.d[p + 1] > 40 && r.d[p + 2] < 220;
      if (on) { const gch = r.d[p + 1]; if (!run) run = { a: px, b: px, peak: gch }; else { run.b = px; run.peak = Math.max(run.peak, gch); } }
      else if (run) { runs.push(run); run = null; }
    }
    if (run) runs.push(run);
    const gaps = [];
    for (let k = 1; k < runs.length; k++) gaps.push(runs[k].a - runs[k - 1].b - 1);
    const sep = runs.length >= 2 && gaps.every((g) => g >= 1);
    const cover = runs.map((q) => Math.round((q.peak / 189) * 100));
    if (!sep) ok = false;
    notes.push(`    ${String(size).padStart(2)}px  ${runs.length} runs  gaps ${gaps.join(",") || "—"}px  ` +
               `coverage ${cover.join("/")}%  ${sep ? "separated" : "FUSED"}`);
  }

  // 4b. The three orientations must be pairwise distinguishable at 16px, and the
  //     measurement must agree with the ideal geometry rather than merely look
  //     plausible. The ideal is rasterised at 64x from the same numbers and scaled
  //     by area; a render that disagrees with its own geometry is rejected.
  const keys = Object.keys(ORIENTATIONS);
  for (const size of [16, 24]) {
    const imgs = {};
    for (const k of keys) imgs[k] = await raster(svgFor(m, size, "#7bbd97", "#0a0e19", ORIENTATIONS[k], `c${size}${k}`));
    let worst = Infinity, worstPair = "";
    for (let i = 0; i < keys.length; i++)
      for (let j = i + 1; j < keys.length; j++) {
        const A = imgs[keys[i]].d, B = imgs[keys[j]].d;
        let diff = 0;
        for (let p = 0; p < A.length; p += 4) if (Math.abs(A[p + 1] - B[p + 1]) > 24) diff++;
        if (diff < worst) { worst = diff; worstPair = `${keys[i]}/${keys[j]}`; }
      }

    // Closed form: the same two capsules, rasterised large from the same geometry.
    const BIG = 64 * (size / 16);
    let worstIdeal = Infinity;
    for (let i = 0; i < keys.length; i++)
      for (let j = i + 1; j < keys.length; j++) {
        const a = await raster(`<svg width="${BIG * 6}" height="${BIG * 6}" viewBox="0 0 ${GRID} ${GRID}"><rect width="${GRID}" height="${GRID}" fill="#000"/>${cueRect(m, ORIENTATIONS[keys[i]], "#fff")}</svg>`);
        const b = await raster(`<svg width="${BIG * 6}" height="${BIG * 6}" viewBox="0 0 ${GRID} ${GRID}"><rect width="${GRID}" height="${GRID}" fill="#000"/>${cueRect(m, ORIENTATIONS[keys[j]], "#fff")}</svg>`);
        let d2 = 0;
        for (let p = 0; p < a.d.length; p += 4) if (Math.abs(a.d[p + 1] - b.d[p + 1]) > 24) d2++;
        const scaled = d2 * Math.pow(size / (BIG * 6), 2);
        if (scaled < worstIdeal) worstIdeal = scaled;
      }

    // The ideal is a LOWER BOUND, not an equal. At true size a thin difference
    // region is mostly partial pixels, and any threshold that counts a partial
    // pixel inflates the count; nothing deflates it below the geometry. So the
    // check is a band on the ratio: below 0.7 the render differs by less than the
    // shapes do, which means the probe is measuring the wrong thing; above 4.0 it
    // is picking up something other than the cue. Either way the number is not
    // evidence and the run fails rather than printing it.
    const ratio = worstIdeal > 0 ? worst / worstIdeal : Infinity;
    const agrees = ratio >= 0.7 && ratio <= 4.0;
    // Three differing pixels is the floor: below that the siblings differ by an
    // amount no viewer resolves, whatever the arithmetic says.
    const distinguishable = worst >= 3;
    if (!distinguishable || !agrees) ok = false;
    notes.push(`    ${String(size).padStart(2)}px  closest pair ${worstPair}: ${worst}px differ  ` +
               `ideal ${worstIdeal.toFixed(1)}px (ratio ${ratio.toFixed(2)})  ${agrees ? "agree" : "DISAGREE — rejected"}  ` +
               `${distinguishable ? "distinguishable" : "NOT distinguishable"}`);
  }

  if (verbose) notes.forEach((n) => console.log(n));
  return ok;
}

// ── 5. Sweep for the largest side margin that still holds ───────────────────
const emitArg = process.argv.includes("--emit");
const explicit = process.argv.find((a) => /^\d+$/.test(a));

let chosen = null;
if (process.argv.includes("--sweep")) {
  console.log(`\nsweeping font size downward — each step opens the side margins and costs cap height:`);
  for (let f = 71; f >= 52; f -= 1) {
    const m = await compose(f);
    const held = await battery(m);
    console.log(`  font ${String(f).padStart(2)}  margin ${m.margin.toFixed(2)}  cap ${((m.cap / GRID) * 100).toFixed(1)}%  ` +
                `mark ${((m.totalW / GRID) * 100).toFixed(1)}%  ${held ? "holds" : "fails"}`);
    if (held) chosen = m; else if (chosen) break;
  }
  if (!chosen) {
    console.error(`\nNO SIZE HOLDS: the battery failed at every size swept.`);
    await browser.close();
    process.exit(1);
  }
  console.log(`\nfrontier: font-size ${chosen.FONT} is the smallest that passes everything,`);
  console.log(`  so it is the largest side margin the small sizes allow: ${chosen.margin.toFixed(2)} units.`);
} else {
  chosen = await compose(Number(explicit || 71));
}

console.log(`\ncomposed at font-size ${chosen.FONT}:`);
console.log(`  cap ${chosen.cap.toFixed(2)}  stroke ${chosen.stroke.toFixed(2)}  ink ${chosen.inkW.toFixed(2)} wide`);
console.log(`  optical gap letter→period ${chosen.opticalGap.toFixed(2)} units, measured at the period's own rows`);
console.log(`  the old nominal cap/9 would have been ${chosen.nominalCapOver9.toFixed(2)} — a bounding-box number taken at the letter's widest row`);
console.log(`  tile margin ${chosen.margin.toFixed(2)} each side`);
console.log(`  fill: cap ${((chosen.cap / GRID) * 100).toFixed(1)}% of height, mark ${((chosen.totalW / GRID) * 100).toFixed(1)}% of width`);
console.log(`\nbattery at the chosen size:`);
const finalOk = await battery(chosen, { verbose: true });

if (emitArg) {
  console.log(`\n── board geometry (96-unit grid, font-size ${chosen.FONT}) ──`);
  console.log(`  text    x="${chosen.penXTile.toFixed(2)}" y="${chosen.baselineY.toFixed(2)}" font-size="${chosen.FONT}"`);
  console.log(`  period  cx="${chosen.periodCx.toFixed(2)}" cy="${chosen.periodCy.toFixed(2)}" r="${(chosen.periodD / 2).toFixed(2)}"`);
  console.log(`  cue     x="${(chosen.counterCx - chosen.barW / 2).toFixed(2)}" y="${(chosen.counterCy - chosen.barH / 2).toFixed(2)}" ` +
              `width="${chosen.barW.toFixed(2)}" height="${chosen.barH.toFixed(2)}" rx="${(chosen.barW / 2).toFixed(2)}"`);
  console.log(`  cue rotate about (${chosen.counterCx.toFixed(2)} ${chosen.counterCy.toFixed(2)}):`);
  for (const [k, deg] of Object.entries(ORIENTATIONS)) console.log(`    ${k.padEnd(9)} ${deg}deg`);
}

await browser.close();
console.log(finalOk ? `\nAccepted at font-size ${chosen.FONT}.` : `\nREFUSED at font-size ${chosen.FONT}.`);
process.exit(finalOk ? 0 : 1);
