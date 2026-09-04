#!/usr/bin/env node
// Composes the monogram from measurement and then checks it, rather than placing the
// period by eye and describing it afterwards.
//
// The period must sit ON THE BASELINE, because that is where a period lives, and it
// must be cut to the letter's stroke weight. Neither can be satisfied inside the
// counter: this face's d encloses its counter with a bottom bar, so the counter's
// floor is well above the baseline. A period on the baseline therefore sits AFTER
// the letter — which is what "d." is, and what the domain's own break looks like.
// That also frees the counter for a per-sibling cue.
//
// Everything below is measured off a render: the glyph's ink box, its baseline, its
// stroke weight, and then whether the composed mark's parts stay separate runs of
// ink at 16, 24 and 32px. A placement that fuses is refused, not shipped.
//
// Usage: node apps/decentralized-cloud/brand/compose-monogram.mjs [fontSize]

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");
const b64 = readFileSync(path.join(REPO, "packages/design-system/assets/fonts/IOI.ttf")).toString("base64");

// The glyph is sized to fill the tile: a review found the mark occupying 45% of the
// tile height, which is the root cause of a faint period and a sub-pixel tick. The
// limit is horizontal — a letter-plus-period lockup is about 1.77:1 and the tile is
// square — so this is the largest size that still leaves a margin, and the resulting
// fill ratio is printed rather than left implicit.
const FONT = Number(process.argv[2] || 71);
const GRID = 96;
const SIZES = [16, 24, 32];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 900, height: 400 }, deviceScaleFactor: 1 });

// ── 1. Measure the glyph in tile units ──────────────────────────────────────
await page.setContent(`<style>
@font-face { font-family: "IOI Display"; src: url(data:font/ttf;base64,${b64}) format("truetype"); font-weight: 400; }
#warm { font-family: "IOI Display"; font-size: 30px; position: absolute; left: -9999px; }
</style><div id="warm">d</div><canvas id="c" width="1200" height="1000"></canvas>`);
await page.waitForFunction(() => document.fonts.ready.then(() => true));
await page.evaluate((f) => document.fonts.load(`${f}px "IOI Display"`), FONT);
await page.waitForTimeout(250);
if (!(await page.evaluate((f) => document.fonts.check(`${f}px "IOI Display"`), FONT))) {
  console.error("REFUSING: IOI Display did not load; every number below would describe a fallback.");
  await browser.close();
  process.exit(1);
}

// Render at 10x the tile so one tile unit is 10 device px and the ink box is precise.
const S = 10;
const glyph = await page.evaluate(({ font, s }) => {
  const c = document.getElementById("c");
  const x = c.getContext("2d");
  x.clearRect(0, 0, 1200, 1000);
  const baseline = 850;
  x.font = `${font * s}px "IOI Display"`;
  x.textBaseline = "alphabetic";
  x.fillText("d", 50, baseline);
  const d = x.getImageData(0, 0, 1200, 1000).data;
  const on = (px, py) => d[(py * 1200 + px) * 4 + 3] > 128;
  let x0 = 1200, x1 = -1, y0 = 1000, y1 = -1;
  for (let py = 0; py < 1000; py++) for (let px = 0; px < 1200; px++) {
    if (on(px, py)) { if (px < x0) x0 = px; if (px > x1) x1 = px; if (py < y0) y0 = py; if (py > y1) y1 = py; }
  }
  // Stroke weight: the vertical stem, scanned a third of the way down the cap.
  const scanY = Math.round(y0 + (y1 - y0) / 3);
  let run = 0;
  for (let px = x0; px <= x1; px++) { if (on(px, scanY)) run++; else if (run) break; }
  return { x0, x1, y0, y1, baseline, stem: run };
}, { font: FONT, s: S });

const u = (v) => v / S;                       // device px at 10x → tile units
const inkW = u(glyph.x1 - glyph.x0 + 1);
const cap = u(glyph.y1 - glyph.y0 + 1);
const stroke = u(glyph.stem);
const drawX = 50 / S;                          // where fillText was told to start
const leftBearing = u(glyph.x0) - drawX;       // ink offset from the pen position

console.log(`glyph at font-size ${FONT} in a ${GRID}-unit tile`);
console.log(`  ink ${inkW.toFixed(2)} wide x ${cap.toFixed(2)} cap   stroke ${stroke.toFixed(2)}   left bearing ${leftBearing.toFixed(2)}`);

// ── 2. Compose: letter + period, both on the baseline ───────────────────────
const periodD = stroke;                        // cut to the stroke weight
// The wordmark's own bearing rule is cap/9. At 16px that is under one device pixel,
// so the small cut needs it opened — an optical size, exactly as a type designer
// cuts one. `--bearing` overrides it and the board states whatever is used.
const bearingArg = process.argv.indexOf("--bearing");
const sideBearing = bearingArg > -1 ? Number(process.argv[bearingArg + 1]) : cap / 9;
const totalW = inkW + sideBearing + periodD;
const inkX = (GRID - totalW) / 2;              // centre the composed mark
const baselineY = (GRID + cap) / 2;            // centre the cap vertically
const penX = inkX - leftBearing;
const periodCx = inkX + inkW + sideBearing + periodD / 2;
const periodCy = baselineY - periodD / 2;      // sits ON the baseline

console.log(`  composed ${totalW.toFixed(2)} wide, ${((GRID - totalW) / 2).toFixed(2)} margin each side`);
console.log(`  baseline y ${baselineY.toFixed(2)}   period d ${periodD.toFixed(2)} at (${periodCx.toFixed(2)}, ${periodCy.toFixed(2)})`);
console.log(`  fill: cap ${(cap / GRID * 100).toFixed(1)}% of tile height, composed mark ${(totalW / GRID * 100).toFixed(1)}% of its width`);

// ── The per-sibling cue ─────────────────────────────────────────────────────
// The counter is the only spare room in the mark, and a cue there must survive 16px
// and one ink. Colour cannot carry it (it dies in one ink) and a second letter is
// not allowed, so what is left is one drawn bar whose POSITION says which sibling.
// Whether three positions are actually distinguishable at 16px is measured below,
// not assumed: the counter is only about four device pixels tall there.
const counterW = 1.064 * cap, counterH = 0.600 * cap;
const counterCx = inkX + inkW * 0.496;         // measured counter centre, from parse
const counterCy = baselineY - cap + cap * 0.497;
// The counter is wide and shallow — 1.064 cap across against 0.600 tall — so a cue
// that varies VERTICALLY has about four device pixels to work in at 16px and cannot
// separate three states; measured, the three landed 0.36px apart. Varying along the
// long axis has nearly twice the room, so the cue is an upright tick whose
// horizontal position names the sibling.
const barW = stroke;                            // the board's own weight rule: the tick is a stroke
const barH = counterH * 0.62;
const CUES = { cloud: -1, exchange: 0, trade: 1 };  // left, centre, right
const cueBar = (which) => {
  if (!(which in CUES)) return "";
  const slot = CUES[which] * (counterW / 2 - barW / 2) * 0.66;
  return `<rect x="${(counterCx + slot - barW / 2).toFixed(2)}" y="${(counterCy - barH / 2).toFixed(2)}" ` +
         `width="${barW.toFixed(2)}" height="${barH.toFixed(2)}" rx="${(barW / 2).toFixed(2)}" fill="INK"></rect>`;
};

const svgFor = (size, ink, ground, cue) => `
<svg width="${size}" height="${size}" viewBox="0 0 ${GRID} ${GRID}">
  <defs><mask id="mm${size}${cue ? "c" : ""}">
    <rect x="0" y="0" width="${GRID}" height="${GRID}" fill="black"></rect>
    <text x="${penX.toFixed(2)}" y="${baselineY.toFixed(2)}" font-family="IOI Display" font-size="${FONT}" fill="white">d</text>
  </mask></defs>
  <rect x="0" y="0" width="${GRID}" height="${GRID}" rx="11" fill="${ground}"></rect>
  <rect x="0" y="0" width="${GRID}" height="${GRID}" fill="${ink}" mask="url(#mm${size}${cue ? "c" : ""})"></rect>
  <circle cx="${periodCx.toFixed(2)}" cy="${periodCy.toFixed(2)}" r="${(periodD / 2).toFixed(2)}" fill="${ink}"></circle>
  ${cue ? cueBar(cue).replace(/INK/g, ink) : ""}
</svg>`;

// ── 3. Refuse any placement that fuses ──────────────────────────────────────
await page.setContent(`<style>
@font-face { font-family: "IOI Display"; src: url(data:font/ttf;base64,${b64}) format("truetype"); font-weight: 400; }
body { margin: 0; background: #fff; display: flex; gap: 20px; padding: 16px; }
#warm { font-family: "IOI Display"; font-size: 20px; position: absolute; left: -9999px; }
</style><div id="warm">d</div>${SIZES.map((s) => svgFor(s, "#7bbd97", "#0a0e19")).join("")}`);
await page.waitForFunction(() => document.fonts.ready.then(() => true));
await page.evaluate((f) => document.fonts.load(`${f}px "IOI Display"`), FONT);
await page.waitForTimeout(250);

console.log(`\nseparation, scanned across the baseline row at true device pixels:`);
let refused = false;
for (const [i, size] of SIZES.entries()) {
  const shot = await page.locator("svg").nth(i).screenshot();
  const r = await page.evaluate(async ({ dataUrl, cyFrac }) => {
    const im = new Image(); im.src = dataUrl; await im.decode();
    const c = document.createElement("canvas");
    c.width = im.width; c.height = im.height;
    const x = c.getContext("2d");
    x.drawImage(im, 0, 0);
    const d = x.getImageData(0, 0, im.width, im.height).data;
    // Threshold on PRESENCE, not on full strength. The onyx ground reads 14 on the
    // green channel and solid ink reads 189; a period only 1.4 device pixels across
    // lands near 70. A threshold of 120 tuned to the letter reports that dot as
    // absent and calls a separated mark fused — which is what this probe did before
    // the row was dumped and read. Peak coverage is reported per run so faintness is
    // visible rather than hidden behind a binary verdict.
    const green = (p) => d[p * 4 + 1] > 40 && d[p * 4 + 2] < 220;
    // Scan the row through the PERIOD's own centre, computed from the composition
    // rather than guessed at a fraction of the tile — a guessed row can miss the dot
    // entirely and report a fusion that is really a bad scan.
    const row = Math.min(im.height - 1, Math.max(0, Math.round((cyFrac) * im.height)));
    const runs = []; let run = null;
    for (let px = 0; px < im.width; px++) {
      const p = row * im.width + px;
      if (green(p)) {
        const g = d[p * 4 + 1];
        if (!run) run = { a: px, b: px, peak: g }; else { run.b = px; run.peak = Math.max(run.peak, g); }
      } else if (run) { runs.push(run); run = null; }
    }
    if (run) runs.push(run);
    return { w: im.width, runs: runs.map((q) => [q.a, q.b, Math.round((q.peak / 189) * 100)]) };
  }, { dataUrl: `data:image/png;base64,${shot.toString("base64")}`, cyFrac: periodCy / GRID });

  const gaps = [];
  for (let k = 1; k < r.runs.length; k++) gaps.push(r.runs[k][0] - r.runs[k - 1][1] - 1);
  const ok = r.runs.length >= 2 && gaps.every((g) => g >= 1);
  if (!ok) refused = true;
  console.log(
    `  ${String(size).padStart(2)}px  ${r.runs.length} run${r.runs.length === 1 ? "" : "s"}` +
    (gaps.length ? `  gap${gaps.length > 1 ? "s" : ""} ${gaps.join(", ")}px` : "  no gap") +
    `  ${ok ? "SEPARATED" : "FUSED — placement refused"}` +
    `  coverage ${r.runs.map((q) => q[2] + "%").join(" / ")}`
  );
}

// ── 4. Is the cue distinguishable at 16px? ──────────────────────────────────
// Three positions in a counter four device pixels tall is the claim under test. The
// bar's vertical centre of mass is measured in each cut; if two siblings land on the
// same row the cue cannot tell them apart and the system has to be told so.
await page.setContent(`<style>
@font-face { font-family: "IOI Display"; src: url(data:font/ttf;base64,${b64}) format("truetype"); font-weight: 400; }
body { margin: 0; background: #fff; display: flex; gap: 20px; padding: 16px; }
#warm { font-family: "IOI Display"; font-size: 20px; position: absolute; left: -9999px; }
</style><div id="warm">d</div>${SIZES.flatMap((s) => Object.keys(CUES).map((k) => svgFor(s, "#7bbd97", "#0a0e19", k))).join("")}${SIZES.map((s) => svgFor(s, "#7bbd97", "#0a0e19")).join("")}`);
await page.waitForFunction(() => document.fonts.ready.then(() => true));
await page.evaluate((f) => document.fonts.load(`${f}px "IOI Display"`), FONT);
await page.waitForTimeout(250);

let crossCheckFailed = false;
console.log(`\nper-sibling cue — tick isolated by differencing against the tickless base:`);
for (const [sizeIdx, cueSize] of SIZES.entries()) {
const centres = [];
for (const [j, key] of Object.keys(CUES).entries()) {
  const i = sizeIdx * Object.keys(CUES).length + j;
  const shot = await page.locator("svg").nth(i).screenshot();
  // DIFFERENCE the sibling against the tickless base. Measuring the centre of mass
  // across the counter's columns pulls in the letter's inner stroke edges, which
  // dominate the average and compress the three siblings toward each other — that is
  // how this probe once reported 0.54px where the geometry says 2.19px, and a ruling
  // was made on the wrong number. Only the tick differs between the two renders, so
  // differencing isolates exactly it.
  const c = await page.evaluate(async ({ dataUrl, baseUrl }) => {
    const load = async (u) => { const im = new Image(); im.src = u; await im.decode(); return im; };
    const [a, b] = await Promise.all([load(dataUrl), load(baseUrl)]);
    const grab = (im) => {
      const cv = document.createElement("canvas");
      cv.width = im.width; cv.height = im.height;
      const x = cv.getContext("2d");
      x.drawImage(im, 0, 0);
      return x.getImageData(0, 0, im.width, im.height).data;
    };
    const da = grab(a), db = grab(b);
    let sum = 0, wt = 0;
    for (let px = 0; px < a.width; px++) {
      for (let py = 0; py < a.height; py++) {
        const p = (py * a.width + px) * 4;
        const diff = Math.abs(da[p + 1] - db[p + 1]);
        if (diff > 8) { sum += px * diff; wt += diff; }
      }
    }
    return wt ? sum / wt : null;
  }, {
    dataUrl: `data:image/png;base64,${shot.toString("base64")}`,
    baseUrl: `data:image/png;base64,${(await page.locator("svg").nth(SIZES.length * Object.keys(CUES).length + sizeIdx).screenshot()).toString("base64")}`,
  });
  centres.push({ key, c });
}
const spread = centres.filter((x) => x.c !== null).map((x) => x.c).sort((a, b) => a - b);
const minSep = spread.length > 1 ? Math.min(...spread.slice(1).map((v, i) => v - spread[i])) : 0;
// One device pixel is the floor: a difference smaller than a pixel is a difference
// nobody can see, whatever the arithmetic says.
const cueWorks = spread.length === Object.keys(CUES).length && minSep >= 1;

// CLOSED-FORM CROSS-CHECK. The tick's step is a constant in this file, so the
// separation at any size is arithmetic. A measurement that disagrees with the
// arithmetic already in the source is a broken measurement, and the run fails rather
// than printing a plausible number — which is precisely what happened before.
const slotStep = (counterW / 2 - barW / 2) * 0.66;
const expected = slotStep * cueSize / GRID;
const agrees = Math.abs(minSep - expected) <= Math.max(0.25, expected * 0.15);
if (!agrees) crossCheckFailed = true;
console.log(
  `  ${String(cueSize).padStart(2)}px  measured ${minSep.toFixed(2)}px  closed form ${expected.toFixed(2)}px  ` +
  `${agrees ? "agree" : "DISAGREE — measurement rejected"}  ` +
  `${cueWorks ? "DISTINGUISHABLE" : "not distinguishable"}`
);
}

// ── 5. Emit the geometry the board should use ───────────────────────────────
// Every number on the board has been hand-copied from this output at least once, and
// at least once it was copied wrong. `--emit` prints the constants and the tick
// offsets so the board can be written from the tool rather than from a transcription.
if (process.argv.includes("--emit")) {
  console.log(`\n── board geometry (96-unit grid, font-size ${FONT}) ──`);
  console.log(`  text        x="${penX.toFixed(2)}" y="${baselineY.toFixed(2)}" font-size="${FONT}"`);
  console.log(`  period      cx="${periodCx.toFixed(2)}" cy="${periodCy.toFixed(2)}" r="${(periodD / 2).toFixed(2)}"`);
  console.log(`  tick        y="${(counterCy - barH / 2).toFixed(2)}" width="${barW.toFixed(2)}" height="${barH.toFixed(2)}" rx="${(barW / 2).toFixed(2)}"`);
  for (const [k, v] of Object.entries(CUES)) {
    const slot = v * (counterW / 2 - barW / 2) * 0.66;
    console.log(`  tick x ${k.padEnd(9)} "${(counterCx + slot - barW / 2).toFixed(2)}"`);
  }
  console.log(`  bearings    letter→period ${sideBearing.toFixed(2)} (cap/9), tile margin ${((GRID - totalW) / 2).toFixed(2)}`);
  console.log(`  fill        cap ${(cap / GRID * 100).toFixed(1)}% of height, mark ${(totalW / GRID * 100).toFixed(1)}% of width`);
}

await browser.close();
console.log(crossCheckFailed
  ? `\nCROSS-CHECK FAILED: a measured separation disagrees with the arithmetic in this file.`
  : `\nCross-check passed: every measured separation agrees with its closed form.`);
console.log(refused
  ? `\nREFUSED at font-size ${FONT}: the period fuses with the letter at one or more sizes.`
  : `\nAccepted at font-size ${FONT}: letter and period stay separate at every size tested.`);
process.exit(refused || crossCheckFailed ? 1 : 0);
