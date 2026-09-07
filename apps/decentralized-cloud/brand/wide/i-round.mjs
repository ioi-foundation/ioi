#!/usr/bin/env node
// THE I ROUND — the other half of the compound fault, on plates that do not blur.
//
// The Z was fixed by a swept round on narrow plates. The I was ruled a NULL RESULT
// and left alone — and that ruling rests on evidence I have since had to retract:
// the plates that produced it were wide enough to be downsampled in delivery, and
// that same downsampling manufactured part of the Z finding it sat beside.
//
// Two fresh readers on narrow lockup plates have now put the fault back:
//
//   reader S, transcribing the wordmark cold at 16px:  "DECENTRAL12ED"
//   reader R:  "at 16px I genuinely had to decide whether I was reading IZ or 12"
//
// The face's I is literally `M32 0 L32 700 L171 700 L171 0 Z` — a bare rectangle,
// 139 units wide on a 700 cap. It is not a stylised I that happens to resemble a
// numeral; it is the same shape as one. The earlier drawn I failed for a reason the
// measurement made obvious afterwards: its bars ran 3x the stem, which at 16px is a
// three-pixel nub — an event the size of the events round two proved cannot carry
// anything.
//
// So this sweeps the I the way the Z was swept: wider bars, heavier bars, and the
// bare stem carried as the control. Same cluster, same narrow plates, same
// whole-number magnification, same shuffled order with the key kept out of the
// filenames.

import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAP, BAR, UPM, Z_PATH, Z_ADVANCE } from "../wordmark/wordmark.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts/i-round");
mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) rmSync(path.join(OUT, f), { force: true });
const FONT_B64 = readFileSync(path.join(HERE, "../../public/fonts/IOI.ttf")).toString("base64");
const INK = "#0d0f12";

// The face's own I, measured off its outline rather than assumed.
const I_STEM = 139;
const I_LSB = 32;

// A drawn I is a stem with a head and a foot. `barMul` is how far the bars run
// relative to the stem, `barH` how heavy they are. The previous attempt used
// barMul 3 and barH 140 — 3.0 and 3.2 device pixels at 16px — and three readers saw
// no difference. The sweep goes wider and heavier because that is where the
// resolution floor actually is, not because heavier looks better.
function iPath(barMul, barH) {
  const barW = I_STEM * barMul;
  const x0 = I_LSB, x1 = I_LSB + barW;
  const sx0 = I_LSB + (barW - I_STEM) / 2, sx1 = sx0 + I_STEM;
  return {
    advance: barW + I_LSB * 2,
    d:
      `M ${x0} ${CAP} L ${x1} ${CAP} L ${x1} ${CAP - barH} L ${sx1} ${CAP - barH} ` +
      `L ${sx1} ${barH} L ${x1} ${barH} L ${x1} 0 L ${x0} 0 L ${x0} ${barH} ` +
      `L ${sx0} ${barH} L ${sx0} ${CAP - barH} L ${x0} ${CAP - barH} Z`,
  };
}

const VARIANTS = [{ id: "I-face-bare-stem", path: null, note: "the face's own I — a bare rectangle, the shape readers type back as 1" }];
for (const barMul of [3.2, 4.0, 4.8]) {
  for (const barH of [160, 200, 240]) {
    const { advance, d } = iPath(barMul, barH);
    VARIANTS.push({
      id: `I-b${barMul}-h${barH}`,
      path: d,
      advance,
      // Units to device pixels at a 16px font-size: the glyph lives in a 1000-unit em,
      // so one unit is 16/1000 px. An earlier version of this label divided by 6 — the
      // MARK grid's conversion, from a 96-unit grid — and reported a 5px bar as 56px.
      // The drawing was unaffected; the label was a claim about the drawing that was
      // wrong by an order of magnitude, which is exactly the kind of number I would
      // have read the results against.
      note: `bars ${barMul}x stem (${(I_STEM * barMul * 16 / 1000).toFixed(2)}px at a 16px font-size), bar height ${barH} (${(barH * 16 / 1000).toFixed(2)}px)`,
    });
  }
}

const glyph = (d, advance, capPx) =>
  `<svg width="${(capPx * advance / CAP).toFixed(3)}" height="${capPx.toFixed(3)}" ` +
  `viewBox="0 -${CAP} ${advance} ${CAP}" style="vertical-align:baseline;overflow:visible;flex-shrink:0;">` +
  `<g transform="scale(1,-1)"><path d="${d}" fill="${INK}"></path></g></svg>`;

const typeStyle = (px) =>
  `font-family:'IOI Display';font-size:${px}px;line-height:1;letter-spacing:0.01em;` +
  `white-space:nowrap;color:${INK};`;

// The cluster is "alized" — the six characters every reported misreading has landed
// in — with the adopted Z always drawn, so the only thing varying between plates is
// the I. Showing it ALONE denies the reader the rest of the word to infer from,
// which is the entire point of the instrument.
function cluster(v, px) {
  const capPx = px * CAP / UPM;
  const i = v.path ? glyph(v.path, v.advance, capPx) : `<span>i</span>`;
  return `<div style="display:flex;align-items:baseline;${typeStyle(px)}">` +
    `<span>al</span>${i}${glyph(Z_PATH, Z_ADVANCE, capPx)}<span>ed</span></div>`;
}

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1200, height: 900 }, deviceScaleFactor: 1 });

// ONE MAGNIFICATION FOR THE WHOLE SET, computed from the WIDEST plate before any is
// written. The first version computed it per plate from that plate's own width — and
// because the variants have different advance widths, the plates came out at
// different magnifications. Both readers named it before they named anything about
// the letter. Reader T: "03, 08, 09, 10 are rendered at a visibly larger pixel size
// than the other six... I noticed the scale difference immediately and the glyph
// difference not at all, which is the wrong ratio for this test."
//
// A comparison set whose members differ in scale is a comparison of scale. The
// variable under test has to be the only thing that varies, and my instrument was
// varying a second thing louder than the first.
let SET_MAG = null;
async function measure(markup) {
  await page.setContent(
    `<style>@font-face{font-family:'IOI Display';src:url(data:font/ttf;base64,${FONT_B64}) format('truetype');}` +
    `body{margin:0;background:#fff;}#w{display:inline-block;padding:3px 5px;background:#fff;}</style>` +
    `<div id="w">${markup}</div>`
  );
  const box = await page.locator("#w").boundingBox();
  return box.width;
}

async function plate(name, markup) {
  await page.setContent(
    `<style>@font-face{font-family:'IOI Display';src:url(data:font/ttf;base64,${FONT_B64}) format('truetype');}` +
    `body{margin:0;background:#fff;}#w{display:inline-block;padding:3px 5px;background:#fff;}</style>` +
    `<div id="w">${markup}</div>`
  );
  const ok = await page.evaluate(async () => {
    await document.fonts.load("100px 'IOI Display'");
    await document.fonts.ready;
    return document.fonts.check("100px 'IOI Display'");
  });
  if (!ok) throw new Error("IOI Display did not load — the plate would be the fallback face");
  const buf = await page.locator("#w").screenshot();
  const box = await page.locator("#w").boundingBox();
  const mag = SET_MAG;
  if (!mag || mag < 4) throw new Error(`the set magnification is ${mag}; below 4x a reader cannot see device pixels`);
  await page.setContent(
    `<style>body{margin:0;background:#fff;}img{image-rendering:pixelated;display:block;}</style>` +
    `<div id="m" style="display:inline-block;padding:14px;background:#fff;">` +
    `<img src="data:image/png;base64,${buf.toString("base64")}" ` +
    `width="${Math.round(box.width * mag)}" height="${Math.round(box.height * mag)}"></div>`
  );
  await page.locator("#m").screenshot({ path: path.join(OUT, `${name}.png`) });
  return mag;
}

const order = VARIANTS.map((v) => v);
for (let i = order.length - 1; i > 0; i--) {
  const j = Math.floor(Math.random() * (i + 1));
  [order[i], order[j]] = [order[j], order[i]];
}

console.log(`── ${order.length} I variants (1 incumbent + ${order.length - 1} swept) ──`);
const key = [];
{
  let widest = 0;
  for (const v of order) widest = Math.max(widest, await measure(cluster(v, 16)));
  SET_MAG = Math.max(1, Math.floor(780 / widest));
  console.log(`  widest plate ${widest.toFixed(1)}px -> ONE magnification of ${SET_MAG}x for every plate in the set`);
}
for (const px of [16]) {
  for (let n = 0; n < order.length; n++) {
    const mag = await plate(`cluster-${px}px-${String(n + 1).padStart(2, "0")}`, cluster(order[n], px));
    if (px === 16) key.push(`  ${String(n + 1).padStart(2, "0")}  ${order[n].id}  —  ${order[n].note}`);
    if (n === 0) console.log(`  ${px}px plates at ${mag}x nearest-neighbour`);
  }
}
console.log(`\nplates: ${readdirSync(OUT).length} in ${OUT}`);
console.log(`\n── KEY (mine, not the reader's) ──`);
for (const k of key) console.log(k);
await browser.close();
