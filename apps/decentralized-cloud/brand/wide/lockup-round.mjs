#!/usr/bin/env node
// THE LOCKUP ROUND — testing whether this identity needs a mark at all.
//
// Six rounds, eleven fresh readers, roughly 1,300 generated candidates, and not one
// mark has been granted by two readers. Every round has judged the mark ALONE,
// because nothing ever survived to be locked up — so bar (4), which is about the
// mark AND WORDMARK TOGETHER on the second-sighting question, has never actually been
// tested. ioi-c0's ruling: test the wordmark-led forms in parallel, because the brief
// left "wordmark-led and dot-removed" open and six rounds of evidence point there.
//
// THREE FORMS, each with its tile:
//
//   I    the wordmark alone, with the adopted Z. No device at all. Its tile is the
//        first letter in a square — deliberately the weakest option, carried because
//        "a letter in a tile" was read in an earlier phase as an ABSENCE of decision,
//        and a form that is going to lose should lose on the record rather than be
//        left out of it.
//   II   the wordmark with the DRAWN PERIOD as its only device, the period given
//        enough weight to be a mark rather than punctuation. Its tile is the period
//        alone. This is the form the evidence actually points at: the period is
//        already drawn (the face has no U+002E, so it was never optional), it is
//        already the thing that makes the name a domain, and it is the one element in
//        this identity that no reader has ever mistaken for a letter, a digit, a
//        control or a stock object.
//   III  the wordmark with a quiet mark beside it, taken from round six. Carried so
//        the comparison is not rigged: if a mark helps, this is where it shows.
//
// WHY THE TILE IS PLATED WITH THE LOCKUP rather than after it: a wordmark-led
// identity still has to ship a favicon and an app icon, and an identity that works on
// a page and collapses in a 32px square has not answered the question. ioi-c0's
// ruling, and it is right — the tile is part of the form, not a follow-up.
//
// Plates are narrow crops at whole-number nearest-neighbour magnification, under the
// 800px ceiling, because round one's wide plates were downsampled in delivery and the
// blur manufactured a defect that the narrow plates do not reproduce.

import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAP, UPM, STEM, Z_PATH, Z_ADVANCE, DOT_DIAMETER_EM, DOT_SIDE_EM, DOT_RAISE_EM } from "../wordmark/wordmark.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts/lockup");
mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) rmSync(path.join(OUT, f), { force: true });
const FONT_B64 = readFileSync(path.join(HERE, "../../public/fonts/IOI.ttf")).toString("base64");

const INK = "#0d0f12";
const GROUND = "#ffffff";

const zGlyph = (px) =>
  `<svg width="${(px * CAP / UPM * Z_ADVANCE / CAP).toFixed(3)}" height="${(px * CAP / UPM).toFixed(3)}" ` +
  `viewBox="0 -${CAP} ${Z_ADVANCE} ${CAP}" style="vertical-align:baseline;overflow:visible;flex-shrink:0;">` +
  `<g transform="scale(1,-1)"><path d="${Z_PATH}" fill="${INK}"></path></g></svg>`;

// The period, at a chosen weight. `scale` 1 is the shipped punctuation size; above
// that it is being asked to carry the identity rather than only the grammar.
function dot(px, scale) {
  const d = px * DOT_DIAMETER_EM * scale;
  return `<span style="display:inline-block;width:${d.toFixed(2)}px;height:${d.toFixed(2)}px;` +
    `border-radius:50%;background:${INK};margin:0 ${(px * DOT_SIDE_EM).toFixed(2)}px;` +
    `position:relative;top:-${(px * DOT_RAISE_EM - (d - px * DOT_DIAMETER_EM) / 2).toFixed(2)}px;"></span>`;
}

const typeStyle = (px) =>
  `font-family:'IOI Display';font-size:${px}px;line-height:1;letter-spacing:0.01em;` +
  `white-space:nowrap;color:${INK};`;

const wordmark = (px, dotScale) =>
  `<div style="display:flex;align-items:baseline;${typeStyle(px)}">` +
  `<span>decentrali</span>${zGlyph(px)}<span>ed</span>${dot(px, dotScale)}<span>cloud</span></div>`;

// A quiet mark from round six's "many into one" family — several arrivals, one
// departure, which is what a router does. It is UNTESTED as a mark: round six's
// readers have not ruled on it, and it is here so the comparison is not rigged in
// favour of the deviceless forms, not because anything has endorsed it.
const quietMark = (px) => {
  const s = px / 96;
  return `<svg width="${(96 * s).toFixed(2)}" height="${(96 * s).toFixed(2)}" viewBox="0 0 96 96" ` +
    `style="flex-shrink:0;vertical-align:baseline;">` +
    `<path d="M 22 26 L 44 48" fill="none" stroke="${INK}" stroke-width="17"></path>` +
    `<path d="M 22 70 L 44 48" fill="none" stroke="${INK}" stroke-width="17"></path>` +
    `<path d="M 44 48 L 84 48" fill="none" stroke="${INK}" stroke-width="22"></path></svg>`;
};

const FORMS = {
  I: (px) => wordmark(px, 1),
  II: (px) => wordmark(px, 2.1),
  III: (px) =>
    `<div style="display:flex;align-items:center;gap:${(px * 0.42).toFixed(1)}px;">` +
    `${quietMark(px * 1.35)}${wordmark(px, 1)}</div>`,
};

// The tiles. Each is the app icon / favicon the form would actually ship.
const TILES = {
  I: (px) =>
    `<div style="width:${px}px;height:${px}px;background:${INK};border-radius:${(px * 0.18).toFixed(1)}px;` +
    `display:flex;align-items:center;justify-content:center;">` +
    `<span style="font-family:'IOI Display';font-size:${(px * 0.62).toFixed(1)}px;line-height:1;color:${GROUND};">d</span></div>`,
  II: (px) =>
    `<div style="width:${px}px;height:${px}px;background:${INK};border-radius:${(px * 0.18).toFixed(1)}px;` +
    `display:flex;align-items:center;justify-content:center;">` +
    `<span style="display:block;width:${(px * 0.34).toFixed(1)}px;height:${(px * 0.34).toFixed(1)}px;` +
    `border-radius:50%;background:${GROUND};"></span></div>`,
  III: (px) =>
    `<div style="width:${px}px;height:${px}px;background:${INK};border-radius:${(px * 0.18).toFixed(1)}px;` +
    `display:flex;align-items:center;justify-content:center;">` +
    `<svg width="${(px * 0.66).toFixed(1)}" height="${(px * 0.66).toFixed(1)}" viewBox="0 0 96 96">` +
    `<path d="M 22 26 L 44 48" fill="none" stroke="${GROUND}" stroke-width="17"></path>` +
    `<path d="M 22 70 L 44 48" fill="none" stroke="${GROUND}" stroke-width="17"></path>` +
    `<path d="M 44 48 L 84 48" fill="none" stroke="${GROUND}" stroke-width="22"></path></svg></div>`,
};

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1400, height: 900 }, deviceScaleFactor: 1 });

async function plate(name, markup) {
  await page.setContent(
    `<style>@font-face{font-family:'IOI Display';src:url(data:font/ttf;base64,${FONT_B64}) format('truetype');}` +
    `body{margin:0;background:${GROUND};}#w{display:inline-block;padding:5px 7px;background:${GROUND};}</style>` +
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
  // Magnification exists so a reader can see DEVICE PIXELS at sizes where they
  // matter. An eighteen-character wordmark at 22px is already 450px wide, so 2x would
  // pass the ceiling and be resampled in delivery — but 1x is not a compromise there,
  // it is the artifact itself, unmagnified and unresampled. What the ceiling forbids
  // is a plate that has been through a scaler; showing true size has not.
  const mag = Math.max(1, Math.floor(780 / box.width));
  if (box.width * mag > 780)
    throw new Error(`plate ${name} is ${Math.round(box.width)}px wide and cannot be shown under the 780px ceiling at any whole magnification`);
  await page.setContent(
    `<style>body{margin:0;background:${GROUND};}img{image-rendering:pixelated;display:block;}</style>` +
    `<div id="m" style="display:inline-block;padding:16px;background:${GROUND};">` +
    `<img src="data:image/png;base64,${buf.toString("base64")}" ` +
    `width="${Math.round(box.width * mag)}" height="${Math.round(box.height * mag)}"></div>`
  );
  const f = path.join(OUT, `${name}.png`);
  await page.locator("#m").screenshot({ path: f });
  console.log(`  ${path.basename(f)}  true size, shown at ${mag}x${mag === 1 ? " (unmagnified — the artifact itself)" : " nearest-neighbour"}`);
}

// The forms are written under NEUTRAL names so a reader cannot tell which is the
// incumbent, which is the deviceless one, and which carries the untested mark. The
// key is printed here and not in any filename a reader sees.
const shuffled = ["I", "II", "III"].sort(() => Math.random() - 0.5);
const key = [];
console.log("── lockups, the small line ──");
for (let i = 0; i < shuffled.length; i++) {
  const form = shuffled[i];
  const label = String.fromCharCode(65 + i);
  key.push(`  form ${label} = ${form}`);
  for (const px of [16, 22]) await plate(`lockup-${label}-${px}px`, FORMS[form](px));
}
console.log("── tiles, at the sizes a favicon and an app icon actually ship ──");
for (let i = 0; i < shuffled.length; i++) {
  const form = shuffled[i];
  const label = String.fromCharCode(65 + i);
  for (const px of [16, 32, 64]) await plate(`tile-${label}-${px}px`, TILES[form](px));
}
console.log(`\n── KEY (mine, not the reader's) ──`);
console.log(`  I   = wordmark alone, no device`);
console.log(`  II  = wordmark with the drawn period as its only device, at 2.1x punctuation weight`);
console.log(`  III = wordmark with an untested quiet mark from round six`);
for (const k of key) console.log(k);
await browser.close();
