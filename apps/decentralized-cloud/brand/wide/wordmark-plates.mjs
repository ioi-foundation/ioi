#!/usr/bin/env node
// TYPE-WHAT-YOU-SEE — the small line, alone.
//
// This is the first of the two probes the closed phase ruled standing and never
// built. It exists because of a specific discovery: asking "is the wordmark OK"
// never surfaced anything, and showing the small line alone and asking a reader to
// TYPE WHAT THEY SEE produced `DECENTRAL1ZED·CLOUD` from two readers independently.
// The question finds the fault; the polite question does not.
//
// So the plates here carry the wordmark and NOTHING else — no mark, no colour, no
// board, no caption, no context that would let a reader infer the word they are
// supposed to be reading. A reader who can guess the answer is not testing it.
//
// WHAT IS BEING COMPARED. The face's I is literally `M32 0 L32 700 L171 700 L171 0
// Z` — a bare rectangle, 139 units wide on a 700 cap. That is not a stylised I that
// happens to read as a numeral 1; it is the same shape as one. Variant B draws an I
// with a head and a foot, at the face's own bar weight, and changes nothing else.
// Which of the two a reader types back correctly is the whole question.
//
// Usage: node apps/decentralized-cloud/brand/wide/wordmark-plates.mjs

import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAP, STEM, BAR, UPM, Z_PATH, Z_ADVANCE, dotSpan } from "../wordmark/wordmark.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts/wordmark");
mkdirSync(OUT, { recursive: true });
const FONT_B64 = readFileSync(path.join(HERE, "../../public/fonts/IOI.ttf")).toString("base64");

const INK = "#0d0f12";

// ── The drawn I ─────────────────────────────────────────────────────────────
// Every number below comes from the face's own tables, so this is the face's I with
// two bars added and nothing else changed: cap 700, stem 139 (the face's measured I
// width), bar 140 (the face's horizontal weight, measured off the E), left bearing
// 32 (every glyph in the face starts there). The bars run 3x the stem, which is the
// narrowest that reads as a head and a foot rather than as a nick.
const I_STEM = 139;
const I_BARW = I_STEM * 3;
const I_LSB = 32;
const I_ADVANCE = I_BARW + I_LSB * 2;
const I_PATH = (() => {
  const x0 = I_LSB, x1 = I_LSB + I_BARW;
  const sx0 = I_LSB + (I_BARW - I_STEM) / 2, sx1 = sx0 + I_STEM;
  return (
    `M ${x0} ${CAP} L ${x1} ${CAP} L ${x1} ${CAP - BAR} L ${sx1} ${CAP - BAR} ` +
    `L ${sx1} ${BAR} L ${x1} ${BAR} L ${x1} 0 L ${x0} 0 L ${x0} ${BAR} ` +
    `L ${sx0} ${BAR} L ${sx0} ${CAP - BAR} L ${x0} ${CAP - BAR} Z`
  );
})();

// One renderer for any drawn glyph, so the I and the Z are set the same way and a
// difference between them is a difference in the drawing rather than in the plumbing.
function drawnGlyph(pathData, advance, capPx, ink) {
  return (
    `<svg width="${(capPx * advance / CAP).toFixed(3)}" height="${capPx.toFixed(3)}" ` +
    `viewBox="0 -${CAP} ${advance} ${CAP}" aria-hidden="true" ` +
    `style="vertical-align:baseline;overflow:visible;flex-shrink:0;">` +
    `<g transform="scale(1,-1)"><path d="${pathData}" fill="${ink}"></path></g></svg>`
  );
}

const typeStyle = (px, ink) =>
  `font-family:'IOI Display';font-size:${px}px;line-height:1;letter-spacing:0.01em;` +
  `white-space:nowrap;color:${ink};`;

const Zg = (px, ink) => drawnGlyph(Z_PATH, Z_ADVANCE, px * CAP / UPM, ink);
const Ig = (px, ink) => drawnGlyph(I_PATH, I_ADVANCE, px * CAP / UPM, ink);

// Variant A is the shipped composition: the run "decentrali" is set in the face, so
// its I is the face's bare stem. Variant B splits one letter earlier and substitutes
// the drawn I. Nothing else differs — same face, same tracking, same Z, same period.
function lineA(px, ink) {
  return `<div style="display:flex;align-items:baseline;${typeStyle(px, ink)}">` +
    `<span>decentrali</span>${Zg(px, ink)}<span>ed</span>${dotSpan(px, ink)}<span>cloud</span></div>`;
}
function lineB(px, ink) {
  return `<div style="display:flex;align-items:baseline;${typeStyle(px, ink)}">` +
    `<span>decentral</span>${Ig(px, ink)}${Zg(px, ink)}<span>ed</span>${dotSpan(px, ink)}<span>cloud</span></div>`;
}

// The stacked forms. The period LEADING line two was plated once and rejected
// immediately by both readers — "a joiner that starts a line is no longer joining
// anything" — and wordmark.mjs still renders it that way, which is a disagreement
// between the module and the ruling that this plate exists to settle rather than
// paper over. Both are plated; the reader says which, and only then does the module
// change.
function stacked(px, ink, withDrawnI, dotOnLineOne) {
  const first = withDrawnI
    ? `<span>decentral</span>${Ig(px, ink)}${Zg(px, ink)}<span>ed</span>`
    : `<span>decentrali</span>${Zg(px, ink)}<span>ed</span>`;
  return `<div style="display:flex;flex-direction:column;align-items:flex-start;gap:${(px * 0.14).toFixed(2)}px;">` +
    `<div style="display:flex;align-items:baseline;${typeStyle(px, ink)}">${first}` +
    (dotOnLineOne ? dotSpan(px, ink) : "") + `</div>` +
    `<div style="display:flex;align-items:baseline;${typeStyle(px, ink)}">` +
    (dotOnLineOne ? "" : dotSpan(px, ink)) + `<span>cloud</span></div></div>`;
}

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
const page = await browser.newPage({ viewport: { width: 1400, height: 900 }, deviceScaleFactor: 1 });

// Plates are rendered at TRUE product size and then magnified 4x with
// image-rendering:pixelated, so the reader sees exactly the device pixels a viewer
// gets and no more. Rendering at 4x and calling it 16px would hand the reader
// information the product does not have, which is the mistake that makes a small-size
// test pass a wordmark that fails in the wild.
async function plate(name, markup, px) {
  await page.setContent(
    `<style>@font-face{font-family:'IOI Display';src:url(data:font/ttf;base64,${FONT_B64}) format('truetype');}` +
    `body{margin:0;background:#fff;}#w{display:inline-block;padding:6px 10px;background:#fff;}</style>` +
    `<div id="w">${markup}</div>`
  );
  const proof = await page.evaluate(async () => {
    await document.fonts.load("100px 'IOI Display'");
    await document.fonts.ready;
    return document.fonts.check("100px 'IOI Display'");
  });
  if (!proof) throw new Error("IOI Display did not load — every plate would be the fallback face");
  const buf = await page.locator("#w").screenshot();
  const url = `data:image/png;base64,${buf.toString("base64")}`;
  const box = await page.locator("#w").boundingBox();
  await page.setContent(
    `<style>body{margin:0;background:#fff;}img{image-rendering:pixelated;display:block;}</style>` +
    `<div id="m" style="display:inline-block;padding:24px;background:#fff;">` +
    `<img src="${url}" width="${Math.round(box.width * 4)}" height="${Math.round(box.height * 4)}"></div>`
  );
  const f = path.join(OUT, `${name}.png`);
  await page.locator("#m").screenshot({ path: f });
  console.log(`  ${f}   (true ${px}px, shown at 4x nearest-neighbour)`);
  return f;
}

console.log("── the small line, alone ──");
for (const px of [13, 16, 22]) {
  await plate(`A-bare-I-${px}px`, lineA(px, INK), px);
  await plate(`B-drawn-I-${px}px`, lineB(px, INK), px);
}
console.log("── the stacked forms, alone ──");
for (const px of [16, 22]) {
  await plate(`S1-dot-ends-line-one-${px}px`, stacked(px, INK, false, true), px);
  await plate(`S2-dot-leads-line-two-${px}px`, stacked(px, INK, false, false), px);
  await plate(`S3-drawn-I-dot-ends-line-one-${px}px`, stacked(px, INK, true, true), px);
}
console.log(`\nThe I override is drawn here and NOWHERE else. It is not in wordmark.mjs, not in`);
console.log(`the shipped markup, and not in any lockup, because a reader has not yet said it is`);
console.log(`better. If it goes in, it goes into wordmark.mjs as the one source and the face`);
console.log(`gate is what holds the shipped copy to it.`);
await browser.close();
