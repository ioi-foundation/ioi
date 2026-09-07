#!/usr/bin/env node
// A look at the drawn I on its own, large, beside the face's own I.
//
// Two fresh readers independently reported no perceptible difference between the
// shipped wordmark and the one carrying a drawn I. The plate bytes differ, so the
// substitution IS happening; what is in question is whether the drawing does
// anything a reader can see. Answering that from the source geometry would be
// exactly the mistake this program keeps paying for, so this renders the two glyphs
// and measures the rendered rasters.

import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAP, BAR, UPM } from "../wordmark/wordmark.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts/wordmark");
mkdirSync(OUT, { recursive: true });
const FONT_B64 = readFileSync(path.join(HERE, "../../public/fonts/IOI.ttf")).toString("base64");

const I_STEM = 139, I_LSB = 32;
const BARW = Number(process.argv[2] || 3) * I_STEM;
const I_ADVANCE = BARW + I_LSB * 2;
const x0 = I_LSB, x1 = I_LSB + BARW;
const sx0 = I_LSB + (BARW - I_STEM) / 2, sx1 = sx0 + I_STEM;
const I_PATH =
  `M ${x0} ${CAP} L ${x1} ${CAP} L ${x1} ${CAP - BAR} L ${sx1} ${CAP - BAR} ` +
  `L ${sx1} ${BAR} L ${x1} ${BAR} L ${x1} 0 L ${x0} 0 L ${x0} ${BAR} ` +
  `L ${sx0} ${BAR} L ${sx0} ${CAP - BAR} L ${x0} ${CAP - BAR} Z`;

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1900, height: 600 }, deviceScaleFactor: 1 });

const capPx = 120;
const drawn =
  `<svg width="${(capPx * I_ADVANCE / CAP).toFixed(2)}" height="${capPx}" viewBox="0 -${CAP} ${I_ADVANCE} ${CAP}">` +
  `<g transform="scale(1,-1)"><path d="${I_PATH}" fill="#0d0f12"></path></g></svg>`;

await page.setContent(
  `<style>@font-face{font-family:'IOI Display';src:url(data:font/ttf;base64,${FONT_B64}) format('truetype');}` +
  `body{margin:0;background:#fff;}#r{display:flex;align-items:baseline;gap:60px;padding:40px;}` +
  `.f{font-family:'IOI Display';font-size:${capPx * UPM / CAP}px;line-height:1;color:#0d0f12;}` +
  `svg{display:block;}</style>` +
  `<div id="r"><span class="f">I</span>${drawn}<span class="f">LIZ</span>` +
  `<span style="display:flex;align-items:baseline;font-family:'IOI Display';font-size:${capPx * UPM / CAP}px;color:#0d0f12;">L${drawn}Z</span></div>`
);
await page.evaluate(async () => {
  await document.fonts.load("100px 'IOI Display'");
  await document.fonts.ready;
});
const f = path.join(OUT, `inspect-drawn-I-bar${process.argv[2] || 3}.png`);
await page.locator("#r").screenshot({ path: f });
console.log(`bar width = ${process.argv[2] || 3}x stem (${BARW} units), advance ${I_ADVANCE}`);
console.log(`the face's own I is ${I_STEM} wide on a ${CAP} cap — aspect ${(I_STEM / CAP).toFixed(3)}`);
console.log(`the drawn I is ${BARW} wide on the same cap — aspect ${(BARW / CAP).toFixed(3)}`);
console.log(f);
await browser.close();
