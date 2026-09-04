#!/usr/bin/env node
// Measures IOI Display off a rendered specimen, so the identity sheet can state
// ratios instead of asserting them.
//
// The period is the only drawn element in this identity, so its diameter and weight
// are not style choices — they are answers to what the face actually does. This
// prints cap height, stem width, set widths and the derived period diameter.
//
// Usage: node apps/decentralized-cloud/brand/measure-face.mjs

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");

const b64 = readFileSync(path.join(REPO, "packages/design-system/assets/fonts/IOI.ttf")).toString("base64");
const EM = 200; // a big specimen so a one-pixel scan error is 0.5% not 5%

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 500 } });
await page.setContent(
  `<style>
     @font-face { font-family: "IOI Display"; src: url(data:font/ttf;base64,${b64}) format("truetype"); font-weight: 400; }
     span { font-family: "IOI Display"; font-weight: 400; letter-spacing: 0.01em; line-height: 1; white-space: nowrap; }
   </style>
   <span id="full" style="font-size:${EM}px">decentralized cloud</span>
   <span id="one" style="font-size:${EM}px">decentralized</span>
   <span id="two" style="font-size:${EM}px">cloud</span>`
);
await page.waitForFunction(() => document.fonts.ready.then(() => true));
await page.waitForTimeout(400);

const m = await page.evaluate((em) => {
  const width = (id) => document.getElementById(id).getBoundingClientRect().width;

  // Rasterise a specimen and read the ink directly: metrics tables lie, renders do not.
  const c = document.createElement("canvas");
  c.width = 600; c.height = 400;
  const ctx = c.getContext("2d");
  ctx.font = `${em}px "IOI Display"`;
  ctx.textBaseline = "alphabetic";
  ctx.fillText("L", 40, 320);
  const px = ctx.getImageData(0, 0, 600, 400).data;
  const on = (x, y) => px[(y * 600 + x) * 4 + 3] > 128;

  // Cap height: first and last inked rows.
  let top = -1, bottom = -1;
  for (let y = 0; y < 400; y++) {
    for (let x = 0; x < 600; x++) {
      if (on(x, y)) { if (top < 0) top = y; bottom = y; break; }
    }
  }

  // Stem width: scan a row a third of the way down the cap, where the L is only
  // its vertical stem, and count the contiguous run of ink.
  const scanY = Math.round(top + (bottom - top) / 3);
  let runs = [], run = 0;
  for (let x = 0; x < 600; x++) {
    if (on(x, scanY)) run += 1;
    else { if (run) runs.push(run); run = 0; }
  }
  if (run) runs.push(run);

  return {
    capPx: bottom - top + 1,
    stemPx: runs.length ? runs[0] : null,
    fullEm: width("full") / em,
    oneEm: width("one") / em,
    twoEm: width("two") / em,
  };
}, EM);

await browser.close();

const cap = m.capPx / EM;
const stem = m.stemPx / EM;
const quarterCap = cap / 4;

console.log(`  cap height          ${cap.toFixed(4)} em   (${m.capPx}px at ${EM}px)`);
console.log(`  stem width          ${stem.toFixed(4)} em   (${m.stemPx}px at ${EM}px)`);
console.log(`  period diameter     ${quarterCap.toFixed(4)} em   (one quarter of cap)`);
console.log(`  diameter / stem     ${(quarterCap / stem).toFixed(3)}`);
console.log(`  "decentralized"     ${m.oneEm.toFixed(3)} em`);
console.log(`  "cloud"             ${m.twoEm.toFixed(3)} em`);
console.log(`  full lockup         set as one line with the drawn period, see the sheet`);
console.log(`\n  at 220px the narrow lockup sets "decentralized" at ${(220 / m.oneEm).toFixed(2)}px, cap ${((220 / m.oneEm) * cap).toFixed(2)}px`);
console.log(`  a cap of exactly 11px needs a ${(11 / cap).toFixed(2)}px face, i.e. ${((11 / cap) * m.oneEm).toFixed(0)}px of width`);
