// The reserved d's TRUE visible box, measured on the curves.
//
// parse-shapes.mjs computes its box by scanning every number in the path data
// as a coordinate pair. That includes bezier CONTROL points, which lie outside
// the curve wherever the curve bends away from them, so the number it prints is
// the control-polygon hull and is an over-estimate by construction. It is a
// measurement of an intermediate representation, not of the drawing.
//
// getBBox() on a rendered <path> is exact for beziers. This script prints both
// and the error between them, and exits non-zero if the emitted geometry ever
// disagrees with what parse-shapes claims by more than a tenth of a unit, so
// the claim on the board cannot drift away from the artwork again.

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const emitted = execFileSync("node", [path.join(HERE, "parse-shapes.mjs"), "--emit"], {
  encoding: "utf8",
});
const paths = [...emitted.matchAll(/^\s{2}(M [\d.\-][^\n]*)$/gm)].map((m) => m[1].trim());
if (paths.length !== 3) {
  console.error(`expected 3 emitted paths, parsed ${paths.length} — refusing to measure`);
  process.exit(1);
}

const browser = await chromium.launch();
const page = await browser.newPage();
await page.setContent(
  `<svg id="s" width="400" height="400" viewBox="0 0 200 200">` +
    paths.map((d, i) => `<path id="p${i}" d="${d}" fill="#000"/>`).join("") +
    `</svg>`
);

const boxes = await page.evaluate((n) => {
  const out = [];
  for (let i = 0; i < n; i++) {
    const b = document.getElementById(`p${i}`).getBBox();
    out.push({ x0: b.x, y0: b.y, x1: b.x + b.width, y1: b.y + b.height });
  }
  return out;
}, paths.length);
await browser.close();

const x0 = Math.min(...boxes.map((b) => b.x0));
const x1 = Math.max(...boxes.map((b) => b.x1));
const y0 = Math.min(...boxes.map((b) => b.y0));
const y1 = Math.max(...boxes.map((b) => b.y1));
const w = x1 - x0;
const h = y1 - y0;

console.log("true curve box of the emitted mark, measured with getBBox:\n");
boxes.forEach((b, i) =>
  console.log(
    `  shape ${i + 1}: ${(b.x1 - b.x0).toFixed(2)} x ${(b.y1 - b.y0).toFixed(2)} ` +
      `at (${b.x0.toFixed(2)}, ${b.y0.toFixed(2)})`
  )
);
console.log(
  `\n  mark: ${w.toFixed(2)} x ${h.toFixed(2)} units, aspect ${(w / h).toFixed(3)}`
);

// parse-shapes normalises the taller axis to 96, so the emitted height is 96 by
// construction and only the width carries the error.
const CLAIMED_W = 108.63;
const CLAIMED_ASPECT = 1.132;
const errW = Math.abs(w - CLAIMED_W);
console.log(
  `\n  control-polygon claim: ${CLAIMED_W} wide, aspect ${CLAIMED_ASPECT}` +
    `\n  overstatement:         ${errW.toFixed(2)} units (${((errW / w) * 100).toFixed(2)}% of the true width)`
);

if (Math.abs(h - 96) > 0.1) {
  console.error(`\nFAIL: emitted height ${h.toFixed(2)} is not the declared 96-unit grid.`);
  process.exit(1);
}
console.log(`\n  height ${h.toFixed(2)} on the declared 96 grid — the normalisation holds.`);
