#!/usr/bin/env node
// The wordmark's Z override — drawn, measured, and scoped to this wordmark only.
//
// WHY THIS EXISTS. Three reviewers who could not see each other's work read the
// wordmark as "DECENTRALI2ED": both round-three cold readers at both sizes in all
// five lockups, and the UX reviewer independently on the live face at 4x device
// scale. The brand's own name is misread, and this identity is wordmark-led, so it
// outranks the mark search.
//
// WHAT IT IS NOT. It is NOT an edit to IOI.ttf. That file is the estate's brand face
// and other products set their wordmarks in it; the same misread may exist there and
// that is the owner's call, not this product's. This draws ONE glyph, uses it in ONE
// wordmark, and leaves the font untouched.
//
// THE DIAGNOSIS, settled from the font's own cmap rather than from appearances:
//
//   U+005A  Z   gid 30  advance 1065  117 path commands  bbox 32,0 → 1033,700
//   U+007A  z   gid 30  — the same glyph; the face is unicase, as recorded.
//   U+0032  2   gid 0 (.notdef) — the face carries NO DIGITS.
//   U+002E  .   gid 0 (.notdef) — the face carries NO PERIOD, which is why the
//               period in this wordmark has always had to be drawn.
//
// So the misread is the face's own Z, not a fallback: ioi-e1's option (d) is ruled
// out mechanically and ruling (a) applies.
//
// A FINDING AGAINST MY OWN FIRST PROBE. Before parsing the cmap I rendered "Z 2 z"
// in the face and concluded from the specimen that the Z and the 2 "look nearly
// identical". That row proved nothing: the face has no U+0032, so the browser fell
// back to a system font and I was comparing IOI's Z against some other font's 2.
// The readers' misread is real — they read the actual wordmark — but my explanation
// of it was measured against the wrong glyph. The cmap is what settled it.
//
// Usage: node apps/decentralized-cloud/brand/wordmark/compose-z-override.mjs [--emit]

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TTF = path.join(HERE, "../../public/fonts/IOI.ttf");
const OUT = path.join(HERE, "../.artifacts/wordmark");
const b64 = readFileSync(TTF).toString("base64");
const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");

const UPM = 1000, CAP = 700, ADV = 1065;   // from the font's own tables
const S = 10;                               // render scale: 1 font unit = S/100 px at 100px type

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 700 }, deviceScaleFactor: 1 });
mkdirSync(OUT, { recursive: true });

await page.setContent(`<style>
@font-face{font-family:"IOI Display";src:url(data:font/ttf;base64,${b64}) format("truetype");}
#warm{font-family:"IOI Display";font-size:40px;position:absolute;left:-9999px;}
</style><div id="warm">DZI</div><canvas id="c" width="1400" height="700"></canvas>`);
await page.waitForFunction(() => document.fonts.ready.then(() => true));
await page.evaluate(() => document.fonts.load('300px "IOI Display"'));
await page.waitForTimeout(250);
if (!(await page.evaluate(() => document.fonts.check('300px "IOI Display"')))) {
  console.error("REFUSING: IOI Display did not load; every metric below would describe a fallback.");
  await browser.close();
  process.exit(1);
}

// ── Measure the face's own stroke weight, rather than guessing at it ─────────
// The horizontal bar of the E, scanned down its middle column, and the vertical
// stem of the D, scanned across its top third. A Z drawn to a weight the face does
// not use is a Z that looks pasted in, which is the failure mode of a single-glyph
// override.
const metrics = await page.evaluate(() => {
  const c = document.getElementById("c"), x = c.getContext("2d");
  const read = (ch) => {
    x.clearRect(0, 0, 1400, 700);
    x.font = '300px "IOI Display"';
    x.textBaseline = "alphabetic";
    x.fillStyle = "#000";
    x.fillText(ch, 40, 500);
    const d = x.getImageData(0, 0, 1400, 700).data;
    const on = (px, py) => d[(py * 1400 + px) * 4 + 3] > 128;
    let x0 = 1400, x1 = -1, y0 = 700, y1 = -1;
    for (let py = 0; py < 700; py++) for (let px = 0; px < 1400; px++)
      if (on(px, py)) { if (px < x0) x0 = px; if (px > x1) x1 = px; if (py < y0) y0 = py; if (py > y1) y1 = py; }
    return { x0, x1, y0, y1, on };
  };
  // Horizontal bar weight: the E's top bar, scanned down a column 60% of the way
  // ACROSS the letter. The first version of this scanned 12px inside the left edge,
  // where the top bar and the vertical stem are the same ink — so the run ran down
  // the stem and reported 573 units, most of the cap height, as a "bar weight". A
  // scan line has to be placed where only the feature being measured exists.
  const e = read("E");
  const barX = Math.round(e.x0 + (e.x1 - e.x0) * 0.6);
  let bar = 0;
  for (let py = e.y0; py <= e.y1; py++) { if (e.on(barX, py)) bar++; else if (bar) break; }
  // Vertical stem weight: the D's left stem, measured horizontally a third down.
  const dG = read("D");
  const scanY = Math.round(dG.y0 + (dG.y1 - dG.y0) / 3);
  let stem = 0;
  for (let px = dG.x0; px <= dG.x1; px++) { if (dG.on(px, scanY)) stem++; else if (stem) break; }
  const z = read("Z");
  return { bar, stem, capPx: e.y1 - e.y0 + 1, zW: z.x1 - z.x0 + 1 };
});

const toU = (px) => (px / 300) * UPM;        // device px at 300px type → font units
const barU = toU(metrics.bar), stemU = toU(metrics.stem);
console.log(`measured from the face at 300px:`);
console.log(`  cap ${metrics.capPx}px = ${toU(metrics.capPx).toFixed(0)} units (font says ${CAP})`);
console.log(`  horizontal bar ${metrics.bar}px = ${barU.toFixed(0)} units`);
console.log(`  vertical stem  ${metrics.stem}px = ${stemU.toFixed(0)} units`);
console.log(`  the face's Z ink is ${metrics.zW}px wide = ${toU(metrics.zW).toFixed(0)} units`);

// ── Draw the replacement ────────────────────────────────────────────────────
// A Z is misread as a 2 when its top-left terminal curves and its bottom is not a
// full straight bar — that is what the face's Z does. This one is drawn with the two
// things that make a Z unambiguous: SQUARE terminals on both bars, and a bottom bar
// that runs the full width. Everything else is the face's: the cap, the bar weight,
// the advance, and a diagonal cut at the same angle as the face's own obliques.
const X0 = 32, X1 = 1033;                    // the face's own Z side bearings
const bar = Math.round(barU);
// A diagonal cut to the same numeric weight as a horizontal reads LIGHTER, because
// it is measured across its width rather than perpendicular to it. 1.35 is the
// horizontal cut that makes the perpendicular weight match at this angle.
const dx = Math.round(bar * 1.35);
const zPath = [
  `M ${X0} ${CAP}`,            // top bar, upper edge, left end
  `L ${X1} ${CAP}`,            // ... to the right end
  `L ${X1} ${CAP - bar}`,      // down the top bar's right end
  `L ${X0 + dx} ${bar}`,       // the diagonal's upper-right side, down to the left
  `L ${X1} ${bar}`,            // along the bottom bar's top edge, back to the right
  `L ${X1} 0`,                 // down the bottom bar's right end
  `L ${X0} 0`,                 // bottom bar, lower edge, full width
  `L ${X0} ${bar}`,            // up the bottom bar's left end
  `L ${X1 - dx} ${CAP - bar}`, // the diagonal's lower-left side, up to the right
  `L ${X0} ${CAP - bar}`,      // along the top bar's under edge, back to the left
  `Z`,
].join(" ");

// SVG's y runs down and the font's runs up, so the glyph is flipped in the viewBox.
// `capPx` is the CAP height the glyph must match, so the box is CAP tall and its
// width follows the viewBox's own ratio, ADV/CAP. The first version set the width
// from ADV/UPM instead — 1.065 x cap where 1.521 x cap was needed — and since
// preserveAspectRatio defaults to "meet", the glyph shrank to fit the narrow box and
// sat centred in the slack. It looked like a badly drawn Z; it was a badly sized box.
const svgZ = (capPx, ink) =>
  `<svg class="wm-z" width="${(capPx * ADV / CAP).toFixed(3)}" height="${capPx.toFixed(3)}" ` +
  `viewBox="0 -${CAP} ${ADV} ${CAP}" aria-hidden="true" focusable="false" ` +
  `style="vertical-align:baseline;overflow:visible;">` +
  `<g transform="scale(1,-1)"><path d="${zPath}" fill="${ink}"></path></g></svg>`;

// ── Look at it beside the original, at the sizes that matter ────────────────
const row = (label, html) =>
  `<div style="display:flex;align-items:center;gap:24px;padding:10px 18px;">` +
  `<span style="font:12px ui-monospace,monospace;color:#818181;width:150px;">${label}</span>${html}</div>`;
// One inline run, so the override sits in the text flow on the same baseline as the
// letters either side rather than being a flex item beside them.
const word = (px, corrected) =>
  `<span style="font-family:'IOI Display';font-size:${px}px;line-height:1;letter-spacing:0.01em;` +
  `color:#0a0e19;white-space:nowrap;">` +
  `decentrali${corrected ? svgZ(px * CAP / UPM, "#0a0e19") : "z"}ed` +
  `</span>`;

await page.setContent(`<style>
@font-face{font-family:"IOI Display";src:url(data:font/ttf;base64,${b64}) format("truetype");}
body{margin:0;background:#fff;}
#warm{font-family:"IOI Display";font-size:40px;position:absolute;left:-9999px;}
</style><div id="warm">DZI</div><div id="sheet" style="width:max-content;padding:14px;background:#fff;">
${row("face's Z, 64px", word(64, false))}
${row("override, 64px", word(64, true))}
${row("face's Z, 22px", word(22, false))}
${row("override, 22px", word(22, true))}
${row("face's Z, 13px", word(13, false))}
${row("override, 13px", word(13, true))}
</div>`);
await page.waitForFunction(() => document.fonts.ready.then(() => true));
await page.evaluate(() => document.fonts.load('64px "IOI Display"'));
await page.waitForTimeout(300);
if (!(await page.evaluate(() => document.fonts.check('64px "IOI Display"')))) {
  console.error("REFUSING: the face did not load for the specimen.");
  await browser.close();
  process.exit(1);
}
writeFileSync(path.join(OUT, "z-override.png"), await page.locator("#sheet").screenshot());
console.log(`\nspecimen: ${path.relative(process.cwd(), path.join(OUT, "z-override.png"))} — LOOK at it before shipping this.`);

if (process.argv.includes("--emit")) {
  console.log(`\n── the override, for public/index.html ──`);
  console.log(`viewBox="0 -${CAP} ${ADV} ${CAP}"  advance ${ADV}/${UPM} em  bar ${bar} units`);
  console.log(zPath);
}
await browser.close();
