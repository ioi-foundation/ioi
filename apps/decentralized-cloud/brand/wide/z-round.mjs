#!/usr/bin/env node
// THE Z ROUND — sweep the one glyph three readers actually misread.
//
// Round one's wordmark read produced two results and they point the same way. The
// drawn I was a NULL RESULT: three readers, three sizes each, no perceptible
// difference, and at 16px its serifs are three-pixel nubs, so that is honest rather
// than surprising. The Z was the defect all three found, WITH the existing override
// already in place:
//
//   reader D  "The Z is the real defect, not the I... its top and bottom bars are
//              flat and full-width, which is exactly the skeleton of a squared 2.
//              Whatever A/B is testing, it is testing the wrong character."
//   reader E  transcribed DECENTRALIZ2D on first pass at 13px
//   reader F  transcribed DeCeNTRAL12eD at 16px
//
// So this sweeps the Z the way round one swept the marks — generate wide, filter
// cheap — instead of drawing one more override and hoping.
//
// PLATE DELIVERY, which round one got wrong. All three readers said the plates
// looked interpolated rather than nearest-neighbour, and they were right: a 4x
// magnification of an eighteen-character line is ~1300px wide and gets downsampled
// before it reaches a reader, which undoes the magnification and hands them a
// blurred artifact while the caption promises exact pixels. Everything here is a
// narrow CLUSTER, magnified 8x, kept under 800px wide, so no resampling happens
// between the render and the eye.

import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CAP, BAR, STEM, UPM, Z_PATH as Z_CURRENT, Z_ADVANCE, Z_BEARINGS } from "../wordmark/wordmark.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../.artifacts/z-round");
mkdirSync(OUT, { recursive: true });
for (const f of readdirSync(OUT)) rmSync(path.join(OUT, f), { force: true });
const FONT_B64 = readFileSync(path.join(HERE, "../../public/fonts/IOI.ttf")).toString("base64");
const INK = "#0d0f12";
const [L, R] = Z_BEARINGS;

// ── The variants ────────────────────────────────────────────────────────────
// Each is built from the face's own metrics — cap 700, bar 140, stem 137, advance
// 1065, bearings 32/1033 — so the fitting of the word never changes and a difference
// a reader reports is a difference in the drawing.
//
// The parameters are the three things that separate a Z from a 2 in a squared face:
//
//   bar       how heavy the two horizontals are. A 2's bottom bar is its heaviest
//             stroke; a Z's three strokes are closer to even.
//   diagonal  how heavy the diagonal is relative to the bar. The existing override
//             cuts it 1.35x because a diagonal at a horizontal's numeric weight
//             reads lighter — that finding is kept and swept rather than assumed.
//   elbow     where the diagonal meets each bar. Flush at the extreme corners is the
//             skeleton of a Z; inset from them is the skeleton of a 2, whose diagonal
//             springs from a bowl rather than from the corner. This is the parameter
//             the existing override never varied, and it is the one the readers'
//             description points at.
function zPath({ bar, diagMul, elbowTop, elbowBot }) {
  const top = CAP, bot = 0;
  const barW = bar;
  const cut = barW * diagMul;                    // horizontal cut of the diagonal
  // The diagonal runs from the top bar's underside to the bottom bar's topside.
  const yTop = top - barW, yBot = bot + barW;
  const xTopRight = R - elbowTop * (R - L);      // where it leaves the top bar
  const xBotLeft = L + elbowBot * (R - L);       // where it lands on the bottom bar
  return (
    `M ${L} ${top} L ${R} ${top} L ${R} ${yTop} ` +
    `L ${(xBotLeft + cut).toFixed(1)} ${yBot} L ${R} ${yBot} L ${R} ${bot} ` +
    `L ${L} ${bot} L ${L} ${yBot} ` +
    `L ${(xTopRight - cut).toFixed(1)} ${yTop} L ${L} ${yTop} Z`
  );
}

const VARIANTS = [];
for (const bar of [140, 170]) {
  for (const diagMul of [1.0, 1.35, 1.7]) {
    for (const elbow of [0, 0.12, 0.24]) {
      VARIANTS.push({
        id: `Z-b${bar}-d${String(diagMul).replace(".", "")}-e${String(elbow).replace(".", "")}`,
        path: zPath({ bar, diagMul, elbowTop: elbow, elbowBot: elbow }),
        note: `bar ${bar}, diagonal ${diagMul}x bar, elbow inset ${elbow}`,
      });
    }
  }
}
// The two incumbents, carried so the round is measured against what exists rather
// than against nothing. The face's own Z is set as TEXT, not as a path, because that
// is how it actually ships.
const INCUMBENTS = [
  { id: "Z-face", path: null, note: "the face's own Z, set as text — the shape four readers called a 2" },
  { id: "Z-override", path: Z_CURRENT, note: "the override on the branch today — square terminals, full-width bottom bar, diagonal 1.35x" },
];

const glyphSvg = (d, capPx) =>
  `<svg width="${(capPx * Z_ADVANCE / CAP).toFixed(3)}" height="${capPx.toFixed(3)}" ` +
  `viewBox="0 -${CAP} ${Z_ADVANCE} ${CAP}" style="vertical-align:baseline;overflow:visible;flex-shrink:0;">` +
  `<g transform="scale(1,-1)"><path d="${d}" fill="${INK}"></path></g></svg>`;

const typeStyle = (px) =>
  `font-family:'IOI Display';font-size:${px}px;line-height:1;letter-spacing:0.01em;` +
  `white-space:nowrap;color:${INK};`;

// The cluster a reader is shown: the letters either side of the Z and nothing else.
// "ALIZED" is where every reported misreading happened, and showing it alone denies
// the reader the rest of the word to guess from — which is the whole point of the
// type-what-you-see instrument.
function cluster(v, px) {
  const z = v.path ? glyphSvg(v.path, px * CAP / UPM) : null;
  return `<div style="display:flex;align-items:baseline;${typeStyle(px)}">` +
    `<span>ali</span>${z || "<span>z</span>"}<span>ed</span></div>`;
}

const { chromium } = await import(
  "/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs"
);
const browser = await chromium.launch({
  args: ["--disable-lcd-text", "--disable-font-subpixel-positioning", "--font-render-hinting=none"],
});
const page = await browser.newPage({ viewport: { width: 1200, height: 900 }, deviceScaleFactor: 1 });

// The ceiling that matters is the plate WIDTH, not the magnification: see plate().
const MAG = 8;
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
  // The magnification is the largest WHOLE number that keeps the plate under the
  // ceiling. Whole numbers only: a fractional scale resamples, which is the fault
  // being fixed. Dropping from 8x to 7x costs nothing a reader can use — the pixels
  // are the same pixels — whereas trimming the cluster would cost the reader the
  // letters either side of the Z, which is the entire instrument.
  const mag = Math.max(1, Math.floor(800 / box.width));
  if (mag < 4)
    throw new Error(
      `plate ${name} can only take ${mag}x before passing the 800px ceiling, and below ` +
      `4x the magnification stops showing a reader the device pixels. Narrow the cluster.`
    );
  const w = Math.round(box.width * mag), h = Math.round(box.height * mag);
  await page.setContent(
    `<style>body{margin:0;background:#fff;}img{image-rendering:pixelated;display:block;}</style>` +
    `<div id="m" style="display:inline-block;padding:14px;background:#fff;">` +
    `<img src="data:image/png;base64,${buf.toString("base64")}" width="${w}" height="${h}"></div>`
  );
  const f = path.join(OUT, `${name}.png`);
  await page.locator("#m").screenshot({ path: f });
  return { f, w, h, mag };
}

const all = [...INCUMBENTS, ...VARIANTS];
console.log(`── ${all.length} Z variants (2 incumbents + ${VARIANTS.length} swept) ──`);
console.log(`magnification ${MAG}x nearest-neighbour, plates capped at 800px wide so`);
console.log(`nothing resamples between the render and the reader.\n`);

// The plates are written in a SHUFFLED, numbered order with the variant names kept
// out of the filenames, so a reader cannot infer from "Z-override" that it is the
// incumbent and grade it kindly. The key is printed here, for me, not for them.
const order = all.map((v, i) => ({ v, i }));
for (let i = order.length - 1; i > 0; i--) {
  const j = Math.floor(Math.random() * (i + 1));
  [order[i], order[j]] = [order[j], order[i]];
}

const key = [];
for (const px of [13, 16]) {
  for (let n = 0; n < order.length; n++) {
    const { v } = order[n];
    const label = `cluster-${px}px-${String(n + 1).padStart(2, "0")}`;
    const { w, mag } = await plate(label, cluster(v, px));
    if (px === 13) key.push(`  ${String(n + 1).padStart(2, "0")}  ${v.id}  —  ${v.note}`);
    if (n === 0) console.log(`  ${px}px plates: ${w}px wide at ${mag}x nearest-neighbour`);
  }
}
console.log(`\nplates: ${readdirSync(OUT).length} in ${OUT}`);
console.log(`\n── KEY (mine, not the reader's) ──`);
for (const k of key) console.log(k);
await browser.close();
