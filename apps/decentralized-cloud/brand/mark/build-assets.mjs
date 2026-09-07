// WRITES THE DOWNLOADABLE BRAND ASSETS from mark.mjs into public/brand/.
//
// Every file here is DERIVED. Editing one by hand makes it disagree with the shell,
// which draws from the same module; `--check` regenerates in memory and fails if any
// file on disk differs, and the package's check script runs it so a hand edit goes
// red before it ships.
//
// Usage: node apps/decentralized-cloud/brand/mark/build-assets.mjs [--check]

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BLOCK, LOCKUP_WIDTH, LOCKUP_HEIGHT, LOCKUP_MARK_SCALE, LOCKUP_WORDMARK_X, LOCKUP_WORDMARK_Y,
  WORDMARK_X, DOT_PATH, SUBSTRATE_NAVY, WHITE, BLACK,
  MARK_PATHS, derivedMarkPaths,
  gradientDefs, markDefs, markPaths, markSvg, glyphSvg, appIconSvg,
} from "./mark.mjs";

// The literal paths and the circles they were written from must agree, or the shell
// draws one cloud and this file documents another.
if (JSON.stringify(MARK_PATHS) !== JSON.stringify(derivedMarkPaths())) {
  throw new Error("MARK_PATHS literals disagree with CLOUD_CIRCLES / CLOUD_RECT in mark.mjs");
}
import { DECENTRALIZED_PATHS, CLOUD_PATHS } from "./wordmark-outlines.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "../../public/brand");

// The full lockup at the owner's proportions: the mark at 2.65× the wordmark block,
// the wordmark one gap of 7.5% of the mark's width after it, centred on the mark's
// height. `ink` is the wordmark colour; the dot is always the gradient.
const lockupSvg = ({ ink, id }) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${LOCKUP_WIDTH} ${LOCKUP_HEIGHT}" role="img" aria-label="decentralized.cloud">\n` +
  `<defs>${markDefs("gradient", id)}${gradientDefs(`${id}-dot`)}</defs>\n` +
  `<g id="mark" transform="scale(${LOCKUP_MARK_SCALE})">${markPaths("gradient", id)}</g>\n` +
  `<g id="wordmark" transform="translate(${(LOCKUP_WORDMARK_X - WORDMARK_X).toFixed(3)} ${LOCKUP_WORDMARK_Y})">\n` +
  `<g fill="${ink}">\n` +
  `<g id="decentralized">${DECENTRALIZED_PATHS.map((d) => `<path d="${d}"/>`).join("")}</g>\n` +
  `<g id="cloud">${CLOUD_PATHS.map((d) => `<path d="${d}"/>`).join("")}</g>\n` +
  `</g>\n` +
  `<path id="dot" fill="url(#${id}-dot)" d="${DOT_PATH}"/>\n` +
  `</g>\n` +
  `</svg>\n`;

// The wordmark alone, translated so its ink starts at x=0.
const wordmarkSvg = ({ ink, id }) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${(559.046 - WORDMARK_X).toFixed(3)} ${BLOCK}" role="img" aria-label="decentralized.cloud">\n` +
  `<defs>${gradientDefs(id)}</defs>\n` +
  `<g transform="translate(${-WORDMARK_X} 0)">` +
  `<g fill="${ink}">${[...DECENTRALIZED_PATHS, ...CLOUD_PATHS].map((d) => `<path d="${d}"/>`).join("")}</g>` +
  `<path fill="url(#${id})" d="${DOT_PATH}"/></g>\n</svg>\n`;

export const ASSETS = {
  "lockup-dark.svg": lockupSvg({ ink: WHITE, id: "g" }),
  "lockup-light.svg": lockupSvg({ ink: BLACK, id: "g" }),
  "wordmark-dark.svg": wordmarkSvg({ ink: WHITE, id: "g" }),
  "wordmark-light.svg": wordmarkSvg({ ink: BLACK, id: "g" }),
  "mark.svg": markSvg({ fill: "gradient", id: "g" }) + "\n",
  "mark-mono-white.svg": markSvg({ fill: WHITE, id: "m" }) + "\n",
  "mark-mono-navy.svg": markSvg({ fill: SUBSTRATE_NAVY, id: "m" }) + "\n",
  "app-icon.svg": appIconSvg({ id: "g" }) + "\n",
  "favicon.svg": glyphSvg({ fill: "gradient", id: "g", size: 96 }) + "\n",
  "glyph-mono-white.svg": glyphSvg({ fill: WHITE, id: "m", size: 96 }) + "\n",
  "glyph-mono-navy.svg": glyphSvg({ fill: SUBSTRATE_NAVY, id: "m", size: 96 }) + "\n",
};

const check = process.argv.includes("--check");
mkdirSync(OUT, { recursive: true });
let drift = [];
for (const [name, body] of Object.entries(ASSETS)) {
  const file = path.join(OUT, name);
  if (check) {
    const onDisk = existsSync(file) ? readFileSync(file, "utf8") : null;
    if (onDisk !== body) drift.push(name);
  } else {
    writeFileSync(file, body);
  }
}
if (check) {
  if (drift.length) {
    console.error(`brand assets drifted from brand/mark/mark.mjs: ${drift.join(", ")} — run build-assets.mjs`);
    process.exit(1);
  }
  console.log(`brand assets: ${Object.keys(ASSETS).length} files match their one source`);
} else {
  console.log(`wrote ${Object.keys(ASSETS).length} files to ${OUT}`);
}
