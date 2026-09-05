#!/usr/bin/env node
// Generates the nine direction artboards from ONE lockup and ONE set of brand
// constants, so the identity is pixel-identical across all of them and cannot drift
// between hand-copies — the same reason the shipped Lockup component imports
// wordmark.mjs instead of restating the paths.
//
// The artboards are the working files; this is what writes them.

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "../..");

// The real brand face, embedded, because the wordmark is set in it and an approximation
// of a wordmark is not a wordmark. 8.5 KB of TTF.
const IOI_B64 = readFileSync(path.join(HERE, "ioi-ttf.b64"), "utf8").trim();

// From brand/wordmark/wordmark.mjs. The Z and the I are DRAWN, not set: the face's own
// Z reads as a 2 and its I is a bare rectangle that reads as a 1, and three fresh
// readers typed digits for both. These two paths are the adopted overrides.
const CAP = 700, UPM = 1000;
const Z_PATH = "M 32 700 L 1033 700 L 1033 560 L 270 140 L 1033 140 L 1033 0 " +
               "L 32 0 L 32 140 L 795 560 L 32 560 Z";
const I_PATH = "M 32 700 L 588 700 L 588 500 L 379.5 500 L 379.5 200 L 588 200 " +
               "L 588 0 L 32 0 L 32 200 L 240.5 200 L 240.5 500 L 32 500 Z";
const Z_ADVANCE = 1065, I_ADVANCE = 620;
const DOT_D = 0.137, DOT_SIDE = 0.10, DOT_RAISE = 0.2815;

// The owner's reserved mark, carried across unchanged. Not mine to redraw.
const MARK = (size, tile, glyph) => `
<svg width="${size}" height="${size}" viewBox="0 0 96 96" role="img" aria-label="decentralized.cloud" style="display:block;flex-shrink:0">
  <defs><mask id="cc-${size}-${tile.replace(/[^a-z0-9]/gi, "")}" maskUnits="userSpaceOnUse" x="-20" y="-20" width="136" height="136">
    <rect x="-20" y="-20" width="136" height="136" fill="#ffffff"></rect>
    <rect x="65.38" y="24.03" width="15" height="6.2" rx="3.1" fill="#000000"></rect>
  </mask></defs>
  <rect x="0" y="0" width="96" height="96" rx="11" fill="${tile}"></rect>
  <g mask="url(#cc-${size}-${tile.replace(/[^a-z0-9]/gi, "")})"><g transform="translate(9.500 13.743) scale(0.71369)">
    <path d="M 41.44 0.00 C 38.66 0.00 36.33 2.13 36.09 4.90 L 34.09 27.84 L 79.17 27.84 L 75.70 67.48 L 103.42 67.48 L 107.83 17.16 C 108.63 7.94 101.36 0.00 92.10 0.00 Z" fill="${glyph}"></path>
    <path d="M 10.57 27.84 C 7.79 27.84 5.46 29.97 5.22 32.75 L 3.14 56.51 L 26.66 56.51 C 29.45 56.51 31.77 54.39 32.01 51.61 L 34.09 27.84 Z" fill="${glyph}"></path>
    <path d="M 17.71 68.00 C 8.93 68.07 1.66 74.86 0.97 83.61 L 0.00 96.00 L 73.47 96.00 L 75.71 67.47 Z" fill="${glyph}"></path>
  </g></g>
</svg>`;

// THE WORDMARK, SET ENTIRELY IN IOI.TTF — owner ruling, 2026-09-05.
//
// One text run in the face, unaltered. The drawn I and the redrawn Z are GONE.
//
// The cost is recorded rather than hidden, because the owner chose it knowingly: on
// narrow plates at 16px, three fresh readers transcribed the face's own Z as "2" and
// two transcribed its bare-stem I as "l" or "1" — the brand's name misspelled by the
// brand's own typeface. The overrides existed to fix precisely that, and were the only
// reader-granted pass this programme produced.
//
// The owner has chosen the face's authenticity over that legibility cost. That is
// theirs to choose. My job is that the choice stays legible and reversible: the
// evidence sits on the identity sheet beside the ruling, and the paths are archived
// rather than deleted.
//
// THE PERIOD IS STILL DRAWN, and only because IOI.ttf carries no U+002E at all — a
// mechanical necessity, not a design change. Medial, at stem weight, in ink.
const WORDMARK = (px, ink) => {
  const dot = (px * DOT_D).toFixed(2);
  return `<div style="display:flex;align-items:baseline;gap:0;font-family:'IOI Display',sans-serif;font-size:${px}px;line-height:1;letter-spacing:0.01em;color:${ink}" aria-hidden="true">
    <span>decentralized</span><span style="position:relative;display:inline-block;width:${dot}px;height:${dot}px;border-radius:50%;background:currentColor;margin:0 ${(px * DOT_SIDE).toFixed(2)}px;top:-${(px * DOT_RAISE).toFixed(2)}px"></span><span>cloud</span>
  </div>`;
};

const LOCKUP = (px, ink, tile, glyph) =>
  `<div style="display:flex;align-items:center;gap:${(px * 0.42).toFixed(0)}px">${MARK(Math.round(px * 1.41), tile, glyph)}${WORDMARK(px, ink)}</div>`;

const FONTFACE = `@font-face{font-family:"IOI Display";src:url(data:font/ttf;base64,${IOI_B64}) format("truetype");font-weight:400 700;font-display:block}`;

const shell = (bodyStyle, helmetExtra, inner) => `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <script src="./support.js"></script>
</head>
<body>
<x-dc>
<helmet>
  <style>
    ${FONTFACE}
    ${helmetExtra}
    body { margin: 0; ${bodyStyle} }
    a { color: inherit; text-decoration: none; }
    a:hover { text-decoration: underline; }
    * { box-sizing: border-box; }
  </style>
</helmet>
${inner}
</x-dc>
</body>
</html>
`;

export { shell, LOCKUP, MARK, WORDMARK };



// Exported for directions.mjs, which authors the artboard bodies.
