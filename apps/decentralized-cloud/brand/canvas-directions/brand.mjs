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

// THE MARK — direction B, the dissolving cloud. Owner reference, head-to-head winner.
//
// Two blind readers picked it over the isometric blocks, both on survival and both
// unhappy about it. Reader two: "a mark that requires three greys to be itself is not
// a logo" (of A), and "picking RIGHT is picking a mark that is legible and meaningless
// over one that is meaningful and illegible."
//
// NEITHER PASSED SECOND SIGHTING. That is recorded here rather than in a footnote,
// because this drawing now sits at the head of every surface and whoever reads this
// file next should know what it cleared and what it did not: "Blunt: neither mark
// passes second-sighting. Both are category pictures."
//
// Imported from marks.mjs so the canvas, the plate and the shell all draw the same
// geometry — the reason the shipped Lockup imports wordmark.mjs rather than restating
// its paths.
import { dissolvingCloud } from "./marks.mjs";

const MARK = (size, tile, glyph) =>
  dissolvingCloud({ size, tile: tile === glyph ? null : tile, mono: glyph === "#ffffff" && tile === "#0a0e19" ? "#ffffff" : null });

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

// THE LOCKUP, resized on both readers' unprompted verdict.
//
// Reader one: "the mark reads as a bullet point before a long line of type rather than
// a co-equal element." Reader two: "Both marks want to be ~15% larger and aligned to
// cap height, not to the full lockup box."
//
// They agreed without being asked and while disagreeing about almost nothing else, and
// it is a LOCKUP fault rather than a mark fault — both candidates shared it, so it
// survived whichever won. 1.41x -> 1.62x, and the mark is aligned to the wordmark's cap
// height rather than centred on a box whose height includes the descender-free face's
// full line, which is what made it sit low and small.
const LOCKUP = (px, ink, tile, glyph) =>
  `<div style="display:flex;align-items:center;gap:${(px * 0.38).toFixed(0)}px">${MARK(Math.round(px * 1.62), tile, glyph)}${WORDMARK(px, ink)}</div>`;

const FONTFACE = `@font-face{font-family:"IOI Display";src:url(data:font/ttf;base64,${IOI_B64}) format("truetype");font-weight:400 700;font-display:block}`;

// THE <link> GOES OUTSIDE THE <style>, and this was a real bug in my own artboards.
//
// `helmetExtra` began with a `<link rel="stylesheet">` to Google Fonts and was
// interpolated INSIDE the `<style>` block — so the browser parsed the link tag as CSS
// text, dropped it, and every headline rendered in a fallback serif. Not the shooter's
// fault and not a timing problem: `document.fonts.ready` reported "loaded" because the
// font was never requested at all. The direction I would have put in front of readers
// was not the direction I specified, and it would have shipped that way in the
// published canvas too.
//
// The tell was that a timing theory explained it and the evidence did not — fonts
// reported loaded and the type was still wrong. Two instruments disagreeing is the
// signal to stop and look, not to lengthen the wait.
const shell = (bodyStyle, links, css, inner) => `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <script src="./support.js"></script>
</head>
<body>
<x-dc>
<helmet>
  ${links}
  <style>
    ${FONTFACE}
    ${css}
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
