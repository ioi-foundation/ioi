// THE WORDMARK SPEC — one source.
//
// This module exists because of a specific failure. The wordmark's Z was fixed on
// the shipped surface and not in the harness that plates the lockups readers judge,
// so round four's lockup half was tested against a name that misspelled itself and
// had to be voided. The first repair was to copy the constants into both files with
// a note saying they must agree. That is not one source; it is two sources and a
// wish. ioi-e1's ruling: one module, and the shipped copy is checked against it
// mechanically rather than by comment.
//
// `public/index.html` is static and cannot import this, so the enforcement is the
// other way round: `verify-decentralized-cloud-face.mjs` asserts the shipped markup
// carries exactly the values below. If they drift, the gate fails — which is the
// only arrangement in which "one source" is a fact rather than an intention.
//
// Every number here was MEASURED off a 300px render of IOI.ttf by
// compose-z-override.mjs, not chosen. The font's own tables gave the rest.

// ── The face, from its own tables ───────────────────────────────────────────
export const UPM = 1000;
export const CAP = 700;          // measured 693 at 300px; the font declares 700
export const STEM = 137;         // vertical stroke, measured off the D
export const BAR = 140;          // horizontal stroke, measured off the E
export const Z_ADVANCE = 1065;   // the face's own Z advance
export const Z_BEARINGS = [32, 1033];

// IOI Display is UNICASE — U+005A and U+007A are one glyph, gid 30 — and it carries
// NO DIGITS and NO PERIOD: U+0032 and U+002E both map to .notdef. Those are facts
// about the file, not style choices, and they are why the period is drawn and why a
// digit set in this face is silently somebody else's glyph.
export const FACE_HAS_NO_DIGITS = true;
export const FACE_HAS_NO_PERIOD = true;

// ── The drawn Z ─────────────────────────────────────────────────────────────
// The face's own Z has a curved upper-left terminal and reads as a numeral 2: four
// independent reviewers read this wordmark as "DECENTRALI2ED". This replacement
// keeps the face's cap, bar weight, advance and side bearings — so the fitting does
// not change — and differs in the two things that make a Z a Z: square terminals on
// both bars, and a bottom bar that runs the full width. The diagonal is cut 1.35x
// the bar horizontally, because a diagonal at a horizontal's numeric weight reads
// lighter. Owner-reversible; IOI.ttf is untouched.
//
// REVISED 2026-09-04 by a swept round rather than by a redraw. Twenty Z variants —
// the face's own, the override above, and eighteen generated across bar weight,
// diagonal weight and elbow inset — were shown to three fresh readers as the cluster
// "alized" ALONE, at a true 13px and 16px, magnified by a whole number with
// nearest-neighbour on plates narrow enough that nothing resampled before the reader
// saw them. (That last clause is not decoration: the previous round's plates were
// wide enough to be downsampled in delivery, and the blur it added is what made three
// readers report a Z fault that the narrow plates do not reproduce. My instrument
// manufactured part of the defect it was measuring.)
//
// Every reader typed a DIGIT for exactly one variant, and it was the face's own Z:
// "ALI2ED", three times out of three. Every other variant, this override included,
// read as Z.
//
// The three agreed on the mechanism, independently, and it is not what this file
// assumed. It is not the terminals and not the bottom bar's width. Reader G: "the top
// bar does not stop and turn down into the diagonal at a hard right angle — it bends
// ... It is a bend versus a corner, and at 13px the bend wins." Reader H: "the
// difference between 'corner' and 'one pixel of rounding at the corner' is the whole
// identity of the letter."
//
// The path below is the ONLY variant all three readers placed in their best group —
// the group where no alternative reading ever crossed their mind. It differs from the
// previous override in exactly one number: the diagonal is cut 1.7x the bar rather
// than 1.35x. The elbow stays FLUSH with the corners, because every inset-elbow
// variant was flagged by two readers as "the darkest spot in the word" — the inset
// makes the junction heavy, and a heavy junction is the bend again.
export const Z_DIAGONAL_CUT_MULTIPLE = 1.7;   // of BAR, cut horizontally
export const Z_PATH =
  "M 32 700 L 1033 700 L 1033 560 L 270 140 L 1033 140 L 1033 0 " +
  "L 32 0 L 32 140 L 795 560 L 32 560 Z";

// ── The drawn I ─────────────────────────────────────────────────────────────
// The face's I is literally `M32 0 L32 700 L171 700 L171 0 Z` — a bare rectangle,
// 139 units wide on a 700 cap. It is not a stylised I that happens to resemble a
// numeral; it is the same shape as one. Two readers typed back `DECENTRAL1ZED`, and
// with the face's Z that compounds: "a barred Z next to a numeral-looking I gives
// AL1ƵED — not two problems, one compound problem."
//
// An earlier drawn I was ruled a NULL RESULT and the letter was left alone. That
// ruling was wrong, and it was wrong for a reason worth keeping: it rested on plates
// wide enough to be downsampled in delivery — the same instrument fault that
// manufactured part of the Z finding beside it. On narrow plates the fault came
// straight back. Reader S, transcribing the wordmark cold at 16px: "DECENTRAL12ED".
//
// So the I was swept the way the Z was: ten variants, the face's own bare stem
// carried as the incumbent, one magnification for the whole set (the first attempt
// let each plate pick its own, and both readers named the scale difference before
// they named anything about the letter — a comparison set that varies in scale is a
// comparison of scale).
//
// TWO FRESH READERS INDEPENDENTLY CHOSE THIS DRAWING, and both put the bare stem in
// their worst group, reading it as a lowercase l or a numeral 1.
//
//   reader V, on the incumbent: "a naked stem carries no capital-ness: it is exactly
//     the shape a lowercase l would take, and it sits in a word where an l is
//     perfectly plausible."
//   reader X, on this variant: "crossbars long enough that no alternative reading
//     occurred to me, while the bars stay in the same weight band as the L's foot and
//     the E's arms, so the letter does not spot the line."
//
// Both also named the trade, and it is why the bars are 4x the stem and not 4.8x:
// the widest, heaviest variants read as "a serif-font gesture" dropped into a
// geometric sans — "the best legibility in the set is bought with the clearest
// stylistic foreignness" (V). This is the drawing where neither complaint fires.
//
// Every number is the face's own: stem 139 measured off its outline, cap 700, left
// bearing 32. Bars run 4x the stem and 200 units deep. IOI.ttf is UNTOUCHED.
export const I_STEM = 139;
export const I_BAR_MULTIPLE = 4.0;
export const I_BAR_DEPTH = 200;
export const I_ADVANCE = I_STEM * I_BAR_MULTIPLE + 64;      // 620
export const I_PATH =
  "M 32 700 L 588 700 L 588 500 L 379.5 500 L 379.5 200 L 588 200 " +
  "L 588 0 L 32 0 L 32 200 L 240.5 200 L 240.5 500 L 32 500 Z";

// ── The drawn period ────────────────────────────────────────────────────────
// MEDIAL, per the standing spec it had drifted from, and cut to the face's stem.
// Its centre sits at half the cap, which is the optical centre of a band where every
// letter is a cap. It is INK, not green: on this surface green marks live evidence
// and nothing else, so a green dot in the brand is chrome making an evidence claim.
export const DOT_DIAMETER_EM = STEM / UPM;        // 0.137em
export const DOT_CENTRE_EM = (CAP / UPM) / 2;     // 0.35em above the baseline
export const DOT_SIDE_EM = 0.10;
export const DOT_RAISE_EM = DOT_CENTRE_EM - DOT_DIAMETER_EM / 2;   // 0.2815em

// ── Lockup geometry ─────────────────────────────────────────────────────────
// The old rule set the mark at 1.25-1.35x the cap. Two rounds of readers found that
// rule produces a mark nobody can see, and both independently worked out why: the
// name is 18 letters plus a separator on one line, so the wordmark's aspect ratio is
// around 20:1 and ANY mark locked to cap height is arithmetically ~5% of the lockup.
// One reader: "you could double every one of these marks and they'd still read as a
// bullet point." That is a fault in the rule, not in a drawing.
//
// Restated by ioi-e1: the single-line lockup sets the mark at one EM as a FLOOR, and
// balance is judged by MASS — the mark's ink area against the wordmark's, measured
// on the render — not by cap ratio. Where a single line would put the mark below one
// em, the STACKED form is primary and the mark stands at the full two-line height.
export const SINGLE_LINE_MARK_EM = 1.0;
export const STACKED_MARK_LINES = 2;
// The word is not stored as a string anywhere here on purpose: the Z is a drawn
// glyph, not a character, so "decentralized" as text would be the broken form again
// the moment anyone rendered it. The renderers below set it in three pieces.

// ── Rendering ───────────────────────────────────────────────────────────────
// One renderer, used by every plate. `ink` is passed in so a reversed form does not
// need a second copy of any of this.
export function zGlyphSvg(capPx, ink) {
  return `<svg width="${(capPx * Z_ADVANCE / CAP).toFixed(3)}" height="${capPx.toFixed(3)}" ` +
    `viewBox="0 -${CAP} ${Z_ADVANCE} ${CAP}" aria-hidden="true" focusable="false" ` +
    `style="vertical-align:baseline;overflow:visible;flex-shrink:0;">` +
    `<g transform="scale(1,-1)"><path d="${Z_PATH}" fill="${ink}"></path></g></svg>`;
}

export function dotSpan(typePx, ink) {
  const d = typePx * DOT_DIAMETER_EM;
  return `<span style="display:inline-block;width:${d.toFixed(2)}px;height:${d.toFixed(2)}px;` +
    `border-radius:50%;background:${ink};margin:0 ${(typePx * DOT_SIDE_EM).toFixed(2)}px;` +
    `position:relative;top:-${(typePx * DOT_RAISE_EM).toFixed(2)}px;"></span>`;
}

const typeStyle = (typePx, ink) =>
  `font-family:'IOI Display';font-size:${typePx}px;line-height:1;` +
  `letter-spacing:0.01em;white-space:nowrap;color:${ink};`;

// The single line: decentrali · [drawn Z] · ed · [drawn period] · cloud
export function wordmarkSingle(typePx, ink) {
  return `<div style="display:flex;align-items:baseline;${typeStyle(typePx, ink)}">` +
    `<span>decentrali</span>${zGlyphSvg(typePx * CAP / UPM, ink)}<span>ed</span>` +
    `${dotSpan(typePx, ink)}<span>cloud</span></div>`;
}

// The stacked form: DECENTRALIZED over .CLOUD, the period LEADING line two, because
// that is where a domain's dot belongs when the name breaks — it separates, and a
// separator stranded at the end of line one separates nothing.
export function wordmarkStacked(typePx, ink) {
  return `<div style="display:flex;flex-direction:column;align-items:flex-start;gap:${(typePx * 0.14).toFixed(2)}px;">` +
    `<div style="display:flex;align-items:baseline;${typeStyle(typePx, ink)}">` +
    `<span>decentrali</span>${zGlyphSvg(typePx * CAP / UPM, ink)}<span>ed</span></div>` +
    `<div style="display:flex;align-items:baseline;${typeStyle(typePx, ink)}">` +
    `${dotSpan(typePx, ink)}<span>cloud</span></div></div>`;
}
