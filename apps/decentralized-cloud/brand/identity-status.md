# Identity status — not served

This file exists because `public/index.html` is served verbatim, so anything written
in it ships in view-source. An independent UX review found the identity's blind score
and an internal file path in the bytes a visitor receives — inside a comment asserting
that the label "belongs here … never on the surface a visitor reads." The comment was
true about intent and false about mechanism.

Everything below has been moved out of the served shell and lives here instead.

## The designer's mark — shipped 2026-09-07

The new-mark phase below closed without a mark. The owner's designer then delivered
one: `brand/mark/source/FInal-CLOUD-v3.svg` (2026-09-06) — three lobes of a cloud in
an indigo→cyan gradient, a two-line wordmark in IOI Display (the outlines in the file
are the face's own glyphs, verified glyph for glyph), and a gradient dot before CLOUD.
It ships in the header from 2026-09-07.

- **One source:** `brand/mark/mark.mjs` holds the lobes' paths verbatim and every
  measured layout number. The shell (`src/components/Lockup.jsx`), the asset builder
  (`brand/mark/build-assets.mjs` → `public/brand/*.svg`) and the face gate all import
  it. `check:decentralized-cloud-brand-assets` fails if a file on disk drifts.
- **Wordmark:** still live text in the face, one run per line, per the owner's ruling
  of 2026-09-05 — now two lines, set inside an SVG so each line is placed by its
  baseline (the face's hhea and Windows metrics disagree by 0.15em, so an HTML stack
  would sit differently per platform). `textLength` fits each run to the outlined
  lockup's width. The dot is the one drawn element and now carries the gradient.
- **Brand assets page:** `/brand/` on the served face (`public/brand/index.html`) —
  lockups, mark variants, wordmark, app icon, reduction glyph, colour tokens, rules,
  downloads. The favicon is the reduction glyph.
- **Tokens added** to `packages/design-system/tokens/colors.css`:
  `--color-dc-mark-indigo #3f3dfa`, `--color-dc-mark-cyan #41dbf9`,
  `--color-dc-substrate-navy #000c26`, `--color-dc-interior-indigo #0e2250`, with
  contrasts. `--brand-blue` (#0048ff) left the face; blue is still the identity only.
- **Not delivered:** the dimensional hover cloud (the designer's layered PNG
  reference) and an animated SVG mark. The brand page says so rather than showing a
  stand-in.
- **Honest floor:** the reduction glyph's knocked-out network holds to 32px; at 16px
  it reads as the closed cloud. No blind reader has scored this mark yet; the 51/100
  of the dissolving cloud it replaces is retired with it.

## Where the mark stands (before the designer's mark)

**identity v0 — provisional, scored 50 of 100** by blind review. The convergence cap
fired at 75, so iteration on that construction stopped and the face shipped with it.

The reviewer's remaining path, unchanged: a base form that does not collapse into the
duplicate-layers glyph and holds in one ink; the sibling cue carried into the lockups
rather than only into the tile; `.cloud` re-derived so it survives 16px on the pale
block; and a mark-to-cap ratio of 1.25–1.35, since one em sags out of the type band.
The identity sheet is `brand/round4/Main.dc.html`.

## The new-mark phase, so far

Three rounds, sixteen skeletons, four fresh cold readers. **No candidate has passed.**

- **Round one** — five skeletons. Four died; three were named as existing system
  controls by two readers independently with confidence *certain* (the share glyph,
  the align-left button, the apps grid), and the isometric slabs died earlier on
  measurement at 16px. Lesson: they shared a vocabulary — few, large, regular, centred
  elements — which is the vocabulary system icons are drawn in.
- **Round two** — six skeletons, that vocabulary banned. One survivor. Both readers
  then said, independently and unprompted, that four of the six were the same drawing:
  a dark mass with one small interior subtraction. Lesson, and the phase's principle:
  **at 16px an interior event is one to three device pixels, so the identity cannot
  live there — it lives in the outline.**
- **Round three** — five skeletons, silhouette-led, judged first as solid shapes with
  every counter closed. All five failed, alone and in lockup, from both readers. The
  new silhouette-distinctness probe killed the incumbent on its own terms: closing its
  counter leaves a shape **93.1% identical** (IoU at 16px) to a mark that never had
  one. One candidate was named by both readers as the IEC 5009 power symbol.

Round four is the last, by ioi-e1's cap. If it passes nothing, the phase returns for a
scope ruling, and the expected ruling is that the brief and the harness are what this
phase produced, with generation going to a human designer using the harness as QA.

## The Z override — owner-reversible

**Wordmark only. `IOI.ttf` is not modified.**

Three reviewers who could not see each other's work read the wordmark as
**"DECENTRALI2ED"** — both round-three cold readers, at both sizes, in all five
lockups, and the UX reviewer independently on the live surface at 4× device scale.

Settled from the font's own tables rather than from appearances:

| codepoint | glyph | id | advance | path commands |
|---|---|---|---|---|
| U+005A `Z` | `Z` | 30 | 1065 | 117 |
| U+007A `z` | `Z` | 30 | 1065 | 117 |
| U+0032 `2` | `.notdef` | 0 | 527 | 26 |
| U+002E `.` | `.notdef` | 0 | 527 | 26 |

So: the face is unicase (`Z` and `z` are one glyph); the misread is **the face's own
Z**, not a fallback; the face carries **no digits and no period**, which is why the
period in this wordmark has always had to be drawn.

The override is drawn to measurements taken off a 300px render, not assumed: cap 700
units, horizontal bar 140, vertical stem 137, advance 1065, side bearings 32 and 1033
— the face's own Z bearings, so the fitting is unchanged. What differs, and what makes
it read as a Z: **square terminals on both bars, and a bottom bar that runs the full
width.** The diagonal is cut 1.35× the bar horizontally, because a diagonal at a
horizontal's numeric weight reads lighter.

`brand/wordmark/compose-z-override.mjs` measures the face, draws the glyph and renders
a specimen at 64/22/13px against the original. It refuses to measure if the face did
not load.

**IOI Display is the estate's brand face and other products set their wordmarks in
it.** Whether the same misread reaches them is the owner's call, not this product's;
it is flagged, not acted on.

## A finding against the harness's own author

Before parsing the cmap, the first probe rendered `Z 2 z` in the face and concluded
from the specimen that the Z and the 2 "look nearly identical". That comparison proved
nothing: the face has no U+0032, so the browser fell back to a system font and the
probe was comparing IOI's Z against some other font's 2. The readers' misread is real
— they read the actual wordmark — but the explanation was measured against the wrong
glyph, and the cmap is what settled it.
