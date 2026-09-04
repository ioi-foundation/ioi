# Identity status — not served

This file exists because `public/index.html` is served verbatim, so anything written
in it ships in view-source. An independent UX review found the identity's blind score
and an internal file path in the bytes a visitor receives — inside a comment asserting
that the label "belongs here … never on the surface a visitor reads." The comment was
true about intent and false about mechanism.

Everything below has been moved out of the served shell and lives here instead.

## Where the mark stands

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
