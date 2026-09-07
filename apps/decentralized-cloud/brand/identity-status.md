# Identity status — not served

This file exists because `public/index.html` is served verbatim, so anything written
in it ships in view-source. Everything below lives here instead of in the served
shell.

## The owner's identity — complete, 2026-09-07

The owner delivered the identity complete as
`brand/mark/source/brand-identity-standalone.html` — a bundled page whose assets are
decoded verbatim into `brand/mark/source/`:

| File | What it is |
|---|---|
| `lockup-dark.svg`, `lockup-light.svg` | the primary lockups: mark + two-line wordmark + gradient dot, at the owner's 2.65× / 7.5% rule |
| `mark-dark.svg`, `mark-light.svg` | the mark: a cloud with a stepped block cut out of its right lobe, interior indigo walls, a cyan eight-node network inside |
| `mark-mono-white.svg`, `mark-mono-navy.svg` | the mark in one colour |
| `glyph.svg` | the reduction glyph, 64 × 64: the cloud with a three-node network knocked out (also the favicon) |
| `wordmark.svg` | the wordmark alone, outlined |
| `mark-animated.html` | the animated SVG mark, "replica engine": the cloud's face opens into the network where the pointer is; no WebGL |
| `hero-3d.html` + `three-d-stage.js` | the WebGL hero (three.js from unpkg through the owner's pinned import map) |
| `brand-page.html` | the owner's brand page |

**Nothing is redrawn.** `public/brand/` is a byte-for-byte copy of those files plus
`favicon.svg` (the glyph) and `index.html` (the owner's page with its asset ids
pointed at the files); `brand/mark/build-assets.mjs --check` fails if any served file
differs from its source. `brand/mark/mark.mjs` exports only the numbers the shell
and the face gate need to agree with the files — the cloud path and cut polygon
(asserted present verbatim in `mark-dark.svg`), the lockup's wordmark transform
(asserted present in `lockup-dark.svg`), the wordmark's measured layout for the
live-text header, and the replica engine's constants.

**The header carries the animated primary lockup** (owner ruling, 2026-09-07):
`src/components/AnimatedMark.jsx` is the owner's replica engine with its arithmetic
kept and two adaptations — the stage is the mark's own box, and the wordmark is set
beside it as live text in IOI Display (owner ruling, 2026-09-05: one run per line, no
drawn letters). It pauses in hidden tabs; under reduced motion the owner's
`mark-dark.svg` stands verbatim. The header follows the owner's lockup rule — the
mark 2.65× the wordmark block, the gap 7.5% of the mark's width — at a 20px block in
a 64px bar (owner, 2026-09-07: the mark is bigger than the wordmark on every lockup).

**Tokens added** to `packages/design-system/tokens/colors.css`:
`--color-dc-cut-face-lit #2b4fb0`, `-side #23409a`, `-shade #1b2f72`, `-deep #101f4e`
— the cut's bevel faces as the owner's file paints them; decorative fills on the mark
only.

**Retired the same day, in order:** the designer's three-lobe mark
(`FInal-CLOUD-v3.svg`, landed and retired 2026-09-07); the cloud I drew from the
owner's hover prototype before the complete file arrived. Both are asserted absent
from the served bytes by their path data. The exploration rounds, the dissolving
cloud plates, the reserved-d monogram and the compose scripts left `brand/` the same
day; they last live in commit `d9e22de35`.

No blind reader has scored this mark on the face yet.

## The Z override — owner-reversible, retired

**Wordmark only. `IOI.ttf` is not modified.** Three reviewers who could not see each
other's work read the wordmark as **"DECENTRALI2ED"**. Settled from the font's own
tables: the face is unicase (`Z` and `z` are one glyph); the misread is the face's own
Z; the face carries no digits and no period, which is why the dot has always had to
be drawn. The owner ruled (2026-09-05) that the wordmark is set entirely in IOI
Display with no drawn letters, and the gate holds that choice: no drawn Z or I reaches
a reader, the dot survives. **IOI Display is the estate's brand face and other
products set their wordmarks in it.** Whether the same misread reaches them is the
owner's call, not this product's; it is flagged, not acted on.
