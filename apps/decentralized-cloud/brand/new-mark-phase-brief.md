# New-mark phase — brief

**Status: recorded, not started.** Filed 2026-09-04. Nothing in this document is to be
drawn until the M15.2 face polish and the hand-back are complete and the owner says to
begin. It exists so the phase starts from today's findings rather than re-deriving them.

## Why there is a new-mark phase

The current family monogram is **identity v0 — provisional, scored 50 of 100** by blind
review against a bar of 90. The convergence cap fired at 75, so iteration on that
construction stopped and the face ships with it. The three reasons it stopped at 50 are
the three things a replacement has to beat:

1. **It reads as a UI control, not a mark.** At 24px an independent reviewer read it as
   the duplicate-layers glyph — an icon that appears in the same toolbars at the same
   size. In one ink its skeleton reads closer to a **2** than a **d**, for want of an
   ascender.
2. **The family cue never reached the lockup.** Fifteen instances of the mark, ten
   carrying the sibling slot and five not — and the five were every lockup and the
   product bar. On the primary brand surface all three siblings were identical.
3. **The one-ink form is one silhouette.** Not three blocks. See the struck control
   below.

## Owner reference for the new direction

A **graph mark**: three or four circular nodes joined by straight edges — a horizontal
edge between two end nodes, with nodes above and below on the right side joined
diagonally. Shown in Google-blue on white, and as white nodes on a blue tile with a long
shadow.

**Concept:** nodes are venues, edges are routes, and **one lit edge is the chosen
placement**. This is the product's thesis rather than the name's — a departure from the
monogram, which tried to carry the name's letter and its period.

**Family derivation hypothesis to test:** *which route is lit* names the sibling. The
hypothesis fails unless the lit route is visible **in the lockup**, not only in the app
icon. That is the exact failure mode that cost the monogram its derivability score, so
it is the first thing to test, not the last.

## Hazards to state on the board BEFORE any drawing

These are not review findings to be discovered later; they are known now and the board
names them itself.

1. **It is structurally the Android/Material "share" glyph.** Three nodes joined by two
   edges is that icon. A mark that reads as a control at 16 and 24px fails the standing
   rule — the same rule the monogram failed against the duplicate-layers glyph, and
   failing it twice in a row with a different shape would be a pattern rather than an
   accident. The construction must escape that read **by geometry**: a highlighted
   route, asymmetric node weights, or a shape the share icon does not make. The board
   names the share icon explicitly and says in one line why this is not it.
2. **It is Google Cloud's product-icon house style** in colour and treatment. Tokens and
   the reversed white-on-onyx form handle the colour half. **Geometry must handle the
   rest** — a token swap on a Google-shaped mark is still a Google-shaped mark.

## Process, as ruled: small-size-first

The monogram phase spent its effort on craft and boards before establishing that the
base form survived product size. It reached expert curve work — corner arcs within 0.04%
of true circles — on a shape that reads as a toolbar icon. That order is inverted here.

**Every concept exists at 16px, 24px and in one ink BEFORE any board or polish.** At that
stage each skeleton faces:

- **the share-icon / control test** — shown cold at 16 and 24px, does a reader name it as
  a control? If yes, the skeleton is dead; it does not proceed to craft.
- **the one-drawing test** — is the reduction the same drawing in fewer inks, or a
  different object? The monogram passed this and the reserved d failed it.
- **the lockup-cue test** — is the sibling cue visible in the lockup at product size, not
  only in the tile?

Skeletons are **scored at skeleton stage**. Only survivors get craft. No board is written
for a skeleton that has not survived.

## Harness inventory — what already exists and can be reused

Built and proven during the monogram phase. These are the instruments; using them is not
optional, and any new claim needs one.

| Instrument | What it establishes | Where |
|---|---|---|
| **Fail-closed font load** | Refuses to measure when the face did not load, instead of silently measuring a fallback glyph. Caught a counter reported at 0.324 cap that was truly 1.064. | `measure-face.mjs` |
| **Ink-run probe** | Scans a true-device-pixel row for separate runs of ink with a presence threshold and per-run coverage. Catches fusion at small sizes. | `compose-monogram.mjs` |
| **Differencing probe + closed-form cross-check** | Isolates a cue by differencing a sibling against the same mark drawn without it, then fails the run if the measurement disagrees with the geometry's own arithmetic. Written after a probe reported 0.54px where the closed form said 2.19px and a ruling was made on the false number. | `compose-monogram.mjs`, `compose-monogram-v2.mjs` |
| **Erosion / deepest-interior placement** | Places a cue where a shape is actually thickest rather than where it looked right. | `compose-reserved-d.mjs` |
| **True-curve bounding box** | `getBBox` on curves rather than scanning path data, whose control points lie outside the curve. Caught a mark reported 108.63 wide that is 107.89. | `reserved-d/true-curve-box.mjs` |
| **Knockout probe** | Proves a notch is absent ink rather than an opaque chip: a colour used nowhere in the artwork must show through, and ink must sit beside it so the sample cannot pass by missing the shape. | `round3` work, `check-notch` pattern |
| **Contrast measurement** | WCAG ratios computed, never asserted. Written after contrast figures were claimed from memory and were wrong. | `measure-contrast.mjs` |
| **Frame / collision gate** | Every artboard fits its declared frame with no leaf colliding; "leaf" means *carries its own text*, not *childless*. | `measure-artboards.mjs` |

### STRUCK — do not reuse

**The connected-region count.** It was used to claim the reserved d's one-ink form was
three separate blocks. It is withdrawn, for two reasons, and both are the lesson:

- Its answer depended entirely on two parameters that were never stated — a 50% alpha
  threshold and 4-connectivity. On any-ink it returns **one** region at every resolution
  tested, and at 32px even the 50% threshold with diagonals returns one.
- More fundamentally it is **a topological answer to a perceptual question**. Whether a
  viewer sees three blocks is not whether the pixels are 4-connected.

The parameters were chosen after seeing which ones returned the wanted answer. Nothing in
this phase may use it, and any new instrument must state its parameters in the same
breath as its result.

## Non-negotiables carried into this phase

- **Fail closed on measurement.** If the instrument cannot measure, it refuses; it never
  prints a plausible number.
- **A control that cannot fail on its own finding is not a control.** Every new probe
  gets a mutation that plants exactly the defect it exists to catch, and a positive
  control that must fail.
- **State parameters with results.** A threshold, a connectivity, a channel — named in
  the output, not implied by the source.
- **The board states its own costs**, and those costs are measured before they are
  written. Two of the monogram phase's costs were written rather than measured, and both
  were false: one against the candidate, one in its favour.
- **Labels claim only what the assertion checks.**
- **The provisional score never reaches the public surface** — identity status lives in
  the identity sheet and in a code comment where the mark is loaded.

## Order of work when the phase opens

1. Skeletons at 16px, 24px, one ink — no colour, no tile, no board.
2. Share-icon / control test on every skeleton, cold reader, no provenance.
3. One-drawing test and lockup-cue test on survivors.
4. Score the surviving skeletons; kill the rest.
5. Craft only on what survived, then boards, then a blind round on the nine criteria.
