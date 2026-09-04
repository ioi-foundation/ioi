# decentralized.cloud — mark brief, for a designer

**The new-mark phase closed at its cap without a mark.** Four rounds, twenty
skeletons, ten fresh blind cold readers, zero passes. This document is what the phase
produced instead: a brief, a harness, and one direction with its central problem
named. It is written for a human designer; the harness is your QA, not your author.

The phase was run by an implementer that could measure but could not generate. That
is the honest summary of why there is no mark here, and it is why the generation is
yours and the verification is already built.

---

## 1. The direction

**A counter in a mass — a hole punched in a solid shape — in a container that is not
a stock object.**

That is the only device any reader rewarded across four rounds. It scored highest
twice on its own merits, and both times what failed was the container around it, not
the hole.

The nearest thing to a success is **round four's "counter in a canted quad"**
(`brand/skeletons/skeletons-r4.mjs`, `canted-counter`): a four-sided mass with no two
edges parallel, no edge on a cardinal angle, one bowed side, a flat base level with
the type's baseline, and an off-centre punched counter. It is the **only mark in the
entire phase that both readers passed on its own**.

Both readers' descriptions of it, verbatim:

> "the only one with a positive form, an off-axis fingerprint, and an interior that
> survives small size"

> "I could describe this mark to another person — 'dark tilted tag with a hole punched
> in it' — which I cannot do for 1, 2 or 4"

**Its central problem, and your brief:**

> "a punched luggage tag… says retail/price/label, and nothing in
> DECENTRALIZED·CLOUD wants to say price tag"

The shape works and its referent is wrong. Keep the counter and the cant; find a
container that is not a hang tag, a location pin, a dice pip or a game token — all
four were named, cold, by readers who were told nothing.

---

## 2. What four rounds ruled out, and why

Each of these killed real drawings. They are not aesthetic preferences.

1. **Few, large, regular, centred, symmetric elements.** That is the vocabulary system
   icons are drawn in, because it is what survives being redrawn by a hundred hands.
   Four drawings built that way were named as four different existing buttons — the
   share glyph, the align-left button, the apps grid — by two readers independently,
   confidence *certain*.
2. **A mass with one small interior subtraction.** Round two banned (1) and produced
   this instead, and both readers said unprompted that four of six were the same
   drawing. **At 16px an interior event is one to three device pixels, so the identity
   cannot live there — it lives in the OUTLINE.** An interior counter is a second
   event, never the first.
3. **A silhouette that is somebody else's.** Round three's incumbent had survived two
   rounds; closing its counter left a shape **93.1% identical** (IoU at 16px) to a
   mark that never had one. The hole was doing all the work.
4. **Anything whose weight, radius and angle match the type it sits beside.** One
   round-four mark "disappears because it matches too well… reads as a filled-in
   letter, a redaction bar, a missing glyph." A mark absorbed into its own wordmark
   has stopped being a mark.
5. **A tilt with nothing level in it.** Reads as a misaligned asset, not a decision.

**The one construction fix that demonstrably worked**, and the template for how to
answer a reader's finding: the canted mark was given **one true horizontal at its
base**, level with the type's baseline, while the container stayed canted. Two fresh
readers then independently called the same tilt *"a decision"* — one adding it was
"the only angle in the set that has a reason." A named fault, fixed by geometry,
confirmed corrected by readers who had not seen the previous round.

---

## 3. The wordmark — two structural faults, both an owner question

`IOI.ttf` is the estate's brand face and other products set their wordmarks in it, so
neither of these is decided here. Both were found by multiple readers who were told
nothing and asked only to read the name aloud.

**The Z reads as a 2.** Four independent reviewers read *"DECENTRALI2ED"*. Overridden
for this wordmark only — square terminals on both bars, a bottom bar running the full
width, the diagonal cut 1.35× the bar because a diagonal at a horizontal's numeric
weight reads lighter. Every metric taken from the face itself: cap 700, bar 140, stem
137, advance 1065, side bearings 32 and 1033. `IOI.ttf` is untouched. **Readers still
report a residual "flicker toward Ƶ".**

**The I is a bare stem and reads as a numeral 1.** Found later, by two readers, who
typed back what they saw: **`DECENTRAL1ZED·CLOUD`**. One stated the compound problem:

> "a barred Z next to a numeral-looking I gives AL1ƵED. Two ambiguous letters adjacent
> is not two problems, it is one compound problem."

The Z override alone therefore does not fix the word.

**Mechanical facts about the face, from its own tables** (33 glyphs total):

| codepoint | glyph | gid |
|---|---|---|
| `U+005A` Z / `U+007A` z | `Z` | 30 — one glyph; the face is unicase |
| `U+0032` 2 | `.notdef` | 0 — **the face has no digits** |
| `U+002E` . | `.notdef` | 0 — **the face has no period** |

The missing period is why this wordmark's period must be drawn: a mechanical
necessity, not a style ruling. Any digit or period set in this face is silently some
other font's glyph.

**The wordmark has one source:** `brand/wordmark/wordmark.mjs`. It exists because the
Z was once fixed on the shipped surface and not in the harness that plates the
lockups, so a round was judged against a name that misspelled itself and had to be
voided. Do not copy its constants anywhere.

---

## 4. Balance is mass, not cap ratio

The old rule set the mark at 1.25–1.35× the cap height. It produces a mark nobody
sees, and two readers worked out why independently:

> "you could double every one of these marks and they'd still read as a bullet point"

The name is 18 letters plus a separator; on one line the wordmark's aspect ratio is
about 20:1, so **any** cap-locked mark is arithmetically a rounding error. Measured
ink area, mark against wordmark, at 22px:

| lockup form | mark's share of the pair's ink |
|---|---|
| single line | **7.0 – 8.4 %** |
| stacked | **14.5 – 17.2 %** |

So: the single line sets the mark at one **em** as a floor, and balance is stated as
measured mass. Where a single line would put the mark below that, the **stacked form
is primary** and the mark stands at the full two-line height.

**Open question, not a settled rule.** The stacked form was first drawn with the
period *leading* line two, and both readers rejected it immediately — "a joiner that
starts a line is no longer joining anything", "a leading mid-dot reads as a bullet
point". The current hypothesis is the period at the **end of line one**
(`DECENTRALIZED.` over `CLOUD`) with a minimum size floor that does not scale
linearly. **It has not been cold-read. Do not call it primary until it has.**

---

## 5. The harness

`brand/skeletons/compose-skeletons.mjs --set <r2|r3|r4> --plates`.

Seven positive controls run **before** any measurement, each handed the exact defect
it exists to catch, and the run aborts unless every one reports it. That is not
ceremony: one control failed legitimately during development and stopped a run whose
numbers would have been meaningless.

| instrument | what it establishes |
|---|---|
| Ink presence, fail-closed | Refuses to measure an empty or fully-inked frame. Caught a path bug that rendered 0.4% ink at every size. |
| Separation | Exact run count at a scan line derived from the geometry, never guessed, plus a 55% faintness floor — a run that is present but pale is a wall that is half there. |
| Cue separation | Isolates a sibling cue by differencing against an event-free base, then cross-checks against the closed form. |
| Top-edge profile | Measures whether a declared taper survives product size. Only declarable for a top edge that is one straight line; anything else declares no claim. |
| **Silhouette IoU at 16px** | Counters closed, flagged at 0.80. Killed the two-round incumbent at 0.931. |
| Ghosts | Retired shapes carried into the IoU matrix only — never plated, never scored — so a later round cannot re-draw something already dead. |

**STRUCK, do not reintroduce:** the connected-region count. Its answer depended on
two parameters that were never stated, and it is a topological answer to a perceptual
question.

**Two additions ruled standing and NOT yet built — the harness cannot currently see
either failure, and says so here until it can:**

1. **Type-what-you-see.** The small line shown alone, out of context, reader asked to
   type what they read — *before* any other question. This is how the numeral-1 I was
   found; asking "is the wordmark OK" never surfaced it.
2. **Mark against TYPE, not only against other marks.** The silhouette probe compares
   candidates with each other. It has no way to detect a mark that vanishes because it
   matches the letterforms beside it, which is how one round-four candidate failed.

---

## 6. How to run a round

1. **Cold reader first, measurement second.** The reader test is the cheaper killer
   and it caught what geometry alone never would: measurement has never once been the
   half that killed a mark, and it passed drawings that readers named as buttons.
2. Skeletons exist at **16px, 24px, one ink** before any board, colour or craft.
3. Ask, in this order: type what you see; name it in one word; is it a control; what
   would you recognise it by next time.
4. The bar is one question: **"Is this a logo I would recognise on second sighting?"**
   Both readers must pass it, and a mark that passes alone and fails beside its name
   has not passed.
5. Every hazard the drawing is near is written on it **before** it is drawn. Every
   number is measured from the render. Every probe has a mutation that plants the
   defect it exists to catch.
6. Look at the plates yourself before sending them. Three of this phase's worst
   errors were invisible to every measurement and plain in a screenshot.
