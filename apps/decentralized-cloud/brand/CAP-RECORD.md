# The mark hunt, capped — the record

This is the second time this programme has stopped without a mark, and this record
exists so the third attempt does not repeat the first two. It is the phase's product,
in the same sense that `HANDOFF.md` was the last phase's: not a drawing, but an
account of what was tried, what every reader actually said, and which of the
instruments could be trusted while they said it.

**Standing: the mark hunt is PAUSED by ioi-c0's ruling and resumes only on an owner
ruling.** The wordmark — with the drawn Z and the drawn I, both earned below — is the
identity the product ships, labelled provisional.

---

## What the numbers were

| | |
|---|---|
| rounds | 6 mark rounds + 1 lockup round |
| candidates generated | ~1,300 |
| candidates that reached a reader | 155 · 58 · (0) · (0) · 100 · 73 |
| fresh cold readers | 13 on marks, 2 on the lockup, 6 on the wordmark's letters |
| marks granted by TWO readers | **0** |
| lockup forms called finished | **0** |

Two rounds never reached a reader at all, and that is a result rather than a gap:
round three's interlocks severed instead of crossing, and round four's stroke
retraced its own ring instead of crossing it. Both were visibly wrong the moment the
sheet was opened, and spending readers on them would have spent them on my bugs.

---

## What every round died of

**Round one — 352 candidates, 9 families, 3 readers, zero.**
The dominant failure was named identically by all three:

> "The single most common failure is that the shape lands on a letter. At 16px a great
> many of these collapse to Z, C, S, E, U, or 7 — and a mark that reads as a letter is
> a letter, not a mark." — reader A

> "The dominant failure is not ugliness, it is **collision with the alphabet and the
> digits**... At icon size a mark that reads as a letter is not a mark, it is a typo."
> — reader B

The two families ioi-c0 had asked for — letterform-derived cuts and wordmark
fragments — were the worst performers in the round. A mark cut from the face's
outlines is the face's letter. **That ruling was overturned by the readers and the
record says so.**

**Round two — 155 candidates, 2 readers, zero, and the only grant this programme
ever produced.** Reader L granted three cells:

> "46, 47, and 50 all have a square whose stroke breaks and doubles back on itself so
> the outline appears to pass through its own corner — an interlock, not a gap. That
> self-crossing is the one thing here I did not have a ready name for, and it is the
> one thing that would make me look twice."

Reader K read the same three cells as "square" and "bracket". One reader is not the
bar.

**Rounds three and four — no readers.** I built what the reader's WORDS described
(an interlock) instead of what the reader's ARTIFACT was (an off-centre knockout that
breaches its own boundary). Two rounds spent on the difference. See "What I got
wrong" below; this is the entry that matters most.

**Round five — 300 candidates sweeping the breach itself, 2 readers, zero.** Both
killed the mechanism directly:

> "The wrap-around does not read as clever at this size; it reads as broken." — reader M

> "The 'ink wraps around and doubles back' effect does not survive to 16px: a thin
> wrap-around limb one or two pixels wide just looks like the edge of the block, or
> like an antialiasing artifact. Whatever design intent lives in that distinction is
> invisible at the size these are meant to be seen." — reader N

Reader N also wrote the diagnosis of the whole search:

> "The whole sheet is one vocabulary: right angles, one stroke weight, one bite. There
> is no curve, no diagonal, no dot, no crossing stroke anywhere in 100 marks. That is
> why so many collapse into 'a C' or 'a box' — you have removed every axis on which a
> viewer could tell two of them apart. **Variety inside a single primitive is not
> variety.**"

And: "Nothing here reads as cloud, network, distribution, or connection. If a theme
was intended, it did not arrive; my first words were furniture and punctuation."

**Round six — 197 candidates across curve, diagonal, dot, crossing stroke and a
router theme, 2 readers, zero.** Widening across primitives did not work either:

> "Barely, and not in a way that helps you... it is the same KIND of non-variety,
> spread across five templates instead of one." — reader P

> "It reads as one vocabulary to me — actually as about three vocabularies bolted
> together in blocks... What you have is monotony wearing three costumes." — reader Q

**The lockup round — 3 forms with their tiles, 2 fresh readers, none finished.**

> "No — none of them... The wordmark in all three is doing no identity work: it is a
> stock-flavoured wide techno face with an interpunct, and 'DECENTRALIZED·CLOUD' is a
> category description, not a name." — reader R

> "None of them. A is a stock UI glyph — I named it as 'sign out' before I knew it was
> a logo, and an identity you can mistake for a system control is not finished. B and
> C are not identities at all; they are a string in a purchased-looking typeface, and
> the tiles are a battery and a record button." — reader S

### The two "winners", both disqualified by the hazard list

Both lockup readers ranked form A first, and both named it, unprompted, as a banned
hazard: "generic right-arrow / play button" (R) and "the 'log out / sign out' glyph"
(S). It also died first at small size — "the one form with a mark has the least robust
mark" (S). The round-two interlock is the other: granted by one reader, refuted by two
when sampled properly.

---

## What is now known about the space, and is not worth re-learning

1. **At 16px the identity lives in the OUTLINE.** An interior event is 1–3 device
   pixels. Anything whose difference lives inside the mass is invisible.
2. **Everything geometric and abstract lands on a letter, a digit, or a UI control.**
   C, L, U, D, O, S, Z, 0, 2, 7, checkbox, folder, floppy, spinner, close, hourglass,
   record, arrow, sign-out. That list is thirteen readers deep.
3. **Tilt is not content.** "At 16px a tilt is not a design gesture — it is a defect.
   Nobody will see 'dynamic'; they will see 'the icon is crooked.'" Both round-five
   readers, independently, after I had leaned on it for four rounds.
4. **A known form is the only thing that survived being small** — the one shape any
   reader said they would recognise again was a crescent — **and being known was also
   why it failed.** That tension is unresolved and is the real problem.
5. **Variety inside one primitive is not variety, and neither is five primitives
   sampled the same way.** Rounds five and six establish both halves.

---

## What I got wrong, and the instrument debts still open

**The reader described a PERCEPT; I built the DESCRIPTION.** Reader L said
"interlock"; the drawing was an off-centre knockout breaching its boundary. I spent
rounds three and four building interlocks. The artifact the reader was shown was on
disk the whole time. This is the programme's standing error — taking an account of a
thing for the thing — in a costume I had not seen it in.

**A stale sheet reached three readers.** Round one's readers scored cells 161–163 that
the run never wrote: a fifth sheet survived from an earlier run with a different
candidate list. Fixed by emptying the output directory, not merely creating it.

**My plates were coloured.** Chromium's LCD subpixel antialiasing put orange and blue
fringes on a one-ink wordmark. Found by opening the picture.

**My plates were downsampled.** A 4x magnification of an eighteen-character line is
~1300px and gets resampled in delivery, which undoes the magnification. That blur
manufactured part of a Z finding I had already reported to ioi-c0 as the wordmark's
fault. Fixed by narrow crops under a width ceiling that throws rather than shipping a
resampled plate.

**My comparison sets varied in scale.** The first I round let each plate compute its
own magnification from its own width; the variants have different advances, so the
plates came out at different sizes. Both readers named the scale before they said
anything about the letter. Fixed: one magnification for the whole set.

### Open debts — do not build on these without fixing them first

- **SHEETS ARE NOT SHUFFLED.** Every mark sheet is ordered by family, so adjacent
  cells are siblings. Reader Q: "the ordering is actively hiding how few ideas are
  present." It also contaminates the same-sentence grouping every round depends on.
  Six rounds of grouping evidence carry this bias. The verdicts were zero either way,
  so nothing is re-derived from it — but a future round must shuffle, with the seed
  written on the sheet.
- **MAGNIFICATION IS NOT A WHOLE NUMBER.** The plate image is scaled to a rounded
  target width rather than an exact multiple of the source raster, so column
  run-lengths vary by one. It changed no reading, and it contradicts the premise
  printed on every plate shown to a reader in this programme.

---

## What the phase DID earn

The wordmark's compound fault is closed, on narrow-plate evidence, for both letters.

- **The Z.** Twenty variants, three fresh readers. All three typed a DIGIT for exactly
  one — the face's own. The mechanism they named is a corner, not a terminal: "it is a
  bend versus a corner, and at 13px the bend wins."
- **The I.** Ten variants, three fresh readers, one magnification. All three put the
  face's bare stem in their worst group and **all three independently chose the same
  drawing**, for the same stated reason: bars long enough that no alternative reading
  occurs, in the same weight band as the L's foot and the E's arms. The trade —
  legibility bought with stylistic foreignness — is settled at 4x the stem, not 4.8x.

Both are held to their one source by gate assertions that read the SERVED BYTES and
that have each been mutation-tested against the defect they exist to catch.

---

## The question that is above this document

Reader R: **"'DECENTRALIZED·CLOUD' is a category description, not a name."** Both
lockup readers found the 45:1 strip unusable — "there is no header, no tab, no card
that takes that shape."

No mark, no Z and no period answers that. It is a naming and product question and it
is with the owner.
