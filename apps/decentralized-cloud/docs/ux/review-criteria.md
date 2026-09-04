# The face's UX bar, and how it is scored

The public face is reviewed blind, by a reviewer who did not build it, against the
criteria below. The bar is **90 of 100**. This document exists so the bar is a thing
in the repository rather than a thing in a prompt: a score is only meaningful if the
criteria were written down before the score was produced, and if the next reviewer is
scored against the same ones.

## How a review is conducted

Three things are required of every round, and a round missing any of them is not a
review of this surface.

**Blind.** The reviewer is not told who built it, is told not to read its git
history, and is told not to read its own verification script or design notes before
reviewing. Those documents say what the surface wants to be believed about itself.

**Measured.** Every number in a review is computed from the rendered page, not
estimated and not remembered. Contrast ratios come from sampled pixels or resolved
colours through the WCAG formula. Sizes and positions come from
`getBoundingClientRect` and `getComputedStyle`. A reviewer who cannot measure
something writes "not measured" rather than a plausible figure. This rule is not
theoretical: an earlier round of this product's brand work reported contrast figures
from memory and every one of them was wrong.

**Looked at.** The reviewer drives a real browser at 1440x900, 1180x800 and 390x844,
screenshots each, and opens the screenshots. A review assembled from reading source
is a code review wearing a UX review's name.

## Criteria and weights

| # | Criterion | Weight |
|---|---|---|
| 1 | Clarity of evidence state | 15 |
| 2 | Honesty of unwired surfaces | 12 |
| 3 | Loading and stale-while-refresh legibility | 12 |
| 4 | Information hierarchy | 12 |
| 5 | Type and colour system | 12 |
| 6 | Responsiveness | 10 |
| 7 | Accessibility | 15 |
| 8 | Copy | 12 |

**1 · Clarity of evidence state (15).** For any number on screen: where did it come
from, when was it observed, is it still valid, and is it real or simulated? A stale
number presented as a current one is the failure this product cannot survive, because
the whole claim of the surface is that it does not present one. A simulator candidate
rendered without its label scores this criterion at zero regardless of everything else.

**2 · Honesty of unwired surfaces (12).** Parts of this product are designed and not
connected. The score is how *impossible* it is to mistake an inert control for a
working one. A labelled stub is a design deliverable and scores well. A stub a reader
cannot tell from truth is refused outright, however well drawn.

**3 · Loading and stale-while-refresh legibility (12).** What the surface does while
it waits, and while it refreshes something it already holds. One of its reads has
taken fifteen seconds. Absence must never be allowed to mean "loading": a page that
blanks while it refetches teaches the reader that an empty table means the data is
coming, which is the one thing an empty table must never mean here.

**4 · Information hierarchy (12).** On each surface, is the most important thing the
most prominent thing, and can it be scanned rather than read?

**5 · Type and colour system (12).** A system or a pile of one-offs, counted from the
rendered DOM rather than from the stylesheet's intentions. Any colour carrying meaning
inconsistently is a defect: on this surface green means live evidence and nothing else,
grey means absence, and red means one thing only — a quote past its `expires_at`.

**6 · Responsiveness (10).** At 1180 and 390: reflow or breakage, any horizontal body
scroll, any clipped content, any collision.

**7 · Accessibility (15).** Computed contrast for every text and non-text pair that can
be sampled, against 4.5:1 for body text and 3:1 for large text and meaningful non-text.
Keyboard reachability of every interactive element, with focus visible at every step.
Semantic structure: headings, landmarks, `aria-live`, buttons that are buttons.

**8 · Copy (12).** Precise, honest, and free of marketing padding. Any sentence
claiming more than the product does is a defect scored here and, if it concerns
evidence, again under criterion 1.

## What a 90 means

A stranger can use the surface without help and without being misled, and finds
nothing that looks unfinished. It does not mean the reviewer liked it.

## What a review must return

A score per criterion with its arithmetic; the defects behind each score, ranked by
what they cost, each with a file-and-line or screenshot reference and the measured
number that proves it; the single highest-value fix; and a paragraph headed **WHAT
REMAINS** — what would still be wrong after every listed defect was fixed. That
paragraph is quoted verbatim and unedited into the round's report, because the useful
half of a review is the part that survives the fixes.

## Ownership, for anyone acting on a review

This surface is split by responsibility rather than by file. Presentation — the
markup, classes, copy and structure emitted by the render functions, plus
`public/index.html` and `public/face.css` — is the identity track's. Logic — the
fetches, the live-versus-simulator classification, batch and expiry computation, the
refresher contract and the job door — is not. A UX fix that needs a logic change is
routed as a diff rather than applied, and
`scripts/verify-decentralized-cloud-face.mjs` must stay green after every change.

Seven of that gate's assertions read `public/face.js` as TEXT: the canonical-vocabulary
names, the no-mutating-fetch check, the two request literals whose diff must remain
exactly one field, the three per-surface "designed, not connected" labels, and the
check that no rendered text mentions the identity score. Reformatting any of those
makes the gate FAIL rather than pass silently, which is the correct direction — but it
means restyling must keep them byte-stable.
