# Standing practice for this surface

Rules that outlived the round that produced them. Each is here because it was learned
expensively, and each names the failure it came from — a rule whose reason is missing
is a rule someone will reasonably delete.

## 1. Every capture labels the state it captured

An instrument that photographs a page must record, **in the artifact**, whether the page
had loaded, and the wait it observed. Loaded / still-waiting / failed, with the number.

**Why.** `contact-sheet.mjs` waited 1500ms per surface for reads measured at 27–61
seconds. On every run it photographed Sources, Placement and Receipts mid-load and
presented three blank rectangles as the product. Three cold readers reported those
blanks back as defects; I relayed them to the director as product findings, wrote
contact-sheet lines describing them, and shipped a commit whose headline rested on
them. The comment directly above the offending line said, correctly, that a shot taken
during the wait is "not the one this sheet is for".

A picture that does not say which state it caught **will** be read as the loaded page.

Applied in: `contact-sheet.mjs` (per-cell caption, red outline), `look.mjs` (a state bar
burned into the image, non-zero exit if the content never arrived).

## 2. No finding is acted on from ONE instrument

Two instruments **of different kinds** must agree before a product finding is fixed or
reported: a capture and a live-browser measurement; a gate assertion and a cold reader;
a body sample and a rendered cell. A finding with one witness is logged as
**single-instrument, unconfirmed** and not acted on.

**Why.** The same defect was found three times in one programme and fixed three times as
an instance:

- gate assertions passing on empty sets (three of seven widths inspecting zero cells
  while reporting 144/144),
- an assertion covering one surface of seven, quoted as covering the product,
- an instrument capturing a loading state and reporting it as the thing.

Each time the instance was repaired and the class was still live somewhere I was looking
straight at. The defect was not that the checks were wrong; it was **trusting the last
thing I built to be the thing that finally sees**. The structural answer is that nothing
sees alone.

## 3. Universally quantified assertions report what they inspected

Enforced by the runner, not by the author remembering. An `every`/`no`/`all`/`only`
assertion that reports no count, or a count of zero without declaring zero valid by name
through `okMayBeEmpty()`, fails the run.

Single-subject assertions are deliberately out of scope: with nothing to inspect their
condition is false and they go red, which is correct. A blanket wide enough to cover
them is a blanket people learn to route around.

## 4. A generated number is only as good as the set it is generated from

Removing a hand-copy is not enough. `capability.mjs` generated "seven reads" above a
table it also generated with eight rows, because one counted daemon reads and the other
rendered every GET route. **A second derivation is a second spine.** A cold reader found
it in under a minute; 170 assertions did not, because every one of them compared the
module against itself.

## 5. A contract in which everything is optional cannot fail

`/api/placement-advisory` declared every field optional "by design", so the surface
rendered "the daemon returned no advisory" against a body containing a complete
advisory, and the contract stayed green. Optionality must be argued per field, not
granted to a whole route.

## 6. The paragraph test is run, not recalled

`STRIP=1 node scripts/look.mjs` hides every `.prose` block and shoots what remains. If a
surface cannot say what it is without its sentences, its facts are living in the prose
instead of in the structure. Judging this by reading one's own source is the same error
as reading source instead of served bytes, one level further out — and on the judgement
most likely to flatter the author.

## 7. Comments are served

Three absence assertions in one session first fired on comments — in a shipped module
and in the stylesheet. The bundle ships them. A comment quoting a false sentence puts
the false sentence on the wire.

## 8. Truncation must announce itself

Content cut off at a **viewport edge** is truncation a reader cannot detect. There is no
ellipsis, no fade, no scrollbar — the sentence simply ends and nothing says it did.

The daemon label in the topbar read `mon 127.0.0.1:4211` at 390px for the whole life of
the port: `.topbar-status` is `justify-content: flex-end` with every child
`flex-shrink: 0`, so the longest chip pushed the label past the left edge. A cold reader
reported it on an earlier build and I did not act on it. The nav-visibility assertion
passed the whole time, correctly — the label is not a nav button.

An ellipsis says "there is more here". A viewport clip says nothing at all, and on a
surface whose subject is not making silent claims, silent truncation is the same defect
one layer down. Applies equally to a scroll container with no cue: four readers could
not tell "horizontally scrollable" from "content unreachable" from a still image.

## 9. Do not resolve an ambiguous state in the product's favour

The catalog rendered the daemon's `candidate_source_unavailable` as **"connected, not
quoting"** whenever an account was verified for that venue. But `unavailable` does not
distinguish *we reached it and it had nothing* from *we could not reach it*, so
"connected" told a stranger the link was healthy and the venue merely declined — a
specific, flattering reading of a state that does not carry it.

Inferring a live connection from a stored account is the same move as inferring liveness
from a cached price, which is the one thing this product exists to refuse.

The repair is not a better adjective. It is to **stop drawing a conclusion across two
facts** and let them sit beside each other: the chip reports what the read returned
("no supply now"), the evidence line reports what is stored ("1 account connected"). A
reader can then draw their own inference, or decline to.

## 10. A proxy signal works until the thing it proxied changes

The contact sheet waited on `networkidle` before capturing. That was never the question
it needed answered — it needed "has THIS surface's content arrived" — but it correlated
well enough while the default surface was cheap. When the default became a surface whose
read runs ~30s, `goto`'s own 30s timeout expired before the network was ever quiet and
the script died outright.

A proxy that has worked for months is indistinguishable from a correct signal right up
to the moment the thing it stood in for changes. Wait on the fact you actually need, by
name, with a stated ceiling and a NOT-MEASURED outcome.

## 11. A phone screenshot must be inspected unscaled

A full-page 390px capture is ~390×4600 and downsamples about 2.3× on the way to a
reader. Neither §8's clipped label nor §9's chip wrap was legible in it.

Phone width is inspected in **unscaled bands** (`scripts/.crop390.mjs`), for the same
reason the mark plate magnifies nothing: a scaled phone screenshot is the identical
class of instrument error as a magnified glyph plate, and that one manufactured a
finding twice in this programme.

## 12. The same probe agreeing with itself is ONE instrument

Director's ruling, 2026-09-05, after a false finding survived three runs and two commits.

The collision probe reported text-on-text on catalog at all seven widths. It was wrong:
every reported pair had one side inside a **closed `<details>`**, which Chrome lays out
(real rects, `display: list-item`) and never paints. The probe compared painted bounds
and had no rule for *laid out but not painted*.

It survived because I treated its own repetition as corroboration. Run again on a second
commit, it said the same thing, and I read that as the two-instrument rule being
satisfied. It is not. **A probe repeating itself is one instrument run twice, and a third
run makes a false finding look more certain rather than less.**

The second instrument must be of a different **KIND**: a screenshot, a DOM interrogation,
a cold reader, a live body. Here the DOM interrogation named the closed disclosure and a
390px screenshot showed the funnel columns stacking cleanly — two different kinds, one
minute of work, available the entire time.

Two signals were visible in the very first report and neither was acted on:

- **The finding was width-independent.** Identical at 1920 and at 390. A reflow collision
  is a function of width; anything that reads the same at every width is shaped like an
  instrument artifact, not a layout defect.
- **Nobody had looked.** §"numbers do not see pictures" already covers this. A collision
  claim that has never been seen by an eye is half a claim.

The corollary, for gates specifically: an exclusion added to stop a false positive must
be mutation-tested in **both** directions, because an exclusion that silences a real
finding looks exactly like one that works. The fix here was proved with three planted
mutants — a visible overlap is CAUGHT, the same overlap behind a closed disclosure is
MISSED, and the same element with the disclosure OPENED is CAUGHT again. Only the third
distinguishes "excludes unpainted text" from "excludes anything inside a `<details>`",
and the lazy version of the fix passes the first two.

**Rule, ruled by the director 2026-09-05 after the instrument commit 4f344e427:** an
instrument's failure path is proved by MUTATION, never by reading its code. For the face
gate's void path that meant two decoy servers occupying the gate's own ports and serving a
copy of the build with one byte appended: the gate had to report both blocks as not
serving its build, print RUN VOID with both bails named, print NO fraction, and exit 1.
A void path that has only been read is a void path that has never been seen to fire, and
the run it was written for printed "119/127 passed" over fifty-one skipped assertions.
