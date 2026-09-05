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
