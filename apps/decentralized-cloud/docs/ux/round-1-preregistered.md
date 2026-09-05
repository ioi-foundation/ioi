# What I already knew, written down before round one spoke

ioi-c0's rule for reading round one's score: mark which of the reviewer's findings
were ALREADY known to me before they reported, so round two's delta separates what the
loop LEARNED from what it merely CONFIRMED.

That marking is only worth anything if the list is registered **before** the reviewer's
output arrives. A list assembled afterwards is a list assembled to match, and I would
have no way to prove otherwise — least of all to myself. So this file is written while
round one is still running and its findings are unknown to me.

**Registered:** 2026-09-05, during Phase D round one, reviewer in flight against the
artifact built from commit `d37f9ff6d`. I have not seen any part of their output.

---

## A · Defects I have measured and can already name

These came out of the class-orphan check I wrote at ioi-c0's instruction and validated
against the built bundle. Every one is a class the surface EMITS with no rule in the
stylesheet it SHIPS. They are in the artifact the reviewer is looking at right now.

| emitted class | what the stylesheet actually defines | likely visible consequence |
|---|---|---|
| `quotes` | `table` | every data table unstyled beyond base rules |
| `button` | only `button-inert` | the Job submit button has no style at all |
| `dial-track` | `track` | freshness dial's ring drawn without its rule |
| `dial-ink` | `sweep` | freshness dial's arc drawn without its rule |
| `notice` | `absent` | the unwired panel styled as a plain panel |
| `basis` | — nothing | the basis cell has no rule |
| `price` | — nothing | the price cell has no rule |
| `reasons` | — nothing | the refusal list has no rule |

I expect a reviewer looking at this surface to report some subset of these by their
CONSEQUENCE rather than their cause — "the submit button looks unstyled", "the price
column does not read as the most important number", "the dial is faint" — and those
should be marked ALREADY KNOWN even though the words will not match.

## B · Things I know are true and have decided are correct

Not defects, and if the reviewer scores them as defects that is a genuine disagreement
worth reporting rather than a finding I concealed.

- **Redundancy is the only unwired surface**, deliberately: the daemon accepts the
  `none` posture and refuses the other two by name until M15.9.
- **A real execution is unreachable from the surface by design.** Placement is decided
  and it stops. This is a dry-run door and the copy says so.
- **No budget is preselected** even when only one exists, so the submit button starts
  disabled. Deliberate: real money is never a default.
- **Reads are slow** — a candidate sweep has been measured at 38s, a sources read at
  60s. The surface waits and says why rather than showing a placeholder.
- **Gate-admitted job records accumulate** in the daemon. They are labelled in the
  daemon's own copy and hidden-with-a-count on Receipts rather than deleted.

## C · What I do NOT know, and am not predicting

I have no measurement of contrast on any pair, no keyboard traversal, no screen-reader
pass, and no judgement about hierarchy, copy or the paragraph test. Anything the
reviewer reports in those areas is LEARNED, not confirmed — I have not looked.

The honest expectation: accessibility (15) and copy (12) are the two heaviest criteria
where I have done no measurement at all, so that is where I expect the score to be
lost, and I would rather write that down now than discover I had believed it all along.
