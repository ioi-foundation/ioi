# What I already know, written down before round four speaks

Same rule as round one's registration: mark what was ALREADY known before the reviewer
reported, so round four's delta separates what the loop LEARNED from what it only
CONFIRMED. A list assembled afterwards is a list assembled to match.

**Registered:** 2026-09-05, before any round-four reviewer is dispatched. Round three's
cold reader is in flight against the contact sheet and I have not seen a word of it.

Round two scored **51.5/100**. The bar is 90. The vanilla face scored 62 before the
port, so round three's floor is 62 and not 51.5 — anything below that is still repair.

---

## A · Defects round two found that I have FIXED, and expect not to see again

If any of these comes back, the fix was wrong, not the reviewer.

| # | Round two's finding | What was actually wrong | Gated? |
|---|---|---|---|
| D1 | Receipts chips all read `0` | `receipts` is an ARRAY; `Object.keys()` gave indices | yes — no chip may be a bare integer |
| D4 | Nothing sorted | daemon response order; `cheapest` was a second derivation | yes — headline price must equal row one, ascending |
| D3 | 39.4s blank cold load | store was in-memory, died on reload | yes — rows must paint while the read is held open 3s |
| D9 | M15.9 / M03.12 on a public page | internal identifiers in rendered text AND in served comments | yes — served-bytes absence check |
| D12 | `read in 0.0s` | `toFixed(1)` on a sub-second duration | no — `duration()` renders ms below 1s |
| D10 | prices left-aligned, headers centred | `.table thead .trow > th` matched NOTHING; no thead carries `trow` | no |
| D7 | submit button dead, no reason | no blocker explanation anywhere | no — blockers now named with valid values |
| D5 | State column cut mid-word | `.chip` is `nowrap` in a narrow column | no — state chips wrap |

## B · Defects I found MYSELF this round that round two did not report

These are mine, not the reviewer's, and I expect no credit for them — but if round four
reports any of them, it is CONFIRMING, not teaching.

- **Placement rendered "no advisory" against a complete advisory.** It read
  `body.decision`; the daemon sends `recommendation`. The most serious defect of the
  round and no reviewer has seen the fix yet.
- **The header-styling block matched no element in the product.** Not one thead carries
  `trow`.
- **A chip in a stacked `td` stretched to 800px**; the restoring rule named `th` only.
- **The cells-stay-cells check visited one surface of seven** while I quoted it as
  covering the product.
- **`the only verb the surface sends is POST` inspected zero verbs** — the door module
  was not in the gate's source list.
- **`the allowlist contains no refresh route` inspected no allowlist** after the table
  moved out of the proxy.

## C · What I have changed structurally, where I expect the score to move

- Criterion 4 (hierarchy, 4.5/12) — sorting, price alignment, real column headers.
- Criterion 3 (loading, 5.5/12) — persisted kept answers, named waiting state. **A
  genuinely first-ever visit is still slow**: the cache helps a returning reader and
  the contact sheet, being a fresh browser every run, still shows the true first-visit
  wait. I expect this to remain a criterion-3 loss and I would rather predict it than
  discover I had assumed it away.
- Criterion 8 (copy, 6/12) — internal identifiers gone, next steps named.
- The paragraph test: I ran it myself with `.prose` hidden in the browser. **All seven
  surfaces pass.** Round two was three of seven. If a reviewer disagrees, my test is
  the thing that is wrong, and the disagreement is the most valuable thing they can
  give me.

## D · What I do NOT know and am not predicting

- Every accessibility number. `--border-strong` at 1.57:1 on form controls is **NOT
  fixed** — I know about it, I have not changed it, and it is 3 points of criterion 7
  sitting there deliberately because I ran out of round before I ran out of findings.
  Anything else in criterion 7 is LEARNED.
- Whether the new tables read well to someone who has not been staring at them. I have
  looked at every one of these surfaces a dozen times today and I am the worst possible
  judge of whether they are legible cold.
- Whether the locked Execute control reads as a boundary or as a broken button. That is
  the single design bet of this round and I have no evidence for it either way.
- Mobile. I fixed nothing about the 390px table clipping (D2, 50.6% and 58.7% of two
  tables hidden with no affordance). It is unaddressed and I expect to be told so.

## E · The honest expectation

Round two's craft criteria were 5.5 / 4.5 / 3 / 7. I expect 3, 4 and 8 to move
materially and 6 (responsiveness, 3/10) to move **not at all**, because I did not touch
it. If the total lands below 62 the port is still not repaired, and I will say so in
those words rather than reporting an improvement over 51.5.
