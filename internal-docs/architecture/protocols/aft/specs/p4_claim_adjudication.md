# AFT-CB P4.4 — Claim Adjudication

> **STATUS SUPERSESSION (2026-08-18, at `59294c96c`).** The yellow-paper
> v2 rewrite this document required is COMPLETE and merged (#333,
> `59294c96c`), including the owner-directed maximality presentation
> recorded below; R4c is merged (#318), so Q4 is killed at both layers.
> References below to the rewrite as "remaining editorial work" are
> historical — the merged manuscript IS the adjudicated final version,
> and this adjudication continues to bind it (the flagship rungs remain
> blocked and machine-gated).

This document adjudicates exactly which claim the program may print, and
enumerates the precise gates blocking each flagship rung. It is the
authority the machine gate enforces: `check_aft_claim_discipline.sh`
asserts that no flagship rung appears in the corpus as a bare assertion —
the "frontier-complete" strings may appear ONLY where they are marked
BLOCKED with their open gates named (as they are here).

The full `yellow_paper.tex` rewrite around the T1–T3/T4a–b/T5a–c′/T6/T7/T8
theorem surface is REMAINING EDITORIAL WORK; it may adopt the printable
claim below verbatim and MUST NOT print either flagship rung while this
adjudication records them blocked. The adjudication — not the LaTeX
prose — is what determines what can be claimed.

## The printable claim (program doc §9, upgraded)

> **Deterministic all-but-one safety for certified boundaries; live
> consensus under separately bounded adversarial weight and eventual
> synchrony.**

**PRINTABLE.** Every leg this claim depends on is closed:

- *Deterministic all-but-one safety for certified boundaries* is T1,
  paper-proved and MECHANIZED at P2.1 (`BoundaryRing.tla` + TLAPS
  inductive invariant; TLC at the MHA corner). It is unconditional under
  A2 and bond-independent — the economics memo (P4.2) prices how open
  selection SUPPLIES A2 but the safety statement does not rest on that
  supply.
- *Live consensus under separately bounded adversarial weight and
  eventual synchrony* is T4a, and the claim STATES its two conditions
  (bounded weight; eventual synchrony = A5). Because the claim scopes
  itself to eventual synchrony, R10's asynchronous-fallback residual
  (RES-R10) does NOT undercut it — the claim never asserted asynchronous
  liveness. This is the exact line the intermediate flagship crosses and
  this claim does not.

No rounded-percentage tolerance figure appears; the claim-discipline
gate (P0.2) enforces that.

## Intermediate flagship — BLOCKED

> "AFT is a frontier-complete consensus architecture…" (program doc §0b) — BLOCKED, does not print; open gates below.

This rung is **BLOCKED**. Its condition set (spec: the §9 claim's
conditions PLUS the four below) is not satisfied:

| Condition | State | Gate |
|---|---|---|
| R10 asynchronous fallback DEMONSTRATED (not residual) | **OPEN** | RES-R10 is filed as a residual + design; the fallback is not built (FLP forecloses it without a common coin — engine-structure change). |
| T7 proven against the wire format | CLOSED | P2.6 (`ForensicAccountability.tla`, 146/146) proves T7 against the P2.6 seal-share wire format; R9 lands the attribution-preserving signer. |
| T8 published in probabilistic form | CLOSED | P4.2 publishes T8 in correlated-failure probabilistic form, with the no-deterministic-conversion rule. |
| Pairing table has ZERO `L-OPEN` rows | **OPEN** | Three `L-OPEN` rows stand: T4a (RES-R10), T5d (withdrawn), T8 (supply lower bound is an analysis, not a proven bound). |

Two independent gates (R10 fallback + the L-OPEN rows) block this rung.
It cannot print this cycle.

## Final flagship — BLOCKED

> "frontier-complete, fully accountable… succession pre-consented at formation and clocked by verifiable elapsed time… verifier held to its proofs by continuous conformance" (program doc §0c) — BLOCKED, does not print; open gates below.

This rung is **BLOCKED**. Beyond the intermediate rung's open gates, its
additional conditions are not satisfied:

| Condition | State | Gate |
|---|---|---|
| T5d mechanized (P2.7) | **OPEN** | T5d is WITHDRAWN for this cycle — three formulations refuted across five review rounds; §16's banner carries the v4 conditions. |
| R11 + R12 landed | **OPEN** | RES-R11 (VDF vetting, rule-12 owner action) and RES-R12 (depends on T5d + R11) are filed as residuals. |
| T9/L9 paired in the table | CLOSED | The pairing table pairs T9 (maximal accountable safety) with L9 (attribution cap, ratio 1.0). |
| R13 trace-conformance lane green | CLOSED | R13 merged; the lane runs in `aft_formal_floor` on every build. |

The "clocked by verifiable elapsed time" and "succession pre-consented at
formation" phrases require exactly the two residual planes (R11, R12);
"held to its proofs by continuous conformance" is R13-green (satisfied)
but the rung needs its full set. It cannot print this cycle.

## Maximality presentation (owner-directed, 2026-08-18)

The owner directed the yellow paper's claims to their maximum defensible
strength. The adjudicated resolution: the defensible superlative is
PROVABLE MAXIMALITY, not comparison. Two presentation-level claims are
authorized because each is a CITED positive-theorem/lower-bound pair in
the pairing table — the ceiling and the achievement print together:

- **Safety at the terminal threshold** (T1 + L1): no protocol in any
  model exceeds all-but-one for safety, and AFT meets that ceiling,
  mechanized. "The safety axis ends here" is a theorem, not marketing.
- **Accountability at the attribution ceiling** (T9 + L9): ratio 1.0 is
  the cap and AFT meets it.

The carrier-replacement framing ("the classical bound is refused, not
refuted — its carrier is replaced, and in the replaced carrier the
threshold ascends to the information-theoretic maximum") is promoted to
the abstract. Conditions preserved: the model delta stays first-class,
the liveness price (L2's forced trade) and the residual list print
BESIDE the maximality claims, no rounded figure appears, and the blocked
flagship rungs remain unprinted — this presentation strengthens the
SAFETY-AXIS claims, which are closed, and touches no completeness-class
rung, which are not.

## Adjudication summary

- **Prints now:** the §9 upgraded claim (deterministic all-but-one
  safety + synchrony-conditional live consensus).
- **Blocked, this cycle:** both flagship rungs, by residuals the program
  deliberately did not paper over (RES-R10, T5d withdrawal, RES-R11/R12,
  three L-OPEN rows).
- **Enforcement:** the flagship strings appear in this corpus only where
  marked BLOCKED; the claim-discipline gate fails on any bare flagship
  assertion.
- **Remaining editorial:** the `yellow_paper.tex` v2 prose rewrite may
  adopt the printable claim and the pairing/measured-cost surfaces, and
  is bound by this adjudication.
