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

> **R10 CLOSURE (2026-09-03).** The normative hash-only fallback, its
> production admission path, adverse/mutation campaigns, exact `n=130`
> benchmark, cold restart, and native PQ re-entry are complete. T4a is paired
> with L-A. This closes only RES-R10; the other claim-ladder gates below keep
> their independent state.

## The printable claim (program doc §9, upgraded)

> **Deterministic all-but-one safety for certified boundaries. Live ordering
> is optimistically responsive after GST and has randomized asynchronous
> progress against a static Byzantine adversary below one-third under its
> separately declared reliable-private-channel profile.**

**PRINTABLE.** Every leg this claim depends on is closed:

- *Deterministic all-but-one safety for certified boundaries* is T1,
  paper-proved and MECHANIZED at P2.1 (`BoundaryRing.tla` + TLAPS
  inductive invariant; TLC at the MHA corner). It is unconditional under
  A2 and bond-independent — the economics memo (P4.2) prices how open
  selection SUPPLIES A2 but the safety statement does not rest on that
  supply.
- *Live ordering under separately declared profiles* is T4a. The optimistic
  arm consumes post-GST delivery; the hash-only fallback consumes static
  `f<n/3`, reliable private authenticated channels, eventual delivery and
  private randomness. The profiles do not inherit one another's timing or
  latency. L-A pairs the result with FLP and the optimal one-third
  asynchronous resilience boundary.

No rounded-percentage tolerance figure appears; the claim-discipline
gate (P0.2) enforces that.

## Intermediate flagship — BLOCKED

> "AFT is a frontier-complete consensus architecture…" (program doc §0b) — BLOCKED, does not print; open gates below.

This rung is **BLOCKED**. Its condition set (spec: the §9 claim's
conditions PLUS the four below) is not satisfied:

| Condition | State | Gate |
|---|---|---|
| R10 asynchronous fallback DEMONSTRATED (not residual) | CLOSED | D1–D4 and the hash-only adverse production/cold-restart gate pass; see `../evidence/m3-adversarial-release-gate-2026-09-03.md`. |
| T7 proven against the wire format | CLOSED | P2.6 (`ForensicAccountability.tla`, 146/146) proves T7 against the P2.6 seal-share wire format; R9 lands the attribution-preserving signer. |
| T8 published in probabilistic form | CLOSED | P4.2 publishes T8 in correlated-failure probabilistic form, with the no-deterministic-conversion rule. |
| Pairing table has ZERO `L-OPEN` rows | **OPEN** | One `L-OPEN` row stands: T8 (the supply analysis is not yet a proved cheapest-capture lower bound). T5d is paired with L-S; its responsive positive theorem is refuted rather than open. |

The remaining T8 `L-OPEN` row blocks this rung. It cannot print while that row
remains open.

## Final flagship — BLOCKED

> "frontier-complete, fully accountable… succession pre-consented at formation and clocked by verifiable elapsed time… verifier held to its proofs by continuous conformance" (program doc §0c) — BLOCKED, does not print; open gates below.

This rung is **BLOCKED**. Beyond the intermediate rung's open gates, its
additional conditions are not satisfied:

| Condition | State | Gate |
|---|---|---|
| Positive responsive T5d cadence theorem | **IMPOSSIBLE IN THE DECLARED ASYNC MODEL** | L-S and `SuccessionSchedule.tla` resolve the question: silence cannot prove inaction. Scheduled slot-disjoint safety is mechanized, but it is not responsive cadence. |
| R11 + scheduled R12 landed | **OPEN** | RES-R11 remains an owner-action VDF-vetting residual. R12 is buildable only as formation-time, clock-fenced scheduled succession after R11; it cannot restore the responsive wording. |
| T9/L9 paired in the table | CLOSED | The pairing table pairs T9 (maximal accountable safety) with L9 (attribution cap, ratio 1.0). |
| R13 trace-conformance lane green | CLOSED | R13 merged; the lane runs in `aft_formal_floor` on every build. |

The final rung's responsive reading is unreachable in the declared model even
if R11 and scheduled R12 land: a clock proves elapsed time, never death.
"Held to its proofs by continuous conformance" is R13-green, but that does not
repair the impossible cadence clause. The rung cannot print as written.

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

- **Prints now:** the upgraded model-relative claim (deterministic all-but-one
  boundary safety, post-GST optimistic progress, and static-adversary
  randomized asynchronous fallback below one-third).
- **Blocked:** the intermediate rung by T8's one `L-OPEN` supply-bound row;
  the final responsive rung by L-S's impossibility result, plus the unbuilt
  R11/scheduled-R12 plane for the weaker scheduled construction.
- **Enforcement:** the flagship strings appear in this corpus only where
  marked BLOCKED; the claim-discipline gate fails on any bare flagship
  assertion.
- **Remaining editorial:** the `yellow_paper.tex` v2 prose rewrite may
  adopt the printable claim and the pairing/measured-cost surfaces, and
  is bound by this adjudication.
