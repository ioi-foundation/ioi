# T5d Resolution — Responsive Succession Is Impossible; Scheduled Succession Is Safe

**Status: RESOLVED (2026-08-18) by a clean-slate theorem challenge with a
mechanized artifact.** This supersedes the T5d "WITHDRAWN — design-open"
state. The succession question is not open pending a fourth design attempt;
it is answered: the class of designs that were refuted three times
(responsive / death-detecting succession) is *provably impossible*, and
the safe alternative (scheduled succession under a clock-fenced lease) is
mechanized. This document is the adjudication; the machine-checked artifact
is `formal/common_boundary/SuccessionSchedule.tla`.

## How this was produced (the discipline, so the result is trustable)

Per the owner ruling on external-capacity substitution: two procedurally
isolated fresh-context theorists were each given ONLY the model and the
desired safety property — never the three refuted formulations (v1
publication≠delivery, v2 bulletin-as-consensus-object, v3
observation-committed adjudication), so neither could anchor on a known-bad
design. One was framed neutrally ("solve or prove impossible"), one
impossibility-first. Their full analyses are internal workspace records
(`reviews/t5d-clean-slate-{neutral,impossibility}.md`). A reviewer's
conclusion closes nothing on its own; what closes the gap here is (a) two
INDEPENDENT rigorous reductions that CONVERGE, and (b) a mechanized TLA+
kernel whose mutation reproduces the impossibility.

## The convergent result

Both theorists reached the same impossibility by the same reduction
family, independently:

**Impossibility (unanimous).** *Responsive* succession — succession
triggered by evidence that the original ring has died (a timeout, a
silence detector) — cannot be both SAFE (never forks a slot) and LIVE
(a genuinely dead ring is eventually succeeded) in the asynchronous
model. Proof: a two-execution indistinguishability argument. A dead
original ring and an alive-but-partitioned original ring that has already
sealed a conflicting value present the standby with an IDENTICAL view at
its decision point; a deterministic mechanism therefore acts identically,
and in the partitioned world that action is a fork. Randomization does not
help (the violation is on safety, not termination). This is the
CAP/partitioned-agreement theorem (Gilbert–Lynch) specialized to a
write-once (ring, slot)→value register, with FLP supplying the
async-indistinguishability method.

**Why the clock cannot save it (the pivotal lemma).** The verifiable-delay
clock certifies elapsed *time*, never the original ring's *inaction*: it
delivers no messages, holds no secret, and compels no one. Safety requires
a certificate of the original's *future inaction* on a slot, and silence
under asynchrony can never provide one — an unsent-looking gap is
indistinguishable from a sent-but-delayed message. The hardware-advantage
margin σ is therefore a *liveness/latency* parameter, not a safety one.
(This is the same structural fact the VDF/coin review found from the other
direction: a VDF is public and deterministic, so it can be a clock but not
a secret-holding coin — `r11_vdf_coin_review.md`.)

**The necessary escape (unanimous): a clock-fenced lease, pre-consented at
formation.** Strengthen the original ring's honesty from value-only to
value-AND-timing: at least one honest member emits NO signature for any
slot past a fixed public clock deadline `T`. This is strictly beyond the
model's honesty (which bounds *which* values a member signs, never *when*
it stops), and the clock cannot impose it — it must be a pre-commitment.
Because a seal is n-of-n, that one fenced honest member VETOES every future
original seal above the fence. This discharges the "no future conflicting
seal" obligation for free, communication-free, across the two disjoint
rings.

## The two safe constructions (a tradeoff, not a disagreement)

The theorists gave two constructions that sit at different points on an
assumption/liveness tradeoff. They do not conflict; the second buys
gapless continuation at the price of a stronger assumption.

- **Scheduled / slot-disjoint (minimal assumption).** The standby takes a
  DISJOINT slot range: the original owns slots ≤ T, the standby owns slots
  > T. Safe with ONLY the fence — no synchrony bound, no cross-ring view —
  because the two ranges never intersect, so the standby need never learn
  the partitioned ring's hidden prefix. Cost: slots below the fence are
  burned, and handover is on a fixed schedule regardless of when the
  original died. **This is the construction mechanized below.**

- **Continued / gapless (stronger assumption).** To let the standby
  CONTINUE the same slot sequence with no burned gap, add a known,
  σ-adjusted staleness bound Δ on original-seal surfacing to the standby
  (equivalently a class-P perfect stop-detector, or a known synchrony
  bound). Strictly stronger than eventual synchrony / Ω / ◇S, and — the
  sharp finding — strictly stronger than what ordinary consensus needs,
  because succession is reconfiguration to a DISJOINT committee with no
  quorum intersection to mask an imperfect detector's mistake (one wrong
  "stopped" verdict is a direct fork).

**Irreducible residue (unanimous).** Responsiveness itself — demoting only
a genuinely-dead ring while never demoting a healthy one — is
unconditionally impossible. A healthy-but-partitioned original MUST be
demoted at the fence. There is no assumption that buys it back.

## The mechanized artifact

`formal/common_boundary/SuccessionSchedule.tla` models the async adversary
(who schedules the clock and may seal the original at any admissible
moment), the two disjoint rings, and the fence. TLC checks the
slot-disjointness invariant and the no-fork safety property over every
reachable state.

- **Sufficiency, machine-checked:** with the fence, TLC explores the model
  (Slots = 1..4, Fence = 2, two values, clock to 5) and finds `Disjoint`
  and `NoFork` hold in all reachable states — scheduled succession is safe.
- **Impossibility, machine-checked:** delete the fence conjunct from
  `OrigSeal` (let the original seal above the fence, as an unfenced honest
  member legally may) and TLC reaches a state where the original and the
  standby seal the same slot with conflicting values — `NoFork` RED. That
  is the impossibility theorem reproduced in the model checker; the fence
  is exactly the load-bearing assumption.

The kernel runs in the `aft_formal_floor` CI job on every build.

## What this changes in the corpus

- **T5d** moves from "WITHDRAWN — design-open" to a resolved pair: the
  responsive-succession IMPOSSIBILITY (a publishable result) plus the
  SCHEDULED-succession safety theorem (mechanized). The §16 banner's "v4
  conditions" are answered: there is no v4 responsive design to find; the
  safe form is scheduled, and it is here.
- The operative exits from a dead ring remain, and are now *justified* as
  the only safe options: the §9 unanimous handover and the §14 labeled
  re-genesis are scheduled/consented transitions, exactly the fence shape.
- The T5d pairing row stays L-OPEN in the flagship sense (the succession
  lower-bound question is now ANSWERED as an impossibility, but the
  program's final-flagship rung was gated on a mechanized *positive* T5d
  with R11+R12 landed; that rung stays unreachable — the resolution
  sharpens the residual rather than opening the rung).
