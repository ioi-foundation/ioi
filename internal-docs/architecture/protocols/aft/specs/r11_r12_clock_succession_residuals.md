# R11 / R12 — VDF Clock Plane and Pre-Consented Succession: the Adjudication

**Status: BOTH LEGS FILED AS NAMED RESIDUALS (RES-R11, RES-R12) — neither
is buildable inside this program cycle, for reasons that are each other's
mirror: R11's load-bearing primitive needs vetting the loop cannot grant
itself, and R12's safety theorem was withdrawn after three refuted
formulations.** This document is the adjudication record: what exists,
what gates, and what would reopen each leg.

## RES-R11 — the VDF clock plane

**What the leg wants.** A permissionless VDF evaluator (one honest
evaluator suffices), the chain seeded by each seal hash, cheap
verification wired into the seal verifier, the σ drift margin published
in the corpus, and a PQ-aware construction choice (C7).

**Why it is a residual and not a build.** The leg's own dependency note
says it: a production-grade VDF needs a trusted-setup-free construction
or a vetted library, and "if the cryptographic choice needs external
review or spend, escalate per rule 12 rather than shipping an unvetted
primitive as load-bearing." Every candidate in the space carries exactly
that need:

- **Wesolowski / Pietrzak over class groups** — trusted-setup-free and
  succinctly verifiable, but the estate has no vetted class-group
  arithmetic dependency, and adopting one is a licensing + security
  review decision (ADR 0033 lane), not a loop decision.
- **Isogeny-based constructions** — PQ-friendly on paper; the literature
  is young and no candidate library clears the "vetted" bar.
- **Hash-chain with published checkpoints** — buildable today from
  estate primitives, but verification is linear (re-evaluate or trust
  checkpoints), which fails the "cheap verification wired into the seal
  verifier" requirement; as a REFERENCE lane it would be honest but it
  cannot be the load-bearing clock.

**Owner action (rule 12):** select and commission review of a VDF
construction/library. Until then the residual stands.

**What exists today, honestly labeled.** The C5 sortition rider (R5)
consumes a beacon ABSTRACTION with the reference ordering beacon behind
it; R10's fallback design (D3) defers its common-coin choice to this
leg's rendezvous. Both are labeled in their own records.

**Closing condition.** A vetted construction lands behind the beacon
abstraction; the e2e gates from the leg spec run (lineage chain verifies
from genesis; elapsed-history comparison; objective tick count across
two independent verifiers) plus the splice and non-seal-seed mutations.

## RES-R12 — pre-consented succession

**What the leg wants.** Policy signing at configuration formation,
activation only on the objective tick trigger, a fallback grace window
with published-old-seal preemption, the honest-publication duty enforced
in the signer, standby diversity against targeted capture.

**Why it is a residual and not a build.** Two independent gates, either
of which suffices:

1. **T5d is WITHDRAWN for this cycle.** Three formulations were refuted
   across five review rounds (publication≠delivery; the bulletin as an
   unmodeled consensus object; observation-committed adjudication whose
   refusal rules Byzantine padding satisfies). The operative exits
   remain §9 handover and §14 labeled re-genesis; §16's banner carries
   the v4 conditions. Building R12's activation path would put runtime
   under a safety statement the program itself refuted.
2. **R11 is a residual.** The "objective tick trigger" IS the VDF
   clock; without it, activation would fall back to wall-clock or
   silence-derived triggers — the exact defect classes the program
   exists to kill.

**What exists today, honestly labeled.** The pieces of R12 that are
SAFE without the theorem all landed elsewhere: R9's signer makes the
honest-publication duty a one-act API (emit = publish); R5's handover
is the only strong-ring transition (typed, silence-unrepresentable) and
its activation queue + sortition give the standby-diversity substrate;
R3's resolution log holds post-close evidence without mutation. What
did NOT land — deliberately — is any path that ACTIVATES a successor
ring from elapsed time or non-response.

**Closing condition.** T5d v4 survives its own adversarial review
(the §16 banner's conditions) AND R11 closes; then R12's build follows
the leg spec's gates (kill-one-member cadence-freeze → T_halt →
activation with continuity labels; the hidden-seal grace-window drill)
and mutations.

## Claim-surface effects

- The frontier-completeness flagship (P4.4) was already unreachable
  this cycle (T5d withdrawn; RES-R10 open; three L-OPEN pairing rows).
  RES-R11 and RES-R12 add two more named gates to that list — nothing
  weakens, the gate list lengthens.
- The interim conditional claim (whitepaper §5.3) is UNAFFECTED: it
  never cited the clock plane or succession.
- P4.5a's audit packet must state both residuals' status (as it must
  for R14 and RES-R10).
