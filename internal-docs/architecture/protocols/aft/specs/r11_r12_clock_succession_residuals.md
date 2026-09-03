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

**In-session assessment (2026-08-18, advisory — does NOT close this
residual).** A procedurally-isolated fresh-context review
(`r11_vdf_coin_review.md`) scoped the decision: the recommended clock
candidate is **class-group Wesolowski** via an independently-vetted
chiavdf-derived dependency — the only candidate that is today
trusted-setup-free, permissionless (one honest evaluator), succinctly
verifiable, mainnet-hardened, Apache-2.0, and carries an EMPIRICAL σ
anchor (ASIC advantage measured ≈3.6×–9.1×). Isogeny VDFs are a
PQ watch item, not an option (no vetted library, no empirical σ,
trusted-setup/pairing baggage on the mature variant, unsettled
post-SIDH assumptions). The single most important number to externally
vet is **σ set ABOVE the demonstrated ASIC ceiling with margin** — an
under-set σ is a real safety hole feeding the T5b/§14 fail-closed waits.
The class-group VDF is NOT post-quantum; adoption is safe only because
A9's safety-critical uses are confined and fail-closed, and only if the
`pq` bit + beacon abstraction genuinely permit a construction swap
without re-genesis (must be vetted). Adoption still requires external
crypto review + an ADR-0033 decision (rule 12); the in-session review's
confidence closes nothing.

**The clock and the async coin are SEPARATE residuals — they cannot be
collapsed.** The clock (this leg) needs a public, deterministic,
verifiable function; R10's D3 common coin needs a SECRET,
unpredictable, bias-resistant value. The determinism that makes a VDF a
good clock is exactly what disqualifies it as a coin, so a VDF-derived
coin is not available (`r11_vdf_coin_review.md` §9; the R10 design's D3
option (b) is retired accordingly). A subtle but load-bearing
distinction the review flags: R5 sortition safely relies on the beacon
being unpredictable UNTIL IT EXISTS (a temporal-ordering,
anti-precomputation guarantee), which is strictly weaker than the
secrecy-at-reveal a coin needs — conflating the two is the trap.

**What exists today, honestly labeled.** The C5 sortition rider (R5)
consumes a beacon ABSTRACTION with the reference ordering beacon behind
it (the temporal-ordering guarantee above, which the beacon abstraction
legitimately supplies); R10's fallback design (D3) now names its coin as
a SEPARATE secret-holding adoption, not this leg's VDF. Both are labeled
in their own records.

**Closing condition.** A vetted construction lands behind the beacon
abstraction; the e2e gates from the leg spec run (lineage chain verifies
from genesis; elapsed-history comparison; objective tick count across
two independent verifiers) plus the splice and non-seal-seed mutations.

## RES-R12 — pre-consented succession

**What the leg wants.** Policy signing at configuration formation,
activation only on the objective tick trigger, a fallback grace window
with published-old-seal preemption, the honest-publication duty enforced
in the signer, standby diversity against targeted capture.

**Why it is a residual and not a build — and, since 2026-08-18, why the
RESPONSIVE version is not merely open but IMPOSSIBLE.** Two independent
gates, either of which suffices:

1. **T5d is RESOLVED as an impossibility (was: withdrawn).** The
   clean-slate theorem challenge (`t5d_succession_resolution.md`,
   mechanized in `SuccessionSchedule.tla`) proved that RESPONSIVE
   succession — activation triggered by evidence the original ring died,
   which is exactly what R12's "kill-one-member → T_halt → activate"
   path is — cannot be safe and live in the async model. So R12's
   responsive activation path is not awaiting a fourth design; it is
   provably unbuildable. What IS safe is SCHEDULED succession under a
   clock-fenced lease pre-consented at formation (the standby seals
   strictly above a public fence, slot-disjoint from the original). R12
   is accordingly re-scoped: if it is ever built, it is the SCHEDULED
   form (a formation-time lease + fence), never the responsive form. The
   operative exits remain §9 handover and §14 labeled re-genesis — both
   already scheduled/consented, i.e. exactly the safe shape.
2. **R11 is a residual.** The clock-fenced lease still needs the
   objective tick trigger — the VDF clock — for the fence deadline to be
   publicly verifiable; without R11, activation would fall back to
   wall-clock or silence-derived triggers, the exact defect classes the
   program exists to kill. (The clock provides the fence's *time*; per
   `t5d_succession_resolution.md` it provably cannot provide death
   *detection*, which is why the lease, not a timeout, is load-bearing.)

**What exists today, honestly labeled.** The pieces of R12 that are
SAFE without the theorem all landed elsewhere: R9's signer makes the
honest-publication duty a one-act API (emit = publish); R5's handover
is the only strong-ring transition (typed, silence-unrepresentable) and
its activation queue + sortition give the standby-diversity substrate;
R3's resolution log holds post-close evidence without mutation. What
did NOT land — deliberately — is any path that ACTIVATES a successor
ring from elapsed time or non-response.

**Closing condition (re-scoped after the T5d resolution).** The
RESPONSIVE R12 is closed as impossible — nothing to build. A SCHEDULED
R12, if the owner wants it, closes when R11 lands (the clock for the
fence deadline) and the formation-time lease is wired into the
membership plane (an honest member's signing is fenced at a public
deadline, mechanically enforced) — its safety is already mechanized in
`SuccessionSchedule.tla`, so its build gate is integration, not a new
theorem. The kill-one-member/T_halt "detect death then activate" gates
from the original leg spec are RETIRED: they describe the impossible
responsive form.

## Claim-surface effects

- The frontier-completeness flagship (P4.4) remains unreachable: responsive
  T5d is refuted by L-S, and T8 is the one remaining `L-OPEN` pairing row.
  RES-R10 closed on 2026-09-03 and is no longer one of those blockers.
  RES-R11 and RES-R12 add two more named gates to that list — nothing
  weakens, the gate list lengthens.
- The interim conditional claim (whitepaper §5.3) is UNAFFECTED: it
  never cited the clock plane or succession.
- P4.5a's audit packet must state both residuals' status (as it must
  for R14 and RES-R10).
