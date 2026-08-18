# VDF Candidate Review — RES-R11 Clock Plane and RES-R10 D3 Common Coin

**Provenance: IN-SESSION FRESH-CONTEXT REVIEW (2026-08-18).** Produced by
a procedurally-isolated fresh-context reviewer within the orchestrating
session — NOT an external audit, NOT organizationally-independent
cryptographic review, and NOT peer review. Per the owner ruling, an
in-session review may supply internally checkable evidence (this
document's cited property matrix and threat model) but its conclusions
do not close RES-R11's cryptographic-vetting gate; that gate closes only
through the external §10 vetting and the ADR-0033 decision. Its value
here is to SCOPE the decision (which primitive, which role, what to
vet), not to authorize adoption.

**Status: ADVISORY CRYPTOGRAPHIC ASSESSMENT — NOT an adoption.** This
review's *confidence* closes nothing. What it delivers are checkable
artifacts: a property matrix, a threat model per role, a reasoned verdict
on the decisive question, a construction recommendation for the clock, a
separate verdict for the coin, and an explicit external-vetting list.
Adoption of any load-bearing primitive still requires external crypto
review and an ADR-0033 licensing decision per the owner ruling (rule 12).
Every claim below cites a source a cryptographer can check.

## 0. Scope: two roles, and what the corpus makes each one consume

**RES-R11 — the objective clock plane (`common_boundary.md` §15, A9).**
The corpus wants a *permissionless* VDF: anyone may evaluate, ONE honest
evaluator suffices (§15.2), the chain is seeded by each seal hash
(§15.1), verification is cheap and wired into the seal verifier, and a
σ (sigma) drift margin — "the assumed bound on adversary hardware
speedup" (§15.4) — is published in the corpus. A9 is stated as "the
protocol's objective clock wherever ticks are read," with SAFETY-critical
consumption *confined* to the A6-iv long-range-forgery hardening (T5b),
§14 fail-closed admissibility/hardening waits, and the design-open
succession extension (T5d). Everywhere else the tick stream is *advisory
cadence* (§3, §15.3: "cadence targets are advice"). PQ-awareness is a
design goal (rider C7 / the `pq` bit, §16 finality menu). A VDF is the
right shape for this role: it makes elapsed real time objective and
publicly verifiable.

**RES-R10 D3 — the asynchronous common coin
(`r10_live_tier_async_fallback.md` §2).** R10's load-bearing finding is
that the live engine is *fully deterministic* (mirror seed zeroed), so by
FLP it cannot guarantee termination under a full asynchronous adversary;
the Ditto/VABA-class pessimistic path "structurally requires a source of
common randomness." D3 lists three coin options — (a) threshold-BLS
(needs DKG + pairing, `pq:false`), (b) "VDF-derived coin from the R11
clock plane," (c) committee hash-coin — and defers the choice to
rendezvous with R11. A common coin must be **unpredictable** to the
adversary until reveal and **bias-resistant** (no party steers it).

**The one-primitive hypothesis this review must adjudicate:** can the
R11 VDF *also* be D3's common coin, collapsing two residuals into one
adoption? The answer (§6, §9) is **no**, and the reason is structural,
not a matter of parameterization.

---

## 1. PROPERTY MATRIX

Rows are the two candidate families this review was asked to assess. The
"σ" column is the specialized-hardware-advantage margin. Clock- and
coin-suitability are the two-role columns.

| Property | Class-group Wesolowski / Pietrzak (chiavdf baseline) | Isogeny-based VDF (research track) |
|---|---|---|
| **Trusted setup** | **None.** Class group of an imaginary quadratic field has unknown order from a *public* discriminant — no ceremony, no toxic waste. [chiavdf], [VDFsurvey] | **Split.** Original DFMPS 2019 **requires** a trusted setup (a supersingular curve with unknown endomorphism ring, produced by a trusted walk-and-forget). [mariascrs] The SAC-2021 "Verifiable Isogeny Walks" construction claims **no** trusted setup but is a research design, not the deployed DFMPS one. [eprint-1289] |
| **Verify cost** | **Wesolowski:** O(1) proof (one group element), verify ≈ two exponentiations. **Pietrzak:** O(log T) proof and O(log T) verify (faster verify than Wesolowski in practice, larger proof). chiavdf ships *n-wesolowski* (nested, ≤64). [VDFsurvey], [chiavdf], [pietrzak-eth] | Quasi-logarithmic verify claimed for the SAC-2021 SNARG-for-isogeny-walks approach, but **unimplemented at production scale**; DFMPS-2019 verify uses **pairings**. [eprint-1289], [dfmps-pairings] |
| **PQ** | **No.** Security rests on unknown group order; a quantum computer computes the class-group structure (hence the order) of an imaginary quadratic field in polynomial time (Hallgren; Biasse–Song), which breaks sequentiality — reduce 2^T mod the group order and shortcut. Adaptive-root/low-order are *classical* assumptions. [hallgren], [biasse-song] | **Aimed PQ**, not proven-PQ. DFMPS-2019 verification via pairings is quantum-broken (so that construction is *not* fully PQ). [dfmps-pairings] SAC-2021 targets PQ verification via isogeny SNARGs, but the *sequentiality against a quantum evaluator* and the SNARG itself remain open. [eprint-1289] |
| **Dependency maturity** | **Highest available.** chiavdf: C++ (GMP/MPIR, Boost, pybind11), NUDUPL squaring; on Chia mainnet since 2021 as the live timelord VDF. Real adversarial exposure, real timelord ecosystem. [chiavdf], [chia-consensus], [chia-timelords] | **Research-grade.** No library clears a "vetted production" bar. Even *evaluation* acceleration is nascent (first hardware accelerators are recent papers). [eprint-1289], [accel-isogeny] Post-SIDH-break (Castryck–Decru), the whole isogeny-assumption landscape is in active revision. [castryck-decru] |
| **Licensing** | **Apache-2.0** (chiavdf), permissive, with an explicit patent grant — clean for an ADR-0033 LICENSE-MANIFEST entry; transitive deps (GMP is LGPL/GPL-dual, Boost is BSL-1.0) must be manifested. [chiavdf] | No production library ⇒ no licensing story yet; would be a fresh implementation obligation. |
| **Hardware-advantage σ (empirical basis)** | **Bounded and measured.** Custom ASICs for class-group squaring demonstrate ≈**3.6×** over the best prior hardware implementation and ≈**9.1×** over optimal C++ on advanced CPUs. [asic-2022-755], [asic-tches] Open-hardware-design norm (Chia) keeps *honest* evaluators near the frontier, shrinking the residual advantage. σ is a *policy choice set above* this demonstrated ceiling with margin. [chia-timelords] | Unknown / unquantified — no deployed evaluator, so no empirical σ exists to publish. This alone disqualifies it from the clock's §15.4 requirement today. |
| **Clock-suitability** | **Strong.** Permissionless, one honest evaluator suffices, succinct public proof, cheap seal-verifier check, measurable σ. Matches §15.1–15.4 directly. | **Weak today.** Right shape in theory, but no vetted library, no empirical σ, trusted-setup baggage on the mature variant. A *watch item*, not an option. |
| **Coin-suitability** | **None** (structural — see §6). Deterministic public output; no secret; a σ-fast adversary learns it *early*. | **None** (structural — same reason). A VDF of any construction is a delayed *public* function, not a secret. |

---

## 2. Candidate notes (justifying the matrix cells)

**Class-group Wesolowski / Pietrzak.** Both build a group of unknown
order without a trusted party by using the class group of an imaginary
quadratic field with a *public* discriminant — this is the property that
makes them trusted-setup-free where RSA-group VDFs are not. [VDFsurvey]
Wesolowski's proof is a single group element verified with ≈two
exponentiations, resting on the **adaptive-root assumption**; Pietrzak's
proof is O(log T) with O(log T) verify, resting on the **low-order
assumption**, which is *no stronger* than adaptive-root (if adaptive-root
holds, low-order holds; the converse is open). [VDFsurvey], [low-order-402]
chiavdf implements Wesolowski (as *n-wesolowski*, nested, up to 64
segments) in C++ over GMP/MPIR with NUDUPL squaring, and is the live VDF
of Chia's consensus since 2021 — the only VDF family in this review with
mainnet adversarial exposure. [chiavdf], [chia-consensus] The **σ** the
clock must publish has an empirical anchor: peer-reviewed ASIC work shows
≈3.6× over the best prior class-group hardware and ≈9.1× over optimal
CPU C++. [asic-2022-755], [asic-tches] The **not-PQ** verdict is the
sharp caveat: computing the class-group order is quantum-polynomial
(Hallgren; Biasse–Song), and known order collapses the delay. [hallgren],
[biasse-song]

**Isogeny-based VDF.** The only *deployed-shape* isogeny VDF is DFMPS
Asiacrypt-2019, titled — literally — "Verifiable Delay Functions from
Supersingular Isogenies **and Pairings**"; its verification uses
pairings (quantum-broken) and it requires a trusted setup, one of its
three documented drawbacks. [dfmps-pairings], [mariascrs] The eprint the
task cites — Chavez-Saab, Rodríguez-Henríquez, Tibouchi, "Verifiable
Isogeny Walks: **Towards** an Isogeny-based Postquantum VDF," SAC 2021
— is explicit in its own title that it is a step *towards* a PQ VDF: it
contributes a SNARG tailored to isogeny walks (no trusted setup, no
pairings) as a *building block*, not a finished, implemented primitive.
[eprint-1289] Meanwhile the 2022 Castryck–Decru key-recovery attack on
SIDH detonated confidence in a neighboring isogeny assumption, so the
whole family is mid-revision. [castryck-decru] **Production-readiness,
honestly: not close.** No library, no empirical σ, unsettled assumptions.
It belongs on a PQ-migration watch list, not in this adoption.

---

## 3. THREAT MODEL — the clock role (RES-R11)

The clock's job is to make elapsed time *objective and verifiable*. Its
adversary and failure surface:

- **T-CLK-1 — σ under-set (the primary safety hole).** A9's
  safety-critical consumers (T5b hardening, §14 fail-closed waits) trust
  that an adversary cannot cross a tick threshold faster than `elapsed/σ`.
  If the published σ is below the true hardware advantage, a fast
  adversary reaches a safety-gated tick early — e.g., re-runs long-range
  sequential work inside the window the σ margin was supposed to price
  (§15.5, A6-iv). **Mitigation:** publish σ *above* the demonstrated
  3.6×–9.1× ASIC ceiling with generous margin, keep it a governed
  parameter, and maintain the open-hardware-design norm so honest
  evaluators track the frontier. This is the single most important
  externally-vetted number in the adoption (§10.4).
- **T-CLK-2 — quantum break of unknown order.** A quantum adversary
  computes the class-group order and evaluates ticks in ~zero sequential
  time, collapsing the clock. Blast radius is bounded by A9's scope: it
  *degrades liveness/hardening* in the confined safety-critical set and
  breaks the advisory cadence, but the §14 uses are *fail-closed* (they
  wait; they never adjudicate), so a broken clock stalls rather than
  mis-decides. **Mitigation:** the `pq` bit + beacon abstraction must
  make the construction swappable without re-genesis (§10.7).
- **T-CLK-3 — proof-verification DoS.** Cheap verify is a two-edged
  property: an adversary floods the seal verifier with bogus proofs.
  Wesolowski's ≈two-exponentiation verify is cheap but non-zero.
  **Mitigation:** rate/econ bound in the seal path (§10.6).
- **T-CLK-4 — seeding manipulation.** The chain is seeded by each seal
  hash (§15.1); a mis-domain-separated or attacker-influenced seed lets a
  forger precompute a parallel tick chain. Note §15.4's own caveat:
  permissionless evaluation means the protocol "cannot reject a PATIENT
  or σ-fast forger who accumulates an equal-or-longer tick chain" — tick
  length is *evidence*, not *authority*. **Mitigation:** domain-separate
  the seal-hash→VDF-input map; the clock hardens an anchor (A6-iv), it is
  never a standalone anchor (A6 ledger entry).
- **Non-threat:** side-channels on the evaluator. The VDF input/output
  are public; there is no secret to leak. (This is exactly why it is a
  clock and not a coin.)

## 4. THREAT MODEL — the coin role (RES-R10 D3)

The coin's job is to inject randomness the adversary cannot predict or
steer, inside a *fully asynchronous* live-tier fallback where the
adversary controls message scheduling.

- **T-COIN-1 — early prediction by a faster evaluator.** If the "coin"
  is a VDF output, whoever finishes the delay first knows it first. The
  clock's *own* threat model grants the adversary a bounded-but-nonzero
  hardware advantage σ (T-CLK-1). That same σ means a σ-fast adversary
  computes the coin **before** honest parties — the precise opposite of
  the unpredictability a coin requires. The clock's tolerated weakness is
  the coin's fatal break.
- **T-COIN-2 — input grinding / bias.** A VDF output is only as
  unpredictable as its *input*. In async, the adversary schedules
  messages and can often choose which value seeds the beacon; given a
  head start or precomputation it can grind candidate inputs (paying T
  per candidate, or less with hardware) and steer the result. The delay
  *raises the cost* of grinding but does not structurally forbid a single
  party steering — it provides no "no one party can bias" guarantee.
- **T-COIN-3 — asynchrony dissolves "reveal time."** A common coin's
  security is stated at a *reveal instant* ("unpredictable until
  revealed"). Under an async adversary who controls delivery order, there
  is no shared reveal instant to defend: the adversary can run the VDF
  throughout and deliver messages whenever it benefits. A clock gives an
  *objective ordering of elapsed work*; it does not give a *secret held
  until a threshold cooperates*.
- **Contrast that the corpus already relies on — do not conflate.**
  Yellow-paper §17 / T-block draws the sortition standby set from the VDF
  beacon and states it is "unpredictable until the beacon value exists."
  That is a **temporal-ordering** guarantee ("you cannot compute it
  before its future seed exists"), which defeats *pre-positioning*
  attacks (targeted capture that must commit *before* the seed exists).
  It is **not** a **secrecy** guarantee ("no one can compute it once the
  seed exists"). The async coin needs secrecy at the reveal instant
  against an adversary who is present and computing — a strictly stronger
  and different property. The same VDF beacon is therefore *safe* for
  sortition-against-precomputation and *unsafe* as an async common coin.
  This distinction is the crux; conflating them is the trap.

---

## 5. (reserved — see §6 for the decisive verdict)

## 6. THE DECISIVE QUESTION — is a VDF output an asynchronous common coin?

**Verdict: NO. A VDF is not a common coin, and cannot be made into one
without importing a separate secret-holding primitive — at which point
that primitive, not the VDF, is the coin.** "Deterministic but delayed"
is not "unpredictable and bias-resistant." Stated plainly and without
papering over it:

1. **A VDF keeps no secret.** `output = VDF(input)` is a deterministic,
   public function. The delay T only postpones *when* the value becomes
   known to a party doing the work; it hides the value from **no one**
   who holds the input and pays the delay. A common coin's unpredictability
   comes from a *secret* (a threshold of shares, an unopened commitment)
   that is revealed only when enough parties cooperate. A VDF has no such
   secret to reveal.
2. **The adversary learns the coin no later than — and, with hardware
   advantage, before — honest parties.** The clock role *assumes* a
   bounded adversary speedup σ (§15.4, A9). A σ-fast adversary finishes
   the VDF first and knows the "coin" before honest parties reveal it.
   Unpredictability is violated by construction, using the clock's own
   tolerated assumption.
3. **A VDF output inherits only the unpredictability of its input, and
   in async the input is steerable.** With adversarial scheduling and any
   influence over the seed, a party can grind inputs to bias the output.
   Bias-resistance is not provided; it is at best *made costlier*.
4. **Async has no shared reveal instant to protect.** The coin abstraction
   is defined against a reveal moment; the async adversary controls
   delivery and can be evaluating throughout, so there is no instant at
   which "unpredictable-until-now" holds for everyone.

**Under what added assumptions could a VDF-derived beacon bootstrap a
coin?** Only by adding a real entropy/secret mechanism — and then the VDF
is not the load-bearing part:

- **VDF + commit-reveal (RANDAO-style), VDF as anti-grinding backstop.**
  Parties commit contributions, reveal, combine to a seed, then apply the
  VDF so the *last revealer* cannot compute the final output within the
  reveal/decision window and thus cannot selectively withhold. This buys
  **bias-resistance against last-revealer grinding** — but (a) it needs a
  **synchrony bound** on the reveal window (T must exceed even a σ-fast
  evaluation; a *fully async* adversary can stretch the window past T,
  breaking it), and (b) it still does not give unpredictability against a
  σ-fast adversary who computes ahead. So: partial-synchrony
  bias-resistance, *not* an async common coin.
- **VDF + threshold primitive (threshold-BLS/PVSS/DKG).** The threshold
  primitive supplies the secret-until-t-cooperate unpredictability and
  bias-resistance; the VDF adds nothing to those properties. This is just
  "use the threshold coin" — which is D3 option (a), with its DKG and
  pairing (`pq:false`) cost — not a VDF coin.
- **No construction** turns a public deterministic function into a secret.
  There is no VDF-only path to an async common coin.

**Consequence for D3 option (b).** "VDF-derived coin from the R11 clock
plane" does **not**, by itself, satisfy the async common-coin requirement.
It can serve as an *anti-grinding hardening layer* over a commit-reveal
beacon *under a synchrony assumption the async fallback does not have* —
which is precisely the setting D3 exists to cover, so it does not help
there. D3 needs a genuine secret-holding primitive.

---

## 7. RECOMMENDATION — clock role (RES-R11)

**Candidate: class-group Wesolowski (via an independently-vetted,
chiavdf-derived dependency), behind the existing beacon abstraction,
with `pq=false` for the VDF and a documented migration path.** Rationale:

- It is the **only** candidate that satisfies §15's requirements *today*:
  trusted-setup-free, permissionless with one-honest-evaluator, succinct
  O(1) proof with a two-exponentiation seal-verifier check, and an
  **empirically anchored σ** (3.6×–9.1× ASIC ceiling to set the published
  margin above). [chiavdf], [VDFsurvey], [asic-2022-755]
- **Deployment maturity** is decisive: chiavdf is live on Chia mainnet,
  giving real adversarial and timelord-ecosystem exposure no other
  candidate has. [chia-consensus], [chia-timelords]
- **Licensing** (Apache-2.0, patent grant) is clean for ADR-0033;
  transitive deps must be manifested. [chiavdf]
- **Wesolowski vs Pietrzak:** prefer Wesolowski for the O(1) proof and
  because chiavdf's *n-wesolowski* is the battle-tested code path; note
  Pietrzak rests on the *weaker* low-order assumption and verifies faster
  but ships larger proofs and is not the mainnet-hardened implementation.
  Keep Pietrzak as a documented fallback should adaptive-root be
  questioned. [VDFsurvey], [low-order-402], [pietrzak-eth]
- **The sharp caveat, stated up front:** this construction is **not PQ**,
  in tension with rider C7. This is acceptable *only because* A9's
  safety-critical blast radius is confined and fail-closed (§14 waits,
  never adjudicates), so a quantum break degrades liveness/hardening
  rather than corrupting safety — **provided** the `pq` bit + beacon
  abstraction genuinely allow a construction swap without re-genesis
  (must be vetted, §10.7). Adopt with the migration path designed in, not
  bolted on.
- **Do NOT adopt an isogeny VDF** for the clock: research-grade, no
  vetted library, no empirical σ, and (for the mature DFMPS variant)
  trusted-setup + pairing-based non-PQ verification. Track it as the
  PQ-migration watch item. [eprint-1289], [dfmps-pairings], [castryck-decru]

## 8. VERDICT — coin role (RES-R10 D3), separately

**No VDF — class-group, isogeny, or otherwise — satisfies the async
common-coin requirement (§6). The clock recommendation does not carry
over to the coin.** D3's coin must come from a genuine secret-holding
primitive, evaluated on its own merits as a *separate* cryptographic
adoption:

- **Option (a) threshold-BLS/PVSS coin** is the standard, well-understood
  choice (unpredictable + bias-resistant under an honest threshold), at
  the cost of a DKG and a pairing assumption (`pq:false`) — the same PQ
  tension C7 flags, and it must be reconciled with the engine's
  *accountability-anchored* (not 2/3-intersection) safety story
  (`r10_...` §1.5). A PQ-oriented alternative (e.g., a lattice/PVSS-based
  threshold VUF) would itself be research-grade and needs its own review.
- **Option (c) committee hash-coin** is cheapest but assumes a weaker
  adversary (an honest committee majority that cannot grind), and should
  be scoped explicitly if chosen.
- Whichever is chosen, **D4's composition rule holds**: the coin
  *schedules*, never *authorizes* — every fallback decision keeps the
  signed-header + guardian-certificate evidence surface, so a biased coin
  costs liveness, never safety (`r10_...` §2, D4). This is the property
  that makes an imperfect coin tolerable; it does not make a VDF a coin.

## 9. Can ONE primitive serve BOTH roles? — explicit answer

**No.** The roles have contradictory core requirements:

| | Clock (R11) needs | Coin (R10 D3) needs |
|---|---|---|
| Output visibility | **Public**, verifiable by anyone | **Secret** until reveal |
| Determinism | **Deterministic** (objective, reproducible) | **Unpredictable** to the adversary |
| Party influence | Doesn't matter (public function) | **Bias-resistant** (no party steers) |
| Adversary speedup σ | Tolerated (priced by margin) | **Fatal** (fast adversary predicts early) |

The very determinism and public verifiability that make a VDF an
*excellent clock* are exactly what disqualify it as a coin. Collapsing
RES-R11 and RES-R10 D3 into a single adoption is **not available**. R11
adopts a class-group VDF as the clock; R10 D3 must separately adopt a
secret-holding coin primitive. The VDF *may* appear in a coin
construction only as an anti-grinding backstop over a commit-reveal
beacon **and only under a synchrony assumption the async fallback lacks**
(§6) — i.e., not in the setting D3 needs it.

---

## 10. What must be EXTERNALLY VETTED before adoption (rule-12 / ADR-0033)

This review is assessment, not adoption. Before any of the above becomes
load-bearing, an external cryptographer / audit must sign off on:

1. **The class-group arithmetic dependency.** Security + correctness
   audit of the chosen chiavdf (or fork) code path: NUDUPL/reduction
   correctness, proof-verification soundness, build reproducibility, and
   the GMP/MPIR/Boost/pybind supply chain. Public inputs mean
   side-channels are out of scope, but a wrong group operation is
   safety-load-bearing. [chiavdf]
2. **Discriminant / parameter choice.** That the discriminant size meets
   the target security level for class-group order hardness, and — load
   bearing — that the discriminant is derived from a **public
   nothing-up-my-sleeve seed**, not chosen, so no one holds a structural
   backdoor; plus domain-separated seal-hash → VDF-input seeding (§15.1).
3. **The hardness assumption.** External sign-off that the
   adaptive-root (Wesolowski) — or low-order (Pietrzak) — assumption holds
   for the specific class group and parameters, including the low-order-
   element / 2-torsion handling that class groups require. [VDFsurvey],
   [low-order-402]
4. **The published σ margin (highest-priority number).** Independent
   review that σ is set above the demonstrated ASIC advantage
   (≈3.6×–9.1×) with margin for future hardware, since σ feeds the
   T5b / §14 safety-critical waits — an under-set σ is a real safety hole
   (T-CLK-1). [asic-2022-755], [asic-tches], [chia-timelords]
5. **Licensing.** ADR-0033 LICENSE-MANIFEST entry for chiavdf (Apache-2.0,
   patent-grant scope confirmed) and every transitive dependency. [chiavdf]
6. **Seal-verifier cost budget.** That the O(1)/O(log T) verify fits the
   per-seal path without becoming a DoS vector (T-CLK-3); rate/econ bound.
7. **PQ migration path.** That the beacon abstraction + `pq` bit truly
   permit swapping the VDF construction without re-genesis, and an
   explicit statement of what a quantum break *degrades* (clock
   liveness/hardening) vs *cannot break* (the fail-closed §14 safety
   uses). [hallgren], [biasse-song]
8. **The coin primitive is a SEPARATE adoption.** If D3 proceeds, its
   async common coin (threshold-BLS + DKG, or a PQ threshold VUF, or a
   scoped committee hash-coin) is its own cryptographic review and
   ADR-0033 decision — independent of, and not satisfied by, the R11 VDF
   (§6, §8).
9. **Isogeny track stays a watch item.** No adoption; revisit only if a
   trusted-setup-free, implemented, benchmarked isogeny VDF with a
   settled post-SIDH assumption base and a publishable σ appears.
   [eprint-1289], [castryck-decru]

---

## Sources

- [chia-consensus] Chia, "Chia's New Consensus Algorithm" v0.9 — https://www.chia.net/wp-content/uploads/2022/09/Chia-New-Consensus-0.9.pdf
- [chiavdf] Chia-Network/chiavdf (Apache-2.0; Wesolowski / n-wesolowski over class groups; C++/GMP/NUDUPL) — https://github.com/Chia-Network/chiavdf
- [chia-timelords] Chia docs, Timelords (VDF evaluators; open-hardware norm) — https://docs.chia.net/chia-blockchain/architecture/timelords/
- [VDFsurvey] Boneh, Bünz, Fisch, "A Survey of Two Verifiable Delay Functions" — https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf
- [low-order-402] "A Note on Low Order Assumptions in RSA groups" — https://eprint.iacr.org/2020/402.pdf
- [pietrzak-eth] "Implementation Study of Cost-Effective Verification for Pietrzak's VDF in Ethereum Smart Contracts" — https://arxiv.org/pdf/2405.06498
- [asic-2022-755] "Low-latency Hardware Architecture for VDF Evaluation in Class Groups" — https://eprint.iacr.org/2022/755
- [asic-tches] "Low-Latency Design and Implementation of the Squaring in Class Groups for VDF Using Redundant Representation," IACR TCHES — https://tches.iacr.org/index.php/TCHES/article/view/9958
- [eprint-1289] Chavez-Saab, Rodríguez-Henríquez, Tibouchi, "Verifiable Isogeny Walks: Towards an Isogeny-based Postquantum VDF," SAC 2021 — https://eprint.iacr.org/2021/1289
- [dfmps-pairings] De Feo, Masson, Petit, Sanso, "Verifiable Delay Functions from Supersingular Isogenies and Pairings," Asiacrypt 2019 — https://www.semanticscholar.org/paper/Verifiable-Delay-Functions-from-Supersingular-and-Feo-Masson/139f9d445f1b8c0ef8a484f56140159d41abebc3
- [mariascrs] Corte-Real Santos, "Trusted Setup with Isogenies" (three drawbacks of the DFMPS isogeny VDF, incl. trusted setup) — https://www.mariascrs.com/2021/01/23/Trusted-Setup.html
- [accel-isogeny] "Accelerating Isogeny Walks for VDF Evaluation," IACR CiC — https://cic.iacr.org/p/2/1/30
- [castryck-decru] Castryck, Decru, "An Efficient Key Recovery Attack on SIDH," Eurocrypt 2023 — https://eprint.iacr.org/2022/975
- [hallgren] Hallgren, "Fast quantum algorithms for computing the unit group and class group of a number field," STOC 2005 (class-group structure/order in quantum polynomial time) — https://dl.acm.org/doi/10.1145/1060590.1060661
- [biasse-song] Biasse, Song, "Efficient quantum algorithms for computing class groups and solving the principal ideal problem," SODA 2016 — https://epubs.siam.org/doi/10.1137/1.9781611974331.ch64

---

*Internal protocol context; non-canonical. Advisory only — no primitive
here is adopted or load-bearing until the §10 external vetting and the
ADR-0033 decision complete (owner ruling, rule 12).*
