# Common Boundary — Paper Theorems and Lower-Bound Pairing (AFT-CB)

Status: internal protocol spec (AFT corpus); non-canonical; research candidate.
Authority: `docs/architecture/` owners and accepted ADRs are canonical and win
on drift. The assumption ledger's single owner is the whitepaper §5.3
(A1–A10); protocol rules cited as §n live in
[`common_boundary.md`](./common_boundary.md) (P1.1). Every proof here is a
**paper proof** — checked by hand, not by TLAPS; the mechanized successors
land under `../formal/common_boundary/` (P2.x) and each theorem below names
its planned mechanization leg. Nothing here is an unconditional quantitative
security claim; every statement is conditional on the AFT common-boundary
model delta.

Machine-checkable convention (enforced by
`.github/scripts/check_aft_theorem_assumes.sh`): every theorem block carries
exactly one `Assumes:` line; only `A1`–`A10` tokens (or `none`) appear on it;
no safety theorem lists A5 (T4a/T4b are the only blocks permitted to);
A9 appears only in T5b (the A6-iv hardening) and T5d; A10 (the
succession-medium observation bound) appears only in T5d; T8 is stated as a
probability, carries its full model, and appears in no deterministic
theorem's proof; T1's block contains no timing vocabulary; the pairing
table exists and every row is a citation or a named `L-OPEN`.

---

## T1 — Uniqueness within one configuration

Assumes: A1, A2, A3.

**Statement.** For any configuration `C_v` and seal slot `s`, at most one
Unanimous Boundary Close exists for `(v, s)`: two UBCs for `(v, s)` carrying
different boundary roots imply that zero members of `C_v` are honest (¬A2).
The claim is weight-independent and holds under adversarial message
delivery and adversarial scheduling; the adversary controls all delivery
and emits arbitrary signed messages for corrupt members (A1 excludes only
forgery of honest signatures).

**Proof.** Suppose UBCs `U_X` and `U_Y` exist for `(v, s)` with roots
`X ≠ Y`. By the wire format (§12), each certificate carries an individually
verifiable final-ack share from EVERY member of `C_v` over its
domain-separated tuple; by A1 none of these shares is forged. Hence every
member of `C_v` produced a final-ack for `(v, s, X)` and a final-ack for
`(v, s, Y)`. An honest member final-acks at most once per `(v, s)` — the
single-final-ack discipline is journal-enforced across crashes (A3; §1.2,
§2.2: recovery replays the journaled tuple and never re-decides, and a
member that cannot read its journal refuses the slot). So no member of
`C_v` is honest, contradicting A2. Retries do not weaken the argument:
pre-acks are attempt-tagged and never enter a certificate (§1.1); the
final-ack is attempt-untagged, so uniqueness quantifies over the slot, not
the attempt. One structural premise is named rather than smuggled (P1.3
round 1, AC-8): the proof consumes the fact that a pre-ack can never be
reinterpreted as a final-ack share — §1 now establishes this doubly
(distinct signing keys, distinct domain tags over distinct tuples), so a
certificate verifier structurally cannot accept promoted pre-acks; this is
a wire-format premise of the theorem in exactly the T7 sense. ∎

Mechanization: P2.1 (`BoundaryRing.tla` + TLAPS inductive invariant).
Pairing: L1.

## T2 — Completeness (censorship at the seal layer)

Assumes: A1, A2, A4.

**Statement.** An artifact received by at least one honest signer before
that signer's local cutoff (§3.1) is contained in every boundary that
signer final-acks, hence in the unique close for the slot (T1). Censoring
an artifact out of a sealed boundary requires corrupting all n signers
(¬A2) or preventing it from reaching any honest signer (¬A4).

**Proof.** Let honest member `m` receive artifact `a` before `m`'s cutoff.
Then `a` is in `m`'s signed declared set (§3.1). `m` final-acks a candidate
boundary `B` only if `B ⊇` its declared set (§1, ACK rule), so every
final-ack `m` emits is over a root whose preimage contains `a`. A UBC
requires all n shares, including `m`'s (A1 prevents substituting a forged
share), so the closed boundary contains `a`. Absent such an `m`, either no
honest signer exists (¬A2) or `a` reached none (¬A4). Batch granularity is
handled by §11.3: a sealed batch must cover the closed boundary, and each
boundary member absent from the batch carries a typed, verifiable omission
justification — so post-close omission is either justified or invalidates
the seal. ∎

Mechanization: P2.1 (completeness invariant over declared sets).
Pairing: L-E.

## T3 — Availability (custody-attested)

Assumes: A1, A2, A4.

**Statement.** A UBC implies that every compliant signer obtained the full
byte set, recomputed the boundary root, and retains and serves the bytes
through `T_retrievable`; under A2 at least one signer is honest (hence
compliant), so a sealed boundary's bytes are HELD AND SERVED through the
horizon, deterministically — with zero audit records — and a retriever
that can reach at least one honest signer obtains them. (A4 is on this
line per round 1's AC-6 — possession is A1+A2, retrieval additionally
needs reach — and the LEDGER's A4 row was re-scoped in round 2 (R2-F11)
to cover the retriever edge explicitly, so this use now matches the
owner's text rather than stretching it.) Deletion by the other n−1 members
does not affect retrievability.

**Proof.** By §4, validate-and-hold is a signing obligation: the final-ack
signature MEANS the signer obtained the bytes, recomputed the root, and
committed to retain and serve. This is definitional, not detective — a
signer that signed without holding is dishonest by definition. A UBC
carries all n signatures (A1: none forged), so all n made the commitment;
A2 supplies one honest member, which therefore actually holds and serves.
Retrieval needs one holder plus a path to it: the retriever reaching that
honest signer is exactly the A4-class reachability now on the Assumes line
— possession alone (A1+A2) does not hand bytes across a network. The
other n−1 deleting is harmless. The
pairwise audit lane (§4) produces slashing evidence and is not load-bearing:
no step of this proof consults an audit record, which is exactly the
zero-audit gate P2.4 checks. ∎

Mechanization: P2.4 (`CustodyObligation.tla`: close-time replication at
compliant signers). Pairing: L-H.

## T4a — Live-tier liveness

Assumes: A5.

**Statement.** Block production advances under the live engine's own fault
bound and partial-synchrony assumption (A5), independently of the ring:
no Boundary Ring rule appears in the live tier's proposal, vote, or commit
path, so ring stalls do not affect block liveness.

**Proof.** The live tier is GuardianMajority operating under its existing
model; its liveness argument is the engine's own and is not restated here.
What this theorem adds is non-interference, and that is structural: by
§11.4, the only protocol edge from ring to live tier is the release gate
for effects TYPED irreversible; block production, ordering, and reversible
effects consult no seal. A ring stall therefore delays irreversible-effect
release and nothing else (unsealed-over-unsafe). The engine's optimistic
responsiveness is inherited; its asynchronous-fallback obligation is
tracked as R10 and deliberately NOT claimed here. ∎

Mechanization: P2.2's two-tier separation property (live-tier progress
abstraction stays green while the ring is stalled). Pairing: L-OPEN
(the live engine's own asynchronous bound is R10's subject; no lower
bound is cited until the fallback is landed or the residual filed).

## T4b — Seal cadence

Assumes: A2, A3, A4, A5.

**Statement.** With all n members responsive and honest-behaving for the
slot, post-GST (A5), seals advance at bounded cadence: each pipeline phase
(§0) completes within a bounded number of message delays, so consecutive
seals close within a bounded interval. A single non-responsive member
freezes seal cadence — never the chain (T4a) — until a §9 handover or a
§14 re-genesis. (The §16 succession extension is design-open with its
claims withdrawn and is deliberately not listed as an operative exit —
the round-3 audit caught this sentence still selling it.)

**Proof.** Two model inputs are named, not smuggled (P1.3 round 1, AC-7):
this theorem reads A5's delivery bound in its ledgered form — PAIRWISE
delivery within Δ between honest parties, i.e. the full honest mesh is
part of what A5 asserts — and it consumes the deployment parameter
`V_slot` bounding per-slot artifact volume, which appears in this
statement's cadence bound as stated, not silently. Post-GST every message
among responsive members arrives within Δ (A5). COLLECT and RECONCILE
converge: set-digest exchange over the full mesh reaches a fixed point in
O(1) rounds, each round ≤ Δ. The proposer assembles B = union of declared
sets (≤ `V_slot` bytes), members discharge validate-and-hold in local work
bounded by `V_slot`, journal (A3's storage is live for honest members) and
final-ack within Δ, and the closing member assembles the n-share
certificate within Δ. Every step needs all n (unanimity), so one withheld
ack blocks the CLOSE step — cadence freezes; no rule substitutes a smaller
quorum (that is L2's forced trade, accepted). The chain continues by T4a.
Completeness within the closed slot is preserved under A4 (T2's
condition). ∎

Mechanization: P2.2 (`BoundaryLiveness.tla`: TLC positive seal advancement
at n≤4, plus the freeze direction under one silent member — both labeled
"model-checked at n≤4", never "proven"). Pairing: L2.

## T5a — Membership canonicity under unanimous transitions

Assumes: A1, A2, A3.

**Statement.** For every lineage segment whose transitions are UBC-closed:
two valid lineages diverging at version `v` imply every member of `C_v`
final-acked both diverging transitions — full-configuration
self-incrimination — hence zero honest members in `C_v` (¬A2). Under
per-configuration MHA the configuration lineage from a given root is
unique.

**Proof.** A transition `C_v → C'` is a typed transition record closed by
a UBC of `C_v` (§9.1). Divergence at `v` means two UBCs of `C_v` over
different transition records for the same transition slot. Apply T1's
argument verbatim at that slot (A1 shares unforgeable; A3 single
final-ack): every member of `C_v` double-acked, so none is honest. The
self-incrimination is constructive: the two certificates exhibit each
member's conflicting share pair (§12.5). Induction over versions from the
root gives lineage uniqueness while each configuration satisfies A2. ∎

Mechanization: P2.3 (`MembershipTransition.tla`, T5a obligation).
Pairing: L1 (applied per configuration).

## T5b — Bootstrap (validity + freshness, separately)

Assumes: A1, A7, A6 (anchor as deployed; A9 iff the elapsed-history
hardening is enabled — the hardening is not an anchor and cannot be the
deployed mechanism, per its round-2 downgrade).

**Statement.** A newcomer that (1) verifies the lineage's recursive proof
chain from genesis and (2) runs exactly one deployed A6 freshness
mechanism obtains: validity of the lineage under A7 (or under A1 alone via
full replay), and liveness-relevant freshness under the deployed
mechanism's own assumption, cited by name. A newcomer with no live A6
mechanism is out of model (§7.3) — stated, not smoothed.

**Proof.** Validity: the recursive proof attests the transition relation
from genesis (A7 soundness; A1 for the embedded signature checks); full
replay derives the same under A1 alone. Freshness, per mechanism: (i) an
authenticated checkpoint within window `W` bounds the adversary to forks
younger than the unbonding window, within which equivocation is
self-incriminating (T5a) and slashable — cross-checking k sources detects
it; (ii) with per-seal evolution and verified erasure (A8, §13), former
members' historical keys do not exist, so no party can re-sign old slots:
a fork purporting to be history fails share verification (A1); (iii) an
external objective checkpoint pins the head by assumption; (iv) —
REQUALIFIED by P1.3 round 1 (its drill k refuted the standalone reading) —
the lineage-embedded VDF chain (§15) is a HARDENING layer, never a
standalone anchor: it forces a long-range forger to re-run sequential
work in real time (A9), making recent forks physically impossible within
`elapsed/σ` and old forks slow and expensive, but a PATIENT or σ-fast
forger accumulates an equal-or-longer tick chain that tick comparison
cannot reject — tick length evidences work and elapsed time, never WHICH
history is live. Freshness under (iv) therefore rests on the anchor it
hardens — here structurally (ii), since per-seal evolution + erasure is
mandatory (§13), so the forger's keys do not exist. Each mechanism's cost
and assumption are stated in the deployment record; the theorem never
claims freshness without naming which anchor is live. ∎

Mechanization: P2.3 (bootstrap-freshness obligation, A6-conditional in the
theorem statement itself). Pairing: L-LR.

## T5c′ — Assurance-preserving reconfiguration

Assumes: A1, A2, A3.

**Statement.** Every strong-ring transition carries old-ring unanimity AND
new-ring acceptance, so configuration lineage is MHA-inductive end to end
with no weight anywhere in the strong chain. No proof-of-silence path
exists: the transition action set contains no silence-derived action, so
no accumulation of non-response records can move a seat. An anchored
re-genesis is a typed lineage root, never continuity.

**Proof.** By §9, the only ordinary transition is the handover requiring
(a) a UBC of `C_v` over the typed record and (b) acceptance signatures
from every member of `C_{v+1}` (A1 for both). Induction: if `C_v` is the
unique version-v configuration of its lineage (T5a under A2 at v), then
any closed transition is unique (T1 at the transition slot), and its
successor is the unique version-(v+1) configuration; acceptance makes the
successor's obligations (§4, §13, and the §16 draft's publication duty —
that last design-open) contractual from its first slot,
so A2 at v+1 continues the induction. No step consults stake weight — the
chain is honesty-inductive, not weight-inductive. The silence claim is
structural rather than behavioral: §10.2 defines the action set, and no
action in it takes a non-response record as input (P2.3 asserts this over
the formal action set; R5 makes it unrepresentable in types). The §16
draft's succession WOULD be a pre-signed T5c′-class transition if the
design-open extension lands (its authority would be formation-time
unanimity — nothing in THIS theorem depends on it; the operative
transition set is §9 handover alone, plus §14 roots which are not
transitions), and §14's re-genesis is typed as a root: `prev_seal_hash`
chains do not cross it and verifiers report a seam (§14.4), so it cannot
be mistaken for — or claim the guarantees of — continuity. ∎

Mechanization: P2.3 (T5c′ obligation + the no-silence action-set
assertion). Pairing: L2 (unanimity forced at f = n−1) and L1.

## T5d — Pre-consented succession safety

Assumes: A1, A2, A3, A9, A10.

**STATUS: DESIGN OPEN — CLAIM WITHDRAWN (P1.3 rounds 1–2).** The round-1
formulation was refuted (publication ≠ delivery under asynchrony); its
round-2 repair was refuted in turn (the succession medium is an unmodeled
consensus object with no consistency rule and no stamp witness —
R2-F1/R2-F2 — and its voidness rules broke normal operation, R2-F3).
Per the estate's twice-falsified-design scar and the program doc's named
fallback, this theorem's claim is WITHDRAWN: the block below is the
refuted-and-repaired DRAFT kept for the P2.7 respecification (whose
commissioned direction — standby-UBC-committed observation sets under
`S_v`'s own MHA, no bulletin, no stamps — is recorded in spec §16's
status banner), the final claim-ladder rung remains unreachable, and the
operative exits on ring death are §9 handover and §14 labeled
re-genesis. No downstream surface may cite T5d until the respecification
survives its own adversarial review. (A1 joined the Assumes line per
R2-F10.5 — the draft proof verifies signatures throughout.)

**Draft statement (non-normative, rebuilt after round 1).** No reachable state contains both a fallback-released
irreversible effect for a slot and a BINDING conflicting old-ring seal for
that slot — where bindingness is the old ring's own formation-time
pre-signed rule (§16.3): a share stamped at or past the slot's authority
expiry (`t_{s−1} + T_halt`) is void, and a seal not anchored in the
pre-named succession medium by `t_{s−1} + T_halt + T_expire` is void.
Succession activates only on the objective trigger, is pre-signed by the
full old ring, and preserves continuity typing. The predecessor claim —
quantifying over "published" rather than "binding" seals — was REFUTED
under pure asynchrony (P1.3 round 1, drill i) and is not restored; this
statement is the honest, weaker-but-real one: late-surfacing old-ring
material is not prevented, it is VOID, by the old ring's own signature.

**Proof.** All thresholds are σ-margined (§15.4), so under A9 tick
comparisons are real-time sound. Consider slot `s` with predecessor seal
tick `t_{s−1}`, and suppose a binding conflicting old-ring seal `S`
exists. By bindingness (§16.3b), `S` was anchored in the succession medium
by tick `t_{s−1} + T_halt + T_expire`. By A10, the acting successor
observes everything anchored by that tick within `G_deliv` further ticks —
that is, by `t_{s−1} + T_halt + T_expire + G_deliv ≤ t_{s−1} + T_halt + G`
(§16.4's constraint on `G`). The fallback releases `s`'s irreversible
effects no earlier than `t_{s−1} + T_halt + G`, and a conflicting observed
seal preempts release (§16.4). So `S` was observed before release and the
fallback aborted — contradiction. Hence no binding conflicting seal
coexists with a released fallback effect. Conversely, material surfacing
after release is void by §16.3 (fresh post-trigger shares void by stamp;
late-anchored assemblies void by deadline — both checkable from signed
stamps and the chain, A9, with no delivery assumption), so the released
effect never faces a binding rival. A2/A3 situate the theorem: the trigger
tick is objective from the seal-seeded chain (§15.1); honest members'
single-final-ack discipline (A3) keeps the old ring's pre-trigger sealing
unique (T1), so "the last seal" is well-defined; and the
honest-publication duty (§16.5) is a liveness courtesy — no step of this
proof consults it, and no step consults crash-recovery latency.
Activation adds no new ring authority: the transition was unanimously
signed at formation or by sealed refresh (§16.1), a T5c′-class continuity
step; re-genesis remains the only root. ∎

**What A10 does and does not carry.** A10 is an observation bound on ONE
pre-named public bulletin — the successor's view of the medium — not
cross-partition delivery. Under a partition that cuts the old ring off
from the medium, the old ring's post-trigger material is void by its own
pre-signed rule and the successor proceeds safely; the partitioned honest
old ring loses those slots (a priced liveness cost), it does not fork
history. Succession under pure asynchrony with no such assumption is
impossible — a dead ring and a partitioned ring are indistinguishable —
and the ledger now prices this (A10) instead of the proof smuggling it.

Mechanization: P2.7 (`SuccessionClock.tla`: the reachability theorem over
BINDING seals, the voidness rules, the no-silence trigger assertion, the
grace-window and anchoring-deadline mutations). Pairing: L-OPEN (the
necessity of a scoped observation assumption for any safe succession —
conjectured forced by the round-1 asynchrony argument; formalization
open).

## T6 — Composition (the lattice meet)

Assumes: A1.

**Statement.** Every certificate profile (live-tier QC, guardian
certificate, witness, observer, UBC, re-genesis root) carries a
machine-readable assumption label; the collapse verifier computes the meet
over all constituents; a collapse object's effective guarantee is exactly
its weakest constituent's, including the `pq` bit (AND, §18.2). There is
no silent degradation between tiers.

**Proof.** Labels are part of the signed content of each certificate (A1:
they cannot be detached or swapped). Soundness of each individual label is
its profile's own theorem (a UBC's label by T1–T3; a live-QC's by the
engine's model; a root's by its anchor mechanism). For the composite:
define the guarantee order as the assumption-lattice order (label ℓ₁ ≤ ℓ₂
iff every execution satisfying ℓ₁'s vector satisfies ℓ₂'s). The meet of
the constituents is, by definition of meet, the greatest label ≤ every
constituent's; the composed object's actual guarantee is bounded by each
constituent (an adversary that breaks one constituent breaks the
composition that relies on it), so the meet is an upper bound on what may
be soundly reported, and it is achieved because the verifier checks each
constituent against its own label. Reporting the meet is therefore exact:
anything stronger is unsound (L-M), anything weaker discards guarantee.
The `pq` AND is the meet restricted to the pq coordinate (§18.2).
Exhaustive matching over profiles (R6: adding a profile without a label is
a compile error) closes the "silent new profile" hole mechanically. ∎

Mechanization: R6 unit gates (meet tests, pq-meet tests,
exhaustive-match-by-construction). Pairing: L-M.

## T7 — Forensic accountability (accountable degradation)

Assumes: A1.

**Statement.** Proven against the wire format of §12, not an abstraction:
above the fault threshold, either no seal exists for a slot, or ANY PARTY
HOLDING both conflicting seals for `(v, s)` extracts a cryptographically
attributable set containing every participant necessary for the violation
— for n-of-n UBCs, the entire configuration. Holder-relative, stated so
after P1.3 round 1 (F10): §12.3's broadcast duty binds honest members
only, so an all-Byzantine signer set can complete a second certificate
over private channels and withhold it — surfacing is guaranteed by USE
(a certificate must be presented to be acted on, and presentation makes
its recipient a holder), by honest broadcast, and by watchtowers, never
by wire-format magic. The extraction procedure is specified and runs on
the two certificates alone.

**Proof.** Conflicting seals `U_X`, `U_Y` are bitmap-complete with
individually verifiable shares over domain-separated tuples (§12.1–12.2),
and shares are broadcast (§12.3), so any observer can hold both
certificates. Extraction (§12.5): verify each certificate; for each member
`m_i`, exhibit the pair (share over `(…, X, …)`, share over `(…, Y, …)`).
Each pair is an A1-sound conviction of `m_i` — two valid signatures by
`m_i`'s key over conflicting tuples for one slot. Since a UBC requires all
n shares, every member was necessary for each seal, so the convicted set =
the necessary set = all n. The wire-format smallnesses are load-bearing,
which is why they are in the theorem: point-to-point-only shares would let
a member deny having completed a certificate an observer cannot assemble;
attribution-destroying aggregation (an opaque combined signature) would
prove the CONFIGURATION equivocated while convicting no individual member,
forfeiting the per-member exhibit this proof constructs; omitting domain
separation would let a share be replayed across slots or lineages. Hence
the format rules of §12 are premises, and the theorem is false without
them. ∎

Mechanization: P2.6 (`ForensicAccountability.tla` over the wire-level
certificate structure; staged all-Byzantine double-seal trace extracting
the full set). Pairing: L9.

## T8 — Selection supply (probabilistic, forever separate)

Assumes: none (this block is an economic MODEL, not a ledger-consuming
theorem; its beacon-unpredictability input is §17.1/§15's mechanism,
carried as a model parameter — deliberately not a ledger citation, so the
ledger discipline that reserves the physical-clock assumption to T5b's
A6-iv mechanism and T5d stays exact).

**Statement (a probability, never a tolerance figure).** Under a stated
model M = (adversary budget `B_adv`, seat-allocation and bond schedule,
constituency-correlation structure `ρ` over the diversity floors,
adaptive-corruption window from sortition unpredictability,
standby-capture term for the pre-named standby set), the probability that
open selection yields at least one honest signer in a formed
configuration is

P[MHA holds for C_v] ≥ 1 − P[every constituency simultaneously captured | B_adv, ρ] − P[adaptive corruption succeeds in the post-seating window] ,

published as a probability with all model inputs, and recomputed when the
model's inputs move. The standby configuration's capture probability is
modeled by the same form with its own (worse, pre-named) exposure and
reported separately.

**Model discipline.** (1) The adversary budget is explicit: seats
purchasable at the bond floor through the public queue, subject to churn
caps and `D_act` delay. (2) Correlation is explicit: MHA fails only if
every constituency (jurisdiction, implementation, operator class, stake
source) fails at once; the correlation matrix is published, not assumed
independent. (3) The adaptive-corruption term exists because sortition
(§17.1) narrows targeting to after-seating/before-sealing; the beacon's
unpredictability enters as a model parameter (its physical grounding lives
in §15, cited by the mechanisms that consume it, not here). (4) The standby-capture term exists because C2's
standby is known in advance (§16.1/§16.7). (5) Composition rule: T8
composes with the deterministic ladder ONLY as "deterministic safety
conditioned on the selection event" — this document and every downstream
surface are forbidden from converting this probability into a
deterministic Byzantine-tolerance figure, and the deterministic theorems
above neither cite this block nor depend on it. (6) Substance disclosure
(P1.3 round 1, F15): the adaptive term's unpredictability parameter is
grounded in the same physical VDF property the ledger prices for the
deterministic mechanisms; if the published σ is falsified, the adaptive
term must be recomputed — a model-input dependence, deliberately not a
ledger citation, because this block makes no deterministic claim for a
ledger line to guard.

Mechanization: none (economic model; P4.2 owns the published computation).
Pairing: L-OPEN (a supply lower bound — the cheapest capture strategy —
is P4.2 analysis work, recorded open).

## T9 — Maximal accountable safety

Assumes: A1.

**Statement.** Any seal-uniqueness violation cryptographically convicts
the entire violating coalition — all n signers of the configuration — with
slashable floor `n × bond`. The convicted-to-necessary ratio is 1.0, which
is maximal (L9): finality with a price tag, by construction.

**Proof.** By T7, two conflicting seals convict every member of `C_v`
individually, for any holder of both. Each conviction is an A1-sound share
pair (§12.5) admissible as slashing evidence against that member's bond
(the bond exists by the membership plane's registration rule, §9). The
violation requires all n (a UBC is n-of-n), so necessary = n and convicted
= n: ratio 1.0. L9 states no protocol can attribute beyond the signers of
the conflicting certificates, so 1.0 is the ceiling and T9 meets it. The
economic floor follows: n bonds are simultaneously slashable on the
evidence. The lineage-escape variant (P1.3 round 1, F11) — converting a
same-slot double-seal into a "fresh lineage" via a self-serving re-genesis
— is closed UPSTREAM OF THIS THEOREM, by §14.2's admissibility machinery:
a root whose own embedded chain reference shows the prior lineage
non-stale is self-refuting and participation in it slashable, and
continuity outranks an unhardened root, while a hardened root's finality
is CONDITIONAL and contest fails closed (§14.2's bounded orphaning plus
the round-4 correction: cross-lineage adjudication awaits the P2.7
observation story; the escape-closure itself — self-refuting roots
slashable, live-lineage roots orphanable — stands on the objective
chain alone). That closure's clock consumes A9 on
§14's OWN Assumes line (per R2-F9 — it is §14's assumption, and this
sentence attributes rather than absorbs it); T9's core claim and its A1
line are untouched by it. So the maneuver changes the offense's name,
not its price. ∎

Mechanization: P2.6 (attribution completeness); R9 (share-level
verification in the signer); the economic floor is P4.2's parameter work.
Pairing: L9.

---

## Lower bounds

## L1 — MHA is the weakest possible honesty assumption for uniqueness

Assumes: none (adversary construction in the bare model).

**Statement.** With zero honest ring members, seal uniqueness is
unattainable: an all-Byzantine configuration can produce two valid
conflicting UBCs for the same slot, and no protocol rule can prevent it.
Hence any uniqueness theorem must assume at least one honest member — A2
is not a convenience but the minimum.

**Proof.** The n corrupt members hold their own keys; they sign
`(v, s, X)` and `(v, s, Y)` with all n shares each. Both certificates are
bitmap-complete and every share verifies — they are valid by construction
of the verification rule, which checks signatures and format, both
satisfied. No additional rule can distinguish them: any rule computable
from public data is satisfied by both certificates symmetrically (the
adversary can produce both transcripts). So uniqueness fails. Contrapositive:
uniqueness requires ≥1 member who refuses the second signature — an
honest member. ∎

Pairs with: T1, T5a.

## L2 — The unanimity trade is forced

Assumes: none (counting argument).

**Statement.** For a q-of-n certificate family: safety against f Byzantine
signers requires `2q − n > f`; liveness under f withheld signatures
requires `q ≤ n − f`; at `f = n − 1` the only safe quorum is `q = n`, and
then a single withholder stops progress. All-but-one safety therefore
FORCES unanimity, and unanimous certificates cannot be 1-honest-immune in
liveness: AFT-CB's safety/liveness split (stall-never-fork, cadence
freezes) is on the frontier, not near it. The same inequalities price any
k-of-n fallback exactly, should MHA ever be deliberately weakened.

**Proof.** Safety: two conflicting q-certificates share at least `2q − n`
signers (inclusion-exclusion over n seats). If `2q − n ≤ f`, the adversary
places all shared signers among its f corrupt members and signs both —
no honest member signs twice, yet both certificates complete: safety
fails. So safety needs `2q − n > f`, forcing an honest member into every
intersection. Liveness: f withheld signatures leave `n − f` available;
a certificate needs `q ≤ n − f`. At `f = n − 1`: safety gives
`2q > 2n − 1`, so `q = n`; liveness would need `q ≤ 1`, impossible for
`n > 1`. Hence no q-of-n family is simultaneously all-but-one-safe and
1-withholder-live; choosing safety costs cadence liveness exactly as T4b
concedes. ∎

Pairs with: T4b, T5c′ (unanimity of transitions).

## L-E — Completeness requires reachability (eclipse bound)

Assumes: none (schedule construction).

**Statement.** If an artifact reaches no honest signer before any honest
cutoff (total eclipse of the submitter), no protocol in this model can
guarantee its inclusion: A4 is necessary for T2, not decorative.

**Proof.** The adversary delivers the artifact only to corrupt members.
Every honest member's declared set omits it (a declared set is what was
received, §3.1); the candidate boundary is the union of declared sets, in
which only corrupt members' sets could contain it — and corrupt members
may declare anything, including its absence. A boundary omitting the
artifact then closes with all n final-acks, each honest one truthful.
Nothing in any rule distinguishes this execution from one where the
artifact never existed — the honest members' views are identical. So
inclusion cannot be forced. ∎

Pairs with: T2.

## L-H — Availability requires a holder

Assumes: none (information argument).

**Statement.** If zero custody-obligated signers are honest, retrievability
of sealed bytes cannot be guaranteed: A2 is necessary for T3.

**Proof.** Bytes are physical: if every party holding them deletes them,
no protocol rule can reproduce them (the seal contains roots, not
preimages). With all n signers corrupt, all n may sign the
validate-and-hold obligation, then delete; the certificate remains valid
(signature verification cannot see storage). Any later retrieval query
fails against every member. The obligation's meaning (§4) makes this
attributable dishonesty — slashable if audited — but attribution is not
availability: the bytes are gone. Hence one honest holder is necessary. ∎

Pairs with: T3.

## L-LR — Costless bootstrap is impossible (long-range bound)

Assumes: none (indistinguishability argument).

**Statement.** In the quasi-permissionless setting, a newcomer given only
self-consistent signed chains — with no freshness mechanism of any A6
class — cannot distinguish the live lineage from a fork re-signed by a
fully-unbonded former configuration whose keys still exist. Some
separately-priced freshness mechanism is necessary; A6 is a forced menu,
not caution.

**Proof.** Construct: configuration `C_v` completes its unbonding window
and later leaks (or sells) its historical keys; the adversary re-signs an
alternative history from the divergence point forward, internally
consistent, every certificate verifying under A1 — because the signatures
are genuine, merely re-used. A newcomer holding both chains sees two
A1-valid, structurally identical lineages. Any deciding rule computable
from the chains alone decides identically on both under relabeling (the
construction is symmetric). Distinguishing them requires an input from
OUTSIDE the chains: a recent checkpoint (A6-i/iii), or a cryptographic
guarantee that old keys cannot re-sign (A6-ii — which is why A8's erasure
defeats the construction: the keys to re-use no longer exist). A physical
cost asymmetry (A6-iv) is deliberately NOT listed as a distinguisher: as
P1.3 round 1 established (F6), a patient or σ-fast forger accumulates an
equal-or-longer VDF chain, so tick length alone cannot select the live
head — (iv) prices and delays the construction; it does not defeat it.
Each anchor is exactly an A6 mechanism; none is free. ∎

Pairs with: T5b.

## L-M — Reporting above the meet is unsound

Assumes: none (counterexample construction).

**Statement.** A composition verifier that reports any label strictly
stronger than the meet of its constituents' labels is unsound: there is an
execution where the reported guarantee fails while every constituent's
label is satisfied.

**Proof.** Let composed object O contain constituent c whose label ℓ_c is
strictly below the reported label ℓ_r in some coordinate (definition of
"above the meet"). Take an execution where exactly the assumptions of ℓ_c
hold and the stronger coordinate of ℓ_r fails (such an execution exists
because the lattice order is semantic, §T6). Break c there — by ℓ_c's own
theorem being tight at its assumptions, c's guarantee can fail in that
execution — and O, which relies on c, fails with it, while ℓ_r asserted
it could not. So ℓ_r is unsound; the meet is the strongest sound report
(T6 shows it is achievable, so it is exactly right). ∎

Pairs with: T6.

## L9 — Attribution is capped at the signers

Assumes: none (indistinguishability argument).

**Statement.** No protocol can cryptographically attribute a
seal-uniqueness violation to any party beyond the signers of the
conflicting certificates. T9's ratio 1.0 (all n convicted, all n
necessary) is therefore the maximum any protocol can achieve — classical
quorum-BFT forensics, by contrast, convicts at most the quorum
intersection, capping near a third of the committee.

**Proof.** The violation's public evidence is the two conflicting
certificates and any transcript messages. A party `p` that signed neither
certificate: for any transcript containing `p`'s other messages, there is
an execution in which `p` behaved honestly and the transcripts are
byte-identical (the adversary can simulate every non-signature
contribution of `p`, and `p`'s signatures appear on nothing conflicting).
Cryptographic conviction requires evidence attributable uniquely to `p`
under A1-class unforgeability — that is, `p`'s signature over conflicting
content — which by assumption does not exist. So the attributable set ⊆
signers of the conflicting certificates. T9 convicts exactly that set
when it equals all n (n-of-n certificates), achieving the bound. ∎

Pairs with: T7, T9.

---

## Lower-bound pairing table

Every positive theorem cites its matching lower bound or records a named
`L-OPEN` residual. Frontier-completeness claims are printable only when
this table has zero `L-OPEN` rows (P4.4 gate).

| Positive theorem | Lower bound | Status |
|---|---|---|
| T1 uniqueness | L1 (zero-honest equivocation) | cited |
| T2 completeness | L-E (eclipse) | cited |
| T3 availability | L-H (holder necessity) | cited |
| T4a live-tier liveness | — | **L-OPEN** (engine's asynchronous bound is R10's subject) |
| T4b seal cadence | L2 (unanimity forces 1-withholder stall) | cited |
| T5a membership canonicity | L1 (per configuration) | cited |
| T5b bootstrap | L-LR (long-range indistinguishability — a NECESSITY bound: it forces some anchor, and does not certify any mechanism's sufficiency; mechanism (iv) is accordingly a hardening layer only, per F6) | cited |
| T5c′ reconfiguration | L2 + L1 | cited |
| T5d succession safety | — | **L-OPEN + CLAIM WITHDRAWN** (refuted rounds 1–2; design-open pending the P2.7 respecification and its own review; the lower-bound question — necessity of a scoped observation assumption for any safe succession — remains open with it) |
| T6 composition | L-M (above-meet unsoundness) | cited |
| T7 forensic accountability | L9 (attribution cap) | cited |
| T8 selection supply | — | **L-OPEN** (cheapest-capture supply bound: P4.2 analysis) |
| T9 maximal accountable safety | L9 (ratio 1.0 is the cap) | cited |

Three `L-OPEN` rows stand. Per the claim ladder, the frontier-completeness
flagship does not print while any row is open; the interim conditional
claim (whitepaper §5.3) does not require this table to be closed.
