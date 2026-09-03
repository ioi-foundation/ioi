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

## T4a — Live-tier liveness and ring non-interference

Assumes: A1, A5.

**Statement.** Block production advances independently of the ring under the
selected live profile. The optimistic profile is responsive after GST under
its exact `n=3f+1`, `q=2f+1` bound. After the durable D2 trigger, the normative
hash-only profile has randomized asynchronous progress against a static
Byzantine adversary with `f<n/3`, reliable private authenticated channels and
eventual delivery. No Boundary Ring rule appears in either proposal, vote,
fallback, or commit path, so a stalled ring cannot stall unrelated live-tier
ordering.

**Proof.** Optimistic quorum intersection and timeout-certificate relay are
the D1/D2 executable obligations. D3 instantiates the Das–Duan–Liu–Momose–Ren–
Shoup hash-only ACS construction with its explicitly declared static-adversary
model; exact rooted availability, ordering, and executed-block certificates
bind its selected set to AFT authority. D4 carries the highest authenticated
lock into the fallback and fences later optimistic authority at that height;
randomness schedules and selects but never signs or authorizes. The bounded
composition model proves the one-height non-conflict seam, and the adverse
simulation plus four-validator production/cold-restart drill establish trace
conformance at `n=4, f=1`. This is randomized termination, not a deterministic
time bound or an adaptive-security claim.

Ring non-interference is structural: by §11.4, the only ring-to-live edge is
the release gate for effects TYPED irreversible. Block production, ordering,
and reversible effects consult no seal. A ring stall therefore delays only
irreversible-effect release (unsealed-over-unsafe). ∎

Mechanization: P2.2's two-tier separation property and
`OptimisticFallbackComposition.tla`; executable evidence is
`../evidence/m3-adversarial-release-gate-2026-09-03.md`. Pairing: L-A.

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

## T5d — Succession adjudication: responsive impossibility and scheduled safety

Assumes: A1, A2, A3, A9.

The scheduled theorem additionally requires the formation-time clock-fenced
lease defined below. A10 is required only by the stronger
gapless-continuation variant; it is not needed for slot-disjoint scheduled
succession.

**STATUS: RESOLVED (2026-08-18) — RESPONSIVE succession is PROVEN
IMPOSSIBLE; SCHEDULED succession is SAFE and MECHANIZED.** A clean-slate
theorem challenge (two procedurally-isolated fresh-context theorists,
each given only the model and the safety property, blind to v1–v3)
CONVERGED on the answer the three refuted formulations were circling:
detection-triggered (responsive) succession cannot be both safe and live
in the asynchronous model — a dead ring is indistinguishable from a
partitioned one (CAP + FLP; robust to randomization). The verifiable
clock cannot help because it certifies elapsed TIME, never the original
ring's future INACTION. The only escape is a CLOCK-FENCED LEASE
pre-consented at formation (an honest member emits no signature past a
public deadline `T`); because seals are n-of-n, one fenced honest member
vetoes every future original seal, so a SCHEDULED succession (standby
seals strictly above the fence, slot-disjoint from the original) is safe
with no cross-ring view. This is machine-checked in
`SuccessionSchedule.tla` (TLC green; deleting the fence reproduces the
fork), and the full adjudication is in `p4`-adjacent
`t5d_succession_resolution.md`. The prior "v4 conditions" question is
answered: there is no v4 RESPONSIVE design to find. The final flagship
rung stays unreachable (it was gated on a mechanized *positive*
pre-consented-succession theorem with R11+R12 landed; the resolution
sharpens that residual into an impossibility rather than opening the
rung). Historical record of the refutation rounds follows. The round-5
review proved the SuccessionClock kernel discharges a strictly NARROWED
statement (the Byzantine standby has no modeled behavior; obs_commit is
never adversary-chosen; the theorem's "binding" restriction excludes
exactly the genuine-but-void rivals that still fork executors — R5-F3),
and refuted the v3 spec twice independently (R5-F1 obs_commit padding;
R5-F2 unwired voidness + the expiry/void contradiction).
Historical record of the first two refutations: The round-1
formulation was refuted (publication ≠ delivery under asynchrony); its
round-2 repair was refuted in turn (the succession medium is an unmodeled
consensus object with no consistency rule and no stamp witness —
R2-F1/R2-F2 — and its voidness rules broke normal operation, R2-F3).
The original RESPONSIVE positive claim is WITHDRAWN and refuted, not
design-open. The active T5d result is the resolved pair above: responsive
succession is impossible in the pure asynchronous model, while scheduled,
slot-disjoint succession is safe under the explicit formation-time fence.
That scheduled result is mechanized but is not a cadence, death-detection, or
production-admission theorem. The final responsive flagship rung is therefore
unreachable under its current wording. The block below is retained only as the
historical refuted-and-repaired draft; no downstream surface may cite it as an
operative protocol or positive responsive result. (A1 joined the historical
draft's Assumes line per R2-F10.5 — that draft verifies signatures throughout.)

**Historical draft statement (non-normative, rebuilt after round 1).** No reachable state contains both a fallback-released
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

Mechanization: the resolution kernel is `SuccessionSchedule.tla` (TLC:
scheduled succession safe — `Disjoint` and `NoFork` hold over all
reachable states; the fence-deleted mutation reaches the fork,
mechanizing the impossibility). `SuccessionClock.tla` survives as the
honestly-narrowed P2.7 kernel of the withdrawn responsive draft.
Pairing: L-S. The succession lower-bound question is answered: responsive
safe succession with liveness is impossible in the pure asynchronous model.
The clock-fenced lease is necessary and sufficient for the scheduled,
slot-disjoint form; a known staleness bound is additionally required for
gapless continuation. Formalization is
`t5d_succession_resolution.md` + `SuccessionSchedule.tla`. The unavailable
positive responsive theorem remains a claim-ladder blocker, not an `L-OPEN`
pairing row.

## T6 — Composition (the lattice meet)

Assumes: A1.

**Statement.** Requirements, verified constituent evidence, and transforms
are three distinct types. For every guarantee coordinate `p`, the verifier
reports the meet of the load-bearing constituents' verified `p` labels. A
constituent that bears no claim for `p` cannot grant it; a constituent declared
evidence-only for `p` is neutral only where the coordinate definition says so.
A wrapper may strengthen `p` only through a versioned rule whose independent
verifier establishes new evidence for `p`, names the permitting theorem, and
commits to the exact inputs and output. The default for every rule and unknown
version is refusal. PQ coordinates use conjunction, exact scopes survive only
on equality, and unrelated safety, availability, collateral, liveness, and
externalization coordinates never promote one another.

**Proof.** A1 binds each certificate to its profile and evidence bytes. The
certificate-only verifier discards any wrapper-reported vector and recomputes
the coordinate meet. Policy evaluation accepts only its opaque verified
result, so a caller cannot substitute a requirements join or a structurally
valid raw claim. For each coordinate, the meet is sound because every
load-bearing constituent establishes at least that value; it is the greatest
such certificate-only report by the lattice definition. L-M proves that any
unverified above-meet report is indistinguishable from an execution in which
the stronger property is false. A verified transform changes the information
available to the verifier, so it escapes that indistinguishability argument
only for the coordinate and theorem its new evidence establishes. Exhaustive
profile/rule matching and the signed transformation commitment make unknown
profiles, rules, inputs, outputs, or cross-coordinate substitutions fail
closed. ∎

Mechanization: `GuaranteeMeet.tla` (11,666 generated / 5,833 distinct states),
the opaque `VerifiedGuaranteeV1` runtime algebra, exhaustive profile census,
and the laundering negative corpus. Pairing: L-M.

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
the entire violating coalition — all n signers of the configuration. The
convicted-to-necessary ratio is 1.0, which is maximal (L9). A monetary floor
does not follow from attribution alone; only T11's separately verified bond
snapshot may establish one.

**Proof.** By T7, two conflicting seals convict every member of `C_v`
individually, for any holder of both. Each conviction is an A1-sound share
pair (§12.5) admissible as slashing evidence against that member's bond
(the bond exists by the membership plane's registration rule, §9). The
violation requires all n (a UBC is n-of-n), so necessary = n and convicted
= n: ratio 1.0. L9 states no protocol can attribute beyond the signers of
the conflicting certificates, so 1.0 is the ceiling and T9 meets it. Whether
those identities have distinct, live, unencumbered and enforceably slashable
bonds is an independent state claim resolved by T11, not assumed here. The
lineage-escape variant (P1.3 round 1, F11) — converting a
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
verification in the signer). Pairing: L9.

## T10 — Consequence at-most-once externalization

Assumes: A1.

**Statement.** Let one accepted effect authorization commit an
`EffectManifestV1` whose exact adapter/resource profile exposes an atomic
put-if-absent, compare-and-set, or equivalent idempotency register. If the
durable executor persists `Claimed` and `InFlight` before its only mutation
invocation, and every state at or after `InFlight` recovers through same-key
lookup rather than reinvocation, then the authorization causes at most one
modeled external-resource mutation. Its receipt binds the intent, request,
predecessor, expected outcome, observed outcome, and reconciliation evidence.
A conflicting resource record yields transferable attribution only when its
evidence verifies under the committed resource profile; ordinary timeout or
network ambiguity is not attributed.

**Proof.** Before `InFlight` no resource call is enabled. The transition to
`InFlight` is device-flushed before the executor calls the resource. Exactly
one code transition out of `Claimed` owns that call, and the resource's atomic
register maps the stable idempotency key to at most one record. A clear reply
persists `Executed`; an ambiguous reply persists `Unknown`. If the process
crashes after the call but before either persistence, restart observes durable
`InFlight` and moves only to `Unknown`. `Executed` and `Unknown` enable only
lookup of the same key and then `Reconciled`; neither enables the mutation
call. Thus all crash, retry, and duplicate-delivery histories contain at most
one invocation by this authorization, and the atomic register contains at
most one corresponding mutation. L-X shows why the endpoint primitive is a
necessary boundary rather than an implementation convenience. For
attribution, A1 plus the committed resource-profile verifier authenticates a
contradictory record; without such evidence the runtime emits only local
ambiguity and constructs no blame proof. ∎

Mechanization: `AtMostOnceExternalization.tla` (66 generated / 42 distinct
states, depth 8), plus Rust trace-conformance, every-boundary crash injection,
duplicate-delivery, unsupported-profile, and forged-evidence tests. Pairing:
L-X.

## T11 — Evidence-qualified distinct collateral floor

Assumes: A1.

**Statement.** Given transferable A1-sound accountability evidence naming a
non-empty implicated member set and an objective signed-fault predicate, the
offline verifier reports exactly the sum, in one native asset, of the distinct
collateral lots in a committed snapshot that (i) belong exclusively to those
members and the implicated configuration, (ii) accept that exact evidence
predicate under one committed slashing contract, (iii) were locked at the
snapshot and remain locked through the complete challenge horizon, and (iv)
are neither withdrawing nor encumbered. Every implicated member must have a
qualifying lot. Duplicate bond IDs or collateral-lot IDs, shared configuration
assignments, mixed assets/contracts, expired locks, and mismatched claimed
amounts refuse. Withholding and silence yield no floor. Optional oracle
assumptions remain visible metadata and never inflate the native-unit sum.

**Proof.** A1 authenticates the implicated signed-fault evidence. The snapshot
root commits every bond field used by the decision. The verifier requires a
strictly increasing bond-ID list and inserts every underlying collateral ID
into a set, refusing a repeated insertion; therefore each lot contributes at
most once. It checks exact equality for configuration, evidence predicate,
asset, and slashing contract, and checks lock, challenge, withdrawal and
encumbrance predicates before arbitrary-precision addition. It independently
recomputes the snapshot root, selected-set root, minimum lock horizon, exact
sum, and complete `EconomicAssuranceV1`, then accepts only equality with the
portable claim. L-C shows that omitted eligibility/distinctness evidence
cannot soundly support a larger floor. The result says nothing about
acquisition cost, asset value, liquidity, corruption supply, or configuration-
capture probability. ∎

Mechanization: `DistinctCollateralFloor.tla` (33 generated / 8 distinct
states, depth 4), the arbitrary-precision Rust verifier, duplicate/expired/
unlocked/encumbered attack corpus, and a guard-deletion mutation. Pairing: L-C.

## T12 — Portable PQ-channel coverage for one authorized payload

Assumes: A1.

**Statement.** Let a portable receipt identify the exact static member set of
one PQ-issued hash-asynchronous ordering certificate and the exact canonical
finality-bundle hash authorizing an effect. If the receipt contains exactly
one valid `PqChannelCompletionEvidenceV1` for every unordered pair of distinct
members, then an offline verifier soundly reports `channel_pq=true` for that
authorized payload. Every evidence object must bind the same network,
configuration, epoch, channel profile, ML-KEM-768 handshake transcript,
derived-key confirmation, protected-payload hash, and both members' rooted
ML-DSA-44 identities. Missing, duplicate, out-of-scope, classically
authenticated, singly attested, or mutated edges refuse. The result proves
complete demonstrated-path coverage and transferable endpoint
accountability; it does not prove secrecy of historical traffic, delivery,
adaptive security, or an unobserved all-time channel property.

**Proof.** The finality verifier independently reconstructs the static member
set and finality-bundle hash from the PQ-issued certificate. A canonical
unordered-pair set over `n` distinct members has exactly `n(n-1)/2` elements.
For every submitted edge, the channel verifier checks the ML-KEM transcript,
both rooted ML-DSA handshake signatures, both derived-key-completion
attestations, the exact scope, and the exact protected-payload hash; the
coverage verifier refuses a repeated pair and then exact-compares the observed
pair set with the complete pair set. Consequently each load-bearing member
pair on this demonstrated payload has independently authenticated PQ channel
completion evidence. L-PQCH shows why neither a profile boolean nor the same
finality bytes alone can establish this coordinate. The conclusion is then
fed through T6's meet rule with consensus and endpoint evidence. ∎

Mechanization: the versioned Rust verifier and its complete-graph, missing-edge,
duplicate-edge, endpoint-signature, transcript, scope and payload mutation
corpus. Pairing: L-PQCH.

**Portable authorization boundary.** T12 and the other receipt-carried
results establish properties relative to externally selected roots; they do
not let a receipt select those roots. A production offline decision therefore
also requires `PortableAssuranceTrustV1`, provisioned independently of the
receipt, that pins network, configuration, epoch, terminal-key root, receipt
signer, anchors, and the relying party's guarantee floor. A self-consistent
parallel configuration remains cryptographically valid data but is not
authority for that relying party.

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

## L-S — Responsive succession cannot infer inaction from silence

Assumes: none beyond the pure asynchronous schedule being challenged.

**Statement.** A responsive succession rule for disjoint configurations cannot
both (a) preserve single-slot safety and (b) eventually replace every dead
configuration when its trigger is derived only from silence or elapsed time in
an asynchronous network. Safe slot-disjoint succession instead requires a
formation-time authority fence; gapless continuation additionally requires a
known staleness/delivery bound or an equivalent inaction oracle.

**Proof.** Construct two executions with the same successor-visible prefix. In
`E_dead`, the original configuration emits nothing and is permanently dead.
In `E_partitioned`, it is alive behind a partition and has already produced,
or may still produce, a valid conflicting seal that has not reached the
successor. Any responsive rule that eventually activates in `E_dead` must act
at some finite successor-visible prefix. It acts at the indistinguishable
prefix in `E_partitioned`, where the two disjoint configurations can authorize
conflicting values. Randomization cannot restore safety: fix any coin outcome
on which the required activation occurs. Elapsed-time evidence distinguishes
neither execution because it proves time, not future inaction.

A formation-time lease changes the executions rather than detecting them: at
least one honest original signer has already committed not to sign above a
public slot/time fence. Since the original certificate is unanimous, that
pre-commitment prevents every later original seal above the fence, making the
original and successor slot ranges disjoint. It supplies scheduled safety but
does not identify death or preserve a gapless prefix. Gapless continuation
needs the successor to know that every earlier valid seal has surfaced, which
is exactly a staleness/delivery bound or equivalent oracle. The formal mutation
in `SuccessionSchedule.tla` removes the fence and reaches the conflicting-seal
state. ∎

Pairs with: T5d.

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

## L-A — Asynchronous agreement requires randomness and the one-third bound

Assumes: none (impossibility bounds).

**Statement.** A deterministic protocol cannot guarantee consensus
termination in a fully asynchronous message-passing system even with one
crash fault (FLP). In the standard asynchronous Byzantine-agreement model used
by the selected hash-only construction, `f<n/3` is the optimal resilience
boundary. Therefore no implementation in that model can soundly promise both
the same agreement/termination properties and either deterministic
termination or tolerance of `f>=n/3`.

**Argument.** FLP supplies the first impossibility directly: an admissible
message schedule can keep a deterministic consensus execution bivalent.
Randomized common-coin/ASKS steps escape that schedule only probabilistically;
they do not create an elapsed-time bound. The second boundary is the standard
three-way indistinguishability partition for asynchronous Byzantine
agreement. The selected construction explicitly identifies its `t<n/3`
resilience as optimal and proves randomized ACS at that boundary. AFT uses
exact `n=3f+1`, so T4a meets rather than evades the bound. See
Das et al., *Asynchronous Consensus without Trusted Setup or Public-Key
Cryptography*, CCS 2024 / IACR ePrint 2024/677, and Shoup, *A Theoretical Take
on a Practical Consensus Protocol*, IACR ePrint 2024/696. ∎

Pairs with: T4a.

## L-M — Reporting above the meet is unsound

Assumes: none (counterexample construction).

**Statement.** For any guarantee coordinate `p`, a verifier whose complete
input is the same constituent-certificate bytes in two executions cannot
soundly report `p` above their verified meet when `p` differs between those
executions. A wrapper certificate over those same bytes does not change the
bound. Strengthening requires new independently verified evidence that rules
out the weaker execution.

**Proof.** Fix the constituent bytes `C`. Construct executions `E0` and `E1`
that expose exactly `C` to the verifier and satisfy every label attached to
`C`, but where a stronger property `p+` is false in `E0` and true in `E1`.
Such a pair is exactly what it means for `p+` not to follow from the verified
constituent labels—for example, identical PQ seal bytes can wrap classical BLS
ordering, identical conflict certificates can coexist with unavailable
payloads, and identical timeout bytes say nothing about permission to
downgrade finality. A deterministic certificate-only verifier has identical
input in `E0` and `E1`, hence identical output. If it reports `p+`, it is false
in `E0`; if it does not, it has not strengthened. Re-signing `C` with a wrapper
key preserves indistinguishability. New evidence verified under a theorem for
`p` changes the input and is the only escape, scoped to that coordinate. Thus
the meet is the greatest sound certificate-only report. ∎

Pairs with: T6.

## L-X — Ambiguous externalization requires endpoint deduplication

Assumes: none (indistinguishability construction at the external boundary).

**Statement.** Without an atomic endpoint-visible idempotency register or an
equivalent operation, no client can guarantee both retry progress and
at-most-once mutation after an ambiguous response.

**Proof.** Consider two executions with the same client-visible trace: in
`E0` the endpoint mutates and the success reply is lost; in `E1` the request is
lost before mutation. After the timeout the client state is byte-identical.
If it retries, a non-deduplicating endpoint may mutate twice in `E0`; if it
does not retry, the requested consequence never occurs in `E1`. Local durable
logging distinguishes neither execution because ambiguity lies beyond the
client's crash boundary. An atomic same-key register changes the observable
contract: retry/lookup returns the one prior record instead of issuing an
independent mutation. Therefore T10's resource premise is necessary for its
combined safety/reconciliation claim. ∎

Pairs with: T10.

## L-C — Unproved collateral eligibility cannot raise a slashable floor

Assumes: none (indistinguishability construction over verifier inputs).

**Statement.** An offline verifier cannot soundly count a collateral lot more
than once, or count a lot whose exclusivity, lock, challenge horizon,
encumbrance state, ownership, predicate, or enforcement contract is absent
from its authenticated snapshot.

**Proof.** For any omitted condition construct two external states with the
same verifier-visible bytes: in one the lot is distinct, exclusive, locked,
unencumbered and slashable by the named proof; in the other it is an alias of
an already counted lot, shared, expired, withdrawn, encumbered, owned by an
unimplicated party, or controlled by an incompatible contract. The verifier
must return the same result in both states, so counting the lot is unsound in
the second. Duplicate identifiers are the direct alias case. Authenticated
snapshot fields and exact predicate/contract checks distinguish the states;
without them the only sound floor excludes the lot. This bounds T11 at the
sum of distinct lots whose complete eligibility is proved. ∎

Pairs with: T11.

## L-PQCH — Channel properties require authenticated channel evidence

Assumes: none (indistinguishability construction over transported bytes).

**Statement.** A verifier given only an authorized payload or consensus
certificate cannot soundly infer that the channel carrying it was
post-quantum authenticated. A profile label or wrapper assertion over those
same bytes does not change the bound. Establishing `channel_pq=true` requires
independently authenticated evidence binding the relevant endpoints, scope,
PQ handshake, completion, and exact protected payload.

**Proof.** Construct two executions that yield byte-identical finality
certificates and payloads. In `E_pq`, every relevant member pair transports
the payload over the declared ML-KEM/ML-DSA channel. In `E_classical`, one
load-bearing pair transports the same bytes over a classically authenticated
channel (or no authenticated PQ session at all). A verifier seeing only the
certificate and payload has identical input and therefore identical output in
both executions; reporting `channel_pq=true` is false in `E_classical`.
Re-signing a boolean assertion merely moves the unsupported claim into a
wrapper. Per-edge dual-endpoint evidence bound to the exact payload and a
complete rooted membership set distinguishes the executions, and T12 states
the resulting positive theorem. ∎

Pairs with: T12.

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
| T4a live-tier liveness | L-A (FLP randomness necessity + optimal `f<n/3` asynchronous resilience) | cited; RES-R10 closed by the hash-only adverse/production drill |
| T4b seal cadence | L2 (unanimity forces 1-withholder stall) | cited |
| T5a membership canonicity | L1 (per configuration) | cited |
| T5b bootstrap | L-LR (long-range indistinguishability — a NECESSITY bound: it forces some anchor, and does not certify any mechanism's sufficiency; mechanism (iv) is accordingly a hardening layer only, per F6) | cited |
| T5c′ reconfiguration | L2 + L1 | cited |
| T5d succession adjudication | L-S (silence cannot prove inaction; fence necessity) | cited; responsive positive claim refuted; scheduled slot-disjoint safety mechanized; no cadence claim |
| T6 composition | L-M (above-meet unsoundness) | cited |
| T7 forensic accountability | L9 (attribution cap) | cited |
| T8 selection supply | — | **L-OPEN** (cheapest-capture supply bound: P4.2 analysis) |
| T9 maximal accountable safety | L9 (ratio 1.0 is the cap) | cited |
| T10 consequence at-most-once externalization | L-X (ambiguous-response retry dilemma) | cited; proved and model-checked |
| T11 distinct collateral floor | L-C (unproved collateral eligibility cannot raise a floor) | cited; proved and model-checked; T8 remains separate and open |
| T12 portable PQ-channel coverage | L-PQCH (transport bytes do not reveal channel properties) | cited; executable complete-graph proof and mutation corpus |

One `L-OPEN` row stands: T8's cheapest-capture supply lower bound. Per the
claim ladder, the frontier-completeness flagship does not print while that row
is open (see `p4_claim_adjudication.md`). Independently, the responsive T5d
flagship condition is impossible under the pure asynchronous model; resolving
its lower bound does not create the missing positive cadence theorem.
