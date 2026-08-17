# Common Boundary — Boundary Ring and Unanimous Boundary Close (AFT-CB)

Status: internal protocol spec (AFT corpus); non-canonical; research candidate.
Authority: `docs/architecture/` owners and accepted ADRs are canonical and win
on drift; this file is private protocol context only. The assumption ledger's
single owner is the whitepaper §5.3 (A1–A10); this spec restates the ledger for
self-containment and cites it per rule. Every safety statement here is
conditional on the AFT common-boundary model delta; nothing in this document
is an unconditional quantitative security claim.

This document is the AFT-CB P1.1 protocol specification. It defines the
Boundary Ring, the Unanimous Boundary Close (UBC), and every named protocol
subtlety as its own normative section (§1–§19). Paper theorems land beside
this file as [`common_boundary_theorems.md`](./common_boundary_theorems.md) (P1.2);
mechanized kernels land under `../formal/common_boundary/` (P2.x). The
Boundary Ring is evidence formation inside the kernel-owned collapse plane —
no rule in this spec mints authority beside it.

## 0. Model, actors, and the assumption ledger

**Actors.** A versioned signer configuration `C_v = {m_1..m_n}` (the strong
ring), publicly committed; the live tier (GuardianMajority BFT) producing
blocks continuously under its own bounds; submitters; watchtowers (anyone);
VDF evaluators (anyone). `n` is a deployment parameter (16–64 is the studied
range), never a theorem input: theorems need only that every seal binds a
known committed configuration.

**Two tiers, one state machine.** The live tier produces blocks on its own
critical path. The ring operates off the critical path: it collects
artifacts continuously and periodically closes an n-of-n super-finality seal
over a batch of live-tier blocks (§11). Irreversible-effect release binds to
seals; everything reversible rides the live tier. A ring stall delays seals,
never blocks: **unsealed-over-unsafe**.

**Seal pipeline per slot.** COLLECT (submitters reach any member; full-mesh
gossip) → RECONCILE (set-digest exchange until local cutoff, §3) → VALIDATE
& HOLD (§4) → PROPOSE (rotating proposer assembles candidate boundary B =
union of declared sets) → ACK (§1, §2) → CLOSE (UBC: n-of-n
attribution-preserving multisignature, §12).

**Assumption ledger (owner: whitepaper §5.3; restated for self-containment).**

| Id | Assumption (compressed) |
|----|----|
| A1 | signature unforgeability + hash collision resistance |
| A2 | MHA: ≥1 honest, non-equivocating signer per committed configuration (economically bought, never proven) |
| A3 | honest single-final-ack discipline over crash-consistent storage |
| A4 | reachability to ≥1 honest signer: for submitters (completeness, T2) and for retrievers (availability's serving path, T3) — re-scoped by the P1.3 round-2 review from "completeness only", which T3's repaired statement had outgrown |
| A5 | post-GST Δ-synchrony — pairwise delivery within Δ between honest parties (full honest mesh) — + bounded dishonest live-tier weight (live tier and seal cadence only; no strong-ring safety rule cites A5) |
| A6 | a historical-freshness ANCHOR, exactly one deployed, separately priced (bootstrap only): (i) recent checkpoint within W; (ii) forward-secure/puncturable keys + secure erasure (structurally always-on here, §13); (iii) external objective checkpoint. (iv) VDF elapsed-history is a HARDENING layer over an anchor — it raises the real-time cost of long-range forgery (requires A9) and is NOT a standalone anchor (§15.5) |
| A7 | proof-system soundness for succinct verification (full replay needs only A1) |
| A8 | per-seal key evolution with verified immediate erasure; NO signing-capable material ever persists to any medium that outlives its slot — the durable journal stores signature OUTPUTS only (§2, §13); PQ one-time/hash-based migration path |
| A9 | VDF sequentiality with bounded adversary hardware advantage σ (physical). Scope stated at its true blast radius (P1.3 round-2 correction): A9 is the protocol's objective clock wherever ticks are read — cadence references (§3), deadlines (§8), tick stamps (§11–§12), re-genesis admissibility (§14), the chain itself (§15), sortition (§17) — with SAFETY-critical consumption confined to the A6-iv hardening (T5b) and the design-open succession extension (T5d) |
| A10 | succession-medium observation: an object ANCHORED in the pre-named succession medium (§16.0) by tick X is observed by the acting successor within `G_deliv` further ticks. A scoped availability assumption on one public bulletin — not cross-partition delivery — consumed by T5d ALONE; the uniqueness/lineage ladder (T1–T3, T5a, T5c′) never cites it |

**Where synchrony lives, exactly.** The uniqueness/lineage ladder (T1, T2,
T3, T5a, T5c′) consumes no timing assumption of any kind. The live tier and
seal cadence consume A5. The OPTIONAL pre-consented succession extension
(§16, T5d) consumes A10 — an observation bound on one pre-named public
medium — because succession under pure asynchrony is impossible:
distinguishing a dead ring from a partitioned one is exactly the
distinction an asynchronous system cannot make, and the review that forced
this paragraph (P1.3 round 1, drill i) demonstrated the failure
concretely. The design answers with pre-agreed priority (the old ring's
own signature voids its untimely material, §16.3) so that A10 carries only
the successor's view of the medium, and the ledger prices that honestly
instead of hiding it.

Rule format: every section carries an `Assumes:` line naming the ledger
entries its rules consume. A rule that needs an assumption not on that line
is a spec defect.

---

## 1. Ack state machine under proposer retries

Assumes: A1, A2, A3.

Per slot key `(v, s)` — configuration version `v`, seal slot `s` — the
proposer may retry candidate boundaries. Retries are safe because pre-acks
and final-acks are different objects, **cryptographically separated in two
independent ways** (either alone suffices; both are mandatory):

- **Pre-ack**: signed by the member's long-lived IDENTITY key (never the
  per-seal key) over the domain-tagged tuple
  `("aft-cb/pre-ack", lineage_id, v, s, attempt, boundary_root)` —
  attempt-tagged, advisory, superseded by any later pre-ack for the same
  slot, bounded per proposer turn (below). A pre-ack commits to nothing
  beyond "this candidate covers my declared set as of this attempt"; it
  can never satisfy a certificate verifier, which checks the final-ack
  domain tag and the per-seal key.
- **Final-ack**: signed by the member's PER-SEAL key `k_s` (§13) over the
  domain-tagged FULL seal tuple of §12.2 —
  `("aft-cb/final-ack", lineage_id, v, s, boundary_root, batch_root,
  prev_seal_hash, tick_ref)` — byte-identical to §12.2's tuple (the P1.3
  round-2 review caught this sentence omitting `tick_ref`; there is
  exactly one final-ack encoding and §12.2 owns it) — attempt-UNtagged,
  exactly one per `(v, s)` per honest
  member, forever (A3). An honest member emits a final-ack only after the
  validate-and-hold obligation (§4) is discharged and `B ⊇` its own
  declared set, and only through the journal protocol (§2). A pre-ack is
  therefore unpromotable into a final-ack share: different key, different
  domain tag, different tuple.
- **Attempt budget**: a proposer's turn carries a deployment-parameter
  budget `K_att` of candidate attempts; members refuse validate-and-hold
  work beyond the budget (a typed refusal, not a silent drop). This bounds
  the fetch-and-validate work a Byzantine proposer can extract per turn
  (the §4 obligation is byte-expensive by design).
- **Volume bound**: `V_slot` is a deployment parameter bounding a slot's
  total boundary bytes. A member refuses (typed) to pre-ack or final-ack
  any candidate whose byte set exceeds `V_slot`, and declared-set
  commitments beyond it are refused at RECONCILE — so the bound T4b's
  cadence proof conditions on is maintained by a rule, not assumed
  (added for the P1.3 round-2 review's R2-F15: a theorem-only token is
  not a bound).

**Rules.**
1. A close (§12) is assembled from final-acks only; pre-acks never enter a
   certificate.
2. An honest member's final-ack for `(v, s)` is unique across all attempts
   and all time. Two final-acks for one `(v, s)` with different roots from
   one member are dishonesty by definition and are cryptographically
   attributable to that member (A1, §12).
3. **Proposer equivocation across retries is harmless to safety**: attempts
   X and Y with different roots may each gather pre-acks freely, but a UBC
   requires all n final-acks on ONE root, and every honest member
   final-acks once — so at most one root can ever assemble n final-acks
   while one honest member exists (A2).
4. **Partition behavior** (the six-step counterexample's dispatch): if
   honest members are split across a partition, neither side assembles
   n-of-n — both stall; if all honest members are on one side, only that
   side can close — unique. Conflict-on-reconnect is unreachable without
   every member of the configuration double-acking (¬A2), and in that event
   the two UBCs are a self-incriminating forensic record (§12). Stall,
   never fork.

## 2. Durable ack-journal crash discipline

Assumes: A1, A3.

The single-final-ack discipline of §1 survives crashes only through a
write-ahead journal; A3 is exactly the assumption that honest members keep
this journal on crash-consistent storage.

**Rules.**
1. **The journal stores the SIGNED SHARE, never key material**: the entry
   for `(v, s)` is the transmit-form final-ack share itself — the full
   §12.2 tuple plus the `k_s` signature over it. Signing and journaling
   are one local sequence: derive the share, durably record it (fsync or
   equivalent), and only then let it leave the process boundary. A share
   observed on the network implies a journal entry exists. The journal
   itself holds signature OUTPUTS only — exactly what the network would
   eventually hold anyway; the sole durable secret is the current
   forward-secure key state, destructively updated per §13.2 so no PRIOR
   slot's key is recoverable from any later image (A8).
2. **Recovery replays bytes, never re-signs and never re-decides**: on
   restart, the member reads the journal. If an entry exists for `(v, s)`,
   the member first completes the §13.2 key-state update if the crash
   interrupted it, then may only re-transmit the journaled share —
   byte-identical — never evaluate the slot fresh and never re-sign
   (nothing needs a key: the journal holds the finished signature). This
   kills the crash-recovery double-final-ack (the second "decision" is a
   byte replay of the first) and bounds the key-compromise surface to
   the current, not-yet-used key state (§13.3's scope note) — historical
   keys are unrecoverable from any post-crash image.
3. **Corrupt or unreadable journal fails closed**: a member that cannot
   establish whether it final-acked `(v, s)` MUST NOT final-ack `(v, s)`.
   The cost is stalled cadence for that slot (§11's stall semantics), never
   a safety risk. Cadence is the price of honesty here, and the live tier
   does not wait (§11).
4. Journal entries are retained at least until the slot's seal is observed
   sealed and the retention horizon of §4 has begun. Ordering with §13:
   sign → journal the share → destructive key-state update → transmit.
   The update precedes first transmission; a crash at any point either
   left no share anywhere (safe: the slot is fresh, and rule 3 governs
   doubt) or left the journaled share (safe: replay-only, update
   completed on recovery). After the update, no interleaving leaves a
   durable image from which the slot's signing key is recoverable.

## 3. Cutoff clocking without a synchrony oracle

Assumes: A1, A2, A4; cadence statements only: A5, A9.

There is no global clock and no synchrony oracle anywhere in a safety rule.

**Rules.**
1. **Cutoff is local**: member `m_i`'s declared set for slot `s` is
   "everything `m_i` received by the moment `m_i` signed its declared-set
   commitment". The commitment is signed (A1) and exchanged during
   RECONCILE. Nothing verifies a cutoff "time"; there is nothing objective
   to verify.
2. **Safety is cutoff-skew-independent**: uniqueness (§1) quantifies over
   whatever sets members actually declared; completeness means exactly
   "an artifact that reached ≥1 honest signer before THAT signer's local
   cutoff is in every boundary that signer final-acks" (A4, A2). Arbitrary
   skew between members' cutoffs narrows completeness's reach, never
   safety.
3. **Cadence targets are advice**: the shared VDF tick stream (§15) gives
   members a common objective cadence reference (A9) for scheduling
   RECONCILE rounds and the cutoff−δ heuristic; seal-cadence claims (the
   only statements about how OFTEN seals close) additionally consume A5.
   No safety rule reads a tick.

## 4. Validate-and-hold as a signing obligation

Assumes: A1, A2.

A final-ack signature MEANS custody. Before final-acking `(v, s,
boundary_root)`, a compliant member has:

1. obtained the FULL byte set of the candidate boundary B (not digests —
   bytes);
2. recomputed `boundary_root` from those bytes and matched it;
3. committed to retain and serve the bytes through the retention horizon
   `T_retrievable`.

Violating any of the three while signing is dishonesty **by definition** —
the obligation is part of the signature's meaning, not an extra protocol
message. Consequences:

- A UBC implies close-time replication at every compliant signer; with A2,
  one honest signer yields conditional availability deterministically —
  no probabilistic custody residue. Deletion by the other n−1 members is
  harmless to retrievability.
- **Pairwise chunk audits are an OPTIONAL enforcement lane**: members may
  randomly audit each other's holdings; a failed audit produces slashing
  evidence. Audits are NEVER a close precondition — a close with zero audit
  records is fully valid (a required audit would make custody probabilistic
  again). The audit lane exists to make deletion slashable, not to make
  availability true.
- Full replication per member; no VRF custody sampling. Erasure coding is a
  recovery/bandwidth lane, never the trust structure.

## 5. Live-tier ejection ladder

Assumes: A5 (live tier's own operation); A1 for record signatures.

Weighted ejection exists ONLY on the live tier — validator-set maintenance
under the live engine's existing weight assumptions.

**Rules.**
1. The ladder (warning → weight reduction → ejection) follows the live
   engine's own governance; its records are typed live-tier maintenance
   records.
2. **Type-enforced firewall**: a live-tier ejection record CANNOT reference
   the strong ring, a ring member qua ring member, a seal, or a
   configuration transition. The implementation makes this
   unrepresentable (R5); this spec makes it a rule so the type is the
   theorem's shadow, not an accident.
3. No output of this ladder is admissible input to any strong-ring
   transition (§9, §16) or to any seal validity rule. A live-tier ejection
   of a person who also holds a ring seat changes nothing about the ring.

## 6. Custody succession (reconstruct-before-release)

Assumes: A1, A2.

Membership change must not tear custody (§4) mid-horizon.

**Rules.**
1. In any handover `C_v → C_{v+1}` (§9), each incoming member MUST
   reconstruct full custody — obtain all bytes under the current retention
   horizon and recompute their roots — before assuming its seat's custody
   duty.
2. **Bond release gates on reconstruction**: the outgoing member's bond
   releases only after the incoming member's signed reconstruction receipt
   for the full horizon verifies. Succession without reconstruction leaves
   the bond locked.
3. The reconstruction receipt is itself a boundary artifact; it rides a
   sealed batch, so custody continuity is part of sealed history.

## 7. Bootstrap

Assumes: A1, A7 (succinct path) or A1 alone (full replay); A6 anchor as
deployed; A9 iff the elapsed-history hardening is enabled; A8 where
anchor (ii) is deployed.

A newcomer establishes two separate things — validity and freshness — and
the spec keeps them separate:

1. **Validity**: verify the recursive proof chain from genesis (A7), or
   replay-verify the full chain under A1 alone. This proves internal
   consistency of a lineage, never that it is the LIVE lineage.
2. **Freshness**: exactly one A6 ANCHOR, deployed by explicit
   configuration and cited by name in the newcomer's verification record
   (the anchor menu has three entries — the round-2 review's R2-F12
   caught the hardening still enumerated as a fourth deployable choice,
   contradicting its own downgrade):
   - (i) a recent authenticated checkpoint within window `W` (= unbonding
     window);
   - (ii) forward-secure/puncturable signatures + secure key erasure — old
     configurations become physically unable to re-sign history (realized
     by A8's per-seal evolution, §13);
   - (iii) an external objective checkpoint.
   Separately, the VDF elapsed-history HARDENING (§15.5) may be enabled
   over whichever anchor is deployed — it is not a menu member and can
   never be the cited mechanism: it prices and delays long-range forgery
   (A9); it cannot select the live head against a patient forger. Anchor
   (ii) is structurally always on here (§13), so the hardening always
   has an anchor beneath it.
3. **Out-of-model is stated, not smoothed**: a newcomer with NO live A6
   anchor is outside the model and the spec says so; no rule pretends
   recursion alone — or tick length alone — yields freshness.
4. **Long-range forks self-incriminate**: conflicting UBCs for one slot
   identify the forked configuration's entire signer set (§12), so
   cross-checking k independent sources detects equivocation and produces
   the forensic record. Under anchor (ii)/A8, post-unbond compromise of
   ALL former members yields no key capable of signing historical slots —
   history is unforgeable even then (§13).

## 8. Challenge receipt-or-silence records

Assumes: A1, A2, A4.

Challenges are first-class boundary artifacts; a UBC proves no admissible
challenge is outstanding (any challenge that reached one honest member by
that member's cutoff is inside the boundary; one that reached no honest
member is by definition inadmissible — A4, A2).

"Missing evidence" is made objective, and only ever fails closed:

1. A canonical challenge-request artifact names the evidence demanded, the
   addressee, and a deadline (in VDF ticks, §15, as reference cadence).
2. Each ring member signs a **receipt** (evidence seen) **or silence
   record** (deadline passed without it) — per-member, attributable (A1).
3. An attested non-response record has exactly ONE power: the challenge
   wins by absence — the protected effect does not release (the
   challenge-dominant doctrine). It is evidence for slashing and for
   voluntary handover pressure.
4. A non-response record is NEVER authority to alter the strong ring — not
   in any quantity, not with any co-signature set (§10).
5. Post-close evidence can slash and can trigger forward-operating governed
   remedies (resolution-log records, descendant fences); it can never
   rewrite a sealed close. Finality's remedy layer is economic, never
   historical.

## 9. Strong-ring handover ceremony

Assumes: A1, A2, A3.

Configurations are event-driven and versioned; there are no calendar
epochs. A configuration lives until an event closes its successor.

The assurance-preserving handover `C_v → C_{v+1}` is the ONLY ordinary
strong-ring transition, and it requires all of:

1. **Old-ring unanimity**: an n-of-n UBC of `C_v` over the typed transition
   record naming `C_{v+1}` (its members, their seats in the CANONICAL
   MEMBER ORDERING — ascending hash of member public key, the ordering
   every §12.1 bitmap indexes — and its policy hash).
2. **New-ring acceptance**: a signature from every member of `C_{v+1}`
   accepting the seat and its obligations (§4 custody, §13 key discipline,
   §16 honest-publication duty).
3. **Custody succession** per §6 before any outgoing bond releases.

The transition record rides a sealed batch, so lineage is itself sealed
history. Versioning: `v` increments exactly at handover; two valid lineages
diverging at `v` imply every member of `C_v` final-acked both transitions —
full-configuration self-incrimination (§12). The ceremony makes lineage
MHA-inductive end to end with no weight anywhere in the strong chain.
Membership entry/exit machinery (bonded registration, activation queue
`D_act`, churn cap `c_max`, unbonding window `W`) feeds candidates into
handovers; none of it moves a seat outside this ceremony or §16/§14.

## 10. The proof-of-silence prohibition

Assumes: A1 (for what records CAN prove); deliberately cites neither A5 nor
any timing assumption — that is the point.

Absence is not objectively provable in an asynchronous system: an attested
non-response record proves that its attesters CLAIM non-response; it cannot
distinguish a crashed member from a slow network from a lying attester set,
and no strong-ring rule may consult a synchrony bound (A5 is barred from
strong-ring safety rules by the ledger itself).

**Rules.**
1. No accumulation of non-response records — any count, any attestation
   weight, any duration — constitutes authority to remove a strong-ring
   member, seat a replacement, or activate succession.
2. The transition action set of this protocol contains NO action whose
   input is an attested-silence record. (P2.3 asserts this mechanically
   over the formal model; R5 makes it unrepresentable in types.)
3. The only strong-ring exits are: the unanimous handover (§9), the
   pre-consented succession on the objective VDF trigger (§16), and the
   labeled anchored re-genesis (§14). Each is loud, typed, and none
   consumes a silence record.
4. Silence records retain their §8 powers only: fail-closed effect
   blocking, slashing evidence, voluntary pressure.

**The exact line this section draws** (sharpened by P1.3 round 1, which
correctly observed that §16's tick trigger infers ring failure from the
absence of a seal): what is prohibited is authority minted from OTHER
PARTIES' CLAIMS about a member's silence — subjective, unattributable-to-
physics evidence, in any aggregation. What §16 executes is different in
kind on two axes, and both are load-bearing: its clock is OBJECTIVE
(elapsed VDF ticks, verifiable by anyone under A9 — not an attestation),
and its authority is the configuration's OWN formation-time unanimous
signature — the ring pre-consented to the exact condition, so activation
executes the ring's standing order rather than overriding it. The
residual truth in the reviewer's observation is priced rather than
denied: a partition can make a live ring look seal-silent, which is why
succession is not fork-safe by cleverness but by the §16 preemption
machinery under its own scoped delivery assumption (A10) — see T5d.

## 11. Batch-seal cadence and irreversible-effect binding

Assumes: A1, A2, A3 (validity); cadence statements: A5, A4; tick references:
A9.

1. **Batch selection**: each seal covers the contiguous range of live-tier
   blocks since the last sealed batch (genesis-anchored for the first).
2. **Seal window**: the ring targets one seal per `W_seal` ticks of the VDF
   reference stream (§15). The window is scheduling advice; only cadence
   claims (T4b-class: "seals advance at bounded cadence when all n are
   responsive") consume A5. No validity rule reads the window.
3. **Seal validity inverts Q1 at batch granularity**: a seal over batch `b`
   is valid iff `b`'s contents cover the ring-collected boundary set for
   the slot, and every boundary member absent from `b` carries a typed,
   verifiable omission justification (`invalid` / `duplicate` /
   `expired`). The sealed batch is checked against the ring-collected
   bulletin; the bulletin is NEVER derived from the batch. The live tier
   can delay an artifact; no seal can close over a batch that silently
   omits one an honest signer collected.
4. **Irreversible-effect binding (unsealed-over-unsafe)**: an effect typed
   irreversible releases only against a seal whose batch contains its
   authorizing artifact. The live tier never waits on the ring: a ring
   stall delays irreversible release and nothing else. Reversible effects
   ride live-tier finality and say so on their receipts (§19).
5. **Stall semantics**: a withheld ack stalls the seal, never the chain.
   The OPERATIVE exits from a stalled ring are §9 handover and §14
   labeled re-genesis — both loud; the §16 pre-consented-succession
   extension is design-open (claims withdrawn, see its status banner)
   and joins this list only when its respecification survives review.
   A stalled ring retains its sealing authority indefinitely under the
   operative rules — stall is harmless-forever, and in particular the
   handover exit remains reachable at any later time (the round-2 review
   showed the withdrawn draft's unconditional expiry silently converted
   stall into forfeiture and made handover unreachable past T_halt; no
   normative rule does that).

## 12. Attribution-preserving certificate encoding

Assumes: A1.

The UBC wire format is part of the forensic theorem, not an implementation
detail; T7 is proven against THIS format.

1. **Bitmap multisig with individually verifiable shares**: a seal
   certificate carries a member bitmap of `C_v` and, for each set bit, that
   member's individually verifiable signature share over the exact signed
   tuple. A UBC requires every bit set and every share verifying. The
   bitmap indexes the CANONICAL MEMBER ORDERING fixed and signed inside
   the §9 configuration record (ascending hash of member public key) —
   there is no other ordering, so "bit i" names one member beyond dispute.
2. **The signed tuple** is `("aft-cb/final-ack", lineage_id, v, s,
   boundary_root, batch_root, prev_seal_hash, tick_ref)` —
   domain-separated, byte-specified. `prev_seal_hash` chains seals;
   `lineage_id` types the lineage (§14); `tick_ref` is the signing-time
   VDF reference that drives share expiry (§16.3); the domain tag and the
   per-seal key separate final-acks from pre-acks cryptographically (§1).
3. **Transport is part of the theorem, stated honestly**: honest members
   broadcast their shares and any certificate they assemble (full ring +
   watchtowers, §17) — never point-to-point-only. This binds HONEST
   members; a fully Byzantine signer set can complete a certificate over
   private channels and withhold it, so surfacing is guaranteed by use,
   not by wire: a certificate must be presented to be acted on, and
   presentation makes its holder a transcript source. The forensic claim
   is therefore holder-relative (§12.5, T7): any party holding both
   conflicting certificates convicts every participant.
4. **No attribution-destroying aggregation on any seal path**: an opaque
   aggregate that cannot be decomposed into per-member verifiable shares
   forfeits the forensic guarantee and is inadmissible, whatever its size
   advantage.
5. **Extraction procedure**: given two conflicting seals for one `(v, s)`,
   the union of their bitmaps with verifying shares identifies every
   participant necessary for the violation — for n-of-n, the entire
   configuration, the maximum any protocol can attribute (L9). The
   procedure is: verify both certificates independently; for each member,
   exhibit its two shares over conflicting tuples; each pair is a
   self-contained conviction (A1).

## 13. Per-seal key evolution with immediate erasure

Assumes: A1, A8; realizes A6 mechanism (ii).

1. **Evolution**: member PER-SEAL keys are one-time/forward-secure per
   seal slot: after use for slot `s`, the member derives the slot-`s+1`
   key and SECURELY ERASES the slot-`s` key. Derivation is one-way (A1):
   the erased key is unrecoverable from the successor or from storage.
   The per-seal key signs final-ack shares ONLY; pre-acks, declared-set
   commitments, receipts, and transport ride the member's long-lived
   identity key (§1), so spending `k_s` never blocks advisory traffic.
2. **Ordering against the journal (§2), exactly** (notation: `k_s` is the
   slot-`s` signing capability; it exists only within the durable
   forward-secure state `SK_s`, which is how the chain survives crashes
   at all): the discipline is: sign the share
   with `SK_s` → journal the share (the finished signature — §2.1) →
   DESTRUCTIVELY update `SK_s → SK_{s+1}` on the durable medium (one-way;
   `SK_s` unrecoverable from `SK_{s+1}`, A1; the update is ATOMIC —
   write-new-then-atomic-swap or equivalent, so a crash mid-update leaves
   exactly one coherent state, added for the round-2 review's R2-F14: a
   torn key state would be permanent seat death, and while that is a
   liveness fault only, an unstated atomicity requirement is still an
   unstated requirement) → transmit. Crash recovery:
   if the journal holds the share for `s` and the durable state is still
   `SK_s`, complete the update FIRST, then re-transmit the journaled
   bytes; recovery never re-signs (§2.2). A crash before journaling
   leaked nothing (§2.1) and the member re-evaluates the slot fresh with
   `SK_s`. Single-final-ack (§1.2) and one-time keys are the same
   discipline seen twice: a member's one final-ack per slot is exactly
   its one use of `SK_s`.
3. **Everlasting safety, and its exact scope**: compromise of a member —
   or ALL former members, including imaging every durable medium any of
   them holds — AFTER unbonding yields no key capable of signing any
   historical slot: by the destructive update, the imaged state is some
   `SK_t` with `t` far past every sealed slot, and prior keys are
   unrecoverable from it (A1 one-wayness). Forged history fails share
   verification because the keys that could sign it no longer exist in
   any recoverable form (A8). Scope stated honestly: the crash-window
   image of a CURRENT member can expose that member's current, not-yet-
   used `SK` — that is a live-member compromise, outside A8's claim,
   handled by the ordinary "corrupt member" case of the fault model (the
   uniqueness ladder tolerates n−1 corrupt members). What A8 buys is
   that HISTORY cannot be re-signed after the fact, which is what
   bootstrap mechanism (ii) needs to be real rather than aspirational.
4. **Erasure is verified, not asserted**: the signer implementation must
   demonstrate (R9's erasure test) that after sealing, prior key material
   is absent from its storage. A signer that cannot demonstrate erasure
   does not implement this spec.
5. **PQ migration path**: the evolution scheme is chosen so the signature
   family can migrate to hash-based one-time/few-time signatures
   (XMSS/SPHINCS+-class) without changing §12's wire shape: bitmap +
   per-member verifiable shares survive the primitive swap. The `pq` bit
   (§18) records which family a certificate actually used.

## 14. Anchored re-genesis (typed lineage root)

Assumes: A1, A9 (the admissibility clock); the anchor cites its own
deployed A6 mechanism. (A9 joined this line by the round-2 review's
R2-F9: rule 2's clock consumed it while the line omitted it.)

Re-genesis is the last exit: only on loss of ring AND standby.

1. **The ceremony**: a re-genesis record is a TYPED ROOT — it carries a
   `root` marker, a fresh `lineage_id`, the anchor mechanism label (which
   A6 anchor grounds the new lineage's freshness), a reference to the
   terminal state of the prior lineage it succeeds administratively, and
   an EMBEDDED CHAIN REFERENCE `tick_root`: a recent value of the prior
   lineage's seal-seeded VDF chain (§15.1), which proves the record was
   minted no earlier than `tick_root` (added by the round-2 review's
   R2-F8: without a tick binding, the admissibility clock had nothing to
   bind to).
2. **Admissibility is objective, and continuity always outranks a
   root**: a root record is admissible only if the prior lineage shows
   ≥ `T_root` seal-free ticks AT ITS EMBEDDED `tick_root` (verifiable by
   anyone from the prior lineage's chain, A9 — the seal-seeded chain is
   single-valued because only seals fold into it), with the parameter
   constraint `T_root > T_halt + G + the standby's own sealing margin`
   pre-published so a root can never be admissible while a live standby
   is inside its succession machinery. **A prior-lineage seal at any tick
   after `tick_root` ORPHANS the root**: verifiers prefer continuity
   over roots always, so a root minted against a lineage that later
   resumes sealing simply dies — no rule ever chooses a root over a
   continuing lineage. **Slashing is confined to what the record itself
   exhibits**: a bonded member whose acceptance signature appears in a
   root whose OWN embedded `tick_root` shows the prior lineage NOT
   `T_root`-stale has co-signed the objective evidence of its offense
   (the record refutes itself against the public chain), and its bond is
   forfeit. A root with an honestly stale `tick_root` that is later
   orphaned by a resumed lineage is not an offense — it is simply void.
   This closes the lineage-escape maneuver: minting a fresh lineage
   against a live prior lineage is either self-refuting (slashable) or
   orphaned by the next real seal (worthless), so a same-slot double-seal
   cannot be laundered into an unslashable fork.
3. **A root is never continuity**: the new lineage's seal chain starts at
   the root; `prev_seal_hash` chains (§12) do not cross it; the uniqueness
   theorems quantify WITHIN one anchored lineage.
4. **Verifier semantics**: a lineage query across a root reports two
   lineages and the typed seam — never one continuous history. A verifier
   that presents a root-crossing history as one lineage violates this spec
   (P2.3's model asserts distinguishability by construction).
5. **The lattice sees the seam**: objects sealed under the new lineage
   carry the root's anchor label in their assumption vector (§18, §19), so
   downstream consumers cannot silently treat re-genesis finality as
   pre-genesis finality.

## 15. VDF chain binding

Assumes: A9, A1.

The VDF chain is the protocol's only objective clock, and it is
permissionless.

1. **Seeding by seal hashes**: the evaluation chain binds to sealed
   history — each seal hash is folded into the chain state at its
   publication point, so "ticks since the last seal" is well-defined and
   verifiable by anyone holding the chain and the seal (A1 for the
   binding, A9 for sequentiality).
2. **Permissionless evaluation**: anyone may evaluate; ONE honest evaluator
   suffices for the chain to exist. Evaluation confers no authority.
3. **Cheap verification**: verifying an evaluation is asymptotically
   cheaper than producing it; tick counts are objective — two independent
   verifiers of the same chain segment count the same ticks (R11's gate).
4. **Published σ margin**: the assumed bound on adversary hardware speedup
   is published and audited. Every tick threshold in this spec (`T_halt`,
   the §16 grace window `G`, `T_expire`, `T_root`, §8 deadlines) is set
   with at least a σ-multiplicative safety margin, so an adversary
   σ-times faster than the honest evaluator cannot cross a threshold
   before real elapsed time does. The margin's cost is named: honest
   waits inflate by the same factor — a genuinely dead ring is succeeded
   only after `σ ×` the intended halt time, and settlement behind a
   grace window pays `σ × G` — a real liveness/latency price, parameterized
   at P4.2, not hidden.
5. **Elapsed-history hardening** (A6-iv — a hardening layer, NOT a
   standalone freshness anchor): the lineage-embedded chain forces a
   long-range forger to re-run sequential work in real time, which the σ
   bound prices — a fork younger than `elapsed/σ` real time is physically
   impossible, so recent forks are detectable and old ones are made
   expensive and SLOW. What the comparison cannot do — stated because the
   P1.3 round-1 review proved the earlier sentence here wrong — is
   reject a PATIENT or σ-fast forger who accumulates an equal-or-longer
   tick chain: permissionless evaluation means tick length is evidence
   of work and elapsed time, never of WHICH history is live. Freshness
   therefore always rests on a deployed A6 anchor — (i)/(iii)
   checkpoint-class, or (ii) key erasure, which this protocol runs
   structurally (§13) so the forger's keys do not exist — with A6-iv
   raising the residual attack's cost and delay on top.

## 16. Pre-consented succession

Assumes: A2, A3, A9, A10; A1 for all signatures.

**STATUS: DESIGN OPEN — CLAIMS WITHDRAWN (P1.3 rounds 1–2).** Two
successive formulations of this section's safety mechanism were refuted
by independent adversarial review: round 1 broke the publication-duty
grace window (publication is not delivery under asynchrony); round 2
broke its repair (the "succession medium" bulletin is an unmodeled
consensus object — multi-server, no consistency rule, no cryptographic
stamp witness — so "anchored by tick X" is observer-relative and the
forbidden state is reconstructible through a medium partition or a
backdated stamp). Per the estate's standing scar — a twice-falsified
design earns no third hardening edge in the same run — and the program
doc's own named fallback, the succession EXTENSION's claims are
WITHDRAWN: T5d is design-open, the final claim-ladder rung remains
unreachable, and the OPERATIVE exits on ring death are §9 handover
(while the ring can still seal) and §14 labeled anchored re-genesis.
The rules below stand as the twice-falsified DRAFT, kept for the
respecification's benefit and explicitly NON-NORMATIVE.

**Respecification commissioned (P2.7), with the direction both reviews
point at recorded here**: eliminate the bulletin entirely — bindingness
of a rival old-ring seal is MEMBERSHIP IN THE STANDBY'S OWN UBC-COMMITTED
OBSERVATION SET: every fallback seal embeds a signed commitment to the
set of old-ring objects the standby observed; under the standby
configuration's OWN MHA (the same trust class as every other seal), its
honest member refuses to sign a commitment omitting an observed rival,
making adjudication priced rather than circular; no stamps exist to
forge (R2-F2 dissolves) and single-valuedness is the standby
certificate's uniqueness, i.e. T1 applied to `S_v` (R2-F1 dissolves).
A10 re-scopes to submission-to-standby observation. Authority expiry
becomes CONDITIONAL on a standby activation record (a UBC of `S_v`,
verifiable against the seal-seeded chain), so a slow ring with no active
succession forfeits nothing (R2-F3 dissolves). Bindingness must then be
wired into §11.3 seal validity, §12 verification, and §19's vectors
(R2-F4), preemption restricted to BINDING rivals (R2-F7), and the
tick_ref honesty split (R2-F6) modeled as advisory-only. The
respecification carries its own adversarial review before any claim
returns to the ladder.

The draft below is retained verbatim-in-substance for that work:

0. **The succession medium**: the pre-signed policy names a public
   anchoring point — a bulletin the standby and any watchtower serve,
   whose entries are tick-stamped against the VDF chain (§15) — as THE
   place where post-halt old-ring material binds. Anchoring is
   permissionless writing plus tick reference; the medium confers no
   authority of its own (it is where bindingness is measured, not who
   decides it — the deciding rule was signed by the old ring at
   formation).

1. **Policy signing at formation**: at its own formation, configuration
   `C_v` unanimously pre-signs a standby policy: the standby configuration
   `S_v` (drawn under §17's sortition and diversity floors), the activation
   threshold `T_halt`, the grace window `G`, and the share-expiry bound
   `T_expire` (rule 3). The pre-signature is a T5c′-class transition
   signed at formation — activation adds no new ring authority.
   **Refresh**: any later seal of `C_v` MAY carry a unanimously re-signed
   replacement standby drawn from the then-current beacon; the effective
   policy is the most recently sealed one, so the standby's exposure
   window is the interval since the last refresh, not `C_v`'s lifetime.
2. **The objective trigger, and nothing else**: succession activates only
   on "≥ `T_halt` VDF ticks since the last seal" (§15). A non-response
   record is never a trigger (§10). No succession exists that the old ring
   did not unanimously pre-sign (at formation or by sealed refresh).
3. **Per-slot authority expiry and the anchoring deadline (pre-signed at
   formation)**: every final-ack share is tick-stamped — the §12.2 tuple
   carries `tick_ref`, a recent VDF chain value at signing time. The
   formation policy the ring itself unanimously signed states, for every
   slot `s` with predecessor seal at tick `t_{s−1}`:
   (a) a share for slot `s` whose `tick_ref ≥ t_{s−1} + T_halt` is VOID —
   the ring's sealing authority for `s` expires at exactly the tick where
   the succession trigger for `s` arms (rule 2), by the ring's own
   standing order; and
   (b) an old-ring seal for slot `s` BINDS only if anchored in the
   succession medium (rule 0) by tick `t_{s−1} + T_halt + T_expire`;
   anchored later or never, it is VOID — not late, VOID.
   Both conditions are objectively checkable from signed stamps and the
   chain (A9), consuming no delivery assumption. Together they kill both
   round-1 arms and the fresh-shares variant this section's first repair
   missed: quietly collected shares cannot become a binding seal later
   (b), and a partitioned old ring signing fresh shares after the trigger
   armed produces only void material (a).
4. **Grace window with preemption, under A10**: after activation, `S_v`
   may produce fallback seals, but a fallback-released irreversible
   effect for slot `s` waits until tick `t_{s−1} + T_halt + G`, where
   `G ≥ T_expire + G_deliv` (σ-margined, §15.4). A conflicting old-ring
   seal observed in the medium preempts the fallback (the fallback
   aborts, the old-ring seal stands). At release time no binding
   conflicting seal can exist unobserved: a binding seal was anchored by
   `t_{s−1} + T_halt + T_expire` (rule 3b), and the successor observes
   everything anchored by then within `G_deliv` further ticks (A10) —
   strictly before release. Material surfacing after release is void by
   rule 3, so the released effect never faces a binding rival. Under
   partition, the old ring simply cannot anchor in time and its
   post-trigger material is void — the succession side wins by the old
   ring's own pre-signed priority rule, not by a race.
5. **Honest-publication duty, re-scoped to what a member actually
   holds**: an honest member publishes its OWN final-ack share upon
   signing and anchors any ASSEMBLED certificate it holds upon assembly
   (part of honest signing, accepted at seat acceptance §9). The duty is
   dischargeable by construction — a signer always holds its share;
   nobody is obligated to publish an object it never held (the round-1
   refutation's second arm). It is a liveness courtesy that lets a
   briefly-partitioned honest ring win the anchoring race where it can;
   SAFETY never rests on it — rules 3–4 close the race by voidness, not
   by anyone's diligence. Crash boundary likewise: a signer that crashes
   and recovers after the deadlines finds its material void — a bounded
   liveness loss, never a safety hole; recovery time appears in no
   safety argument.
6. **Continuity typing**: fallback seals carry the succession-transition
   type (T5c′-class, pre-signed); re-genesis (§14) remains the only root
   event. Cadence resumes under `S_v` with continuity labels intact.
7. **Standby capture is priced, not assumed away**: `S_v` is pre-named —
   that is what pre-consent costs — so from its (re)signing until
   activation or replacement it is a KNOWN target; rule 1's refresh
   bounds that exposure to the inter-refresh interval, diversity floors
   and queueing (§17) raise its capture price, and the residual is
   modeled probabilistically in T8's standby-capture term — never
   composed into a deterministic tolerance figure. A Byzantine old-ring
   majority that griefs cadence to force succession into a captured
   standby is the composed attack that term must price (P4.2); the
   deterministic ladder never claimed to prevent it, and says so here
   rather than implying otherwise.

## 17. Sortition seat assignment, diversity floors, watchtowers

Assumes: A9 (beacon), A1; honest-supply probability is T8's subject, cited
as probabilistic only.

1. **Sortition**: seat assignment for a forming configuration (and its
   standby) is drawn from the VDF beacon (§15) at activation time over the
   public bonded queue. The queue is public; the ASSIGNMENT is
   unpredictable until the beacon value exists — targeted capture cannot
   begin before seating, narrowing adaptive corruption to the
   after-seating/before-sealing window (T8's adaptive term).
2. **Constituency diversity floors**: a valid configuration satisfies
   published floors across constituencies (jurisdiction, implementation,
   operator class, stake source). Floors are validity conditions on the
   configuration record (§9); MHA failure then requires every constituency
   to fail at once, which is T8's correlated-failure model — published
   correlations, probabilistic claims only.
3. **Watchtowers gate nothing**: anyone may countersign any seal. A
   countersignature is recorded and widens the forensic net (§12's
   transcripts get more independent holders); a seal verifies identically
   with zero countersignatures. No rule anywhere consumes a watchtower
   record as authority.

## 18. The `pq` bit

Assumes: A1 (primitive families), A8 (migration path).

Every assumption-lattice label (T6/R6) carries a `pq` bit.

1. `pq = true` on a certificate label iff EVERY cryptographic primitive in
   that certificate's verification chain (signatures, hashes, proof
   system, VDF construction where cited) is post-quantum.
2. **Meet rule**: the collapse verifier computes `pq(meet) = AND` over all
   constituents — any non-pq constituent makes the composed object
   non-pq. There is no override.
3. Pairing-based and classical-DL-based certificates are never `pq`.
   Hash-based one-time/few-time signature families (§13.5) are the
   intended pq signature path; the VDF and proof-system choices carry
   their own pq assessment (R11, P2.5).
4. The bit exists so migration is measurable: the estate can state exactly
   which finality classes (§19) are pq-clean and which await primitive
   swaps, mechanically, from the labels.

## 19. The finality menu

Assumes: per class, exactly the vector it names; the menu mechanism itself
A1.

Applications choose finality explicitly; receipts prove which class
authorized each effect. Three typed per-effect SLAs:

| Class | What it is | Assumption vector (by ledger id) | Latency shape | Price shape |
|---|---|---|---|---|
| `live-QC` | live-tier BFT finality | A1 + the live engine's own vector (A5-class) | seconds-class, optimistically responsive | cheapest |
| `sealed` | UBC super-finality (§11, §12) | A1, A2, A3 (+A4 for completeness claims) | seal cadence (`W_seal` ticks) | bond-backed |
| `sealed+anchored` | sealed, plus the deployed freshness anchor | `sealed` vector + A6(anchor as deployed) (+A9 iff the elapsed-history hardening is enabled) | seal cadence + anchor availability | dearest |

1. Every effect declaration names its required class; the executor refuses
   release below it (irreversible effects are `sealed` or above, §11.4).
2. Every receipt records the class that authorized the effect AND that
   class's assumption vector with its `pq` bit (§18) at authorization
   time. A receipt is thus a self-contained statement of what was trusted.
3. Latency and price per class are published deployment parameters,
   recorded on the receipt alongside the vector, so "what did this
   finality cost and assume" is answerable from the receipt alone.
4. The lattice meet (T6) makes cross-class composition honest: an object
   composed from mixed-class constituents reports the weakest, with no
   silent degradation between tiers.

---

## Index of dispatched adversarial drills

For P1.3's convenience — the drill → dispatching rules map (informative;
updated after round 1, whose findings rebuilt §16 and requalified §15.5):
(a) six-step pre-GST partition → §1.4 + §1's domain separation; (b)
honest-split partition → §1.4 (and §16's promotion of a long partition
into succession is priced at T5d under A10); (c) all-but-one-Byzantine
equivocation → §1.3 + §12.5; (d) proposer equivocation across retries →
§1.3 + the §1 attempt budget; (e) crash-recovery double-final-ack →
§2.2–2.4 + §13.2 (one unified journal-the-share discipline); (f)
proof-of-silence reconfiguration → §10 (including its exact-line
paragraph); (g) staged double-seal forensics → §12.5 (holder-relative,
§12.3) + §14.2 (lineage escape closed); (h) post-unbond key compromise →
§13.3 + §7.4; (i) hidden-seal succession → §16.0–16.5 (authority expiry +
anchoring deadline + A10 observation + re-scoped duty); (j) standby
capture → §16.1/16.7 +
§17.1–17.2; (k) σ-speedup → §15.4 (wait thresholds) + §15.5 (comparison
downgraded to hardening).
