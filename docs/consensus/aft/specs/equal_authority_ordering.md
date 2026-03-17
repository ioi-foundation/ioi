# Equal-Authority Canonical Ordering

This document defines the final-mile design target for pushing AFT beyond
`Asymptote` sealed effects and toward an honest `99%` equal-authority ordering
story without sacrificing throughput.

The normative protocol details now live in
[`canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/canonical_ordering.md).
This note remains the architectural motivation and escape-route framing.

The target is not "make ordinary BFT thresholds disappear." The target is:

- keep every validator equally eligible to reveal the canonical order
- stop using dense positive voting as the source of ordering truth
- make order a proof-discoverable fact over a public availability surface
- preserve throughput by keeping dissemination hot and verification cheap

## Core Claim

The escape route is to move from:

- "which order did the validator quorum choose?"

to:

- "which revealed order certificate is the unique valid certificate for this slot?"

Under this model, validators remain equal-authority with respect to *eligibility
to reveal* the next ordered view. They do not each carry equal positive voting
power in a dense ordering round.

## Why Ordinary Equal-Authority BFT Does Not Reach 99%

If every validator is an equal-authority voter in a standard worst-case BFT
ordering protocol, then sparse fast committees cannot deterministically include
an honest observer when faults approach `0.99n`, and dense all-node voting
destroys throughput.

So the ordering layer must change shape:

- sparse hot-path dissemination
- dense but cheap verification
- deterministic invalidation of incomplete or conflicting order views

## Design Overview

The design has two planes.

### Plane A: Dissemination and Availability

This plane is optimized for throughput.

- transactions and batches are published to a public bulletin-board / DA surface
- publication produces objective inclusion commitments
- the network disseminates data quickly, but does not decide truth by voting on
  every ordered edge

This plane can reuse high-throughput mempool / DAG ideas already adjacent to AFT.

### Plane B: Canonical Ordering and Proof

This plane is optimized for correctness.

For each slot `h`, the protocol derives a unique canonical order from:

- the objectively available set of eligible transactions
- a deterministic slot cutoff
- a public randomness beacon
- a deterministic ordering function
- a proof that the claimed ordered set is complete and correctly executed

The first correct revealer of that proof wins because the proof is locally
verifiable by every other node.

## Canonical Objects

For slot `h`:

```text
B_h   = bulletin-board / DA view admitted before cutoff τ_h
R_h   = public randomness for slot h
E_h   = { tx | Included(tx, B_h) ∧ Eligible(tx, root_{h-1}) }
O_h   = CanonicalOrder(R_h, E_h)
root_h = Execute(root_{h-1}, O_h)
```

The slot certificate is:

```text
OCert_h = (
  h,
  root_{h-1},
  bulletin_commitment_h,
  randomness_commitment_h,
  ordered_commitment_h,
  root_h,
  π_h
)
```

where `π_h` proves:

```text
1. bulletin_commitment_h is the committed DA surface for slot h
2. randomness_commitment_h binds the public beacon for slot h
3. ordered_commitment_h commits exactly O_h = CanonicalOrder(R_h, E_h)
4. root_h = Execute(root_{h-1}, O_h)
5. no objectively eligible transaction before cutoff τ_h was omitted from O_h
```

## Acceptance Rule

Every validator applies the same deterministic rule:

```text
Accept(OCert_h) iff
  VerifyProof(π_h) = true
  and Predecessor(root_{h-1}) is already accepted
  and bulletin/randomness commitments match the slot schedule
```

No separate dense ordering vote is required once a valid `OCert_h` exists.

## Omission and Outlier Proofs

The final mile depends on making incompleteness instantly objective.

Define an omission proof:

```text
Ω(tx, h) = proof that:
  tx was included in B_h before cutoff τ_h
  tx was eligible under root_{h-1}
  tx is absent from the committed ordered set O_h
```

Then:

```text
Reject(OCert_h) if ∃ valid Ω(tx, h)
```

This is the ordering analog of `Abort` in `Asymptote`:

- a valid omission proof dominates a candidate order certificate
- messy equivocation or selective exclusion becomes an instantly objective fault
- ambiguity collapses to rejection, not to heuristic retry

## Why This Preserves Throughput

The throughput win comes from moving the expensive thing.

Do not ask all validators to:

- execute the full ordering search
- cross-sign the next slot
- participate in a dense positive-vote protocol

Instead:

- let the network disseminate data at high throughput
- let one or more provers compute the canonical order and proof
- let every validator perform only cheap local verification of `OCert_h`

This is the same structural move already used by proof-carrying effect sealing:

- sparse heavy work
- dense light verification

## Equal-Authority Property

This design preserves equal-authority in the sense that:

- every validator is equally entitled to publish data to the bulletin board
- every validator is equally entitled to derive and reveal the next valid
  canonical order certificate
- every validator applies the same acceptance rule locally

Authority no longer comes from privileged committee membership or stake weight.
Authority comes from revealing a valid canonical proof first.

## 99% Story

The intended `99%` story is:

- if `99%` of validators are arbitrary but at least one honest validator can
  reconstruct the bulletin-board view, derive the canonical order, and publish
  the valid order certificate, then all honest verifiers adopt the same order
  because the order certificate is objectively checkable

That is a different object than classical dense-vote BFT. It is:

- equal-authority canonical-order revelation
- proof-carrying total-order certification
- deterministic rejection of incomplete views

The relevant safety unit is no longer "how many validators voted yes?" It is
"can any honest validator reveal the unique valid order proof?"

## Dependency Assumptions

This route depends on the following assumptions being explicit and enforced:

1. `B_h` is objectively committed and admits inclusion proofs.
2. Slot cutoff `τ_h` is objective and not locally malleable.
3. The randomness beacon `R_h` is objective and bias-bounded.
4. `CanonicalOrder` is deterministic.
5. The proof system for `π_h` is sound.
6. Data availability is strong enough that at least one honest revealer can
   reconstruct the eligible set.
7. Omission proofs are cheap enough to verify and dominate invalid certificates.

Without these assumptions, the protocol falls back to high-confidence or
accountable survivability rather than deterministic `99%`-class ordering.

## Relation To Existing AFT Modes

- `GuardianMajority` remains the fast base ordering and certification path used
  today.
- `Asymptote` already provides deterministic sealed effects through
  observer- or witness-backed collapse.
- `Equal-Authority Canonical Ordering` is the next layer: it moves the same
  proof-carrying / collapse idea into ordering itself.

In other words:

- `Asymptote` proves effects from committed order
- this design proves the committed order itself

## Minimal New Protocol Objects

The repo should grow the following objects if this route is pursued:

- `BulletinCommitment`
- `SlotCutoffCertificate`
- `OrderIntentSetCommitment`
- `CanonicalOrderCertificate`
- `CanonicalOrderProof`
- `OmissionProof`
- `OrderNullifier` or equivalent replay key for externalized order-derived effects

## Recommended Execution Strategy

1. Keep current AFT hot-path ordering intact.
2. Add a public bulletin-board commitment surface for batches/transactions.
3. Define one deterministic `CanonicalOrder` function for a slot.
4. Add a reference order-proof system, even if initially a hash-binding or
   accumulator-based scaffold rather than a full zk backend.
5. Add omission proofs and make them dominate candidate order certificates.
6. Only after that, move from "proof-carrying effects" to "proof-carrying
   ordering."

## Non-Claim

This document is the escape route, not a claim that the repo already proves it.

It should not be summarized as:

- classical `99% Byzantine consensus`

It should be summarized as:

- a design for equal-authority, proof-carrying canonical ordering where the
  first valid revealed order certificate wins, omission is objectively
  slashable, and throughput is preserved by separating dissemination from
  verification
