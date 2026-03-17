# Canonical Ordering

This document is the normative protocol model for AFT's proof-carrying
equal-authority ordering path.

Its job is to close the gap between:

- the target high-fault ordering theorem where the ordered set is accepted
  because it is uniquely and recoverably *proved*, not because it won a dense
  validator vote.

## Objective

For each slot `h`, define a unique canonical ordered set `O_h` and a certificate
`OCert_h` such that:

- every honest verifier can check `OCert_h` cheaply,
- any omission is objectively provable,
- the ordered set is recoverable from public data,
- conflicting valid certificates for the same slot are impossible, and
- arbitrary behavior by almost all validators cannot create a conflicting valid
  order certificate so long as at least one honest revealer can reconstruct the
  public bulletin surface and publish the proof.

## Canonical Objects

For slot `h`:

```text
B_h   = bulletin / DA surface objectively published before cutoff τ_h
R_h   = public randomness beacon for slot h
E_h   = { tx | Included(tx, B_h) ∧ Eligible(tx, root_{h-1}) }
O_h   = CanonicalOrder(R_h, E_h)
root_h = Execute(root_{h-1}, O_h)
```

The certifying object is:

```text
OCert_h = (
  h,
  root_{h-1},
  cutoff_certificate_h,
  bulletin_commitment_h,
  canonical_set_commitment_h,
  resulting_state_root_h,
  succinct_witness_h
)
```

## Succinct Witness

The witness must be *succinct*: all validators verify a small object instead of
replaying the full bulletin or recomputing the ordering search.

The target witness shape is:

```text
succinct_witness_h = (
  verifier_id,
  proof_bytes,
  bulletin_root_h,
  eligibility_root_h,
  canonical_order_root_h,
  recoverability_root_h,
  omission_commitment_h
)
```

The witness proves:

```text
1. bulletin_root_h commits the public bulletin / DA surface B_h
2. cutoff_certificate_h defines the unique admissible cutoff τ_h
3. eligibility_root_h commits exactly E_h
4. canonical_order_root_h commits exactly O_h = CanonicalOrder(R_h, E_h)
5. resulting_state_root_h = Execute(root_{h-1}, O_h)
6. recoverability_root_h is sufficient for any verifier to reconstruct O_h
7. omission_commitment_h makes any omitted eligible transaction objectively provable
```

The live runtime uses `CommittedSurfaceV1`: a commitment-level witness where the
certificate carries only succinct commitment data and omission commitments, not
a full inline transaction list.

## Public Bulletin / DA Assumptions

The ordering theorem depends on a public bulletin surface with explicit
assumptions.

### A1. Objective publication

Transactions or batches published to `B_h` have:

- a stable content hash,
- a verifiable inclusion path into the bulletin commitment,
- an objective publication time or publication order relative to the slot
  cutoff.

### A2. Availability

At least one honest validator can reconstruct the bulletin contents committed by
`bulletin_commitment_h`.

This is the recoverability assumption. Without it, the system may preserve
uniqueness of valid certificates but cannot guarantee timely revelation.

### A3. Append-only commitment

The bulletin commitment must be append-only or otherwise equivocation-evident at
the slot boundary.

### A4. Eligibility determinism

`Eligible(tx, root_{h-1})` is deterministic and locally checkable from the
committed predecessor root and the transaction object.

### A5. Sound proof system

`VerifyProof(succinct_witness_h) = true` implies the witness obligations above
actually hold.

## Canonical Cutoff Model

The cutoff for slot `h` is not a local clock read. It is a protocol object.

Define:

```text
τ_h = Cutoff(h, root_{h-1}, R_h, timing_policy_h)
```

`cutoff_certificate_h` binds:

- `h`
- `root_{h-1}`
- the effective cutoff timestamp or bulletin-close position
- the timing-policy version
- the randomness beacon commitment used by the slot

The cutoff is canonical if:

- every honest verifier derives the same `τ_h`, and
- no transaction published strictly after `τ_h` can be admitted to `E_h`.

This prevents local latency games from changing the ordered set.

## Omission Model

An omission is objective when a transaction is:

- included in `B_h` before cutoff `τ_h`,
- eligible under `root_{h-1}`,
- absent from the committed canonical ordered set `O_h`.

Define the omission proof:

```text
Ω(h, tx) = (
  inclusion_proof(tx, bulletin_root_h),
  cutoff_admissibility_proof(tx, cutoff_certificate_h),
  eligibility_proof(tx, root_{h-1}),
  non_membership_proof(tx, canonical_order_root_h)
)
```

A valid omission proof immediately dominates a candidate order certificate:

```text
Valid(Ω(h, tx)) => Reject(OCert_h)
```

This is the ordering analogue of `Abort` in `Asymptote`: ambiguity collapses to
rejection, not to heuristic retry.

## Acceptance Rule

Every validator applies the same deterministic rule:

```text
Accept(OCert_h) iff
  VerifyProof(succinct_witness_h) = true
  and VerifyCutoff(cutoff_certificate_h) = true
  and Predecessor(root_{h-1}) is already accepted
  and no valid omission proof Ω(h, tx) exists
```

No dense positive vote is needed once a valid `OCert_h` is revealed.

## Uniqueness Theorem

Let `ValidOrderCert(h, C)` mean certificate `C` satisfies the acceptance rule
for slot `h`.

Then:

```text
Theorem (Uniqueness)
For any slot h, if ValidOrderCert(h, C1) and ValidOrderCert(h, C2),
then C1 and C2 commit the same canonical ordered set O_h.
```

Reason:

- the predecessor root is fixed,
- the cutoff certificate is canonical,
- the bulletin commitment is canonical,
- eligibility is deterministic,
- `CanonicalOrder` is deterministic,
- proof soundness forbids a witness for a different ordered set.

So two valid certificates for the same slot cannot disagree on the ordered set.

## Recoverability Theorem

Let `Recover(B_h, cutoff_certificate_h, root_{h-1}, R_h)` be the deterministic
reconstruction procedure using the public bulletin surface and the slot inputs.

Then:

```text
Theorem (Recoverability)
If ValidOrderCert(h, C) and the bulletin availability assumption holds,
then every honest verifier can reconstruct the same ordered set O_h from
public data and the succinct witness commitments.
```

In other words, the ordered set is not only unique; it is recoverable by any
honest node with bulletin access.

## High-Fault Theorem

This is a *revelation* theorem, not a classical dense-vote BFT theorem.

```text
Theorem (High-Fault Equal-Authority Ordering)
Assume:
  1. at least one honest validator can reconstruct B_h,
  2. cutoff_certificate_h is canonical,
  3. the proof system is sound,
  4. bulletin commitments and omission proofs are objectively verifiable.

Then arbitrary behavior by all other validators cannot create a conflicting
valid canonical-order certificate for slot h.
```

This is the honest high-fault statement:

- it is equal-authority because any validator may reveal the winning
  certificate,
- it is high-fault because correctness does not depend on a majority of
  positive votes,
- it does not overclaim a classical `99% Byzantine consensus` theorem.

The strongest shorthand is:

```text
up to n-1 validators may behave arbitrarily with respect to revelation,
provided at least one honest validator can reconstruct and reveal the unique
valid order certificate.
```

That is the non-classical escape route.

## Relation To Current Runtime

Current runtime state:

- `BaseFinal` ordering remains on the fast AFT path.
- `CommittedSurfaceV1` is the live runtime path and proves ordering from a
  succinct commitment-level witness.
- bulletin commitments and order certificates are now persisted into chain
  state during normal block production.

Target runtime state:

- replace the explicit published witness with the succinct witness model above,
- keep omission proofs objective and dominant,
- make the canonical ordered set cheaply verifiable and recoverable from public
  data.

## Non-Claim

This model should not be described as:

- classical `99% Byzantine fault tolerance`

It should be described as:

- proof-carrying equal-authority canonical ordering with uniqueness and
  recoverability under public bulletin / DA assumptions.
