# CanonicalOrdering Formal Model

This directory contains the formal artifacts for AFT's proof-carrying
equal-authority canonical-ordering model.

The canonical prose spec lives at
[`docs/consensus/aft/specs/canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/canonical_ordering.md).

This package focuses on the deterministic kernel behind the high-fault ordering
story:

- a slot has one canonical ordered set once the bulletin surface and cutoff are
  fixed,
- admitted order certificates are unique,
- valid omission proofs dominate candidate certificates,
- the canonical ordered set is recoverable from public bulletin data.

As with the other AFT proof surfaces, the package is split:

- `CanonicalOrderingProof.tla` is the TLAPS proof kernel over admitted objects
  and omission proofs.
- `CanonicalOrdering.tla` is the richer executable TLC model of bulletin
  publication, cutoff closure, candidate certification, omission, and
  recoverability.
- `CanonicalOrdering.cfg` is the bounded TLC configuration.

The separate high-fault theorem in the prose spec is intentionally stated over
public bulletin availability and proof soundness. That probability- and
availability-sensitive part is not encoded as a TLAPS probability proof here;
the formal package proves the deterministic uniqueness, omission-dominance, and
recoverability core.

## Running locally

```bash
bash .github/scripts/run_aft_formal_checks.sh
```
