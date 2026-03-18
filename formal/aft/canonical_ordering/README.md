# CanonicalOrdering Formal Model

This directory contains the formal artifacts for AFT's proof-carrying
equal-authority canonical-ordering model and its `99%` equal-authority
ordering consensus claim.

The canonical prose spec lives at
[`docs/consensus/aft/specs/canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/canonical_ordering.md).

This package captures the deterministic kernel of that claim:

- a slot has one canonical ordered set once the canonical bulletin-close object
  is fixed,
- admitted order certificates are unique,
- valid omission proofs dominate candidate certificates,
- the canonical ordered set is recoverable from the canonical bulletin-close
  object plus public bulletin data, and the current runtime now makes that
  extraction a precondition for positive closed-slot certificate admission.

As with the other AFT proof surfaces, the package is split:

- `CanonicalOrderingProof.tla` is the TLAPS proof kernel over admitted objects
  and omission proofs.
- `CanonicalOrdering.tla` is the richer executable TLC model of bulletin
  publication, cutoff closure, availability certification, canonical
  bulletin-close formation, candidate certification, omission, and
  recoverability.
- `CanonicalOrdering.cfg` is the bounded TLC configuration.
- `CanonicalCollapseRecursiveContinuity.tla` and
  `CanonicalCollapseRecursiveContinuity.cfg` are the bounded TLC model for the
  reference recursive continuity carrier used by
  `CanonicalCollapseObject.continuity_recursive_proof` and
  `CanonicalCollapseExtensionCertificate`.
- `CanonicalOrderingOmissionTrace.tla` and
  `CanonicalOrderingOmissionTrace.cfg` are a small executable TLC witness that
  intentionally produce a concrete omission-dominance trace.

The prose spec states the full `99%` equal-authority ordering consensus theorem
over canonical bulletin close, omission dominance,
recoverability, and proof soundness. This package proves the deterministic
uniqueness, omission-dominance, and recoverability core of that theorem.
Bulletin availability is now represented by a protocol object in the TLC model.
The TLC correspondence already matches the current runtime direction:
availability is certified and canonical bulletin close forms before candidate
certification. The remaining retrieval and proof-soundness conditions remain
explicit environmental assumptions rather than TLAPS-proved network theorems;
the open assumption is publication-substrate retrievability, not optional
execution of the extractor.

In the yellow-paper terminology, this package is one half of AFT's `public
state continuity with extractable obstructions` program: the positive object is
the canonical order certificate, and the negative kernel is the omission proof
that objectively dominates any incomplete candidate. In the live runtime, that
kernel is refined into a richer `CanonicalOrderAbortReason` family over the
same public surface: missing certificates, bulletin-surface reconstruction or
publication failures, invalid bulletin-close formation, omission dominance, and
certificate-level mismatches over height, randomness, ordered root,
resulting-state root, public inputs, bulletin-availability binding, and proof
binding.

This same proof shape now appears in `Asymptote` observer sealing as well:
public evidence, a unique positive object, a unique negative object, and
negative-authority dominance. Canonical ordering remains the repository's
ordering theorem package; `Asymptote` applies the same structural discipline to
sealed-effect release.

In the live runtime, canonical ordering is also accountable: `OmissionProof`
names the offending validator, `guardian_registry` replay-deduplicates valid
omission evidence, and the registry can optionally apply membership updates as
policy aftermath. That accountability layer is intentionally described as an
implementation and policy strengthening above the deterministic proof kernel
proved here.

The omission-trace witness is intentionally not part of the passing CI proof
set, because TLC exits with a counterexample when it reaches the target state.
That counterexample is the point: it emits a six-state witness in which
`tx1` and `tx2` are published, the cutoff closes, availability is certified,
the canonical bulletin close forms, a candidate certificate for `{tx1}`
appears, and an omission proof against `tx2` is then published while the
incomplete candidate remains unadmitted.

On the implementation side, the ordering theorem now feeds a reference
recursive continuity carrier too: `CanonicalCollapseObject` stores a
`HashPcdV1` recursive proof step, and proposal headers carry the predecessor
commitment plus predecessor proof hash in
`CanonicalCollapseExtensionCertificate`. The current TLA+
package now includes a dedicated executable model of that reference recursive
carrier: `CanonicalCollapseRecursiveContinuity.tla` models deterministic proof
steps, predecessor-proof hashing, succinct extension-certificate carriage, and
header-admission dependence on the anchored predecessor proof relation. The
runtime now also has a `SuccinctSp1V1` backend seam for those same recursive
public inputs, and that seam is now exercised by live consensus verification
and validator durable-state gating, but the model stays at the reference
`HashPcdV1` level rather than a succinct cryptographic proof backend. Even so,
it no longer leaves the recursive relation as prose-only runtime
correspondence.

## Running locally

```bash
bash .github/scripts/run_aft_formal_checks.sh
```

To emit the omission-dominance trace directly:

```bash
java -cp .artifacts/tla/tla2tools.jar tlc2.TLC -cleanup -deadlock \
  -config formal/aft/canonical_ordering/CanonicalOrderingOmissionTrace.cfg \
  formal/aft/canonical_ordering/CanonicalOrderingOmissionTrace.tla
```

TLC is expected to exit with an invariant violation for
`NoOmissionDominanceWitness`; that emitted counterexample is the witness trace.

To run the recursive continuity model directly:

```bash
java -cp .artifacts/tla/tla2tools.jar tlc2.TLC -cleanup -deadlock \
  -config formal/aft/canonical_ordering/CanonicalCollapseRecursiveContinuity.cfg \
  formal/aft/canonical_ordering/CanonicalCollapseRecursiveContinuity.tla
```
