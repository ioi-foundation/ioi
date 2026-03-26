# CanonicalOrdering Formal Model

This directory contains the formal artifacts for AFT's proof-carrying
equal-authority canonical-ordering model and its `99%` equal-authority
ordering consensus claim.

The canonical prose spec lives at
[`docs/consensus/aft/specs/canonical_ordering.md`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs/canonical_ordering.md).

This package captures the deterministic kernel of that claim:

- a slot has one canonical ordered set once the canonical bulletin-close object
  is fixed,
- positive admission now runs through a compact signed publication frontier
  bound to the slot's canonical-order certificate,
- same-slot frontier conflicts and stale predecessor links admit short objective
  contradiction objects that dominate the positive lane,
- admitted order certificates are unique once omission and frontier
  contradictions are absent.

As with the other AFT proof surfaces, the package is split:

- `CanonicalOrderingProof.tla` is the TLAPS proof kernel over admitted objects
  and omission proofs.
- `CanonicalOrdering.tla` is the richer executable TLC model of bulletin
  publication, cutoff closure, availability certification, canonical
  bulletin-close formation, candidate certification, compact publication
  frontier publication, frontier contradiction, omission, and positive
  admission. Frontier parent references are bounded to predecessor-linked
  choices plus an explicit absent-parent sentinel, matching the live compact
  link surface rather than an arbitrary hash oracle. The bounded model also
  follows sequential closed-slot progression so TLC spends its budget on the
  contradiction surface rather than on irrelevant cross-slot interleavings.
- `CanonicalOrdering.cfg` is the bounded TLC configuration.
  It intentionally uses the minimal witness set that still exercises
  same-slot frontier conflict, stale parent linkage, omission dominance, and
  positive admission, including explicit caps on candidate/frontier witness
  multiplicity so the checker explores the contradiction basis rather than
  redundant larger combinations.
- `CanonicalCollapseRecursiveContinuity.tla` and
  `CanonicalCollapseRecursiveContinuity.cfg` are the bounded TLC model for the
  reference recursive continuity carrier used by
  `CanonicalCollapseObject.continuity_recursive_proof` and
  `CanonicalCollapseExtensionCertificate`.
- `CanonicalOrderingOmissionTrace.tla` and
  `CanonicalOrderingOmissionTrace.cfg` are a small executable TLC witness that
  intentionally produce a concrete omission-dominance trace.
- `CanonicalOrderingRetrievability.tla` and
  `CanonicalOrderingRetrievability.cfg` are the bounded TLC model for the
  endogenous retrievability plane: profile publication, shard-manifest
  publication, custody-assignment publication, custody-receipt publication,
  custody-response publication, positive reconstruction certification,
  objective retrievability challenges, positive extraction, historical
  retrievability promotion, and deterministic reconstruction abort.

The prose spec states the full `99%` equal-authority ordering consensus theorem
over canonical bulletin close, omission dominance, endogenous retrievability,
and proof soundness. The live runtime has now narrowed the hot-path theorem
boundary: honest positive ordering carries a compact signed publication frontier
plus objective contradiction objects for same-slot frontier conflicts and stale
predecessor links, while the full bulletin surface is reconstructed or aborted
through a protocol-native retrievability plane rooted in canonical close. This
package now matches that boundary. It proves and model-checks the deterministic
uniqueness and negative-dominance core over bulletin close, compact frontier
publication, frontier contradiction, omission, and endogenous retrievability.
Full extraction of the ordered set now depends on protocol objects rather than
on any parallel bulletin surface. In the repository's now-singular theorem story,
this package remains the ordering-specific PSC kernel inside the one AFT
theorem surface rather than the baseline half of a split theorem stack.
Ordinary canonical collapse / replay history now names the deeper historical
retrievability root, the AFT recovered-state contract carries the same
historical retrievability surface for restart consumers, and archived
publication / replay correctness is historical and index-free through profile-hash /
activation-hash bindings plus predecessor/checkpoint validation.

In the yellow-paper terminology, this package is one half of AFT's `public
state continuity with extractable obstructions` program. The live positive
object is now the canonical order certificate plus its compact signed
publication frontier; the negative kernel is no longer just omission. Same-slot
frontier disagreement and stale predecessor links now admit short public
contradiction objects on the hot path, while omission remains the objective
negative witness over incomplete ordered sets. In the live runtime, that kernel
is refined into the broader `CanonicalOrderAbortReason` family over the same
public surface: frontier conflict, stale frontier linkage, missing
certificates, bulletin-surface reconstruction or publication failures, invalid
bulletin-close formation, omission dominance, and certificate-level mismatches
over height, randomness, ordered root, resulting-state root, public inputs,
bulletin-availability binding, proof binding, and endogenous retrievability
failures such as missing profiles, missing manifests, contradictory manifests,
missing or contradictory custody assignments, missing or contradictory custody
receipts, missing or invalid custody responses, and invalid or absent
published bulletin entries.

This same proof shape now appears in `Asymptote` observer sealing as well:
public evidence, a unique positive object, a unique negative object, and
negative-authority dominance. Canonical ordering remains the repository's
ordering theorem package; `Asymptote` applies the same structural discipline to
sealed-effect release; and the nested-guardian recovery lane now lands inside
the same qualifier-free whole-stack theorem rather than outside it as a
separate theorem lane.

In the live runtime, canonical ordering is also accountable: `OmissionProof`
names the offending validator, `guardian_registry` replay-deduplicates valid
omission evidence, and the registry can optionally apply membership updates as
policy aftermath. That accountability layer is intentionally described as an
implementation and policy strengthening above the deterministic proof kernel
proved here. The same is true for frontier contradictions: the registry stores
them as short durable domination objects, but the formal package treats them as
objective negative witnesses rather than as a policy aftermath mechanism.

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
  -config docs/specs/formal/aft/canonical_ordering/CanonicalOrderingOmissionTrace.cfg \
  docs/specs/formal/aft/canonical_ordering/CanonicalOrderingOmissionTrace.tla
```

TLC is expected to exit with an invariant violation for
`NoOmissionDominanceWitness`; that emitted counterexample is the witness trace.

To run the recursive continuity model directly:

```bash
java -cp .artifacts/tla/tla2tools.jar tlc2.TLC -cleanup -deadlock \
  -config docs/specs/formal/aft/canonical_ordering/CanonicalCollapseRecursiveContinuity.cfg \
  docs/specs/formal/aft/canonical_ordering/CanonicalCollapseRecursiveContinuity.tla
```
