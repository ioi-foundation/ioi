# AFT Formal Models

This directory is the top-level home for the formal artifacts backing the Aft
protocol family.

The canonical prose specifications live under
[`docs/consensus/aft/specs/`](/home/heathledger/Documents/ioi/repos/ioi/docs/consensus/aft/specs).

Layout:

- `AsymptoteProof.tla`, `Asymptote.tla`, and `Asymptote.cfg` define the
  scalable two-tier finality model directly at the Aft root, including the
  deterministic equal-authority observer transcript/challenge, canonical close,
  and canonical abort kernel used for sealed-effect collapse.
- [`canonical_ordering/README.md`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft/canonical_ordering/README.md)
  covers the proof-carrying equal-authority canonical-ordering model: succinct
  witness commitments, canonical bulletin close, omission dominance,
  uniqueness, recoverability, and the repository's `99%` equal-authority
  ordering consensus claim under its explicit assumptions, plus
  current-runtime mandatory closed-slot extraction before positive order
  admission. That package now also ships an executable TLC witness trace for a concrete
  omission-dominance case.
- [`guardian_majority/README.md`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft/guardian_majority/README.md)
  covers the guardian-majority proof kernel and executable model.
- [`nested_guardian/README.md`](/home/heathledger/Documents/ioi/repos/ioi/formal/aft/nested_guardian/README.md)
  covers the witness-augmented nested-guardian model.

Run all formal checks locally with:

```bash
bash .github/scripts/run_aft_formal_checks.sh
```

The `Asymptote` proof kernel now proves the deterministic observer-sealing
surface at the admitted-object boundary:

- base-certificate uniqueness
- uniqueness of the canonical observer close object
- close / abort exclusivity
- abort dominance over sealed release

The richer TLC model carries the deterministic publication flow:

- transcript-surface publication
- challenge-surface publication
- canonical close formation from an empty challenge surface
- canonical abort formation from a non-empty challenge surface
- sealed release only from canonical close

The old `99%+` observer-sampling bound is no longer the normative `Asymptote`
theorem surface. It remains only as historical analytical context for the
superseded sampled affirmative observer lane, and is not encoded as a TLAPS
probability theorem.

The canonical-ordering package carries the ordering-specific subtheorem inside
the repository's broader PSC claim: once canonical bulletin close, omission
dominance, deterministic closed-slot extraction, and proof soundness are
assumed, arbitrary behavior by the rest of the validator set cannot create a
conflicting valid ordering outcome. The formal artifacts discharge the
deterministic uniqueness, omission-dominance, and recoverability kernel of that
claim at the admitted-object boundary. For current runtime correspondence,
closed-slot extraction is no longer merely a recoverer-side capability: the
positive ordering path admits an order certificate only after successful
extraction from the published bulletin surface, and the negative path rewrites
the slot into a canonical abort when objective obstructions are published.

The live runtime now also carries a reference recursive continuity proof on the
proposal path: each `CanonicalCollapseObject` stores a `HashPcdV1` recursive
proof step over its commitment, predecessor commitment hash, payload hash, and
previous proof hash, and each proposal carries the predecessor commitment plus
predecessor proof hash in `CanonicalCollapseExtensionCertificate`. The runtime
now also exposes a `SuccinctSp1V1` backend seam for the same recursive public
inputs, and that seam is now exercised by live `GuardianMajority`
proposal/QC verification plus validator durable-state gating, but the
canonical-ordering package still models the reference carrier.
The canonical-ordering package now
also includes `CanonicalCollapseRecursiveContinuity.tla`, a bounded executable
TLC model of that reference recursive carrier: deterministic proof steps,
predecessor-proof hashing, succinct extension-certificate carriage, and header
admission dependence on the anchored predecessor proof relation. The current
formalization is still a reference `HashPcdV1` model rather than a succinct
cryptographic recursion backend, but the recursive relation is now explicitly
modeled rather than left as runtime-only correspondence.

For readers who want a concrete executable example in addition to invariants,
the canonical-ordering directory now includes
`CanonicalOrderingOmissionTrace.tla`, a small TLC witness that reaches the
public-evidence state "`tx1` and `tx2` published, cutoff closed, availability
certified, canonical bulletin close formed, incomplete candidate certified,
omission proof published, candidate still unadmitted."

The `Asymptote` package now mirrors that structural shape for sealing:
deterministic public evidence, a unique positive object, a unique negative
object, and challenge dominance over sealed release.

The current runtime still layers accountable publication on top of those formal
kernels, but it is no longer theorem-critical: objective `OmissionProof` and
`AsymptoteObserverChallenge` publication is replay-deduplicated, immediately
decisive for the slot, and may optionally drive policy-controlled membership
updates through `guardian_registry`. TLAPS proves the uniqueness /
close-or-abort safety core; the accountable-penalty wiring is now an
implementation and policy layer above that kernel.

Taken together, the canonical-ordering and `Asymptote` packages should be read
as the repository's formal kernel for `99% Byzantine Tolerance` over the
public-state-continuity substrate: a fixed public boundary admits at most one
durable close-or-abort result, conflicting candidates are killed by short
objective negative witnesses, and durable execution or sealed release advances
only through canonical collapse. In the live runtime, the ordering side now
refines that kernel into an explicit `CanonicalOrderAbortReason` basis over the
executable verifier surface, while the formal package keeps omission dominance
as the minimal proof kernel that those richer runtime aborts elaborate.
