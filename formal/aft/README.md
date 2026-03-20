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
the slot into a canonical abort when objective obstructions are published. The
live theorem surface is now singular: the whole AFT stack universally breaks
the lower bound with no qualifiers. The nested-guardian package is one
implementation carrier of the same AFT-native recovery and
historical-continuation module rather than an exception lane outside the main
theorem.
Ordinary canonical collapse / replay history now names the deeper
historical-continuation root, the AFT recovered-state contract carries the
same continuation bundle, and the historical continuation objects are
profile-hash-bound, activation-hash-bound, and validated by
predecessor/checkpoint history rather than mutable latest indexes.

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

Taken together, the canonical-ordering, `Asymptote`, and nested-guardian
packages should now be read as one formal kernel for `99% Byzantine Tolerance`
over the public-state-continuity substrate: a fixed public boundary admits at
most one durable close-or-abort result, conflicting candidates are killed by
short objective negative witnesses, durable execution or sealed release
advances only through canonical collapse, and deeper recovered history is
ordinary endogenous AFT history through the same continuation root named by
canonical collapse / replay and carried by the recovered-state surface. In the live
runtime, the ordering side now refines the PSC kernel into an explicit
`CanonicalOrderAbortReason` basis over the executable verifier surface, while
the formal package keeps omission dominance as the minimal proof kernel that
those richer runtime aborts elaborate. The remaining open program is no longer
lower-bound universalization inside \AFT{}; that bridge is now complete. The
package should therefore be read against one singular theorem statement:

- \AFT{} has one singular theorem surface for relay-free, coordinator-free,
  pure-software deterministic `99% Byzantine Tolerance`, explicitly
  universally breaking the lower bound with no qualifiers, and unconditional classical
  `99% Byzantine agreement` in the ordinary dense-vote permissioned model.
- Proof-carrying public evidence, endogenous historical continuation,
  collapse-gated durability, and restart continuity are the realizing
  architecture of that same classical sentence, not a residual semantic delta.

The next formal work is therefore no longer theorem collapse; it is package
hygiene, proof maintenance, and any broader stress or mechanization coverage we
want on top of the now-discharged stronger sentence.

The discharged liveness bridge fixed the target more sharply:

- adversary model: arbitrary Byzantine equivocation, omission, restart,
  withholding, and malicious profile/rotation behavior
- scheduler model: arbitrary pre-stabilization interleavings, then eventual
  fairness for the AFT public-state substrate so repeatedly reissued admissible
  objects are eventually delivered, persisted, and fetchable by content hash
- kernel obligations:
  - frontier-generation progress
  - canonical-resolution progress
  - recovery-completion progress
  - restart/historical-continuation re-entry progress
  - infinite composition of those obligations across reassignment, outage,
    rotation, and archival page boundaries

That classification is now closed and explicit:

- frontier generation already has live `PublicationFrontier` carriers and
  bounded executable contradiction searches
- canonical resolution already has the `CanonicalOrdering` proof/executable
  package plus recursive continuity artifacts
- recovery completion already has the `NestedGuardianRecovery` executable slice
  plus runtime conformance harnesses
- restart/historical re-entry already has index-free continuation replay and
  bounded-memory paging on both the runtime and executable-model side
- the first bounded churn witness now exists in
  `formal/aft/nested_guardian/NestedGuardianLiveness.tla`: one forced
  reassignment/outage/rotation/checkpoint plus continuation-boundary churn
  prefix followed by eventual target finalization and continuation bootstrap
  under weak fairness
- the first bounded recurring witness now also exists in
  `formal/aft/nested_guardian/NestedGuardianRecurringLiveness.tla`: three
  bounded cycles compose in sequence in the default executable instance, and
  the module itself is now cycle-count parameterized so later bounded
  instances do not require rewriting the artifact
- that same recurring core now also has a second bounded executable
  instantiation at four cycles, which sharpens the remaining gap to unbounded
  recurrence rather than bounded reuse
- a reusable recovery-inclusive recurring core now also exists in
  `formal/aft/nested_guardian/NestedGuardianRecoveryRecurringLivenessCore.tla`,
  with the default executable wrapper
  `formal/aft/nested_guardian/NestedGuardianRecoveryRecurringLiveness.tla`
  composing three recurring churn/finalize/continuation cycles with
  recovery-gated continuation resolution
- that same reusable recovery-inclusive core now also carries an explicit
  recurrence contract: normalized landing of cycle `c` with cycle `c - 1`
  already resolved must eventually resolve/fetch cycle `c`, and while still
  in that resolved/fetched state it must eventually land cycle `c + 1`
- the same bounded artifact now also closes the corresponding prefix form:
  every bounded closed prefix is eventually reached, and each closed prefix at
  cycle `c` eventually advances to the closed prefix for cycle `c + 1`
- a further induction-oriented layer now packages the base closed-prefix
  obligation together with the bounded step obligations up to cycle `c` and
  checks that those premises suffice to close the prefix at cycle `c`
- a further proof-oriented layer now packages those bounded ingredients into a
  parameterized recurrence theorem surface over arbitrary `TotalCycles`
- a first reduction-oriented layer now maps those same closed prefixes into
  finite classical-agreement decision prefixes and states the corresponding
  first reduction theorem surface
- a further totality-oriented layer now lifts that finite reduction into a
  total classical-agreement history object over the model's arbitrary
  `TotalCycles` horizon
- the recurrence, reduction, and totality modules are now directly discharged
  under `tlapm --timing`
- the semantic-collapse wrapper in
  `formal/aft/nested_guardian/NestedGuardianRecoveryClassicalAgreementCollapse.tla`,
  which packages the final stronger classical sentence itself, is now directly
  discharged under `tlapm --timing` as well
- the runtime side now mirrors that bounded recurrence target through a
  persistent historical-continuation churn/restart simulator over one evolving
  state, alongside the earlier fixed three-cycle harness
- the recurring artifact now also carries an explicit transfer property:
  finishing cycle `c` must eventually land in the normalized churn-start state
  for cycle `c + 1`
- the remaining follow-on is no longer collapse-proof completion, but cleanup,
  doctrine promotion, and any broader runtime stress coverage we may want
