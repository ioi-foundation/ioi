# ADR 0041: Adopt Coordinate-Wise AFT Assurance And Refuse Evidence Laundering

- Status: Accepted and implemented through the M4 certificate-only verifier
  and runtime-v3 assurance boundary; this decision grants no externalization,
  economic, deployment, or final-release claim by itself
- Date: 2026-09-01
- Owners: AFT consensus / governed-effect admission / portable verification
- Refines: ADR 0039's obligation separation and versioned finality evidence
- Does not amend: current deployment selection, the canonical
  ordering/admission/finality profile enum, Agentgres authority ownership, or
  the existing AFT theorem assumptions
- Confidence: accepted from the owner-directed M0–M8 program; every executable
  claim remains gated by the implementation, proof, simulation, independent
  verification, and release evidence named below

## Context

The existing AFT assumption lattice records one ordered finality rank, the
union of assumptions, and a single post-quantum bit. It successfully prevents
a weak finality-bearing constituent from being hidden behind a stronger one,
but the scalar cannot distinguish consensus cryptography from channel or
external-endpoint cryptography, deterministic eventual-synchrony progress from
randomized asynchronous progress, conflict safety from availability, or a
ledger authorization from its real-world consequence.

That ambiguity creates evidence-laundering risks. A PQ seal could visually wrap
a classical ordering certificate; a strong conflict-safety certificate could
be presented as availability; a timeout could be used to select a weaker
certificate class; or a bond figure could be presented as a general economic
cost even when only a particular objectively provable fault is slashable.

AFT is being developed toward effect-native assurance. The portable object
therefore has to state the exact properties established for an effect and the
assumptions, evidence, and transformations that established each one.

## Decision

### 1. AFT assurance is a versioned vector

New AFT authorization and portable evidence use a versioned
`GuaranteeVectorV1`. The vector keeps at least these coordinates distinct:

- conflict safety, configuration, committee geometry, quorum, fault bound, and
  conflict domain, including an explicit safety-construction label that keeps
  legacy guardian majority distinct from quorum-intersection BFT;
- liveness theorem, network model, adversary model, and fault bound;
- consensus, authenticated-channel, externalization, and derived end-to-end PQ
  posture;
- cryptographic primitive census and private threshold setup/DKG dependency;
- accountability;
- publication availability, custody, and retention;
- external-resource semantics and at-most-once support;
- distinct slashable collateral;
- profile-scoped measured latency;
- assumption and theorem identifiers; and
- commitments to constituents and independently verified transformations.

Missing or unresolved coordinates are unclaimed. They never inherit a sibling
coordinate's value and never default to the stronger value.

### 2. Requirements and evidence are different operations

Effect policies are `GuaranteeRequirementsV1`. Combining policies is a
requirements join: the result retains the stricter lower bound, and
incompatible exact scopes refuse.

Combining evidence is an evidence meet. It retains only guarantees established
across the load-bearing constituents, unions consumed assumptions, and refuses
to infer a stronger property from wrapper shape or caller intent.

The types and entry points for these two operations remain separate. A policy
join is never accepted as evidence.

### 3. Strengthening requires a named verified transformation

A wrapper may establish a property that its constituents do not establish only
when it contributes independently verified evidence under a versioned,
coordinate-specific transformation rule. Each such rule names its theorem and
commits to its evidence. Unknown transformations cannot strengthen any
coordinate.

This is the runtime form of the no-laundering rule. M4 must pair it with the
certificate-only lower bound: a verifier cannot distinguish two executions
that expose identical certificates, so it cannot soundly assert a property
that differs between those executions without additional evidence.

### 4. End-to-end PQ is a validated conjunction

`end_to_end_pq=true` is valid only when every load-bearing consensus primitive,
the confidentiality and peer-authentication channel, and the externalization
verification chain are PQ, and no primitive remains unresolved. A hash-only
continuity object or terminal seal cannot make a classical constituent PQ.

ADR 0048 supersedes production BLS and threshold-BLS optimizations. Historical
evidence remains explicitly `pq=false`; VDF evidence is advisory and may not
be a safety or liveness dependency in the target PQ profile.

The initial hash-only asynchronous profile is scoped to the construction it
implements and proves:

- static Byzantine adversary;
- randomized asynchronous termination below one-third Byzantine membership;
- private authenticated channels, with a PQ channel implementation required
  for an end-to-end PQ claim; and
- no private threshold setup or DKG.

It is forbidden to infer adaptive security from removal of a DKG. “No trusted
setup” is also forbidden as an unqualified substitute for “no private
threshold setup or DKG”; membership enrollment and channel authentication
remain visible assumptions.

### 5. Consequence claims stop at the declared resource model

At-most-once externalization is available only under a committed adapter and
resource profile exposing an atomic idempotency register, compare-and-set, or a
precisely equivalent contract. The durable claim precedes invocation. An
ambiguous result enters an explicit unknown/reconciliation state and is not
blindly replayed.

An arbitrary HTTP request, physical action, network timeout, or ledger
authorization alone does not earn an at-most-once or attributable-failure
claim. Unsupported resource profiles report the coordinate as false, and an
effect policy requiring it refuses.

### 6. Economic assurance names slashable collateral only

The economic coordinate is the minimum distinct collateral that the verifier
proves is locked, unencumbered, attributable under the named fault-evidence
rule, and enforceably slashable through the declared challenge horizon.

It is not called the adversary's cost to violate, capture the committee, or buy
all seats. Shared collateral is counted once. Silence and withholding have no
monetary floor unless a separate sound evidence rule makes that exact behavior
objectively punishable. The existing T8 capture/supply lower-bound row remains
separate until independently closed.

### 7. Latency and downgrade claims are profile-specific

Latency measurements bind the cryptographic, committee, network, and benchmark
profile that produced them. A BLS fast-path measurement does not become a PQ
latency claim. No timeout may select a weaker certificate, cryptographic suite,
adversary model, or finality class when an effect policy requires the stronger
one.

### 8. Migration is additive and fail-closed

Legacy scalar receipts may continue to decode while migration is active. Their
conversion populates only coordinates established by the legacy evidence;
missing scope, channel, externalization, and theorem data remains unclaimed.
No legacy production profile currently earns `end_to_end_pq=true`.

Production authorization moves to v1 only after its issuer binds exact verified
constituent hashes and all effect-policy coordinates. Removing legacy decoding
is a later compatibility decision, not an implication of this ADR.

## Canonical claim vocabulary

Permitted only with the named evidence:

- **post-quantum consensus** — every load-bearing consensus primitive is PQ;
- **post-quantum authenticated channel** — confidentiality and peer identity
  authentication are PQ;
- **end-to-end post-quantum** — the validated consensus/channel/externalization
  conjunction is true;
- **randomized asynchronous progress** — the implemented ACS theorem and its
  declared static-adversary/private-channel model are present;
- **no private threshold setup or DKG** — the verification chain consumes no
  such setup;
- **all-but-one conflict safety** — the unanimous boundary theorem and exact
  committed configuration are present;
- **transferable accountability** — the receipt carries independently
  verifiable conflicting evidence and implicated identities;
- **at-most-once externalization** — the declared resource profile and durable
  execution/reconciliation proof are present;
- **slashable-collateral floor** — distinct, locked, attributable collateral is
  verified; and
- **offline-verifiable assurance** — the frozen receipt, schema, algorithms,
  state proofs, and verifier reproduce the decision without an IOI node.

Forbidden without separately completed evidence:

- adaptive security for the initial hash-only ACS profile;
- unqualified “no trusted setup”;
- a global PQ bit derived from a PQ wrapper around classical evidence;
- availability, freshness, external occurrence, or correctness inferred from
  conflict safety;
- at-most-once arbitrary HTTP or physical effects;
- timeout-based assurance downgrade;
- slashable collateral relabelled as general violation or capture cost;
- cross-domain progress inferred for the stalled domain itself;
- a universal latency claim spanning different profiles; and
- “first,” “unique,” or competitor-superlative claims without a dated,
  systematic related-work review.

## Implementation and release gates

The additive type and validation foundation lives in
`crates/types/src/app/consensus/collapse/guarantee_vector.rs`. M4 adds the
opaque certificate-only verifier, exhaustive coordinate/rule vocabulary,
default-deny transformation registry, bounded TLA+ model, negative/mutation
corpus, and runtime-v3 emission plus independent recomputation. No
strengthening transform is enabled merely because its metadata shape is
recognized.

The decision becomes a releasable AFT claim only after the M0–M8 ledger records
reproducible evidence for PQ primitives and channels, the optimistic core,
hash-only fallback, no-laundering proof, consequence state machine, economic
proof, portable clean-room verification, mixed-domain demonstration, affected
workspace CI, and resolution of high-severity security findings.

## Consequences

- Assurance becomes longer and less compressible, but callers cannot silently
  substitute one property for another.
- Some legacy evidence that previously carried `pq=true` at an artifact level
  will correctly carry `end_to_end_pq=false`.
- Policies can select consequence-level guarantees without naming a consensus
  marketing tier.
- Production has no BLS optimization surface; historical BLS evidence cannot
  contaminate PQ claims.
- External resources and collateral become explicit theorem boundaries rather
  than prose implications.
- Independent verifiers can report achieved coordinates and exact refusals
  instead of one Boolean or one finality rank.

## Rejected alternatives

### Keep one ordered assurance rank

Rejected because safety, liveness, availability, cryptography,
externalization, economics, and latency are not one total order.

### Keep one `pq` Boolean

Rejected because it cannot identify a classical channel or endpoint beneath a
PQ certificate wrapper.

### Let wrappers declare stronger labels

Rejected because wrapper shape is not evidence. Strengthening requires a
verified coordinate-specific transformation.

### Treat authorization as external occurrence

Rejected because consensus can authorize an effect without proving that an
arbitrary external resource executed it exactly once.
