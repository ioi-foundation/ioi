# The Canonical Categorical Internet Of Intelligence — Thesis For Adoption And Canon Change Recommendations

Status: ratified sequenced canon agenda (owner ruling 2026-08-04); still
non-canonical as text. Nothing in this file amends a canonical owner under
`docs/architecture/`. Canonical owner docs and accepted ADRs win if this
document later drifts.

Date: 2026-08-04.

## Ruling Record (2026-08-04)

Both requested rulings ratified:

1. **The tiered program is the sequenced canon agenda.** First canon leg after
   this ruling = R-08 through R-12-residual (the M5-gating tier), with R-01 and
   R-02 riding the same leg cheaply; R-13 and R-14 one owner-pass each; R-05
   through R-07 after the sovereign-local-completeness proof per the standing
   first-proof ruling (ADR 0021). No canon edit rides the M5 branch except the
   already-ruled event-classification fold, which was commanded as a separate
   commit on that branch before this agenda existed.
2. **R-03 (licensing ADR) starts now as a parallel track**, independent of
   every program gate. Track opener:
   [`licensing-adr-track-opener.md`](./licensing-adr-track-opener.md) — the
   decision space and exact questions for legal review; the accepted ADR lands
   in `docs/decisions/` through its own leg after legal review.

R-12 amendment recorded at ratification, matching the verifier's byte-check
below: the classification substance was ruled in the M5 director-cell STOP-1
answers and its agentgres-side canon landed at `3b193423b` — inside this
document's own provenance HEAD, so the original R-12 entry claimed a gap that
was already partially closed. The residual is only the
`events-receipts-delivery-bundles.md` owner side referencing the agentgres
classification (two owners that can drift until it does), folded in the same
owner pass as R-11. The corrected entry's lesson stands: a claim of absence
needs byte-verification exactly as a claim of presence does.

Provenance: full canon familiarization pass over `docs/architecture/`
(foundations 21 files + 17 object modules, domains 16 files, components 7
subsystems, decisions ADR 0001–0031) plus the live program state under
`internal-docs/implementation/` at branch
`agent/hypervisor-m5-event-substrate`, HEAD `114d7561f`.

Purpose: (1) state, in canon-adoptable register, why the machine-authority and
cryptographic-labor-economy substrate — and not the academic
federated-knowledge-pooling model — is the canonical categorical Internet of
Intelligence; (2) enumerate every recommended canon change surfaced by the
familiarization pass and the independent assessment, each bound to its named
canon owner.

Sequencing discipline: no `docs/architecture/` edit proposed here rides the M5
branch. `internal-docs/implementation/NOW.md` already names uncovered canon
subjects and post-baseline digest drift as advancement blockers; canon edits
follow `_meta/source-of-truth-map.md` ownership and the canon acceptance
process as a separate leg after owner ruling.

---

## Part I — Thesis For Adoption

Proposed canonical placement: a new foundations owner,
`docs/architecture/foundations/internet-of-intelligence.md`, sibling and
companion to `web4-and-ioi-stack.md` — the definitional owner of the Internet
of Intelligence category, exactly as `web4-and-ioi-stack.md` owns the Web4
category. See R-01. The text below is drafted in canon register so it can be
lifted with minimal editing.

### Canonical Definition

**The Internet of Intelligence is the network condition in which independently
governed intelligent institutions exchange bounded, verifiable work under
machine authority. It is not the condition in which separate entities pool
knowledge, parameters, or gradients into shared models.**

Category definition:

> **The Internet of Intelligence is an economy of accountable intelligent
> labor across sovereign boundaries — identity-bound actors, leased authority,
> attributable evidence, challengeable results, and sparse settlement — not a
> commons of pooled cognition.**

Short form:

> **The IoI exchanges verified work, not weights.**

This definition is categorical: it names what the network *is*, independent of
any IOI product. IOI's claim is to implement the canonical category, not to
own a proprietary variant — the same posture `web4-and-ioi-stack.md` takes for
Web4.

### The Rival Model, Stated Fairly

The academic model of an internet of intelligence — inherited from federated
learning, multi-agent systems research, and recent "internet of agents"
position papers — assumes: separate entities cooperate by exchanging
knowledge (gradients, parameters, distillates, traces); trust is assumed or
recovered statistically (differential privacy, secure aggregation, robust
aggregation); identity is soft and capability is self-declared; incentives are
an afterthought; and the coordination substrate *is* the learning protocol.

This model is coherent inside a single trust domain — a lab consortium, one
enterprise, a grant-funded collaboration — where contracts and shared purpose
already exist. As the substrate of a network of self-interested, independently
governed institutions, it fails structurally, for four reasons.

### Four Structural Failures Of The Pooling Model

**1. Wrong adversary.** Federated learning was engineered against a privacy
adversary: honest-but-curious participants and a semi-trusted aggregator. The
moment participation carries economic stakes — and at network scale it must,
because compute and intelligent labor are costly — the adversary becomes
economic: sybils, free-riders, poisoning, claimed-but-unperformed work,
inflated contribution. A decade of Byzantine-robust aggregation research
concedes the point: adversarial contribution cannot be aggregated away
statistically; it must be attributed, verified, and made accountable per
contributor. That is an authority-and-receipts problem, not a learning
problem.

**2. Silence at the effect boundary.** Federated learning is a training-time
protocol. The Internet of Intelligence matters only when machine cognition
produces consequential effects in systems owned by other parties — and there
the pooling model has no semantics at all. Once effects cross an entity
boundary, either delegation is bounded, revocable, and receipted, or the
network oscillates between paralysis (no one delegates) and ambient authority
(everyone regrets it). This clause of the thesis is close to analytically
necessary rather than merely preferable: consequential cross-boundary action
among self-interested parties *entails* a machine-authority substrate.

**3. Weights launder rights.** A gradient or parameter delta crossing a
boundary is an irreversible, unattributable, unrevocable disclosure. Once
trained in, provenance is gone: nothing can be attributed, revoked, licensed,
or adjudicated after the fact. No institution with competitive interests,
liability exposure, or jurisdictional constraints can rationally participate
under that regime — which is why cross-competitor federated learning has
effectively zero production footprint after a decade. Work products with
lineage and receipts preserve rights; parameter exchange destroys them. The
empirical thinness of federated deployment is evidence, not accident.

**4. No incentive layer.** The pooling model's answer to "why contribute?" is
mutual model improvement. It collapses under valuation asymmetry
(contributions are unequal, and Shapley-style contribution accounting is
computationally infeasible and gameable), free-riding, and competition (no
institution strengthens a shared model its rivals also use, uncompensated).
Sustained cooperation among strangers requires pricing, attribution, dispute,
and settlement — a labor market, not a potluck.

### The Inversion Principle

The two models are mirror images:

```text
academic pooling model    assumes cooperation, engineers privacy
canonical IoI             assumes sovereignty, engineers cooperation
```

The first describes how a lab consortium behaves. The second describes how
institutions behave. The canonical IoI takes sovereignty as the ground state
and makes cooperation *contractible* — exact terms roots, expected-surplus
participation tests, bounded leases, receipted contribution, conditional
settlement. This is already IOI canon (`INV-30`, `INV-31`, the
CollaborationTermsEnvelope, the conditional cooperation thesis in `aiip.md`);
the thesis names it as the category-defining inversion.

### The Institutional Recapitulation Argument

Humanity already built an internet of intelligence once — for human
intelligences — and its substrate was not shared brains or pooled cognition.
It was identity, contracts, bounded agency (agency law, literally),
attribution, courts, reputation, and money. Knowledge-pooling among trusting
peers — academia itself — exists *inside* that institutional order, funded and
governed by it, never as its substrate.

Principal-agent economics is the mature theory of exchanging intelligent
effort between self-interested parties; federated learning is a metaphor that
treats intelligence as a poolable fluid. The machine version of the Internet
of Intelligence therefore needs machine-speed versions of the institutional
primitives: leases for agency law, receipts for attribution, challenges for
courts, sparse settlement for money. That is precisely the machine-authority
protocol plus the cryptographic labor economy. The canonical IoI recapitulates
the solution that worked, rather than the one that is academically elegant.

### What Carries The Necessity

The necessity claim decomposes, and honesty about the decomposition is what
makes it defensible:

- **Machine authority is the near-analytic half.** Any network in which
  bounded non-human actors take consequential cross-boundary action among
  self-interested parties requires scoped, revocable, receipted delegation.
  This holds under every market structure — including a model-provider
  oligopoly, where the *users* of those models still require authority
  boundaries against their providers (the provider-trust boundary in
  `web4-and-ioi-stack.md`).
- **The labor economy is the economic half.** Sustained, incentive-compatible
  cooperation among strangers requires attribution, pricing, challenge, and
  settlement. This is necessary for the *economic* Internet of Intelligence —
  the network as an economy rather than a demo.
- **"Cryptographic" is the implementation, not the point.** The necessity
  attaches to properties — non-repudiation, tamper evidence, offline
  verifiability, revocability — not to any chain. Canon already encodes this
  discipline: L1 optional and sparse, receipts checkable offline, complexity
  collapsing when boundaries do (`INV-19`). A version of this thesis that
  mandated a ledger per thought would be ideological; the canonical version is
  not, and its defensibility depends on keeping that discipline.

### The Binding Constraint

The thesis carries one honest asterisk: **verifier economics is the binding
constraint on the Internet of Intelligence, not authority plumbing.** A labor
economy prices work, but pricing *unverifiable* work silently reintroduces the
trust the substrate exists to remove. Much intelligent work is nearly as
expensive to verify as to produce. Canon is already honest that a receipt is
not correctness and that assurance is staged; the categorical consequence is
that the throughput of the IoI scales with the cost curve of verification.
Verification cost must therefore be a first-class, declarable, routable
quantity in the architecture (see R-13), and reputation plus repeated-game
structure — the same residual human labor markets use — carries what
per-result verification cannot.

### The Demotion Rule

Federated learning is not refuted; it is demoted. Cross-boundary exchange of
parameters, gradients, or distillates is a **governed workload on top of the
substrate** — a rights-bound training campaign with exact terms, metering,
contribution accounting, and eligibility gates under the Worker Training
lifecycle and the institutional learning boundary — never a substrate
primitive. Gradient or parameter egress across a sovereign boundary is a
declassification event: it requires resolved rights and receipts like any
other consequential effect, because it is one (see R-14). The academic
model's error was never federated learning itself; it was assuming knowledge
exchange as the coordination substrate rather than as one contractible job
type running on it.

### The Adoption Bet

The true rival of the canonical IoI is not the academic model — it is
vertically integrated, provider-trust, ambient-authority convenience. History
shows convenience beats sovereignty for a long time before institutions with
real liability demand the sovereign version; that is why the enterprise and
liability wedge, the adoption calculus, and the unresolved licensing input are
more decisive to the outcome than any protocol detail. The authority half of
the thesis survives any market structure; the open labor-market half is the
bet. The category is won by making the machine-authority path portable and
unavoidable — and by making the bet observable rather than assumed (see
R-15).

### Non-Claims

- This thesis does not claim federated learning is useless; it demotes it to a
  governed, rights-bound workload.
- It does not claim cognitive alignment; it claims execution-boundary
  alignment, exactly as `verifiable-bounded-agency.md` bounds it.
- It does not claim the current estate passes the north-star network proof;
  the M-sequencer program records the honest distance.
- It does not claim token or L1 inevitability; product, network, and token
  value remain three ledgers until evidence couples them.
- It does not claim verification is solved; it names verifier economics as
  the binding constraint.

---

## Part II — Recommended Canon Changes

Each recommendation names its canon owner(s) per `_meta/source-of-truth-map.md`
discipline. Tiers order by structural leverage, not urgency; sequencing
constraints are listed where they bind. Items already named inside stage
records are restated here so they are not lost to the program estate — the
stage docs correctly rule that canon gaps close in canon, by the named owner,
never inside a work item.

### Tier 0 — Definitional and structural

**R-01 — Mint the definitional owner for the Internet of Intelligence.**
Create `docs/architecture/foundations/internet-of-intelligence.md` from Part I
above; register it in `_meta/source-of-truth-map.md`. Today the term appears
in the repository's own name, the public positioning, and the north-star
proof, yet has no definitional owner: usage is five scattered mentions across
the domains tree, a plurality table in `_meta/start-here.md`, and the network
proof duplicated between `_meta/start-here.md` and `docs/architecture/README.md`.
The category IOI claims to implement should have exactly one owner, as Web4
does. The new file owns the category definition and necessity argument and
cites the north-star test; test ownership stays where it is unless the owner
rules otherwise.

**R-02 — Protect the term.** Add an "Internet of Intelligence" row to
`foundations/term-boundaries.md`: canonical meaning per R-01; must not mean a
shared or global model, a federated-learning network, an agent swarm or
leaderboard, one provider's agent ecosystem, or a global collaboration
database. The term is load-bearing in public copy; without a protected-term
row, drift is unenforceable.

**R-03 — Land the licensing ADR.** Owner: a dedicated accepted ADR with legal
review. Both ADR 0015 and
`foundations/economic-flywheel-and-pricing-boundaries.md` require it, and
`web4-and-ioi-stack.md` names it the single most load-bearing adopt-vs-fork
input: whether a third party may legally implement and independently operate
L0 under `LICENSE-BBSL` versus the required permissive/standards-compatible
open surface. Every adoption-calculus property downstream of this is
contingent until it lands. Recorded gap today; it should not remain one.

**R-04 — Resolve the ADR 0025 dangling reference.** The file is parked in wip
commit `2e9091e32`, absent from the working tree and from
`docs/decisions/README.md`, yet cited as accepted by
`components/daemon-runtime/doctrine.md` (§ Hypervisor App primary attach) and
`components/hypervisor/core-clients-surfaces.md`. Either land it through
acceptance or strip the two citations and close the numbering gap. A canon doc
citing a nonexistent accepted decision is exactly the class of defect the
tracked-caller census exists to catch, one layer up.

### Tier 1 — Adoption-calculus contract gaps (named in `web4-and-ioi-stack.md`, still open)

**R-05 — Reference-implementation contract.** No contract defines what makes a
release *the* reference implementation or how a third party proves parity;
"reference" is used per-subject only. Owner: a new section in
`web4-and-ioi-stack.md` or a dedicated foundations contract, coordinated with
`ecosystem-assurance-certification-liability.md`.

**R-06 — Protocol-governance neutrality owner.** `marketplace-neutrality.md`
owns routing/marketplace neutrality; nothing owns IOI's neutrality as spec
owner and network operator (change process, capture resistance, versioning
rights). Owner: extend `marketplace-neutrality.md` or mint a sibling
foundations owner.

**R-07 — Outsider-runnable conformance suite.** Adopters cannot self-certify;
certification surface is contract-only. Sequencing is already ruled: the
sovereign-local-completeness proof lands first (ADR 0021), then the claim
coverage index in `docs/conformance/README.md` grows a runnable public
profile. Restated here so the adoption-calculus framing keeps pulling it.

### Tier 2 — M5-blocking canon gaps (named in `internal-docs/implementation/stages/m5.md`; close in canon before the affected M5 records claim exit)

**R-08 — Register the M5 contract families.** Nineteen of twenty-two families
resolve only through `reviewed_owner_locator` with empty `contract_ids` —
including `LocalAgentPairingSessionEnvelope`, `RoomParticipantLeaseEnvelope`,
`WorkFrontierItemEnvelope`, `WorkClaimLeaseEnvelope`, `AttemptEnvelope`,
`FindingEnvelope`, `VerifierChallengeEnvelope`, `WorkResultEnvelope`/
`OutcomeDeltaEnvelope`, `ParticipantStateBundleEnvelope`. Owners:
`foundations/common-objects-and-envelopes.md` +
`_meta/schemas/architecture-contract-registry.v1.json`. Constraint: new
registrations must not grow the generated-contract quarantine (71 of 88
generated TypeScript contracts currently have no deriving Rust type; the
register is shrink-only).

**R-09 — Define "independently implemented client."** The M5 exit requires two
independently implemented clients; no owner defines independence (separate
transport? codegen? authoring party? binary?). Owners: ADR 0002 +
`components/hypervisor/core-clients-surfaces.md`. Note the definition also
interacts with `INV-18` (multiplicity is not independence) — the ruling should
say which axes of independence the exit proof actually claims.

**R-10 — Authenticated time source.** Lease TTL, heartbeat, expiry, and
forged-time denial all turn on authenticated time; no owner defines the
trusted source, trust boundary, skew tolerance, or denial semantics. Owners:
`foundations/invariants.md` +
`components/daemon-runtime/platform-operability.md`.

**R-11 — Frontier backpressure and fairness vocabulary.** Canon names queue
backpressure and fair allocation as required room controls and carries
`fairness_and_backpressure_policy_refs`, but defines no admissible policy
vocabulary and no participant-observable denial semantics. Owners:
`domains/ioi-ai/collaborative-outcome-pattern.md` +
`components/daemon-runtime/events-receipts-delivery-bundles.md`.

**R-12 — Admitted-truth versus ephemeral-transport event classes and the
interactive latency budget. PARTIALLY LANDED; re-scoped to the residual.**

**Already canon, verified at the bytes before this entry was written.**
`components/agentgres/doctrine.md` §"Admitted truth versus ephemeral delivery"
(from line 1260) owns the classification rule, states that each owner namespace
declares which of its event classes are admitted truth and which are ephemeral
delivery-only, fixes the discriminator as a property of the occurrence rather
than its urgency, and carries the p95 budgets. Landed at `3b193423b`
(`canon(agentgres): event-class line and the subscription-lease refusals`) —
inside this document's own provenance HEAD, which is why the original entry was
stale on the day it was written. It was later extended with the rule that
consulting the declaration is a read, not an operation, and that a verifier must
establish the ephemeral path by COUNTING traversals rather than observing an
unchanged head.

**Residual, still open.** The
`components/daemon-runtime/events-receipts-delivery-bundles.md` owner side: the
delivery-bundle owner does not yet reference the agentgres classification, so a
reader arriving from the delivery side finds no rule and the two owners can
drift. Resolve in the same owner pass as R-11.

**Why this entry is corrected rather than deleted.** A recommendations register
that restates a closed gap as open is the recorded-verdict class pointing the
other way: **a claim of absence needs byte-verification exactly as a claim of
presence does.** "No owner classifies this" was asserted, not measured, and the
owner had classified it before the sentence was written.

### Tier 3 — New doctrine from the independent assessment

**R-13 — Verifier-economics doctrine.** Adopt "verification cost is the
binding constraint" as explicit canon. Concretely: (a) `VerifierPath` and
acceptance profiles declare a verification-cost class (order-of-magnitude
cost-to-verify relative to cost-to-produce, or typed tiers); (b) routing and
acceptance policy may reason over that class; (c) a pricing rule — work whose
declared assurance ceiling is unverifiable-at-price must carry that ceiling
visibly rather than price as verified. Owners:
`components/hypervisor/evaluations.md` (judgment contract) +
`foundations/economic-flywheel-and-pricing-boundaries.md` (pricing boundary),
with `RoutingDecisionEnvelope` untouched except for the declared class ref.
This converts the thesis's honest asterisk into an enforceable contract
surface instead of prose.

**R-14 — The demotion rule as canon.** One clause, stated once by the right
owner: cross-sovereign-boundary exchange of parameters, gradients, or
distillates is a rights-bound governed workload (Worker Training lifecycle +
`InstitutionalLearningBoundaryProfile`), never a substrate primitive; gradient
or parameter egress is a declassification event requiring resolved rights and
receipts. Owners: `foundations/institutional-learning-boundary.md` (the
egress/rights clause) + `foundations/worker-training-lifecycle.md` (the
workload classification), with an information-flow cross-reference in
`foundations/security-privacy-policy-invariants.md`. Canon implies all of
this today; nothing states it, which leaves the front door open to exactly the
substrate confusion the academic model carries.

**R-15 — Make the adoption bet observable.** Add one measured indicator to the
flywheel doctrine: the share of consequential effects crossing the
machine-authority path versus explicitly labeled provider-trust routes, per
deployment and in aggregate. The category claim is that the machine-authority
path becomes unavoidable; a claim of that shape should be falsifiable from
receipts, not asserted. Owner:
`foundations/economic-flywheel-and-pricing-boundaries.md` (indicator), with
`ecosystem-assurance-certification-liability.md` naming it in the assurance
posture projection. Low urgency; high honesty value.

### Out of scope here

The 2026-07-30 hypervisor surface end-state audit
(`internal-docs/audits/2026-07-30-hypervisor-surface-end-state-audit/`)
already files the Settings-ownerless finding, the absent M6 surface-record
contract families, and the `UX-00` gap with their own owners; they are not
duplicated into this document.

## Sequencing Summary

1. Nothing above edits `docs/architecture/` on the M5 branch; canon digest
   drift is a named advancement blocker in the program estate.
2. R-08 through R-12 gate M5 records and should be the first canon leg after
   owner ruling, since the stage cannot exit around them.
3. R-01/R-02 (definitional owner + protected term) can ride the same canon
   leg cheaply; R-13/R-14 are one-owner-pass additions each.
4. R-03 (licensing ADR) is independent of every program gate and is the
   longest-lead item; it should start now regardless of sequencing elsewhere.
5. R-05/R-06/R-07 follow the sovereign-local-completeness proof per the
   already-ruled first-proof ordering.
