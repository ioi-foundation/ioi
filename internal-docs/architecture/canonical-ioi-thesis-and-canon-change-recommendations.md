# The Canonical Categorical Internet Of Intelligence — Thesis For Adoption And Canon Change Recommendations

Status: archived executed canon agenda; promotion complete; non-canonical
historical record. Executed in full on 2026-08-05 and frozen as rationale.
Authority: `docs/architecture/` owners and accepted ADRs are canonical and win
on drift; this file must not direct current work.
Archived: 2026-08-30.
Succeeded by: the canonical owners named in the status table below and the live
[`machine-authority-category-program.md`](./machine-authority-category-program.md)
for new category evidence and promotion work.

Date: 2026-08-04. Regime restatement: 2026-08-05.

**Historical regime note.** At execution time this register became the sole
remaining carrier of the then-open Tier-2 gap names after the program estate —
`internal-docs/implementation/` (master guide, stages, modules, work items,
`NOW.md`, and the whole sequencer toolchain) — was deleted on 2026-08-05 by the
ratified merge-and-strip directive (historical deleted path
`internal-docs/overhaul/2026-08-05-merge-and-strip-action-plan.md` §5.1,
retained in Git history at the 2026-08-05 transition), together with the
certification harness, the checker/ratchet fleet, and
the retained-evidence tree. Every R-item later closed and the current owners now
carry their own implementation status; this archived register is no longer a
live gap or sequencing authority. Dated provenance and the dated ruling record
are kept as history—they record what was true when the agenda was ratified, not
what binds work today.

## Ruling Record (2026-08-04) — history, kept verbatim

The two rulings below are recorded as they were made. Their *substance* — the
tier ordering, R-03 as an independent parallel track — is still in force. Their
*machinery* references (the M5 branch, the M5-gating tier, the canon leg) name a
program estate deleted on 2026-08-05; see the regime restatement at the head of
this file and the rewritten Sequencing Summary at the foot. Nothing here is
edited to look like it was made under the current regime.

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

Provenance (history, 2026-08-04): full canon familiarization pass over
`docs/architecture/` (foundations 21 files + 17 object modules, domains 16
files, components 7 subsystems, decisions ADR 0001–0031) plus the then-live
program state under `internal-docs/implementation/` at branch
`agent/hypervisor-m5-event-substrate`, HEAD `114d7561f`. That estate no longer
exists in the working tree; the paths above resolve only inside history and at
the `pre-overhaul/*` tags. They are recorded here because provenance must stay
checkable, not because anything below depends on reading them.

Purpose: (1) state, in canon-adoptable register, why the machine-authority and
cryptographic-labor-economy substrate — and not the academic
federated-knowledge-pooling model — is the canonical categorical Internet of
Intelligence; (2) enumerate every recommended canon change surfaced by the
familiarization pass and the independent assessment, each bound to its named
canon owner.

Sequencing discipline (restated 2026-08-05 for the light regime): the original
rule — no `docs/architecture/` edit rides the M5 branch, because `NOW.md` named
uncovered canon subjects and post-baseline digest drift as advancement blockers
— is discharged. There is no M5 branch to keep clean, no `NOW.md` to raise a
blocker, and no digest to drift. What survives it is the part that was never
about the estate: **canon edits follow `_meta/source-of-truth-map.md` ownership,
land at the named owner rather than inside a work record, and are proposed as
their own change.** The post-strip verification bar is the whole bar — `cargo
build`, `cargo test`, `npm run lint`, `npm run typecheck` — and this agenda adds
no gate of its own.

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
constraints are listed where they bind. Items that were once co-named inside
stage records are restated here in full because the stage records are gone: the
estate's own rule was that canon gaps close in canon, by the named owner, never
inside a work item, and the strip made this register the only place the naming
still lives. A reader needs nothing but this file and the owner docs it points
at.

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
certification surface is contract-only. What R-07 owes is a *definition* — the
claim coverage index in `docs/conformance/README.md` grows a defined runnable
public profile naming what an outside adopter runs and what passing it claims.
ADR 0021's first-proof ordering governs when a sovereign-local-completeness
*proof* may be claimed; it does not delay writing the contract surface such a
proof would be checked against, and writing the definition first is what makes
the eventual proof checkable. New proof apparatus is explicitly out of scope.

### Tier 2 — collaboration-substrate canon gaps (formerly the M5-blocking tier; now owed on their own terms)

These four were originally raised as stage-exit blockers in
`internal-docs/implementation/stages/m5.md`. That file no longer exists, and no
stage record can raise them again. They are restated here as ordinary canon
obligations: each names a real absence at a named owner, and each stays true
whether or not any milestone ever asks for it. **The gap is the reason; the gate
never was.**

**R-08 — Register the collaboration-substrate contract families.** Ten families
that canon defines field-for-field under `foundations/objects/` need a
foundations-plane contract registration:
`LocalAgentPairingSessionEnvelope`, `RoomParticipantLeaseEnvelope`,
`WorkFrontierItemEnvelope`, `WorkClaimLeaseEnvelope`, `AttemptEnvelope`,
`FindingEnvelope`, `VerifierChallengeEnvelope`, `WorkResultEnvelope`,
`OutcomeDeltaEnvelope`, `ParticipantStateBundleEnvelope`. Owners:
`foundations/common-objects-and-envelopes.md` +
`_meta/schemas/architecture-contract-registry.v1.json`, with every family
derived from its real field-level owner under `foundations/objects/`.

*Scope, re-scoped at the bytes on 2026-08-05.* "No registered contract at all"
would have been the wrong claim, and measuring it first is what caught that.
Eight of the ten names already resolve to a registered v3 contract carrying the
same `canonical_owner_ref` anchor — `WorkFrontierItem`, `Attempt`, `Finding`,
`VerifierChallenge`, `WorkClaimLease`, `ParticipantStateBundle` in the
`schema://ioi/applications/ioi-ai/...` namespace, and `WorkResult` and
`OutcomeDelta` in `schema://ioi/foundations/...`. Only
`RoomParticipantLeaseEnvelope` and `LocalAgentPairingSessionEnvelope` have
nothing at all. **The honest residual is the foundations envelope registration**,
which is a different contract from its v3 sibling in three measurable ways: it
lives in the `ioi.foundations.*` schema-version namespace; it carries canon's
own required set (only the fields the owner marks mandatory) where every v3
schema is total — all properties required, nullable ones present-as-null; and it
leaves neighbouring families opaque instead of restating their shape. That is
exactly the relationship family 1 established between `WorkFrontierItem v3` and
`WorkFrontierItemEnvelope v1`, and the remaining nine follow it.

*Constraint, re-derived at the bytes on 2026-08-05.* The original constraint —
"must not grow the generated-contract quarantine (71 of 88 generated TypeScript
contracts have no deriving Rust type; the register is shrink-only)" — cited the
wrong artifact. That quarantine was the **ts-rs export lane** over
`apps/hypervisor/src/generated/hypervisor-contracts/` (90 banner-carrying files
today), held in `scripts/data/generated-contract-owner-quarantine.v1.json` and
enforced by `npm run check:generated-contract-owners`; both the register file and
the check were deleted with the rest of the apparatus, and
`foundations/term-boundaries.md` still linked to the dead file until this leg
repaired it. The **architecture contract registry** — the artifact R-08 actually
registers into — is a different lane and has always declared a `rust_projection`
for every contract (141 of 141 at pre-strip master, 144 of 144 today). A
statement about one lane was never evidence about the other. The live constraint
is the invariant the number was protecting, stated directly: **every new
registration lands with its deriving Rust type in the same change — zero
TypeScript-only growth, permanently.**
`scripts/generate-architecture-contracts.mjs` is the enforcement surface, and
its refusals are correct by construction: fit the schema to what both
projections provably represent, never weaken the generator to admit a schema.

**R-09 — Define "independently implemented client."** Canon requires two
independently implemented clients and never says what independence is (separate
transport? codegen? authoring party? binary?). The stage record that would have
consumed the definition is gone; the definitional hole is not, because ADR 0002
and `core-clients-surfaces.md` both lean on the phrase. Owners: ADR 0002 +
`components/hypervisor/core-clients-surfaces.md`. The definition also interacts
with `INV-18` (multiplicity is not independence) — the ruling must say which
axes of independence any claim of two clients actually asserts.

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

## Status Table — What Closed (2026-08-05)

The whole agenda executed on 2026-08-05 in thirteen changes. Every R-item is
closed. This table is the record; where an item was **re-scoped at
byte-verification** — because the register named a gap that had already moved —
the re-scope is stated rather than smoothed over, since the register's own R-12
lesson is that a claim of absence needs byte-verification exactly as a claim of
presence does. It earned that lesson four more times here.

| Item | State | Closing change | Landed at |
| --- | --- | --- | --- |
| Register cleanup | **closed** | restated every retired-estate passage as a live obligation; the register now declares itself the sole live carrier of the Tier-2 gap namings | PR #142 |
| R-01 | **closed** | `foundations/internet-of-intelligence.md` minted from Part I, registered in `_meta/source-of-truth-map.md`; north-star proof deduplicated as the strict union of both prior copies | PR #144 |
| R-02 | **closed** | protected-term row in `foundations/term-boundaries.md`, category `protocol`, all five Must-Not-Mean failure modes plus two more | PR #144 |
| R-03 | **closed** | ADR 0033: split surface (Apache-2.0 protocol surface now, CC BY 4.0 prose now, BBSL reference implementation to 2029-11-06, marks and certification separate); D-1 and D-2 both fixed in `LICENSE-BBSL`; `LICENSE-MANIFEST.json` covers 6,354 tracked files with zero unmatched. Counsel review stated as advised inside the ADR | PR #153 |
| R-04 | **closed — landed, not stripped** | ADR 0025 landed through acceptance. Judgment recorded: `execution-horizons.md:255` still carries the six-point binding bar, and both citing owners already stated the decision's substance as current prose, so stripping the citations would have deleted a pointer to something canon lives by | PR #143 |
| R-05 | **closed** | § The Reference-Implementation Contract in `foundations/web4-and-ioi-stack.md`: five designation conditions, parity by fixture + **refusal** + surface completeness + independence disclosure, and the rule that a designated release cannot legislate | PR #152 |
| R-06 | **closed** | new owner `foundations/protocol-governance-neutrality.md`, registered in the ownership map: three roles held apart, the change process and its timing-only emergency exception, four falsifiable capture resistances, versioning rights | PR #152 |
| R-07 | **closed as a definition** | `ioi_public_conformance_profile_v1` in `docs/conformance/README.md`: mechanical admission rule, three entitlement levels each with an explicit *not* column, and the profile's own `target_defined` row. Defined and unpopulated, and it says so; **no proof apparatus was built, per the run's standing rule** | PR #152 |
| R-08 | **closed — re-scoped at the bytes** | ten envelope families registered with schemas derived field-for-field from their owners, fixtures red-proven in both directions, and a deriving Rust type each. Registry 144 → 153 contracts, **153 of 153 with a `rust_projection`** | PR #145, #146 (family 1 pre-landed) |
| R-09 | **closed** | ADR 0032 + owner section in `core-clients-surfaces.md`: four axes, the `INV-18` split between contract claims and party claims, and the ruling that an exit proof claims binary + codegen + transport and **not** authoring party unless a disclosed third party authored one | PR #149 |
| R-10 | **closed — re-scoped at the bytes** | `INV-39` (invariants.md had nothing) + § The authenticated time source in `platform-operability.md`: lease TTL/heartbeat/expiry bound to the temporal contract, and forged-time refusal, which did not exist | PR #148 |
| R-11 | **closed** | closed backpressure and fairness discipline sets + participant-observable denial semantics; four consequences including "silence is not a denial" and "a denial consumes nothing" | PR #147 |
| R-12-residual | **closed** | `events-receipts-delivery-bundles.md` now references the agentgres classification instead of restating it, and adds the delivery-side obligations the classification does not cover | PR #147 |
| R-13 | **closed** | verification-cost class on `VerifierPath` and acceptance profiles (`negligible … unverifiable_at_price`), routing may reason over it, and the pricing rule that an unverifiable-at-price ceiling travels with the **price**, not the receipt | PR #150 |
| R-14 | **closed** | one clause per owner: parameter/gradient egress as declassification, cross-boundary exchange as a governed Worker Training workload never a substrate primitive, and Information-Flow Invariant 8 as the cross-reference | PR #151 |
| R-15 | **closed** | `machine_authority_share` in the flywheel owner and on `AssurancePostureProjection`; unlabeled routes count as provider-trust, and a falling share is information rather than embarrassment | PR #150 |

### Items re-scoped at byte-verification

Four register claims were measurably stale on the day they were worked. Each
re-scope is recorded in its own change and summarized here:

1. **R-08's scope.** "No registered contract" was false for eight of the ten
   names: a v3 contract already existed at the same `canonical_owner_ref`
   anchor. The honest residual was the **foundations envelope** registration —
   `ioi.foundations.*` namespace, canon's own required set where every v3 schema
   is total, neighbouring families left opaque. Only `RoomParticipantLease` and
   `LocalAgentPairingSession` had nothing at all.
2. **R-08's constraint.** The "71 of 88" quarantine was the **ts-rs export
   lane** over `apps/hypervisor/src/generated/hypervisor-contracts/`, not the
   architecture contract registry this item writes into. `term-boundaries.md`
   still linked to the deleted quarantine register; repaired in the same change.
3. **R-10.** Most of it was already closed — `INV-36`, the Temporal
   Verification Contract, the `clock` plane, and declared skew tolerance all
   existed. The genuine residual was an absent invariant, an unbound
   lease/heartbeat path, and a missing forged-time refusal.
4. **R-06's owner path.** The register wrote
   `foundations/marketplace-neutrality.md`; the file is at
   `domains/marketplace-neutrality.md`.

### Deviations from the register, under canon precedence

Where a register clause met a canonical owner that already claimed the subject,
the owner won and the deviation is recorded:

- **R-11's member sets** went to `foundations/canonical-enums.md`, not to the
  two named owners, because that file's charter reads "This file owns the member
  sets. Other docs show the enum only as a labeled excerpt with a link here."
  The named owners carry the semantics.
- **R-13's `VerifierPath` clause** split: `evaluations.md` owns the class (a
  judgment-contract property), while `VerifierPath` itself is defined by
  `domains/ioi-ai/collaborative-outcome-pattern.md` and carries only the
  declaration requirement.
- **R-09** landed as ADR 0032 refining ADR 0002 rather than editing it, per this
  repository's convention that accepted ADRs are amended by successors.
- **R-05/R-06** each chose between two options the register offered: a section
  in `web4-and-ioi-stack.md` for R-05 (it already carried the recorded gap), and
  a **sibling** owner for R-06 (extending `marketplace-neutrality.md` would have
  merged the two questions R-06 exists to separate).

### Standing rules honored

No proof apparatus was rebuilt. This run produced canon text, two ADRs, nine
contract registrations with their generated Rust and TypeScript projections,
fixtures, and license drafting — and certified nothing. Fixture red-proofs ran
through the existing generator and the existing generated Rust test; no checker,
gate, script, or npm target was added. The post-strip verification bar was met
throughout: `cargo build`, `cargo test`, `cargo fmt --check`, `npm run lint`,
`npm run typecheck` all green, with the architecture-contract suite at 14/14.

## Sequencing Summary

Restated 2026-08-05. The original summary sequenced this agenda against program
gates — an M5 branch to stay off, a stage that could not exit around R-08
through R-12, a first-proof ordering enforced by the estate. Three of those five
clauses named machinery that no longer exists. What remains is ordering by
dependency and leverage, which is the only ordering canon ever needed:

1. **Nothing here waits on a branch or a milestone.** The M5 branch, the canon
   digest, and the advancement-blocker mechanism are gone; canon edits are
   ordinary changes at their named owners under `_meta/source-of-truth-map.md`.
2. **R-08 through R-12 stay first by leverage, not by gate.** They are the
   contract- and vocabulary-level absences other work compounds on: an
   unregistered family is re-derived by every reader, and an undefined denial
   vocabulary is re-invented by every implementer.
3. **R-01/R-02 (definitional owner + protected term) ride cheaply alongside**;
   R-13/R-14 are one-owner-pass additions each.
4. **R-03 (licensing ADR) is independent of everything** and is the longest-lead
   item; it starts regardless of sequencing elsewhere.
5. **R-05/R-06/R-07 are contract-surface definitions, not proofs.** ADR 0021's
   first-proof ordering still governs when a *proof* may be claimed; it does not
   govern when the contract a future proof would satisfy may be *written*.
   Writing the definition earlier is what lets the eventual proof be checked
   against something.
