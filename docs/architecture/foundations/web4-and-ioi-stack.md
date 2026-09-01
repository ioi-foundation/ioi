# Canonical Web4 and the IOI Stack

Status: canonical architecture authority.
Canonical owner: this file for the Web4 category definition, the IOI stack
boundary, the source-neutral deterministic admission kernel contract (C1–C12),
and the institution boundary as stated for the Web4 stack. Machine Authority
category and protocol-family ownership live in [`machine-authority.md`](./machine-authority.md)
and [`ioi-authority-protocol.md`](./ioi-authority-protocol.md).
Supersedes: overlapping product or plan prose when the Web4 stack definition conflicts.
Superseded by: none.
Last alignment pass: 2026-08-30 (Machine Authority category and IOI Authority
Protocol ownership extracted; Web4 retained as the broader system category).
Doctrine status: canonical
Implementation status: mixed (category definition; stack layers span built to speculative)
Last implementation audit: 2026-07-19

## Canonical Definition

**Canonical Web4 is the internet architecture where applications do not merely
let users read, write, or own state; they delegate bounded authority to
autonomous actors that can understand domain meaning, pursue goals, act across
systems, selectively contract across sovereign boundaries when each party
expects net benefit, and produce attributable, challengeable evidence under
verifiable policy and sparse settlement.**

Category definition:

> **Web4 is the system and application category built on Machine Authority:
> bounded autonomous actors use scoped power to perform consequential work with
> attributable evidence, revocation, interop, and optional settlement.**

Short form:

> **Web4 = Read + Write + Own + Act, under machine authority.**

IOI defines the canonical Web4 target as a machine-authority stack and
implements it incrementally according to each owner document's stated status.

Protocol thesis:

> **L0 makes one constitution-bound autonomous system safely distributable
> across governed compute, state, verification, human, and embodied nodes; AIIP
> makes selective, positive-surplus interoperation between separately sovereign
> systems contractible; IOI L1 optionally supplies shared trust and economic
> finality.**

Product thesis:

> **Governed work should be able to become reusable autonomous capability.**

Builder/category thesis:

> **IOI is the open operating stack that turns intelligence into bounded
> autonomous institutions. L0 distributes each institution across its admitted
> members through native L0 and Embodied Runtime coordination; AIIP makes
> selective, positive-surplus interoperation between separately sovereign
> institutions contractible; IOI L1 supplies optional shared trust and economic
> finality.**

Hypervisor is IOI's first-party execution and control environment; no release
is yet designated as the reference implementation under this file's contract.
Locally canonical Domain Ontologies plus optional accepted mappings are the
semantic world plane; the IOI Authority Protocol is the portable Machine
Authority protocol-family target; and Agentgres is the operational truth
substrate.

The ontology-centered operating environment and Hypervisor's deployment,
resource-relationship, and autonomy-capability facets are not competing
product theses. They answer different questions:

```text
local ontology planes with optional federation
  what objects, relationships, events, actions, policies, claims, and goals mean

collective-intelligence plane
  how intelligences discover, divide, attempt, verify, challenge, and course-correct work

Hypervisor autonomy plane
  how agency, context, tools, memory, authority, evidence, and effects are virtualized

controller deployment and resource relationship
  where the controller runs and whether resources are hosted, attached, or node-root
```

Together they form one ontology-native autonomy fabric. The category is not a
decentralized clone of a centralized enterprise ontology vendor, a VM manager
with agents attached, or two loosely related products. Domain Ontologies make
the world legible; the autonomy hypervisor makes action in that world
governable.

L0 is the modular builder and operating substrate for constitution-bound
autonomous institutions rather than chain scaffolding alone. Its category is
constitution-to-effect governance, machine authority, ontology/action
contracts, operational evidence and replay, proposal-mediated improvement with
optional bounded Campaigns, lifecycle continuity, and optional shared trust.
No mandatory hub, consensus algorithm, token, or value-accrual path is implied.

In this framing, an intelligent blockchain is a self-driving bounded actor: a
stateful autonomous-system domain that can sense state, route work, request
authority, execute through governed runtimes, recover from failures, improve
future behavior, and settle what matters without gaining ambient or
unreviewable power.

Web4 is not only about delegation. It is about compounding useful work into
portable workers, workflows, tools, model routes, evals, data recipes,
packages, service modules, and market-listed capabilities without collapsing
execution, authority, truth, and settlement into one vendor-owned layer.

## Provider-Trust Boundary

Canonical Web4 moves machine authority outside provider trust by default.

Providers may supply cognition, compute, storage, connectors, liquidity,
distribution, hosted workspaces, or managed execution. They are useful execution
and service participants. They are not the default authority root, secret owner,
policy owner, receipt truth, settlement root, or revocation plane.

Provider-trust routes are still allowed when a user, organization, policy, or
domain explicitly accepts them. They must be labeled, policy-bound, receipted,
revocable where possible, and distinct from routes where authority, secrets,
plaintext custody, and settlement commitments remain outside provider control.

## Blockchain Substrate and User Abstraction

Web4 is blockchain-native underneath, but it must not be chain-first in ordinary
product experience. In IOI, blockchain is the verifiability, rights, dispute,
governance, and settlement substrate below machine authority; users mostly meet
it as authority grants, receipts, proofs, state roots, revocation controls,
contribution records, and settlement outcomes.

The default user experience should abstract raw chain mechanics behind
machine-authority language. A user should be able to ask what was authorized,
what executed, what proof exists, what can be revoked, and what settled without
having to reason about contracts, gas, chain IDs, custody, transaction hashes, or
bridge details during every task.

The substrate still has to be knowable. Receipts, replay views, settlement
views, dispute views, developer consoles, exportable evidence bundles, and
state-root/proof drilldowns must let technical users, auditors, counterparties,
and autonomous systems inspect the underlying commitments when public trust,
settlement, governance, or dispute resolution depends on them.

## Machine Authority Dependency

Web4 depends on **Machine Authority** as its legible security primitive. The
category definition, completeness bar, role boundary, and claim ladder are
owned by [`machine-authority.md`](./machine-authority.md); this file does not
redefine them.

Within Web4, a non-human actor, worker, runtime, workflow, service, or autonomous
system receives limited power from a human, organization, domain, or contract
and uses that power across real systems. The power remains bounded by identity,
scope, policy, purpose, time, budget, data permission, approval requirements,
revocation, exact-effect admission, receipts, and replay.

The category is not won by calling every agent a wallet or every application a
chain. It is won by making the machine-authority path portable and unavoidable:

```text
intent
  -> authority request
  -> scoped lease / denial / step-up
  -> runtime assignment
  -> policy and admission
  -> autonomous execution
  -> receipts and replay
  -> Agentgres state root or projection
  -> AIIP handoff or settlement intent
  -> optional sparse IOI L1 commitment when explicit enrollment and the
     selected settlement profile require shared public trust
```

This is the security substrate for autonomous work. It is source-neutral: any
model, runtime, connector, worker, marketplace, enterprise domain, or sovereign
application can participate if it satisfies the applicable authority, receipt,
interop, and settlement profiles.

The category claim is not that every Web4 product should become an IOI-hosted
L1. The claim is that the IOI L0/kernel, Hypervisor, SDK, ADK, AIIP,
wallet.network, Agentgres, and IOI L1 together make it practical to create
autonomous-system domains that can remain sovereign at the edge while becoming
interoperable, attributable, and economically legible through shared authority,
receipt, reputation, and settlement semantics.

The resulting layer relationship is:

```text
Machine Authority                         category and completeness boundary
  -> IOI Authority Protocol               portable external protocol family
     -> wallet.network + Hypervisor        first-party authority/PEP path
     -> Agentgres                          first-party admitted truth and replay
  + edge-in domain kernels
  + locally canonical semantic object/action contracts and optional mappings
  + Goal Kernel bounded pursue/verify/course-correct loops
  + optional ImprovementCampaign and OutcomeRoom lifecycles
  + AIIP work interop
  + optional IOI L1 sparse settlement
  = IOI's canonical Web4 operating fabric
```

### The Adoption Calculus

Category ownership is an architectural property, not a positioning one. IOI
owns this category only if a capable outsider's rational move is **adopt**
rather than fork or ignore. That calculus rests on five properties. Each is
audited here against its owning contract, because a property with no contract
is a hope; where the contract is missing, the gap is recorded rather than
papered over.

| Property | Owning contract today | Honest state |
| --- | --- | --- |
| Open protocol surface | the currently licensed source pool in [`../../../LICENSE-MANIFEST.json`](../../../LICENSE-MANIFEST.json) `open_protocol_surface` under [ADR 0033](../../decisions/0033-licensing-split-surface-and-license-manifest.md), plus the future exact profile manifest owned by [`ioi-authority-protocol.md`](./ioi-authority-protocol.md) | legal inspectability is enumerated and permissively licensed, subject to the ADR's counsel caveat; exact IAP profile closure, offline verifier, and independent implementability are not yet established |
| Reference implementation | § The Reference-Implementation Contract below — five designation conditions, the parity claim (fixture, refusal, surface completeness, independence disclosure), and the rule that a designated release cannot legislate | contracted, planned; no release is designated and no parity claim exists |
| Conformance certification | the profile and entitlement contract in [`ioi-authority-protocol.md`](./ioi-authority-protocol.md), plus `ConformanceProfile` / `CertificationClaim` / `EcosystemAssuranceProfile` in [`ecosystem-assurance-certification-liability.md`](./ecosystem-assurance-certification-liability.md) | target profiles are defined but unreleased; no frozen public surface manifest, outsider-runnable artifact, computed parity membership, or issuer-accreditation/separation rule exists |
| Credible neutrality | [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md) for routing/marketplace; [`protocol-governance-neutrality.md`](./protocol-governance-neutrality.md) for IOI as spec owner and network operator | both owned; the governance contract is written and its change process, objection record, and designation record are unimplemented |
| Portable exit | enrollment exit transitions ([`objects/bounded-system-genesis.md`](./objects/bounded-system-genesis.md)), `ParticipantStateBundle`, portable memory vault, SLC attach/detach cases, and attach-lane adapter portability ([`daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)) | best-covered; every lane is contracted, none is evaluator-proven |

The target rational move is adopt, stated so a hostile reader can attack it:
compatibility remains free and untaxed (`ioi_compatible` owes no fee, token, or
enrollment); a released profile makes its exact claims verifiable offline; exit
is typed, so adoption is not a one-way door; and a fork should buy nothing that
compatibility does not already provide while losing shared interoperability.
Today the schemas and focused verifier paths are inspectable, but no frozen IAP
manifest, public profile runner, portable outer-signature closure, or
independent parity makes that full argument true. It has two open flanks:

1. **The license question is architecturally resolved and legally unreviewed.**
   [ADR 0033](../../decisions/0033-licensing-split-surface-and-license-manifest.md)
   splits the surface: the protocol surface — registered contracts, schemas,
   invariants, fixtures, both generated projections, and the client-facing
   protocol type libraries — is Apache-2.0 **now**;
   specification and decision prose is CC BY 4.0 **now**; the reference
   implementation stays under `LICENSE-BBSL` until the 2029-11-06 Change Date;
   marks and certification are separate. `LICENSE-MANIFEST.json` defines the
   Licensed Work per path, and the grant is now perpetual and irrevocable except
   on the licensee's own breach. So the load-bearing input — may a third party
   legally implement and operate L0 — is answered yes for the open surface.
   **The remaining flank is that ADR 0033 has not been reviewed by external
   counsel**, and it says so itself; no public release should rely on it until
   that review happens.
2. **The authority profiles are not yet runnable by an outsider.** What a
   passing implementation may and may not claim is defined in
   [`ioi-authority-protocol.md`](./ioi-authority-protocol.md), but no profile has
   a frozen `ProtocolSurfaceManifest`, public clone-and-run verifier, complete
   published fixture bundle, or computed parity membership. The retired
   `docs/conformance/` document tree is not recreated; the runnable artifact
   must ship with the public protocol surface and remain usable without private
   program state. Adopters cannot self-certify today.

Neither flank is closed by wording. The licensing flank closes only through the
manifest plus counsel review. The runnability flank closes only through a
frozen profile manifest, public vectors and verifier, served path, independent
parity, operational governance, and the applicable complete-system proof.

## Web Evolution

```text
Web1: Read
Web2: Write
Web3: Own
Web4: Act
```

A Web4 application has autonomous execution as a first-class ability. It can run workers, workflows, tools, connectors, model calls, and service deliveries, while preserving authority boundaries and verifiable state.

Web4 does not make the model the economic actor. In IOI, the protocol actor is
the **Worker**: a bounded executable actor with manifest, policy envelope,
capability surface, receipt obligations, and settlement identity. Models are
cognition backends mounted by workers. Agents are product-facing or colloquial
UX language.

Models are deployment-profile resources, not architecture-default node
binaries. A Hypervisor Node includes model routing and invocation boundaries;
local weights, local servers, BYOK providers, hosted pools, TEE/DePIN sessions,
or customer VPC endpoints are mounted by policy and deployment profile.

## IOI First-Party Stack

```text
IOI Kernel / L0 Substrate
  reusable domain, runtime, policy, receipt, and state-machine primitives

IOI L1
  optional IOI Network registry, shared security, rights, settlement,
  governance, and recognized-release commitments for enrolled systems

wallet.network
  identity, secrets, authority grants, approvals, payments, revocation

Agentgres Domains
  application/domain state, runs, orders, receipts, projections, quality, contribution accounting

Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts, and upgrade paths

Hypervisor Nodes
  local autonomous-system orchestration, interop, authority, state, replay, routing, and settlement domains

AIIP
  RPC-shaped, receipt-native interop for bounded autonomous work, handoffs, authority, receipts, settlement intents, disputes, and reputation queries

Domain Ontologies and Data Recipes
  locally canonical semantic world planes for versioned objects, relationships,
  events, claims, actions, policy-bound views, connector mappings, evals, and
  projections; explicit mappings enable optional federation after accepted terms

Goal Kernel / GoalRun
  bounded grounding, pursuit, verification, repair, course-correction, and continuation loop for one participant or subteam

OutcomeRoom / Collaborative Work Graph
  shared objective, frontier, participant leases, work claims, attempts, findings, resources, verifier challenges, contribution lineage, admission, and replay across many GoalRuns

Hypervisor Daemon / Runtime Nodes
  execution and admission runtime for workflows, workers, tools, models, connectors, artifacts, and semantic actions

Mixture of Workers
  labor routing across bounded workers by policy, benchmarks, receipts, cost, trust, and contribution quality

Client Surfaces
  Hypervisor App, Hypervisor Web, CLI/headless, optional TUI, SDK, ADK,
  browser apps, harness profiles, benchmarks

Hypervisor Core Workspaces
  Home, Systems, Projects, Applications, Work
  policy-filtered product context and projections; never new truth stores

Shell-Placed Owner Application
  Automations
  one owner-application registration with a permanent launch placement

Hypervisor Application Surfaces
  Studio, Automations, Ontology, Data, Governance, Provenance, Evaluations,
  Improvement, Foundry, Packages with optional Marketplace mode, Developer
  Workspace, Developer Console, plus the Environments and Operations substrate
  lane, generated and installed System interfaces,
  and the conditional Embodied Systems `owner_application` planned registration (contextual and
  nonlaunchable until its route and implementation are built)

Storage Backends
  immutable package, artifact, evidence, receipt, checkpoint, snapshot, sealed archive byte availability

aiagent.xyz
  first-party worker marketplace using AIIP, local product accounting, and
  explicitly selected settlement services

sas.xyz
  first-party service/outcome marketplace using AIIP, local contracting truth,
  and explicitly selected settlement services

ioi.ai
  first-party intent-to-outcome conductor and Goal Space product over Hypervisor;
  owns account/subscription experience and goal coordination, not runtime,
  authority, Agentgres truth, marketplaces, or settlement
```

## The Reference-Implementation Contract

"Reference" was used per-subject — the reference Hypervisor, the reference
OutcomeRoom, the reference Default Harness Profile — with no contract for what
makes a *release* the reference implementation, and no way for a third party to
prove parity with it. That is a load-bearing hole in the adoption calculus: a
would-be adopter cannot evaluate compatibility against a moving, undefined
target, and a spec whose only complete statement is one vendor's running code is
not a spec.

### What makes a release the reference implementation

A release is **the reference implementation of a named protocol surface** for
the period it is designated, if and only if all five hold:

1. **Named surface, versioned.** It designates the exact protocol surface it
   implements — the registered contract ids and versions from
   [`../_meta/schemas/architecture-contract-registry.v1.json`](../_meta/schemas/architecture-contract-registry.v1.json),
   plus the canonical owner docs that define behavior the registry cannot carry.
   "The reference implementation of IOI" is not a designation; "the reference
   implementation of protocol surface *S* at version *v*" is.
2. **Complete over that surface.** Every contract in the named surface is
   implemented, or is explicitly declared unimplemented in the release's own
   manifest. A silent omission disqualifies the designation; a declared one
   narrows the surface.
3. **Specification-sufficient.** The named surface is documented well enough
   that an independent implementation can be built from the specification alone.
   The operational test is `separate_codegen` + `separate_transport` per
   [ADR 0032](../../decisions/0032-independently-implemented-client-definition.md):
   if building against the surface required reading this implementation's source
   rather than its specification, the surface is under-specified and the release
   is not a reference for it.
4. **Behaviorally pinned.** The release publishes the fixture set and expected
   outcomes that define correct behavior over the surface — including the
   negative cases, which are where implementations actually diverge. A reference
   that pins only its happy paths has specified nothing contested.
5. **Designated, dated, and superseded explicitly.** Exactly one release holds
   the designation for a given surface at a time, with a start date and a named
   successor when it ends. A designation that quietly transfers is not a
   designation.

### How a third party proves parity

Parity is a claim **against a named surface at a named version**, never against
"IOI" in general. A third-party implementation claims parity by showing:

- **Fixture parity** — it produces the reference's published expected outcomes
  over the pinned fixture set, including every negative case. Negative parity is
  the load-bearing half: agreeing about what to accept is easy, and agreeing
  about what to refuse is what makes two implementations interchangeable.
- **Refusal parity** — where the reference refuses, it refuses, with the
  same typed reason. An implementation that accepts what the reference refuses
  is more permissive, not more compatible, and this is the difference between an
  interoperable implementation and a security hole with a compatibility badge.
- **Surface completeness** — its own manifest of implemented and declared-
  unimplemented contracts over the named surface, so partial parity is
  expressible rather than being forced to overstate.
- **Independence disclosure** — which axes of ADR 0032 its implementation
  asserts, so a reader can tell whether parity demonstrates that the
  specification is sufficient or only that the code was reused.

**What parity does not confer.** Parity is a statement about behavior over a
surface. It is not certification, not a trademark or marks licence, not
membership, not network enrollment, and not permission to describe an
implementation as endorsed. Certification and its issuer rules stay with
[`ecosystem-assurance-certification-liability.md`](./ecosystem-assurance-certification-liability.md);
marks and naming stay with their own licence, per the licensing ADR. This
separation is deliberate: a category whose reference implementation is also the
certifier and the marks holder cannot credibly claim neutrality, which is why
[`protocol-governance-neutrality.md`](./protocol-governance-neutrality.md) holds
the third of those three roles apart from the other two.

**What the reference implementation does not get.** Being the reference confers
no protocol authority. It cannot define behavior by shipping it: a divergence
between a designated release and its named surface is a **defect in the
release** until the surface is amended through the change process, never an
implicit amendment to the surface. This is the single rule that keeps "reference
implementation" from meaning "whatever we do is the spec".

## Canonical Web4 Requirements

A canonical Web4 application should have:

1. **Identity-bound actors** — users, agents, workers, publishers, providers, and runtimes have stable identity.
2. **Scope-bound authority** — autonomous actors receive bounded powers, not ambient authority.
3. **Policy-bounded execution** — consequential actions pass through explicit policy and approval paths.
4. **Autonomous runtime** — workers and workflows can act over time, not only answer prompts.
5. **Verifiable state changes** — important state transitions bind to receipts, evidence, roots, or commitments.
6. **Revocation and emergency stop** — granted authority can be withdrawn.
7. **Portable manifests** — workers, services, workflows, models, apps, and domains are described by signed manifests.
8. **Settlement-aware outcomes** — economic delivery and reputation are backed by contracts, escrows, bonds, roots, or receipts.
9. **Self-driving bounded behavior** — the domain can monitor state, route work, recover, and continue under explicit authority, policy, budget, safety, and proof envelopes.
10. **Bounded recursive improvement** — a one-shot change may move directly to
    an evaluated `UpgradeProposal`; adaptive or multi-epoch work uses an optional
    `ImprovementCampaign` with frozen judgment, cumulative exposure, finite
    inherited bounds, learning eligibility, target-owner promotion, and typed
    effect recovery. Improvement evidence never self-promotes.
11. **Standalone local completeness, zero-to-idle, and managed optionality** —
    the target contract requires a compatible IOI deployment, within its
    declared standalone capability, durability, custody, and assurance
    envelope, to bootstrap
    deployment-local identity and locally permitted authority, create and
    govern a bounded System, execute local or BYO work, preserve and replay
    Agentgres truth, and back up, restore, export, and verify evidence without
    an `ioi.ai` account, IOI-managed runtime, marketplace participation, IOI
    Network enrollment, IOI L1, or an always-on IOI connection. A selected
    workload may still declare external dependencies; unavailable managed or
    cooperative capabilities remain typed unavailable rather than being
    simulated as local parity. Managed services add explicitly selected
    capabilities instead of completing a crippled core. Clients and runtimes
    continue serving from local, static, or projection state where possible,
    waking authority and active runtime only when the requested operation
    requires them. This is a conformance requirement, not a claim that the
    current product has passed the end-to-end profile.
12. **Marketplace neutrality** — default runtime/harness infrastructure does not silently absorb third-party intelligence.
13. **Worker routing over model centrality** — MoW selects accountable workers,
    not merely model providers.
14. **Trainable supply** — workflows, examples, corrections, data, and gates can
    become trained workers without collapsing IOI into a training-only platform.
15. **Local autonomous-system settlement** — Hypervisor Nodes settle autonomous
    work locally; explicitly enrolled systems may anchor selected roots to IOI
    L1 when a chosen shared-trust or economic service requires it.
16. **Work interop** — AIIP moves delegated work, authority leases, receipts,
    settlement intents, disputes, reputation queries, and handoffs between
    bounded execution domains.
17. **IOI Authority Protocol profile compliance** — authority requests,
    decisions, leases, denials, step-up challenges, delegation, revocation,
    exact-effect admission, proof obligations, and applicable settlement intents
    use a named portable profile rather than product-local permission checks.
18. **Local-first semantic contracts** — ontologies are locally canonical,
    namespaced, versioned, mappable, and policy-bound; executable actions bind
    semantic meaning to capability, authority, effects, compensation, evidence,
    and verification.
19. **Conditional cooperation** — a sovereign system is complete locally.
    Federation, external contribution, marketplace participation, and shared
    trust appear only when every required party accepts one exact terms root
    and its governed decision finds expected utility under those terms minus
    the utility of its best permitted outside option and incremental
    cooperation costs to be positive. Attribution does not create allocation
    or payout.
20. **Bounded collaborative pursuit** — the reusable OutcomeRoom package
    instantiates each persistent room through genesis as a bounded DAS over one
    or more GoalRuns, with participant leases, claimable
    frontier items, durable positive and negative attempts, findings, resources,
    verifier challenges, contribution lineage, and declared admission. Its
    mutations use the resulting System's Agentgres-backed operation and receipt
    chain; the room package owns no parallel admission, sequence, state-root, or
    receipt-root spine.
21. **Sovereign room truth** — every collaborative room declares hosted or
    federated admission, while each domain retains local operational truth and
    private context.
22. **Complexity collapse** — direct local work remains first-class; room,
    ontology breadth, marketplace, federation, and L1 machinery appear only
    where the actual work boundary needs them. Shared-graph compare-and-swap is
    expressed through Agentgres expected heads and the enclosing System's
    predecessor condition rather than a room-specific concurrency primitive.
23. **Constitutional and lifecycle bounds** — purpose, prohibitions, authority
    and effect ceilings, protected amendment, oracle/evidence, succession,
    migration, dissolution, and decommission exist before durable autonomy.
    Package release is reusable build lifecycle; genesis alone creates a live
    system and live lifecycle.
24. **One system across admitted nodes** — logical identity survives node churn;
    node joins, roles, catch-up, roots, declared recovery, and degraded state are
    governed and observable. Writer epochs/fencing apply only to single-writer
    restore or promotion; other profiles use their native recovery proofs.
25. **Consensus neutrality** — no-consensus/PoA-1, replicated authority,
    threshold authority, BFT consensus, and external finality are declared
    profiles; none is hidden in node count.
26. **Explicit network enrollment** — compatible, connected, and secured
    systems make L1 dependency, service, assurance, fee, and bond boundaries
    explicit.

## The Deterministic Admission Kernel Contract

Canonical Web4 requirement 5 says important state transitions bind to receipts,
evidence, roots, or commitments. That sentence names an outcome without naming
the machine that produces it, which lets any store claim it by asserting the
words. This section states the machine: the **minimum behavioral contract** a
component must satisfy to be a Web4 deterministic admission kernel — equivalently,
a conforming operational-state substrate for a Web4 domain.

The contract is **source-neutral by construction**. It names no vendor, engine,
storage format, hash, signature suite, tree shape, or wire protocol. Any
implementation satisfying every clause conforms; no implementation conforms by
being ours. This is the same discipline the reference-implementation contract
above applies to releases, applied one layer down to the substrate itself.

**C1 — Deterministic transitions.** Admission is a pure function of declared
inputs and the exact prior state. The same inputs against the same prior state
produce the same next state, the same commitments, and the same accept/refuse
decision on every conforming implementation, on every host, at every replay.

**C2 — Authenticated, fully declared inputs.** Every input the transition
function reads is present in the operation and authenticated to a principal the
kernel resolved. An input the kernel cannot authenticate is not an input; an
input the operation does not declare cannot be read.

**C3 — No ambient clock, randomness, authority, or mutable truth.** Inside
admission there is no wall-clock read, no entropy source, no thread-scheduling
dependence, no ambient permission, and no mutable row that admission trusts as
truth. Time, randomness, and authority decisions enter only as recorded,
authenticated operation inputs, subject to `INV-1`, `INV-37`, and `INV-39`. A
kernel that reads the clock during admission cannot satisfy C1 and does not
conform.

**C4 — Exact heads or versions.** Every state-changing operation names the
exact predecessor it expects — an object head, a sequence, or a state version.
Admission compares and swaps against it. "Latest" is not an expectation, and a
transition that would apply against an unexamined head is refused, not merged.

**C5 — Operation-backed state and typed receipts.** State is the fold of
accepted operations, never a directly mutated store. Every consequential
crossing mints a typed receipt bound to the boundary facts it actually
establishes, individually verifiable, and never collapsed into a batch summary
that hides which operation did what (`INV-9`).

**C6 — State and receipt commitments.** Each admitted unit publishes a state
commitment and a receipt commitment over exactly the operations it admitted,
plus the commitment of the unit it follows. Commitment construction may be
batched and incremental; what it commits to may not be approximate.

**C7 — Atomic durability and ACK.** The acknowledgement boundary is atomic and
never precedes durability. No ACK may be returned before the append, state
commitment, individual receipts, and the durable linearization point required
by the declared durability class have all been reached, and recovery admits an
entire unit or none of it. A partial unit is not a small success.

**C8 — Deterministic replay and recovery.** From the operation history alone, a
conforming implementation reconstructs the identical state, commitments, and
receipt set, and a crash at any point resolves to a state the history explains.
Recovery replay does not repeat external effects, spend authority again, or
mint replacement receipts; it reproduces the already admitted history and its
receipts byte-for-byte. A **new execution** proposed from replayed evidence is a
new crossing: it revalidates fresh authority under C11 and mints new receipts,
never re-spending an old grant or reusing an old receipt as proof of that new
crossing.

**C9 — Fail-closed external payload availability.** External payload bytes are
content-addressed and referenced, never inlined as truth. Content addressing
proves integrity and identity; it proves neither availability nor authority. A
missing, unfetchable, or mismatched payload fails closed by a named reason and
never degrades to a weaker admitted result (`INV-12`).

**C10 — Rebuildable projections.** Every query surface, index, view, SQL
bridge, cache, and UI read model is derived and disposable: it can be dropped
and rebuilt from admitted operations, and it carries a freshness watermark. A
projection that cannot be rebuilt has become truth by accident, which is a
defect, not a schema.

**C11 — Current authority and revocation revalidated at the boundary.**
Authority captured when work was staged is evidence of what was held then.
Admission revalidates the *current* grant, expiry, revocation epoch, and policy
against the exact effect immediately before it materializes, and the receipt
binds the revocation epoch it checked. Stale or revoked authority forces
re-authorization; it never rides through on a staged decision.

**C12 — Conformance and adversarial verifiers.** Conformance is claimed only
against executable verifiers that include the negative cases: stale, missing,
forged, reordered, replayed, truncated, and conflicting operation, receipt,
payload, commitment, and authority evidence, plus crash injection at each
boundary in C7. A verifier that cannot fail on its own subject proves nothing,
and a conformance claim with only happy paths has specified nothing contested.

### Agentgres is the first-party conforming implementation

**Agentgres is IOI's first-party canonical conforming implementation of this
contract and the current runtime owner of admitted operational truth**
([ADR 0003](../../decisions/0003-agentgres-operation-backed-domain-truth.md);
[`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md)).
Those are two distinct claims and both matter: *conforming* is a behavioral
statement about C1–C12, and *current runtime owner* is a statement about which
component actually admits truth in this estate today.

Three consequences follow, and they are the point of separating the contract
from the implementation:

1. **The contract outranks the implementation.** A divergence between Agentgres
   and C1–C12 is a defect in Agentgres until the contract is amended through
   the change process — never an implicit amendment to the contract. Shipping
   behavior does not legislate it.
2. **Parity is over the same contracts.** A second implementation may claim
   parity only against C1–C12 and the registered contracts they bind, with
   fixture parity, refusal parity, surface completeness, and independence
   disclosure as defined in § The Reference-Implementation Contract. Parity is
   a behavioral claim; it confers no authority.
3. **Parity may not create dual truth, and may not silently replace Agentgres.**
   A conforming second implementation does not thereby become a second
   admission spine beside Agentgres for the same domain. Two components
   admitting truth for one domain is split brain, not redundancy. Replacing the
   runtime owner is a governed cutover with an unambiguous transition and no
   dual-authority interval — never a deployment default, a configuration flag,
   or an inference from a passing parity run.

Nothing here makes the contract Agentgres-shaped. Agentgres-specific product
language, engine mechanics, Postgres-bridge positioning, and implementation
prose stay Agentgres-specific and stay in the Agentgres owner docs.

Implementation status: the contract is a **target conformance statement**. It is
not a claim that a current implementation has passed all twelve clauses under
executable adversarial verifiers; C12 in particular is where that claim would
have to be earned. [ADR 0039](../../decisions/0039-propose-finality-profiles-over-agentgres-verifiable-batch-log.md)
proposes — and does not accept — how ordering and finality obligations vary
over one spine satisfying this contract.

## The Institution Boundary

"Institution" is load-bearing in the theses above, so it needs a boundary rather
than a mood. The unit of governance vocabulary is owned by
[`term-boundaries.md`](./term-boundaries.md); this is its Web4-stack statement.

**An institution is an independently governed bounded System or domain**: one
stable `system_id` with its own constitution, membership, ordering/admission/
finality profile, authority root, operational truth, lifecycle, and credible
exit. Independent governance is the whole test — the institution boundary is
exactly where authority, truth, risk, and exit stop being someone else's.

None of the following is an institution, no matter how autonomous it looks:

```text
a model call            cognition, not a governed party
a subagent / thread fork  a delegation surface inside one system (ADR 0034)
a GoalRun               one bounded pursue/verify/course-correct loop
a participant           a leased role inside a room, not a governing body
an Attempt              durable evidence of tried work
an OutcomeRoom          a composition over GoalRuns and domains (ADR 0030)
a HarnessInvocation     one scoped step resolution
```

Each of those is a *unit of work, delegation, or evidence inside* an
institution. Promoting one to institution status would let it claim its own
authority root, its own truth, and its own exit — which is precisely the
ambient-authority failure `INV-1` and the one-spine rule exist to prevent.

Two boundaries follow directly. Coordination among admitted members of one
`system_id` is native L0 and never AIIP; AIIP begins only when work crosses
between independently governed institutions (`INV-32`). And multiplicity inside
one institution — several models, workers, nodes, providers, or keys under one
principal — is one party, not many (`INV-18`).

An `OutcomeRoom` is the instructive case. A persistent room is instantiated
*through genesis as a bounded System*, and it is that resulting System — not the
room package, not the collaborative work graph, not any participant in it —
that is the institution.

### Ownership inside the institution

Source-neutral admission does not flatten the owners above it. The following
ownership laws remain exact:

- **GoalRun** owns application state, executable plans, contexts, and invocation
  references.
- **Sessions, launches, threads, HarnessInvocations, and child owners** retain
  their kernel truth; a parent reference is not ownership.
- **wallet.network** owns authority, secrets, grants, approvals, payments,
  revocation, and consumable authority evidence.
- The **deterministic admission substrate** owns admitted domain-operational
  truth, object heads, operation history, state and receipt commitments,
  receipt metadata, replay, recovery, and rebuildable projections. Agentgres is
  the current IOI runtime owner of that role.
- **IOI L1** remains optional public registry, rights, settlement, dispute,
  governance, and commitment finality. It is never the local admission kernel.
- No application object may mint a parallel admission, receipt, state-root, or
  authority spine. It may retain references to evidence issued by the owner;
  it may not become that owner by copying the evidence.

## IOI System Boundary

IOI is not one monolithic chain and not one monolithic application. It is a layered architecture:

```text
IOI Kernel / L0 Substrate = reusable kernel/toolchain for domains and chains
IOI L1                    = public coordination, settlement, governance, release commitments
Application Domains       = per-app kernel + Agentgres state substrate
Governed AS Chains        = local autonomous-system state machines with modules, proposals, receipts
Hypervisor Nodes           = local operational-finality and interop domains for many governed AS chains
AIIP                      = semantic work interop between distinct independently governed systems; same-system handoffs remain native L0
Semantic Data Plane       = ontologies, object models, recipes, mappings, policy-bound views
Collective Pursuit Plane  = OutcomeRooms, collaborative work graphs, GoalRuns, claims, attempts, findings, verification, contribution lineage
Execution Nodes           = local/hosted/DePIN/TEE/customer runtime nodes
Portable Authority Plane  = wallet.network
Artifact-Ref Plane        = Agentgres artifact refs
Storage Backends          = local disk, S3/object stores, Filecoin, CAS/IPFS, provider blobs
Core Workspaces            = Home, Systems, Projects, Applications, Work
Shell-Placed Owner App      = Automations
Application Surfaces      = Studio, Automations, Ontology, Data, Governance, Provenance, Evaluations, Improvement, Foundry, Packages with optional Marketplace mode, Developer Workspace, Developer Console; substrate lane: Environments, Operations; generated and installed System interfaces; conditional Embodied Systems `owner_application` planned registration (contextual and nonlaunchable until built)
Developer/Operator Clients = Hypervisor App, Hypervisor Web, IOI CLI/headless, optional TUI, @ioi/agent-sdk, IOI ADK, harness profiles
MoW Routing               = worker selection, sparse categories, contribution policy, benchmark eligibility
```

Storage/state split:

```text
Agentgres = state machine, query substrate, and artifact-ref meaning/admission/validity plane
Domain Ontologies/Data Recipes = locally canonical semantic meaning, governed transformations, mappings, and projections
Storage backends = payload bytes, evidence bytes, and sealed archive bytes
IOI L1 = trust, registry, rights, settlement, and sparse commitments
Hypervisor Node = local orchestration, interop, domain-policy enforcement, receipts, replay, and settlement coordination
AIIP = work interop protocol across bounded execution domains
GoalRun = one bounded intelligence or subteam's pursue/verify/course-correct loop
OutcomeRoom = shared frontier and admission profile over many GoalRuns and domains
Hypervisor Daemon runtime nodes = execution layer
MoW = labor routing layer for bounded workers
Hypervisor App/Web/CLI-headless/SDK/ADK = clients and builder frameworks over runtime/domain contracts
Workflow Compositor = shared directed-work builder substrate
TUI = optional CLI presentation over the same runtime/domain contracts
Developer Workspace/Foundry = application surfaces over Hypervisor Core and daemon/domain contracts
Applications Catalog / Open Application = first-party surface discovery, launch, and one active surface slot
Environments = runtime substrate, provider placement, environment lifecycle, services, tasks, ports, restore, readiness, and contextual views over sessions/providers/environments
```

## Edge-In Topology

IOI intentionally inverts traditional blockchain topology.

Chain-first topology usually starts from the global ledger:

```text
global chain
  -> application contracts
  -> hosted app/backend
  -> user/client edge
```

IOI starts at the edge where work actually happens:

```text
local or remote runtime edge
  -> domain kernel + Agentgres operational truth
  -> Domain Ontologies and Data Recipes for locally canonical semantic meaning
  -> GoalRun for bounded local work
  -> optional OutcomeRoom only when collective machinery creates positive participant-level surplus
  -> optional AIIP handoff only after exact-root terms acceptance and admitted leases
  -> otherwise remain local
  -> receipts, evidence, verification, artifacts, state roots, and contribution records
  -> optional sparse IOI L1 commitments when explicit enrollment selects shared trust
```

This keeps autonomous work local-first, zero-to-idle, and domain-specific while
allowing consequential commitments to opt into a neutral settlement,
shared-security, or governance root.

The Web4 domain flywheel has three non-equivalent effects:

```text
compatible adoption
  improves L0 tooling, interoperability reach, and potential product demand

connected enrollment
  improves registry coverage, rights/reputation portability, and market liquidity

secured service consumption
  creates actual shared-security fees, bonded risk, and possible L1 demand
```

Each new domain, worker market, service market, enterprise kernel, robot fleet,
or independent AS-L1 can increase ecosystem value without forcing operational
state into one global runtime. Only explicit service consumption creates the
corresponding L1 economics.

Agentgres state is not Filecoin blobs. Agentgres records canonical operations,
object heads, indexes, projections, subscriptions, delivery state, receipts
metadata, artifact refs, archive refs, and restore validity. Storage backends
such as Filecoin/CAS store the bulky immutable payloads those refs point to.

Raw source data is not domain truth by itself. Domain Ontologies define what the
work means locally and how versions map across domains; Data Recipes and their
receipts make the transformation from documents, traces, connector payloads,
and examples into ontology-bound training, evaluation, runtime, and projection
data attributable and inspectable.

## What Web4 Apps Are Not

A canonical Web4 app is not merely:

- a website with an LLM chat box;
- a smart contract with a frontend;
- a model endpoint;
- a fine-tuning dashboard;
- a generic AI worker catalog without receipts, benchmarks, and routing semantics;
- a DePIN compute node;
- a workflow graph without authority or receipts;
- a marketplace listing without execution and delivery semantics.
- one global enterprise ontology that erases local domain meaning;
- a message board, agent swarm, or leaderboard without typed work, admission,
  authority, evidence, and replay;
- a public blockchain transaction for every model call, tool call, GoalRun,
  receipt, or local state change.

A canonical Web4 app is a stateful, authority-aware, autonomous application domain.

## Category Examples

| App | Canonical Web4 Role |
|---|---|
| Hypervisor Core | Shared product/runtime substrate for governed autonomous work; the Hypervisor Daemon owns execution inside it. |
| Hypervisor App | Native desktop client over Hypervisor Core. |
| Hypervisor Web | Browser/team/remote client over Hypervisor Core. |
| Hypervisor Developer Workspace | Code/systems/workspace application surface over Hypervisor Core, with editors and terminals as adapter targets. |
| Hypervisor Node | Local operational-finality, interop, policy enforcement, state, replay, and routing domain for governed autonomous systems; authority still comes from the applicable authority provider and governance path. |
| AIIP | RPC-shaped, receipt-native protocol for voluntarily accepted, terms-bound autonomous work across bounded execution domains. |
| CollaborationTerms | Exact versioned bargain for cross-party scope, roles, rights, obligations, disclosure, contribution/reward basis, risk, exit, and settlement; acceptance enables later admission but grants no authority, award, or payout. |
| GoalRunProfile / GoalRun / Goal Kernel | Immutable reusable convergence definition / durable admitted pursuit / bounded grounding, planning, verification, repair, course-correction, and continuation interpreter for one participant or subteam. |
| ImprovementGovernanceProfile / ImprovementAgenda / ImprovementCampaign | Immutable owner-scoped Campaign admission policy / non-executable investigation portfolio / optional multi-epoch candidate, evaluation-exposure, cutoff, and target-owner proposal-lineage lifecycle. None executes work or owns release authority. |
| OutcomeRoom / Collaborative Work Graph | Conditional shared objective, terms roots, frontier, participant/claim leases, attempts, findings, resources, verifier challenges, contribution lineage, admission, and replay across GoalRuns and sovereign domains when expected cooperation surplus justifies it. |
| Bounded Execution Domain | Any local-runtime, hosted, enterprise, marketplace, robot, worker, service, or AS-L1 domain that performs scoped autonomous work under policy and receipts. A GoalRunProfile or HarnessProfile is not itself a domain. |
| Governed Autonomous-System Chain | Logically scoped stateful execution object, possibly spanning several admitted nodes, with policy, modules, proposals, receipts, and governed upgrades. |
| IOI CLI/headless | Local operator, scripting, CI, and node-ops client for daemon, domain, authority, receipt, and settlement workflows; TUI is an optional presentation. |
| IOI SDK | Low-level protocol/client library over daemon, Agentgres, wallet.network, AIIP, and IOI L1 contracts. |
| IOI ADK | Autonomous development kit for building workers, service modules, harnesses, evals, manifests, receipts, deployment profiles, and governed autonomous systems. |
| IOI ODK | Ontology development kit for building ontology-aware surfaces, domain apps, data recipes, connector mappings, eval packs, worker/package skeletons, and marketplace-ready ontology packs over semantic data-plane contracts. |
| Hypervisor Daemon | Portable runtime endpoint for local, hosted, provider, DePIN, TEE, and customer execution. |
| IOI Kernel / L0 Substrate | Reusable substrate for creating application domains, sovereign domains, and intelligent or non-intelligent chains/state machines. |
| MoW | Labor-routing layer for bounded workers, sparse categories, routing receipts, and contribution accounting. |
| Domain Ontologies and Data Recipes | Semantic data plane for ontology-bound training, evaluation, connector mapping, generated surfaces, domain apps, and Agentgres projections. |
| Hypervisor Foundry | Product surface for building models, workers, evaluator assets, datasets, and simulation artifacts; running admitted experiments; and packaging candidate promotion bundles. Evaluations owns judgment and Governance owns deployment. |
| aiagent.xyz | First-party marketplace for portable Web4 workers, benchmarks, sparse categories, installs, managed instances, and routing eligibility, built on AIIP, local product accounting, and explicitly selected settlement services. |
| sas.xyz | First-party marketplace for Web4 service outcomes, including Worker Training contracts, built on AIIP, local contracting truth, and explicitly selected settlement services. |
| ioi.ai | First-party intent-to-outcome conductor and Goal Space subscription product over ordinary Hypervisor, authority, Agentgres, marketplace, and AIIP contracts. |
| wallet.network | Authority vault and scope control plane. |
| Agentgres | State/change/provenance substrate for Web4 application domains. |
| IOI L1 | Optional IOI Network registry, shared-security, rights, dispute, governance, and economic-finality layer for connected or secured systems. |
| IOI Authority Protocol | Portable action-authorization, delegated-authority, and governed-effect profiles implementing the Machine Authority completeness contract without requiring the complete IOI stack. |

## Core Doctrine

> **IOI does not define a proprietary Web4. IOI implements canonical Web4:
> an open, edge-sovereign operating fabric for governed autonomous systems,
> combining locally canonical and selectively interoperable semantic meaning,
> bounded machine authority, attributable
> evidence, collaborative intelligence, sovereign operational truth, work
> interop, and sparse settlement.**
