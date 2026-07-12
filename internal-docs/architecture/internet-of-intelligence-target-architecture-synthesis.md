# Internet of Intelligence Target Architecture

Status: promotion-complete synthesis; non-canonical rationale and pressure-test
source. Its target state was distributed into canonical owners under
`docs/architecture/` on 2026-07-11. Canonical owner docs and accepted ADRs win
if this synthesis later drifts.

Date: 2026-07-11.

Purpose: pressure-test the relationship between Hypervisor Type 1/2/3, the
ontology-centered operating environment, the Goal Kernel, open multi-agent
collaboration, machine authority, governed autonomous systems, and the
cryptographic labor economy.

This document proposes a preferred end state. It does not amend the canonical
owners under `docs/architecture/`, and it deliberately distinguishes current
doctrine, current implementation, and recommended direction.

## Executive Judgment

The architecture is headed in the right direction, but the apparent choice is
the wrong choice.

The decentralized, Palantir/Foundry-like enterprise ontology environment and
the Hypervisor Type 1/2/3 direction should not become competing product theses.
They are complementary halves of one system:

- the ontology fabric makes the world legible to autonomous systems;
- the autonomy hypervisor makes action in that world governable;
- machine authority connects semantic actions to real power;
- Agentgres turns execution into admitted, branchable operational truth;
- Goal loops turn static capability into purposeful intelligence;
- AIIP turns sovereign autonomous domains into a network;
- verification, contribution accounting, and sparse settlement turn networked
  work into an economy.

The clean end-state category is:

> **IOI is an open, edge-sovereign operating fabric for governed autonomous
> systems. Hypervisor is its reference execution and control environment;
> federated ontologies are its semantic world plane; machine authority is its
> security protocol; Agentgres is its operational truth substrate; AIIP is its
> inter-domain work protocol; and ioi.ai is its first outcome-conductor
> product.**

This is neither a decentralized Palantir clone nor a VM manager with agents
bolted on. It is an ontology-native autonomy fabric whose intelligence can act
under hypervisor-grade control.

The largest remaining gap is not another application. Canon already names
collaborative outcomes, cross-session graphs, multi-party contexts, and
`outcome_room` refs. What is still missing is their generalized and implemented
**shared work-frontier lifecycle**: dynamic participation, claimable work,
durable attempts and findings, verifier challenges, resource exchange, and
cross-domain admission. The current architecture describes a sovereign
autonomous-system platform more completely than it demonstrates an actual
Internet of Intelligence.

The highest-leverage correction is therefore:

> **Keep the Goal Kernel as the bounded recursive loop for one participant or
> subgoal, but add a first-class collaborative work graph in which many
> independent GoalRuns can discover work, claim it, exchange artifacts,
> publish positive and negative attempts, challenge evaluation, earn credit,
> and collectively course-correct.**

## One Architecture, Not Two Products

The two directions answer different questions.

| Plane | Question it answers | Primary IOI mechanisms | Failure if it stands alone |
| --- | --- | --- | --- |
| Semantic operating plane | What objects, relationships, events, actions, policies, and goals exist in this world? | Domain Ontologies, canonical object models, Data Recipes, policy-bound views, ODK, generated domain apps | Becomes an enterprise data and workflow platform with AI attached, but no portable machine authority or trustworthy execution boundary |
| Collective-intelligence plane | How do intelligences investigate, divide work, learn from one another, verify, and change course? | GoalRun, GoalGroundingLoop, Context Cells, future collaborative work graph, Evaluations, Improvement | Becomes chat, a fixed swarm, or a central conductor without a durable shared work model |
| Execution and control plane | Where does intelligence run, what is isolated, and how are resources scheduled? | Hypervisor Core and Daemon, Type 1 HypervisorOS, Type 2 Desktop/Workstation, Type 3 autonomy virtualization, providers, embodied runtime | Becomes a safe agent or VM launcher with no durable domain meaning |
| Authority and safety plane | Who may cause which effect, for what purpose, for how long, and with what revocation or local veto? | Local/domain governance, wallet.network, daemon admission, Physical Action Safety | Becomes orchestration that can recommend or execute without a constitutional power boundary |
| Truth and evidence plane | What was admitted, what changed, and what evidence supports the claim? | Agentgres operations and projections, receipts, branches, replay, artifact refs | Becomes dashboards, provider logs, or message-board consensus masquerading as truth |
| Interop and economic plane | How do independent systems exchange work, proof, reputation, rights, and value? | AIIP, Mixture of Workers, ContributionReceipts, Verified Work Graph, marketplaces, sparse IOI L1 settlement | Becomes one large platform rather than an internet |

An operating-system analogy is useful if it is not taken literally:

| Operating-system concept | IOI analogue |
| --- | --- |
| Domain type system and world ABI | Federated ontologies, object/action/event contracts, Data Recipes |
| Process or pursuit runtime | Goal Kernel and collaborative-pursuit policies |
| Virtualization | Hypervisor Type 3 for agents, workers, tools, models, memory, authority, and evidence |
| Host substrate modes | Type 1 HypervisorOS and Type 2 hosted desktop/workstation modes |
| Capability security and system-call admission | Machine authority, wallet.network, daemon policy and admission |
| Transactional operational state | Agentgres operations, branches, projections, receipts, replay |
| Network stack | AIIP |
| Capability construction and packaging | ODK, Foundry, generated domain-app and worker packages |
| Labor discovery and routing | MoW, aiagent.xyz, sas.xyz |
| First-party shell and application | ioi.ai and the Hypervisor clients/suite |

This framing explains why the Hypervisor application currently appears to be
both a hypervisor and an open operating environment. An autonomy operating
environment needs both kernel-grade controls and user-space semantic tools. The
mistake would be to turn those into two unrelated centers of gravity.

## The Preferred Product and Category Shape

The public category should not be “decentralized Palantir.” That comparison is
useful for recognizing the value of an ontology, object graph, operational
applications, and control-room experience, but it imports the wrong center of
gravity: centralized data integration and vendor-owned operational truth.

The better category language is:

> **Open operating fabric for governed autonomous systems.**

Within that category:

- **Hypervisor** is the reference operating environment and control plane.
- **Type 3** is the differentiating kernel idea: virtualize agency, context,
  tools, authority, memory, evidence, and effects rather than only machines.
- **Type 1 and Type 2** are deployment, custody, isolation, and operator modes.
  They make Type 3 trustworthy on bare metal, clusters, desktops, workstations,
  customer clouds, and high-assurance environments.
- **Ontology, Data, Automations, Foundry, Evaluations, Provenance, Governance,
  Missions, and generated domain apps** are semantic and operational lenses
  over shared objects. They should not become independent mini-platforms.
- **ioi.ai** is the intent and collective-outcome front door. It proves the
  substrate without receiving privileged runtime, authority, or truth paths.

Type 1/2/3 should remain a precise architecture and operator grammar, not the
whole public category pitch. Type 3 plus the semantic action plane is the
initial wedge. Type 1 earns priority where IOI needs custody, local sovereignty,
air-gapped operation, embodied control, or high assurance; it should not make
generic VM or cluster management the critical path.

## Product Architecture: One Goal Space, Two Supply Lanes

The best product is not a choice between a single-node subscription and a
separate node-network product.

The decisive product shape is:

> **ioi.ai sells one Goal Space subscription. Same-domain 1–N worker
> orchestration is built in. Independent network participation is an opt-in,
> metered supply lane. IOI operates the initial worker fleet as disclosed seed
> liquidity, but that fleet is not presented as independent multi-party
> collaboration.**

The product is unified; the owner boundaries are not collapsed. ioi.ai conducts
the goal and owns account/subscription experience. Hypervisor/daemon executes
and meters managed work. aiagent.xyz/MoW supplies, routes, and attributes
marketplace workers. sas.xyz owns outcome-service procurement, delivery,
acceptance, and dispute records. wallet.network and local/domain governance
authorize. Agentgres domains retain admitted operational truth.

### Seat-like experience without seat arbitrage

ioi.ai should deliberately reproduce the useful simplicity of a foundation-
model seat — one account, one recurring plan, broad access, and a predictable
ordinary-use allowance — without treating ChatGPT, Claude, or another provider's
named-user subscription limits as wholesale machine capacity.

The highest-alpha commercial shape is:

```text
ioi.ai Goal Space subscription
  = conductor, persistent goal state, memory, policy, receipts, replay,
    collaboration, and ordinary support entitlement
  + a bounded monthly grant of non-transferable Hypervisor Work Credits
  + access to provider-neutral Auto routing and disclosed route controls

additional managed work
  = Work Credit top-up, overage, or committed-spend drawdown

Network / Open participation
  = a separately bounded goal budget for independent workers, verifiers,
    services, challenge, and settlement

Enterprise / Private
  = seats plus committed managed-work spend, private or customer-boundary
    runtime, reserved capacity, governance, audit, SLA, and support
```

This is a seat-like **outcome product**, not a resale bundle assembled by adding
the retail price or nominal usage limits of several chat subscriptions. Those
plans are neither interchangeable with API capacity nor a stable basis for
IOI's unit economics. The monthly Work Credit grant should be sized from
observed workload cohorts and managed-work cost, with explicit caps, quotes,
and overage behavior; it should never imply unlimited model or agent usage.

Work Credits are the product-facing budget unit because raw tokens are not
comparable across input, output, cached, reasoning, image, tool, accelerator,
and self-hosted routes. They should remain non-transferable product credits,
not cash, a speculative token, or a labor-settlement asset. Every execution
receipt should still expose the accountable worker, actual model/provider and
route, token/compute categories where available, fallback or escalation reason,
underlying managed cost class, IOI charge class, and total Work Credits.

Three execution policies should fit inside the same subscription:

| Policy | Behavior | Charging rule |
| --- | --- | --- |
| `Auto` / `1-of-N` | Hypervisor selects the cheapest eligible route expected to satisfy quality, privacy, authority, latency, and context constraints; it may run a cheap-first cascade and escalate only after verification fails | Actual admitted attempts, verification, and runtime consume Work Credits under a pre-run estimate or cap |
| `Pinned` | The user or policy selects a named eligible worker/model/provider route | Route-specific actual usage consumes Work Credits; unavailable or ineligible routes fail closed unless the user authorized fallback |
| `Compare` / `N-of-N` | Several independent routes run and a declared verifier or synthesis rule compares them | All admitted attempts, verifier work, and synthesis consume Work Credits and are visible before confirmation |

`1-of-N` is therefore a routing policy, not a separate plan. The economically
important mechanism is often a verified cascade — inexpensive worker first,
deterministic or model verifier second, frontier escalation only when needed —
rather than always invoking the most expensive model or hiding several attempts
inside a flat allowance.

Sell the governed goal experience, not physical node count. One logical
Hypervisor domain may schedule many workers across several machines, clouds,
model providers, and failure domains while remaining one authority, truth, and
settlement domain.

### Keep four kinds of plurality distinct

| Shape | What is actually distinct | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Multi-model | Foundation-model routes or model families | Cognitive diversity and route choice | Accountable worker identity or independent parties |
| Multi-worker | Versioned worker compositions with different roles, manifests, policies, tools, and outputs | Division of labor and comparable contributions | Independent authority, truth, or settlement roots |
| Multi-node | Runtime nodes, compute sessions, providers, or failure domains | Scale, isolation, locality, custody, and resilience | Governance or economic independence |
| Multi-party | Separate organization/domain/wallet principals controlling authority, revocation, truth, risk, challenge, and settlement | Actual federation and a reason for `MultiPartyCollaborationEnvelope` | Independence when affiliations or dependencies are hidden |

Ten IOI-owned workers on ten nodes using five model vendors are still one party
if IOI controls their authority, operational truth, verifier, and settlement.
They can seed multi-worker behavior and network capacity; they cannot by
themselves demonstrate a multi-party Internet of Intelligence.

A model endpoint is also not the protocol actor. The accountable unit remains
the Worker composition:

```text
Worker
  = manifest and publisher
  + model route
  + harness/runtime entrypoint
  + tools and connectors
  + policy and authority requirements
  + memory and persistence posture
  + verifier and receipt obligations
  + version, benchmark, cost, and contribution identity
```

Foundation models are mounted cognition. This keeps the same worker portable
across provider APIs, dedicated capacity, open weights, customer endpoints, and
future model routes without turning a provider seat into the labor-market
identity.

### Product controls are orthogonal axes

Do not overload privacy, participation, and placement into one mode selector.

| Axis | User-facing choices | Meaning |
| --- | --- | --- |
| Execution/custody | `Standard` or `Private` | Provider-trust disclosure and custody/proof posture |
| Contributor scope | `My workers`, `Organization`, or `Network / Open` | Which accountable worker/provider domains may participate |
| Placement, when advanced control is useful | `Run local`, `Use my infrastructure`, `Pick a cloud`, or `Let Hypervisor choose` | Where admitted work executes |

`Standard` versus `Private` remains the managed-execution choice.
`My workers` versus `Network / Open` is a participation choice. Multi-node and
multi-provider diversity are placement/trust details, not new collaboration
products.

### Lane A — Subscription-backed Goal Space

The base subscription should include:

- persistent goal/conductor state and account experience;
- private and organization Goal Spaces;
- goal-appropriate direct or 1–N worker execution inside one logical governed
  domain;
- receipts, replay, memory, collaboration, budgets, and governance;
- a modest included Work Credit allowance for ordinary managed work;
- BYOM, BYOK, BYOA, local, and customer-infrastructure routes;
- access to both the `Standard` and `Private` selector/policy semantics.

Making the `Private` selector available does not mean IOI-provisioned private
compute, customer-boundary custody, attestation, or proof is free inside every
seat. Managed `Private` execution may require Work Credits, Private Workspace
entitlement, reserved capacity, customer infrastructure, or an enterprise plan
when IOI supplies real private runtime/custody obligations.

Heavy multi-session, multi-model, managed-compute, connector, training, or
verifier work consumes additional Work Credits. Do not include unlimited
multi-model or multi-worker burn in a flat seat price: that creates adverse
selection, opaque subsidy, and an unstable margin. Direct local/BYO provider
spend should not receive a hidden percentage markup; subscription value attaches
to the conductor, policy, memory, collaboration, receipts, and governance.

This lane uses GoalRun/OutcomeRoom coordination without claiming a multi-party
boundary merely because several workers or model providers participated.

Contributor scope never declassifies data or weakens the selected custody,
privacy, retention, authority, or provider-trust policy. Every candidate worker
must satisfy the intersection of the Goal Space policy and its own domain's
policy; otherwise it is ineligible.

### Lane B — Network / Open Goal Space

Opening contributor scope to `Network / Open` should:

- create or bind a separately funded goal budget, bounty, procurement limit, or
  sas.xyz service order rather than silently consume the ordinary seat
  allowance;
- admit worker-provider and verifier domains through declared room membership
  and bind `MultiPartyCollaborationEnvelope` when the admitted principals are
  actually independent;
- show candidate workers, affiliations, model/runtime dependencies, price,
  privacy, verification, license, and settlement posture;
- use AIIP for signed handoffs and permitted refs while every party retains
  local operational truth;
- emit RoutingDecisionReceipts and ContributionReceipts;
- distinguish execution, verification, acceptance, challenge/adjudication, and
  payout;
- let ioi.ai charge for real cross-worker selection, orchestration, verifier
  routing, evidence synthesis, and settlement handoff; preserve worker-market
  fees in aiagent.xyz, service procurement/dispute fees in sas.xyz, and managed
  execution charges in Hypervisor.

A model or cloud provider is normally a disclosed dependency/subprocessor, not
automatically a collaboration party. It becomes a party only when its owning
principal accepts room-level rights, obligations, evidence, challenge, or
settlement roles.

The UI label does not determine the protocol boundary. An `Organization` room
spanning sovereign domains requires `MultiPartyCollaborationEnvelope`; a
`Network / Open` room currently served only by IOI-owned workers remains one
party until an independent principal joins.

### IOI-operated seed fleet

IOI should operate the initial managed worker supply to solve cold start. Useful
reference compositions include:

- planner/researcher;
- builder/implementer;
- deterministic verifier;
- model-based critic;
- synthesizer;
- benchmark, challenge, and evaluation capacity.

The fleet should be modeled as ordinary, named, versioned first-party Worker
compositions over Hypervisor/daemon runtime nodes. It must:

- disclose IOI ownership, model/runtime dependencies, subsidy, and real cost;
- use the same authority, isolation, receipt, replay, and contribution contracts
  required of external workers;
- receive no hidden MoW or marketplace preference;
- avoid circularly acting as coordinator, paid worker, sole verifier, ranking
  authority, and settlement judge for the same outcome;
- be replaceable or outperformable by a third-party worker without changing the
  pursuit contract.

The correct role is **anchor liquidity**: baseline quality, last-resort
capacity, conformance fixtures, and a credible starting experience. IOI should
be the initial market maker, not its own permanent only counterparty.

### Foundation-model procurement rule

Do not build production worker supply by buying enterprise chat/workspace seats
and pooling, sharing, browser-automating, or reselling them as machine capacity.
Official provider boundaries already point the other way. OpenAI documents
ChatGPT and API billing as separate in its
[subscription/API guidance](https://help.openai.com/en/articles/8156019) and
permits API integration into customer applications while prohibiting shared
credentials and resale/lease of account access under its
[Services Agreement](https://openai.com/policies/services-agreement/).
Anthropic likewise states that paid Claude plans, including Team and Enterprise,
do not include API/Console access in its
[subscription/API guidance](https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-do-i-have-to-pay-separately-to-use-the-claude-api-and-console).

Negotiated order forms may grant broader automation or downstream rights. IOI
should record and enforce the actual contract posture rather than assume the
public default is either broader or narrower than the signed agreement.

The procurement hierarchy should be:

1. open/self-hosted weights where operationally suitable;
2. provider APIs or managed cloud endpoints;
3. dedicated capacity or negotiated enterprise inference agreements for scale,
   retention, SLA, or data posture;
4. explicit OEM/reseller authorization when IOI exposes near-raw provider
   capability;
5. named-human workspace seats only for internal operators or
   provider-approved interactive harnesses.

The durable supply portfolio should combine all of those mechanisms rather
than make one aggregator or provider the product boundary:

| Supply source | Preferred role | Architectural posture |
| --- | --- | --- |
| Direct provider API, managed endpoint, or negotiated inference agreement | High-volume routes, feature fidelity, negotiated economics, regional/privacy commitments, dedicated capacity, and high-assurance workloads | First-class adapter with a versioned provider/model contract and direct receipts |
| [OpenRouter](https://openrouter.ai/) | Bootstrap breadth, long-tail models, price/availability discovery, policy-qualified fallback, overflow, and fast route experimentation | Procurement and routing adapter behind Hypervisor; never the sole inference authority or IOI's defensible product layer |
| Customer BYOK/BYOA | Enterprise cost ownership, existing provider commitments, user-selected interactive harnesses, and customer control | Customer-owned credential binding; IOI charges explicitly for conductor/runtime/governance rather than hiding a provider-spend markup |
| Open or self-hosted weights | Private/no-provider-trust execution, sovereignty, customization, training/distillation rights, and cost/concentration hedge | Hypervisor-managed or customer-boundary runtime with explicit model/license and attestation posture |

OpenRouter is useful precisely because it can expose many providers through one
integration, support BYOK, and route or fall back across eligible capacity. It
does not erase provider terms, model terms, data-handling differences, or
commercial rights. Its current public economics also make it a poor foundation
for a thin token-resale margin: OpenRouter publishes a fee on credit purchases
while passing through provider inference prices, and its BYOK path gains a fee
after a published free allowance. Enterprise discounts apply to OpenRouter's
fees rather than the underlying inference price. These values are procurement
inputs that can change, not product promises. See OpenRouter's current
[pricing](https://openrouter.ai/pricing), [FAQ](https://openrouter.ai/docs/faq),
and [BYOK documentation](https://openrouter.ai/docs/guides/overview/auth/byok).

OpenRouter's current Terms contemplate customers incorporating the service into
their own products, but also prohibit reselling raw API access to models and
building a competing service. Because IOI includes provider-neutral routing,
IOI should obtain an explicit enterprise/OEM interpretation or authorization
for its customer-facing use rather than infer permission from public language.
The route must fail closed if the applicable right is missing. See OpenRouter's
current [Terms of Service](https://openrouter.ai/terms/) and
[enterprise offering](https://openrouter.ai/enterprise/).

Provider abstraction must also not weaken privacy policy. OpenRouter can enforce
zero-data-retention routing, but its provider selection and model fallback
defaults are broader than a governed sensitive route should assume. A
`Standard` route may use a qualified aggregator path when its declared data and
retention policy permits it. A strict `Private` or no-provider-trust route must
resolve to a custody-proven direct, dedicated, customer-boundary, or local path;
an aggregator's ZDR flag alone does not satisfy that stronger promise. See the
current [provider-routing](https://openrouter.ai/docs/guides/routing/provider-selection),
[model-fallback](https://openrouter.ai/docs/guides/routing/model-fallbacks), and
[ZDR](https://openrouter.ai/docs/guides/features/zdr) controls.

For every provider/model candidate, Hypervisor should resolve a versioned route
contract before admission:

```yaml
commercial_posture: direct | aggregator | customer_byok | customer_byoa | self_hosted
customer_facing_allowed: true | false
reseller_oem_authorized: true | false | not_required
provider_terms_version: ref
model_terms_version: ref
endpoint_ref: ref
model_version: ref
provider_allowlist: [ref]
automation_right: interactive_only | unattended_allowed | negotiated
downstream_right: internal_only | customer_application | reseller_oem
data_collection: allow | deny
zdr_required: true | false
region: ref
fallback_classes: [ref]
max_price: ref
required_parameters: [ref]
training_or_distillation_right: ref
```

An aggregator fallback that changes the underlying provider or model is a
semantic substitution, not merely an availability event. It must remain within
the goal's route contract, produce a RoutingDecisionReceipt, and re-run the
applicable acceptance/verifier path.

Provider/model-route contracts should fail closed on unattended work unless
they declare the relevant rights:

```yaml
access_mode: named_human_seat | api | dedicated_endpoint | self_hosted
automation_right: interactive_only | unattended_allowed | negotiated
downstream_right: internal_only | customer_application | reseller_oem
credential_principal: named_human | service_account | customer_owned
output_training_right: prohibited | noncompeting_only | expressly_licensed | open_license
```

Users may connect a provider-approved named-user harness subscription as BYOA
inside their own Goal Space. That remains a user-scoped integration, not IOI
marketplace inventory. BYO API credentials remain customer-owned credential
bindings; IOI brokers use without transferring or reselling the key.

Inference rights and training/distillation rights must remain separate. Foundry
should use open weights or expressly licensed teacher agreements rather than
assuming ordinary inference spend grants permission to train a competing model
or reusable worker.

### Monetization boundary

The gross-margin thesis should not be “buy tokens wholesale and sell them
opaque.” IOI's durable margin comes from the conductor, verified routing and
cascade savings, governed runtime, memory and context continuity, private
deployment, evidence and assurance, worker/service discovery, and successful
outcome coordination. Provider inference is a cost of delivered work and may
carry a disclosed managed-service margin, but it is not the defensible product.

A quote can normalize heterogeneous supply into Work Credits while preserving
an auditable breakdown:

```text
Work Credits charged
  = model / accelerator / compute cost
  + sandbox, storage, connector, and replay cost
  + external worker, verifier, or service cost
  + declared IOI managed-work and orchestration charge
```

The public rate card may simplify that breakdown, but the receipt ledger must
preserve it. IOI should price the included monthly grant only after observing
real P50/P90 workload and escalation behavior; fixed retail-chat plan prices
are not a substitute for API COGS. A direct BYOK route should normally remove
the provider-cost component and retain explicit IOI conductor/runtime charges.

| Canonical owner | Revenue lane | What the customer buys |
| --- | --- | --- |
| ioi.ai | Conductor subscription and network-orchestration usage | Persistent Goal Spaces, account experience, plan selection, cross-worker coordination, verifier routing, evidence synthesis, and settlement handoff |
| Hypervisor | Work Credits and managed-runtime charges | Managed model, compute, multi-path, connector, storage, replay, automation, private-runtime, and reserved-capacity usage |
| Hypervisor / enterprise deployment | Enterprise/private plan | Customer-boundary deployment, policy, audit, retention, compliance, support, administration, and stronger custody posture |
| aiagent.xyz | Worker invocation, install/subscription, managed-instance, and marketplace take-rate | External worker capability, benchmark/certification trust, managed worker operation, matching, and distribution |
| sas.xyz | Service order, outcome procurement, escrow, SLA, acceptance, dispute, and service take-rate | Contracted autonomous outcome delivery and its commercial lifecycle |

A Goal Space may present one budget and quote, but it must preserve these owner
records underneath. ioi.ai must not turn worker-marketplace or service-order
revenue into a private conductor fee, and aiagent.xyz/sas.xyz must not become
runtime or Work Credit owners.

This is one product experience with different supply and value boundaries, not
a separate SKU for every internal primitive.

### Commercial readiness is not yet the target state

The product architecture above is a target, not a claim that the current
metering plane can safely support a paid multi-model subscription. Current canon
marks Work Credits and marketplace fees as planned or deferred. The live OCU
metering slice charges `0.1` OCU for any model-backed receipt regardless of its
provider, input/output/cache/reasoning usage, retry chain, or actual invoice.
The live model-route overview also declares that sealed BYOK is unimplemented
and only Ollama-transport routes are currently bindable for session execution.

Before IOI prices an included managed-work allowance, it needs invoice-grade
reconciliation that records at least:

- endpoint, provider, model and price-schedule version;
- uncached input, cache write/read, visible output, reasoning and other billed
  token classes where the supplier exposes them;
- image, audio, tool, accelerator, environment and storage usage;
- every attempted route, success/failure class, fallback, escalation and which
  attempts the supplier actually billed;
- estimated pre-run cost, reserved budget, finalized supplier cost, external
  broker fee, IOI fee basis and amount, refund/adjustment, and receipt refs;
- organization and goal caps, concurrency/child-agent/runtime limits,
  background-work policy, and explicit overage/top-up consent.

The prudent commercial sequence is:

1. build invoice-grade internal telemetry and reconcile it against supplier
   statements;
2. run a prepaid, capped beta with no model-quality or upstream-availability
   SLA;
3. introduce the seat plus expiring monthly Work Credit grant and opt-in
   top-ups only after P50/P90 cost and fallback amplification are bounded;
4. add pooled organization budgets and route-policy administration;
5. add enterprise commitments, reserved capacity, private deployment, support,
   and decomposed control-plane/runtime/route-class SLAs.

Progression should be gated on provider-invoice reconciliation, positive cohort
contribution margin, bounded p95 COGS, abuse and chargeback behavior, fallback
cost amplification, and accepted outcomes per dollar — not gross token volume.

## Does This Facilitate an Internet of Intelligence?

At the design level: **yes**.

At the implementation and network-proof level: **not yet**.

The architecture already contains most of the ingredients:

- source-neutral workers, models, harnesses, tools, and providers;
- bounded authority, step-up, revocation, and emergency stop;
- local and customer-controlled execution;
- typed operational state, receipts, replay, and attribution;
- ontology-bound data, actions, projections, and generated applications;
- multi-harness goal pursuit and verifier paths;
- portable worker, memory, package, and service concepts;
- work-native rather than token-native interop semantics;
- contribution accounting and sparse public settlement doctrine.

But an internet is not merely a well-designed node. It requires independently
operated systems to join and create value without sharing one runtime, one
database, one administrator, or one account provider.

The decisive conformance question is:

> Can a worker operated outside IOI infrastructure discover an eligible goal,
> negotiate semantics, receive only permitted context/resources/authority,
> submit an independently verifiable contribution, preserve derivation and
> credit, participate in challenge or dispute, and leave with portable state —
> without trusting one IOI-hosted database as universal truth?

The current answer is architectural intent rather than demonstrated behavior.
The mismatch is visible in implementation status:

- GoalRun multi-harness orchestration exists, but its first policy is narrow;
- the semantic data plane is mostly planned beyond an initial ODK object plane;
- MoW routing receipts are planned;
- AIIP is designed but not implemented;
- autonomous-system chains and local settlement domains remain speculative;
- public/economic L1 behavior is intentionally later and sparse.

That is a healthy order only if IOI now prioritizes an end-to-end, cross-node
collective-pursuit proof over continued application-catalog expansion or
premature chain economics.

## Goal Kernel: Keep It, but Put It at the Right Scale

The concern that Goal Kernel is not generic or loop-based enough is half right.

The canonical `GoalGroundingLoop` is already a real loop:

```text
receive intent
  -> classify goal and risk
  -> gather grounding
  -> inspect current state
  -> derive constraints and acceptance
  -> select topology and lease context
  -> execute or delegate
  -> monitor
  -> verify
  -> repair or escalate
  -> reconcile and persist learning
  -> continue or close
```

That is the correct local control loop. Replacing it with a message board would
discard typed context, authority, verification, and continuation semantics.

The implementation, however, validates the concern. The current first cut is
explicitly `parallel_implement_reconcile`: one deterministic conductor, at most
two implementers, software-shaped task briefs, isolated candidate workspaces,
file-oriented results, deterministic candidate verification, and one admitted
reconciliation. The kernel currently admits only that policy and caps parallel
invocations at two. This is a strong and honest software-orchestration slice;
it is not yet a general sea-of-agents substrate.

The durable contracts also retain implementation bias:

- `RoleTopology` is selected up front and centers conductor, implementer,
  reviewer, and verifier roles;
- `TaskBriefPayload` foregrounds implementation, repair, changed files, diffs,
  and tests;
- `HarnessAdapterEvent` foregrounds files, patches, and test events;
- `ImplementationResultPayload` is a software result rather than a generic
  outcome delta;
- point-to-point typed handoffs are strong, but pull-based communal work is not
  first-class;
- open join/leave, claim leases, wake/sleep, heartbeat, replacement, dynamic
  taskforces, negative results, and verifier-rule challenges are not one
  coherent lifecycle.

The correction is not to remove Goal Kernel. It is to separate two scales of
coordination:

```text
OutcomeRoom / CollaborativeWorkGraph
  shared objective, frontier, claims, attempts, findings, resources,
  evaluation, contribution lineage, discussion projections, and replay

    -> GoalRun A -> bounded Goal Kernel loop -> harnesses / workers
    -> GoalRun B -> bounded Goal Kernel loop -> harnesses / workers
    -> GoalRun C -> bounded Goal Kernel loop -> harnesses / workers

  admitted results update the shared frontier and may create new GoalRuns
```

`GoalRun` answers: “How does one bounded intelligence or subteam pursue and
verify this objective?”

`OutcomeRoom` answers: “How do many independent intelligences discover work,
coordinate, relay artifacts, challenge one another, and improve shared state?”

AIIP answers: “How does that participation cross autonomous-system and
organizational boundaries?”

This is a hybrid, but not a compromise. Each layer owns a different problem.
Most ordinary goals still collapse to one direct GoalRun or one harness.
Collective machinery appears only when expected value justifies its cost.

## The Missing Collective-Pursuit Objects

`OutcomeRoom` is a useful working name because the current architecture already
uses outcome-room language in places without defining a strong canonical
object. The name can change; the boundary should not. It must be a profile and
composition of existing owners, not a peer runtime or a duplicate global truth
store.

| Existing owner/object | Role in the proposed composition |
| --- | --- |
| `IoiAiGoal` | First-party user goal and constraints |
| `IoiAiOutcomePlan` | ioi.ai's goal-appropriate plan and materialization choice |
| `IoiAiAttemptSummary` | User-facing comparable projection of a durable attempt |
| `IoiAiCrossSessionOutcomeGraph` | First-party cross-session evidence and attempt projection |
| `GoalRun` | One bounded participant/subgoal pursuit loop |
| `HypervisorMission` and `HypervisorAutomationSpec` | Durable background execution/materialization, including the existing `outcome_room` kind/ref |
| `MultiPartyCollaborationEnvelope` | Cross-party policy, allowed refs, restricted views, authority, revocation, proof, and settlement context |
| `OutcomeRoom` / CollaborativeWorkGraph | Proposed shared-frontier, participation, attempt, finding, evaluation, and course-correction profile over those owners |
| Agentgres domains | Each domain's admitted operational state and room projections |
| AIIP | Signed, sequenced cross-domain room updates and refs; never a shared raw context |

A minimum durable composition is:

### `OutcomeRoom`

- shared objective, constraints, acceptance criteria, and stop conditions;
- room mode: private goal, permissioned team mission, cross-org pursuit, or
  open challenge;
- participation, identity, visibility, privacy, and contribution policies;
- declared coordination/admission topology and ordering policy;
- ontology and semantic-profile refs;
- scorecard, guardrail, verifier, resource, budget, and settlement refs;
- artifact license, IP, retention, and export-policy refs;
- participant, work-frontier, attempt, discussion, admission, replay, and
  contribution refs.

### `RoomParticipantLease`

- participant actor, operator, and home-domain refs;
- worker, harness, model, tool, connector, and capability advertisement refs;
- join request, identity/eligibility evidence, admission decision, and room
  visibility scope;
- context, runtime, resource, budget, and authority lease refs;
- current claim, heartbeat, wake condition, quiet-hours/backoff, and last
  contribution refs;
- invited, joining, active, sleeping, waiting, suspended, quarantined,
  retiring, retired, and revoked state.

This room-specific lifecycle should reuse existing `ContextLease`, authority
leases, runtime assignments, resource-allocation decisions, and
`MultiPartyCollaborationEnvelope.party_refs`; it should not create a second
identity or authority system.

### `ResourceOffer` / `CapabilityOffer`

- provider/participant, resource or capability profile, capacity, locality,
  trust, privacy, cost, and availability;
- eligible frontier/attempt classes and policy constraints;
- allocation, queue, preemption, expiry, and fairness policy refs;
- resource-allocation decision, spend, use, and contribution receipt refs.

This may be a collaboration profile over existing provider inventory, worker
manifests, capability discovery, and resource-allocation objects rather than a
new standalone market.

### `WorkFrontierItem`

- question, problem, hypothesis, task, review need, or resource need;
- dependency and related-attempt graph;
- required capabilities, context, compute, authority, and evidence;
- expected value, uncertainty, priority, and duplication policy;
- claimability, concurrency, expiration, and stop conditions.

### `WorkClaimLease`

- claimant and participant identity;
- bounded work scope and context refs;
- authority, compute, data, budget, and tool leases;
- TTL, heartbeat, renewal, release, reassignment, and quarantine state;
- duplicate-work and independent-replication policy.

### `Attempt`

- declared method, hypothesis, parent/derived-from lineage, and environment;
- input state, resources, software/model/worker versions, and authority posture;
- outcome class: positive, negative, inconclusive, invalid, exploit-found, or
  superseded;
- result or `OutcomeDelta`, artifacts, receipts, costs, verifier refs, and
  reproduction state;
- artifact license, IP/provenance, disclosure, retention, and export posture;
- contribution refs for execution, derivation, debugging, review, resource
  provision, and synthesis.

### `Finding` / `Claim`

- proposition and confidence/uncertainty;
- supporting and contradicting evidence;
- applicability conditions and known counterexamples;
- source, attempt, ontology, and provenance refs;
- proposed effect on the frontier, routing prior, policy, or capability.

### `VerifierChallenge`

- challenge to a metric, evaluation rule, verifier, evidence, eligibility
  decision, or claimed result;
- challenge evidence and adjudicator policy;
- verifier-version or rule-version change;
- affected-attempt graph and required re-verification.

### Generic `WorkResult` / `OutcomeDelta`

This should become the general result seam. `ImplementationResultPayload`
should remain its software profile rather than define the whole pursuit model.
Other profiles can represent research findings, ontology mutations, incident
resolution, service delivery, physical mission state, review, or evaluation.

The communal board, inbox, digest, taskforce view, leaderboard, and replay are
projections over these objects. They are not operational truth themselves.

### Shared-state ownership and admission

A CollaborativeWorkGraph must never imply one magically global, mutable
Agentgres graph.

Every room declares one coordination topology:

1. **Hosted admission:** one named governed domain orders and admits room-level
   frontier, attempt, finding, evaluation, and decision updates. This should be
   the first implementation because its failure and dispute semantics are
   legible.
2. **Federated admission:** a versioned policy names participating domains, the
   ordering/merge rule, quorum or adjudicator requirements, conflict handling,
   and failover. This is a later protocol profile, not an implicit property of
   every room.

In both cases, each party retains its local operational truth and private
context. AIIP carries signed, sequenced, idempotent refs and permitted updates.
The room host or declared federation policy admits shared-room state.
`MultiPartyCollaborationEnvelope` remains the cross-party policy and proof
context. Restricted views, receipts, and evidence can cross domains; raw private
context does not cross unless an explicit policy-bound view and authority path
permit it.

## The Generic Intelligence Loop

The combined system should support this loop at every useful scale:

```text
ground objective, world state, constraints, and acceptance
  -> observe and identify uncertainty or opportunity
  -> form hypotheses, candidate plans, or frontier items
  -> claim, allocate, or delegate bounded work
  -> lease context, resources, tools, and authority
  -> execute isolated or cooperative attempts
  -> publish results, evidence, negative findings, and integrity incidents
  -> evaluate, falsify, reproduce, compare, merge, reject, or challenge
  -> update shared knowledge, contribution lineage, and routing priors
  -> adapt topology, budget, participants, and verifier paths
  -> continue until acceptance, risk, budget, deadline, or marginal-value stop
```

This is more generic than a fixed planner/executor/verifier DAG and more
governable than an unbounded swarm. It allows hierarchy, leaderless blackboard
coordination, markets, specialist meshes, branch-and-merge, independent
replication, and ordinary direct execution to be policies over one substrate.

The “sea of agents” should therefore be a participation and allocation mode,
not a hard-coded topology.

## What the Hugging Face Examples Actually Teach

The Fast Gemma Challenge and RL-LLM Wiki are credible proto–Internet of
Intelligence applications. Their useful primitive is not a large group chat. It
is a shared blackboard plus leases, scratch workspaces, durable/versioned attempts,
artifact promotion, verification, inboxes/digests, and replay.

The [Fast Gemma Challenge](https://huggingface.co/gemma-challenge) and its
[agent workspace guide](https://huggingface.co/buckets/gemma-challenge/gemma-main-bucket/tree/README.md)
combine:

- one shared, measurable objective;
- a fixed execution environment;
- heterogeneous coding-agent participation;
- a live message board and leaderboard;
- throughput as the objective and perplexity as a quality guardrail;
- organizer verification against private prompts for trusted results;
- reproducible implementation artifacts.

The important architectural lesson is the coupling of open exploration with a
hard admission boundary. Ideas, reports, and provisional results can be broad;
trusted leaderboard state requires verification.

The [RL-LLM Wiki workspace](https://huggingface.co/buckets/rl-llm-wiki/rl-main-bucket)
is an even closer reference for the macro-loop:

- roles are emergent suggestions rather than permanent central assignments;
- agents claim leased items from a shared frontier;
- agent scratch stores are distinct from the canonical public dataset;
- source records preserve provenance;
- independent review and a controlled automated promotion path move work into
  canonical state;
- board discussion is separate from reviewed artifacts;
- queues, channels, taskforces, inboxes, digests, traces, and replay coordinate
  attention;
- review, curation, skepticism, and audit can become more valuable than further
  raw production as the system matures.

Its [public knowledge-base dataset](https://huggingface.co/datasets/rl-llm-wiki/knowledge-base)
is the promoted artifact, while its collaboration bucket holds process state.
The [Collab Replay](https://rl-llm-wiki-rl-dashboard.hf.space/replay.html) makes
the work history inspectable.

These examples should be treated as topology and product references, not as
the architecture to copy wholesale.

### Copy

- pull-based claim leases in addition to conductor assignment;
- a shared frontier and one-call digest of where help is scarce;
- dynamic roles and taskforces formed from live bottlenecks;
- durable/versioned positive, negative, and inconclusive attempts;
- separate narrative discussion from structured results;
- scratch workspaces with explicit canonical promotion;
- reproducible artifacts and derivation lineage;
- independent evaluation, held-out tests, and verifier versioning;
- replay as a first-class operational view;
- credit for review, debugging, replication, integrity reports, resource
  provision, negative results, and synthesis — not only the winning execution.

### Do not copy

- one SaaS organization, bucket ACL, or API writer as universal authority;
- public boards, inboxes, traces, or context by default;
- raw Markdown or chat as the high-stakes coordination contract;
- one scalar leaderboard as the definition of success;
- self-reported results mixed with admitted results;
- one lightweight review as sufficient admission for consequential enterprise
  or physical work;
- shared-workspace execution for sensitive code, enterprise state, or embodied
  systems;
- unbounded agent spawning or every participant reading every message;
- benchmark incentives without verifier challenges, hidden tests, diversity,
  and anti-collusion controls.

The examples show what an IOI application can feel like. IOI's opportunity is
to make that pattern portable across private data, organizations, economic
boundaries, domain ontologies, and embodied systems without losing local
sovereignty.

## How Background Agents Should Appear to the User

Do not create a separate permanent “Swarm” application. Render the same durable
objects through existing surfaces.

The central user experience should be a **Goal Space** in ioi.ai and the same
underlying object as a **Mission detail** in Hypervisor.

That room-shaped view should appear only for persistent collective goals. A
simple question, direct run, ordinary automation, or single-session task should
remain direct; “collaborative outcome” must not become “room UI” by default.

Its default view should show:

1. objective, acceptance criteria, constraints, deadline, budget, visibility,
   and stop policy;
2. a workstream/frontier graph showing open, claimed, blocked, replicating,
   verifying, accepted, rejected, and superseded work;
3. active, sleeping, waiting, failed, quarantined, and completed participants;
4. each participant's current claim, context/resource/authority leases,
   heartbeat, spend, last contribution, and next wake condition;
5. hypotheses, findings, artifacts, negative results, and unresolved
   contradictions with evidence refs;
6. evaluation state, guardrails, Pareto frontier, verifier versions, and
   integrity challenges;
7. approvals, authority blockers, privacy boundaries, incidents, and operator
   pause/kill/quarantine controls;
8. contribution and derivation lineage;
9. a replayable timeline that can reconstruct why the room changed direction.

The existing suite then provides focused drill-downs:

- **Missions**: outcome room, topology, workstreams, blockers, budget, deadline.
- **Sessions**: one participant, GoalRun, context cell, or attempt.
- **Evaluations**: scorecards, guardrails, replications, and Pareto frontiers.
- **Provenance**: claims, evidence, lineage, integrity incidents, credit, and
  disputes.
- **Governance**: authority, spend, privacy, participation, pause, kill,
  quarantine, and promotion.
- **Improvement**: promoted findings, reusable playbooks, canaries, rollback,
  and evaluator changes.
- **Studio**: room/topology templates, workers, policies, object/action schemas,
  and application composition.
- **Workbench**: code, artifacts, branches, and environment-specific work.

A live feed remains useful, but chat should be the social projection of the
work graph, not the work graph itself.

## Ontology: The Necessary Half, with Important Refinements

The ontology direction is not a distraction. It is what lets IOI graduate from
generic agents and generic tools into autonomous systems that understand a
domain's objects, relationships, constraints, actions, and evidence.

It also reinforces collective pursuit. An outcome room can use an
ontology-bound collaboration schema hosted by, or federated across, governed
domains:

```text
Objective
WorkFrontierItem
WorkClaimLease
Hypothesis
Attempt
Finding
Artifact
Evaluation
VerifierChallenge
ResourceLease
ContributionClaim
Decision
```

Agents then operate on permitted semantic object/action projections under Type
3 isolation plus machine-authority admission. Ontology makes the work legible;
Goal loops create intelligence; Hypervisor governs effects; Agentgres admits
each domain's operational state; the declared room coordinator or federation
policy admits shared graph updates; AIIP opens the pursuit across organizations;
contribution accounting rewards accepted marginal value.

The current ontology doctrine is strong on object models, connector mappings,
Data Recipes, policy-bound views, transformation receipts, projections, ODK
descriptors, generated apps, and ontology-to-worker plans. It needs five
refinements to work at internet scale.

### 1. Local canonicality, not one global ontology

Each organization or autonomous domain can have canonical local definitions.
The network must support:

- namespaced, versioned ontologies;
- local extensions, overlays, and policy-bound views;
- explicit crosswalks and semantic adapters;
- schema evolution, compatibility negotiation, and deprecation;
- mapping receipts and challengeable mapping decisions;
- policy-bound federated query and derived-object exchange.

AIIP handoffs should declare input/output ontology and action-schema profiles
and negotiate mappings. Data should remain at the edge by default; other
domains receive permitted projections, proofs, summaries, or derived objects.

### 2. Claims, uncertainty, time, and disagreement

Operational truth and semantic belief are not identical.

Agentgres can canonically record that a domain admitted an assertion or
decision. That does not make the proposition universally true. Ontology-bound
properties and relationships need provenance-bearing assertions with:

- valid time and transaction time;
- source and observation context;
- confidence or uncertainty;
- supporting and contradicting evidence;
- scope and applicability conditions;
- supersession and dispute state;
- causal or counterfactual context where relevant.

This is necessary for research, intelligence analysis, incident response,
forecasting, supply chains, compliance, and embodied world models.

### 3. Make the action layer executable

The semantic/action bridge should be a first-class contract, not an untyped
array of ontology actions.

A future `OntologyActionContract` should bind:

- target object or object set and typed inputs/outputs;
- preconditions, postconditions, invariants, and expected state transition;
- capability and runtime/tool/automation binding;
- risk class, local policy, authority scopes, approvals, and revocation;
- dry-run/preview, idempotency, retry, ambiguous-effect, and compensation
  semantics;
- verifier path, evidence requirements, and receipt obligations;
- physical safety profile when an action can affect the real world.

This is the exact seam where the ontology fabric and the autonomy hypervisor
become one architecture.

### 4. Progressive adoption

Do not require an enterprise to model its entire world before an agent can do
useful work. Start with minimal object/action contracts at consequential
boundaries, infer candidate schemas from real work, and promote changes through
governed proposals, validation, compatibility tests, and replay.

The ontology should compound from execution rather than become a long
consulting prerequisite.

### 5. Generated surfaces, not application sprawl

ODK-generated domain applications should be lenses over shared objects,
actions, policies, and receipts. The suite should converge on one object graph
and consistent lifecycle grammar rather than accumulate hand-built applications
with slightly different truth and authority models.

## The Cryptographic Labor Economy

The edge-in and fractal direction is correct, but “blockchain” should describe
the trust boundary, not mandate a chain per agent or per loop.

The useful topology is:

```text
attempt / execution branch
  -> local governed autonomous-system state machine
  -> organization or project Hypervisor Node / Agentgres domain
  -> AIIP cross-domain work and evidence exchange
  -> sparse public commitment when independent trust or economic finality needs it
```

These layers need different mechanisms:

| Boundary | Usually required | Usually not required |
| --- | --- | --- |
| One attempt or branch | deterministic admission, isolation, signed receipts, artifacts, replay | independent consensus |
| One governed autonomous system | policy-bound state transitions, authority, upgrade governance, local roots | a public L1 |
| One Hypervisor Node or organization | local ordering, reconciliation, contribution and dispute state | global publication of every operation |
| Cross-domain AIIP handoff | identities, schemas, sequence/idempotency, restricted views, evidence, acceptance/challenge | shared runtime or shared operational database |
| Public/economic settlement | shared ordering, rights, bonds, reputation roots, dispute finality, payment settlement | raw prompts, tool calls, model thoughts, every receipt |

The labor economy should therefore be composed of:

- local operational work graphs and execution branches;
- federated semantic object/action graphs;
- receipt-backed contribution and verification graphs across domains;
- Work Credits for product budgeting and managed usage;
- fiat, stablecoin, token, or other approved payout rails as policy permits;
- IOI L1 commitments only when public registry, rights, dispute, reputation, or
  economic finality creates real value.

This is one recursive trust topology, not two competing classes of blockchain.
“Fractal edge-in” should mean that each boundary can keep sovereign state and
export progressively stronger commitments — not that every boundary runs
consensus.

### Clarify what a receipt proves

The canonical phrase “receipts prove” is directionally useful but too broad if
read literally. A receipt can strongly prove the boundary facts it binds: a
request was admitted, a policy hash was evaluated, a tool reported an effect,
or a named signer emitted an observation. It does not automatically prove that
the external world changed as claimed, the output is correct, the work caused
the result, or the contribution is economically valuable.

The Verified Work Graph should preserve an assurance ladder:

```text
receipt / attestation
  authenticated statement about a declared boundary fact

evidence bundle
  support for a claim

verification
  a declared verifier evaluated the claim under a named rule/version

acceptance
  a user, customer, domain, or counterparty accepted the outcome

adjudication
  a challenge or dispute was resolved

settlement
  rights or value moved under the accepted/adjudicated claim
```

Cryptography makes labor claims attributable and challengeable. It does not by
itself make them correct or valuable. Evaluation, acceptance, scarcity,
causality, demand, and dispute resolution do that.

## Pressure Tests

### Open engineering or research challenge

**Fit:** strong partial fit. The collaborative-outcome canon already permits a
shared objective, scorecard, guardrail, attempt registry, optional message
board, and leaderboard. GoalRun, isolated workspaces, verifier paths, replay,
and contribution receipts are strong substrate choices.

**Break:** the current GoalRun is single-owner, push-oriented, statically
topologized, and software-result shaped. There is no durable pull-based
frontier, dynamic participation lifecycle, negative-result graph, shared
finding layer, resource exchange, or benchmark-rule adjudication.

**Correction:** implement the OutcomeRoom/CollaborativeWorkGraph profile,
generic attempts, claim leases, verifier challenges, dynamic actor lifecycle,
multi-objective evaluation, and credit for marginal information rather than
only the top score.

### Adversarial participant and scarce-resource shock

**Fit:** isolated runtimes, authority leases, policy admission, receipts,
restricted views, verifier paths, quarantine concepts, resource-allocation
decisions, and explicit contribution state provide the right ingredients.

**Break:** an open participant can submit a malicious patch, prompt-injected
artifact, poisoned finding, deceptive ontology mapping, benchmark exploit, or
evaluator change. A Sybil cluster can flood the board, monopolize compute,
manufacture apparent consensus, cross-review its own work, or steer shared
memory and routing priors. Even honest agents can create O(N²) attention costs
and starve verification or curation.

**Correction:** treat every participant message, artifact, claim, mapping, and
verifier suggestion as hostile input until admitted. Carry provenance, taint,
license/export, and trust labels; execute untrusted artifacts in bounded
environments; forbid automatic promotion into durable memory, ontology,
routing, authority, or production capability; require independent verification
and separation-of-duty where risk demands it; bound authority, context,
resource, spend, and network blast radius; add rate limits, identity/eligibility
policy, Sybil and collusion signals, reviewer independence, queue backpressure,
fair resource allocation, quarantine, and reversible promotion. Shared
agreement is evidence, never authority or truth by itself.

### Enterprise operations over an ontology

**Fit:** strong conceptual fit. Objects, relationships, mappings, recipes,
restricted views, generated applications, authority, and receipts can make
enterprise work both legible and executable.

**Break:** a monolithic “canonical ontology” would recreate centralized
platform lock-in, while incomplete action contracts leave a gap between an
object graph and real effects.

**Correction:** federated namespace/version/mapping semantics plus executable
ontology action contracts tied to daemon admission, authority, idempotency,
compensation, verification, and receipts.

### Cross-organization autonomous service delivery

**Fit:** AIIP envelopes, delivery lifecycle, restricted views,
`MultiPartyCollaborationEnvelope`, contribution receipts, acceptance, dispute,
and sparse settlement form the right conceptual boundary.

**Break:** AIIP is not implemented; semantic compatibility is not negotiated;
signed statements can be confused with verified outcomes; retry, cancellation,
and ambiguous-effect state need a hard protocol lifecycle.

**Correction:** build a local AIIP profile and conformance harness, then connect
two independently operated nodes. Bind ontology/action profiles, idempotency,
verifier/acceptor roles, assurance levels, and challengeable contribution
claims before depending on L1.

### Sensitive or regulated enterprise workflow

**Fit:** policy-bound views, training-evidence eligibility, provider-trust
separation, cTEE posture, authority distinctions, governed exports, and release
controls are well-shaped.

**Break:** policy-pack precedence and conflicts can become ambiguous; eligibility
revocation must propagate into derived datasets, models, caches, workers, and
releases; raw room context cannot leak across parties.

**Correction:** deterministic policy-composition traces, continuous
obligations, derived-artifact impact/recall, and restricted projections rather
than shared raw context.

### Embodied fleet or warehouse

**Fit:** the architecture correctly separates identity, controller bindings,
sensors/actuators, mission policy, heartbeat/failsafe, operator handoff,
incidents, recovery, local safety vetoes, and evidence.

**Break:** a full daemon/wallet round trip per high-frequency actuator command
is not a viable real-time control model, and per-command proof can become
unbounded.

**Correction:** make the two-speed architecture explicit. The slow governance
plane authorizes a bounded mission/action envelope; a certified local
control-and-safety plane executes high-frequency control inside it, holds the
local e-stop, and emits segment commitments plus exception receipts. Goal
Kernel operates at mission and course-correction timescales, not motor-control
timescales.

### Provider failure during external effects

**Fit:** the existing incident, candidate preview, authority/cost preview,
recovery attempt, WorkRun reconciliation, and receipt spine is strong.

**Break:** restoring an environment does not establish whether an external
provider committed an effect before a timeout. Not all work is safely
replayable.

**Correction:** classify work as replayable, checkpointable, compensatable,
reconciliation-required, or non-retryable. Add explicit ambiguous-effect
reconciliation and compensation receipts, and distinguish environment restore
from outcome restore.

### Recursive improvement

**Fit:** proposal-mediated improvement, evidence eligibility, evaluation,
shadow/canary/rollback, regression records, and governance are correct.

**Break:** governing every observation suffocates learning, while direct
promotion invites reward hacking. Correlated evaluators and reputation loops
can entrench bad priors.

**Correction:** use an epistemic ladder:

```text
cheap observation
  -> branch-local hypothesis or finding
  -> evaluated capability candidate
  -> governed production promotion
```

Add evaluator-integrity incidents, rule-version changes and re-scoring,
verifier diversity, adversarial holdouts, exploration budgets, and
uncertainty-bearing contribution claims.

### Solo local coding or automation

**Fit:** direct harness execution and local-first operation already provide a
simple path.

**Break:** the architecture can become ceremonial if every task appears to
require an ontology, swarm, marketplace, wallet ceremony, or chain.

**Correction:** preserve collapse. One user, one process, one local authority
context, one minimal object contract, and no L1 must remain a first-class
configuration. Complexity should appear only at the boundary that needs it.

## Decisive Course Corrections

### 1. Converge the category story

State one end state: an open, edge-sovereign operating fabric for governed
autonomous systems. Hypervisor is its reference execution/control environment;
the ontology layer is its semantic userspace; they are not peer products.
Productize it as one Goal Space subscription with same-domain multi-worker work
inside the core experience and an opt-in, separately funded Network/Open
contributor scope — not competing single-node and network-node SKUs.

### 2. Promote collective pursuit to a first-class protocol behavior

Define `OutcomeRoom` and its CollaborativeWorkGraph above GoalRuns. Support
private, team, cross-org, and open-challenge modes through policy, not separate
runtimes. Compose existing ioi.ai goal/plan/attempt projections,
HypervisorMission, GoalRun, `MultiPartyCollaborationEnvelope`, Agentgres, and
AIIP; require every room to declare its ordering and admission topology.

### 3. Generalize the Goal Kernel seam

Keep the canonical loop. Replace the assumption that every result is an
implementation patch with a generic `WorkResult`/`OutcomeDelta`; make software
one profile. Allow topology mutation, pull-based claims, dynamic join/retire,
wake conditions, heartbeat, resource offers/backpressure, quarantine, and
marginal-value stop rules. Treat participant inputs as untrusted until admitted.

### 4. Finish the semantic action bridge

Add federated ontology versioning/mapping and a first-class action contract that
binds domain meaning to capability, authority, effect, compensation, evidence,
and verification.

### 5. Prove the network before broadening the suite

Implement AIIP first as a local semantic profile and conformance harness, then
demonstrate one collective pursuit across two independently operated nodes.
This is more important to the Internet-of-Intelligence claim than another
surface or speculative settlement feature.

### 6. Refine proof language into assurance levels

Receipts prove bound boundary facts. Verification, acceptance, adjudication,
and settlement are separate states. Carry those distinctions through the
Verified Work Graph, UI, reputation, and contribution economics.

### 7. Keep blockchains sparse and trust-driven

Do not chainify every GoalRun, autonomous system, tool call, or receipt. Use
deterministic local state and signatures inside domains; use consensus only
where independent ordering, rights, disputes, reputation, or economic finality
requires it.

### 8. Make the operator experience graph-first

Missions/Goal Spaces should render agents as participants in a workstream graph
with claims, leases, evidence, evaluations, costs, and authority — not as chat
bubbles or a hidden process list. Existing applications remain drill-down
lenses.

### 9. Make embodied execution explicitly two-speed

Separate mission-level intelligence and authority from certified local
real-time control. Hypervising the mission must not imply a network round trip
inside the motor loop.

### 10. Delay precision economics until contribution assurance works

Do not tokenize ambiguous quality deltas. First make attempts reproducible,
verification independent, acceptance explicit, disputes resolvable, derivation
traceable, and negative contributions creditable. Settlement rails can remain
chain-agnostic until public finality is needed.

## Recommended Build Sequence

### Phase 0 — Contract convergence

- define `OutcomeRoom`, `RoomParticipantLease`, `WorkFrontierItem`,
  `WorkClaimLease`, `ResourceOffer`/`CapabilityOffer`, `Attempt`, `Finding`,
  `VerifierChallenge`, and generic `WorkResult`/`OutcomeDelta`;
- define room visibility, participation, coordination/admission, ordering,
  artifact license/export, and settlement policies;
- bind model/provider routes to access mode, unattended-automation,
  downstream-application, credential-principal, and output-training rights;
- replace flat per-receipt model metering with invoice-grade route-attempt,
  price-schedule, supplier-cost, fee-basis, adjustment, and reconciliation
  receipts before attaching a paid Work Credit allowance;
- add ontology namespace/version/mapping and semantic action contracts;
- add the assurance ladder and verifier/rule versioning;
- map the objects onto `IoiAiGoal`, `IoiAiOutcomePlan`,
  `IoiAiAttemptSummary`, `IoiAiCrossSessionOutcomeGraph`, GoalRun, Missions,
  `MultiPartyCollaborationEnvelope`, Evaluations, Provenance, Governance,
  Agentgres, and AIIP owners without creating a new runtime.

### Phase 1 — Single-node reference pursuit

Build a permissioned collaborative engineering or research room on one
Hypervisor Node:

- operate a disclosed IOI seed mesh of named planner, builder, verifier,
  critic, and synthesizer Worker compositions;
- mount cognition through open/self-hosted weights, commercial APIs, dedicated
  endpoints, or expressly permitted user-scoped BYOA routes — not pooled
  enterprise workspace seats;
- preserve worker, model-route, runtime-node, provider, and operator affiliation
  as separate identities;
- label the entire IOI-operated mesh honestly as one party;
- heterogeneous agents join and advertise capabilities;
- the room names one governed host domain for ordering and admission;
- agents claim frontier items through leases;
- resource offers, allocation, backpressure, spend, and fairness are visible;
- attempts run in isolated branches/workspaces;
- participant inputs remain tainted until policy and verification admit them;
- positive and negative results remain durable;
- findings and shared playbooks update the frontier;
- a verifier separated from candidate execution admits results, without yet
  claiming independent-party verification;
- verifier challenges can change a rule and trigger re-evaluation;
- Missions shows live participants, claims, costs, blockers, evidence, and
  replay;
- ContributionReceipts preserve derivation and non-winning value.

Use a software or model-optimization task as the first profile because current
GoalRun machinery can support it, but implement the contracts generically.

### Phase 2 — Two sovereign nodes

Run the same pursuit across two independently operated Hypervisor/Agentgres
domains via AIIP:

- begin with a customer/data-owner domain and the IOI coordinator/managed-worker
  domain, then add an independently operated worker provider and verifier;
- no shared raw operational database;
- a declared hosted or federated coordination policy owns room-level ordering,
  admission, conflicts, and failover;
- `MultiPartyCollaborationEnvelope` owns the shared policy/proof boundary;
- negotiated ontology/action profiles;
- policy-bound context and restricted views;
- cross-domain claim/attempt/evidence exchange;
- independent verification and acceptance;
- portable contribution lineage and dispute state;
- no L1 dependency for ordinary operation.

This is the minimum credible Internet-of-Intelligence proof.

### Phase 3 — Team and open challenge service

Expose the same substrate through ioi.ai as Goal Spaces:

- persistent private collaborative goal;
- organization mission;
- invited cross-org pursuit;
- open challenge.

Add resource offers, marketplace sourcing, anti-spam/Sybil controls,
permissioned visibility, public projections, multi-objective leaderboards, and
a separately funded sponsor budget/bounty or service order. Add settlement only
where useful; do not hide external worker spend inside the ordinary seat
allowance.

### Phase 4 — Enterprise and embodied verticals

Apply the proven collaboration fabric to a federated enterprise operations
domain and an embodied mission. This validates semantic negotiation, restricted
views, two-speed control, audit, liability, and local authority under conditions
that an open benchmark does not exercise.

### Phase 5 — Public economic commitments

Only after repeated verified demand should IOI attach public reputation roots,
rights, bonds, dispute finality, or token economics to selected contributions.

## The North-Star Conformance Demonstration

IOI should be able to demonstrate this without hand-waving:

```text
an organization opens an ontology-bound OutcomeRoom
  -> the room declares its coordination/admission topology and shared-state owner
  -> one local agent and one independently operated external agent discover it
  -> each negotiates a permitted semantic view
  -> each claims bounded work and receives distinct context/resource/authority leases
  -> attempts execute in isolated domains
  -> every external message, artifact, mapping, and evaluator suggestion stays tainted until admitted
  -> one result succeeds, one result is negative but eliminates a false path
  -> a third participant challenges an evaluator weakness
  -> the verifier policy changes and affected attempts are re-evaluated
  -> accepted findings update the shared frontier and capability proposal
  -> contribution lineage credits execution, negative information, and verifier hardening
  -> the user sees objective, topology, evidence, spend, authority, and replay
  -> each domain retains local truth and private context
  -> only selected contribution/settlement commitments leave the domains
```

If that works through open contracts and independently operated nodes, IOI has
demonstrated an Internet of Intelligence rather than merely named one.

## Anti-Goals

Do not build:

- a separate swarm runtime or permanent Swarm application;
- separate single-node and network-node products when one Goal Space with
  contributor-scope policy suffices;
- a universal central conductor that every agent must trust;
- an implicitly global mutable Agentgres graph without a declared room
  coordination/admission topology;
- one global enterprise ontology or knowledge graph;
- pooled, shared, browser-automated, or resold enterprise chat/workspace seats
  treated as production worker capacity;
- raw foundation-model endpoints presented as accountable Worker identities;
- multiple IOI-owned workers, keys, clouds, or model vendors presented as
  independent parties;
- a chat room presented as a collaboration protocol;
- automatic promotion of participant messages, artifacts, findings, mappings,
  or evaluator changes into memory, ontology, routing, authority, or production;
- an autonomous-system chain per agent by default;
- L1 transactions for local cognition, tool calls, workflow steps, or routine
  receipts;
- one scalar leaderboard as universal intelligence or contribution truth;
- background agents that are invisible except for token streams;
- unlimited multi-model or multi-worker managed burn hidden inside a flat
  subscription price;
- Type 1 infrastructure breadth that delays Type 3 semantic-action proof;
- precise token rewards before verification, acceptance, derivation, and
  disputes are credible.

## Final Thesis

The architecture is not choosing between an autonomy hypervisor and a
decentralized ontology operating environment. Its winning form requires both.

The ontology plane tells autonomous systems what the world means and which
actions exist. The hypervisor plane determines where those systems run and
whether they may act. Machine authority makes power explicit. Agentgres makes
state and evidence durable. Goal Kernel gives each bounded intelligence a
repeatable pursue/verify/course-correct loop. The collaborative work graph lets
many such intelligences create more value together than a single conductor can.
AIIP makes the collaboration cross sovereign boundaries. Sparse settlement
makes selected contributions economically portable without turning all work
into chain traffic.

The product expression should be equally unified: one subscribed Goal Space
experience, same-domain multi-worker orchestration as the useful default, an
opt-in Network/Open supply lane for genuine independent parties, and a
transparent IOI seed fleet procured through lawful inference capacity. The
subscription monetizes the conductor and ordinary work; Work Credits meter
managed execution; goal budgets and network fees fund real external labor,
verification, assurance, and settlement.

The direction is right. The necessary course correction is to make **open,
adaptive, cross-node collective pursuit** a first-class protocol behavior, not
merely a public-dashboard variant of a sophisticated single-owner GoalRun.

## Grounding

### Current canonical architecture

- [Hypervisor Core, clients, and surfaces](../../docs/architecture/components/hypervisor/core-clients-surfaces.md)
- [Domain Ontologies and Data Recipes](../../docs/architecture/foundations/domain-ontologies-and-data-recipes.md)
- [Governed Autonomous Systems and Hypervisor Nodes](../../docs/architecture/foundations/governed-autonomous-systems.md)
- [Common Objects and Envelopes](../../docs/architecture/foundations/common-objects-and-envelopes.md)
- [ioi.ai Collaborative Outcome Pattern](../../docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md)
- [Canonical Web4 and the IOI Stack](../../docs/architecture/foundations/web4-and-ioi-stack.md)
- [Architecture invariants](../../docs/architecture/foundations/invariants.md)
- [AIIP](../../docs/architecture/foundations/aiip.md)
- [Mixture of Workers](../../docs/architecture/foundations/mixture-of-workers.md)
- [Model Router API, BYOK, and Mounting](../../docs/architecture/components/model-router/api-byok-mounting.md)
- [Marketplace Neutrality and Contribution Accounting](../../docs/architecture/domains/marketplace-neutrality.md)
- [aiagent.xyz Worker Marketplace](../../docs/architecture/domains/aiagent/worker-marketplace.md)
- [Agentgres doctrine](../../docs/architecture/components/agentgres/doctrine.md)
- [wallet.network doctrine](../../docs/architecture/components/wallet-network/doctrine.md)
- [Economic Flywheel and Pricing Boundaries](../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md)
- [Physical Action Safety](../../docs/architecture/foundations/physical-action-safety.md)
- [Embodied Runtime](../../docs/architecture/components/daemon-runtime/embodied-runtime.md)
- [Architecture implementation matrix](../../docs/architecture/_meta/implementation-matrix.md)

### Current implementation evidence

- [GoalRun daemon routes](../../crates/node/src/bin/hypervisor_daemon_routes/goalrun_routes.rs)
- [GoalRun admission planner](../../crates/services/src/agentic/runtime/kernel/runtime_goal_run_admission.rs)
- [GoalRun multi-harness verifier](../../apps/hypervisor/scripts/verify-hypervisor-goalrun-multi-harness.mjs)
- [Current OCU receipt metering](../../crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs)
- [Current model-route execution and BYOK gaps](../../crates/node/src/bin/hypervisor_daemon_routes/model_routes.rs)

### Existing internal pressure tests

- [Embodied fleet incident](../prompts/hypervisor-pressure-tests/results/01-embodied-fleet-incident-result.md)
- [Cross-domain AIIP service delivery](../prompts/hypervisor-pressure-tests/results/04-cross-domain-aiip-service-delivery-result.md)
- [Sensitive enterprise data](../prompts/hypervisor-pressure-tests/results/05-sensitive-enterprise-data-to-model-conductor-result.md)
- [Provider failure and recovery](../prompts/hypervisor-pressure-tests/results/06-provider-failure-domain-recovery-result.md)
- [Recursive improvement regression](../prompts/hypervisor-pressure-tests/results/09-recursive-improvement-regression-result.md)
- [Multi-organization collaboration](../prompts/hypervisor-pressure-tests/results/10-multi-org-collaboration-result.md)

### External primary references

- [Fast Gemma Challenge](https://huggingface.co/gemma-challenge)
- [Fast Gemma agent workspace guide](https://huggingface.co/buckets/gemma-challenge/gemma-main-bucket/tree/README.md)
- [RL-LLM Wiki collaboration workspace](https://huggingface.co/buckets/rl-llm-wiki/rl-main-bucket)
- [RL-LLM Wiki public knowledge base](https://huggingface.co/datasets/rl-llm-wiki/knowledge-base)
- [RL-LLM Wiki Collab Replay](https://rl-llm-wiki-rl-dashboard.hf.space/replay.html)
- [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
- [OpenAI subscription and API separation](https://help.openai.com/en/articles/8156019)
- [Anthropic paid-plan and API separation](https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-do-i-have-to-pay-separately-to-use-the-claude-api-and-console)
- [OpenRouter pricing](https://openrouter.ai/pricing)
- [OpenRouter terms](https://openrouter.ai/terms/)
- [OpenRouter enterprise](https://openrouter.ai/enterprise/)
- [OpenRouter routing and fallback controls](https://openrouter.ai/docs/guides/routing/provider-selection)
- [OpenRouter zero-data-retention controls](https://openrouter.ai/docs/guides/features/zdr)

The public challenge dashboards and counts are live. This synthesis relies on
their durable coordination mechanics, not on a particular historical agent
count, message count, or leaderboard score.
