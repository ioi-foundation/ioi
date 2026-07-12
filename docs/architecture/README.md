# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (navigation index over built, partial, planned, and speculative subjects)
Last implementation audit: 2026-07-11

## Purpose

This directory is the tracked architecture and product-doctrine authority for
IOI. It separates owner documents by subject so implementation, product copy,
protocol schemas, and the whitepaper can converge on one target without turning
any synthesis or UI into a competing source of truth.

Start with [`START_HERE.md`](./START_HERE.md). Then use:

- [`current-canon-defaults.md`](./_meta/current-canon-defaults.md) for the
  cross-owner target-state digest;
- [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) before changing a
  subject;
- [`implementation-matrix.md`](./_meta/implementation-matrix.md) before making
  a built/partial/planned claim;
- [`execution-horizons.md`](./_meta/execution-horizons.md) to distinguish the
  convergence target from later gated horizons;
- [`vocabulary.md`](./_meta/vocabulary.md) and
  [`canonical-enums.md`](./foundations/canonical-enums.md) for shared names and
  values.

[`whitepaper.tex`](./whitepaper.tex) is the publishing synthesis. It is not the
owner of component doctrine. Ignored guides, prompt packs, reverse-engineering
notes, captures, and archived specs are evidence or workbench material, not
parallel canon.

## Category And Target End State

IOI is a unified operating fabric for governed autonomous systems and the
Internet of Intelligence:

> Intelligence may reason and execute anywhere; consequential effects cross a
> governed boundary; domains retain local truth; typed intelligence and work
> move between domains; only selected commitments settle publicly.

The target joins two complementary architecture directions:

- Hypervisor is the open operating substrate for infrastructure and governed
  autonomy: models, workers, harnesses, tools, services, connectors, memory,
  VMs, containers, GPUs, remote nodes, and embodied systems share one control,
  authority, receipt, replay, and state fabric.
- Goal Space plus the federated semantic/collaboration plane is the open
  operating environment for distributed intelligence: participants coordinate
  around shared outcomes, explicit ontologies, leased work, findings,
  verification, contribution lineage, and cross-domain handoffs without one
  global Palantir-like database owning every domain.

The architecture is edge-in. Work begins near users, data, tools, providers,
and physical systems; Agentgres admits operational truth inside bounded
domains; AIIP connects domains; IOI L1 receives sparse public commitments when
rights, settlement, registry, dispute, governance, or cross-domain trust
requires them.

## Canonical Stack

```text
Product and collaboration
  ioi.ai Goal Space
  Hypervisor App / Web / CLI-headless / optional TUI
  Studio / Automations / Ontology / Data / Governance / Missions / Provenance /
  Evaluations / Improvement / Foundry / Marketplace / Workbench / Developer Console
  aiagent.xyz / sas.xyz / wallet.network

Shared pursuit
  OutcomeRoom / CollaborativeWorkGraph
  participants / resource and capability offers / frontier / claims
  attempts / findings / verifier challenges / contribution lineage / replay

Bounded execution
  GoalRun / GoalGroundingLoop / RoleTopology
  ContextCells / leases / typed handoffs / HarnessInvocations
  WorkResult / OutcomeDelta

Operating substrate
  Hypervisor Core and Hypervisor Daemon
  Type 1 HypervisorOS / Type 2 workstation / Type 3 autonomy plane
  model router / connectors / runtimes / provider and environment plane

Authority, truth, memory, and evidence
  wallet.network plus local/domain policy and authority providers
  Agentgres operations, object heads, projections, and state roots
  MemorySpace and policy-filtered MemoryProjections
  receipts, evidence bundles, verification, acceptance, replay, artifacts

Federation and settlement
  Domain Ontologies / overlays / crosswalks / semantic mapping decisions
  OntologyActionContracts
  AIIP between bounded execution domains
  IOI L1 for selected public commitments
```

Stable product taxonomy:

```text
IOI daemon = hypervisor/control plane for autonomous execution
Hypervisor App/Web/CLI-headless = first-class clients over Hypervisor Core
Hypervisor Workbench/Automations/Foundry = application surfaces over Hypervisor Core
IOI Authority Gateway = compatibility adapter profile
```

## Decisions That Define The Target

### Goal Space is the primary managed product

ioi.ai should provide one Goal Space subscription: persistent conductor and
goal state, portable memory, policy, receipts, replay, collaboration, support,
and a bounded grant of non-transferable Work Credits. Additional managed work
uses top-ups, overage, or committed spend. Network/Open contributors use a
separate goal budget, bounty, procurement cap, or service order.

IOI must not pool or resell named-human ChatGPT, Claude, or similar workspace
subscriptions as production worker capacity. Supply is a plural portfolio of
direct and dedicated provider routes, replaceable aggregators such as
OpenRouter, customer BYOK/BYOA when permitted, and open/self-hosted weights.
Every candidate route must resolve an explicit versioned rights contract.

### OutcomeRoom is above GoalRun

`OutcomeRoom` is the durable shared-pursuit container;
`CollaborativeWorkGraph` is its admitted participant/frontier/claim/attempt/
finding/evaluation graph. A room may coordinate many bounded `GoalRun` objects.
It is not a runtime, global graph, marketplace, or authority plane.

`GoalRun` remains a generic, loop-native kernel that orients, plans, acts,
observes, verifies, course-corrects, and closes or escalates. Simple work
collapses to direct execution. `WorkResult` and `OutcomeDelta` are generic;
`ImplementationResultPayload` is the software profile.

### Plurality dimensions stay distinct

Multi-model, multi-worker, multi-node, and multi-party are different claims.
Only multi-party collaboration implies independently governed principals, and
even that does not imply a trustworthy result without evidence, verification,
acceptance, and dispute semantics.

### The semantic plane is federated

No ontology or Agentgres database is presumed globally canonical. Domains own
local ontology versions, overlays, assertions, provenance, valid and
transaction time, uncertainty, contradictions, and disputes. Cross-domain work
uses explicit crosswalks and receipted, challengeable mapping decisions.

Semantic meaning does not grant authority. Consequential actions compile to an
`OntologyActionContract` and then pass capability, policy, authority, daemon,
evidence, and verification gates.

### Authority and execution are separate

Policy and authority providers authorize. The Hypervisor Daemon admits,
enforces, schedules, executes or mediates, receipts, and fails closed.
wallet.network is mandatory for portable delegated authority and the high-risk
external actions assigned to it; local/domain governance may own local
authority where canon permits.

### Receipts are not the final assurance claim

Assurance remains explicit across `attested`, `evidenced`, `verified`,
`accepted`, `adjudicated`, and `settled`. The Verified Work Graph is the
cross-domain provenance and economic memory over those stages, including
negative, inconclusive, invalid, superseded, disputed, and exploit-finding work.

### Physical and external effects require recovery semantics

Actions declare replayable, checkpointable, compensatable,
reconciliation-required, or non-retryable recovery posture. A timeout after a
possible external effect is ambiguous. Environment restore is not outcome
reconciliation.

Embodied systems use a two-speed architecture: deterministic local safety and
control stays available below the slower intelligence/mission loop. Models may
propose physical action segments; they do not become safety heartbeats or
emergency-stop authorities.

## Navigation And Ownership

### Meta canon

| File | Owns |
| --- | --- |
| [`start-here.md`](./_meta/start-here.md) | reader orientation and reading paths |
| [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) | edit-first subject ownership |
| [`current-canon-defaults.md`](./_meta/current-canon-defaults.md) | cross-owner defaults |
| [`vocabulary.md`](./_meta/vocabulary.md) | shared names and boundary terms |
| [`implementation-matrix.md`](./_meta/implementation-matrix.md) | durable forms, status, code anchors, conformance hooks |
| [`execution-horizons.md`](./_meta/execution-horizons.md) | convergence target and gated later horizons |
| [`doc-classes.md`](./_meta/doc-classes.md) | document classes and authority order |
| [`decisions/README.md`](../decisions/README.md) | accepted architecture decision records |

### Foundation owners

| Area | Canonical owners |
| --- | --- |
| stack and category | [`web4-and-ioi-stack.md`](./foundations/web4-and-ioi-stack.md), [`verifiable-bounded-agency.md`](./foundations/verifiable-bounded-agency.md) |
| invariants and security | [`invariants.md`](./foundations/invariants.md), [`security-privacy-policy-invariants.md`](./foundations/security-privacy-policy-invariants.md) |
| shared objects and values | [`common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md), [`canonical-enums.md`](./foundations/canonical-enums.md) |
| domains and autonomous systems | [`domain-kernels.md`](./foundations/domain-kernels.md), [`governed-autonomous-systems.md`](./foundations/governed-autonomous-systems.md) |
| semantic world plane | [`domain-ontologies-and-data-recipes.md`](./foundations/domain-ontologies-and-data-recipes.md) |
| worker routing and training | [`mixture-of-workers.md`](./foundations/mixture-of-workers.md), [`worker-training-lifecycle.md`](./foundations/worker-training-lifecycle.md) |
| interop | [`aiip.md`](./foundations/aiip.md) |
| physical safety | [`physical-action-safety.md`](./foundations/physical-action-safety.md) |
| economics | [`economic-flywheel-and-pricing-boundaries.md`](./foundations/economic-flywheel-and-pricing-boundaries.md) |
| ecosystem assurance | [`ecosystem-assurance-certification-liability.md`](./foundations/ecosystem-assurance-certification-liability.md) |
| public settlement | [`ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md), [`ioi-l1-contract-interfaces.md`](./foundations/ioi-l1-contract-interfaces.md) |

### Component owners

| Area | Canonical owners |
| --- | --- |
| daemon runtime | [`doctrine.md`](./components/daemon-runtime/doctrine.md), [`api.md`](./components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md), [`task-capsule-protocol.md`](./components/daemon-runtime/task-capsule-protocol.md) |
| Goal Kernel and harnesses | [`default-harness-profile.md`](./components/daemon-runtime/default-harness-profile.md) |
| portable memory | [`portable-memory-vault.md`](./components/daemon-runtime/portable-memory-vault.md) |
| improvement gates | [`improvement-governance-gates.md`](./components/daemon-runtime/improvement-governance-gates.md) |
| privacy and nodes | [`private-workspace-ctee.md`](./components/daemon-runtime/private-workspace-ctee.md), [`runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md), [`hypervisoros.md`](./components/daemon-runtime/hypervisoros.md) |
| embodied runtime | [`embodied-runtime.md`](./components/daemon-runtime/embodied-runtime.md) |
| Hypervisor product | [`core-clients-surfaces.md`](./components/hypervisor/core-clients-surfaces.md), [`providers-and-environments.md`](./components/hypervisor/providers-and-environments.md), [`foundry.md`](./components/hypervisor/foundry.md) |
| Hypervisor identity and supply | [`identity-access-and-metering.md`](./components/hypervisor/identity-access-and-metering.md), [`byo-provider-plane.md`](./components/hypervisor/byo-provider-plane.md) |
| model routing | [`doctrine.md`](./components/model-router/doctrine.md), [`api-byok-mounting.md`](./components/model-router/api-byok-mounting.md) |
| Agentgres | [`doctrine.md`](./components/agentgres/doctrine.md), [`api-object-model.md`](./components/agentgres/api-object-model.md), [`artifact-ref-plane.md`](./components/agentgres/artifact-ref-plane.md), [`projection-system-reference.md`](./components/agentgres/projection-system-reference.md), [`postgres-bridge-and-readiness-contract.md`](./components/agentgres/postgres-bridge-and-readiness-contract.md) |
| wallet authority | [`doctrine.md`](./components/wallet-network/doctrine.md), [`api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md), [`product-exchange-risk.md`](./components/wallet-network/product-exchange-risk.md) |
| connectors and tools | [`doctrine.md`](./components/connectors-tools/doctrine.md), [`contracts.md`](./components/connectors-tools/contracts.md) |
| storage | [`doctrine.md`](./components/storage-backends/doctrine.md), [`filecoin-cas.md`](./components/storage-backends/filecoin-cas.md) |

Some link labels repeat because the owner path, not the basename, carries the
namespace.

### Product and application-domain owners

| Domain | Canonical owners |
| --- | --- |
| ioi.ai Goal Space | [`collaborative-outcome-pattern.md`](./domains/ioi-ai/collaborative-outcome-pattern.md), [`control-plane.md`](./domains/ioi-ai/control-plane.md) |
| aiagent.xyz ontology-bound digital and embodied workers | [`worker-marketplace.md`](./domains/aiagent/worker-marketplace.md), [`digital-worker-ontology.md`](./domains/aiagent/digital-worker-ontology.md), [`vertical-ontology-packs.md`](./domains/aiagent/vertical-ontology-packs.md), [`integration-surface-taxonomy.md`](./domains/aiagent/integration-surface-taxonomy.md), [`managed-worker-instance-lifecycle.md`](./domains/aiagent/managed-worker-instance-lifecycle.md), [`managed-agent-console-contract.md`](./domains/aiagent/managed-agent-console-contract.md), [`worker-endpoints.md`](./domains/aiagent/worker-endpoints.md) |
| sas.xyz | [`service-marketplace.md`](./domains/sas/service-marketplace.md), [`service-endpoints.md`](./domains/sas/service-endpoints.md) |
| marketplace neutrality | [`marketplace-neutrality.md`](./domains/marketplace-neutrality.md) |
| decentralized route intelligence | [`README.md`](./domains/decentralized/README.md), [`exchange.md`](./domains/decentralized/exchange.md), [`trade.md`](./domains/decentralized/trade.md), [`cloud.md`](./domains/decentralized/cloud.md) |

## Runtime And Product Boundaries

| Layer or product | Owns | Does not own |
| --- | --- | --- |
| ioi.ai Goal Space | goals, plans, room/workstream UX, subscription and budget controls, synthesis | execution effects, wallet authority, global truth |
| OutcomeRoom | shared-pursuit policy and graph | runtime, marketplace, authority, global database |
| GoalRun | bounded loop and typed orchestration | global collaboration or permanent memory |
| Hypervisor Core | shared client/control substrate | independent authority or truth beside daemon/Agentgres |
| Hypervisor Daemon | admission, scheduling, mediation/execution, receipts, fail-closed runtime boundary | inventing authority or universal truth |
| HypervisorOS | daemon-rooted bare-metal profile and node integrity | confidential-compute claim by itself |
| wallet.network | portable delegated and designated high-risk authority | runtime execution or operational truth |
| Agentgres | admitted domain-local operations, object heads, projections, roots | all memory, payload bytes, or one global graph |
| MemorySpace | portable governed memory truth | runtime admission or public settlement |
| storage backends | payload bytes and availability | semantic meaning or authority |
| model router | eligible cognition route selection and invocation | accountable labor actor or provider-seat resale |
| AIIP | typed inter-domain work, evidence, authority refs, disputes, settlement intents | remote database access or global sequence |
| IOI L1 | selected public registry, rights, economics, disputes, governance, roots | per-step runtime or operational notebook |

## North-Star Network Proof

IOI has demonstrated an Internet of Intelligence only when an independently
operated external Worker can discover eligible work through a policy-bound
projection, negotiate semantic/action profiles, submit a typed participation
request, receive bounded context/resource/authority/budget leases, claim work,
return a verifiable contribution, preserve credit and dispute lineage, and exit
with portable permitted state. The proof must not require participants to share
one runtime, operational database, administrator, or continued trust/access to
an IOI-hosted room. Same-owner multi-model, multi-worker, or multi-node
orchestration is useful seed behavior, but it is not this network proof.

## Non-Negotiables

1. There is one governed operating fabric, not a daemon plus competing hidden
   runtimes in apps, harnesses, SDKs, editors, or provider adapters.
2. Hypervisor Type 1, Type 2, and Type 3 are deployment/control postures of one
   product, not three disconnected products.
3. OutcomeRoom is above GoalRun. Neither is one global graph or ambient swarm.
4. GoalRun is generic and loop-native; coding-specific files/diffs/tests live in
   the ImplementationResult profile, not the universal WorkResult contract.
5. Simple work collapses to a direct path. Parallelism and collaboration must
   earn their cost through uncertainty, expected value, independence, or
   verification need.
6. Multi-model, multi-worker, multi-node, and multi-party claims remain
   separate in schemas, UI, receipts, and economics.
7. Participants and claims are explicit leases with scope, TTL, heartbeat,
   policy, visibility, authority, resource, and budget bounds.
8. Domain Ontologies and Agentgres truth are locally canonical. Cross-domain
   semantics require explicit versions, crosswalks, mapping decisions, and
   challenges.
9. Ontology semantics do not grant capability or authority.
10. Policy and authority providers authorize; the daemon admits, enforces,
    executes or mediates, receipts, and fails closed.
11. Workers receive declared `prim:*` capabilities and bounded `scope:*`
    authority grants, not ambient raw secrets or unlimited credentials.
12. Worker is the accountable labor actor; model is cognition; harness is an
    execution adapter/profile; runtime node is placement; party is an
    independently governed principal.
13. Named-human foundation-model subscriptions are not pooled, automated, or
    resold as production worker capacity unless an explicit provider agreement
    authorizes the exact use.
14. Every managed model route has a versioned rights contract. Missing rights
    fail closed; provider fallback is a semantic substitution.
15. OpenRouter or another aggregator is a replaceable supply adapter, not the
    product moat, sole trust boundary, or excuse to ignore underlying terms.
16. Inference permission does not imply output-training, distillation, resale,
    or OEM rights.
17. Work Credits are bounded non-transferable product budget, not cash, provider
    tokens, pooled seats, worker payout, or the IOI protocol token.
18. Network/Open work uses explicit separate funding and preserves marketplace,
    service, verifier, attribution, dispute, and settlement owner boundaries.
19. A receipt is attributable evidence, not automatic correctness, truth,
    verification, acceptance, adjudication, settlement, or payout.
20. Assurance stages remain explicit from attested through settled and preserve
    negative, inconclusive, invalid, exploit, superseded, disputed, and no-fault
    information.
21. Effect recovery is typed. Ambiguous external effects reconcile before
    retry; restore is not reconciliation.
22. Persistent intelligence belongs to governed MemorySpace and Agentgres
    admission, not the selected model, harness, or local cache.
23. Improvement remains proposal-driven and gated by evaluation, policy,
    authority, receipts, rollback, and Agentgres admission.
24. Private/no-provider-trust claims require a custody-proven route. Contractual
    provider privacy is useful but is not cTEE no-plaintext custody.
25. Embodied action uses deterministic local safety/control beneath a slower
    intelligence loop; emergency stop cannot depend on a model, cloud, chain,
    or stale telemetry.
26. Storage backends hold bytes; Agentgres refs define meaning, lifecycle,
    integrity, policy/authority linkage, and restore validity.
27. AIIP transports bounded signed handoffs and refs while each domain keeps
    local truth. It is not raw remote database access.
28. IOI L1 is sparse settlement and coordination, not the per-thought or
    per-tool execution database.
29. Product surfaces monetize real product value. Substrates meter, attest,
    authorize, record, or settle; token economics activate only with real
    verified network demand.
30. UI boards, chat, leaderboards, replays, and admin consoles are projections.
    They never become authority or canonical runtime truth by convenience.

## Implementation Discipline

The target architecture is not a claim that every target object is built.
Consult [`implementation-matrix.md`](./_meta/implementation-matrix.md) for the
current durable form and code anchors. In particular, the existing narrow
software GoalRun is partial implementation; OutcomeRoom federation,
collaborative AIIP, full route-right enforcement, invoice-grade Work Credits,
the complete semantic action plane, and cross-domain assurance remain target
work unless the matrix is updated with current proof.

When implementing:

```text
owner doc -> shared objects/enums -> API/envelope -> daemon/domain admission
          -> receipt/evidence -> Agentgres truth/projection -> conformance
```

Run the architecture documentation checks before claiming alignment:

```bash
npm run check:architecture-docs
git diff --check -- docs/architecture
```
