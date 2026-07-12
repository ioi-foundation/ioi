# Start Here

Status: canonical reader entry point.
Canonical owner: this file for first-read architecture orientation and role-based reading paths.
Supersedes: ad hoc onboarding paths across architecture docs.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (reader entry point over built, partial, planned, and speculative subjects)
Last implementation audit: 2026-07-11

## Five-Minute Mental Model

IOI is a unified operating fabric for governed autonomous systems and the
Internet of Intelligence. It combines two complementary directions:

1. a Hypervisor substrate that mounts models, workers, tools, services,
   runtimes, infrastructure, memory, and embodied systems behind one governed
   effect boundary; and
2. a federated semantic and collaboration fabric in which people,
   organizations, workers, services, and autonomous-system domains can pursue
   shared outcomes without surrendering local truth or authority to one global
   database.

The first direction makes intelligence executable and governable. The second
makes independently owned intelligence composable. Neither replaces the other.

```text
Goal Space (ioi.ai)
  durable goals, subscriptions, budgets, collaboration, replay, outcome UX
  -> OutcomeRoom / CollaborativeWorkGraph when shared pursuit is useful
     -> one or more bounded GoalRuns
        -> GoalGroundingLoop and RoleTopology
           -> ContextCells, claims, leases, typed handoffs, attempts
              -> Workers composed from models, harnesses, tools, and services

Hypervisor
  one control plane across Type 1 bare-metal, Type 2 workstation, and
  Type 3 governed-autonomy postures
  -> Hypervisor Daemon admits and mediates effects
  -> Agentgres records admitted operational truth
  -> artifact/storage planes hold governed payloads
  -> wallet.network and local/domain policy supply authority

Federated semantic world plane
  local Domain Ontologies, assertions, overlays, and action contracts
  <-> explicit crosswalks and challengeable mapping decisions
  <-> AIIP signed handoffs between bounded execution domains

Sparse public coordination
  local work stays local by default
  -> IOI L1 only for selected rights, registry, economic, dispute,
     governance, or cross-domain commitments
```

This is not a choice between a “hypervisor app” and a decentralized enterprise
ontology. Hypervisor is the execution and operating substrate; Goal Space and
the semantic/collaboration planes are how many intelligences and domains use
that substrate to converge on open or private outcomes.

## The Core Product Shape

### Goal Space

ioi.ai should sell one coherent Goal Space subscription rather than a bundle of
pooled model seats. The subscription includes persistent conductor state,
portable memory, private and organization goals, governance, collaboration,
receipts, replay, and a bounded grant of non-transferable Work Credits.

Managed model and runtime supply is a portfolio:

- direct provider APIs, dedicated capacity, and negotiated inference;
- replaceable aggregators such as OpenRouter for breadth and discovery;
- customer BYOK or provider-approved user-scoped BYOA;
- open-weight, local, customer-boundary, and self-hosted routes.

Every route resolves a versioned commercial and technical rights contract.
Named-human ChatGPT, Claude, or similar subscriptions are not pooled production
worker capacity. Missing automation, downstream, OEM/reseller, data, region,
credential-principal, or output-training rights fail closed.

The user controls independent axes:

- execution/custody: `Standard` or `Private`;
- goal routing: `Auto`, `Pinned`, or `Compare`;
- contributors: `My workers`, `Organization`, or `Network / Open`;
- placement: local, customer infrastructure, selected cloud, or Hypervisor
  choice.

Network/Open contribution uses a separate funded goal budget, bounty,
procurement cap, or sas.xyz service order. It must not silently burn an
ordinary seat allowance.

### OutcomeRoom And GoalRun

An `OutcomeRoom` is the durable shared-pursuit container. Its
`CollaborativeWorkGraph` records admitted participants, offers, frontier items,
leased claims, attempts, findings, verifier challenges, contribution lineage,
discussion projections, and replay. Goal Space workstreams and Hypervisor
Mission detail are projections over this same graph.

A `GoalRun` is a bounded execution unit below an optional OutcomeRoom. Its
generic loop is:

```text
orient -> plan -> implement/act -> observe -> verify -> course-correct
       -> continue, escalate, hand off, reconcile, or close
```

The kernel should be generic and loop-native. It should not be a global swarm,
a hard-coded coding loop, or a chat transcript. Simple work collapses to one
direct path. Hard or uncertain work may fan out across models, workers,
verifiers, sessions, or parties when expected value justifies the added cost.

`WorkResult` and `OutcomeDelta` are the generic result seam.
`ImplementationResultPayload` is only the software-implementation profile.

### Hypervisor

Hypervisor is one operating fabric with three complementary postures:

- Type 1: HypervisorOS bare-metal, appliance, and cluster substrate;
- Type 2: desktop/workstation hosting of local environments, models, tools,
  VMs, containers, microVMs, and sandboxes;
- Type 3: the autonomy plane for sessions, workers, goals, authority, receipts,
  replay, outcomes, and governed improvement.

Hypervisor App, Hypervisor Web, CLI/headless, optional TUI, SDK, ADK, the
application suite (Studio with its agent lens, Automations, Ontology, Data,
Governance, Missions, Provenance, Evaluations, Improvement, Foundry,
Marketplace, Workbench, Developer Console), the Environments and Operations
substrate lane, generated domain apps, and Robot Fleets are clients, builder
surfaces, or projections over the same Core. ODK is the developer kit beneath
Ontology and Data; the former Work Ledger card converges in Provenance. They do not create private runtime
truth beside the daemon.

### Federated Ontology And Action

There is no universal enterprise graph. Each domain owns local ontology
versions, overlays, assertions, valid time, transaction time, provenance,
uncertainty, contradictions, supersession, and disputes. Cross-domain work uses
explicit `OntologyCrosswalk` and `SemanticMappingDecision` objects.

Semantic meaning never grants power. A consequential ontology action becomes
executable only through an `OntologyActionContract` binding typed IO,
preconditions, postconditions, state transition, capability, runtime, policy,
authority, risk, idempotency, ambiguous-effect recovery, compensation,
verification, evidence, receipts, and physical safety where applicable.

### Internet Of Intelligence

IOI facilitates an Internet of Intelligence when it preserves all four forms
of plurality instead of conflating them:

| Plurality | What changes | What it does not prove |
| --- | --- | --- |
| Multi-model | cognition routes | independent workers or parties |
| Multi-worker | accountable labor actors | independent infrastructure or governance |
| Multi-node | placement, custody, and failure domains | independent contributors |
| Multi-party | ownership, policy, authority, attribution, dispute, economics | automatically trustworthy results |

Hugging Face-style open agent experiments are a useful product pattern:
shared frontier, public attempts, negative results, verifier challenges,
resource offers, relays, credit, and replay. IOI generalizes that pattern into a
governed service that also supports private rooms, enterprise federation,
machine authority, typed handoffs, policy, economics, and embodied effects.

## Core Effect Boundary

```text
intent or room claim
  -> worker/model/harness proposes
  -> semantic and capability checks
  -> policy and authority providers authorize
  -> Hypervisor Daemon admits, schedules, executes or mediates
  -> environment/provider/actuator performs
  -> observations, receipts, artifacts, and state deltas return
  -> verifier and acceptance paths classify assurance
  -> Agentgres admits local operational truth
  -> AIIP handoff or L1 commitment only when policy triggers it
```

The daemon does not invent authority. Policy and authority providers authorize;
the daemon admits, enforces, executes or mediates, receipts, and fails closed.

Receipt assurance is staged:

```text
attested -> evidenced -> verified -> accepted -> adjudicated -> settled
```

A receipt proves only its bound event or claim. It is not automatically proof
of correctness, truth, acceptance, or settlement.

External-effect recovery is also explicit:

```text
replayable | checkpointable | compensatable |
reconciliation_required | non_retryable
```

A timeout after a possible external effect is ambiguous, not safely retryable.
Environment restore and outcome reconciliation are separate operations.

## Persistent Intelligence, Privacy, And Embodiment

- `MemorySpace` is portable vault truth; `MemoryProjection` is the filtered
  harness/model/worker view. Harness-local memory is cache, not the durable
  brain.
- Improvement is proposal-driven. Traces and failures may yield skill, memory,
  workflow, verifier, harness, routing, or Foundry candidates, but eval,
  policy, authority, receipts, and Agentgres admission gate promotion.
- Private Workspace backed by cTEE keeps protected plaintext, secrets,
  strategy, and unrestricted authority off untrusted rented nodes by default.
  Provider-trust API routes remain explicitly labeled provider-trust.
- Embodied execution is two-speed: a deterministic local safety/control loop
  handles heartbeat, limits, stop, and immediate actuator control; the slower
  intelligence loop proposes missions, plans, semantic actions, and bounded
  physical action segments. Model output is never a safety heartbeat.

## Route By Problem

Use [`current-canon-defaults.md`](./current-canon-defaults.md) for the current
cross-owner digest, [`source-of-truth-map.md`](./source-of-truth-map.md) before
editing doctrine, and [`implementation-matrix.md`](./implementation-matrix.md)
before claiming that a target object is built.

| Problem | Start here | Then read |
| --- | --- | --- |
| Goal Space, open agent collaboration, room/workstream UX | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) |
| Goal Kernel, multi-harness execution, context cells | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`api.md`](../components/daemon-runtime/api.md) |
| Goal Space pricing, Work Credits, Network/Open budgets | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) | [`identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md), [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) |
| Foundation-model supply, OpenRouter, BYOK/BYOA, route rights | [`model-router/doctrine.md`](../components/model-router/doctrine.md) | [`api-byok-mounting.md`](../components/model-router/api-byok-mounting.md), [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) |
| Hypervisor product shell, clients, sessions, adapters | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`doctrine.md`](../components/daemon-runtime/doctrine.md) |
| Type 1/2/3 substrate and HypervisorOS | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) |
| Enterprise ontology, semantic federation, ODK | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`foundry.md`](../components/hypervisor/foundry.md) |
| Cross-domain collaboration or autonomous-system interop | [`aiip.md`](../foundations/aiip.md) | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) |
| Authority, secrets, approvals, revocation | [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | [`wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) |
| Operational truth, object heads, projections | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md) | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres/projection-system-reference.md`](../components/agentgres/projection-system-reference.md) |
| Portable memory and model/harness projections | [`portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md) | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) |
| Artifact refs, archives, restore, missing payloads | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`storage-backends/doctrine.md`](../components/storage-backends/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Private rented/cloud compute | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`model-router/doctrine.md`](../components/model-router/doctrine.md) |
| Worker marketplace and managed instances | [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent/digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md), [`aiagent/managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md) |
| Service procurement and delivery | [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas/service-endpoints.md`](../domains/sas/service-endpoints.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Governed improvement and promotion | [`improvement-governance-gates.md`](../components/daemon-runtime/improvement-governance-gates.md) | [`foundry.md`](../components/hypervisor/foundry.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) |
| Physical/embodied execution | [`physical-action-safety.md`](../foundations/physical-action-safety.md) | [`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md), [`aiip.md`](../foundations/aiip.md) |
| Assurance, certification, liability, audit | [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md) |
| L1, token, BME, and sparse public settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) |

## Reader Paths

### Runtime implementer

Read, in order:

1. [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
2. [`doctrine.md`](../components/daemon-runtime/doctrine.md)
3. [`api.md`](../components/daemon-runtime/api.md)
4. [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
5. [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
6. [`implementation-matrix.md`](./implementation-matrix.md)

### Product implementer

Read Goal Space and Hypervisor as two views over one fabric:

1. [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
2. [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
3. [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
4. [`identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md)
5. [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md)

### Semantic and interop implementer

1. [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md)
2. [`aiip.md`](../foundations/aiip.md)
3. [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
4. [`agentgres/doctrine.md`](../components/agentgres/doctrine.md)
5. [`security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md)

### Economics and marketplace implementer

1. [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md)
2. [`mixture-of-workers.md`](../foundations/mixture-of-workers.md)
3. [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md)
4. [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md)
5. [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md)
6. [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md)

## North-Star Internet-of-Intelligence Test

An independently operated external Worker must be able to discover an eligible
OutcomeRoom through a policy-bound projection, negotiate semantic/action
profiles, request admission, receive bounded leases, claim work, return a
verifiable contribution, retain credit/dispute lineage, and exit with a
portable policy-filtered participant-state bundle. Passing the test cannot
require one runtime, operational database, administrator, or continued access
to an IOI-hosted room. This is the minimum network proof; same-owner worker or
model multiplicity alone does not satisfy it.

## Most Common Boundary Mistakes

Reject these models:

```text
Goal Space = pooled frontier-model subscriptions
OutcomeRoom = global database, chat room, or leaderboard
Goal Kernel = one global swarm or coding-only loop
multi-model = multi-worker = multi-node = multi-party
ImplementationResult = universal work result
ontology name = executable capability or authority
receipt = verified truth, acceptance, or settlement
daemon = authority provider
provider fallback = harmless endpoint substitution
provider-trust API = Private/no-provider-trust execution
OpenRouter = the product moat or sole inference boundary
Agentgres = one global enterprise graph or all payload bytes
memory projection = portable vault truth
environment restore = external-effect reconciliation
model output = physical safety heartbeat
IOI L1 = per-step execution database
Work Credit = pooled provider token, cash, or protocol token
```

Use this model instead:

```text
Goal Space sells governed outcome pursuit.
OutcomeRoom coordinates shared pursuit above bounded GoalRuns.
GoalRun loops, verifies, course-corrects, and collapses to direct when simple.
Workers compose models, harnesses, tools, services, and runtime placements.
Domains own local semantic and operational truth.
AIIP moves typed, permitted work and refs between domains.
Policy and authority providers authorize.
The daemon admits, enforces, executes or mediates, and receipts.
Agentgres admits local truth; storage holds payload bytes.
Receipts feed explicit assurance stages.
Hypervisor spans infrastructure and governed autonomy.
Goal Space, Hypervisor, marketplaces, and services monetize product value.
Substrate layers meter, attest, authorize, record, and settle.
IOI L1 receives only selected public commitments.
```

## Maintaining The Canon

- Edit the subject owner named in
  [`source-of-truth-map.md`](./source-of-truth-map.md) first.
- Reconcile cross-owner defaults in
  [`current-canon-defaults.md`](./current-canon-defaults.md).
- Put shared enum values in
  [`canonical-enums.md`](../foundations/canonical-enums.md).
- Put shared names in [`vocabulary.md`](./vocabulary.md).
- Record built/partial/planned truth in
  [`implementation-matrix.md`](./implementation-matrix.md).
- Do not use the whitepaper, an archive, an ignored internal guide, or a UI
  projection as a competing architecture owner.
