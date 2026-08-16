# Start Here: Route By Problem

Status: canonical problem-to-owner routing map.
Canonical owner: this file for problem-to-owner routing, role reading paths, and the common boundary-mistake register; first-read narrative orientation is owned by the architecture guide at [`../guide/`](../guide/README.md).
Supersedes: ad hoc onboarding paths across architecture docs; this file's own former first-read narrative sections, which moved to the guide on 2026-08-16.
Superseded by: none.
Last alignment pass: 2026-08-16 (narrowed to routing: the five-minute model, bounded-DAS minute, core product shape, effect boundary, and learning/embodiment orientation moved to `../guide/` chapters 00–07).
Doctrine status: canonical
Implementation status: mixed (routing map over built, partial, planned, and speculative subjects)
Last implementation audit: 2026-08-16

New to the architecture? Read the guide first —
[`../guide/README.md`](../guide/README.md) — nine chapters from the category
problem to current state, every load-bearing statement linked to its owner.
This file is the map you use afterward: it routes a specific problem to the
owner document where that subject is decided.

## Route By Problem

Use [`current-canon-defaults.md`](./current-canon-defaults.md) for the current
cross-owner digest, [`source-of-truth-map.md`](./source-of-truth-map.md) before
editing doctrine, and [`canon-to-code-delta.md`](./canon-to-code-delta.md) plus
the [`work-items/`](./work-items/) records before claiming that a target object
is built (the former implementation matrix is archived).

| Problem | Start here | Then read |
| --- | --- | --- |
| Bounded DAS/intelligent blockchain constitution, deployment, membership, failover, lifecycle | [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md) | [`domain-kernels.md`](../foundations/domain-kernels.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`execution-horizons.md`](./execution-horizons.md) |
| Goal Space, open agent collaboration, room/workstream UX | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) |
| GoalRunProfile, GoalRun, Goal Kernel, topology, context cells, and typed step/result seams | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`api.md`](../components/daemon-runtime/api.md) |
| Goal Space pricing, Work Credits, Network/Open budgets | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) | [`identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md), [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) |
| Foundation-model supply, OpenRouter, BYOK/BYOA, route rights | [`model-router/doctrine.md`](../components/model-router/doctrine.md) | [`api-byok-mounting.md`](../components/model-router/api-byok-mounting.md), [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) |
| Hypervisor shell, Systems/Work, applications, packages, clients, sessions, adapters | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`canonical-enums.md`](../foundations/canonical-enums.md), [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`doctrine.md`](../components/daemon-runtime/doctrine.md) |
| Project discovery, environment recipes/startup, routes, backups, restore, and provider cleanup | [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md) | [`api.md`](../components/daemon-runtime/api.md), [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md), [`doctrine.md`](../components/daemon-runtime/doctrine.md) |
| Type 1/2/3 substrate and HypervisorOS | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) |
| Enterprise ontology, semantic federation, ODK | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`foundry.md`](../components/hypervisor/foundry.md) |
| Enterprise-owned learning, provider exposure, capability portability, and model-swap continuity | [`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md) | [`model-router/doctrine.md`](../components/model-router/doctrine.md), [`foundry.md`](../components/hypervisor/foundry.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) |
| Cross-domain collaboration, standards bindings, or autonomous-system interop | [`aiip.md`](../foundations/aiip.md) | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) |
| Authority, secrets, approvals, revocation | [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | [`wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) |
| Operational truth, object heads, projections | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md) | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres/projection-system-reference.md`](../components/agentgres/projection-system-reference.md) |
| Portable memory and model/harness projections | [`portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md) | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) |
| Artifact refs, archives, restore, missing payloads | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`storage-backends/doctrine.md`](../components/storage-backends/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Private rented/cloud compute | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`model-router/doctrine.md`](../components/model-router/doctrine.md) |
| Worker marketplace and managed instances | [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent/digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md), [`aiagent/managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md) |
| Service procurement and delivery | [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas/service-endpoints.md`](../domains/sas/service-endpoints.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Governed improvement, bounded campaigns, evaluation epochs, and promotion | [`bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md) | [`improvement.md`](../components/hypervisor/improvement.md), [`evaluations.md`](../components/hypervisor/evaluations.md), [`improvement-governance-gates.md`](../components/daemon-runtime/improvement-governance-gates.md), [`foundry.md`](../components/hypervisor/foundry.md) |
| Native embodied execution, runtime graphs, units, fleets, and swarms | [`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md) | [`physical-action-safety.md`](../foundations/physical-action-safety.md), [`foundry.md`](../components/hypervisor/foundry.md), [`aiip.md`](../foundations/aiip.md) |
| Physical actuation authority, local safety, supervision, and emergency stop | [`physical-action-safety.md`](../foundations/physical-action-safety.md) | [`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md), [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) |
| Assurance, certification, liability, audit | [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md) |
| Network enrollment, Standard DAS, L1, token/BME, and sparse public settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md), [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) |

## Reader Paths

### Runtime implementer

Read, in order:

1. [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
2. [`doctrine.md`](../components/daemon-runtime/doctrine.md)
3. [`api.md`](../components/daemon-runtime/api.md)
4. [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
5. [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
6. [`canon-to-code-delta.md`](./canon-to-code-delta.md)

### Product implementer

Read Goal Space and Hypervisor as two views over one fabric:

1. [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
2. [`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md)
3. [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
4. [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
5. [`identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md)
6. [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md)

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

Owner: [`../foundations/internet-of-intelligence.md`](../foundations/internet-of-intelligence.md)
§ North-Star Network Proof. Read it there; what follows is orientation, not the
test, and the owner wins on any point of substance.

The minimum network proof asks one thing: can an **independently operated
external Worker** discover an eligible OutcomeRoom, get admitted, receive
bounded leases, do claimed work, return a verifiable contribution, keep its
credit and dispute lineage, and leave with a portable participant-state bundle
— all without sharing a runtime, an operational database, an administrator, or
continued access to an IOI-hosted room? Same-owner worker or model multiplicity
alone does not satisfy it.

## Most Common Boundary Mistakes

Reject these models:

```text
Goal Space = pooled frontier-model subscriptions
OutcomeRoom = global database, chat room, or leaderboard
Goal Kernel = one global swarm or coding-only loop
GoalRunProfile = executable, authority, live run state, or workflow graph
WorkflowTemplate = AutomationSpec, trigger, run history, or canvas state
SkillManifest = executable tool, hook, authority, or marketplace listing
multi-model = multi-worker = multi-node = multi-party
same-system member routing = AIIP federation
ImplementationResult = universal work result
ontology name = executable capability or authority
receipt = verified truth, acceptance, or settlement
daemon = authority provider
provider fallback = harmless endpoint substitution
provider-trust API = Private/no-provider-trust execution
enterprise operation = ownership or training rights over every trace
receipt or ZDR contract = proof of hidden provider non-learning
model-neutral routing = equivalent replacement quality without retained state/evals
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
Same-system distributed work uses native L0 membership, RuntimeAssignment,
leases, state/evidence, and Embodied Runtime contracts.
Cross-plane operation readiness is evaluated per operation through the
[`Platform Operability`](../components/daemon-runtime/platform-operability.md)
contract; one green process or dashboard never substitutes for current truth,
authority, clock, billing, attestation, storage, provider, fleet, or settlement
evidence.
AIIP begins only across independently governed system boundaries.
Workers compose models, harnesses, tools, services, and runtime placements.
Domains own local semantic and operational truth.
InstitutionalLearningBoundaryProfile compiles the institution's learning rules;
source rights and per-subject eligibility still decide what may be learned.
AIIP moves typed, permitted work and refs between domains.
Policy and authority providers authorize.
The daemon admits, enforces, executes or mediates, and receipts.
Agentgres admits local truth; storage holds payload bytes.
Receipts feed explicit assurance stages.
Hypervisor spans infrastructure and governed autonomy.
Goal Space, Hypervisor, marketplaces, and services monetize product value.
Substrate layers meter, attest, authorize, record, and settle.
IOI L1 receives selected public commitments only for explicitly enrolled
systems.
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
  [`canon-to-code-delta.md`](./canon-to-code-delta.md) or a
  [`work-items/`](./work-items/) record.
- Keep the [`../guide/`](../guide/README.md) chapters non-owning: they may
  re-sequence what owners say, never originate it.
- Do not use the whitepaper, an archive, an ignored internal guide, or a UI
  projection as a competing architecture owner.
