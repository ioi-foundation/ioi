# aiagent.xyz Broad Autonomous Labor Canon Plan

Status: implementation plan for canon-doc refactor.
Owner target: `docs/architecture/domains/aiagent/`.
Related canon: [`worker-marketplace.md`](./worker-marketplace.md), [`worker-endpoints.md`](./worker-endpoints.md), [`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md), [`../../foundations/domain-ontologies-and-data-recipes.md`](../../foundations/domain-ontologies-and-data-recipes.md), [`../../components/daemon-runtime/api.md`](../../components/daemon-runtime/api.md), [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md), [`../../components/agentgres/artifact-ref-plane.md`](../../components/agentgres/artifact-ref-plane.md).

## Objective

Refactor the aiagent.xyz canon from a worker marketplace description into a broad autonomous labor substrate that can accommodate millions of vertical digital-worker and embodied-worker profiles without hardcoding those verticals into the marketplace, runtime, or authority model.

The target shape is:

```text
aiagent.xyz
  discovers, compares, installs, initializes, procures, and routes
  ontology-bound digital workers.

Digital Worker Ontology
  supplies the generic labor substrate.

Vertical Ontology Packs
  extend the substrate for specific domains.

Managed Worker Instances
  bind a worker package to a user, org, project, runtime, authority policy,
  memory policy, and lifecycle.

Hypervisor Daemon
  executes workers.

wallet.network
  authorizes power, secrets, payments, and step-up.

Agentgres
  records operational truth, receipts, state roots, memory refs, archive refs,
  install records, invocation state, and managed-instance lifecycle.

AIIP / RPC
  lets platforms, services, workers, and external systems invoke bounded work.

Embodied / physical systems
  use the same ontology substrate, but bind to physical-action safety,
  supervision, evidence, liability, and emergency-control profiles.
```

## Target Doctrine

Canonize this doctrine:

> **aiagent.xyz is the discovery, procurement, installation, initialization, and routing layer for ontology-bound digital and embodied workers. It does not hardcode autonomous labor categories. It indexes workers by capabilities, action types, authority requirements, integration surfaces, runtime posture, policy, receipts, benchmark evidence, safety posture, and managed-instance lifecycle.**

Do not model aiagent.xyz as:

```text
a chatbot marketplace
a fixed category directory
the execution runtime
the provider operating system
the authority layer
a separate chain
a generic gig board without receipt-backed worker objects
```

## Phase 1: Add Digital Worker Ontology Canon

Add:

```text
docs/architecture/domains/aiagent/digital-worker-ontology.md
```

The doc should define the stable universal primitives for broad autonomous labor:

```text
DigitalWorker
WorkerPackage
ManagedWorkerInstance
Capability
TaskClass
ActionType
IntegrationSurface
ConnectorRequirement
PrimitiveCapability
AuthorityScope
RiskClass
PolicyProfile
ReceiptObligation
EvidenceRequirement
BenchmarkProfile
RuntimeProfile
MemoryPolicy
PersistencePolicy
SettlementPolicy
VerticalOntologyPack
PhysicalActionPolicy
SafetyEnvelope
EmergencyStopAuthority
HumanSupervisionPolicy
LiabilityProfile
```

Required doctrine:

> **Verticals extend the Digital Worker Ontology. They do not fork the daemon, marketplace, authority, Agentgres, receipt, or settlement model.**

Implementation-grade requirements:

- define each primitive as a canonical object or profile;
- identify whether it is a marketplace object, Agentgres object, policy profile, receipt schema, projection, or manifest field;
- map each primitive to current durable forms when known;
- define required conformance checks;
- define anti-patterns that would create bespoke vertical runtimes.

## Phase 2: Add Vertical Ontology Pack Spec

Add:

```text
docs/architecture/domains/aiagent/vertical-ontology-packs.md
```

Vertical ontology packs should act like installable domain extensions over the stable Digital Worker Ontology. They should support unbounded vertical variety without making aiagent.xyz a hand-built category tree.

Each pack should be able to define:

```text
object types
action types
capability vocabulary
integration surfaces
connector mappings
policy profiles
risk mappings
receipt schemas
evidence requirements
benchmark rubrics
UI projections
forbidden actions
platform terms constraints
settlement hooks when applicable
safety envelopes when physical action is possible
emergency-stop and supervision requirements when embodied systems are involved
```

Example packs:

```text
community.discord_moderation.v1
game.server_finder.v1
game.coaching.v1
game.platform_coordination.v1
quant.research.v1
coding.review.v1
customer_support.shopify.v1
legal.contract_review.v1
finance.backoffice.v1
robotics.warehouse_pick.v1
robotics.carwash_prep.v1
robotics.humanoid_facility_assistant.v1
field_service.inspection.v1
```

Required doctrine:

> **The marketplace should not know every vertical. It should know how to validate, index, compare, route, and govern vertical ontology packs.**

## Phase 3: Make Managed Worker Instance Lifecycle First-Class

Add:

```text
docs/architecture/domains/aiagent/managed-worker-instance-lifecycle.md
```

This doc should own the lifecycle for persistent agents and managed worker instances:

```text
discover
install
initialize
grant authority
assign runtime
run
pause
resume
upgrade
suspend
payment past_due
zero_to_idle
archive
restore
migrate
delete
forget
```

Payment lapse doctrine:

> **Compute entitlement may lapse; user-owned context must remain restorable according to retention, archive, wallet authority, and deletion policy.**

The lifecycle doc should specify:

- what happens to active authority grants when payment lapses;
- what happens to standing orders and schedules;
- how warm runtime becomes zero-to-idle or archived;
- how Agentgres records state roots, archive refs, receipts, and restore/import metadata;
- how wallet.network verifies restore or export authority;
- how provider exit, package delisting, or version upgrade affects a long-lived agent;
- how user state can be migrated from aiagent.xyz web console into Hypervisor or another compatible runtime.

## Phase 4: Add Integration Surface Taxonomy

Add:

```text
docs/architecture/domains/aiagent/integration-surface-taxonomy.md
```

This doc should define integration classes that vertical packs can bind to:

```text
chat / community
game / platform
browser / SaaS
developer / code
commerce
finance / trading
local computer-use
enterprise / VPC
webhook / API
voice / SMS access
robotics / physical
embodied systems / humanoids
field service / inspection
vehicles / mobility
education / tutoring
creative / media
support / operations
```

Each integration class should map to:

```text
allowed action classes
forbidden action classes
primitive capabilities
authority scopes
risk defaults
approval defaults
receipt obligations
connector requirements
platform policy posture
abuse controls
settlement triggers
safety envelope requirements
human supervision requirements
emergency-stop authority
sensor and actuator evidence requirements
liability / insurance hooks
```

Special treatment examples:

- Discord/community agents require connector scopes, moderation policy, audit receipts, and human approval for punitive or mass actions.
- Game agents require platform-policy classification. Server finding, coaching, stats analysis, schedule coordination, and invite management may be valid. Cheating, anti-cheat evasion, deceptive competitive play, credential capture, or unauthorized real-money gambling automation must be restricted or disallowed unless explicitly platform-authorized and legally compliant.
- Finance/trading agents require strict separation between research, drafting, simulation, order proposal, and order execution.
- Robotics and embodied workers require a physical-action policy. Perception, planning, simulation, and reporting may be low or medium risk, but actuator commands, navigation near humans, chemical/tool use, vehicle interaction, and sensor override require explicit safety envelopes, supervision policy, receipts, and emergency-stop authority.
- Open-source robot runtimes, humanoid workers, facility robots, carwash-prep robots, warehouse robots, drones, and field-service agents should all compile into the same worker ontology, but they must bind to `physical_action` risk, `SafetyEnvelope`, `SensorEvidenceReceipt`, `ActuatorCommandReceipt`, and incident/dispute hooks.
- SMS, email, chat, and voice access points are low-assurance rails. They may notify, wake, steer, pause, or request step-up; they must not decrypt, declassify, hold grants, or approve high-risk actions without wallet.network step-up.

## Phase 5: Standardize Managed Agent Console Contract

Add:

```text
docs/architecture/domains/aiagent/managed-agent-console-contract.md
```

The default console is a projection over daemon, Agentgres, wallet.network, and aiagent.xyz APIs. It is not a hidden runtime.

Required modules:

```text
chat / task thread
status
standing orders
schedules
runs
receipts
artifacts
memory summary
authority grants
integration bindings
usage / billing
pause / resume / archive
export / restore
API keys / webhooks
version and upgrade state
trust / benchmark profile
```

Required doctrine:

> **Every managed worker instance should expose a default console projection, but durable truth remains in Agentgres and execution remains with Hypervisor Daemon runtime-node profiles.**

## Phase 6: Extend Worker Manifests, Endpoints, and Meta Docs

Update:

```text
docs/architecture/domains/aiagent/worker-marketplace.md
docs/architecture/domains/aiagent/worker-endpoints.md
docs/architecture/foundations/common-objects-and-envelopes.md
docs/architecture/_meta/implementation-matrix.md
docs/architecture/_meta/source-of-truth-map.md
docs/architecture/_meta/vocabulary.md
docs/architecture/_meta/start-here.md
docs/architecture/README.md
```

Add or tighten fields for:

```text
ontology_pack_refs
action_type_refs
integration_surface_refs
policy_profile_refs
receipt_schema_refs
benchmark_profile_refs
platform_policy_refs
console_module_refs
lapse_policy
archive_policy
restore_policy
api_embedding_policy
forbidden_action_refs
managed_instance_lifecycle_ref
physical_action_policy_ref
safety_envelope_ref
emergency_stop_authority_ref
human_supervision_policy_ref
liability_profile_ref
```

Endpoint implications:

- marketplace install and instance creation should accept ontology pack refs and integration surface bindings;
- managed instance APIs should expose lifecycle, standing orders, authority, memory summary, archive, restore, and subscription state;
- API/inter-agent endpoints should use AIIP-compatible envelopes for invocation, handoff, evidence request, decision request, receipt commitment, and dispute;
- console APIs should be projections over daemon/runtime APIs and Agentgres refs, not independent execution loops.

## Phase 7: Add Conformance Checks

Every worker listing and managed instance should be mechanically answerable:

```text
What can it do?
Where can it act?
What authority does it need?
What is forbidden?
What receipts does it emit?
What evidence does it produce?
How is it benchmarked?
Where can it run?
What state persists?
What happens if payment lapses?
Can it be called by API?
Can it be installed into Hypervisor?
Can it run as a managed web instance?
Can it be safely invoked by another platform?
Which ontology pack and action types support these claims?
Can it produce physical effects?
What safety envelope and emergency-stop authority govern those effects?
```

Conformance hooks should include:

- manifest validation;
- ontology pack validation;
- action type validation;
- policy profile validation;
- connector/tool contract validation;
- authority-scope validation;
- receipt-schema validation;
- benchmark profile validation;
- managed instance lifecycle validation;
- payment lapse/archive/restore validation;
- forbidden action validation.
- physical-action safety envelope validation;
- emergency-stop and supervision validation.

## Phase 8: Seed Example Vertical Packs

Add compact example packs or appendices that prove breadth without overfitting:

```text
community.discord_moderator
game.server_finder
coding.review_worker
quant.research_worker
customer_support.agent
robotics.carwash_prep
robotics.facility_inspection
```

Use risky examples such as poker bots, real-time competitive game bots, gambling automation, account-control bots, unsupervised humanoid operation, safety-sensor override, chemical/tool use near humans, and vehicle control as policy stress tests, not as launch examples.

## Acceptance Criteria

- `aiagent.xyz` canon reads as a broad autonomous labor substrate, not merely a chatbot/worker storefront.
- A new reader can understand how millions of digital and embodied vertical profiles are accommodated through vertical ontology packs instead of hardcoded marketplace categories.
- The source-of-truth map assigns canonical owners for Digital Worker Ontology, Vertical Ontology Packs, Managed Worker Instance lifecycle, integration surfaces, and managed console contract.
- Worker package and managed instance docs clearly distinguish capability, authority, policy, evidence, receipt, benchmark, runtime, memory, and settlement concepts.
- Payment lapse, archive, restore, and migration semantics are explicit.
- Low-assurance access points are explicitly not authority or decryption surfaces.
- Game, Discord/community, finance/trading, platform automation, robotics, humanoid, vehicle-adjacent, and physical-action examples are handled through integration policy instead of bespoke runtime exceptions.
- Embodied workers have explicit physical-action semantics, including `PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`, `HumanSupervisionPolicy`, `SensorEvidenceReceipt`, `ActuatorCommandReceipt`, liability hooks, and incident/dispute hooks.
- Existing doctrine remains intact: Hypervisor Daemon executes, wallet.network authorizes, Agentgres records truth, storage backends hold bytes, aiagent.xyz lists/routes workers, sas.xyz contracts outcomes, and IOI L1 settles only when public/economic/cross-domain triggers require it.
- No stale terminology or contradictory owner claims are introduced.
- `git diff --check -- docs/architecture` passes.

## Suggested Implementation Order

1. Add `digital-worker-ontology.md`.
2. Add `vertical-ontology-packs.md`.
3. Add `managed-worker-instance-lifecycle.md`.
4. Add `integration-surface-taxonomy.md`.
5. Add `managed-agent-console-contract.md`.
6. Update `worker-marketplace.md` and `worker-endpoints.md`.
7. Update shared objects and envelopes.
8. Update `_meta/source-of-truth-map.md`, `_meta/implementation-matrix.md`, `_meta/vocabulary.md`, `_meta/start-here.md`, and `README.md`.
9. Add example vertical packs or appendices.
10. Run stale terminology and whitespace checks.

## Goal Prompt

```text
/goal

Goal:
Refactor the IOI canon docs so aiagent.xyz becomes the canonical broad autonomous labor substrate for ontology-bound digital and embodied workers, capable of accommodating millions of vertical profiles without hardcoding vertical categories into the marketplace, runtime, authority, or state model.

Target end state:
- aiagent.xyz is canonized as the discovery, procurement, installation, initialization, managed-instance, API invocation, and routing layer for ontology-bound digital and embodied workers.
- Digital Worker Ontology provides stable universal primitives for workers, capabilities, tasks, actions, integration surfaces, authority, risk, policies, receipts, evidence, benchmarks, runtime profiles, memory, persistence, settlement, and physical-action safety.
- Vertical Ontology Packs extend the core ontology for unbounded domains such as Discord moderation, game server finding, quant research, code review, customer support, legal review, finance operations, robotics, humanoid facility work, vehicle-adjacent work, and future verticals.
- Managed Worker Instance lifecycle is first-class, including install, initialize, runtime assignment, authority grants, run, pause, resume, upgrade, payment lapse, zero-to-idle, archive, restore, migrate, delete, and forget.
- Integration Surface Taxonomy makes special-treatment verticals explicit without creating bespoke runtimes, including physical-action and embodied-system surfaces.
- Managed Agent Console Contract defines the default web/API projection for rented or persistent agents.
- Worker manifests, endpoints, shared object envelopes, source-of-truth map, implementation matrix, vocabulary, start-here, and README all agree.

Primary deliverables:
1. Add `docs/architecture/domains/aiagent/digital-worker-ontology.md`.
2. Add `docs/architecture/domains/aiagent/vertical-ontology-packs.md`.
3. Add `docs/architecture/domains/aiagent/managed-worker-instance-lifecycle.md`.
4. Add `docs/architecture/domains/aiagent/integration-surface-taxonomy.md`.
5. Add `docs/architecture/domains/aiagent/managed-agent-console-contract.md`.
6. Update `docs/architecture/domains/aiagent/worker-marketplace.md`.
7. Update `docs/architecture/domains/aiagent/worker-endpoints.md`.
8. Update `docs/architecture/foundations/common-objects-and-envelopes.md`.
9. Update `docs/architecture/_meta/source-of-truth-map.md`.
10. Update `docs/architecture/_meta/implementation-matrix.md`.
11. Update `docs/architecture/_meta/vocabulary.md`.
12. Update `docs/architecture/_meta/start-here.md` and `docs/architecture/README.md`.

Constraints:
- Do not weaken or flatten the architecture.
- Do not introduce a new runtime beside Hypervisor Daemon.
- Do not turn aiagent.xyz into the authority layer, runtime, provider OS, or state store.
- Preserve the distinction: aiagent.xyz lists/routes workers; sas.xyz contracts outcomes; Hypervisor Daemon executes; wallet.network authorizes; Agentgres records admitted truth; storage backends hold bytes; AIIP moves bounded work; IOI L1 settles only by trigger.
- Preserve `prim:*` for primitive execution capabilities and `scope:*` for authority scopes.
- Treat verticals as ontology packs and profiles, not bespoke architecture forks.
- Treat physical and embodied workers as ontology-bound worker instances with stricter safety, supervision, evidence, emergency-stop, and liability profiles, not as a separate runtime class.
- Treat low-assurance access points such as SMS, email, chat apps, voice, and webhooks as notification/initiation rails only; they cannot decrypt, declassify, hold grants, release secrets, or approve high-risk actions without step-up.
- Preserve historical/deep material where useful, but clearly mark it as supporting context if it competes with canon.
- Keep edits scoped to `docs/architecture` unless an outside link must be updated.

Acceptance criteria:
- A new reader can understand that aiagent.xyz scales to millions of vertical digital-worker and embodied-worker profiles through a Digital Worker Ontology plus Vertical Ontology Packs.
- Every major concept has one canonical owner doc.
- Worker manifests clearly expose ontology pack refs, action type refs, integration surfaces, policy profiles, receipt obligations, benchmark profiles, platform policies, console modules, lifecycle refs, archive/restore policy, and forbidden actions.
- Managed Worker Instance lifecycle covers payment lapse, archive, restore, migration, provider exit, and package version changes.
- Integration Surface Taxonomy covers at least chat/community, games/platforms, SaaS/browser, developer/code, commerce, finance/trading, local computer-use, enterprise/VPC, webhook/API, voice/SMS, robotics/physical, embodied systems/humanoids, vehicle-adjacent work, field service/inspection, creative/media, and support/operations.
- Game, Discord/community, finance/trading, and platform automation examples are handled through policy and risk classes rather than bespoke runtime exceptions.
- Physical-action examples such as open-source robot runtimes, humanoid facility assistants, carwash-prep robots, warehouse robots, drones, and field-service inspection agents are handled through `PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`, `HumanSupervisionPolicy`, `SensorEvidenceReceipt`, `ActuatorCommandReceipt`, and incident/dispute hooks.
- Managed Agent Console Contract states that the console is a projection over daemon, Agentgres, wallet.network, and aiagent APIs, not a hidden runtime.
- Source-of-truth map, implementation matrix, vocabulary, start-here, and README agree with the new canon.
- No stale owner claims or live-architecture terminology conflicts remain.
- `git diff --check -- docs/architecture` passes.
```
