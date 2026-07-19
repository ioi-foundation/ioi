# aiagent.xyz Digital Worker Ontology

Status: canonical architecture authority.
Canonical owner: this file for the base ontology used to describe broad autonomous labor on aiagent.xyz.
Supersedes: plan prose that treats aiagent categories as hardcoded marketplace verticals.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: canonical
Implementation status: planned (ontology design over the draft plane)
Last implementation audit: 2026-07-05

## Canonical Definition

`DigitalWorkerOntology` is the stable object vocabulary for ontology-bound
autonomous labor. The name is historical: it covers software workers by
default and becomes embodied work when a vertical pack binds physical-action
safety objects.

aiagent.xyz indexes and procures workers through this ontology. It does not
hardcode every vertical into marketplace code, fork the daemon, fork
wallet.network, fork Agentgres, or create custom settlement logic per industry.

```text
WorkerPackage
  -> declares capabilities, surfaces, policies, receipts, runtime profiles,
     and memory compatibility
VerticalOntologyPack
  -> extends domain language and risk/evidence rules
ManagedWorkerOnboardingPlan
  -> compiles package requirements + buyer environment into setup steps
ManagedWorkerInstance
  -> binds package + owner + runtime + authority + memory + lifecycle
ManagedWorkerInstanceConfigRevision / ChangePlan
  -> governs post-hire customization, update, canary, apply, and rollback
Hypervisor Daemon
  -> executes
authority providers / local governance
  -> authorize power, secrets, payments, declassification, revocation as required
Agentgres
  -> admits state, receipts, refs, lifecycle, restore truth
Storage backends
  -> hold package, archive, evidence, and payload bytes
IOI L1
  -> settles only selected public/economic/cross-domain commitments
```

## Owns

This ontology owns the common labor description primitives:

| Primitive | Durable Form | Owner Boundary |
| --- | --- | --- |
| `DigitalWorkerOntology` | canonical vocabulary/profile | aiagent domain canon |
| `StarterWorkerTemplate` | package-draft seed / recipe ref | aiagent authoring object; not invokable |
| `WorkerPackage` | manifest plus Agentgres/package refs | marketplace object |
| `WorkerComposition` | model + harness + tools + runtime + policy version | benchmark/listing identity |
| `ManagedWorkerOnboardingPlan` | requirement-to-step plan / readiness projection | marketplace install/configuration object |
| `ManagedWorkerInstance` | owner-bound instance record | aiagent Agentgres domain object |
| `ManagedWorkerInstanceConfigRevision` | desired instance configuration ref | aiagent lifecycle object; not execution |
| `ManagedWorkerInstanceChangePlan` | diff/gates/canary/rollback ref | aiagent lifecycle object over daemon admission |
| `RuntimeManagementChannel` | `management_channel://...` | daemon-mediated projection/control path; not truth |
| `Capability` | manifest field / ontology field | descriptive; not authority |
| `TaskClass` | ontology field | index/routing vocabulary |
| `ActionType` | ontology field plus risk mapping | proposal vocabulary |
| `SourceProvenance` | repo/package/signature/SBOM refs | supply-chain evidence |
| `HarnessAdapter` | adapter ref / runtime entrypoint | execution topology binding |
| `ModelRouteOption` | model route ref | selectable model component |
| `IntegrationSurface` | profile ref | vertical/UI/API binding |
| `ConnectorRequirement` | manifest field | dependency declaration |
| `MemoryProfile` | `memory_profile://...` | package-declared and instance-bound memory posture |
| `MemoryProjection` | `memory_projection://...` | harness/model/surface-compatible memory view |
| `MemoryArchive` | `memory_archive://...` | encrypted restorable managed-instance memory payload |
| `PrimitiveCapability` | `prim:*` field | execution capability requirement |
| `AuthorityScope` | `scope:*` field | authority-provider or local-governance requirement |
| `RiskClass` | policy field | daemon and authority/governance gate input |
| `PolicyProfile` | policy ref | daemon, authority-provider, or local-governance policy object |
| `ReceiptObligation` | receipt policy ref | accountability requirement |
| `EvidenceRequirement` | evidence bundle/profile | verification input |
| `BenchmarkProfile` | benchmark ref | quality/routing metadata |
| `ListingAdmission` | submission/fee/benchmark state | marketplace admission record |
| `RuntimeProfile` | runtime placement profile | daemon/node placement |
| `MemoryPolicy` | Agentgres/ioi-memory policy ref | durable context behavior |
| `PersistencePolicy` | lifecycle profile | instance availability behavior |
| `SettlementPolicy` | local/L1 trigger profile | economic/dispute behavior |
| `VerticalOntologyPack` | installable domain extension | aiagent ontology extension |

Embodied workers additionally bind to
[`physical-action-safety.md`](../../foundations/physical-action-safety.md) for
`PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`,
`HumanSupervisionPolicy`, `SensorEvidenceReceipt`, `ActuatorCommandReceipt`,
and `PhysicalActionIncident`.

## Does Not Own

The ontology does not own:

- worker execution semantics;
- user authority or credentials;
- payload bytes;
- physical safety by itself;
- marketplace settlement contracts;
- vertical-specific legality or compliance decisions;
- model weights or model routing;
- app UI truth.

## Lifecycle

The ontology is applied in this order:

```text
optional StarterWorkerTemplate seeds a package draft
  -> worker author declares WorkerPackage
  -> binds SourceProvenance, HarnessAdapter, ModelRouteOptions, and runtime policy into a WorkerComposition
  -> selects base ontology primitives
  -> attaches zero or more VerticalOntologyPacks
  -> declares IntegrationSurfaces and ConnectorRequirements
  -> declares memory profiles, supported memory kinds, projection targets, and archive posture
  -> binds prim:* requirements and scope:* requirements
  -> declares ReceiptObligations, EvidenceRequirements, BenchmarkProfiles
  -> publishes package/listing refs
  -> user hires, installs, or initializes through a ManagedWorkerOnboardingPlan
  -> post-hire edits create ManagedWorkerInstanceConfigRevision and, when needed, ManagedWorkerInstanceChangePlan
  -> daemon executes after the relevant authority-provider or local/domain governance gates
  -> Agentgres records receipts, lifecycle, refs, and restore state
```

## Minimal Implementation Objects

```yaml
DigitalWorkerOntologyProfile:
  ontology_id: ontology:aiagent.base.v1
  worker_package_ref: package://...
  task_classes:
    - task_class:...
  action_types:
    - action_type:...
  worker_composition_ref: composition://...
  source_provenance_refs:
    - git://... | package://... | artifact://...
  harness_profile_revision_ref: harness-profile://.../revision/... | null
  harness_profile_content_hash: hash | null
  agent_harness_adapter_revision_ref:
    agent-harness-adapter://.../revision/... | null
  agent_harness_adapter_content_hash: hash | null
  model_route_options:
    - model_route://...
  integration_surfaces:
    - integration_surface:...
  primitive_capability_requirements:
    - prim:...
  authority_scope_requirements:
    - scope:...
  risk_classes:
    - read | draft | local_write | external_message | commerce | funds | physical_action
  policy_profile_refs:
    - policy:...
  receipt_policy_ref: receipt_policy:...
  evidence_requirement_refs:
    - evidence_requirement:...
  listing_admission_ref: submission://...
  onboarding_plan_refs:
    - onboarding_plan://...
  config_revision_schema_ref: schema://... | optional
  change_plan_policy_ref: policy://... | optional
  runtime_profiles:
    - local | hosted | provider | depin | private_workspace_ctee | tee | customer_vpc
  integration_export_profiles:
    - web_console | worker_api | model_compatible_api | mcp | workflow_node | local_hypervisor_install
  persistence_profiles:
    - ephemeral | session | zero_to_idle | persistent
  memory_profiles:
    - memory_profile://...
  supported_memory_kinds:
    - preference
    - fact
    - procedure
    - doctrine
    - route
    - tool_affordance
    - failure
    - eval
    - game_lesson
    - project_convention
    - connector_observation
  memory_projection_targets:
    - harness-profile://...
    - model_route://...
    - surface://...
  memory_archive_policy_ref: policy://... | optional
  runtime_management_channel_profiles:
    - hosted_fleet
    - customer_vpc
    - local_daemon
    - depin_node
    - tee_node
    - private_workspace_ctee
  vertical_pack_refs:
    - vertical_pack:...
```

## Admission / Settlement Boundary

Ontology metadata can be indexed by aiagent.xyz, but it does not execute work or
grant authority. Consequential transitions require daemon gates, the relevant
authority provider or local/domain governance gate, Agentgres admission, and
receipts. wallet.network is mandatory when the action needs portable delegated
authority, secrets, spend, decryption, external effects, or high-risk approval.
IOI L1 is used only when an active connected/secured enrollment selected that
service and its listing, license, payout, dispute, reputation, rights, or
cross-domain settlement trigger applies.

## Events And Receipts

At minimum, ontology-bound worker flows should produce:

- `WorkerPackagePublishedReceipt`
- `WorkerCompositionVersionedReceipt`
- `ListingAdmissionSubmittedReceipt`
- `BenchmarkFeePaidReceipt`
- `WorkerPackageInstalledReceipt`
- `ManagedWorkerInstanceInitializedReceipt`
- `ManagedWorkerConfigRevisionCreatedReceipt`
- `ManagedWorkerChangePlanCreatedReceipt`
- `ManagedWorkerChangePlanAppliedReceipt`
- `AuthorityGrantRequestedReceipt`
- `WorkerInvocationReceipt`
- `EvidenceBundleReceipt`
- `BenchmarkSubmissionReceipt`
- `ManagedWorkerLifecycleReceipt`

## Conformance Checks

- Every worker listing declares ontology/profile refs instead of relying only on
  free-form categories.
- Starter templates are not invokable until normalized into worker packages
  with declared requirements, policies, receipts, and runtime profiles.
- Benchmark and routing claims attach to a `WorkerComposition`, not only a
  worker name, raw source repository, harness, or model checkpoint.
- Post-hire customization attaches to `ManagedWorkerInstanceConfigRevision` and
  `ManagedWorkerInstanceChangePlan`; it does not mutate worker package truth or
  silently reuse stale benchmark claims.
- Runtime management channels project and control assigned runtime nodes through
  daemon admission. They are not alternate runtimes, secret tunnels, or
  Agentgres truth.
- `prim:*` requirements do not masquerade as `scope:*` authority grants.
- Physical-action workers reference the physical-action safety owner doc.
- Vertical packs extend ontology primitives; they do not define alternate
  runtimes, wallets, state stores, or settlement layers.
- Missing risk/evidence coverage is treated as `unknown`, not safe.

## Anti-Patterns

- Building one bespoke runtime per vertical.
- Treating marketplace categories as the ontology.
- Treating a prompt, persona, form, or workflow recipe as an executable worker
  before package normalization.
- Treating a raw model checkpoint or source repository as a benchmarked worker
  without binding harness, runtime, policy, authority, and receipt obligations.
- Reusing benchmark scores after material composition changes without
  rebenchmarking or clearly marking the score stale.
- Letting dashboard edits mutate a persistent managed instance without config
  revisions, change plans, policy gates, and receipts.
- Treating an integration name such as Discord, Steam, Shopify, or robot arm as
  authority.
- Letting a worker package imply credentials without wallet.network scopes.
- Treating physical action as an ordinary connector call.
- Treating a managed console as runtime truth.

## Related Canon

- [`worker-marketplace.md`](./worker-marketplace.md)
- [`worker-endpoints.md`](./worker-endpoints.md)
- [`vertical-ontology-packs.md`](./vertical-ontology-packs.md)
- [`integration-surface-taxonomy.md`](./integration-surface-taxonomy.md)
- [`managed-worker-instance-lifecycle.md`](./managed-worker-instance-lifecycle.md)
- [`managed-agent-console-contract.md`](./managed-agent-console-contract.md)
- [`physical-action-safety.md`](../../foundations/physical-action-safety.md)
