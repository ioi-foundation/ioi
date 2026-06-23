# aiagent.xyz Digital Worker Ontology

Status: canonical architecture authority.
Canonical owner: this file for the base ontology used to describe broad autonomous labor on aiagent.xyz.
Supersedes: plan prose that treats aiagent categories as hardcoded marketplace verticals.
Superseded by: none.
Last alignment pass: 2026-06-22.

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
  -> declares capabilities, surfaces, policies, receipts, runtime profiles
VerticalOntologyPack
  -> extends domain language and risk/evidence rules
ManagedWorkerInstance
  -> binds package + owner + runtime + authority + memory + lifecycle
Hypervisor Daemon
  -> executes
wallet.network
  -> authorizes power, secrets, payments, declassification, revocation
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
| `ManagedWorkerInstance` | owner-bound instance record | aiagent Agentgres domain object |
| `Capability` | manifest field / ontology field | descriptive; not authority |
| `TaskClass` | ontology field | index/routing vocabulary |
| `ActionType` | ontology field plus risk mapping | proposal vocabulary |
| `SourceProvenance` | repo/package/signature/SBOM refs | supply-chain evidence |
| `HarnessAdapter` | adapter ref / runtime entrypoint | execution topology binding |
| `ModelRouteOption` | model route ref | selectable model component |
| `IntegrationSurface` | profile ref | vertical/UI/API binding |
| `ConnectorRequirement` | manifest field | dependency declaration |
| `PrimitiveCapability` | `prim:*` field | execution capability requirement |
| `AuthorityScope` | `scope:*` field | wallet.network authority requirement |
| `RiskClass` | policy field | daemon/wallet gate input |
| `PolicyProfile` | policy ref | wallet/daemon policy object |
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
  -> binds prim:* requirements and scope:* requirements
  -> declares ReceiptObligations, EvidenceRequirements, BenchmarkProfiles
  -> publishes package/listing refs
  -> user installs or initializes ManagedWorkerInstance
  -> daemon executes under wallet authority
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
  harness_adapter_ref: harness_adapter://...
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
  runtime_profiles:
    - local | hosted | provider | depin | private_workspace_ctee | tee | customer_vpc
  integration_export_profiles:
    - web_console | worker_api | model_compatible_api | mcp | workflow_node | local_hypervisor_install
  persistence_profiles:
    - ephemeral | session | zero_to_idle | persistent
  vertical_pack_refs:
    - vertical_pack:...
```

## Admission / Settlement Boundary

Ontology metadata can be indexed by aiagent.xyz, but it does not execute work or
grant authority. Consequential transitions require daemon gates, wallet.network
authority, Agentgres admission, and receipts. IOI L1 is used only when a listing,
license, payout, dispute, reputation root, rights commitment, or cross-domain
settlement trigger requires it.

## Events And Receipts

At minimum, ontology-bound worker flows should produce:

- `WorkerPackagePublishedReceipt`
- `WorkerCompositionVersionedReceipt`
- `ListingAdmissionSubmittedReceipt`
- `BenchmarkFeePaidReceipt`
- `WorkerPackageInstalledReceipt`
- `ManagedWorkerInstanceInitializedReceipt`
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
