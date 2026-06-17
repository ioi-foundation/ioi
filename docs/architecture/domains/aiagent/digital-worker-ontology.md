# aiagent.xyz Digital Worker Ontology

Status: canonical architecture authority.
Canonical owner: this file for the base ontology used to describe broad autonomous labor on aiagent.xyz.
Supersedes: plan prose that treats aiagent categories as hardcoded marketplace verticals.
Superseded by: none.
Last alignment pass: 2026-06-17.

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
| `WorkerPackage` | manifest plus Agentgres/package refs | marketplace object |
| `ManagedWorkerInstance` | owner-bound instance record | aiagent Agentgres domain object |
| `Capability` | manifest field / ontology field | descriptive; not authority |
| `TaskClass` | ontology field | index/routing vocabulary |
| `ActionType` | ontology field plus risk mapping | proposal vocabulary |
| `IntegrationSurface` | profile ref | vertical/UI/API binding |
| `ConnectorRequirement` | manifest field | dependency declaration |
| `PrimitiveCapability` | `prim:*` field | execution capability requirement |
| `AuthorityScope` | `scope:*` field | wallet.network authority requirement |
| `RiskClass` | policy field | daemon/wallet gate input |
| `PolicyProfile` | policy ref | wallet/daemon policy object |
| `ReceiptObligation` | receipt policy ref | accountability requirement |
| `EvidenceRequirement` | evidence bundle/profile | verification input |
| `BenchmarkProfile` | benchmark ref | quality/routing metadata |
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
worker author declares WorkerPackage
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
  runtime_profiles:
    - local | hosted | provider | depin | private_workspace_ctee | tee | customer_vpc
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
- `prim:*` requirements do not masquerade as `scope:*` authority grants.
- Physical-action workers reference the physical-action safety owner doc.
- Vertical packs extend ontology primitives; they do not define alternate
  runtimes, wallets, state stores, or settlement layers.
- Missing risk/evidence coverage is treated as `unknown`, not safe.

## Anti-Patterns

- Building one bespoke runtime per vertical.
- Treating marketplace categories as the ontology.
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
