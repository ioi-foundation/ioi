# Canonical Enumerations

Status: canonical architecture authority.
Doctrine status: canonical
Implementation status: mixed (each enum states its code grounding)
Canonical owner: this file for the canonical member set and spelling of cross-component enumerations that previously drifted.
Supersedes: divergent local redefinitions of risk classes, execution venues /
privacy modes, provider account kinds, Goal Space controls, Hypervisor product-
surface classification, collaborative-pursuit modes, provider-route rights,
assurance stages, bounded-improvement evidence claims, autonomous-system
ordering/finality and node roles, native embodied runtime profiles and execution
strata, and IOI Network enrollment.
Settlement-rail selection is also owned here; settlement trigger rules and
rail-specific fields remain with their envelope/profile owners.
Superseded by: none.
Last alignment pass: 2026-07-15.

## Purpose

An audit found the same enumerations defined with different member sets in
multiple canonical files (three divergent risk-class lists; task-capsule
privacy modes lagging the venue taxonomy). This file owns the member sets.
Other docs show the enum only as a labeled excerpt with a link here; adding or
renaming a member happens here first.

## Risk Classes (`risk_class`)

Canonical ladder, lowest to highest required assurance:

```text
read
draft
local_write
write_reversible
external_message
commerce
funds
credential_access
policy_widening
secret_export
identity_change
system_destructive
```

`physical_action` is a peer top-tier class outside the monotonic ladder: it
additionally requires the Physical Action Safety envelope
([`physical-action-safety.md`](./physical-action-safety.md)) and is the one
class already enforced by daemon admission code
(`crates/services/src/agentic/runtime/kernel/runtime_worker_package_install_admission.rs`).

Higher classes require stronger approval or a higher wallet security tier
(INV-1; ladder application in
[`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md)).

Deprecated aliases (do not introduce in new docs; map on sight):

| Deprecated | Canonical |
| --- | --- |
| `read_only` | `read` |
| `external_draft` | `draft` |
| `commerce_cart` | `commerce` (cart/draft stage; approval preview binds cart contents) |
| `commerce_order` | `commerce` (order placement stage) |
| `funds_transfer` | `funds` |
| `credential_touching` | `credential_access` |

Code grounding: the current daemon uses free-form adapter-internal
`risk_class`/`effect_class` strings in several runtime surfaces (e.g.
`"low"`, `"connector_call"`, `"runtime_state_projection"`); those predate this
consolidation and are not doc-canonical. New contract surfaces must use the
canonical ladder; migrating legacy strings is tracked implementation debt, and
this file does not pretend it has already happened.

## Privacy And Data Classes (`privacy_class`)

```text
public | internal | confidential | restricted | regulated | safety_critical
```

`privacy_class` classifies the sensitivity/handling class of data carried by an
event, artifact, task, result, or receipt. Encryption, redaction, custody,
retention, provider-trust, and execution venue are separate fields; values such
as `encrypted`, `local`, `external_api`, `tenant_private`, `tee_private`, or
`shared_encrypted` must not be overloaded into this enum. `regulated` and
`safety_critical` add domain obligations and do not by themselves name a
custody or execution posture.

## Execution Venues and Capsule Privacy Modes

The nine-venue taxonomy (local daemon, hosted IOI runtime, provider runtime,
DePIN runtime, HypervisorOS bare-metal, Private Workspace cTEE, TEE runtime,
customer VPC, embodied runtime) is owned by
[`../components/daemon-runtime/runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md).

Task-capsule execution privacy modes are a projection of that taxonomy, not a
second taxonomy:

| Privacy mode | Venue(s) it projects |
| --- | --- |
| `local` | Local Hypervisor Daemon |
| `hosted` | Hosted IOI Runtime; Provider Runtime |
| `customer_vpc` | Customer VPC Runtime |
| `depin_mutual_blind` | DePIN Runtime (mutual-blind claim set) |
| `hypervisoros_bare_metal` | HypervisorOS Bare-Metal Runtime |
| `tee_enterprise` | TEE Runtime |
| `ctee_private_workspace` | Private Workspace cTEE Runtime |
| `embodied_local` | Embodied Runtime (requires Physical Action Safety) |

`ctee_private_workspace` and `embodied_local` complete the projection so the
capsule protocol no longer lags the venue taxonomy; their runtime contracts
are design-stage (see those files' Implementation status).

## Native Embodied Runtime Profiles (`NativeEmbodiedRuntimeProfile`)

```text
micro | edge | site
```

- `micro` is the bounded MCU, PLC, flight-controller, or RTOS footprint for
  deterministic IO/control and locally enforceable safety partitions.
- `edge` is the on-unit footprint for perception, estimation, planning,
  inference, motion, replay capture, and local coordination.
- `site` is the multi-unit footprint for shared-world projections, fleet work,
  spacetime coordination, evidence, and operations.

Profiles are composable deployment footprints inside one native embodied
system. They are not products, sovereignty boundaries, assurance grades, AIIP
peers, or a requirement that every leaf host a full Hypervisor Daemon. Their
semantics and admission contract are owned by
[`../components/daemon-runtime/embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md).
The compiler, executors, and profile-specific runtimes are not implemented.

## Embodied Runtime Execution Strata (`EmbodiedRuntimeExecutionStratum`)

```text
autonomy | deterministic_motion | runtime_assurance_safety
```

- `autonomy` proposes perception-, planning-, policy-, behavior-, or
  teleoperation-derived action under declared timing and uncertainty.
- `deterministic_motion` realizes admitted motion with exact resource ownership,
  bounded scheduling, and no bypass around the safety switch.
- `runtime_assurance_safety` independently monitors the safe set and stream/time
  health, arbitrates commands, switches to bounded recovery, and holds the
  final local veto.

Strata are local fault-containment and assurance classes, not deployment
profiles. A conforming graph declares scheduling, memory, restart, and failure
boundaries for each active stratum; failure of AI, GPU, network, wallet, chain,
or remote operator cannot disable `runtime_assurance_safety`.

## ProviderAccount Kinds

Grounded verbatim in daemon code (`ACCOUNT_KINDS`,
`crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs`):

```text
baremetal_ssh | aws | gcp | k8s | vast | runpod | lambda_cloud | akash
```

Lifecycle posture per kind is owned by
[`../components/hypervisor/byo-provider-plane.md`](../components/hypervisor/byo-provider-plane.md)
(reference full lifecycle · guarded quote-gated · credential_preflight_only).
Docs must not present a kind the daemon does not admit.

## Durability Classes (`durability`)

Carried on every substrate admission ack — INV-14 rendered into the
protocol: an ack never claims a durability it has not proven. Grounded in
code (`crates/agentgres/src/lib.rs`, enforced by the replicate-then-ack
writer and proven in the unit battery):

```text
buffered               appended (write_all); device flush pending on an async cadence
device_flush           fdatasync completed on the local device before ack
replicated_same_host   a replica holds the batch bytes, but shares this host's
                       failure domain — mechanism proof, not failure-independence
quorum_replicated      acknowledged by peer(s) declared failure-independent;
                       the fractal end state (requires real multi-node deployment)
```

Rules: replication-as-durability moves device flush off the ack critical
path (background hygiene on both sides); a failed replica link degrades
acks LOUDLY to the base label — the replicated classes are never faked;
`quorum_replicated` may not be claimed by same-host peers.

## Managed Execution Modes (`managed_execution_mode`)

```text
standard | private
```

`standard` permits policy-qualified provider-trust model routes with disclosure
over IOI's private-native operating substrate. `private` additionally requires
a no-provider-trust model route and matching custody proof. These values describe
execution/custody posture only; they do not select contributors or placement.

Implementation grounding: planned product/API field. Technical evidence states
such as `private_native`, `redacted_api`, `provider_trust`, and `unsafe` remain
owned by the private-workspace/model-router contracts and are not extra product
modes.

## Goal Space Controls

### Execution policy (`goal_execution_policy`)

```text
auto | pinned | compare
```

- `auto` is 1-of-N eligible routing, including a verified cheap-first cascade;
- `pinned` uses a selected eligible route and fails closed unless fallback was
  explicitly authorized;
- `compare` is N-of-N execution under a declared verifier or synthesis rule.

These are routing policies, not plan tiers.

### Contributor scope (`contributor_scope`)

```text
my_workers | organization | network_open
```

Contributor scope selects which accountable worker/provider domains may
participate. It never declassifies data, widens authority, weakens custody, or
changes placement by itself.

Implementation grounding: both fields are planned. Their product behavior is
owned by the ioi.ai collaborative-outcome contract; model and worker routing
owners apply them to eligible routes.

## Hypervisor Product-Surface Classification

These axes classify catalog, shell, command-palette, API, and contextual-launch
projections. They are deliberately independent. In particular, being generated,
distributed through a marketplace, installed, available, or operationally deep
does not make a surface a first-party owner application.

### Surface class (`surface_class`)

```text
owner_application | substrate_application | tool_surface | extension_application
```

- `owner_application` is a first-party expert workbench with one durable product
  job and one primary object/lifecycle responsibility;
- `substrate_application` operates infrastructure lifecycle or posture, such as
  Environments or Operations, without owning logical System or Work truth;
- `tool_surface` is an editor, inspector, inbox, graph, picker, wizard, report,
  dashboard, or comparison owned by exactly one primary application even when it
  is searchable or consumed contextually elsewhere;
- `extension_application` is an organization- or publisher-authored interface,
  including a generated System interface or packaged custom application. Its
  installation and System binding are separate fields.

Core workspaces such as Home, Systems, Projects, Applications, and Work are not
members of this enum. They are navigation and policy-filtered projection
identities beside the application catalog. Automations is one
`owner_application` that may also have permanent shell placement; that creates
another launch affordance, not another registration.

The twelve enduring baseline owner applications and the conditional Embodied
Systems planned specialist registration all use `owner_application`; conditional
availability is expressed by `surface_availability`, not another class.

### Publisher origin (`surface_origin`)

```text
first_party | organization | external_publisher
```

`surface_origin` identifies who is accountable for the surface definition. A
marketplace is a distribution route, not an origin. Use `organization` for a
user, project, or organization acting inside the deployment's organization
boundary; the concrete accountable publisher remains a separate
`publisher_ref`. External publishers use a non-null `ioi://publisher/...` ref;
an organization-origin surface uses its accountable `org://...` or
`user://...` ref inside the deployment boundary. Null is reserved for bundled
first-party surfaces whose publisher accountability is fixed by the release.

### Creation method (`surface_creation_method`)

```text
hand_authored | studio_generated | developer_kit_generated | imported | adapted
```

Studio and developer-kit generation stay distinct when their admission and
conformance obligations differ. A developer kit is a creation mechanism, not a
publisher.
`adapted` may record a source-neutral implementation lineage; reference-product
screenshots, parity certificates, and capture provenance remain evidence and do
not decide product membership.

### Distribution channel (`surface_distribution`)

```text
bundled | direct_package | organization_catalog | private_registry | marketplace
```

Distribution does not grant installation, admission, authority, or launch
eligibility. `marketplace` is optional commerce/discovery over package truth;
local package lifecycle never depends on it.

### Admission state (`surface_admission_state`)

```text
not_applicable | candidate | under_review | admitted | rejected | revoked
```

Admission decides whether a candidate surface or release is eligible to enter
the product estate. It does not install or start it. Revocation removes future
eligibility without erasing historical evidence.

### Installation state (`surface_installation_state`)

```text
not_applicable | not_installed | installing | installed | update_available |
uninstalling | uninstalled
```

Installation is a binding state, not an application class or serving-health
claim.

### Package disposition (`surface_package_disposition`)

```text
not_applicable | active | deprecated | superseded | recalled
```

Recall removes ordinary launch or new-install eligibility and exposes affected
Systems. It never silently mutates, stops, or uninstalls a live System.

### Enablement state (`surface_enablement_state`)

```text
not_applicable | enabled | disabled
```

Enablement records the deployment or administrator decision that permits
ordinary launch. A disabled surface remains admitted and installed, preserves
history, and may still be inspected by authorized operators; disablement is not
revocation, recall, uninstall, unavailability, or runtime failure.

### Availability (`surface_availability`)

```text
planned | preview | limited | available | deprecated | unavailable
```

Availability describes the product exposure promise. A `planned` registration
may support roadmap and dependency inspection but is not launchable.

### Capability depth (`surface_capability_depth`)

```text
browse | inspect | propose | act | workflow_complete
```

This is the current surface-depth ladder. `act` requires at least one real,
admitted, receipted mutation. `workflow_complete` requires a real governed
intent-to-durable-result path. Maturity belongs to the registration itself: an
owner application's maturity cannot be inflated by its strongest child tool.

### Operational state (`surface_operational_state`)

```text
inactive | starting | ready | serving | degraded | blocked | stopped | unavailable
```

Operational state is current serving/readiness posture. It is independent from
capability depth and enablement: `ready` means the admitted implementation can
serve, while `serving` means an enabled route or instance is actively serving.
A workflow-complete surface can be degraded, and a ready surface may still be
browse-only.

Implementation grounding: these are canonical target enums for the planned
`HypervisorApplicationSurfaceRegistration` family and policy-filtered product-
surface compiler. The current application estate and shell still use several
hard-coded catalogs and parity-derived classifications; that is migration
evidence, not proof that this target compiler is built.

## Collaborative-Pursuit Modes

### Room mode (`room_mode`)

```text
private_goal | permissioned_team | cross_org | open_challenge
```

### Shared-state coordination topology (`coordination_topology`)

```text
hosted_admission | federated_admission
```

`hosted_admission` names one governed domain as the shared-room ordering and
admission owner. `federated_admission` names a versioned ordering, merge,
quorum/adjudication, conflict, failover, and dispute policy. Neither value
creates a global mutable Agentgres graph.

### Attempt and result outcome class (`outcome_class`)

```text
positive | negative | inconclusive | invalid | exploit_found | superseded
```

`outcome_class` is the canonical wire key on both `Attempt` and `WorkResult`.
Negative and inconclusive attempts remain durable when they contribute
information, reproduction evidence, debugging, review, integrity findings,
resource provision, or synthesis.

Implementation grounding: these values are planned contract fields on the
`OutcomeRoom`, `Attempt`, and generic `WorkResult` families in
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).
Object-local participant, frontier, claim, finding, challenge, and room lifecycle
states remain owned by their envelope schemas there.

## Improvement Evidence Claim Classes (`claim_class`)

Ordered by what the evidence establishes, not by marketing strength:

```text
bounded_optimization
self_targeted_improvement
net_positive_recursive_improvement
ignition_evidence
inflection_evidence
```

- `bounded_optimization` improved an external target under one frozen
  evaluation contract.
- `self_targeted_improvement` improved a component of the pursuit method that
  produced prior work and cleared direct, transfer, and operability gates; it
  does not establish a better future improver.
- `net_positive_recursive_improvement` establishes that the successor produced
  a better distribution of fresh lower-order outcomes, net of full physical
  and human cost, over a sustained declared transfer portfolio.
- `ignition_evidence` additionally establishes that the improved method occupied
  the next-order improver seat and produced better same-order pursuit-method
  successors than its predecessor at equal budget over a fresh portfolio.
- `inflection_evidence` requires independent reproduction of increasing rather
  than diminishing marginal gains at fixed budget across multiple recursive
  promotions.

The canonical wire key belongs on `ImprovementEvidenceClaimEnvelope` and any
Governance, Provenance, or product projection of that claim. It never changes
`target_improvement_order`. Target order, pursuit-method order, target and
candidate generation, active nesting depth, and transfer tier remain separate
coordinates. Campaign modes and Campaign/Epoch/ledger lifecycle states are
object-local and intentionally do not become global enums here.

Implementation grounding: canonical target field on the planned
`ImprovementEvidenceClaimEnvelope`; no runtime may emit a stronger member from
Campaign status or a score alone.

### Contribution kind (`contribution_kind`)

```text
planning | execution | generation | worker_invocation | service_delivery |
tool_use | model_use | dataset_use | workflow_use | resource_provision |
debugging | review | verification | replication | negative_result |
integrity_report | semantic_mapping | verifier_hardening | curation |
synthesis | training_data | distilled_training_data | training_service |
benchmark_submission | routing_selection | verifier_signal
```

This enum classifies the attributable work, not the accountable actor. The
actor remains a Worker, service, publisher, tool, organization, or domain;
models and provider routes may be attributed dependencies but are not economic
actors by endpoint identity alone. Both `ContributionEnvelope` and
`ContributionReceipt` use this same wire field and member set.

## External-Effect Recovery Classes (`effect_recovery_class`)

```text
replayable | checkpointable | compensatable | reconciliation_required | non_retryable
```

This class describes what may happen after timeout, provider failure, or an
ambiguous external effect. Environment restoration never proves outcome
restoration. `reconciliation_required` and `non_retryable` must fail closed
rather than replaying an effect whose prior commit state is unknown.

Implementation grounding: planned across ontology actions, provider recovery,
runtime reconciliation, and receipt contracts.

## Model-Route Commercial Rights

These member sets are carried by the versioned provider/model route contract:

```text
commercial_posture
  direct | aggregator | customer_byok | customer_byoa | self_hosted

access_mode
  named_human_seat | api | dedicated_endpoint | self_hosted

automation_right
  interactive_only | unattended_allowed | negotiated

downstream_right
  internal_only | customer_application | reseller_oem

credential_principal
  named_human | service_account | customer_owned

provider_material_use_right
  prohibited | transient_only | security_incident_only | contract_limited |
  explicitly_permitted | not_applicable

provider_retention_posture
  zero_retention | transient_processing | contract_bounded |
  provider_default | not_applicable

customer_output_use_right
  prohibited | terms_limited | expressly_licensed | open_license
```

`provider_material_use_right` is the shared value family for the route
contract's request/prompt logging, human-review, abuse/security, service-
improvement, provider-training, and cross-customer-aggregation fields; each
field uses only the members meaningful to that purpose.
`customer_output_use_right` applies independently to retain, replay,
evaluation, RAG/memory, same-provider tuning, distillation, competing-model
training, internal-package reuse, publication, and resale.

Missing unattended, downstream, provider-use, customer-output-use, or training
rights fail closed. Inference rights never imply either provider secondary-use
rights or customer training/distillation rights. Implementation grounding:
route registry/local Ollama execution is partial; commercial-rights admission,
sealed BYOK, and broad provider transports remain planned or unimplemented.

## Autonomous-System Ordering And Finality Profiles

Every bounded autonomous system declares how operations become canonical. The
profile is a property of the logical system, not a synonym for node count:

```text
single_authority | replicated_single_authority | threshold_authority |
bft_consensus | external_chain_finality
```

- `single_authority` admits through one declared writer. A PoA-1 or
  operator-controlled deployment may use this profile.
- `replicated_single_authority` preserves one writer authority while replicating
  ordered state to declared failure domains for recovery, reads, and failover.
- `threshold_authority` requires the declared threshold of independently held
  authority shares before admission.
- `bft_consensus` admits through a versioned Byzantine-fault-tolerant protocol
  and named membership/governance rules.
- `external_chain_finality` treats a named external consensus system as the
  finality source for the transitions in scope.

No member implies that the system is public, permissionless, economically
independent, or IOI-secured. A `single_authority` system can still be a bounded
distributed autonomous system and an intelligent blockchain when its
constitution, operation log, policy, authority, receipts, replay, lifecycle,
and improvement boundaries are explicit. Consensus increases the set of
failures or adversaries the system can tolerate; it does not create bounded
agency by itself.

Implementation grounding: planned contract field on
`OrderingAdmissionFinalityProfileEnvelope`. Existing Agentgres primary/standby
mechanisms are evidence for replication and fencing, not a claim that dynamic
membership, automatic failover, threshold authority, or BFT consensus exists.

## Autonomous-System Node Roles (`autonomous_system_node_role`)

```text
admission_writer | hot_standby | state_replica | projection_replica |
execution_worker | artifact_replica | verifier | availability_witness |
gateway | authority_member | consensus_member
```

A node may hold multiple declared roles. Roles do not grant authority by their
name; admission, membership, leases, fencing epochs, and the system's ordering
profile do. Adding a node must never silently widen authority or change
finality.

Implementation grounding: planned contract field on
`AutonomousSystemDeploymentProfileEnvelope` and system membership records.

## IOI Network Enrollment Profiles (`ioi_network_enrollment`)

```text
ioi_compatible | ioi_connected | ioi_secured
```

- `ioi_compatible` uses the open L0 contracts or conformance profile without a
  mandatory IOI L1 dependency, network fee, or IOI Network assurance claim.
- `ioi_connected` additionally registers selected commitments and uses AIIP or
  optional IOI rights, reputation, escrow, dispute, and settlement services.
  It pays only for services it explicitly consumes.
- `ioi_secured` opts into an approved Standard DAS profile and named shared
  security/assurance services such as verifier, guardian, availability,
  ordering, or finality coverage. It accepts the declared bonds, service fees,
  slashing/dispute rules, or explicit network-contribution covenant.

Enrollment is explicit, versioned, and reversible subject to outstanding
obligations. Compatibility does not imply connection; connection does not imply
shared security. No profile creates an ambient tax on local execution.

Implementation grounding: target contract enum on `IOINetworkEnrollmentEnvelope`;
the profiles and associated network services are not yet deployed.

## Settlement Modes (`settlement_mode`)

```text
local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1
```

The mode names the selected settlement rail, not the trigger that caused a
settlement intent. Trigger conditions such as acceptance, dispute, reputation
publication, periodic root, or contract condition belong to the referenced
settlement/public-commitment policy.

- `local_domain` is the default and requires no external network.
- `bilateral` binds a counterparty-agreed off-network settlement record.
- `invoice` binds a declared invoice/payment ledger.
- `external_escrow` binds a named escrow service and terms.
- `external_chain` binds a named non-IOI chain/network, contract, asset, and
  confirmation policy.
- `ioi_l1` is valid only under an active `ioi_connected` or `ioi_secured`
  enrollment that selected the named service.

Work Credits are not a settlement mode or payout asset. Missing, expired,
suspended, or mismatched enrollment/rail facts fail closed rather than falling
back to IOI L1.

Implementation grounding: canonical target field used across the common
settlement-selection contract and `SettlementEnvelope`; broad runtime and
marketplace migration remains planned.

## Assurance Stages (`assurance_stage`)

Ordered from the narrowest attributable statement to economic finality:

```text
attested | evidenced | verified | accepted | adjudicated | settled
```

A receipt proves only the declared boundary fact it binds. It does not by
itself establish external-world occurrence, correctness, causality, acceptance,
or economic value. The field-level receipt schemas remain owned by the events
and receipts contract.

## Ownership Pointers (enums owned elsewhere)

- **RuntimeToolContract field set** — owned by
  [`../components/connectors-tools/contracts.md`](../components/connectors-tools/contracts.md).
  The contract's `risk_class` draws from the ladder above; other docs show the
  contract only as a labeled excerpt.
- **Receipt type schemas** — owned by
  [`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).
  Venue/domain docs describe when their receipts mint, not what fields they
  have.
- **Placement fee bases** (`none | subscription_control_plane |
  adapter_orchestration_fee | routing_fee | managed_margin`) — owned by
  [`../components/hypervisor/byo-provider-plane.md`](../components/hypervisor/byo-provider-plane.md).
- **OutcomeRoom object-local lifecycle states** — owned by
  [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md). This
  file owns only the cross-component room, topology, and outcome sets above.

## Related Canon

- [`invariants.md`](./invariants.md) — canonical invariant registry.
- [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md) — shared envelopes and ID namespaces.
