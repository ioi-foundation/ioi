# Canonical Enumerations

Status: canonical architecture authority.
Doctrine status: canonical
Implementation status: mixed (each enum states its code grounding)
Canonical owner: this file for the canonical member set and spelling of cross-component enumerations that previously drifted.
Supersedes: divergent local redefinitions of risk classes, execution venues /
privacy modes, provider account kinds, Goal Space controls, collaborative-
pursuit modes, provider-route rights, and assurance stages.
Superseded by: none.
Last alignment pass: 2026-07-11.

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

output_training_right
  prohibited | noncompeting_only | expressly_licensed | open_license
```

Missing unattended, downstream, or training rights fail closed. Inference
rights never imply training or distillation rights. Implementation grounding:
route registry/local Ollama execution is partial; commercial-rights admission,
sealed BYOK, and broad provider transports remain planned or unimplemented.

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
