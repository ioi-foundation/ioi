# Canonical Enumerations

Status: canonical architecture authority.
Doctrine status: canonical
Implementation status: mixed (each enum states its code grounding)
Canonical owner: this file for the canonical member set and spelling of cross-component enumerations that previously drifted.
Supersedes: divergent local redefinitions of risk classes, execution venues / privacy modes, and provider account kinds.
Superseded by: none.
Last alignment pass: 2026-07-05.

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

## Related Canon

- [`invariants.md`](./invariants.md) — canonical invariant registry.
- [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md) — shared envelopes and ID namespaces.
