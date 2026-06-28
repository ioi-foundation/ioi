# ADR 0012: Define IOI As Autonomous-System Settlement Layer And AIIP As Work Interop

- Status: Accepted
- Date: 2026-05-25
- Owners: IOI architecture / IOI L1 / AIIP / Hypervisor / aiagent.xyz / sas.xyz / wallet.network / Agentgres

## Context

IOI architecture had already separated governed autonomous-system chains,
Hypervisor Nodes, and IOI L1. That clarified local and global settlement but did
not fully name the protocol category.

The remaining ambiguity was whether IOI should be framed as:

- an agent marketplace;
- an outcome marketplace;
- agents on a blockchain;
- a local Hypervisor Node architecture;
- a broader autonomous-system settlement and interoperability layer.

The broader category is the durable one. Autonomous systems can run in local
runtimes, private enterprise environments, third-party systems, microharnesses,
robots, VMs, APIs, model providers, marketplaces, or independent
autonomous-system L1s. The shared problem is not where execution happens. The
shared problem is how authority, receipts, payments, reputation, disputes,
worker eligibility, routing decisions, and cross-system handoffs become
trustworthy across systems.

## Decision

IOI adopts this protocol thesis:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

IOI mainnet is the base settlement layer for sovereign autonomous systems. It
settles the consequential record of autonomous work when public trust,
economic finality, reputation portability, dispute resolution, or cross-system
interoperability requires it.

AIIP is IOI's RPC-shaped, receipt-native interoperability protocol for bounded
autonomous work.

Canonical split:

```text
Autonomous systems execute anywhere.
AIIP routes delegated work across systems.
Receipts prove what happened.
IOI mainnet settles the consequential record.
```

AIIP is used for both internal Hypervisor microharness routing and external
handoffs between workers, service providers, marketplaces, enterprises,
third-party systems, and independent AS-L1s. The protocol semantics stay the
same; transport, trust boundary, privacy posture, and settlement depth vary by
profile.

aiagent.xyz and sas.xyz are first-party protocol applications and demand
generators. They use AIIP and IOI settlement, but they do not define the full
protocol boundary.

## Consequences

- Public whitepaper and protocol docs should lead with settlement for
  autonomous systems, not merely agents on a blockchain.
- IOI L1 docs should name authority, receipts, payments, reputation, disputes,
  worker eligibility, routing roots, AIIP channel/schema registration, and
  cross-system handoff finality as core settlement objects.
- AIIP requires its own canonical foundation doc and later low-level protocol
  references for packets, profiles, conformance, channels, relay/router
  markets, and privacy modes.
- Hypervisor becomes the reference meta-harness and local governance surface for
  AIIP-powered work, not the entire protocol.
- First-party marketplaces should be described as applications of the protocol,
  not as the protocol itself.
- Independent AS-L1s, appchains, sovereign domains, enterprises, robot fleets,
  and third-party autonomous systems are positive when they increase IOI
  settlement demand.
- Routing decisions that affect payment, reputation, trust, settlement, or
  disputes should produce routing receipts.

## Non-Goals

- Do not require every autonomous action to settle on IOI mainnet.
- Do not turn IOI mainnet into a model-inference or workflow-execution chain.
- Do not create separate bespoke interop APIs for Hypervisor, aiagent.xyz,
  sas.xyz, and external systems when AIIP semantics apply.
- Do not let each appchain invent isolated authority, receipt, reputation, or
  dispute standards.
- Do not make users reason about low-level channel/path mechanics when a
  quote/invoke/handoff/settle call shape can hide that complexity.
- Do not make public disclosure the default for private enterprise or personal
  execution data.

## Canonical References

- `docs/architecture/foundations/aiip.md`
- `docs/architecture/foundations/governed-autonomous-systems.md`
- `docs/architecture/foundations/ioi-l1-mainnet.md`
- `docs/architecture/foundations/web4-and-ioi-stack.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/domains/aiagent/worker-marketplace.md`
- `docs/architecture/domains/sas/service-marketplace.md`
- `docs/architecture/domains/marketplace-neutrality.md`
