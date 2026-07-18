# ADR 0011: Canonicalize Hypervisor Nodes As Local Settlement Domains

- Status: Superseded by [ADR 0015](./0015-bounded-distributed-autonomous-systems-and-network-enrollment.md)
- Date: 2026-05-24
- Owners: IOI architecture / Hypervisor / daemon runtime / Agentgres / wallet.network / IOI L1

## Context

IOI needs precise language for the relationship between local autonomous
systems, Hypervisor, Agentgres, wallet.network, and IOI L1.

Several useful analogies were circulating:

- each agent as an intelligent blockchain;
- each autonomous system as a local L1;
- Hypervisor as a settlement layer;
- IOI L1 as the global machine-economy layer.

Those analogies point at a coherent architecture, but they can also overclaim.
They risk implying that every agent is a standalone public blockchain, that the
Hypervisor UI owns settlement, or that IOI L1 records every internal step of
every autonomous system.

## Decision

IOI adopts the following canonical layer split:

```text
Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts

Hypervisor Node
  local orchestration, interop, authority, state, replay, routing, and local settlement

IOI L1
  global identity, registry, rights, receipt roots, disputes, reputation, and economic settlement
```

A **Hypervisor Node** is the local autonomous-system settlement domain for a
user, organization, project, or deployment. It is not merely the Workbench UI.
It is the composition of Hypervisor Core clients and surfaces, Hypervisor
Daemon, Agentgres, wallet.network authority paths, local registries,
receipt/replay stores, and runtime profiles.

A **governed autonomous-system chain** is a policy-bound, stateful autonomous
execution object whose bounded GoalRuns and scoped HarnessInvocations may invoke
typed service modules, emit receipts, and commit consequential transitions only
through deterministic authority and governance paths.

The canon sentence is:

> **Hypervisor Nodes are local settlement domains for autonomous systems; IOI L1
> is the global settlement layer for the machine economy.**

## Consequences

- Public architecture should avoid saying "each agent is a blockchain" without
  qualification. Use `governed autonomous-system chain`, `governed autonomous
  system`, `intelligent execution node`, or `Hypervisor Node` depending on the
  layer.
- Internal state-machine discussions may use "system-local base layer" for a
  governed autonomous system, but `IOI L1` remains reserved for the shared
  public chain.
- Hypervisor-node settlement means local canonical acceptance of work, state
  transitions, proposals, receipts, authority outcomes, and interop messages.
- IOI L1 settlement means public economic, registry, rights, dispute,
  reputation, governance, and root-anchoring finality.
- Agentgres owns the local/domain operational truth for autonomous-system
  chains and Hypervisor-node state.
- wallet.network owns authority, secrets, grants, leases, approvals, payments,
  and revocation.
- aiagent.xyz and sas.xyz connect to the global machine economy through IOI L1
  roots, rights, marketplaces, settlement, and disputes while retaining rich
  operational state in Agentgres-backed domains.

## Non-Goals

- Do not make Hypervisor Workbench the settlement layer.
- Do not make every agent a public blockchain, validator, or standalone L1.
- Do not put every agent step, HarnessInvocation, receipt, or Agentgres operation on
  IOI L1.
- Do not let autonomous systems self-modify or self-grant authority outside
  proposal, policy, approval, receipt, and governance paths.

## Canonical References

- `docs/architecture/foundations/governed-autonomous-systems.md`
- `docs/architecture/foundations/verifiable-bounded-agency.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/agentgres/doctrine.md`
- `docs/architecture/foundations/ioi-l1-mainnet.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
