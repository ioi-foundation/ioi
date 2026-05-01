# Canonical Web4 and the IOI Stack

Status: canonical architecture authority.
Canonical owner: this file for the Web4 category definition and IOI stack boundary.
Supersedes: overlapping product or plan prose when the Web4 stack definition conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**Canonical Web4 is the internet architecture where applications do not merely let users read, write, or own state; they delegate bounded authority to autonomous actors that can act across systems under verifiable policy, receipts, and settlement.**

Short form:

> **Web4 = Read + Write + Own + Act, with proof.**

IOI is the reference implementation of canonical Web4.

## Web Evolution

```text
Web1: Read
Web2: Write
Web3: Own
Web4: Act
```

A Web4 application has autonomous execution as a first-class ability. It can run workers, workflows, tools, connectors, model calls, and service deliveries, while preserving authority boundaries and verifiable state.

## IOI Reference Stack

```text
IOI L1
  canonical Web4 registry, contracts, rights, settlement, governance

wallet.network
  identity, secrets, authority grants, approvals, payments, revocation

Agentgres Domains
  application/domain state, runs, orders, receipts, projections, quality, contribution accounting

Autopilot / IOI CLI/Daemon
  execution runtime for workflows, workers, tools, models, connectors, artifacts

Filecoin / CAS / CDN
  package, artifact, evidence, receipt, checkpoint availability

aiagent.xyz
  worker marketplace Web4 application domain

sas.xyz
  service/outcome marketplace Web4 application domain
```

## Canonical Web4 Requirements

A canonical Web4 application should have:

1. **Identity-bound actors** — users, agents, workers, publishers, providers, and runtimes have stable identity.
2. **Scope-bound authority** — autonomous actors receive bounded powers, not ambient authority.
3. **Policy-bounded execution** — consequential actions pass through explicit policy and approval paths.
4. **Autonomous runtime** — workers and workflows can act over time, not only answer prompts.
5. **Verifiable state changes** — important state transitions bind to receipts, evidence, roots, or commitments.
6. **Revocation and emergency stop** — granted authority can be withdrawn.
7. **Portable manifests** — workers, services, workflows, models, apps, and domains are described by signed manifests.
8. **Settlement-aware outcomes** — economic delivery and reputation are backed by contracts, escrows, bonds, roots, or receipts.
9. **Local-first and zero-to-idle paths** — clients and runtimes serve from local/static/projection state where possible, waking authority only when needed.
10. **Marketplace neutrality** — default runtime/harness infrastructure does not silently absorb third-party intelligence.

## IOI System Boundary

IOI is not one monolithic chain and not one monolithic application. It is a layered architecture:

```text
IOI L1                    = public coordination and settlement
Application Domains       = per-app kernel + Agentgres state substrate
Execution Nodes           = local/hosted/DePIN/TEE/customer runtime nodes
Authority Plane           = wallet.network
Payload Plane             = Filecoin/CAS/CDN
Application Surfaces      = React/Web/native apps such as Autopilot, aiagent.xyz, sas.xyz
```

## What Web4 Apps Are Not

A canonical Web4 app is not merely:

- a website with an LLM chat box;
- a smart contract with a frontend;
- a model endpoint;
- a DePIN compute node;
- a workflow graph without authority or receipts;
- a marketplace listing without execution and delivery semantics.

A canonical Web4 app is a stateful, authority-aware, autonomous application domain.

## Category Examples

| App | Canonical Web4 Role |
|---|---|
| Autopilot | Local Web4 runtime and workflow construction surface. |
| aiagent.xyz | Marketplace for portable Web4 workers. |
| sas.xyz | Marketplace for Web4 service outcomes. |
| wallet.network | Authority vault and scope control plane. |
| Agentgres | State/change/provenance substrate for Web4 application domains. |
| IOI L1 | Registry, rights, settlement, and governance layer for canonical Web4. |

## Core Doctrine

> **IOI does not define a proprietary Web4. IOI implements canonical Web4: autonomous action with identity, authority, receipts, and settlement.**
