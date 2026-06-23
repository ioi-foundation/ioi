# Canonical Web4 and the IOI Stack

Status: canonical architecture authority.
Canonical owner: this file for the Web4 category definition and IOI stack boundary.
Supersedes: overlapping product or plan prose when the Web4 stack definition conflicts.
Superseded by: none.
Last alignment pass: 2026-06-22.

## Canonical Definition

**Canonical Web4 is the internet architecture where applications do not merely let users read, write, or own state; they delegate bounded authority to autonomous actors that can act across systems under verifiable policy, receipts, and settlement.**

Category definition:

> **Web4 is the protocol category for machine authority: bounded autonomous
> actors receiving scoped power to perform consequential work with proof,
> revocation, interop, and settlement.**

Short form:

> **Web4 = Read + Write + Own + Act, with proof.**

IOI defines and implements canonical Web4 as a machine-authority stack.

Protocol thesis:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

Product thesis:

> **Governed work should be able to become reusable autonomous capability.**

Builder/category thesis:

> **IOI is the Web4 substrate for building autonomous-system domains:
> intelligent blockchains where workers can act, authority is bounded, receipts
> prove what happened, and settlement happens only when shared trust requires
> it.**

Web4 is not only about delegation. It is about compounding useful work into
portable workers, workflows, tools, model routes, evals, data recipes,
packages, service modules, and market-listed capabilities without collapsing
execution, authority, truth, and settlement into one vendor-owned layer.

## Provider-Trust Boundary

Canonical Web4 moves machine authority outside provider trust by default.

Providers may supply cognition, compute, storage, connectors, liquidity,
distribution, hosted workspaces, or managed execution. They are useful execution
and service participants. They are not the default authority root, secret owner,
policy owner, receipt truth, settlement root, or revocation plane.

Provider-trust routes are still allowed when a user, organization, policy, or
domain explicitly accepts them. They must be labeled, policy-bound, receipted,
revocable where possible, and distinct from routes where authority, secrets,
plaintext custody, and settlement commitments remain outside provider control.

## Blockchain Substrate and User Abstraction

Web4 is blockchain-native underneath, but it must not be chain-first in ordinary
product experience. In IOI, blockchain is the verifiability, rights, dispute,
governance, and settlement substrate below machine authority; users mostly meet
it as authority grants, receipts, proofs, state roots, revocation controls,
contribution records, and settlement outcomes.

The default user experience should abstract raw chain mechanics behind
machine-authority language. A user should be able to ask what was authorized,
what executed, what proof exists, what can be revoked, and what settled without
having to reason about contracts, gas, chain IDs, custody, transaction hashes, or
bridge details during every task.

The substrate still has to be knowable. Receipts, replay views, settlement
views, dispute views, developer consoles, exportable evidence bundles, and
state-root/proof drilldowns must let technical users, auditors, counterparties,
and autonomous systems inspect the underlying commitments when public trust,
settlement, governance, or dispute resolution depends on them.

## Category Ownership Doctrine

IOI's Web4 category claim is to make **machine authority** the legible
primitive.

Machine authority is the protocolized ability for a non-human actor, worker,
runtime, workflow, service, or autonomous system to receive limited power from a
human, organization, domain, or contract and use that power across real systems.
The power is bounded by identity, scope, policy, purpose, time, budget, data
permission, approval requirements, revocation, receipts, replay, and settlement.

The category is not won by calling every agent a wallet or every application a
chain. It is won by making the machine-authority path portable and unavoidable:

```text
intent
  -> authority request
  -> scoped lease / denial / step-up
  -> runtime assignment
  -> policy and admission
  -> autonomous execution
  -> receipts and replay
  -> Agentgres state root or projection
  -> AIIP handoff or settlement intent
  -> sparse IOI L1 commitment when public trust is required
```

This is the protocol substrate for autonomous work. It is source-neutral: any
model, runtime, connector, worker, marketplace, enterprise domain, or sovereign
application can participate if it speaks the same authority, receipt, interop,
and settlement semantics.

The category claim is not that every Web4 product should become an IOI-hosted
L1. The claim is that the IOI L0/kernel, Hypervisor, SDK, ADK, AIIP,
wallet.network, Agentgres, and IOI L1 together make it practical to create
autonomous-system domains that can remain sovereign at the edge while becoming
interoperable, attributable, and economically legible through shared authority,
receipt, reputation, and settlement semantics.

IOI's category wedge is therefore:

```text
machine authority protocol
  + edge-in domain kernels
  + wallet.network authority leases
  + Hypervisor execution/admission
  + Agentgres operational truth
  + AIIP work interop
  + IOI L1 sparse settlement
  = canonical Web4
```

## Web Evolution

```text
Web1: Read
Web2: Write
Web3: Own
Web4: Act
```

A Web4 application has autonomous execution as a first-class ability. It can run workers, workflows, tools, connectors, model calls, and service deliveries, while preserving authority boundaries and verifiable state.

Web4 does not make the model the economic actor. In IOI, the protocol actor is
the **Worker**: a bounded executable actor with manifest, policy envelope,
capability surface, receipt obligations, and settlement identity. Models are
cognition backends mounted by workers. Agents are product-facing or colloquial
UX language.

Models are deployment-profile resources, not architecture-default node
binaries. A Hypervisor Node includes model routing and invocation boundaries;
local weights, local servers, BYOK providers, hosted pools, TEE/DePIN sessions,
or customer VPC endpoints are mounted by policy and deployment profile.

## IOI Reference Stack

```text
IOI Kernel / L0 Substrate
  reusable domain, runtime, policy, receipt, and state-machine primitives

IOI L1
  canonical Web4 registry, contracts, rights, settlement, governance, release commitments

wallet.network
  identity, secrets, authority grants, approvals, payments, revocation

Agentgres Domains
  application/domain state, runs, orders, receipts, projections, quality, contribution accounting

Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts, and upgrade paths

Hypervisor Nodes
  local autonomous-system orchestration, interop, authority, state, replay, routing, and settlement domains

AIIP
  RPC-shaped, receipt-native interop for bounded autonomous work, handoffs, authority, receipts, settlement intents, disputes, and reputation queries

Domain Ontologies and Data Recipes
  semantic data plane for ontology-bound sources, connector mappings, evals, and projections

Hypervisor Daemon / Runtime Nodes
  execution runtime for workflows, workers, tools, models, connectors, artifacts

Mixture of Workers
  labor routing across bounded workers by policy, benchmarks, receipts, cost, trust, and contribution quality

Client Surfaces
  Hypervisor App, Hypervisor Web, CLI/headless, optional TUI, SDK, ADK,
  Workbench, Workflow Compositor, browser apps, harness profiles, benchmarks

Hypervisor Application Surfaces
  Workbench, Foundry, Agents / Workers, Models, Connectors / Tools / MCP,
  Data / Knowledge, Ontology, Authority / Govern, Receipts / Replay,
  Operate / Monitoring, Providers / Environments, Privacy / cTEE,
  Change Plane, Marketplace, Patterns / Examples / Training, Domain Apps

Storage Backends
  immutable package, artifact, evidence, receipt, checkpoint, snapshot, sealed archive byte availability

aiagent.xyz
  first-party worker marketplace using AIIP and IOI settlement

sas.xyz
  first-party service/outcome marketplace using AIIP and IOI settlement

ioi.ai
  lightweight account, device, restore, publishing, entitlement, and runtime-discovery control plane
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
11. **Worker routing over model centrality** — MoW selects accountable workers,
    not merely model providers.
12. **Trainable supply** — workflows, examples, corrections, data, and gates can
    become trained workers without collapsing IOI into a training-only platform.
13. **Local autonomous-system settlement** — Hypervisor Nodes settle autonomous
    work locally and anchor selected roots to IOI L1 only when public trust or
    economic settlement requires it.
14. **Work interop** — AIIP moves delegated work, authority leases, receipts,
    settlement intents, disputes, reputation queries, and handoffs between
    bounded execution domains.
15. **Machine-authority protocol compliance** — authority requests, leases,
    denials, step-up challenges, delegation, revocation, proof obligations, and
    settlement intents use portable machine-readable envelopes rather than
    product-local permission checks.

## IOI System Boundary

IOI is not one monolithic chain and not one monolithic application. It is a layered architecture:

```text
IOI Kernel / L0 Substrate = reusable kernel/toolchain for domains and chains
IOI L1                    = public coordination, settlement, governance, release commitments
Application Domains       = per-app kernel + Agentgres state substrate
Governed AS Chains        = local autonomous-system state machines with modules, proposals, receipts
Hypervisor Nodes           = local settlement and interop domains for many governed AS chains
AIIP                      = semantic work interop for local and cross-system autonomous handoffs
Semantic Data Plane       = ontologies, object models, recipes, mappings, policy-bound views
Execution Nodes           = local/hosted/DePIN/TEE/customer runtime nodes
Authority Plane           = wallet.network
Artifact-Ref Plane        = Agentgres artifact refs
Storage Backends          = local disk, S3/object stores, Filecoin, CAS/IPFS, provider blobs
Application Surfaces      = Workbench, Foundry, Agents / Workers, Models, Connectors / Tools / MCP, Data / Knowledge, Ontology, Authority / Govern, Receipts / Replay, Operate / Monitoring, Providers / Environments, Privacy / cTEE, Change Plane, Marketplace, Patterns / Examples / Training, Domain Apps
Developer/Operator Clients = Hypervisor App, Hypervisor Web, IOI CLI/headless, optional TUI, @ioi/agent-sdk, IOI ADK, Workbench, Workflow Compositor, harness profiles
MoW Routing               = worker selection, sparse categories, contribution policy, benchmark eligibility
```

Storage/state split:

```text
Agentgres = state machine, query substrate, and artifact-ref authority
Domain Ontologies/Data Recipes = semantic data truth for training/evaluation/projections
Storage backends = payload bytes, evidence bytes, and sealed archive bytes
IOI L1 = trust, registry, rights, settlement, and sparse commitments
Hypervisor Node = local orchestration, interop, authority, receipts, replay, and settlement
AIIP = work interop protocol across bounded execution domains
Hypervisor Daemon runtime nodes = execution layer
MoW = labor routing layer for bounded workers
Hypervisor App/Web/CLI-headless/SDK/ADK/Workbench/Workflow Compositor = clients, builder frameworks, and projections over runtime/domain contracts
TUI = optional CLI presentation over the same runtime/domain contracts
Workbench/Foundry = application surfaces over Hypervisor Core and daemon/domain contracts
Providers / Environments = first-party application catalog, Open Application, and contextual views over sessions, providers, and environments
```

## Edge-In Topology

IOI intentionally inverts traditional blockchain topology.

Chain-first topology usually starts from the global ledger:

```text
global chain
  -> application contracts
  -> hosted app/backend
  -> user/client edge
```

IOI starts at the edge where work actually happens:

```text
local or remote runtime edge
  -> domain kernel + Agentgres operational truth
  -> Domain Ontologies and Data Recipes for semantic data truth
  -> receipts, artifacts, state roots, and contribution records
  -> sparse commitments to IOI L1 when public trust is required
```

This keeps autonomous work local-first, zero-to-idle, and domain-specific while
still giving consequential commitments a global settlement and governance root.

This is the Web4 domain flywheel: each new domain, worker market, service
market, enterprise kernel, robot fleet, or independent AS-L1 that reuses the
shared authority, receipt, AIIP, and settlement grammar increases the value of
the substrate without forcing operational state into one global runtime.

Agentgres state is not Filecoin blobs. Agentgres records canonical operations,
object heads, indexes, projections, subscriptions, delivery state, receipts
metadata, artifact refs, archive refs, and restore validity. Storage backends
such as Filecoin/CAS store the bulky immutable payloads those refs point to.

Raw source data is not domain truth by itself. Domain Ontologies define what the
work means; Data Recipes prove how documents, traces, connector payloads, and
examples became ontology-bound training, evaluation, runtime, and projection
data.

## What Web4 Apps Are Not

A canonical Web4 app is not merely:

- a website with an LLM chat box;
- a smart contract with a frontend;
- a model endpoint;
- a fine-tuning dashboard;
- a generic AI worker catalog without receipts, benchmarks, and routing semantics;
- a DePIN compute node;
- a workflow graph without authority or receipts;
- a marketplace listing without execution and delivery semantics.

A canonical Web4 app is a stateful, authority-aware, autonomous application domain.

## Category Examples

| App | Canonical Web4 Role |
|---|---|
| Hypervisor Core | Shared product/runtime substrate for governed autonomous work; the Hypervisor Daemon owns execution inside it. |
| Hypervisor App | Native desktop client over Hypervisor Core. |
| Hypervisor Web | Browser/team/remote client over Hypervisor Core. |
| Hypervisor Workbench | Code/systems/workspace application surface over Hypervisor Core, with editors and terminals as adapter targets. |
| Hypervisor Node | Local settlement, interop, authority, state, replay, and routing domain for governed autonomous systems. |
| AIIP | RPC-shaped, receipt-native interop protocol for autonomous work across bounded execution domains. |
| Bounded Execution Domain | Any local, hosted, enterprise, marketplace, robot, worker, service, microharness, or AS-L1 domain that performs scoped autonomous work under policy and receipts. |
| Governed Autonomous-System Chain | Local stateful execution object with policy, modules, proposals, receipts, and governed upgrades. |
| IOI CLI/headless | Local operator, scripting, CI, and node-ops client for daemon, domain, authority, receipt, and settlement workflows; TUI is an optional presentation. |
| IOI SDK | Low-level protocol/client library over daemon, Agentgres, wallet.network, AIIP, and IOI L1 contracts. |
| IOI ADK | Autonomous development kit for building workers, service modules, harnesses, evals, manifests, receipts, deployment profiles, and governed autonomous systems. |
| Hypervisor Daemon | Portable runtime endpoint for local, hosted, provider, DePIN, TEE, and customer execution. |
| IOI Kernel / L0 Substrate | Reusable substrate for creating application domains, sovereign domains, and intelligent or non-intelligent chains/state machines. |
| MoW | Labor-routing layer for bounded workers, sparse categories, routing receipts, and contribution accounting. |
| Domain Ontologies and Data Recipes | Semantic data plane for ontology-bound training, evaluation, connector mapping, and Agentgres projections. |
| Hypervisor Foundry | Product surface for capturing, training, evaluating, and deploying workers through Hypervisor. |
| aiagent.xyz | First-party marketplace for portable Web4 workers, benchmarks, sparse categories, installs, managed instances, and routing eligibility, built on AIIP and IOI settlement. |
| sas.xyz | First-party marketplace for Web4 service outcomes, including Worker Training contracts, built on AIIP and IOI settlement. |
| ioi.ai | Lightweight user/control plane for accounts, devices, restore, publishing, sync metadata, and runtime discovery. |
| wallet.network | Authority vault and scope control plane. |
| Agentgres | State/change/provenance substrate for Web4 application domains. |
| IOI L1 | Registry, rights, settlement, governance, and autonomous-system settlement layer for Web4. |
| Machine Authority Protocol | Portable authority-request, lease, revocation, proof, and settlement semantics that let machines act without receiving ambient secrets or uncontrolled power. |

## Core Doctrine

> **IOI does not define a proprietary Web4. IOI implements canonical Web4:
> machine authority for autonomous action with identity, scoped power, receipts,
> interop, and settlement.**
