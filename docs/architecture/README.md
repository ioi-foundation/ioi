# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-05-25.

## Purpose

This pack distills the IOI / canonical Web4 architecture into separate
authority documents so each facet has a clear role, boundary, and dependency
surface.

The core doctrine is:

> **IOI is an edge-in Web4 stack for alignment-secure machine authority:
> workers act under scoped authority, domains remember operational truth, and
> IOI L1 settles only the commitments that need public trust.**

The protocol thesis is:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

The Autopilot/autonomous-execution canon is:

```text
IOI daemon = hypervisor/control plane for autonomous execution
Autopilot Node = local autonomous-system settlement and interop domain
Autopilot Workbench = IDE-grade operator console
Electron/VS Code fork = canonical app shell
IOI Authority Gateway = compatibility adapter profile for existing IDEs/agents
Workers/models/tools/connectors = guest workloads/capabilities
Policy/receipts/replay = trust and audit substrate
```

Product taxonomy:

> **The IOI Runtime Daemon is the deterministic execution substrate for portable,
> verifiable autonomous systems. Autopilot is the flagship product surface for
> building, deploying, and governing those systems.**

Machine-economy canon:

> **Autopilot nodes are local settlement domains for autonomous systems; IOI L1
> is the global settlement layer for the machine economy.**

Interop canon:

> **AIIP moves autonomous work across systems. IOI settles what happened.**

Read the stack this way:

- the IOI kernel is the L0 substrate for instantiating domains and chains;
- IOI L1 anchors rights, settlement, registries, disputes, governance, release
  commitments, and public commitments;
- domain kernels run Agentgres, routing, policy, projections, and application
  state;
- governed autonomous-system chains are local stateful execution objects with
  policy, modules, proposals, receipts, and upgrade paths;
- Domain Ontologies and Data Recipes bind raw sources into trainable,
  queryable, receipted, and distillable domain truth;
- IOI daemon/runtime nodes act as the autonomous-execution hypervisor/control
  plane, supervising workers, workflows, tools, models, connectors, computer-use
  leases, artifacts, policy, receipts, and replay;
- Autopilot nodes coordinate many governed autonomous-system chains, route work
  between them, manage local authority and receipts, and anchor selected roots
  upward when public trust or settlement requires it;
- AIIP is the RPC-shaped, receipt-native interop protocol for bounded
  autonomous work across microharnesses, workers, services, marketplaces,
  enterprises, third-party autonomous systems, and AS-L1s;
- wallet.network authorizes identity, secrets, approvals, payments, data use,
  and decryption;
- Filecoin/CAS stores payload bytes, packages, artifacts, evidence bundles,
  checkpoints, and sealed archive bytes;
- MoW routes bounded workers by policy, benchmarks, receipts, cost, trust, and
  contribution quality;
- Autopilot Workbench is the IDE-grade operator console for autonomous systems,
  exposed through the Electron/VS Code fork as the canonical app shell and backed
  by local or remote daemon profiles;
- IOI Authority Gateway is the daemon sidecar/adapter profile for existing IDE,
  CLI, browser, hosted-agent, and MCP/tool ecosystems: keep your IDE, keep your
  model, and put consequential execution behind IOI;
- agent-ide and the workflow compositor render typed recipes over the shared
  builder substrate; CLI/TUI, SDK, ADK, harnesses, benchmarks, and workbench
  extensions are clients, builder frameworks, or projections rather than
  runtime owners;
- aiagent.xyz is a first-party protocol application that publishes,
  benchmarks, ranks, installs, initializes managed instances, and routes
  workers through AIIP and IOI settlement;
- sas.xyz is a first-party protocol application that sells worker-powered
  outcomes, including Worker Training contracts, through AIIP and IOI
  settlement;
- ioi.ai coordinates accounts, devices, publishing, restore, sync metadata, and
  remote-runtime access.

Agentgres should not be read as "state stored as Filecoin blobs." Agentgres is
the state machine and query substrate; Filecoin/CAS is the content-addressed
payload and evidence availability layer.

These documents should be treated as architectural authority prose. They are
not implementation tickets, but they should constrain implementation choices,
naming, product boundaries, and future specs.

## Taxonomy

Architecture contains stable authority prose and low-level component
references. Conformance contracts live in [`docs/conformance`](../conformance/).
Implementation plans, runtime iteration specs, product-internal notes, protocol
corpora, prompt scratchpads, and generated formal outputs are retained outside
the forward-facing docs tree and do not supersede this architecture pack.
Internal master guides may contain raw strategic comparisons, transitional
language, or third-party architecture notes that are useful for execution but
easy to misconstrue as doctrine. Durable conclusions from those guides must be
distilled back into this architecture pack or into an accepted decision record.

## Navigation And Ownership

- [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) — canonical subject ownership, edit rules, and conflict policy.
- [`Architecture Decision Records`](../decisions/README.md) — accepted decision history for durable architecture choices.
- [`doc-classes.md`](./_meta/doc-classes.md) — documentation class vocabulary for future metadata/linting.

## High-Level Canonical Spec Files

- [`web4-and-ioi-stack.md`](./foundations/web4-and-ioi-stack.md) — category definition and stack map.
- [`aiip.md`](./foundations/aiip.md) — AIIP work interop protocol, bounded execution domains, profiles, packets, and handoff semantics.
- [`governed-autonomous-systems.md`](./foundations/governed-autonomous-systems.md) — governed autonomous-system chains, Autopilot nodes, local settlement domains, and the coherent machine-economy stack.
- [`verifiable-bounded-agency.md`](./foundations/verifiable-bounded-agency.md) — alignment-security thesis, bounded agency, and execution-boundary alignment.
- [`mixture-of-workers.md`](./foundations/mixture-of-workers.md) — MoW labor-routing doctrine, sparse worker categories, routing receipts, and router neutrality.
- [`worker-training-lifecycle.md`](./foundations/worker-training-lifecycle.md) — Worker Training lifecycle, Autopilot Foundry product home, training receipts, and training-vs-mutation doctrine.
- [`domain-ontologies-and-data-recipes.md`](./foundations/domain-ontologies-and-data-recipes.md) — semantic data plane for domain ontologies, data recipes, connector mappings, evaluation datasets, and ontology-aware projections.
- [`ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md) — IOI L1 duties, L0/L1 boundary, smart contracts, gas boundaries.
- [`domain-kernels.md`](./foundations/domain-kernels.md) — L0 substrate, fractal/edge-in topology, application-domain kernels, and Agentgres hosting.
- [`agentgres/doctrine.md`](./components/agentgres/doctrine.md) — per-domain state substrate for canonical operational truth.
- [`agentgres/postgres-bridge-and-readiness-contract.md`](./components/agentgres/postgres-bridge-and-readiness-contract.md) — Postgres bridge posture, consistency levels, durability/readiness contract.
- [`daemon-runtime/doctrine.md`](./components/daemon-runtime/doctrine.md) — universal execution endpoint for local, hosted, and DePIN nodes.
- [`wallet-network/doctrine.md`](./components/wallet-network/doctrine.md) — identity, secrets, authority scopes, approvals, payments.
- [`domains/aiagent/worker-marketplace.md`](./domains/aiagent/worker-marketplace.md) — worker marketplace, managed instances, and routing application domain.
- [`domains/sas/service-marketplace.md`](./domains/sas/service-marketplace.md) — Service-as-Software outcome marketplace application domain.
- [`domains/ioi-ai/control-plane.md`](./domains/ioi-ai/control-plane.md) — lightweight account, device, restore, publishing, and remote-runtime control plane.
- [`filecoin-cas/doctrine.md`](./components/filecoin-cas/doctrine.md) — package, artifact, evidence, checkpoint availability.
- [`daemon-runtime/runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md) — local/hosted/DePIN/TEE execution modes.
- [`model-router/doctrine.md`](./components/model-router/doctrine.md) — model registry, BYOK, local mounting, run-to-idle compute.
- [`connectors-tools/doctrine.md`](./components/connectors-tools/doctrine.md) — typed tools, connector authority, risk classes.
- [`domains/marketplace-neutrality.md`](./domains/marketplace-neutrality.md) — anti-cannibalization doctrine, contribution receipts, attribution.
- [`security-privacy-policy-invariants.md`](./foundations/security-privacy-policy-invariants.md) — non-negotiable security and authority invariants.

## Low-Level Reference Files

- [`common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md) — shared envelopes, ID namespaces, primitive capabilities, authority scopes.
- [`aiagent-xyz-worker-and-inter-agent-endpoints.md`](./domains/aiagent/worker-endpoints.md) — aiagent.xyz worker and inter-agent endpoints.
- [`sas-xyz-service-endpoints.md`](./domains/sas/service-endpoints.md) — sas.xyz order, delivery, provider, and dispute endpoints.
- [`daemon-runtime/api.md`](./components/daemon-runtime/api.md) — public daemon runtime API, event streaming, inspect, scorecard, replay.
- [`agentgres/api-object-model.md`](./components/agentgres/api-object-model.md) — Agentgres APIs, object classes, operation log, runtime v0 state.
- [`agentgres/projection-system-reference.md`](./components/agentgres/projection-system-reference.md) — CSPS taxonomy reference for projection-native state systems.
- [`wallet-network/api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md) — wallet.network authority scopes, grants, approvals, brokerage, revocation.
- [`ioi-l1-contract-interfaces.md`](./foundations/ioi-l1-contract-interfaces.md) — IOI L1 contract interfaces.
- [`daemon-runtime/task-capsule-protocol.md`](./components/daemon-runtime/task-capsule-protocol.md) — runtime assignment, task capsules, privacy modes, attestation.
- [`filecoin-cas/api-artifact-refs.md`](./components/filecoin-cas/api-artifact-refs.md) — artifact/package refs, bundles, verification.
- [`model-router/api-byok-mounting.md`](./components/model-router/api-byok-mounting.md) — model provider, endpoint, route, invocation, BYOK, mounting.
- [`connectors-tools/contracts.md`](./components/connectors-tools/contracts.md) — RuntimeToolContract, connector/tool APIs, risk classes.
- [`daemon-runtime/events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md) — runtime events, receipts, delivery bundles, traces, quality.

## Boundary And Generated References

- [`vocabulary.md`](./_meta/vocabulary.md) — runtime, audit, substrate, projection, and legacy naming vocabulary.
- [`CIRC.md`](../conformance/agentic-runtime/CIRC.md) — hidden intent-resolution conformance invariant.
- [`CEC.md`](../conformance/agentic-runtime/CEC.md) — hidden completion-evidence conformance invariant.

## Source Of Truth By Subject

The edit-first source of truth for each subject is
[`source-of-truth-map.md`](./_meta/source-of-truth-map.md). Plans, specs, prompts, and
evidence files are supporting references. When they conflict with
`docs/architecture/`, update the architecture owner first and then reconcile the
supporting file.

## One-Sentence Boundary Summary

| Facet | Canonical Role |
|---|---|
| IOI L1 | Registry, rights, settlement, governance, bonds, disputes, and public trust commitments. |
| AIIP | RPC-shaped, receipt-native interop protocol for bounded autonomous work, authority leases, receipts, settlement intents, disputes, and handoffs. |
| Bounded Execution Domain | Any local, hosted, enterprise, marketplace, robot, worker, service, microharness, or AS-L1 domain that performs scoped autonomous work under policy and receipts. |
| Governed Autonomous-System Chain | Local stateful execution object with policy, modules, proposals, receipts, state roots, and governed upgrades. |
| Autopilot Node | Local settlement, orchestration, authority, state, replay, routing, and interop domain for many governed autonomous-system chains. |
| Verifiable Bounded Agency | Alignment-security thesis: probabilistic workers may propose, but only bounded, authorized, receipted effects may cross the deterministic execution boundary. |
| Mixture of Workers | Labor-routing architecture that selects bounded workers by policy, benchmark evidence, cost, trust, and contribution quality. |
| Worker Training | Supply-creation lifecycle for turning workflows, examples, corrections, data, gates, and training profiles into deployable benchmarked workers. |
| Domain Ontologies and Data Recipes | Semantic data plane that turns sources, connector payloads, traces, schemas, and policies into ontology-bound, optionally distilled training, evaluation, runtime, and projection truth. |
| Domain Kernel | Application-domain authority/runtime deployment for Agentgres and routing. |
| Agentgres | Per-domain canonical operational state, receipts, projections, quality, and contribution accounting. |
| IOI Daemon / Runtime Node | Hypervisor/control plane for autonomous execution across workflows, workers, tools, models, connectors, computer-use leases, artifacts, policy, receipts, and replay. |
| IOI CLI/TUI | Human terminal and TUI operator client over daemon/public runtime APIs. |
| IOI SDK | Low-level protocol/client library over daemon, Agentgres, wallet.network, AIIP, and IOI L1 contracts; never the canonical execution owner. |
| IOI ADK | Autonomous development kit for building workers, service modules, harnesses, evals, manifests, receipts, deployment profiles, and governed autonomous systems. |
| Shared Builder Substrate | Shared graph model, typed node contracts, schemas, recipes, daemon execution path, and receipt model used by Autopilot builder lenses. |
| agent-ide / Workflow Compositor | GUI/workbench projection that renders typed recipes and workflows over the shared builder substrate. |
| Autopilot Workbench | IDE-grade operator console for autonomous systems; observes, requests, approves, interrupts, debugs, and explains daemon-governed work without owning runtime truth. |
| Electron/VS Code Fork | Canonical Autopilot app shell for Workbench and Desktop modes. |
| Autopilot Desktop | Local user mode for private/device automation that trains, runs, inspects, and governs workers through a local IOI daemon/runtime profile. |
| IOI Authority Gateway / Autopilot Guard | Compatibility sidecar/adapters for existing IDEs, CLI agents, hosted agents, browser tools, and MCP ecosystems; routes proposed actions through daemon policy, authority, receipts, and replay without becoming a second runtime. |
| wallet.network | Sovereign authority layer for identity, secrets, keys, authority scopes, approvals, payments, and revocation. |
| aiagent.xyz | Canonical Web4 marketplace for portable digital workers, benchmark profiles, Sparse Worker Categories, installs, and routing eligibility. |
| sas.xyz | Canonical Web4 marketplace for autonomous service outcomes, including Worker Training as Service-as-Software. |
| ioi.ai | Lightweight account/control plane for devices, restore routing, publishing, sync metadata, and remote-runtime entitlement. |
| ai:// | Naming and manifest resolution protocol for intelligence, workers, services, apps, and domains. |
| Filecoin/CAS | Immutable payload availability for packages, artifacts, evidence, receipts, and checkpoints. |
| DePIN/TEE Nodes | Execution venues that run IOI daemon profiles, not the Web4 apps themselves. |

## Core Layering

```text
IOI L1
  registry, rights, settlement, governance, bonds, disputes, roots

Application Domains
  aiagent.xyz, sas.xyz, ioi.ai, Autopilot local domains, enterprise domains
  each runs kernel/runtime deployment + Agentgres domain

Governed Autonomous-System Chains
  local agents, workers, workflows, policies, service modules, proposals, receipts, and upgrade paths

AIIP Work Interop Layer
  capability discovery, quotes, invokes, handoffs, authority leases, receipts, settlement intents, disputes, reputation queries, and channel/profile registration

Semantic Data Plane
  domain ontologies, canonical object models, data recipes, connector mappings, policy-bound data views, distilled ontology datasets, evaluation datasets, ontology-aware projections

MoW Routing Layer
  sparse worker categories, routing decisions, contribution policies, benchmark eligibility

Execution Hypervisor / Runtime Nodes
  local IOI daemon under an Autopilot node, hosted IOI daemon, provider daemon, DePIN node, TEE node, customer VPC

Autopilot Node / Local Settlement Domain
  Workbench, daemon, Agentgres, wallet.network authority path, local registries, receipts, replay, interop, and local settlement

Client Surfaces
  Autopilot Workbench, Autopilot Desktop, agent-ide, IOI Authority Gateway adapters, IOI CLI/TUI, @ioi/agent-sdk, IOI ADK, browser apps, harnesses, benchmarks

Storage Plane
  Filecoin/CAS/CDN for packages, artifacts, evidence bundles, checkpoints, sealed state archive bytes

Authority Plane
  wallet.network for identity, secrets, authority scopes, payments, approvals, revocation
```

## Key Non-Negotiables

1. Agentgres does not run on IOI L1. It runs per application/domain.
2. aiagent.xyz and sas.xyz are not separate chains by default. They are canonical Web4 application domains with their own Agentgres backends and IOI L1 smart-contract settlement rails.
3. IOI L1 is not the operational notebook. It stores registry, rights, economic commitments, disputes, and sparse roots.
4. IOI gas is consumed at coordination and settlement boundaries, not per model thought, tool call, or workflow node.
5. The default harness must be marketplace-neutral and must not cannibalize worker/service markets through silent appropriation.
6. wallet.network is the authority plane. Agents and runtimes receive authority scopes, not raw secrets.
7. DePIN nodes are execution venues; Web4 apps define state, rights, UX, contracts, and outcomes.
8. Filecoin/CAS stores payloads; trust comes from manifests, hashes, signatures, receipts, and settlement roots.
9. Agentgres state MUST NOT be reduced to opaque Filecoin blobs. Agentgres owns canonical operations, object heads, indexes, constraints, projections, subscriptions, delivery state, receipt metadata, and artifact refs.
10. Compute nodes initialize IOI daemon/runtime-node profiles, optionally bridging into runtime services; the SDK is a client over that substrate, not the substrate itself.
11. CLI/TUI, SDK, and ADK are separate surfaces: CLI/TUI is the operator interface, SDK is the low-level client library, and ADK is the autonomous-system builder framework.
12. CLI/TUI, agent-ide, SDK, ADK, Autopilot Desktop, harnesses, and benchmarks must share daemon/domain contracts rather than creating private runtime truth paths.
13. Worker is the protocol actor; model is a cognition backend; agent is product-facing or colloquial language.
14. MoW is labor routing across bounded workers, not a fifth Web primitive and not model-provider routing.
15. Worker Training creates or improves capability but does not grant authority; wallet.network or equivalent authority grants power.
16. Workers train on ontology-bound, policy-bound, and when useful distilled data, not raw blobs or ambient connector payloads.
17. Models and agents may reason or propose; IOI daemon authority decides what crosses the deterministic execution boundary.
18. IOI Authority Gateway, Autopilot Guard, IDE extensions, CLI wrappers, MCP gateways, Git hooks, API proxies, browser adapters, and CI gates are mediation surfaces only. They must route consequential actions through daemon policy, authority, receipts, and replay, and they must not claim total interception of opaque third-party runtimes.
19. IOI's alignment-security claim is execution-boundary alignment: it constrains consequential effects through bounded authority, policy, receipts, and verification; it must not be framed as proving every model's private cognition or goals are safe.
20. Autopilot Workbench is not the Autopilot node. The workbench is an operator console; the Autopilot node is the local settlement and interop domain composed around daemon, Agentgres, wallet.network authority paths, registries, receipts, and replay.
21. Governed autonomous-system chains are system-local state machines, not necessarily standalone public blockchains or IOI L1s. IOI L1 anchors selected roots and settles global machine-economy rights, disputes, reputation, and economics.
22. The marketplace is not the protocol. aiagent.xyz and sas.xyz are first-party applications of AIIP and IOI settlement, while IOI mainnet remains the generic settlement layer for autonomous systems.
23. AIIP is the shared interop semantics for local microharness routing and external autonomous-system handoffs. Transports and settlement depth may vary; protocol grammar should not fragment.
