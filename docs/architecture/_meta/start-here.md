# Start Here

Status: canonical reader entry point.
Canonical owner: this file for first-read architecture orientation and role-based reading paths.
Supersedes: ad hoc onboarding paths across architecture docs.
Superseded by: none.
Last alignment pass: 2026-06-22.

## Five-Minute Mental Model

IOI is an edge-in Web4 architecture for verifiable autonomous labor. Work
starts near the user, data, tools, and authority boundary. It becomes
operational truth in domain-local state. Only selected commitments settle
publicly.

Read the stack like this:

```text
ioi.ai Goal Chat
  asks, discovers, coordinates, and drafts handoffs; durable automations and
  execution live in Hypervisor

Hypervisor clients
  request, inspect, steer, and approve work through the same Core
  Hypervisor App, Hypervisor Web, CLI/headless, SDK, ADK, Authority Gateway adapters
  TUI is an optional CLI presentation, not a separate first-class client

Hypervisor product shell
  Home starts/resumes work; Projects organize persistent software/system work;
  Automations own durable workflows/services; Applications expose specialized
  surfaces; Sessions show live and historical execution

Hypervisor application surfaces
  organize the same Core by job-to-be-done
  Workbench, Automations, Foundry, Agents / Workers, Models,
  Connectors / Tools / MCP, Data / Knowledge, Ontology, Authority / Govern,
  Receipts / Replay, Operate / Monitoring, Providers / Environments,
  Privacy / cTEE, Change Plane, Marketplace, Patterns / Examples / Training, Domain Apps

ioi.ai collaborative outcome pattern
  chat.ioi.ai's goal-appropriate multi-model/multi-path pursuit over Hypervisor,
  with evidence, receipts, verifier state, and final ownership synthesis

Hypervisor Foundry
  model, worker, eval, dataset, registry, endpoint, training, and
  ontology-aware package-building surface over Hypervisor Core

Hypervisor sessions/providers/environments
  default cross-session views over managed workspaces, provider integrations,
  services, tasks, ports, logs, archive refs, restore refs, costs, and health

Hypervisor Core
  shared runtime/control substrate whose execution owner is the daemon; it
  coordinates authority gateways but does not replace wallet.network

Agent harness adapters
  mediate external agent harnesses such as Codex, Claude Code, Grok Build,
  OpenHands, Aider, shell/tmux agents, CI agents, and hosted coding agents

Hypervisor Daemon
  executes work and owns effect semantics

HypervisorOS
  bare-metal node profile where the daemon is the node root

Workflow Compositor
  shapes high-level directed workflows, services, dependencies, step contracts,
  review points, and delivery contracts over Hypervisor Core

Harness Profiles
  resolve scoped steps through selected model/tool/worker/service/harness paths;
  the Default Harness Profile is the reference scaffold/fallback profile, not a
  meta-harness and not the only admissible harness

Persistent workspace intelligence
  skills, Agent Wiki / ioi-memory, wiki facts, learned tool affordances, and
  durable behavior-affecting context persist at workspace/project/domain level
  across model or harness swaps when compatibility, provenance, policy, and
  authority allow

wallet.network
  authorizes identity, secrets, approvals, payments, exchanges, scopes,
  decryption, revocation, and protection actions; route sources produce
  exchange candidates, but Wallet owns authority and the user-facing cockpit

decentralized.exchange / decentralized.trade
  Wallet-consumed route/venue intelligence engines for asset conversion and
  exposure management; they propose candidates without becoming authority,
  required UIs, or trust roots

Hypervisor provider integrations
  direct integrations for cloud compute, storage, GPUs, confidential compute,
  DePIN, local machines, customer cloud, enterprise clusters, decentralized
  storage networks, and user-specified providers

Agentgres
  admits and proves operational truth for app, user, agent, and run state

Agent Wiki / ioi-memory
  governs semantic memory, recall, wiki surfaces, and retrieval

Agentgres artifact refs
  define what payload bytes mean and how they bind to receipts, policy,
  authority, and state roots

Storage backends
  hold bytes: local disk, S3, Filecoin, CAS/IPFS, object stores, provider blobs;
  private payloads are encrypted before storage

Private Workspace backed by cTEE
  lets users open a normal private workspace on persistent rented GPU
  Hypervisor Nodes without exposing protected plaintext to the node by default;
  Plaintext-Free Runtime Mounting is the daemon boundary for tools and models,
  Candidate-Lattice Private Decoding is the default protected-agency strategy, and
  Counterfactual Lattice Execution can spend extra public token volume to reduce
  online private-choice leakage; cTEE preserves ordinary GPU kernels for public
  work but does not promise same-token-budget arbitrary private inference;
  Candidate Coverage Profile estimates when redundancy makes this trade cheap
  and when exponential redundancy decay should route the work away from CLPD/CLE;
  the Cryptographic Operator Plane routes protected scoring/retrieval/policy
  checks to FHE/MPC/local/threshold paths behind the same user-facing workspace;
  third-party model APIs over sensitive plaintext are provider-trust, while
  public/redacted/declassified API calls can remain cTEE-compatible;
  deterrence/detection receipts support canaries, watermarks, and disputes

AIIP
  moves bounded autonomous work across local, marketplace, enterprise, and
  third-party domains

Ecosystem Assurance
  makes profiles, certifications, compliance packs, liability routes, abuse
  advisories, and commercial exports legible from existing receipts and policy
  without becoming execution, authority, truth, marketplace, or settlement

IOI L1 / compatible L1s
  settle selected public, economic, rights, dispute, registry, and cross-domain
  commitments
```

Private user/app state follows the same split as private agent state:

```text
wallet.network
  authenticates, authorizes, and controls viewing/decryption leases

Agentgres
  records canonical meaning, refs, policy, receipts, and state roots

storage backends
  hold encrypted private profile, workspace, app, service, and metadata bytes

IOI L1
  receives only selected public/economic/cross-domain commitments
```

The short version:

```text
Surfaces request.
Hypervisor Core coordinates clients, surfaces, sessions, and adapters.
Hypervisor Daemon executes.
HypervisorOS roots serious nodes.
Hypervisor manages sessions, providers, and environments directly.
Workflow Compositor shapes directed work.
HarnessProfiles resolve scoped steps.
Default Harness Profile is the reference scaffold/fallback.
wallet.network authorizes, risk-labels, approves/denies, revokes, protects, and receipts.
decentralized.exchange/trade expose route/venue intelligence for liquidity, exposure, and event markets.
Hypervisor provider integrations propose execution routes.
Agentgres admits truth.
Agent Wiki remembers.
Artifact refs define payload meaning.
Storage holds encrypted bytes.
Private Workspace keeps protected plaintext off rented nodes.
CLPD lets rented GPUs generate candidates while private heads select.
AIIP moves work.
Ecosystem Assurance explains trust posture from profiles and evidence.
L1 settles selected public/economic commitments.
```

## Core Boundary Diagram

```text
Intent
  -> Hypervisor client or application surface
  -> Hypervisor Core session / adapter boundary
  -> Hypervisor Daemon
  -> Workflow Compositor when work needs directed graph structure
  -> selected HarnessProfile, service module, tool, worker, verifier, or model path
  -> scoped model/tool/result/model or deterministic step loop
  -> receipts + normalized observations
  -> Agentgres operations + artifact refs
  -> storage backend payload bytes
  -> optional AIIP handoff or L1 settlement by trigger
```

Do not add another runtime beside the Hypervisor Daemon. Runtime profiles,
harnesses, adapters, SDK clients, Hypervisor App/Web/CLI-headless clients, and
Workbench/Automations/Foundry surfaces, other application surfaces, and
Providers / Environments views are clients, projections, application surfaces,
editors, views, or daemon-executed profiles.

## Route By Problem

If you are entering the architecture with a concrete implementation problem,
use this map before reading deep doctrine:

| Problem | Start Here | Then Read |
| --- | --- | --- |
| Build the Hypervisor cockpit from the IOI reference shell | [`components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`components/daemon-runtime/api.md`](../components/daemon-runtime/api.md), [`_meta/implementation-matrix.md`](./implementation-matrix.md) |
| Route work through Codex/Claude/DeepSeek/Aider-style tools | [`components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`components/daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Build ioi.ai multi-model goal pursuit, Stockfish-style coding search, or goal-appropriate collaborative outcomes | [`domains/ioi-ai/collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | [`components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md), [`components/daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Implement wallet authority, approvals, scopes, or agent credentials | [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | [`components/wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`components/wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md) |
| Build exchange, trade, perps, or prediction-market flows | [`components/wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md) | [`domains/decentralized/exchange.md`](../domains/decentralized/exchange.md), [`domains/decentralized/trade.md`](../domains/decentralized/trade.md) |
| Run private work on rented/cloud/DePIN compute | [`components/daemon-runtime/private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`components/daemon-runtime/runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md) |
| Decide where model weights, private files, or plaintext may live | [`components/daemon-runtime/private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`components/model-router/doctrine.md`](../components/model-router/doctrine.md), [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) |
| Persist app/user/agent state, snapshots, archives, or restore refs | [`components/agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`components/agentgres/doctrine.md`](../components/agentgres/doctrine.md), [`components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md) |
| Handle missing/corrupt/stale payload bytes | [`components/agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md), [`components/storage-backends/filecoin-cas.md`](../components/storage-backends/filecoin-cas.md), [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Publish or rent a long-lived worker | [`domains/aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`domains/aiagent/digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md), [`domains/aiagent/managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md) |
| Sell or fulfill an autonomous service outcome | [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | [`domains/sas/service-endpoints.md`](../domains/sas/service-endpoints.md), [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Train robotics or embodied models in simulation | [`components/hypervisor/foundry.md`](../components/hypervisor/foundry.md) | [`foundations/domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md), [`foundations/physical-action-safety.md`](../foundations/physical-action-safety.md) |
| Execute robots, vehicles, drones, or embodied work physically | [`foundations/physical-action-safety.md`](../foundations/physical-action-safety.md) | [`foundations/aiip.md`](../foundations/aiip.md), [`components/wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) |
| Add certification, compliance, liability, quarantine, SLA, billing, or customer audit posture | [`foundations/ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) | [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md), [`components/agentgres/doctrine.md`](../components/agentgres/doctrine.md), [`domains/aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md), [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md) |
| Integrate AWS/GCP/Akash/Filecoin/local/customer providers | [`components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md) | [`components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md), [`components/daemon-runtime/hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) |
| Move work across autonomous systems | [`foundations/aiip.md`](../foundations/aiip.md) | [`foundations/common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`foundations/ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) |

## Reader Paths

### Implementing Runtime Orchestration

Start here:

1. [`components/daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
2. [`components/daemon-runtime/private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md)
3. [`components/daemon-runtime/runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md)
4. [`components/daemon-runtime/hypervisoros.md`](../components/daemon-runtime/hypervisoros.md)
5. [`components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
6. [`components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
7. [`domains/decentralized/README.md`](../domains/decentralized/README.md)
8. [`components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)
9. [`components/daemon-runtime/api.md`](../components/daemon-runtime/api.md)
10. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
11. [`../conformance/hypervisor-core/intent-resolution.md`](../../conformance/hypervisor-core/intent-resolution.md)
12. [`../conformance/hypervisor-core/effect-execution.md`](../../conformance/hypervisor-core/effect-execution.md)

Build for: intent resolution, action proposals, policy/authority gates,
execution, normalized observations, receipts, context topology, output
ownership, and terminal-state conformance.

For ioi.ai collaborative outcomes, build goal-appropriate multi-model or
multi-path pursuit. Coding goals may use code search, test/eval playouts,
static analysis, visual verification, runtime traces, rollback/snapshot
branching, skill reuse, failure mining, and benchmark-gated improvement. Other
goals may use retrieval, connector calls, simulations, citations, screenshots,
policy checks, or human review instead.

For persistent cloud Hypervisor on rented GPUs, build for Open Private
Workspace, private workspace capsules, encrypted patches/blobs, no-plaintext
protected classes, autonomy leases, cTEE guardians, declassification receipts,
capability exits, and Candidate-Lattice Private Decoding as the default
protected-agency path.

For bare-metal or serious provider nodes, build for HypervisorOS: measured boot
profiles, daemon-rooted workload launch, node integrity receipts,
denied-by-default egress, cTEE compatibility, and no unmanaged model/tool/workspace
bypass around the Hypervisor Daemon.

For provider and environment management, build for Hypervisor sessions,
providers, and environments: node registry, provider integrations, VMs,
containers, microVMs, WASM workloads, image/volume/network posture, GPU pools,
DePIN/cloud GPU endpoints, storage posture, runtime placement, health, cost
posture, cTEE posture, receipt/replay projections, and migration cockpit
workflows. Hypervisor manages machines and workload posture while coordinating
governance; Hypervisor Daemon executes; wallet.network authorizes; Agentgres
records truth. For resource routing, direct provider connectors, local
inventory, customer clouds, DePIN markets, storage networks, or user-specified
routes may propose CloudRoute candidates. Hypervisor still routes through
wallet.network authority, daemon/provider execution boundaries, Agentgres refs,
and receipts.

### Implementing Agentgres

Start here:

1. [`components/agentgres/doctrine.md`](../components/agentgres/doctrine.md)
2. [`components/agentgres/api-object-model.md`](../components/agentgres/api-object-model.md)
3. [`components/agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md)
4. [`components/agentgres/postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md)
5. [`components/agentgres/projection-system-reference.md`](../components/agentgres/projection-system-reference.md)
6. [`components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md)

Build for: accepted operations, object heads, state roots, projections,
artifact refs, archive refs, receipt refs, restore/import operations, and
Postgres-compatible read surfaces.

Storage backend implementers should then read
[`components/storage-backends/filecoin-cas.md`](../components/storage-backends/filecoin-cas.md)
or another backend profile. Backend profiles explain byte availability; they do
not own artifact meaning.

### Implementing Memory

Start here:

1. [`components/agentgres/doctrine.md#memory-and-agent-wiki-boundary`](../components/agentgres/doctrine.md#memory-and-agent-wiki-boundary)
2. [`foundations/common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
3. [`components/daemon-runtime/api.md#memory-api`](../components/daemon-runtime/api.md#memory-api)
4. [`components/agentgres/api-object-model.md`](../components/agentgres/api-object-model.md)

Build for: Agent Wiki / `ioi-memory` as the semantic memory plane and
Agentgres `ContextMutation` or equivalent operations as the admission path for
durable behavior-affecting memory.

### Implementing Authority

Start here:

1. [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md)
2. [`components/wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md)
3. [`components/wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md)
4. [`domains/decentralized/README.md`](../domains/decentralized/README.md)
5. [`foundations/security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md)
6. [`components/daemon-runtime/api.md#action-mediation--authority-gateway-api`](../components/daemon-runtime/api.md#action-mediation--authority-gateway-api)

Build for: `scope:*` authority scopes, `prim:*` primitive capabilities,
grants, approvals, exact request hashes, revocation epochs, decryption leases,
payment authority, exchange authority, trade authority, route-source
boundaries, risk labels,
asset exposure records, protection actions, approval inbox items, and wallet
receipts.

### Implementing Marketplace Or Routing

Start here:

1. [`foundations/mixture-of-workers.md`](../foundations/mixture-of-workers.md)
2. [`domains/marketplace-neutrality.md`](../domains/marketplace-neutrality.md)
3. [`domains/aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md)
4. [`domains/aiagent/digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md)
5. [`domains/aiagent/vertical-ontology-packs.md`](../domains/aiagent/vertical-ontology-packs.md)
6. [`domains/aiagent/integration-surface-taxonomy.md`](../domains/aiagent/integration-surface-taxonomy.md)
7. [`domains/aiagent/managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md)
8. [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md)
9. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)

Build for: worker packages, service packages, MoW routing, contribution
receipts, routing receipts, ontology-bound digital and embodied workers,
managed worker lifecycles, marketplace neutrality, and optional L1 settlement
for listings, escrows, disputes, rights, and reputation.

### Implementing Ecosystem Assurance

Start here:

1. [`foundations/ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md)
2. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
3. [`components/agentgres/doctrine.md`](../components/agentgres/doctrine.md)
4. [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md)
5. [`domains/aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md)
6. [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md)
7. [`foundations/ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md)

Build for: assurance profiles, conformance profiles, certification claims,
jurisdiction policy packs, evidence bundles, posture projections, abuse signals,
quarantine advisories, liability claim routes, commercial exports, and public
anchors only when certification, marketplace eligibility, bond, dispute,
governance, or cross-domain trust requires them.

### Implementing Product UX

Start here:

1. [`components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)
2. [`components/daemon-runtime/api.md`](../components/daemon-runtime/api.md)
3. [`components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
4. [`domains/ioi-ai/control-plane.md`](../domains/ioi-ai/control-plane.md)
5. [`components/hypervisor/providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
6. [`domains/aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md)
7. [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md)

Build for: operator controls, approval cards, run graphs, context topology
views, receipt timelines, artifact viewers, first-class App/Web/CLI clients,
Workbench/Automations/Foundry application surfaces, other Applications
surfaces, Providers / Environments views, package install/publish flows, and
clear distinction between Hypervisor Core, Hypervisor Node, Hypervisor Daemon,
Agentgres, wallet.network, and L1.

### Implementing Interop

Start here:

1. [`foundations/aiip.md`](../foundations/aiip.md)
2. [`foundations/ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md)
3. [`foundations/common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
4. [`components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md)

Build for: bounded execution domains, AIIP envelopes, profiles, channels,
authority leases, receipt commitments, settlement intents, disputes, and
cross-domain finality.

## Implementation Navigation

Use these meta docs while building:

- [`_meta/source-of-truth-map.md`](./source-of-truth-map.md): where each
  concept is canonically owned.
- [`_meta/vocabulary.md`](./vocabulary.md): canonical names and inactive naming
  boundaries.
- [`_meta/implementation-matrix.md`](./implementation-matrix.md): concept
  to durable form, owner, code anchor, and conformance hook.
- [`_meta/canon-readability-audit.md`](./canon-readability-audit.md):
  current readability gaps and cleanup priorities.

## Most Common Boundary Mistakes

Avoid these models:

```text
Default Harness Profile = a peer runtime beside the daemon
Default Harness Profile = the only admissible autonomous harness
Default Harness Profile = a meta-harness above other harnesses
selected harness/model = owner of workspace memory or skills
Hypervisor App/Web/CLI-headless = runtime truth
TUI = separate first-class client lane
external CLI agent harness = Hypervisor runtime truth
Codex/Claude Code/Grok Build = Hypervisor client
Hypervisor Workbench/Automations/Foundry/provider views = runtime truth
one editor shell = live parent product term
ioi.ai Goal Chat = durable automation owner
provider posture = standalone provider-management product, execution runtime, or authority plane
decentralized.exchange = exchange backend or liquidity owner
decentralized.trade = broker, custodian, or ordinary swap route
decentralized.exchange/trade = mandatory UIs users must visit before Wallet
Persistent rented GPU node = trusted private machine
Agentgres = all memory or all payload bytes
Agent Wiki / ioi-memory = canonical admitted truth
Filecoin/CAS/S3/local disk = authority layer
Boot measurement = consumer GPU privacy guarantee
strategy source on rented node = protected strategy
AIIP = separate bespoke protocol per app
Ecosystem Assurance = runtime, wallet, marketplace, legal-advice engine, or insurer
IOI L1 = execution database for every run
aiagent.xyz -> sas.xyz = mandatory supply chain
ioi.ai collaborative outcome = group chat or unbounded swarm
Model output = authority
scope:* = primitive capability
prim:* = authority scope
```

Correct them to:

```text
daemon executes
Hypervisor Core coordinates clients, surfaces, sessions, and adapters
Hypervisor App/Web/CLI-headless are first-class clients
TUI is an optional CLI presentation
Hypervisor Workbench/Automations/Foundry and other application surfaces are projections over Core
ioi.ai Goal Chat proposes, coordinates, compares, and synthesizes
ioi.ai collaborative outcomes are goal-appropriate multi-model/multi-path
pursuits over Hypervisor with evidence, receipts, and authority gates
Foundry builds and evaluates models, workers, datasets, endpoints, registries,
simulation-training jobs, and ontology-aware packages
Providers / Environments views manage sessions, providers, and environments
External agent harnesses are mediated through Agent Harness Adapters
Workflow Compositor shapes high-level directed work
selected HarnessProfiles resolve scoped steps
Default Harness Profile is the reference scaffold/fallback HarnessProfile
workspace skills and Agent Wiki / ioi-memory persist across harness/model swaps
Agentgres admits operational truth
Agent Wiki / ioi-memory remembers and retrieves
artifact refs bind payload meaning
storage backends hold bytes
Private Workspace backed by cTEE forbids protected plaintext on rented nodes
Plaintext-Free Runtime Mounting exposes only public/redacted refs and private handles
wallet.network authorizes
decentralized.exchange/trade expose route/venue intelligence and propose candidates
Hypervisor provider integrations propose execution routes
AIIP moves bounded autonomous work
Ecosystem Assurance projects trust posture from profiles, evidence, policy packs, and owner-domain receipts
L1 settles selected public/economic/cross-domain commitments
```
