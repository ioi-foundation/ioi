# Start Here

Status: canonical reader entry point.
Canonical owner: this file for first-read architecture orientation and role-based reading paths.
Supersedes: ad hoc onboarding paths across architecture docs.
Superseded by: none.
Last alignment pass: 2026-06-12.

## Five-Minute Mental Model

IOI is an edge-in Web4 architecture for verifiable autonomous labor. Work
starts near the user, data, tools, and authority boundary. It becomes
operational truth in domain-local state. Only selected commitments settle
publicly.

Read the stack like this:

```text
Operator surfaces
  request, inspect, steer, and approve work
  Hypervisor IDE, CLI/TUI, SDK, ADK, Authority Gateway adapters

Hypervisor Daemon
  executes work and owns effect semantics

HypervisorOS
  bare-metal node profile where the daemon is the node root

Hypervisor Fleet
  general infrastructure manager whose first-class workload is autonomous
  systems; coordinates machines, workloads, private workspaces, nodes,
  providers, placement, storage posture, cTEE posture, receipts, replay
  projections, and policy visibility without owning execution or authority

Default Harness Profile
  orchestrates loop-native autonomous work inside the daemon

wallet.network
  authorizes identity, secrets, approvals, payments, exchanges, scopes,
  decryption, revocation, and protection actions; route sources produce
  exchange candidates, but Wallet owns authority

decentralized.exchange / decentralized.trade
  Wallet-native route intelligence for asset conversion and exposure
  management; they propose candidates without becoming authority or trust roots

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
Hypervisor Daemon executes.
HypervisorOS roots serious nodes.
Hypervisor Fleet manages infrastructure for autonomous systems.
Default Harness Profile orchestrates.
wallet.network authorizes, risk-labels, approves/denies, revokes, protects, and receipts.
decentralized.exchange/trade propose liquidity, exposure, and event-market routes.
Hypervisor provider integrations propose execution routes.
Agentgres admits truth.
Agent Wiki remembers.
Artifact refs define payload meaning.
Storage holds encrypted bytes.
Private Workspace keeps protected plaintext off rented nodes.
CLPD lets rented GPUs generate candidates while private heads select.
AIIP moves work.
L1 settles selected public/economic commitments.
```

## Core Boundary Diagram

```text
Intent
  -> operator surface
  -> Hypervisor Daemon
  -> Default Harness Profile
  -> model/tool/result/model loop
  -> receipts + normalized observations
  -> Agentgres operations + artifact refs
  -> storage backend payload bytes
  -> optional AIIP handoff or L1 settlement by trigger
```

Do not add another runtime beside the Hypervisor Daemon. Runtime profiles,
harnesses, adapters, SDK clients, and Hypervisor IDE controls are clients,
projections, or daemon-executed profiles.

## Reader Paths

### Implementing Runtime Orchestration

Start here:

1. [`components/daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
2. [`components/daemon-runtime/private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md)
3. [`components/daemon-runtime/runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md)
4. [`components/daemon-runtime/hypervisoros.md`](../components/daemon-runtime/hypervisoros.md)
5. [`components/hypervisor/fleet.md`](../components/hypervisor/fleet.md)
6. [`domains/decentralized/README.md`](../domains/decentralized/README.md)
7. [`components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)
8. [`components/daemon-runtime/api.md`](../components/daemon-runtime/api.md)
9. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
10. [`../conformance/agentic-runtime/CIRC.md`](../../conformance/agentic-runtime/CIRC.md)
11. [`../conformance/agentic-runtime/CEC.md`](../../conformance/agentic-runtime/CEC.md)

Build for: intent resolution, action proposals, policy/authority gates,
execution, normalized observations, receipts, context topology, output
ownership, and terminal-state conformance.

For persistent cloud Hypervisor on rented GPUs, build for Open Private
Workspace, private workspace capsules, encrypted patches/blobs, no-plaintext
protected classes, autonomy leases, cTEE guardians, declassification receipts,
capability exits, and Candidate-Lattice Private Decoding as the default
protected-agency path.

For bare-metal or serious provider nodes, build for HypervisorOS: measured boot
profiles, daemon-rooted workload launch, node integrity receipts,
denied-by-default egress, cTEE compatibility, and no unmanaged model/tool/workspace
bypass around the Hypervisor Daemon.

For infrastructure and autonomous runtime-fleet management, build for
Hypervisor Fleet: node registry, provider integrations, VMs, containers,
microVMs, WASM workloads, image/volume/network posture, GPU pools, DePIN/cloud
GPU endpoints, storage posture, runtime placement, fleet health, cost posture,
cTEE posture, receipt/replay projections, and migration cockpit workflows.
Fleet manages machines and workload posture while coordinating governance;
Hypervisor Daemon executes; wallet.network authorizes; Agentgres records truth.
For resource routing, direct provider connectors, local inventory, customer
clouds, DePIN markets, storage networks, or user-specified routes may propose
CloudRoute candidates. Fleet and Hypervisor still route through wallet.network
authority, daemon/provider execution boundaries, Agentgres refs, and receipts.

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
4. [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md)
5. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)

Build for: worker packages, service packages, MoW routing, contribution
receipts, routing receipts, marketplace neutrality, and optional L1 settlement
for listings, escrows, disputes, rights, and reputation.

### Implementing Product UX

Start here:

1. [`components/daemon-runtime/doctrine.md`](../components/daemon-runtime/doctrine.md)
2. [`components/daemon-runtime/api.md`](../components/daemon-runtime/api.md)
3. [`domains/ioi-ai/control-plane.md`](../domains/ioi-ai/control-plane.md)
4. [`components/hypervisor/fleet.md`](../components/hypervisor/fleet.md)
5. [`domains/aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md)
6. [`domains/sas/service-marketplace.md`](../domains/sas/service-marketplace.md)

Build for: operator controls, approval cards, run graphs, context topology
views, receipt timelines, artifact viewers, Fleet surfaces, package
install/publish flows, and clear distinction between Hypervisor IDE,
Hypervisor Fleet, Hypervisor Node, Hypervisor Daemon, Agentgres, and L1.

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
- [`_meta/vocabulary.md`](./vocabulary.md): canonical names and deprecated
  wording.
- [`_meta/implementation-matrix.md`](./implementation-matrix.md): concept
  to durable form, owner, code anchor, and conformance hook.
- [`_meta/canon-readability-audit.md`](./canon-readability-audit.md):
  current readability gaps and cleanup priorities.

## Most Common Boundary Mistakes

Avoid these models:

```text
Default Harness Profile = a peer runtime beside the daemon
Hypervisor IDE = runtime truth
Hypervisor Fleet = execution runtime or authority plane
decentralized.exchange = exchange backend or liquidity owner
decentralized.trade = broker, custodian, or ordinary swap route
parked future decentralized.cloud = present cloud gateway or privacy proof
Persistent rented GPU node = trusted private machine
Agentgres = all memory or all payload bytes
Agent Wiki / ioi-memory = canonical admitted truth
Filecoin/CAS/S3/local disk = authority layer
Boot measurement = consumer GPU privacy guarantee
strategy source on rented node = protected strategy
AIIP = separate bespoke protocol per app
IOI L1 = execution database for every run
aiagent.xyz -> sas.xyz = mandatory supply chain
Model output = authority
scope:* = primitive capability
prim:* = authority scope
```

Correct them to:

```text
daemon executes
Hypervisor Fleet manages infrastructure for autonomous systems
Default Harness Profile orchestrates inside the daemon
Agentgres admits operational truth
Agent Wiki / ioi-memory remembers and retrieves
artifact refs bind payload meaning
storage backends hold bytes
Private Workspace backed by cTEE forbids protected plaintext on rented nodes
Plaintext-Free Runtime Mounting exposes only public/redacted refs and private handles
wallet.network authorizes
decentralized.exchange/trade propose liquidity/exposure/event-market routes
Hypervisor provider integrations propose execution routes
AIIP moves bounded autonomous work
L1 settles selected public/economic/cross-domain commitments
```
