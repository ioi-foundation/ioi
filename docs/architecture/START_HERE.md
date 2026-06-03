# Start Here

Status: canonical reader entry point.
Canonical owner: this file for first-read architecture orientation and role-based reading paths.
Supersedes: ad hoc onboarding paths across architecture docs.
Superseded by: none.
Last alignment pass: 2026-06-01.

## Five-Minute Mental Model

IOI is an edge-in Web4 architecture for verifiable autonomous labor. Work
starts near the user, data, tools, and authority boundary. It becomes
operational truth in domain-local state. Only selected commitments settle
publicly.

Read the stack like this:

```text
Operator surfaces
  request, inspect, steer, and approve work
  Autopilot Workbench, CLI/TUI, SDK, ADK, Authority Gateway adapters

IOI daemon
  executes work and owns effect semantics

Default Harness Profile
  orchestrates loop-native autonomous work inside the daemon

wallet.network
  authorizes identity, secrets, approvals, payments, scopes, and decryption

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
  Autopilot nodes without exposing protected plaintext to the node by default;
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
Daemon executes.
Default Harness Profile orchestrates.
wallet.network authorizes.
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
  -> IOI daemon
  -> Default Harness Profile
  -> model/tool/result/model loop
  -> receipts + normalized observations
  -> Agentgres operations + artifact refs
  -> storage backend payload bytes
  -> optional AIIP handoff or L1 settlement by trigger
```

Do not add another runtime beside the daemon. Runtime profiles, harnesses,
adapters, SDK clients, and workbench controls are clients, projections, or
daemon-executed profiles.

## Reader Paths

### Implementing Runtime Orchestration

Start here:

1. [`components/daemon-runtime/default-harness-profile.md`](./components/daemon-runtime/default-harness-profile.md)
2. [`components/daemon-runtime/private-workspace-ctee.md`](./components/daemon-runtime/private-workspace-ctee.md)
3. [`components/daemon-runtime/runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md)
4. [`components/daemon-runtime/doctrine.md`](./components/daemon-runtime/doctrine.md)
5. [`components/daemon-runtime/api.md`](./components/daemon-runtime/api.md)
6. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md)
7. [`../conformance/agentic-runtime/CIRC.md`](../conformance/agentic-runtime/CIRC.md)
8. [`../conformance/agentic-runtime/CEC.md`](../conformance/agentic-runtime/CEC.md)

Build for: intent resolution, action proposals, policy/authority gates,
execution, normalized observations, receipts, context topology, output
ownership, and terminal-state conformance.

For persistent cloud Autopilot on rented GPUs, build for Open Private
Workspace, private workspace capsules, encrypted patches/blobs, no-plaintext
protected classes, autonomy leases, cTEE guardians, declassification receipts,
capability exits, and Candidate-Lattice Private Decoding as the default
protected-agency path.

### Implementing Agentgres

Start here:

1. [`components/agentgres/doctrine.md`](./components/agentgres/doctrine.md)
2. [`components/agentgres/api-object-model.md`](./components/agentgres/api-object-model.md)
3. [`components/agentgres/artifact-ref-plane.md`](./components/agentgres/artifact-ref-plane.md)
4. [`components/agentgres/postgres-bridge-and-readiness-contract.md`](./components/agentgres/postgres-bridge-and-readiness-contract.md)
5. [`components/agentgres/projection-system-reference.md`](./components/agentgres/projection-system-reference.md)
6. [`components/storage-backends/doctrine.md`](./components/storage-backends/doctrine.md)

Build for: accepted operations, object heads, state roots, projections,
artifact refs, archive refs, receipt refs, restore/import operations, and
Postgres-compatible read surfaces.

Storage backend implementers should then read
[`components/storage-backends/filecoin-cas.md`](./components/storage-backends/filecoin-cas.md)
or another backend profile. Backend profiles explain byte availability; they do
not own artifact meaning.

### Implementing Memory

Start here:

1. [`components/agentgres/doctrine.md#memory-and-agent-wiki-boundary`](./components/agentgres/doctrine.md#memory-and-agent-wiki-boundary)
2. [`foundations/common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md)
3. [`components/daemon-runtime/api.md#memory-api`](./components/daemon-runtime/api.md#memory-api)
4. [`components/agentgres/api-object-model.md`](./components/agentgres/api-object-model.md)

Build for: Agent Wiki / `ioi-memory` as the semantic memory plane and
Agentgres `ContextMutation` or equivalent operations as the admission path for
durable behavior-affecting memory.

### Implementing Authority

Start here:

1. [`components/wallet-network/doctrine.md`](./components/wallet-network/doctrine.md)
2. [`components/wallet-network/api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md)
3. [`foundations/security-privacy-policy-invariants.md`](./foundations/security-privacy-policy-invariants.md)
4. [`components/daemon-runtime/api.md#action-mediation--authority-gateway-api`](./components/daemon-runtime/api.md#action-mediation--authority-gateway-api)

Build for: `scope:*` authority scopes, `prim:*` primitive capabilities,
grants, approvals, exact request hashes, revocation epochs, decryption leases,
and payment authority.

### Implementing Marketplace Or Routing

Start here:

1. [`foundations/mixture-of-workers.md`](./foundations/mixture-of-workers.md)
2. [`domains/marketplace-neutrality.md`](./domains/marketplace-neutrality.md)
3. [`domains/aiagent/worker-marketplace.md`](./domains/aiagent/worker-marketplace.md)
4. [`domains/sas/service-marketplace.md`](./domains/sas/service-marketplace.md)
5. [`components/daemon-runtime/events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md)

Build for: worker packages, service packages, MoW routing, contribution
receipts, routing receipts, marketplace neutrality, and optional L1 settlement
for listings, escrows, disputes, rights, and reputation.

### Implementing Product UX

Start here:

1. [`components/daemon-runtime/doctrine.md`](./components/daemon-runtime/doctrine.md)
2. [`components/daemon-runtime/api.md`](./components/daemon-runtime/api.md)
3. [`domains/ioi-ai/control-plane.md`](./domains/ioi-ai/control-plane.md)
4. [`domains/aiagent/worker-marketplace.md`](./domains/aiagent/worker-marketplace.md)
5. [`domains/sas/service-marketplace.md`](./domains/sas/service-marketplace.md)

Build for: operator controls, approval cards, run graphs, context topology
views, receipt timelines, artifact viewers, package install/publish flows, and
clear distinction between Workbench, Autopilot node, daemon, Agentgres, and L1.

### Implementing Interop

Start here:

1. [`foundations/aiip.md`](./foundations/aiip.md)
2. [`foundations/ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md)
3. [`foundations/common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md)
4. [`components/wallet-network/doctrine.md`](./components/wallet-network/doctrine.md)

Build for: bounded execution domains, AIIP envelopes, profiles, channels,
authority leases, receipt commitments, settlement intents, disputes, and
cross-domain finality.

## Implementation Navigation

Use these meta docs while building:

- [`_meta/source-of-truth-map.md`](./_meta/source-of-truth-map.md): where each
  concept is canonically owned.
- [`_meta/vocabulary.md`](./_meta/vocabulary.md): canonical names and deprecated
  wording.
- [`_meta/implementation-matrix.md`](./_meta/implementation-matrix.md): concept
  to durable form, owner, code anchor, and conformance hook.
- [`_meta/canon-readability-audit.md`](./_meta/canon-readability-audit.md):
  current readability gaps and cleanup priorities.

## Most Common Boundary Mistakes

Avoid these models:

```text
Default Harness Profile = a peer runtime beside the daemon
Autopilot Workbench = runtime truth
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
Default Harness Profile orchestrates inside the daemon
Agentgres admits operational truth
Agent Wiki / ioi-memory remembers and retrieves
artifact refs bind payload meaning
storage backends hold bytes
Private Workspace backed by cTEE forbids protected plaintext on rented nodes
Plaintext-Free Runtime Mounting exposes only public/redacted refs and private handles
wallet.network authorizes
AIIP moves bounded autonomous work
L1 settles selected public/economic/cross-domain commitments
```
