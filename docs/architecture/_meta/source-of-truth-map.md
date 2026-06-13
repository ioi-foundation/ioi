# Architecture Source Of Truth Map

Status: canonical documentation ownership map.
Canonical owner: this file for where architecture subjects should be edited first.
Supersedes: informal subject ownership scattered across plans/specs.
Superseded by: none.
Last alignment pass: 2026-06-12.

## Purpose

This map prevents split-brain architecture documentation. When a subject appears
in multiple plans, specs, evidence bundles, or implementation guides, edit the
canonical architecture file first and let supporting docs reference it.
Internal master guides are private execution scaffolding, not doctrine. They may
carry raw comparisons, sensitive sequencing, and transitional language; any
durable architectural decision they produce must be distilled into the canonical
owner below or into an accepted ADR before other docs or code treat it as canon.

New readers should start with [`../START_HERE.md`](../START_HERE.md), which
points to the canonical [`start-here.md`](./start-here.md). Builders who already
know the stack can use [`implementation-matrix.md`](./implementation-matrix.md)
to map each concept to its durable form, owner doc, code anchor, and conformance
hook.

Conflict rule:

1. Prefer `docs/architecture/` over plans, specs, ignored local master guides,
   and evidence when architecture direction conflicts.
2. If two architecture files disagree, prefer the newer aligned direction.
   Current canonical defaults:
   - `prim:*` means primitive execution capability;
   - `scope:*` means wallet/provider authority scope;
   - daemon/public runtime APIs own execution semantics;
   - Hypervisor Daemon runtime nodes are the hypervisor/control plane for
     autonomous execution;
   - the Default Harness Profile is the daemon-executed, wallet-authorized,
     Agentgres-backed, loop-native orchestration profile for bounded
     autonomous work; it is not a peer runtime beside the daemon;
   - the Hypervisor Daemon is the deterministic execution substrate for
     portable, verifiable autonomous systems;
   - HypervisorOS is the bare-metal node profile where the Hypervisor Daemon is
     the node root; it improves control, integrity, containment, measurement,
     reproducibility, and policy enforcement, but it is not a peer runtime and
     does not replace cTEE no-plaintext-custody;
   - Hypervisor Fleet is the general infrastructure manager whose first-class
     workload is autonomous systems; Fleet coordinates machines, VMs,
     containers, microVMs, WASM workloads, nodes, provider integrations,
     placement, health, cost, storage posture, cTEE posture, receipts, replay
     projections, and policy visibility, but does not execute work, authorize
     power, admit truth, or own payload bytes;
   - Hypervisor IDE is the IDE-grade operator console, not runtime truth;
   - Hypervisor is the flagship product surface for building, deploying, and
     governing autonomous systems through daemon/runtime contracts;
   - the Electron/VS Code fork is the canonical Hypervisor app shell;
   - IOI Authority Gateway is the daemon sidecar/compatibility profile for
     existing IDE, CLI, browser, hosted-agent, and MCP/tool ecosystems; it is
     not a separate runtime;
   - Agentgres is operation-backed domain truth with a Postgres bridge;
   - Agent Wiki / `ioi-memory` is the adjacent context-memory plane for what
     agents can know, retrieve, and remember; Agentgres admits and proves
     durable memory mutations when they become canonical, shared, portable,
     replayable, policy-relevant, routing-relevant, training-relevant, or
     restore-relevant;
   - `SCS` is legacy terminology removed as the product-memory architecture by
     ADR 0001; do not use it for new live architecture except as historical
     context;
   - Agentgres artifact refs own payload meaning, lifecycle, policy,
     authority, receipts, replay/import metadata, archive/restore validity, and
     state-root validity;
   - private user/app state follows the same split as private agent state:
     Agentgres owns canonical refs and meaning, storage backends hold encrypted
     bytes, wallet.network controls viewing/decryption/mutation authority, and
     IOI L1 receives only selected public/economic/cross-domain commitments;
   - wallet.network is the authority wallet for autonomous finance: it owns
     exchange authority, trade authority, risk disclosure, approval,
     signing/denial, revocation, protection actions, and wallet receipts,
     while route sources only produce candidates;
   - `decentralized.exchange` is a preferred first-party route source and
     public exchange surface, not a mandatory exchange backend, authority
     layer, liquidity owner, execution owner, or trust root;
   - `decentralized.trade` is a preferred first-party trading route source and
     advanced exposure-management surface, not a broker, custodian, user
     position owner, authority layer, venue execution owner, or trust root;
   - the Cloud Resource Lane is the source-agnostic Hypervisor/Fleet execution
     route lane for direct provider connectors, local inventory, customer cloud,
     hyperscalers, DePIN compute, decentralized storage, confidential compute,
     enterprise infrastructure, and user-specified routes;
   - `decentralized.cloud` is parked future product space for a possible public
     provider catalog, P2P/PQ-aware cloud routing layer, compute/storage receipt
     explorer, provider reputation surface, or infrastructure marketplace; it
     is not part of the present canon spine, a compute provider, mandatory
     gateway, execution owner, authority layer, storage authority, or trust
     root;
   - the `decentralized.*` resource lanes propose; wallet.network authorizes;
     Hypervisor deploys or executes; venues and providers perform; Agentgres
     records; IOI L1 settles by trigger;
   - storage backends such as Filecoin/CAS, S3, local disk, and object stores
     hold payload bytes only;
   - Private Workspace backed by cTEE is the daemon-owned workspace/execution
     profile for persistent rented GPU Hypervisor Nodes that must keep protected
     plaintext off provider-controlled nodes by default;
   - Candidate-Lattice Private Decoding is the default protected-agency strategy
     for Private Workspace backed by cTEE: rented nodes generate candidates,
     sealed/private heads select or deny;
   - IOI kernel is the L0 substrate;
   - IOI L1 is the public settlement, registry, dispute, and governance root;
   - autonomous systems can execute anywhere; IOI settles what matters;
   - AIIP moves delegated autonomous work, authority leases, receipts,
     settlement intents, disputes, reputation queries, and handoffs across
     bounded execution domains;
   - AIIP uses the same semantic protocol for local Hypervisor microharness
     routing and external autonomous-system handoffs, while transport and
     settlement mode vary by profile;
   - governed autonomous-system chains are system-local execution chains with
     policy, modules, proposals, receipts, state roots, and governed upgrades;
   - a Hypervisor Node is a local settlement, orchestration, authority, state,
     replay, routing, and interop domain for many governed autonomous-system
     chains;
   - Hypervisor IDE is not the Hypervisor Node; the IDE is the operator
     console, while the node is the local settlement domain composed around
     Hypervisor Daemon, Agentgres, wallet.network authority paths, local
     registries, receipts, and replay;
   - Hypervisor Nodes settle autonomous work locally; IOI L1 settles machine
     labor globally;
   - IOI topology is edge-in and fractal;
   - verifiable bounded agency is IOI's execution-boundary alignment thesis:
     workers may reason or propose probabilistically, but consequential effects
     cross reality only through bounded authority, policy, receipts, and
     verification;
   - workers, models, tools, connectors, browsers, shells, and computer-use
     providers are guest workloads/capabilities leased through daemon
     authority;
   - policy, receipts, replay, approvals, authority scopes, and settlement hooks
     are the shared trust/audit substrate;
   - clients are projections or operators, not private runtime truth;
   - Fleet surfaces in Hypervisor IDE and console.ioi.ai are projections and
     control lenses over daemon, Agentgres, wallet.network, cTEE, AIIP, and
     provider substrate; they are not separate apps with separate runtime truth;
   - CLI/TUI, SDK, and ADK are separate surfaces: CLI/TUI is the operator
     interface, SDK is the low-level protocol/client library, and ADK is the
     autonomous-system builder framework;
   - IDE/CLI/browser/hosted-agent adapters mediate through available control
     points only and must not claim total interception of opaque tools;
   - models and agents may reason or propose; the daemon authorizes anything
     that crosses the deterministic execution boundary;
   - Hypervisor's primary build artifact is an Autonomous System Package;
   - Autonomous System Package lifecycle is compose -> bind -> simulate ->
     authorize -> run -> verify -> inspect receipts -> package -> deploy ->
     promote -> improve;
   - Worker is the protocol actor;
   - Model is a cognition backend;
   - MoW is labor routing;
   - Worker Training is the supply-creation lifecycle;
   - TrainingBatchPlan, RawBatchArchive, QualityGateReport,
     ModelCapacityProfile, and TrainingCostLedger are first-class Foundry and
     Agentgres objects when batch-level training mechanics matter;
   - Domain Ontologies and Data Recipes are the semantic data plane;
   - DistilledOntologyDataset is the compact high-signal data substrate for
     efficient specialist training and evaluation when useful;
   - adaptive work graph is execution strategy only.
3. Record resolved contradictions only when the decision history is needed for
   future maintainers; do not keep obsolete variants as parallel doctrine.

## Subject Ownership

| Subject | Canonical Owner | Low-Level Reference | Supporting Context |
| --- | --- | --- | --- |
| First-read architecture path | [`start-here.md`](./start-here.md), [`../START_HERE.md`](../START_HERE.md) | [`source-of-truth-map.md`](./source-of-truth-map.md), [`implementation-matrix.md`](./implementation-matrix.md), [`vocabulary.md`](./vocabulary.md) | role-based onboarding paths; top-level shim avoids broken references |
| Concept implementation status and durable form | [`implementation-matrix.md`](./implementation-matrix.md) | subject owner docs listed per row | code anchors, conformance hooks, promotion guidance |
| Hypervisor kernel substrate unification migration, Step/Module ABI, route-family owner map, Rust core extraction target, JS facade retirement, and terminal conformance command contract | [`hypervisor-kernel-substrate-unification-master-guide.md`](./hypervisor-kernel-substrate-unification-master-guide.md) | [`hypervisor-kernel-substrate-migration-matrix.md`](./hypervisor-kernel-substrate-migration-matrix.md), [`implementation-matrix.md`](./implementation-matrix.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | `hypervisor-conformance`, Rust core module targets, and route-family cleanup conditions |
| Canon readability and enterability workplan | [`canon-readability-audit.md`](./canon-readability-audit.md) | [`start-here.md`](./start-here.md), [`implementation-matrix.md`](./implementation-matrix.md) | cleanup backlog and terminology watchlist |
| Web4 category and IOI stack | [`web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | architectural-improvements plans |
| `decentralized.*` resource lanes, Cloud Resource Lane, route-intelligence doctrine, decentralized.exchange, decentralized.trade, parked future decentralized.cloud, lane boundaries, trade/cloud lane non-ownership, and cross-lane proposal/authority/execution/truth/settlement split | [`decentralized-resource-lanes.md`](../foundations/decentralized-resource-lanes.md) | [`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md), [`hypervisor/fleet.md`](../components/hypervisor/fleet.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | decentralized.exchange routes liquidity, decentralized.trade routes exposure, Cloud Resource Lane routes execution; decentralized.cloud is parked future product space, not present canon spine or mandatory gateway; lanes propose, Wallet authorizes, Hypervisor executes/deploys, venues/providers perform, Agentgres records, IOI settles by trigger |
| AIIP, bounded execution domains, work interop, and cross-system handoffs | [`aiip.md`](../foundations/aiip.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | autonomous-system settlement layer synthesis, IBC comparison notes, marketplace interop docs |
| Governed autonomous-system chains, Hypervisor Nodes, and machine-economy stack | [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | Hypervisor Node, local settlement, interop, and machine-economy strategy docs |
| Verifiable bounded agency and execution-boundary alignment | [`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md) | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | bounded-agency thesis, conformance contracts, investor/product framing |
| Mixture of Workers and worker routing | [`mixture-of-workers.md`](../foundations/mixture-of-workers.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | aiagent/sas routing docs |
| Worker Training lifecycle and training profiles | [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | Hypervisor Foundry, aiagent categories, sas worker-training contracts |
| Domain Ontologies and Data Recipes | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | Hypervisor Foundry, Worker Training, connector mappings, distilled ontology datasets, ontology-aware projections |
| IOI L1, L0/L1 boundary, and settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`ioi-l1-smart-contract-interfaces.md`](../foundations/ioi-l1-contract-interfaces.md) | sas/aiagent marketplace docs |
| Kernel/domain architecture and edge-in topology | [`domain-kernels.md`](../foundations/domain-kernels.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime package boundaries |
| Autonomous System Package lifecycle | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | Hypervisor lifecycle clarity master guide, autonomous systems shape audit, workflow compositor docs |
| Agentgres canonical state and Postgres bridge | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres-postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md), [`canonical-state-and-projection-system-whitepaper.md`](../components/agentgres/projection-system-reference.md) | detailed Agentgres reference module inside canonical owner, evidence/architectural-improvements-broad |
| Agentgres artifact refs, payload refs, evidence bundles, delivery bundles, archive refs, and restore/import validity | [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | storage backend docs, delivery/evidence docs |
| Private user/app state refs, encrypted profile metadata, app preferences, service intake state, workspace snapshots, and non-public app payloads | [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`storage-backends-doctrine.md`](../components/storage-backends/doctrine.md) | App surfaces may resolve authorized views; IOI L1 stores only selected public/economic commitments |
| Agent Wiki, `ioi-memory`, and context-memory admission boundary | [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`canonical-state-and-projection-system-whitepaper.md`](../components/agentgres/projection-system-reference.md) | ADR 0001, roadmap memory notes, Hypervisor product context |
| Default Harness Profile, loop-native orchestration, context topology, and output ownership | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | CIRC/CEC, runtime harness code, default-harness projection/shadow/gated/live activation |
| HypervisorOS, bare-metal Hypervisor nodes, measured boot, daemon-rooted node control, node measurement receipts, and HypervisorOS conformance | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | bare-metal node image plans, measured boot plans, provider/DePIN node integrity docs |
| Hypervisor Fleet, general infrastructure manager, autonomous infrastructure manager, node registry, provider integrations, Cloud Resource Lane, CloudRoute, CloudCandidate, VMs, containers, microVMs, WASM workloads, images, volumes, networks, snapshots, backups, restore, GPU pools, DePIN/cloud/local/bare-metal fleet posture, storage posture, cTEE posture, placement, cost, health, receipts, replay projections, migration cockpit, Hypervisor IDE Fleet surface, and console.ioi.ai Fleet surface | [`fleet.md`](../components/hypervisor/fleet.md) | [`decentralized-resource-lanes.md`](../foundations/decentralized-resource-lanes.md), [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | VMware/Proxmox/KubeVirt/Nutanix/Kubernetes/bare-metal migration cockpit, direct provider connectors, DePIN/cloud GPU manager, Akash/Filecoin/CAS/S3 posture, HypervisorOS estate, provider connectors, node health/cost/placement, Fleet surfaces inside Hypervisor IDE and console.ioi.ai |
| Private Workspace backed by cTEE, Plaintext-Free Runtime Mounting, Plaintext-Free Model Mounting, Custody Types, Custody Proof, Private Agency Transform, Candidate Coverage Profile, Counterfactual Lattice Execution, Cryptographic Operator Plane, Candidate-Lattice Private Decoding, External Model API Boundary, Execution Privacy Posture, persistent rented GPU Hypervisor Nodes, private files/folders, private strategy execution, deterrence/detection, and autonomy leases | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | private quant strategy profile, DePIN/cloud node privacy, provider-trust boundary, coverage/redundancy profiles, privacy posture labels, custody proofs, runtime/model/lattice/private-operator receipts, canary/watermark receipts, deprecated shielded-compute notes |
| Hypervisor IDE, Electron/VS Code shell, shared builder substrate, and workflow compositor | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | internal product context, IDE-first Tauri retirement guide, and workflow-compositor specs |
| IOI Authority Gateway, Hypervisor Guard, and compatibility adapters | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | IDE/CLI/browser adapter specs, MCP gateways, shell wrappers, Git hooks, hosted-agent gateways |
| Daemon and public runtime API | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | Cursor SDK parity guide |
| CLI/TUI operator surface | [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | CLI product context, operator workflows |
| SDK and ADK boundaries | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | agent-sdk package docs, future ADK docs, internal package-boundary docs |
| SDK, CLI, GUI, harness, benchmark, compositor boundaries | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | Compatibility row for shared client-surface validation; use the split CLI/TUI and SDK/ADK rows above for ownership. |
| wallet.network authority, low-assurance access points, SMS/challenge escalation, and step-up grants | [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md) | [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | CIRC/CEC, access-point bindings, step-up challenges, guardian/auth surface boundary |
| wallet.network product doctrine, exchange authority, trade authority, route-source boundaries, `ExchangeIntent`, `RouteCandidate`, `TradeIntent`, `PositionReceipt`, asset exposure, protection actions, approval inbox, wallet receipts, and wallet SDK events | [`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md) | [`decentralized-resource-lanes.md`](../foundations/decentralized-resource-lanes.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`wallet-network-authority-layer.md`](../components/wallet-network/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`agentgres-state-substrate.md`](../components/agentgres/doctrine.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | decentralized.exchange as preferred route source, decentralized.trade as preferred trading route source, direct pools, DEX routers, solvers, quote APIs, bridge routers, venue adapters, perps/margin policy, route-risk and position-risk disclosure, protection center, Activity receipts |
| Capability and authority ontology | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`conformance/CIRC.md`](../../conformance/agentic-runtime/CIRC.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | agent tool vocabulary plan |
| aiagent.xyz worker marketplace and managed instances | [`aiagent-xyz-worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent-xyz-worker-and-inter-agent-endpoints.md`](../domains/aiagent/worker-endpoints.md) | product context module inside canonical owner, marketplace neutrality doc |
| sas.xyz service marketplace | [`sas-xyz-service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas-xyz-service-endpoints.md`](../domains/sas/service-endpoints.md) | product context module inside canonical owner, service settlement docs |
| ioi.ai control plane | [`ioi-ai-control-plane.md`](../domains/ioi-ai/control-plane.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md), [`wallet-network-api-and-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | product context in marketplace/CLI/litepaper docs |
| Storage backends | [`storage-backends-doctrine.md`](../components/storage-backends/doctrine.md) | [`filecoin-cas-backend-profile.md`](../components/storage-backends/filecoin-cas.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | deprecated `components/filecoin-cas/*` redirect stubs |
| Filecoin/CAS/IPFS backend profile | [`filecoin-cas-backend-profile.md`](../components/storage-backends/filecoin-cas.md) | [`storage-backends-doctrine.md`](../components/storage-backends/doctrine.md), [`agentgres-artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | historical `components/filecoin-cas/*` paths |
| Runtime nodes, hosted workers, TEE, DePIN | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) | [`runtime-node-and-task-capsule-protocol.md`](../components/daemon-runtime/task-capsule-protocol.md) | hosted/self-hosted proof plans |
| Model routing, BYOK, run-to-idle | [`model-router-byok-run-to-idle.md`](../components/model-router/doctrine.md) | [`model-router-api-byok-and-mounting.md`](../components/model-router/api-byok-mounting.md) | model-router specs |
| Connectors, tools, MCP | [`connectors-tools-and-authority-registry.md`](../components/connectors-tools/doctrine.md) | [`connector-and-tool-contracts.md`](../components/connectors-tools/contracts.md) | MCP/skills/hooks guides |
| Events, receipts, traces, replay | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`agentgres-api-and-object-model.md`](../components/agentgres/api-object-model.md) | runtime evidence specs |
| Smarter-agent runtime loop | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | internal runtime loop plans |
| Marketplace neutrality and contribution accounting | [`marketplace-neutrality-and-contribution-accounting.md`](../domains/marketplace-neutrality.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | aiagent/sas docs |
| Security/privacy/policy invariants | [`security-privacy-and-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) | [`conformance/CIRC.md`](../../conformance/agentic-runtime/CIRC.md), [`conformance/CEC.md`](../../conformance/agentic-runtime/CEC.md) | runtime invariant specs |

## Edit Rules

- Add new runtime/client/package ownership language to the public daemon,
  event, and common-object contracts first. Internal package-boundary plans may
  track implementation sequencing, but they do not own canonical doctrine.
- Add new bare-metal node, measured boot, node-root, node integrity receipt,
  HypervisorOS image, or firmware/TPM profile language to
  [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) first. Do
  not let measured boot replace cTEE no-plaintext-custody or wallet.network
  authority.
- Add new AIIP packet, profile, channel, bounded-execution-domain, handoff,
  relay/router, settlement-intent, or inter-autonomous-system protocol language
  to [`aiip.md`](../foundations/aiip.md) first. Do not create separate bespoke
  interop protocols for Hypervisor, aiagent.xyz, sas.xyz, or external systems
  when AIIP semantics apply.
- Add new governed-autonomous-system-chain, Hypervisor Node, local settlement,
  autonomous-system interop, service-module invocation, or machine-economy stack
  language to
  [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md)
  first. Do not collapse Hypervisor IDE, Hypervisor Node, Agentgres domain,
  and IOI L1 into one layer.
- Add new alignment-security, bounded-agency, process-containment,
  self-upgrade, or execution-boundary proof language to
  [`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md)
  first. Do not canonize claims that IOI proves every model's private cognition
  or goals are safe; route such wording through explicit non-claims or ADRs.
- Add new Hypervisor shell, IDE, extension-host, or GUI authority language
  to daemon/runtime ownership docs and Hypervisor product architecture docs before
  implementation plans rely on it. Hypervisor IDE surfaces are operator consoles and
  projections; they do not own runtime truth.
- Add new IOI Authority Gateway, Hypervisor Guard, IDE/CLI sidecar, shell
  wrapper, MCP gateway, API proxy, Git hook, browser adapter, hosted-agent
  gateway, or CI/CD mediation language to daemon/runtime ownership docs and
  daemon API contracts before implementation plans rely on it. These adapters
  submit proposed actions, observations, and approvals to the daemon; they do
  not own policy, durable runtime state, receipts, replay, secrets, or effects.
- Add new Autonomous System Package, lifecycle verb, package readiness,
  deployment profile slot, promotion slot, or `AutonomousSystemManifest`
  language to [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  before Phase 5 connectors, Hypervisor, workflow compositor, SDK, or CLI
  surfaces depend on it.
- Add new MoW, worker-routing, Sparse Worker Category, Worker Training, batch
  planning, generation-batch, quality-gate, model-capacity, or training-cost
  doctrine to [`mixture-of-workers.md`](../foundations/mixture-of-workers.md)
  and [`worker-training-lifecycle.md`](../foundations/worker-training-lifecycle.md)
  before product/domain docs rely on it.
- Add new ontology, DataRecipe, CanonicalObjectModel, ConnectorMapping,
  PolicyBoundDataView, DistilledOntologyDataset, EvaluationDataset,
  OntologyProjection, or
  ontology-to-worker doctrine to
  [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md)
  before product, connector, Agentgres, or Worker Training docs rely on it.
- Add new operator-facing CLI/TUI control language to
  [`ioi-cli-daemon-runtime.md`](../components/daemon-runtime/doctrine.md),
  [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md), and
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before product-surface docs rely on it.
- Add new SDK client behavior or ADK builder-framework behavior to
  [`ioi-daemon-runtime-api.md`](../components/daemon-runtime/api.md) and
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before product-surface docs rely on it. SDK language should mean low-level
  client library. ADK language should mean autonomous-system builder framework.
- Add new shared object fields to
  [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
  before copying examples into endpoint docs.
- Add new Agentgres durability, consistency, SQL bridge, migration, index, or
  database-readiness doctrine to
  [`agentgres-postgres-bridge-and-readiness-contract.md`](../components/agentgres/postgres-bridge-and-readiness-contract.md)
  before product or implementation docs rely on it.
- Add new event, trace, receipt, scorecard, or replay fields to
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
  before referencing them in daemon, Agentgres, GUI, harness, or benchmark docs.
- Add new low-level proof gates to canonical runtime/event/conformance docs
  before adding them to internal implementation prompts.
- Keep internal master guides private when they contain raw competitive,
  transitional, or potentially misconstruable architecture notes. Treat them as
  execution inputs only; promote their settled outcomes into canonical docs or
  ADRs before making them durable references.

## Decision History Policy

Accepted architecture decision history belongs in
[`docs/decisions`](../../decisions/README.md). Do not recreate contradiction
logs as parallel doctrine; port durable rationale into ADRs and keep current
architecture prose clean.

Older plans may keep historical terms such as `adaptive work graph`, former artifact names, or
pre-split capability language only when they are clearly describing decision history.
New canonical architecture must use:

```text
adaptive_work_graph for public delegated execution strategy
prim:* for primitive execution capabilities
scope:* for wallet/provider authority scopes
grant:// or authority_grant_id for authority grants/leases
projection/cache/checkpoint for non-canonical client state
```
