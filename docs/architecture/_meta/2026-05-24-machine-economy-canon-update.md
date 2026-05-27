# Machine-Economy Canon Update Brief

Status: architecture change brief.
Authority: supporting summary only. Canonical authority remains the linked
`docs/architecture/` files and accepted ADRs.
Date: 2026-05-24, updated 2026-05-25.
Scope: Canon changes from the machine-economy stack and autonomous-system settlement-layer canonization passes.

## Executive Summary

This pass canonicalized the coherent machine-economy stack:

```text
Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts

Autopilot Node
  local orchestration, interop, authority, state, replay, routing, and local settlement

AIIP
  RPC-shaped, receipt-native work interop across bounded execution domains

IOI L1
  global identity, registry, rights, receipt roots, disputes, reputation, and economic settlement
```

The core machine-economy sentence is now:

> Autopilot nodes are local settlement domains for autonomous systems; IOI L1 is the global settlement layer for the machine economy.

The public shorthand is:

> Autopilot settles autonomous work locally. IOI settles machine labor globally.

The broader protocol thesis is:

> Autonomous systems can execute anywhere. IOI settles what matters.

The AIIP thesis is:

> AIIP moves autonomous work across systems. IOI settles what happened.

This framing prevents three layers from collapsing:

```text
Autopilot UI != Autopilot node != IOI L1
```

It also makes explicit that models are mounted cognition backends supplied by
deployment profile. The node owns model routing and invocation boundaries, not
model weights by default.

## Why This Matters

The updated canon turns IOI from "agent app plus blockchain plus marketplace"
into a layered machine-economy stack:

```text
Autopilot
  local sovereign coordination layer for autonomous systems

IOI daemon
  deterministic execution and authority-enforcement substrate

Agentgres
  local/domain canonical operational truth, projections, proposals, receipts, and state roots

wallet.network
  authority, secrets, leases, grants, approvals, payment authority, and revocation

Model Router
  policy-bound cognition routing; model weights/endpoints are deployment-profile resources

AIIP
  work interop protocol for bounded autonomous domains, handoffs, authority leases, receipts, settlement intents, disputes, and reputation queries

aiagent.xyz
  first-party worker and service-module marketplace built on AIIP and IOI settlement

sas.xyz
  first-party outcome and Service-as-Software marketplace built on AIIP and IOI settlement

IOI L1
  global autonomous-system settlement, registry, reputation, dispute, rights, and root-anchoring layer
```

The result is scalable: local autonomous work does not spam IOI L1, but public
rights, disputes, settlement, reputation, and marketplace roots still anchor to
the shared chain when needed.

## New Canonical Documents

### `docs/architecture/foundations/governed-autonomous-systems.md`

Added a new canonical foundation document for:

- governed autonomous-system chains;
- Autopilot nodes;
- local settlement domains;
- service-module invocation;
- proposal-mediated upgrades;
- local autonomous-system interop;
- the coherent machine-economy stack.

Key doctrine added:

> Autonomous systems are not prompts. They are governed execution objects.

> Each Autopilot node is a local autonomous-system settlement domain. It hosts many governed autonomous-system chains, routes work between them, manages authority through wallet.network, stores state and receipts through Agentgres, and anchors selected commitments to IOI L1 for global registry, dispute, reputation, and economic settlement.

### `docs/decisions/0011-autopilot-nodes-and-governed-autonomous-system-chains.md`

Added ADR 0011 to record the durable decision:

- Autopilot node is a local settlement domain, not merely the Workbench UI.
- Governed autonomous-system chains are local stateful execution objects.
- IOI L1 remains the shared public chain for registry, rights, disputes,
  reputation, economics, and selected roots.
- Public docs should avoid "each agent is a blockchain" unless heavily
  qualified.

Updated `docs/decisions/README.md` to include ADR 0011.

### `docs/architecture/foundations/aiip.md`

Added a new canonical foundation document for:

- AIIP as the RPC-shaped, receipt-native interop protocol for bounded
  autonomous work;
- bounded execution domains;
- AIIP packet classes;
- AIIP envelopes and profiles;
- internal Autopilot microharness routing and external autonomous-system
  handoffs using the same semantic protocol;
- routing receipts;
- first-party marketplaces as protocol applications rather than the protocol
  boundary;
- independent AS-L1s and the "sovereignty at the edge, settlement at the
  center" doctrine.

Key doctrine added:

> Autonomous systems can execute anywhere. IOI settles what matters.

> AIIP moves autonomous work across systems. IOI settles what happened.

> The marketplace is not the protocol. The marketplace is a first-party application of the protocol.

### `docs/decisions/0012-ioi-autonomous-system-settlement-and-aiip.md`

Added ADR 0012 to record the durable decision:

- IOI mainnet is the base settlement layer for sovereign autonomous systems.
- AIIP is the work interop protocol for local and cross-system autonomous
  handoffs.
- aiagent.xyz and sas.xyz are first-party protocol applications and demand
  generators, not the whole protocol.
- Independent AS-L1s, appchains, sovereign domains, enterprises, robot fleets,
  and third-party autonomous systems are positive when they increase IOI
  settlement demand.

Updated `docs/decisions/README.md` to include ADR 0012.

## Updated Canonical Docs

### `docs/architecture/README.md`

Added the machine-economy canon to the architecture index:

- `Autopilot Node = local autonomous-system settlement and interop domain`.
- `AIIP = RPC-shaped, receipt-native interop protocol for bounded autonomous
  work`.
- `Bounded Execution Domain = any local, hosted, enterprise, marketplace,
  robot, worker, service, microharness, or AS-L1 domain that performs scoped
  autonomous work under policy and receipts`.
- New high-level spec link for `governed-autonomous-systems.md`.
- New high-level spec link for `aiip.md`.
- New one-sentence boundary rows for governed autonomous-system chains and
  Autopilot nodes, AIIP, and bounded execution domains.
- Core layering now includes governed autonomous-system chains and Autopilot
  node/local settlement domain, plus the AIIP work interop layer.
- Added non-negotiables:
  - Autopilot Workbench is not the Autopilot node.
  - Governed autonomous-system chains are local state machines, not necessarily
    standalone public blockchains or IOI L1s.
  - The marketplace is not the protocol.
  - AIIP is shared semantics for local microharness routing and external
    autonomous-system handoffs.

### `docs/architecture/_meta/source-of-truth-map.md`

Made `governed-autonomous-systems.md` the edit-first owner for:

- governed-autonomous-system chains;
- Autopilot nodes;
- local settlement;
- autonomous-system interop;
- service-module invocation;
- machine-economy stack language.

Added conflict-rule defaults:

- autonomous systems can execute anywhere; IOI settles what matters;
- AIIP moves delegated autonomous work, authority leases, receipts, settlement
  intents, disputes, reputation queries, and handoffs across bounded execution
  domains;
- AIIP uses the same semantic protocol for local Autopilot microharness routing
  and external autonomous-system handoffs, while transport and settlement mode
  vary by profile;
- Autopilot nodes settle autonomous work locally.
- IOI L1 settles machine labor globally.
- Autopilot Workbench is not the Autopilot node.
- Governed autonomous-system chains are system-local execution chains with
  policy, modules, proposals, receipts, state roots, and governed upgrades.

### `docs/architecture/_meta/vocabulary.md`

Added canonical terms:

- `AIIP`
- `BoundedExecutionDomain`
- `AIIPEnvelope`
- `AIIPProfile`
- `AIIPChannel`
- `GovernedAutonomousSystemChain`
- `IntelligentExecutionNode`
- `AutopilotNode`
- `LocalSettlementDomain`
- `ServiceModule`
- `ModuleInvocation`
- `ModelDeploymentProfile`

Refined `Model`:

- models are cognition backends mounted or invoked by workers;
- model routing belongs to the runtime/node contract;
- model weights or provider endpoints are mounted by deployment profile;
- model weights are not part of the Autopilot node binary by default.

Clarified `AutopilotWorkbench`:

- it is the IDE-grade operator console;
- it is not the full Autopilot node.

### `docs/architecture/foundations/common-objects-and-envelopes.md`

Added shared envelope types:

- `BoundedExecutionDomainEnvelope`
- `AIIPChannelEnvelope`
- `AIIPEnvelope`
- `CapabilityDescriptorEnvelope`
- `TaskOfferEnvelope`
- `TaskAcceptanceEnvelope`
- `HandoffEnvelope`
- `ReceiptCommitmentEnvelope`
- `SettlementIntentEnvelope`
- `ReputationEventEnvelope`
- `AutonomousSystemChainEnvelope`
- `AutopilotNodeEnvelope`
- `ServiceModuleManifestEnvelope`
- `ModuleInvocationEnvelope`
- `UpgradeProposalEnvelope`
- `UpgradeDecisionEnvelope`
- `LocalSettlementEnvelope`
- `ModelDeploymentProfileEnvelope`

Added ID namespaces:

- `domain://...`
- `node://...`
- `module://...`
- `invocation://...`
- `proposal://...`
- `transition://...`
- `aiip://channel/...`
- `packet://...`
- `settlement-intent://...`

Extended manifest and package surfaces:

- `manifest_type` now includes `autonomous_system_chain` and `service_module`.
- Autonomous-system manifests can bind model deployment profiles.
- Receipt types now include `module_invocation`, `local_settlement`,
  `upgrade_proposal`, and `upgrade_decision`.

Added model deployment profile semantics:

```text
mount_mode =
  bundled_weights
  local_file
  local_server
  external_api
  hosted_pool
  tee_session
  depin_session
  customer_vpc
```

Explicit rule:

> Bundled local weights are valid for offline, demo, small sovereign, or deployment-specific profiles. They are not the architecture default.

### `docs/architecture/components/daemon-runtime/doctrine.md`

Added `Autopilot Node Boundary`:

- Autopilot node is local autonomous-system settlement and interop domain.
- Daemon is execution and authority-enforcement substrate inside the node.
- Workbench is operator console.
- Agentgres is local operational truth.
- wallet.network owns authority.
- IOI L1 receives selected roots.

Clarified harness execution:

- daemon may execute an autonomous-system harness as a modular
  state-transition pipeline;
- consequential harness steps are typed service-module invocations;
- daemon writes governed autonomous-system transitions and Autopilot-node local
  settlement records through Agentgres-compatible APIs.

Added explicit model boundary:

- daemon owns model routing and invocation boundaries;
- model weights, local model files, local model servers, BYOK providers,
  hosted pools, TEE sessions, DePIN sessions, and customer VPC endpoints are
  deployment-profile resources.

### `docs/architecture/components/agentgres/doctrine.md`

Added machine-economy role for Agentgres:

- operational truth substrate for governed autonomous-system chains and
  Autopilot-node settlement domains;
- records proposals, module invocations, local settlement records, receipt
  roots, upgrade decisions, state roots, and replayable projections.

Added owned state categories:

- governed autonomous-system chain records;
- Autopilot-node local settlement records;
- service module manifests and registry roots;
- module invocation records;
- proposal queues;
- upgrade decisions.

Clarified that Autopilot-node local settlement truth is recorded through
Agentgres/domain operations, not Workbench UI state.

### `docs/architecture/components/agentgres/api-object-model.md`

Added Agentgres API/object-model support for:

- `/v1/autopilot-nodes`
- `/v1/autonomous-system-chains`
- `/v1/service-modules`
- `/v1/module-invocations`
- `/v1/upgrade-proposals`
- `/v1/upgrade-proposals/{proposal_id}/decisions`
- `/v1/local-settlements`

Added object classes:

- `AutopilotNode`
- `AutonomousSystemChain`
- `ServiceModuleManifest`
- `ModuleInvocation`
- `UpgradeProposal`
- `UpgradeDecision`
- `LocalSettlementRecord`

Added example shapes for Autopilot node, autonomous-system chain, module
invocation, and local settlement records.

### `docs/architecture/foundations/ioi-l1-mainnet.md`

Added local/global settlement doctrine:

```text
Governed Autonomous-System Chain
  accepts local module invocations, proposals, receipts, and state transitions

Autopilot Node
  coordinates many autonomous-system chains and settles local interop, authority
  outcomes, receipt bundles, replay, and escalation records

IOI L1
  anchors selected roots and settles public rights, disputes, reputation,
  registry commitments, and economics
```

Expanded IOI L1 duties to include selected:

- Autopilot-node roots;
- autonomous-system-chain roots;
- policy roots;
- module roots;
- upgrade roots;
- local settlement roots;
- receipt roots.

Added non-ownership and gas-boundary clarifications:

- IOI L1 does not own Autopilot-node local settlement state.
- IOI L1 does not own every governed autonomous-system-chain transition.
- IOI gas is not consumed for Autopilot-node local settlement records or
  autonomous-system-chain module invocations.

Extended 2026-05-25 autonomous-system settlement doctrine:

- IOI L1 is the canonical Web4 settlement layer for autonomous systems.
- Authority lease commitments, settlement claims, routing roots, worker
  eligibility commitments, and cross-system handoff finality are core
  settlement objects when public trust requires them.
- AIIP channel, profile, schema, endpoint, relay/router policy, and capability
  registry commitments can anchor to IOI L1 when global interoperability
  requires them.
- Independent AS-L1s and sovereign domains may register for `ai://`
  discoverability, AIIP interoperability, and settlement.

Added L1 contract family names for:

- `AutonomousSystemRegistry`
- `AIIPChannelRegistry`
- `AIIPSchemaRegistry`
- `SettlementAccountRegistry`
- `AuthorityLeaseCommitment`
- `ReceiptRootRegistry`
- `HandoffFinalityRegistry`
- `SettlementIntentRegistry`
- `WorkerEligibilityRoot`

### `docs/architecture/foundations/verifiable-bounded-agency.md`

Added proposal-mediated autonomous-system upgrade doctrine:

```text
observe limitation
-> draft upgrade proposal
-> bind target module, workflow, policy, tool, model route, schema, or contract
-> simulate, evaluate, benchmark, or dry-run
-> review under policy and authority
-> approve, reject, escalate, or roll back
-> commit accepted operation through daemon/Agentgres
-> emit receipts and optional IOI L1 roots
```

Canon invariant:

> Agents do not self-modify directly. Autonomous systems propose upgrades to governed modules, and only policy-bound, receipted governance makes those upgrades canonical.

### `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`

Added event kinds:

- `module.invocation_proposed`
- `module.invocation_started`
- `module.invocation_completed`
- `module.invocation_committed`
- `upgrade.proposal_submitted`
- `upgrade.proposal_approved`
- `upgrade.proposal_rejected`
- `upgrade.proposal_committed`
- `local_settlement.committed`

Added receipt types:

- `ModuleInvocationReceipt`
- `UpgradeProposalReceipt`
- `UpgradeDecisionReceipt`
- `LocalSettlementReceipt`

Added receipt examples for:

- module invocation;
- upgrade proposal/decision;
- local settlement.

Updated `RoutingDecisionReceipt` to cover AIIP and marketplace-neutral routing
across workers, services, domains, runtime nodes, and autonomous systems:

- `intent_hash`
- `selected_domain_or_worker`
- `authority_scope`
- `cost_bound`
- `reason_code`
- `fallback_policy`

### `docs/architecture/foundations/web4-and-ioi-stack.md`

Added governed autonomous-system chains and Autopilot nodes to the reference
stack and system boundary.

Added AIIP to the reference stack and Web4 category requirements:

- AIIP is RPC-shaped, receipt-native interop for bounded autonomous work.
- AIIP moves delegated work, authority leases, receipts, settlement intents,
  disputes, reputation queries, and handoffs between bounded execution domains.

Added Web4 requirement:

> Local autonomous-system settlement.

Added model deployment-profile rule:

> Models are deployment-profile resources, not architecture-default node binaries.

### `docs/architecture/foundations/domain-kernels.md`

Added governed autonomous-system chains and Autopilot nodes to the fractal
kernel/domain topology.

Clarified:

- Autopilot node is a local domain composition of Workbench, daemon, Agentgres,
  wallet.network authority paths, local registries, receipts, replay, and
  runtime profiles.
- It may host many governed autonomous-system chains.
- It does not become IOI L1.

### `docs/architecture/foundations/security-privacy-policy-invariants.md`

Added invariants:

- autonomous-system upgrades are proposal-mediated;
- only policy-bound governance may commit upgrades;
- Autopilot-node local settlement records are Agentgres/domain truth until
  selected roots are anchored to IOI L1;
- Autopilot nodes settle autonomous work locally; IOI L1 settles machine labor
  globally.

### `docs/architecture/foundations/ioi-l1-contract-interfaces.md`

Added autonomous-system settlement and AIIP contract interface stubs:

- `AutonomousSystemRegistry`
- `AIIPChannelRegistry`
- `AIIPSchemaRegistry`
- `SettlementAccountRegistry`
- `AuthorityLeaseCommitmentRegistry`
- `ReceiptRootRegistry`
- `SettlementIntentRegistry`
- `HandoffFinalityRegistry`
- `WorkerEligibilityRootRegistry`

Extended the gas-boundary examples to include autonomous-system registration,
AIIP channel/schema/profile registration, authority lease commitments, receipt
root anchoring, settlement intents, and cross-system handoff finality.

### `docs/architecture/domains/aiagent/worker-marketplace.md`

Reframed aiagent.xyz as:

- a first-party Web4 marketplace application built on AIIP and IOI settlement;
- an AIIP marketplace-worker profile user;
- a protocol client, demand generator, and proof surface rather than the whole
  protocol.

### `docs/architecture/domains/sas/service-marketplace.md`

Reframed sas.xyz as:

- a first-party Web4 marketplace application built on AIIP and IOI settlement;
- an AIIP outcome-service profile user;
- a protocol client, demand generator, and proof surface rather than the whole
  protocol.

### `docs/architecture/domains/marketplace-neutrality.md`

Updated `RoutingDecisionReceipt` to support AIIP routing across bounded
execution domains and to make first-party routing bias auditable.

### `docs/architecture/components/model-router/doctrine.md`

Made explicit:

- model router belongs inside the runtime/node contract;
- model weights, provider endpoints, local model servers, and hosted cognition
  backends are mounted by deployment profile;
- they are not part of the Autopilot node binary or architecture default.

Added node packaging doctrine:

> The node contains model routing and invocation boundaries. The model itself is a mounted cognition backend unless a deployment profile explicitly bundles local weights.

Added invariants:

- Autopilot node binary must not assume embedded model weights.
- Embedded or bundled weights are allowed only when declared by deployment
  profile.
- Service modules and workers invoke models through routes, not direct
  assumptions about local files, provider names, or bundled binaries.

### `docs/architecture/components/model-router/api-byok-mounting.md`

Added API fields:

- `mount_mode`
- `deployment_profile_ref`
- `model_artifact_ref`

Added non-negotiables:

- bundled model weights are a deployment profile, not the architecture default;
- node binaries own router and invocation contracts, not implicit model
  possession.

## Whitepaper Update Weighting

### Strongly Consider Updating the Whitepaper

The whitepaper should likely be updated if it currently frames IOI as:

- an agent app plus blockchain;
- a monolithic chain-centered architecture;
- every agent writing directly to IOI L1;
- Autopilot as primarily a UI/app rather than a local coordination node;
- models as embedded node binaries or the central economic actor;
- marketplaces as separate from local autonomous-system settlement.

The new canon gives a cleaner thesis:

> IOI is the settlement and interoperability layer for Web4 autonomous systems.
> Autonomous systems can execute anywhere; IOI settles what matters.

This should affect any whitepaper sections on:

- core thesis;
- system architecture;
- AIIP and interop;
- Autopilot;
- IOI L1;
- Agentgres;
- model routing;
- worker/module marketplace;
- Service-as-Software;
- safety and bounded recursive improvement;
- interop and settlement.

### High-Value Whitepaper Additions

Add a stack diagram:

```text
Execution Layer
  models, tools, APIs, browsers, terminals, robots, VMs, humans, enterprise systems

Bounded Execution Domains
  local microharnesses, installed workers, remote workers, outcome providers, AS-L1s

Autopilot Node
  meta-harness, router, governance surface, local control plane, receipt aggregator

AIIP
  task offers, quotes, invocations, handoffs, authority leases, receipts, settlement intents

IOI L1
  identity, authority, receipt roots, payments, disputes, reputation, worker eligibility, handoff finality
```

Add a strategic line:

> Autonomous systems can execute anywhere. IOI settles what matters.

Add an interop line:

> AIIP moves autonomous work across systems. IOI settles what happened.

Add a safety line:

> Agents do not self-modify directly. Autonomous systems propose upgrades to governed modules, and only policy-bound, receipted governance makes those upgrades canonical.

Add a model-routing line:

> The node owns model routing and invocation boundaries; models are mounted cognition backends supplied by deployment profile.

Add a marketplace line:

> The marketplace is not the protocol. The marketplace is a first-party application of the protocol.

### Whitepaper Language to Avoid

Avoid:

- "each agent is a blockchain" without qualification;
- "each agent is an L1" in public-facing copy;
- "Autopilot is the settlement layer" when referring only to the UI;
- "models are part of the node binary" as a default architecture claim;
- "IOI L1 stores every agent step";
- "receipts are blocks" as a literal protocol claim.
- "IBC for agents" without explaining the work-native, receipt-native upgrade;
- "the agent marketplace is the protocol";
- "everything runs on mainnet".

Prefer:

- governed autonomous-system chain;
- intelligent execution node;
- Autopilot node;
- local settlement domain;
- service-module invocation;
- proposal-mediated self-improvement;
- model deployment profile.
- bounded execution domain;
- AIIP;
- settlement layer for autonomous systems.

### Recommended Whitepaper Framing

Use this as the whitepaper-level thesis:

> IOI is the settlement and interoperability substrate for Web4 autonomous
> systems. Autonomous systems, marketplaces, microharnesses, and independent
> AS-L1s can run anywhere and specialize locally, while IOI mainnet anchors the
> shared trust layer: identity, authority, receipts, payments, disputes,
> reputation, and cross-system handoffs.

Use this as the concise product/protocol split:

```text
Autopilot node = local machine-labor operating domain
AIIP = work interop fabric for bounded autonomous systems
IOI L1 = global autonomous-system settlement layer
aiagent.xyz = first-party worker and service-module marketplace
sas.xyz = first-party outcome marketplace
wallet.network = authority layer
Agentgres = operational truth substrate
daemon = deterministic execution substrate
```

### Whitepaper Priority

Priority: high.

Reason: this update changes the architecture's strategic center of gravity. It
does not merely add new object types. It clarifies what IOI is:

```text
not just an agent app
not just a blockchain
not just a marketplace

but a local-to-global settlement stack for governed machine labor
```

The whitepaper does not need to expose every envelope or API shape. It should
absorb the layer split, strategic sentence, AIIP role, local/global settlement
model, first-party marketplace boundary, bounded self-improvement model, and
model deployment-profile boundary.

## Validation

Architecture documentation validation passed after the changes:

```bash
npm run check:architecture-docs
```
