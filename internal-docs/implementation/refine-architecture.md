# Refine Architecture Master Guide

Status: internal implementation master guide.
Owner: implementation/canon hardening workstream.
Primary canon target: `docs/architecture`.
Last reviewed against current canon: 2026-06-16.

## Purpose

This guide turns the recent architecture convergence into an implementation
pressure audit. It is not a marketing summary and not another doctrine layer.
It is the guide for finding places where the canon is correct in principle but
would become awkward, ambiguous, or over-abstracted when an engineer tries to
build the system.

The review posture is:

```text
Read the canon as if you must implement it tomorrow.
Stress it with edge cases.
Find where reality wants a cleaner abstraction.
Patch the canon only when the cleaner shape improves implementation.
```

## Current Spine

The architecture now mostly converges on this clean spine:

```text
Hypervisor Core and first-class clients
  Hypervisor Core is the shared product/runtime substrate whose execution owner
  is the Hypervisor Daemon. Hypervisor App, Hypervisor Web, and Hypervisor
  CLI/headless are first-class clients over Core; TUI is an optional
  presentation of the CLI/headless client, not a separate runtime lane.

Hypervisor application surfaces
  Workbench, Foundry, Fleet, Agents, Services, Models, cTEE/Privacy,
  Receipts/Audit, Connectors, Wallet presentations, aiagent.xyz, sas.xyz,
  console.ioi.ai, embedded approval cards, and marketplace consoles are
  surfaces over shared authority/runtime contracts.

Hypervisor adapters and harnesses
  VS Code, Cursor, Windsurf, JetBrains, browser IDEs, terminals, browsers, VMs,
  local OS surfaces, cloud resources, and HypervisorOS nodes are adapter
  targets. Codex, Claude Code, Grok Build, OpenHands, Aider, shell/tmux agents,
  CI agents, and hosted coding agents are Agent Harness Adapters: they may
  propose work through Hypervisor Core, but they are not Hypervisor clients or
  runtime truth.

Hypervisor Daemon
  Owns execution semantics, runtime-node profiles, effect boundaries,
  model/tool/worker/service execution, receipts, and replay hooks.

Default Harness Profile
  The daemon-executed loop-native orchestration profile, not a peer runtime.

Rust/WASM workload/kernel substrate
  Target authoritative step/module execution backend underneath the daemon.

wallet.network
  Owns authority, approvals, credentials, decryption, capability leases,
  payments, revocation, step-up, and user/action receipts.

Agentgres
  Owns admitted operational truth, object heads, state roots, artifact refs,
  archive refs, receipt linkage, replay/import metadata, restore validity,
  projections, delivery state, and local/domain settlement records.

Agent Wiki / ioi-memory
  Owns semantic memory and retrieval surfaces. It is not random Agentgres rows.

Agentgres Artifact Plane
  Owns payload meaning, lifecycle, authority linkage, receipt linkage, and
  restore/import validity.

Storage backends
  Hold bytes only: local disk, S3/object stores, Filecoin, CAS/IPFS, provider
  blobs, customer VPC blobs, and storage engines used as payload stores.

cTEE / Open Private Workspace
  Protects agency on untrusted compute by preventing protected state from
  entering provider-readable plaintext custody by default.

AIIP
  Moves bounded autonomous work across domains and systems.

aiagent.xyz
  Lists, installs, initializes, routes, and manages worker capabilities and
  managed worker instances.

sas.xyz
  Contracts, delivers, accepts, disputes, and settles service outcomes.

decentralized.exchange / decentralized.trade
  Candidate and venue intelligence services consumed by Wallet. They are not
  trust roots, execution owners, or authority layers.

Hypervisor direct provider integrations
  Route to local, customer cloud, hyperscaler, DePIN, confidential-compute,
  storage, GPU, and enterprise providers without requiring decentralized.cloud.

IOI L1
  Settles selected public, economic, dispute, rights, registry, reputation,
  cross-domain, and governance commitments by trigger only.
```

Short doctrine:

```text
Hypervisor Daemon executes.
wallet.network authorizes.
Agentgres admits truth.
Storage backends hold bytes.
Route engines propose.
Providers perform.
IOI L1 settles only what needs public trust.
```

## Executive Verdict

The canon is coherent enough to implement the core stack, but the next hardening
pass should focus on edge-case boundaries rather than adding more doctrine.

Top implementation-pressure discoveries:

| Rank | Cleaner shape revealed by pressure | Why it matters |
| --- | --- | --- |
| 1 | Hypervisor needs the Core/client/surface/adapter taxonomy everywhere. | Prevents the old "Hypervisor IDE" or "CLI/TUI" framing from collapsing product clients, app surfaces, external harnesses, and runtime truth into one bucket. |
| 2 | `WalletAuthorityCore` should become the reusable authority kernel; Wallet UI is one presentation. | Prevents all Web3/Web4 apps from inheriting a heavy finance console. |
| 3 | Broad autonomous labor needs first-class ontology and integration-surface canon, not only a plan doc. | aiagent still reads as "portable digital workers" while edge cases include games, Discord, finance, robotics, and embodied systems. |
| 4 | Physical/embodied action needs a canonical safety envelope owner. | `physical_action` appears as a risk class, but robotics-grade objects are still plan-level. |
| 5 | cTEE must expose lane selection for user privacy, model-weight privacy, and provider trust separately. | Harness/workspace privacy is not the same as protecting proprietary model weights. |
| 6 | Long-lived managed instances need lapse, archive, restore, and context-custody semantics. | Years-long agents and subscription lapses cannot rely on generic "persistent" wording. |

The target is not more surface area. The target is sharper object ownership:

```text
AuthorityReview, CapabilityLease, and ApprovalMode for all app authority.
ManagedWorkerInstanceLifecycle for persistent agents.
IntegrationSurfaceTaxonomy for vertical-specific constraints.
PhysicalActionSafetyEnvelope for embodied work.
ExecutionPrivacyPosture for every model/provider route.
```

## Edge-Case Stress Tests

| Edge case | Current canon fit | Coherence pressure | Cleaner architecture result |
| --- | --- | --- | --- |
| Game hires an agent for one hour with tiny repeated payments | Wallet session approvals and aiagent managed instances mostly fit. | Full Wallet console would be too heavy; per-action modals would fail UX. | Use `WalletAuthorityCore` with `lite_approval_card`, `session_envelope`, spend cap, receipt bundle, and platform-policy labels. |
| User rents a DePIN 3090 for private quant workspace | Private Workspace cTEE fits well. | Users may believe "encrypted workspace" means the node can run private source in plaintext. | Require `ExecutionPrivacyPosture` display: public trunk on node, private head via guardian/local/crypto/TEE, explicit unsafe mount warning. |
| Proprietary model must run remotely without leaking weights | Runtime nodes and cTEE distinguish workspace privacy from hardware privacy. | cTEE does not protect model weights once mounted to root-owned GPU. | Canonize three lanes: remote API capability, user/local weights, or TEE/customer-cloud weight mount. |
| Discord moderation agent needs scoped credentials and revocation | Wallet scopes and secret brokerage fit. | aiagent lacks vertical pack for platform policy, mass actions, bans, and audit. | Add integration-surface taxonomy plus `CapabilityLease` examples for moderation actions. |
| Persistent aiagent instance runs for years, then payment lapses | Runtime nodes mention zero-to-idle and persistent. | Lapse behavior is not yet implementation-grade. | Add `ManagedWorkerInstanceLifecycle` with active, suspended, archived, restored, expired, export, and delete states. |
| sas.xyz outcome uses nested workers, private data, disputes | sas delivery bundles and receipts fit. | Nested contribution, privacy posture, and delivery evidence need default bundle shape. | Add service composition evidence profile that binds worker contribution, private data posture, and dispute refs. |
| Humanoid/robot preps cars at a carwash | AIIP and common envelopes mention robot domains. | Physical safety objects are still in broad plan, not canonical owner docs. | Add `physical-action-safety.md` or equivalent under aiagent/foundations. |
| Wallet user approves a session envelope instead of per-action modals | Wallet authority UX model now fits. | Needs protocol package implementation, not only docs. | Implement `AuthorityReview`, `ApprovalMode`, and `CapabilityLease` in `@ioi/wallet-protocol` and SDK. |
| Operator uses Codex, Claude Code, Grok Build, or Aider inside a Hypervisor-managed workspace | Authority Gateway and Hypervisor adapter docs mostly fit. | External agent harnesses can be mistaken for first-class Hypervisor clients or trusted runtimes. | Treat them as `AgentHarnessAdapter` targets: proposal in, daemon gate, wallet authority, Agentgres receipt/replay out. |
| Operator wants a terminal UI for node ops | CLI/headless plus optional TUI fits. | Calling this "CLI/TUI" suggests the TUI is a separate client/runtime lane. | Keep `HypervisorCliHeadless` as the first-class client and `HypervisorTui` as optional presentation over the same daemon/domain APIs. |
| Prediction market trade proposed by an agent | decentralized.trade and Wallet Trade fit. | Live event exposure by agents needs eligibility, compliance, and market-category policy. | Add `PredictionAuthorityPolicy` as a profile over `PredictionIntent`. |
| Cloud route needs AWS/GCP/Akash/Filecoin/local choices | Fleet direct provider integrations fit. | "CloudRoute" can sound like one router, not a provider decision object. | Clarify `CloudCandidate` as provider evidence and `CloudRoute` as selected approved plan. |
| Storage backend loses payload bytes but Agentgres has refs | Artifact-ref plane fits. | Need repair playbook in operational docs. | Add `ArtifactAvailabilityIncident` and repair receipts in Agentgres artifact doc. |
| Route engine returns stale quote or stale risk label | Wallet risk coverage states fit. | Candidate services must return evidence and expiry, not only "best route." | Add conformance: stale/unknown labels block silent execution. |
| SMS access point requests escalation | Wallet access-point binding fits. | Product copy may imply SMS auth. | Keep canon explicit: SMS can carry challenge pointer only. |
| Model API provider receives sensitive data | ProviderTrustBoundary fits. | Product/harness should classify this as `redacted_api`, `provider_trust`, or `unsafe`. | Require `ExecutionPrivacyPosture` disclosure on model-route selection. |
| cTEE node infers private strategy via timing or candidate leakage | cTEE leakage docs fit. | Leakage quantification must be attached to schedules and receipts. | Add `LeakageBudget` / `CandidateCoverageProfile` conformance to Private Workspace. |

## Coherence Findings

### 1. aiagent broad labor plan is not yet live canon

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `docs/architecture/domains/aiagent/worker-marketplace.md`, `docs/architecture/domains/aiagent/broad-autonomous-labor-canon-plan.md` |
| Edge case | Discord moderation, game server finding, robotics carwash prep, embodied field-service agents. |
| Issue | The marketplace doc still centers "portable digital workers" while a plan file describes a broader ontology for digital and embodied workers. |
| Why it matters | Implementers may build a worker storefront instead of an autonomous labor substrate that supports millions of vertical profiles. |
| Recommended change | Promote broad labor plan into canonical aiagent docs: Digital Worker Ontology, Vertical Ontology Packs, Integration Surface Taxonomy, Managed Worker Lifecycle, Managed Agent Console Contract. |
| Fix type | Docs now; schema/API implementation next. |

### 1A. Hypervisor client/surface/adapter taxonomy must stay implementation-visible

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `docs/architecture/components/hypervisor/core-clients-surfaces.md`, daemon runtime doctrine, source-of-truth map, vocabulary. |
| Edge case | A team builds Hypervisor as a VS Code product, treats TUI as a runtime lane, or lets Codex/Claude Code/Grok Build bypass daemon receipts. |
| Issue | The canon now has the cleaner taxonomy, but implementation plans can drift back to old "IDE" or "CLI/TUI" shorthand. |
| Why it matters | The product becomes brittle if clients, application surfaces, adapter targets, and external agent harnesses each invent their own runtime truth. |
| Recommended change | Keep `HypervisorCore`, `HypervisorClient`, `HypervisorApplicationSurface`, `HypervisorAdapterTarget`, and `AgentHarnessAdapter` in source maps, vocabulary, implementation matrix, app APIs, and future conformance checks. |
| Fix type | Docs already patched; API/schema/conformance still needed. |

### 2. Physical-action safety lacks a canonical owner

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `common-objects-and-envelopes.md`, `aiip.md`, `default-harness-profile.md`, broad aiagent plan. |
| Edge case | Humanoid or robot performs vehicle-adjacent work near humans. |
| Issue | `physical_action` exists as a risk class, but the safety envelope objects are not in canonical owner docs. |
| Why it matters | Physical action cannot be treated as just another connector call. It needs supervision, emergency stop, sensor evidence, actuator receipts, liability, and incident handling. |
| Recommended change | Add `physical-action-safety.md` under `foundations/` or `domains/aiagent/`, then wire source map and vocabulary. |
| Fix type | Docs plus conformance and runtime gate implementation. |

### 3. Managed worker instance lapse semantics are under-specified

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `aiagent/worker-marketplace.md`, `aiagent/worker-endpoints.md`, `runtime-nodes-tee-depin.md`, Agentgres artifact refs. |
| Edge case | User rents an agent for years, stops paying, then wants context restored. |
| Issue | Persistent/zero-to-idle profiles exist, but lapse/archive/export/delete/restore semantics are not yet explicit enough. |
| Why it matters | User trust and marketplace economics depend on context custody, retention, and restore behavior. |
| Recommended change | Add `managed-worker-instance-lifecycle.md` with lifecycle states, payment lapse policy, archive refs, restore authority, export rights, and deletion policy. |
| Fix type | Docs plus Agentgres/wallet/aiagent API implementation. |

### 4. cTEE protects workspace state, not model weights by default

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `private-workspace-ctee.md`, `runtime-nodes-tee-depin.md`, `model-router/doctrine.md`. |
| Edge case | User mounts proprietary model weights on a rented 3090. |
| Issue | Current docs have the right non-claims, but implementation-facing routing should expose the distinction between harness privacy and weight privacy. |
| Why it matters | Users will confuse "my strategy is protected" with "my weights are protected." |
| Recommended change | Add a model-weight custody table: open/local weights, remote API capability, provider-trust weight mount, TEE/customer-cloud mount, forbidden mount. |
| Fix type | Docs plus model-mount admission policy implementation. |

### 5. Wallet protocol packaging is now planned but not implemented

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `wallet-network/doctrine.md`, `api-authority-scopes.md`, `_meta/wallet-protocol-sdk-packaging-plan.md`. |
| Edge case | Embedded dapp approval card needs `AuthorityReview` and `ApprovalMode`. |
| Issue | Rust wallet types and service are current truth, but `@ioi/wallet-protocol`, OpenAPI/JSON Schema, and `@ioi/wallet-sdk` do not exist yet. |
| Why it matters | Product repos may keep inventing local authority objects until the package boundary exists. |
| Recommended change | Execute wallet packaging plan before major Wallet UI work. |
| Fix type | Implementation plus conformance. |

### 6. Route engines are correctly bounded but need candidate-evidence conformance

| Field | Detail |
| --- | --- |
| Severity | Medium |
| Current canon | `decentralized/exchange.md`, `decentralized/trade.md`, Wallet product risk docs. |
| Edge case | Route engine returns stale quote or unknown-risk venue. |
| Issue | Doctrine says route engines propose; conformance needs to prove candidates include source, timestamp, expiry, evidence refs, and risk coverage state. |
| Why it matters | Without evidence shape, the candidate service can become a hidden trust root. |
| Recommended change | Add route/trade candidate conformance profiles and schema rows. |
| Fix type | Docs plus route/trade API validation. |

### 7. Fleet/provider selection is cleaner without present decentralized.cloud

| Field | Detail |
| --- | --- |
| Severity | Medium |
| Current canon | `hypervisor/fleet.md`, `decentralized/cloud-parked-future.md`. |
| Edge case | User chooses their own GCP account or Akash node directly. |
| Issue | Current wording is mostly fixed, but `CloudRoute` naming may still feel like a router product rather than an approved placement decision. |
| Why it matters | Hypervisor must not imply a mandatory cloud marketplace gateway. |
| Recommended change | Clarify `CloudRoute` as `ProviderPlacementDecision` alias or add vocabulary note that direct provider mode is first-class. |
| Fix type | Docs only initially. |

### 8. Agent Wiki / ioi-memory boundary needs object/API consequences

| Field | Detail |
| --- | --- |
| Severity | Medium |
| Current canon | Agentgres doctrine, source-of-truth map, memory references. |
| Edge case | Long-lived agent context is restored after archive or marketplace migration. |
| Issue | The ownership distinction exists, but the implementer still needs the object/API boundary between semantic memory, Agentgres operation truth, and encrypted artifact refs. |
| Why it matters | Without this, memory becomes either random rows or magical context. |
| Recommended change | Add implementation object table for memory admission, memory refs, retrieval receipts, and restore projections. |
| Fix type | Docs plus memory/Agentgres API implementation. |

### 9. Service composition needs nested contribution defaults

| Field | Detail |
| --- | --- |
| Severity | Medium |
| Current canon | `sas/service-marketplace.md`, `marketplace-neutrality.md`, receipts docs. |
| Edge case | sas outcome uses multiple aiagent workers and disputes quality. |
| Issue | Service delivery bundle shape exists, but nested worker contribution and dispute evidence should be standard by default. |
| Why it matters | Outcome settlement and reputation need attribution that is better than token usage or platform preference. |
| Recommended change | Add service composition receipt bundle profile with worker contribution refs, route decisions, verifier receipts, and dispute evidence. |
| Fix type | Docs plus receipt implementation. |

### 10. Wallet authority UX is strong but should be treated as protocol, not UI

| Field | Detail |
| --- | --- |
| Severity | Medium |
| Current canon | `wallet-network/product-exchange-risk.md`, `api-authority-scopes.md`, vocabulary. |
| Edge case | Web3 game embeds a single approval card. |
| Issue | The new docs are clear, but implementation must avoid making presentation profiles actual authority. |
| Why it matters | UI shells must not change policy or receipt semantics. |
| Recommended change | Conformance check: presentation profile cannot alter `AuthorityReview.policy_result`, allowed approval modes, or receipt obligations. |
| Fix type | Implementation/conformance. |

### 11. Private user/app state shape is good but needs app-level examples

| Field | Detail |
| --- | --- |
| Severity | Low |
| Current canon | Agentgres artifact-ref plane, ioi.ai control plane, wallet docs. |
| Edge case | App stores user profile metadata off chain in encrypted blobs and decrypts on login. |
| Issue | The doctrine is correct, but examples should map app state, wallet authority, Agentgres refs, and storage bytes. |
| Why it matters | App implementers may put profile state on L1 or in plaintext app DBs. |
| Recommended change | Add one `PrivateUserAppStateRef` walkthrough. |
| Fix type | Docs only initially. |

### 12. L1 trigger boundary is strong but should be repeated in marketplace docs

| Field | Detail |
| --- | --- |
| Severity | Low |
| Current canon | `ioi-l1-mainnet.md`, aiagent/sas docs. |
| Edge case | Every agent action is treated as on-chain. |
| Issue | L1 docs are clear, but product docs can over-index on settlement. |
| Why it matters | Cost and UX die if everything becomes a chain event. |
| Recommended change | Add concise trigger table to aiagent/sas docs: local receipt, Agentgres domain record, L1 commitment. |
| Fix type | Docs only. |

## Cleaner Architecture Opportunities

| Opportunity | Replace this | With this |
| --- | --- | --- |
| Hypervisor product taxonomy | "Hypervisor IDE", "Electron/VS Code fork", or "CLI/TUI" as parent product | Hypervisor Core with App/Web/CLI-headless clients, optional TUI presentation, Workbench/Foundry/Fleet surfaces, adapter targets, and Agent Harness Adapters. |
| Authority UX | "Wallet app UI handles approvals" | `WalletAuthorityCore` plus presentation profiles. |
| Cloud/provider routing | "Cloud lane" or future `decentralized.cloud` as present product | Direct Hypervisor provider integrations plus optional future catalog. |
| Marketplace verticals | Hardcoded agent categories | Digital Worker Ontology plus Vertical Ontology Packs. |
| Physical work | `physical_action` as a loose risk class | Physical Action Safety Envelope with supervision, e-stop, evidence, incident hooks. |
| cTEE promises | "Private compute on rented GPU" | No-plaintext-custody by default, explicit privacy posture, private head/guardian/crypto/TEE lane selection. |
| Model routes | Model provider as actor | Worker/service actor owns responsibility; model is a cognition backend with receipts. |
| Route engines | Exchange/trade as execution backends | Candidate/evidence services consumed by Wallet authority. |
| Storage | Blob URL or CID as truth | Agentgres ArtifactRef plus backend bytes. |
| Persistent agents | Warm process as state | Managed instance lifecycle plus archive/restore refs. |
| Service delivery | Output file as delivery | DeliveryBundle plus EvidenceBundle plus typed receipts plus dispute hooks. |

## Source-of-Truth Corrections

| Concept | Current state | Needed owner |
| --- | --- | --- |
| Hypervisor client/surface/adapter taxonomy | Canon docs patched, implementation plans must stay aligned | `docs/architecture/components/hypervisor/core-clients-surfaces.md` |
| Digital Worker Ontology | Plan doc only | `docs/architecture/domains/aiagent/digital-worker-ontology.md` |
| Vertical Ontology Packs | Plan doc only | `docs/architecture/domains/aiagent/vertical-ontology-packs.md` |
| Managed Worker Instance lifecycle | Partly in worker marketplace/endpoints | `docs/architecture/domains/aiagent/managed-worker-instance-lifecycle.md` |
| Integration Surface Taxonomy | Plan doc only | `docs/architecture/domains/aiagent/integration-surface-taxonomy.md` |
| Physical Action Safety | Scattered risk terms and plan text | `docs/architecture/foundations/physical-action-safety.md` or aiagent domain doc |
| Managed Agent Console Contract | Partly in aiagent endpoints | `docs/architecture/domains/aiagent/managed-agent-console-contract.md` |
| Model weight custody | cTEE/model-router concepts but no direct table | `docs/architecture/components/model-router/doctrine.md` plus cTEE doc |
| Artifact availability incidents | Implied in artifact/storage docs | `docs/architecture/components/agentgres/artifact-ref-plane.md` |
| Service composition contribution bundle | Implied in sas and receipts docs | `docs/architecture/domains/sas/service-marketplace.md` plus receipts doc |

## Vocabulary Corrections

Add or tighten:

```text
DigitalWorkerOntology
HypervisorCore
HypervisorClient
HypervisorCliHeadless
HypervisorTui
HypervisorApplicationSurface
HypervisorWorkbench
HypervisorSession
HypervisorAdapterTarget
AgentHarnessAdapter
VerticalOntologyPack
IntegrationSurface
ManagedWorkerInstanceLifecycle
InstanceLapsePolicy
InstanceArchivePolicy
InstanceRestorePolicy
PhysicalActionPolicy
SafetyEnvelope
EmergencyStopAuthority
HumanSupervisionPolicy
SensorEvidenceReceipt
ActuatorCommandReceipt
IncidentReceipt
ProviderPlacementDecision
ModelWeightCustodyProfile
ArtifactAvailabilityIncident
CandidateEvidence
ServiceCompositionReceiptBundle
```

Potentially clarify:

```text
CloudRoute
  Clarify as a selected provider placement plan, not a mandatory cloud router.

PrivateWorkspaceNode
  Keep as rented/hosted node profile, not proof of model-weight secrecy.

WalletPresentationProfile
  UI profile only; not authority.

RouteCandidate / TradeCandidate
  Candidate plus evidence, never approval.
```

## Implementation Applicability

Can a new engineer build from the canon today?

```text
Core runtime/authority/state/storage stack: yes, with repo inspection.
Wallet UX/authority packaging: conceptually yes, package implementation missing.
Private Workspace cTEE: yes for architecture, partial for full conformance.
Fleet/provider integrations: yes for boundary, provider adapters still needed.
aiagent broad labor: not yet; plan exists, canon needs promotion.
sas nested outcomes: partially; delivery bundle exists, contribution defaults need work.
Physical/embodied systems: not yet; risk class exists, safety owner missing.
```

Blocking object/API/schema gaps:

```text
@ioi/wallet-protocol and @ioi/wallet-sdk
AuthorityReview schema
CapabilityLease schema
ApprovalMode conformance
ManagedWorkerInstance lifecycle API
VerticalOntologyPack manifest/schema
IntegrationSurface taxonomy schema
PhysicalActionPolicy and SafetyEnvelope schema
ExecutionPrivacyPosture admission enforcement
ModelWeightCustodyProfile
CandidateEvidence schema for exchange/trade
ArtifactAvailabilityIncident receipt
ServiceCompositionReceiptBundle
```

Docs that are too doctrinal and need implementation objects:

```text
Hypervisor Core client/surface/adapter taxonomy
aiagent broad labor plan
physical/embodied work references
Agent Wiki / ioi-memory boundary
service composition and contribution defaulting
model-weight custody lane selection
```

Docs that risk becoming too implementation-specific:

```text
Wallet product surface doctrine
  Keep UI modules as presentation profiles over authority contracts.

Fleet provider details
  Keep provider examples as integrations, not mandatory provider stack.

cTEE candidate-lattice math
  Keep as privacy/performance strategy, not universal private inference claim.
```

## Anti-Patterns to Add

| Doc | Anti-pattern |
| --- | --- |
| Hypervisor core/client/surface docs | Treating Hypervisor Workbench or a VS Code shell as the parent product/runtime. |
| Hypervisor core/client/surface docs | Treating TUI as a first-class runtime lane instead of optional CLI/headless presentation. |
| Hypervisor core/client/surface docs | Treating Codex, Claude Code, Grok Build, OpenHands, Aider, shell/tmux agents, CI agents, or hosted coding agents as Hypervisor clients or runtime truth. |
| aiagent worker marketplace | Treating categories as hardcoded verticals instead of ontology-pack indexed profiles. |
| aiagent worker marketplace | Treating managed instance web console as runtime truth. |
| aiagent worker marketplace | Letting payment lapse silently delete user context without archive/export policy. |
| aiagent worker marketplace | Treating game bots, platform automation, or robotics as generic workers without platform/safety policy. |
| physical-action safety doc | Treating actuator commands as ordinary tool calls. |
| cTEE/private workspace | Claiming rented 3090 protects proprietary model weights without TEE/customer/local custody. |
| model router | Treating external API privacy policies as cTEE no-plaintext-custody. |
| decentralized exchange/trade | Treating candidate service output as approval or truth. |
| Wallet docs | Letting presentation profile alter policy result or receipt obligations. |
| Agentgres artifact plane | Restoring from bytes without Agentgres restore/import receipt. |
| sas service docs | Settling service outcomes without evidence bundle and contribution receipts. |

## Proposed Patch Plan

### Phase 0: Keep Hypervisor Core Taxonomy Implementation-Visible

| Field | Detail |
| --- | --- |
| Files | `docs/architecture/components/hypervisor/core-clients-surfaces.md`, daemon API/docs, source map, vocabulary, implementation matrix, future app/API contracts |
| Change | Ensure product APIs, schemas, and implementation plans preserve the distinction between Core, clients, application surfaces, adapter targets, and Agent Harness Adapters. |
| Acceptance | No live implementation guide treats Hypervisor Workbench/IDE, VS Code shells, TUI, or external CLI agents as runtime truth. |
| Verify | Run `rg -n "Hypervisor IDE|CLI/TUI|Electron/VS Code fork|Codex.*runtime truth|TUI = separate" docs/architecture internal-docs/implementation`; remaining hits must be deprecated, historical, or anti-pattern examples only. |

### Phase 1: Promote Broad Autonomous Labor Canon

| Field | Detail |
| --- | --- |
| Files | `aiagent/worker-marketplace.md`, new aiagent ontology/lifecycle docs, `_meta/source-of-truth-map.md`, `_meta/implementation-matrix.md`, `_meta/vocabulary.md`, `README.md`, `_meta/start-here.md` |
| Change | Move broad autonomous labor plan into canonical docs. |
| Acceptance | aiagent definition covers ontology-bound digital and embodied workers; digital-only phrasing is removed or qualified. |
| Verify | `git diff --check -- docs/architecture` and `rg -n "portable digital workers|DigitalWorkerOntology|VerticalOntologyPack" docs/architecture/domains/aiagent docs/architecture/_meta` |

### Phase 2: Add Physical Action Safety Owner

| Field | Detail |
| --- | --- |
| Files | new `foundations/physical-action-safety.md` or `domains/aiagent/physical-action-safety.md`, common objects, DHP, wallet scopes, source map, vocabulary |
| Change | Canonize safety envelopes, supervision, emergency stop, sensor/actuator receipts, incident/dispute hooks. |
| Acceptance | Physical and embodied workers have explicit safety semantics and cannot execute actuator commands as generic tool calls. |
| Verify | `rg -n "PhysicalActionPolicy|SafetyEnvelope|ActuatorCommandReceipt|EmergencyStopAuthority" docs/architecture` |

### Phase 3: Execute Wallet Protocol Packaging Plan

| Field | Detail |
| --- | --- |
| Files | `packages/wallet-protocol`, `packages/wallet-sdk`, `crates/types/src/app/wallet_network`, scripts, conformance |
| Change | Generate protocol package from Rust wallet truth; provide SDK over it. |
| Acceptance | Packages build/test; schemas and fixtures exist; product repo imports packages. |
| Verify | `npm run test:wallet-protocol && npm run test:wallet-sdk && npm run check:wallet-protocol` |

### Phase 4: Add cTEE and Model-Weight Custody Lane Table

| Field | Detail |
| --- | --- |
| Files | `private-workspace-ctee.md`, `runtime-nodes-tee-depin.md`, `model-router/doctrine.md`, model-mount API docs |
| Change | Distinguish workspace privacy, model-input privacy, model-output privacy, and model-weight custody. |
| Acceptance | A rented 3090 path cannot be presented as safe for proprietary weights unless TEE/customer/local custody applies. |
| Verify | `rg -n "ModelWeightCustodyProfile|proprietary model weights|provider_trust|tee_session" docs/architecture/components` |

### Phase 5: Harden Managed Instance Lifecycle

| Field | Detail |
| --- | --- |
| Files | new `aiagent/managed-worker-instance-lifecycle.md`, worker endpoints, Agentgres artifact refs, wallet APIs |
| Change | Define install, initialize, active, idle, zero-to-idle, suspended, lapsed, archived, restored, exported, deleted. |
| Acceptance | Payment lapse and restore/export/delete behavior are explicit. |
| Verify | `rg -n "lapse|archive_policy|restore_policy|ManagedWorkerInstanceLifecycle" docs/architecture/domains/aiagent docs/architecture/_meta` |

### Phase 6: Add Candidate Evidence Conformance

| Field | Detail |
| --- | --- |
| Files | decentralized exchange/trade docs, Wallet product risk, API scopes, conformance docs |
| Change | Require source, adapter, timestamp, expiry, evidence refs, coverage state, failure conditions for route/trade candidates. |
| Acceptance | Candidate services cannot be hidden trust roots. |
| Verify | `rg -n "CandidateEvidence|coverage_state|expiry|adapter_id" docs/architecture/domains/decentralized docs/architecture/components/wallet-network` |

### Phase 7: Harden Service Composition Delivery

| Field | Detail |
| --- | --- |
| Files | sas marketplace/endpoints, daemon receipts, marketplace neutrality |
| Change | Add nested contribution and dispute evidence defaults for service outcomes. |
| Acceptance | Delivery bundle includes worker contribution refs, verifier refs, private-data posture, and dispute evidence. |
| Verify | `rg -n "ServiceCompositionReceiptBundle|ContributionReceipt|delivery bundle|dispute evidence" docs/architecture/domains/sas docs/architecture/components/daemon-runtime` |

### Phase 8: Add Artifact Availability Incident Flow

| Field | Detail |
| --- | --- |
| Files | Agentgres artifact-ref plane, storage backend doctrine, receipts docs |
| Change | Define incident when payload bytes are missing, corrupt, stale, or unavailable. |
| Acceptance | Agentgres lifecycle and repair receipts govern backend failure. |
| Verify | `rg -n "ArtifactAvailabilityIncident|missing|invalid|repair receipt" docs/architecture/components/agentgres docs/architecture/components/storage-backends` |

### Phase 9: Update Start Here and Readability Entry Points

| Field | Detail |
| --- | --- |
| Files | `_meta/start-here.md`, `START_HERE.md`, `README.md` |
| Change | Show refined stack and route readers by edge case: Wallet authority, private compute, marketplace worker, service outcome, physical action, provider integration. |
| Acceptance | New implementer can find the owner doc for each refined concept in five minutes. |
| Verify | `npm run check:architecture-docs` |

## Final Doctrine Delta

The architecture becomes cleaner if we say:

```text
Wallet is not the universal UI; it is the authority core plus presentations.
Hypervisor is not an IDE shell; it is Core plus first-class clients,
application surfaces, sessions, adapter targets, and mediated agent harnesses.
aiagent is not a fixed worker catalog; it is an ontology-bound labor substrate.
Physical action is not a tool call; it is a safety-envelope-bound effect.
cTEE does not make rented GPUs trusted; it keeps protected plaintext out of
their custody by default.
Provider routing is not a product gateway; it is a direct, approved placement
decision.
Route engines are not exchanges or brokers; they are candidate/evidence
services.
Agentgres does not store all bytes; it owns what bytes mean.
IOI L1 does not run work; it settles selected public/economic commitments.
```

## Completion Checklist for This Guide

This guide is complete when it contains:

- an executive verdict;
- at least ten edge-case stress tests;
- at least ten coherence findings;
- at least five simplification opportunities;
- source-of-truth corrections;
- vocabulary corrections;
- implementation applicability analysis;
- anti-pattern additions;
- an executable patch plan;
- final doctrine delta.

Verification for this guide:

```text
git diff --check -- internal-docs/implementation/refine-architecture.md
rg -n "Executive Verdict|Edge-Case Stress Tests|Coherence Findings|Proposed Patch Plan|Final Doctrine Delta" internal-docs/implementation/refine-architecture.md
```
