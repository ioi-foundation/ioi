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

Harness Profiles and Default Harness Profile
  HarnessProfiles are daemon-executed or daemon-mediated step-resolution
  adapters. The Default Harness Profile is IOI's reference scaffold/fallback
  HarnessProfile, not a peer runtime, not the only admissible harness, and not a
  meta-harness.

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
| 2 | Hypervisor App should become the reference operator cockpit, not a VS Code/IDE shell. | The current UX opens into code-repository/OpenVSCode gravity; the target is one Core with sessions, projects, surfaces, adapters, model mounts, authority, privacy, and receipts. |
| 3 | `WalletAuthorityCore` should become the reusable authority kernel; Wallet UI is one presentation. | Prevents all Web3/Web4 apps from inheriting a heavy finance console. |
| 4 | Broad autonomous labor needs first-class ontology and integration-surface canon, not only a plan doc. | aiagent still reads as "portable digital workers" while edge cases include games, Discord, finance, robotics, and embodied systems. |
| 5 | Physical/embodied action needs a canonical safety envelope owner. | `physical_action` appears as a risk class, but robotics-grade objects are still plan-level. |
| 6 | cTEE must expose lane selection for user privacy, model-weight privacy, and provider trust separately. | Harness/workspace privacy is not the same as protecting proprietary model weights. |
| 7 | Long-lived managed instances need lapse, archive, restore, and context-custody semantics. | Years-long agents and subscription lapses cannot rely on generic "persistent" wording. |

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

### 8A. Hypervisor App UX needs a master implementation plan

| Field | Detail |
| --- | --- |
| Severity | High |
| Current UX evidence | Screenshot shows the product inside OpenVSCode with tabs such as "Autopilot Workflow Composer", "Autopilot Models", "Autopilot Runs", "Autopilot Policy", "Autopilot Connectors", and "Autopilot Code"; the active surface is a code repository gate. |
| Reference evidence | `internal-docs/reverse-engineering/ioi` is the primary target UX reference: persistent left nav, New Session, Home, Projects, Automations, Insights, Sessions, session-detail tabs, environment status, changes panel, ports/services/tasks/terminal inspector, settings, default editor selection, secrets, git auth, tokens, integrations, and session history. Local screenshots and static mirror assets exist in that directory; mirrored labels must be translated into Hypervisor language rather than copied literally. |
| Issue | The current product reads like an IDE extension host with Autopilot tabs. The canon now says Hypervisor App/Web/CLI-headless are clients over Hypervisor Core, Workbench/Foundry/Fleet are application surfaces, editors are adapter targets, and external coding agents are Agent Harness Adapters. |
| Why it matters | If the UX stays IDE-first, the architecture will keep drifting back toward "Hypervisor IDE" instead of "Hypervisor of IDEs / governed autonomous-work cockpit." |
| Recommended change | Add a staged implementation plan that converts the app shell from Autopilot/OpenVSCode gravity into a Hypervisor Core cockpit with sessions, projects, application surfaces, adapter targets, model/harness/provider setup, cTEE/privacy posture, authority, and receipts. |
| Fix type | Internal implementation plan now; UI/code migration next. |

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
| Hypervisor App UX shell | Current app code exists but still carries Autopilot/OpenVSCode gravity | `internal-docs/implementation/refine-architecture.md` for implementation plan, then `apps/autopilot/src/windows/AutopilotShellWindow/*` or renamed Hypervisor shell modules for implementation |
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
HypervisorSurfaceId
HypervisorSessionCard
HypervisorSessionLaunchRecipe
HypervisorShellNavigationModel
HypervisorAdapterTarget
AgentHarnessAdapter
WorkbenchAdapterPreference
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
Hypervisor App UX: conceptually yes; shell IA and product naming migration needed.
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
HypervisorShellNavigationModel
HypervisorSessionCard
HypervisorSessionLaunchRecipe
WorkbenchAdapterPreference
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
Hypervisor App shell IA and session launcher
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
| Hypervisor app implementation | Treating current Autopilot/OpenVSCode tabs as the target product IA. |
| Hypervisor app implementation | Treating model mounting as the primary user job instead of global infrastructure plus contextual session setup. |
| Hypervisor app implementation | Creating one separate GUI app per surface instead of one Core with App/Web/CLI-headless clients and application surfaces. |
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

### Phase 0A: Hypervisor App UX Master Plan

Status: implementation leg for moving the current Autopilot/OpenVSCode-shaped
UX into the Hypervisor Core product architecture.

Reference inputs:

```text
Current screenshot:
  OpenVSCode parent chrome
  Autopilot Workflow Composer / Models / Runs / Policy / Connectors / Code tabs
  active Code repositories surface

Primary IOI reference mirror:
  internal-docs/reverse-engineering/ioi
  local static server: internal-docs/reverse-engineering/ioi/server.js
  observed from local screenshots and mirror assets:
    Home: New Session, Home, Projects, Automations, Insights, Sessions,
          prompt composer, project selector, model control, recent sessions
    Session detail: Code / Agent / Environment tabs, run transcript/todos,
          environment status, remote VM lifecycle, initialized repository,
          loaded secrets, loaded automations, dev container status
    Right inspector: Changes, changed-file tree, review controls
    Bottom inspector: Ports & Services, Tasks, Terminal
    Automations: metrics, filters, run actions, suggested templates
    Settings: account, default editor, embedded VS Code toggle, secrets,
          git authentications, personal access tokens, integrations
  note: the mirror contains sanitized reference labels; translate them into
        Hypervisor product language instead of copying names literally.

Current code anchors:
  apps/autopilot/src/main.tsx
  apps/autopilot/src/windows/AutopilotShellWindow/*
  apps/autopilot/src/surfaces/Home/*
  apps/autopilot/src/surfaces/Workspace/*
  apps/autopilot/src/surfaces/MissionControl/*
  apps/autopilot/src/surfaces/Policy/*
  apps/autopilot/src/surfaces/Settings/*
  apps/autopilot/src/surfaces/Capabilities/*
  packages/hypervisor-workbench/src/features/*
  packages/runtime-daemon/src/http/public-runtime-routes.mjs
  packages/runtime-daemon/src/step-module-abi.test.mjs
```

Design thesis:

```text
Hypervisor App is not an IDE.
Hypervisor App is the native operator cockpit over Hypervisor Core.

The IOI reference shell is the primary UX target:
  left navigation
  New Session
  active session list
  session detail tabs
  changes inspector
  ports/services/tasks/terminal inspector
  settings modal for account, editor, secrets, git auth, tokens, integrations

Workbench is the code/systems surface inside Hypervisor.
Editors are adapter targets inside Workbench.
Workflow Compositor lives primarily inside Automations and Missions.
Model mounting is global infrastructure plus contextual setup.
Agents are configured runtime actors with skills, harness adapter choices,
authority leases, model routes, and memory/workspace bindings.
Foundry is training/eval/worker-improvement.
Fleet is infrastructure/provider/workspace estate.
Authority, Privacy, and Receipts are always-visible governance rails.
```

Target information architecture:

| Surface | User job | Runtime/canon owner |
| --- | --- | --- |
| Home | Start work, inspect active sessions, continue recents | Hypervisor Core session projection |
| Sessions | Every live, idle, archived, blocked, or restorable run | Hypervisor Session + Agentgres receipts |
| Projects | Workspace/project roots, private state, repos, environments | Hypervisor Project + Agentgres refs |
| Missions | Goal-driven autonomous runs with acceptance criteria | Workflow Compositor + selected HarnessProfile |
| Workbench | Code/systems workspace with editor/terminal/browser adapters | Hypervisor Workbench + Adapter Targets |
| Automations / Workflows | Repeatable workflow templates, scheduled runs, and compositor graphs | Workflow Compositor |
| Insights | Runtime metrics, run analytics, quality trends, cost/latency, failure patterns | Agentgres projections + trace/receipt projections |
| Agents | Configured workers, harness adapters, skills, leases | aiagent + wallet.network authority |
| Models | Model inventory, providers, endpoints, mounts, downloads | Model mounting daemon APIs |
| Privacy / cTEE | Workspace privacy posture, cTEE lanes, unsafe mount warnings | Private Workspace / cTEE |
| Authority | Approvals, capability leases, connector scopes, spend gates | wallet.network |
| Receipts / Audit | Receipts, replay, artifacts, state roots, restore | Agentgres + receipts |
| Foundry | Eval, distillation, training, benchmark, package promotion | Hypervisor Foundry |
| Fleet | Local/cloud/DePIN/customer provider estate and persistent nodes | Hypervisor Fleet |
| Settings | Identity, editor preference, secrets, git auth, tokens, integrations, policy defaults | Hypervisor client settings + wallet.network |

Core UX decisions:

```text
1. Default screen becomes Hypervisor Home, not embedded OpenVSCode.
2. "New Session" is the primary CTA.
3. "Create Agent" and "Create Mission" are guided setup flows, not raw tabs.
4. Model mounting appears in two places:
   - global Models surface for inventory, providers, endpoints, downloads;
   - contextual step inside New Session / Create Agent / Mission setup.
5. Workbench owns editor choice:
   VS Code, Cursor, Windsurf, JetBrains, browser IDE, terminal/tmux,
   OpenVSCode direct surface, or substrate editor.
6. Embedded VS Code is optional, not the product identity.
7. IOI-reference "Automations" maps to Hypervisor Workflow Compositor:
   templates, repeatable graphs, scheduled runs, and reusable run recipes,
   not a separate runtime.
8. Every session row shows model, harness, authority, privacy posture, receipts,
   project, environment, cost/budget, and restore state.
9. Right-side inspectors should be contextual:
   selected session -> changes/receipts/privacy/authority/replay
   selected model -> provider/custody/runtime health
   selected workflow -> gates/receipts/versions
10. Bottom inspectors should follow the IOI reference:
    ports/services, tasks, terminal, logs, environment health.
11. Settings owns configuration:
    account, editor preference, secrets, git auth, tokens, integrations,
    policy defaults. Authority owns live approvals, grants, leases,
    revocation, and high-risk review.
12. App/Web/CLI-headless share the same surface contracts.
```

Target shell layout:

```text
Hypervisor App
  left rail
    New Session
    Home
    Projects
    Sessions
    Missions
    Workbench
    Automations / Workflows
    Insights
    Agents
    Models
    Privacy
    Fleet
    Foundry
    Authority
    Receipts
    Settings

  secondary session/project rail
    active sessions
    recent projects
    pinned workspaces
    blocked approvals

  main canvas
    selected application surface

  right inspector
    changes, authority, privacy, receipts, model/harness/provider, artifact refs

  bottom inspector
    ports & services, tasks, terminal, logs, environment health
```

New / refined implementation objects:

```ts
type HypervisorSurfaceId =
  | "home"
  | "sessions"
  | "projects"
  | "missions"
  | "workbench"
  | "automations"
  | "insights"
  | "agents"
  | "models"
  | "privacy"
  | "fleet"
  | "foundry"
  | "authority"
  | "receipts"
  | "settings";

type HypervisorSessionDetailTab =
  | "agent"
  | "workbench"
  | "environment"
  | "changes"
  | "receipts"
  | "replay";

type HypervisorInspectorPanelId =
  | "changes"
  | "ports_services"
  | "tasks"
  | "terminal"
  | "logs"
  | "authority"
  | "privacy"
  | "receipts"
  | "model_harness_provider";

interface HypervisorSessionCard {
  session_id: string;
  title: string;
  project_ref: string;
  surface_hint: HypervisorSurfaceId;
  status: "draft" | "running" | "blocked" | "review" | "idle" | "archived";
  selected_harness_profile_ref?: string;
  selected_model_mount_ref?: string;
  authority_summary_ref?: string;
  privacy_posture_ref?: string;
  latest_receipt_refs: string[];
  restore_state?: "hot" | "warm" | "zero_to_idle" | "archived" | "unavailable";
}

interface HypervisorSessionLaunchRecipe {
  recipe_id: string;
  label: string;
  kind:
    | "mission"
    | "workbench"
    | "agent"
    | "automation"
    | "foundry_job"
    | "fleet_job"
    | "privacy_workspace";
  required_inputs: string[];
  model_mount_policy: "inherit" | "select" | "required" | "forbidden";
  harness_profile_policy: "default" | "select" | "external_adapter";
  authority_scope_templates: string[];
  privacy_posture_templates: string[];
}

interface WorkbenchAdapterPreference {
  adapter_id:
    | "vscode"
    | "cursor"
    | "windsurf"
    | "jetbrains"
    | "browser_ide"
    | "openvscode_embedded"
    | "terminal_tmux"
    | "workspace_substrate";
  launch_mode: "embedded" | "external" | "remote_url" | "headless";
  default_for_project?: boolean;
}
```

Implementation phases:

| Phase | Objective | Main files | Acceptance |
| --- | --- | --- | --- |
| 0A.1 Product-shell rename and route map | Introduce Hypervisor naming without relying on old Autopilot tab semantics. | `apps/autopilot/src/main.tsx`, `AutopilotShellWindow/*`, CSS, tests | App copy says Hypervisor; compatibility names are implementation-only. |
| 0A.1B Retire IDE-root naming | Rename launcher/script/docs away from `ide`/Electron-as-product language and move tracked adapter metadata and ignored local adapter artifacts to `workbench-adapters/`. | `workbench-adapters/`, launcher scripts, package scripts, conformance readers | Electron/VS Code is one Workbench adapter host; root `ide/` is retired and must not be used as a product or artifact path. |
| 0A.1C Retire Tauri app shims | Replace active `@tauri-apps/*` imports and `TauriRuntime` service naming with Hypervisor client bridge APIs; keep archived Tauri code only under `internal-docs/legacy`. | `apps/autopilot/src/services/*`, shell hooks/components, package deps, validation scripts | Active app code no longer depends on Tauri APIs or `apps/autopilot/src-tauri`; legacy Tauri references are historical only. |
| 0A.2 App shell IA | Build IOI-reference shell with left rail, New Session, sessions rail, main surface, right inspector, and bottom inspector. | `AutopilotShellContent.tsx`, `ChatLocalActivityBar.tsx`, `ChatLeftSidebarShell.tsx`, shell CSS | Home opens as app cockpit, not Code repositories/OpenVSCode. |
| 0A.3 Session/project model | Add session cards, project cards, restore state, blocked approvals, recent sessions. | `autopilotShellModel.ts`, `operatorSubstrateModel.ts`, Home/Session services | Sessions persist visually and map to daemon/Agentgres refs where available. |
| 0A.4 New Session flow | Create guided launch flow: Mission, Workbench, Agent, Automation, Foundry job, Fleet job, Private Workspace. | New surface or Home components; `workspaceRuntimeNavigation.ts`; runtime launch services | User can start a governed session with model/harness/privacy/authority summary. |
| 0A.5 Workbench as adapter hub | Move "Code repositories" under Workbench and expose editor adapter preference. | `WorkspaceShell.tsx`, `WorkspaceRepositoryGate.tsx`, `workspaceWorkbenchHost.ts`, settings | VS Code/OpenVSCode is one adapter target; Cursor/Windsurf/JetBrains/browser IDE/terminal can be represented. |
| 0A.6 Automations / Workflow Compositor | Convert current workflow composer/runs into Automations/Workflows with templates, filters, run buttons, graph editing, receipt state. | MissionControl workflow views, `packages/hypervisor-workbench/src/WorkflowComposer.tsx`, workbench webview | IOI-reference automations become Hypervisor compositor graphs and reusable recipes. |
| 0A.7 Models as infrastructure and setup | Keep a Models surface, but also embed model mounting into New Session/Create Agent/Mission setup. | `MissionControlMountsView.tsx`, model daemon actions, public `/v1/model-mount/*` clients | Model mounts are not a detached tab; each session shows selected model/provider/custody. |
| 0A.8 Authority/privacy/receipts inspectors | Add persistent contextual right/bottom governance and environment panels. | Policy, Capabilities, Settings, cTEE/private workspace services, receipt components | Selected session reveals changes, authority scope, privacy posture, latest receipts, ports/services, tasks, terminal/logs. |
| 0A.9 Fleet and private workspace path | Surface direct providers, remote VM workspaces, DePIN nodes, zero-to-idle/restore. | Fleet surface, workspace host/session services, provider integrations | User can create persistent workspace/node route without treating provider as trusted. |
| 0A.10 Visual and behavior conformance | Add Playwright smoke checks and source scans for naming/IA. | App tests, `scripts/conformance/hypervisor-conformance.mjs` | Checks prove no user-facing "Autopilot" tabs, no Workbench-as-parent, and Home/Sessions/Workbench flows work. |

Current implementation cut:

```text
0A.1B is partially implemented:
  ChatIdeHeader.tsx -> HypervisorClientHeader.tsx
  workspaceIde.ts -> workspaceEditorAdapterBridge.ts
  scripts/lib/autopilot-electron-app-paths.mjs ->
    scripts/lib/hypervisor-workbench-adapter-host-paths.mjs
  check:autopilot-electron-source-fork-optional ->
    check:hypervisor-workbench-adapter-host-paths
  active adapter metadata defaults to workbench-adapters/
  active launch marker is IOI_HYPERVISOR_CANONICAL_CLIENT_HOST

0A.1C remains a live guard, not an active Tauri app removal task:
  apps/autopilot/src-tauri is absent from the live app path
  internal-docs/legacy/autopilot-tauri-src is historical extraction inventory
  any active @tauri-apps import, TauriRuntime service, or src-tauri dependency is
  a regression unless it appears in a negative test or legacy reference.
```

Code migration posture:

```text
Do not rewrite the app from scratch.
Do create a new shell contract and progressively move existing surfaces under it.
Do not delete model mounting, Workflow Composer, Policy, Settings, or
WorkspaceShell; rehome them under the sharper IA.
Do not clone the IOI mirror literally; translate it:
  New Session, persistent sessions rail, session detail tabs, changes,
  ports/services/tasks/terminal, automations, settings, default editor.
Do not make model mounting a lonely infra page; make it contextual in launch.
Do not make Workbench the parent product; make it one surface.
Do not let a root `ide/` artifact path or Electron/VS Code packaged host define
the product. Root `ide/` is retired; current Workbench adapter-host metadata and
ignored local adapter artifacts belong under `workbench-adapters/`.
Do not preserve Tauri compatibility shims in active app paths. Tauri is legacy
extraction inventory only.
Do not collapse Settings and Authority:
  Settings configures account/secrets/git/tokens/integrations/policy defaults.
  Authority governs live approvals, leases, grants, revocation, and review.
```

First implementation slice:

```text
1. Add `HypervisorShellNavigationModel` and `HypervisorSurfaceId`.
2. Replace visible Autopilot shell labels with Hypervisor labels.
3. Make Home the default route and render a left rail:
   New Session, Home, Projects, Sessions, Missions, Workbench, Automations,
   Insights, Agents, Models, Privacy, Fleet, Foundry, Authority, Receipts,
   Settings.
4. Move Code repositories under Workbench.
5. Add a New Session modal with fixture-backed choices and model/harness/privacy
   summary rows.
6. Add IOI-reference inspectors:
   Changes, Ports & Services, Tasks, Terminal, environment health.
7. Add tests/source scans for:
   - no "Autopilot Code" visible tab label;
   - Workbench is a surface, not parent product;
   - model mounting appears in session setup and Models surface;
   - editor preference supports embedded and external adapter modes.
```

Verification ladder:

```text
npm run build --workspace=@ioi/hypervisor-workbench --if-present
npm run build --workspace=@ioi/workspace-substrate --if-present
npm run build --workspace=autopilot
node --check touched .mjs files
focused shell/navigation tests
Playwright smoke:
  / -> Hypervisor Home
  New Session opens
  Workbench opens repository gate/editor adapter selector
  Automations opens workflow/compositor templates
  Models surface opens daemon model-mount projection
  Changes/Authority/Privacy/Receipts inspector changes with selected session
  Ports & Services / Tasks / Terminal inspector renders for environment session
git diff --check -- apps/autopilot packages/hypervisor-workbench internal-docs/implementation docs/architecture
```

UX anti-patterns:

```text
Hypervisor = VS Code fork
Hypervisor App = Workbench only
Workbench = parent product
Model mounting = primary user job
Autopilot tabs = product IA
One separate GUI app per surface
New Session = raw prompt box without authority/privacy/model/harness setup
External agent harness = trusted runtime
Embedded VS Code = required
Rented GPU workspace = trusted local desktop
```

Completion target:

```text
The user opens Hypervisor and sees an autonomous-work cockpit.
They can start a mission, open a workbench in their preferred editor adapter,
select or inherit a model mount, bind authority, see privacy posture, and inspect
changes, ports/services, tasks, terminal, receipts, and restore state without
the app feeling like a VS Code tab collection.
```

### Phase 0B: Harness Adapter Testbed

Status: implementation leg for proving heterogeneous harnesses under the same
Hypervisor Core contract.

Decision:

```text
Do not implement Default Harness Profile as Codex, Claude Code, DeepSeek TUI,
or any other external harness.

Default Harness Profile remains IOI's reference scaffold/fallback
HarnessProfile.

Codex-style, Claude-style, DeepSeek-style, Aider-style, OpenHands-style,
shell/tmux, and hosted coding agents become AgentHarnessAdapters. Hypervisor may
launch them, compare them, containerize them, route them through model mounts
where supported, and receipt their actions, but they do not become runtime truth.
```

Current repo adapter candidates:

```text
examples/codex-desktop-linux
  Codex-like desktop/client lane and computer-use reference path.

examples/claude-code-main/claude-code-main
  Claude Code-like CLI architecture reference. Treat carefully as reference
  material, not a canonical dependency or endorsed source import.

examples/DeepSeek-TUI-main/DeepSeek-TUI-main
  DeepSeek TUI-like terminal harness with Docker, approval modes, tool registry,
  session resume, rollback, HTTP/SSE runtime API, and OpenAI-compatible client
  shape.

examples/LocalAI-master(1)/LocalAI-master
  Local model server/backend candidate. Treat as model-route infrastructure,
  not as an AgentHarnessAdapter.
```

Target contract:

```ts
interface AgentHarnessAdapterProfile {
  adapter_id:
    | "codex_cli"
    | "codex_desktop_linux"
    | "claude_code_cli"
    | "deepseek_tui"
    | "aider_cli"
    | "openhands"
    | "generic_cli";
  adapter_kind:
    | "cli"
    | "desktop_example"
    | "containerized_cli"
    | "remote_harness"
    | "hosted_agent";
  execution_lane:
    | "host_dev"
    | "docker_container"
    | "podman_container"
    | "microvm_later"
    | "desktop_linux_example"
    | "remote_api";
  model_route_policy:
    | "hypervisor_model_mount"
    | "adapter_builtin"
    | "provider_trust"
    | "forbidden";
  workspace_mount_policy:
    | "public_trunk"
    | "redacted_projection"
    | "plain_workspace"
    | "ctee_private_workspace";
  required_authority_scopes: string[];
  receipt_policy_ref: string;
}

interface HarnessComparisonRun {
  run_id: string;
  project_ref: string;
  task_ref: string;
  candidate_adapter_refs: string[];
  selected_model_mount_ref?: string;
  comparison_mode: "same_task" | "same_fixture" | "benchmark" | "shadow";
  acceptance_criteria_refs: string[];
  receipt_refs: string[];
}

interface HarnessAdapterReceipt {
  receipt_id: string;
  adapter_profile_ref: string;
  execution_lane: AgentHarnessAdapterProfile["execution_lane"];
  model_route_ref?: string;
  container_image_ref?: string;
  command_argv_hash?: string;
  workspace_mount_policy: AgentHarnessAdapterProfile["workspace_mount_policy"];
  authority_scope_refs: string[];
  privacy_posture_ref: string;
  agentgres_operation_refs: string[];
  artifact_refs: string[];
}
```

Harness/model split:

```text
Harness adapters decide how a step is reasoned through:
  Codex CLI, codex-desktop-linux, Claude Code, DeepSeek TUI, Aider, OpenHands,
  shell/tmux agents, hosted coding agents.

Model routes decide where cognition is served:
  Hypervisor model mount, LocalAI, Ollama, llama.cpp, vLLM, provider APIs,
  customer endpoints, hosted models.

The selector must allow:
  harness = Codex adapter + model = local model mount, if compatible;
  harness = DeepSeek TUI adapter + model = configured OpenAI-compatible route,
    if compatible;
  harness = Claude Code adapter + model = adapter-native/provider route unless
    a supported local-model bridge is proven;
  harness = Default Harness Profile + model = selected Hypervisor model route.
```

Execution lanes:

| Lane | Use | Boundary |
| --- | --- | --- |
| Host dev CLI | Fast local development and adapter probing. | Lowest isolation; never privacy proof. |
| Docker/Podman container | Reproducible harness smoke tests and public workspace tasks. | Useful sandbox; not a root-provider privacy guarantee. |
| `examples/codex-desktop-linux` | Desktop/client parity and computer-use reference. | Adapter target, not Hypervisor Core. |
| Local model server | LocalAI/Ollama/llama.cpp/vLLM endpoint behind model mount. | Model backend, not harness authority. |
| Remote/provider API | Existing harness-native provider path. | Provider-trust lane; mark privacy posture explicitly. |

Implementation phases:

| Phase | Objective | Main files | Acceptance |
| --- | --- | --- | --- |
| 0B.1 Adapter manifest fixtures | Add static manifests for Codex, codex-desktop-linux, Claude Code, DeepSeek TUI, and generic CLI. | new adapter manifest module under app/daemon, test fixtures | UI can list adapters without executing them. |
| 0B.2 Harness selector in New Session | Add harness selector beside model route and privacy posture. | Hypervisor App launch flow from Phase 0A | Session summary shows harness, model route, workspace mount, and privacy posture. |
| 0B.3 Model-mount compatibility check | Probe `/v1/model-mount/*` inventory before offering local route. | `packages/agent-sdk/src/substrate-client.ts`, model mount clients | No harness silently falls back to cloud/provider if local route is unavailable. |
| 0B.4 Container lane contract | Define Docker/Podman command, mount, network, env, and receipt envelope. | runtime daemon adapter service, docs, tests | Container run receipts include image, argv hash, mounts, network policy, exit status. |
| 0B.5 First public smoke task | Run the same non-sensitive fixture task through two adapters where installed. | adapter runner tests, sample workspace | Receipts prove both were mediated by daemon gates. |
| 0B.6 cTEE/private workspace guard | Restrict external harnesses to public trunk/redacted projection unless explicitly allowed. | private workspace policy, adapter runner | Sensitive work cannot be mounted into plain external harness workspace by default. |
| 0B.7 Comparison dashboard | Add HarnessComparisonRun view to Workbench/Foundry. | Hypervisor App Workbench/Foundry surfaces | User can compare adapter output, cost, receipts, and verification results. |

First implementation slice:

```text
1. Define `AgentHarnessAdapterProfile`, `HarnessAdapterReceipt`, and
   `HarnessComparisonRun` fixtures.
2. Add adapter choices to New Session:
   Default Harness Profile, Codex CLI, codex-desktop-linux, Claude Code,
   DeepSeek TUI, Generic CLI.
3. Add model route choices from the daemon model-mount inventory.
4. Add compatibility states:
   compatible, adapter-native only, provider-trust, local-route unavailable.
5. Add container lane dry-run receipt for a public fixture workspace.
6. Add source scans proving no external harness bypasses daemon gates.
```

Anti-patterns:

```text
Codex = Default Harness Profile
Claude Code = Default Harness Profile
External harness = Hypervisor runtime truth
Container = cTEE privacy guarantee
Docker mount of private workspace = safe because encrypted at rest
LocalAI/Ollama/llama.cpp = harness adapter
Harness-native provider fallback = private local model route
Adapter comparison = unreceipted manual experiment
```

Verification ladder:

```text
rg -n "Codex = Default Harness|Claude Code = Default Harness|external harness.*runtime truth" \
  internal-docs/implementation docs/architecture
  # Remaining hits must be anti-pattern examples only.
node --check touched adapter .mjs files
focused adapter manifest tests
focused model-mount compatibility tests
container dry-run receipt test
git diff --check -- internal-docs/implementation docs/architecture apps/autopilot packages/runtime-daemon
```

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
- a Hypervisor App UX implementation plan from Autopilot/OpenVSCode gravity to
  an IOI-reference Hypervisor Core cockpit with session tabs and inspectors;
- a Harness Adapter Testbed plan for Codex-style, Claude-style, DeepSeek-style,
  and generic CLI harness comparison under daemon gates;
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
rg -n "Hypervisor App UX Master Plan|HypervisorSessionLaunchRecipe|WorkbenchAdapterPreference|HypervisorSessionDetailTab|HypervisorInspectorPanelId" internal-docs/implementation/refine-architecture.md
rg -n "Harness Adapter Testbed|AgentHarnessAdapterProfile|HarnessAdapterReceipt|HarnessComparisonRun" internal-docs/implementation/refine-architecture.md
```
