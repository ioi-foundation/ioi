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
  Workbench, Foundry, Agents, Services, Models, cTEE/Privacy,
  Receipts/Audit, Connectors, Wallet presentations, aiagent.xyz, sas.xyz,
  console.ioi.ai, embedded approval cards, marketplace consoles, and
  provider/environment views are surfaces over shared authority/runtime
  contracts.

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
| 2 | Hypervisor App should become the reference operator cockpit, not a code-editor shell. | The retired UX opened into code-repository/editor gravity; the target is one Core with sessions, projects, surfaces, adapters, model mounts, authority, privacy, and receipts. |
| 3 | `WalletAuthorityCore` should become the reusable authority kernel; Wallet UI is one presentation. | Prevents all Web3/Web4 apps from inheriting a heavy finance console. |
| 4 | Broad autonomous labor needs first-class ontology and integration-surface canon, not only a plan doc. | This is now canonized through the aiagent ontology docs and worker-package install admission; live marketplace endpoints remain the adoption frontier. |
| 5 | Physical/embodied action needs a canonical safety envelope owner. | This is now canonized through Physical Action Safety and daemon admission; live actuator adapters remain the adoption frontier. |
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
| Discord moderation agent needs scoped credentials and revocation | Wallet scopes and secret brokerage fit. | The ontology now has integration-surface vocabulary; product-specific moderation packs still need endpoint adoption. | Use integration-surface taxonomy plus `CapabilityLease` examples for moderation actions. |
| Persistent aiagent instance runs for years, then payment lapses | Runtime nodes mention zero-to-idle and persistent. | Lifecycle is now canonized and daemon-admitted; live aiagent marketplace/product endpoints remain follow-up. | Use `ManagedWorkerInstanceLifecycle` with active, suspended, archived, restored, expired, export, and delete states. |
| sas.xyz outcome uses nested workers, private data, disputes | sas delivery bundles and receipts fit. | Default service composition evidence is now daemon-admitted; SAS product endpoints remain follow-up. | Use service composition evidence profile that binds worker contribution, private-data posture, and dispute refs. |
| Humanoid/robot preps cars at a carwash | AIIP and common envelopes mention robot domains. | Physical safety is now canonized and daemon-admitted; live actuator adapters remain follow-up. | Use Physical Action Safety with supervision, e-stop, sensor evidence, and actuator receipts. |
| Wallet user approves a session envelope instead of per-action modals | Wallet authority UX model now fits. | Protocol/SDK packages now carry approval modes and presentation profiles; deeper Rust-derived generation remains follow-up. | Use `AuthorityReview`, `ApprovalMode`, and `CapabilityLease` in `@ioi/wallet-protocol` and SDK. |
| Operator uses Codex, Claude Code, Grok Build, or Aider inside a Hypervisor-managed workspace | Authority Gateway and Hypervisor adapter docs mostly fit. | External agent harnesses can be mistaken for first-class Hypervisor clients or trusted runtimes. | Treat them as `AgentHarnessAdapter` targets: proposal in, daemon gate, wallet authority, Agentgres receipt/replay out. |
| Operator wants a terminal UI for node ops | CLI/headless plus optional TUI fits. | Calling this "CLI/TUI" suggests the TUI is a separate client/runtime lane. | Keep `HypervisorCliHeadless` as the first-class client and `HypervisorTui` as optional presentation over the same daemon/domain APIs. |
| Prediction market trade proposed by an agent | decentralized.trade and Wallet Trade fit. | Live event exposure by agents needs eligibility, compliance, and market-category policy. | Add `PredictionAuthorityPolicy` as a profile over `PredictionIntent`. |
| Cloud route needs AWS/GCP/Akash/Filecoin/local choices | Hypervisor direct provider integrations fit. | "CloudRoute" can sound like one router, not a provider decision object. | Clarify `CloudCandidate` as provider evidence and `CloudRoute` as selected approved plan. |
| Storage backend loses payload bytes but Agentgres has refs | Artifact-ref plane fits. | Need repair playbook in operational docs. | Add `ArtifactAvailabilityIncident` and repair receipts in Agentgres artifact doc. |
| Route engine returns stale quote or stale risk label | Wallet risk coverage states fit. | Candidate services must return evidence and expiry, not only "best route." | Add conformance: stale/unknown labels block silent execution. |
| SMS access point requests escalation | Wallet access-point binding fits. | Product copy may imply SMS auth. | Keep canon explicit: SMS can carry challenge pointer only. |
| Model API provider receives sensitive data | ProviderTrustBoundary fits. | Product/harness should classify this as `redacted_api`, `provider_trust`, or `unsafe`. | Require `ExecutionPrivacyPosture` disclosure on model-route selection. |
| cTEE node infers private strategy via timing or candidate leakage | cTEE leakage docs fit. | Leakage quantification must be attached to schedules and receipts. | Add `LeakageBudget` / `CandidateCoverageProfile` conformance to Private Workspace. |

## Coherence Findings

### 1. aiagent broad labor canon is implementation-visible

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `docs/architecture/domains/aiagent/worker-marketplace.md`, `digital-worker-ontology.md`, `vertical-ontology-packs.md`, `integration-surface-taxonomy.md`, `managed-agent-console-contract.md`, `managed-worker-instance-lifecycle.md` |
| Edge case | Discord moderation, game server finding, robotics carwash prep, embodied field-service agents. |
| Issue | Resolved at canon and first daemon admission level; live marketplace endpoints and product surfaces still need to adopt the ontology-bound contract. |
| Why it matters | Implementers may build a worker storefront instead of an autonomous labor substrate that supports millions of vertical profiles. |
| Recommended change | Keep all aiagent endpoint/product work bound to Digital Worker Ontology, Vertical Ontology Packs, Integration Surface Taxonomy, Managed Worker Lifecycle, and Managed Agent Console Contract. |
| Fix type | Canon and first daemon admission implemented; live endpoint/product adoption next. |

### 1A. Hypervisor client/surface/adapter taxonomy must stay implementation-visible

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `docs/architecture/components/hypervisor/core-clients-surfaces.md`, daemon runtime doctrine, source-of-truth map, vocabulary. |
| Edge case | A team builds Hypervisor as a VS Code product, treats TUI as a runtime lane, or lets Codex/Claude Code/Grok Build bypass daemon receipts. |
| Issue | The canon now has the cleaner taxonomy, but implementation plans can drift back to old "IDE" or "CLI/TUI" shorthand. |
| Why it matters | The product becomes brittle if clients, application surfaces, adapter targets, and external agent harnesses each invent their own runtime truth. |
| Recommended change | Keep `HypervisorCore`, `HypervisorClient`, `HypervisorApplicationSurface`, `HypervisorAdapterTarget`, and `AgentHarnessAdapter` in source maps, vocabulary, implementation matrix, app APIs, and future conformance checks. |
| Fix type | Docs, API/schema, and conformance implemented through `ioi.runtime.hypervisor_core_taxonomy.v1` and `GET /v1/hypervisor/core-taxonomy`; future work is product adoption wherever a client needs to hydrate the taxonomy. |

### 2. Physical-action safety has a canonical owner

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `docs/architecture/foundations/physical-action-safety.md`, `common-objects-and-envelopes.md`, `aiip.md`, `default-harness-profile.md`, runtime physical-action admission. |
| Edge case | Humanoid or robot performs vehicle-adjacent work near humans. |
| Issue | Resolved at canon and daemon admission level; live actuator adapters and incident integrations remain follow-up hardening. |
| Why it matters | Physical action cannot be treated as just another connector call. It needs supervision, emergency stop, sensor evidence, actuator receipts, liability, and incident handling. |
| Recommended change | Keep every physical/embodied worker and service package bound to `PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`, sensor evidence, and actuator receipts. |
| Fix type | Canon and daemon admission implemented; live actuator adapter implementation next. |

### 3. Managed worker instance lapse semantics are canonical

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `aiagent/managed-worker-instance-lifecycle.md`, `worker-marketplace.md`, `worker-endpoints.md`, `runtime-nodes-tee-depin.md`, Agentgres artifact refs, runtime lifecycle admission. |
| Edge case | User rents an agent for years, stops paying, then wants context restored. |
| Issue | Resolved at canon and daemon admission level; live aiagent marketplace/product endpoints still need to call the lifecycle admission boundary. |
| Why it matters | User trust and marketplace economics depend on context custody, retention, and restore behavior. |
| Recommended change | Use `ManagedWorkerInstanceLifecycle` states, payment lapse policy, archive refs, restore authority, export rights, and deletion policy for all persistent agent instances. |
| Fix type | Canon and daemon admission implemented; live Agentgres/wallet/aiagent product adoption next. |

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

### 5. Wallet protocol packaging has a first implementation boundary

| Field | Detail |
| --- | --- |
| Severity | High |
| Current canon | `wallet-network/doctrine.md`, `api-authority-scopes.md`, `_meta/wallet-protocol-sdk-packaging-plan.md`. |
| Edge case | Embedded dapp approval card needs `AuthorityReview` and `ApprovalMode`. |
| Issue | The base package boundary now exists, but product repos still need to adopt it and deeper generation from Rust exports should be hardened. |
| Why it matters | Product repos may otherwise keep inventing local authority objects despite the package boundary. |
| Recommended change | Wire Wallet product/import surfaces to `@ioi/wallet-protocol` and `@ioi/wallet-sdk`; later harden Rust-derived generation and conformance. |
| Fix type | Product adoption plus generator/conformance hardening. |

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

### 7. Provider/environment selection is cleaner without present decentralized.cloud

| Field | Detail |
| --- | --- |
| Severity | Medium |
| Current canon | `hypervisor/providers-and-environments.md`, deprecated `hypervisor/fleet.md` stub, `decentralized/cloud-parked-future.md`. |
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
| Current UX evidence | Legacy screenshot showed the product trapped inside editor tabs for composer, models, runs, policy, connectors, and code. That shape is retired: code editors are adapter targets only, while Home/Sessions/Projects live in the Hypervisor shell. |
| Reference evidence | `internal-docs/reverse-engineering/ioi` is the primary target UX reference: persistent left nav, New Session, Home, Projects, Automations, Insights, Sessions, session-detail tabs, environment status, changes panel, ports/services/tasks/terminal inspector, settings, default code editor target selection, secrets, git auth, tokens, integrations, and session history. Local screenshots and static mirror assets exist in that directory; mirrored labels must be translated into Hypervisor language rather than copied literally. |
| Issue | The current product reads like an IDE extension host with Autopilot tabs. The canon now says Hypervisor App/Web/CLI-headless are clients over Hypervisor Core, Workbench/Foundry are application surfaces, provider/environment posture is a default Hypervisor view, editors are adapter targets, and external coding agents are Agent Harness Adapters. |
| Why it matters | If the UX stays IDE-first, the architecture will keep drifting back toward "Hypervisor IDE" instead of "Hypervisor of IDEs / governed autonomous-work cockpit." |
| Recommended change | Add a staged implementation plan that converts the app shell from legacy editor gravity into a Hypervisor Core cockpit with sessions, projects, application surfaces, adapter targets, model/harness/provider setup, cTEE/privacy posture, authority, and receipts. |
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
| Hypervisor product taxonomy | "Hypervisor IDE", "Electron/VS Code fork", or "CLI/TUI" as parent product | Hypervisor Core with App/Web/CLI-headless clients, optional TUI presentation, Workbench/Foundry surfaces, provider/environment views, adapter targets, and Agent Harness Adapters. |
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
| Hypervisor App UX shell | Current app code now uses the Hypervisor shell, but this guide remains the source of truth for keeping old editor-shell gravity from returning | `internal-docs/implementation/refine-architecture.md` for implementation plan, then `apps/hypervisor/src/windows/HypervisorShellWindow/*` or renamed Hypervisor shell modules for implementation |
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
CodeEditorAdapterPreference
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
Wallet UX/authority packaging: initial protocol/SDK packages and Hypervisor
  Authority Center import adoption exist; deeper Rust-derived generation and
  wallet-network product adoption remain.
Private Workspace cTEE: yes for architecture, partial for full conformance.
Provider/environment integrations: yes for boundary, provider adapters still needed.
aiagent broad labor: canon and first daemon install admission exist; live
  marketplace/product endpoints remain.
sas nested outcomes: service composition receipt bundle admission exists; live
  SAS endpoint adoption remains.
Physical/embodied systems: Physical Action Safety canon and daemon admission
  exist; live actuator adapters remain.
```

Blocking object/API/schema gaps:

```text
Hypervisor live projection hydration for Home/Projects/Sessions/Privacy
Hypervisor row-level drill-in inside destination surfaces
HypervisorSessionLaunchRecipe live daemon admission and execution
CodeEditorAdapterPreference external editor/browser/VM control wiring
wallet-network product imports for @ioi/wallet-protocol and @ioi/wallet-sdk
Rust-derived wallet schema generation
CapabilityLease product flows
ApprovalMode embedded/lite UI adoption
ManagedWorkerInstance live marketplace endpoints
VerticalOntologyPack live package manifests
IntegrationSurface endpoint adoption
PhysicalActionPolicy and SafetyEnvelope live actuator adapters
ExecutionPrivacyPosture live model/provider admission hydration
ModelWeightCustodyProfile model-router route selection
CandidateEvidence provider-specific route-source integrations
ArtifactAvailabilityIncident live Agentgres artifact endpoint integration
ServiceCompositionReceiptBundle SAS endpoint adoption
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

Provider/environment details
  Keep provider examples as integrations, not mandatory provider stack.

cTEE candidate-lattice math
  Keep as privacy/performance strategy, not universal private inference claim.
```

## Anti-Patterns to Add

| Doc | Anti-pattern |
| --- | --- |
| Hypervisor core/client/surface docs | Treating Hypervisor Workbench or a VS Code shell as the parent product/runtime. |
| Hypervisor app implementation | Treating legacy editor/application tabs as the target product IA. |
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

Status: implementation leg for moving the legacy editor-shaped UX into the
Hypervisor Core product architecture. The active tree must stay hard-cut away
from direct editor product surfaces and deleted onboarding walkthroughs.

Reference inputs:

```text
Retired screenshot:
  editor parent chrome
  editor-owned composer / models / runs / policy / connectors / code tabs
  editor-owned project/workspace gate

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
    Settings: account, default code editor target selection, embedded editor
          toggle, secrets, git authentications, personal access tokens,
          integrations
  note: the mirror contains sanitized reference labels; translate them into
        Hypervisor product language instead of copying names literally.
  corrected comparison evidence:
    /tmp/ioi-hypervisor-compare/ioi-reference-correct.png
    /tmp/ioi-hypervisor-compare/hypervisor-current-correct.png
    /tmp/ioi-hypervisor-compare/side-by-side-correct.png
  capture note:
    run the IOI mirror with PORT=9226 from internal-docs/reverse-engineering/ioi;
    port 9225 may already be occupied by the separate Palantir mirror.

Current code anchors:
  apps/hypervisor/src/main.tsx
  apps/hypervisor/src/windows/HypervisorShellWindow/*
  apps/hypervisor/src/surfaces/Home/*
  apps/hypervisor/src/surfaces/Workspace/*
  apps/hypervisor/src/surfaces/{Home,Automations,Models,Authority,Insights,Conversation,Workspace}/*
  apps/hypervisor/src/surfaces/Policy/*
  apps/hypervisor/src/surfaces/Settings/*
  apps/hypervisor/src/surfaces/Capabilities/*
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
Provider/environment views are infrastructure/provider/workspace estate.
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
| Agents | Workers, harness adapters, skills, access, and receipts | aiagent + wallet.network authority |
| Models | Model inventory, providers, endpoints, mounts, downloads | Model mounting daemon APIs |
| Privacy / cTEE | Workspace privacy posture, cTEE lanes, unsafe mount warnings | Private Workspace / cTEE |
| Authority | Approvals, capability leases, connector scopes, spend gates | wallet.network |
| Receipts / Audit | Receipts, replay, artifacts, state roots, restore | Agentgres + receipts |
| Foundry | Eval, distillation, training, benchmark, package promotion | Hypervisor Foundry |
| Providers / Environments | Local/cloud/DePIN/customer provider estate and persistent nodes | Hypervisor provider/environment views |
| Settings | Identity, editor preference, secrets, git auth, tokens, integrations, policy defaults | Hypervisor client settings + wallet.network |

Core UX decisions:

```text
1. Default screen becomes Hypervisor Home, not an embedded code editor.
2. "New Session" is the primary CTA.
3. "Create Agent" and "Create Mission" are guided setup flows, not raw tabs.
4. Model mounting appears in two places:
   - global Models surface for inventory, providers, endpoints, downloads;
   - contextual step inside New Session / Create Agent / Mission setup.
5. Workbench owns code-editor and workspace target choice:
   embedded editor host, desktop editor bridge, browser IDE, terminal/tmux,
   provider workspace, HypervisorOS node, or substrate preview.
6. Embedded editor hosts are optional adapter targets, not product identity.
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
    Providers / Environments
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
  | "providers"
  | "environments"
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
    | "provider_environment_job"
    | "privacy_workspace";
  required_inputs: string[];
  model_mount_policy: "inherit" | "select" | "required" | "forbidden";
  harness_profile_policy: "default" | "select" | "external_adapter";
  authority_scope_templates: string[];
  privacy_posture_templates: string[];
}

type HypervisorEnvironmentLifecycleState =
  | "draft"
  | "provisioning"
  | "running"
  | "idle"
  | "zero_to_idle"
  | "stopped"
  | "archived"
  | "unarchiving"
  | "restoring"
  | "failed"
  | "deleted";

interface HypervisorEnvironmentClass {
  class_id: string;
  label: string;
  provider_ref:
    | "local"
    | "customer_cloud"
    | "hyperscaler"
    | "depin_compute"
    | "decentralized_storage"
    | "hypervisor_os";
  cpu: string;
  memory: string;
  gpu?: string;
  storage: string;
  privacy_posture_refs: string[];
  default_for_project?: boolean;
}

interface HypervisorEnvironmentOpsProfile {
  environment_id: string;
  session_id: string;
  project_ref: string;
  lifecycle_state: HypervisorEnvironmentLifecycleState;
  class_ref: string;
  adapter_preference_ref?: string;
  provider_candidate_ref?: string;
  restore_state_ref?: string;
  archive_ref?: string;
  latest_activity_signal_ref?: string;
  access_token_lease_refs: string[];
  log_token_lease_refs: string[];
  service_refs: string[];
  task_refs: string[];
  port_refs: string[];
  scm_auth_requirement_refs: string[];
  receipt_refs: string[];
}

interface HypervisorEnvironmentActivitySignal {
  signal_id: string;
  environment_id: string;
  source: "hypervisor_app" | "hypervisor_web" | "code_editor_adapter" | "agent_harness" | "daemon";
  observed_at: string;
  lease_ref?: string;
  receipt_ref: string;
}

interface HypervisorSessionAccessLease {
  lease_id: string;
  environment_id: string;
  purpose: "connect" | "logs" | "port_forward" | "support_bundle";
  scope_refs: string[];
  expires_at: string;
  wallet_authority_ref: string;
  receipt_ref: string;
}

interface HypervisorEnvironmentService {
  service_id: string;
  environment_id: string;
  name: string;
  reference: string;
  start_command_ref: string;
  ready_check_ref?: string;
  status: "configured" | "starting" | "ready" | "failed" | "stopped";
  port_refs: string[];
  receipt_refs: string[];
}

interface HypervisorEnvironmentTask {
  task_id: string;
  environment_id: string;
  name: string;
  command_ref: string;
  depends_on: string[];
  trigger:
    | "manual"
    | "post_environment_start"
    | "post_workspace_restore"
    | "scheduled"
    | "workflow_step";
  status: "configured" | "queued" | "running" | "succeeded" | "failed" | "cancelled";
  execution_receipt_refs: string[];
}

interface HypervisorEnvironmentPort {
  port_id: string;
  environment_id: string;
  port: number;
  name: string;
  exposure_policy: "private" | "workspace" | "authenticated_link" | "public_forbidden";
  url_ref?: string;
  access_lease_ref?: string;
}

interface HypervisorScmAuthRequirement {
  requirement_id: string;
  environment_id: string;
  host: string;
  method: "oauth" | "personal_access_token" | "ssh_key" | "unavailable";
  required_scope_refs: string[];
  credential_lease_policy_ref: string;
  satisfied_by_ref?: string;
}

interface CodeEditorAdapterPreference {
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

Environment-ops doctrine:

```text
Hypervisor environments are managed session resources, not runtime truth.

The Hypervisor Daemon owns lifecycle operations:
  create, create_from_project, start, stop, mark_active, archive,
  unarchive, restore, delete.

wallet.network authorizes:
  environment access leases, log leases, port-forward leases,
  SCM credential release, support-bundle access, provider spend,
  and any secret-bearing action.

Agentgres records:
  environment lifecycle receipts, activity signals, service/task execution
  receipts, access/log lease receipts, archive refs, restore refs,
  provider evidence, and state-root linkage.

Storage backends may hold:
  encrypted workspace blobs, logs, archives, build artifacts, datasets,
  and delivery bundles, but they do not define restore truth.

code editor adapters and AgentHarnessAdapters may connect to environments
through short-lived leases. They do not receive durable credentials or become
the workspace custody domain.
```

Environment inspector target:

```text
Selected session -> Environment tab:
  lifecycle state
  machine/provider class
  selected editor adapter
  activity freshness
  access/log lease status
  SCM auth requirements
  services
  tasks
  ports
  logs / terminal
  archive and restore refs
  latest receipts
```

Implementation phases:

| Phase | Objective | Main files | Acceptance |
| --- | --- | --- | --- |
| 0A.1 Product-shell rename and route map | Introduce Hypervisor naming without relying on old Autopilot tab semantics. | `apps/hypervisor/src/main.tsx`, `HypervisorShellWindow/*`, CSS, tests | App copy says Hypervisor; compatibility names are implementation-only. |
| 0A.1B Retire IDE-root naming | Rename launcher/script/docs away from `ide`/Electron-as-product language and move tracked adapter metadata and ignored local adapter artifacts to `code-editor-adapters/`. | `code-editor-adapters/`, launcher scripts, package scripts, conformance readers | Electron/VS Code is one Code editor adapter host; root `ide/` is retired and must not be used as a product or artifact path. |
| 0A.1C Retire Tauri app shims | Replace active `@tauri-apps/*` imports and `TauriRuntime` service naming with Hypervisor client bridge APIs; delete the retired Tauri tree from the active repo instead of keeping it as a contract archive. | `apps/hypervisor/src/services/*`, shell hooks/components, package deps, validation scripts | Active app code no longer depends on Tauri APIs, `apps/hypervisor/src-tauri`, or `internal-docs/legacy/autopilot-tauri-src`; git history is the recovery handle. |
| 0A.1D Retire Autopilot proof-runner names | Rename or remove active root package scripts and proof-runner entry points that still advertise Autopilot as the product, while preserving historical evidence under legacy/evidence paths. | `package.json`, `scripts/run-*-goal.mjs`, `scripts/lib/*`, conformance readers | `npm run` exposes Hypervisor/App/Workbench/Foundry/provider-environment names; any remaining `autopilot` script/file names are historical fixtures or explicitly marked legacy. |
| 0A.2 App shell IA | Build IOI-reference shell with left rail, New Session, sessions rail, main surface, right inspector, and bottom inspector. | `HypervisorShellContent.tsx`, `ChatLocalActivityBar.tsx`, `ChatLeftSidebarShell.tsx`, shell CSS | Home opens as app cockpit, not an editor-host console. |
| 0A.3 Session/project model | Add session cards, project cards, restore state, blocked approvals, recent sessions. | `hypervisorShellModel.ts`, `operatorSubstrateModel.ts`, Home/Session services | Sessions persist visually and map to daemon/Agentgres refs where available. |
| 0A.4 New Session flow | Create guided launch flow: Mission, Workbench, Agent, Automation, Foundry job, provider/environment job, Private Workspace. | New surface or Home components; runtime launch services | User can start a governed session with model/harness/privacy/authority summary. |
| 0A.5 Workbench as code-editor workspace surface | Open the current project directly in the governed code-editor workspace substrate; keep adapter preference in New Session/Settings. | `WorkspaceShell.tsx`, `workspaceSessionHost.ts`, `useWorkspaceSession.ts`, settings | Workbench no longer owns project creation, adapter-state bridges, or intermediate chooser landings. Code editors are adapter targets; terminal, VM, provider, and node posture belong to Sessions/Providers/Environments. |
| 0A.6 Automations / Workflow Compositor | Convert current workflow composer/runs into Automations/Workflows with templates, filters, run buttons, graph editing, receipt state. | Automations surface and Workflow Composer view, `packages/hypervisor-workbench/src/WorkflowComposer.tsx`, workbench webview | IOI-reference automations become Hypervisor compositor graphs and reusable recipes. |
| 0A.7 Models as infrastructure and setup | Keep a Models surface, but also embed model mounting into New Session/Create Agent/Mission setup. | `ModelMountsSurfaceView.tsx`, model daemon actions, public `/v1/model-mount/*` clients | Model mounts are not a detached tab; each session shows selected model/provider/custody. |
| 0A.8 Authority/privacy/receipts inspectors | Add persistent contextual right/bottom governance and environment panels. | Policy, Capabilities, Settings, cTEE/private workspace services, receipt components, environment ops projections | Selected session reveals changes, authority scope, privacy posture, latest receipts, environment lifecycle, access/log lease state, SCM auth requirements, ports/services, tasks, terminal/logs. |
| 0A.9 Provider/environment and private workspace path | Surface direct providers, remote VM workspaces, DePIN nodes, zero-to-idle/restore. | Provider/environment views, workspace host/session services, provider integrations, environment lifecycle APIs | User can create, stop, start, archive, unarchive, and restore persistent workspace/node routes without treating provider resources as trusted custody or restore truth. |
| 0A.10 Visual and behavior conformance | Add built-shell contract checks and source scans for naming/IA. | Focused app harness contract, runtime layout guard | Checks prove no user-facing "Autopilot" tabs, no Workbench-as-parent, and Home/Sessions/Workbench flows work without retaining campaign runners. |

Current implementation cut:

```text
0A.1 is implemented as the active shell identity cut:
  apps/hypervisor/src/main.tsx routes to HypervisorShellWindow
  apps/hypervisor/src/windows/HypervisorShellWindow/* is the active product shell
  HypervisorShellContent, HypervisorShellModel, and useHypervisorShellController
    replace the previous shell-facing Autopilot names
  the default project seed is Hypervisor Core
  VITE_HYPERVISOR_INITIAL_VIEW replaces the old initial-view flag
  the retired Workbench repository registry/materialization path is deleted;
    Projects/New Session own project creation and code editor sessions open the active
    governed code-editor workspace session directly
  apps/hypervisor/vite.config.ts no longer carries Tauri dev host or src-tauri
    watch configuration

0A.1B is partially implemented:
  ChatIdeHeader.tsx -> HypervisorClientHeader.tsx
  workspaceIde.ts and the later `workspaceEditorAdapterBridge.ts` command-queue
    shim are deleted from active implementation paths. Code editor adapters
    publish context envelopes only; Hypervisor Home/Sessions/Projects owns
    product controls.
  `check:runtime-layout` rejects both retired `workspace_ide` command ids and
    the later unused `code_editor_adapter_bridge` command queue.
  companion/work-graph shell entry points now route to the canonical `process`
    view instead of the retired `autopilot` Chat shell view id, with a
    `check:runtime-layout` guard
  workspace-substrate replay notebooks now use `.hypervisor`,
    `hypervisor_replay`, `hypervisor-cell-*`, and `hypervisor-replay` active
    format identifiers; the Code OSS theme helper is `defineHypervisorTheme`,
    and `check:runtime-layout` rejects the retired active replay/theme tokens
  generated frontend contracts now live at
    `apps/hypervisor/src/generated/hypervisor-contracts`, and active type
    wrappers import that path instead of `generated/autopilot-contracts`
  scripts/lib/autopilot-electron-app-paths.mjs ->
    scripts/lib/hypervisor-code-editor-adapter-host-paths.mjs
  check:autopilot-electron-source-fork-optional ->
    check:hypervisor-code-editor-adapter-host-paths
  active adapter metadata defaults to code-editor-adapters/
  active launch marker is IOI_HYPERVISOR_CANONICAL_CLIENT_HOST

0A.1C is implemented for active app paths and remains a live regression guard:
  apps/hypervisor/src-tauri is absent from the live app path
  apps/hypervisor/scripts/dev-desktop.sh is deleted; npm run dev:hypervisor-app
    launches the Hypervisor App shell, while
    npm run dev:hypervisor-code-editor-adapter-host launches the packaged Code
    editor adapter host
  internal-docs/legacy/autopilot-tauri-src is deleted from the active tree;
    git history is the historical extraction inventory
  any active @tauri-apps import, TauriRuntime service, or src-tauri dependency is
  a regression unless it appears in a negative test or legacy reference.
  active desktop probes and active contract tests no longer create or read
  `apps/hypervisor/src-tauri`; throwaway probe workspaces live under `.tmp/`
  and client-runtime checks read `HypervisorClientRuntime.ts`.
  active desktop probes now target the explicit code-editor-adapter host command
    when validating editor targets, and `check:runtime-layout` rejects Tauri
    product language in active Hypervisor probe files plus the retired
    `Workspace IDE` marker.

0A.1B/0A.1C guardrails were tightened:
  `internal-docs/implementation/runtime-module-map.md` no longer points
  Hypervisor proof work at `apps/hypervisor/src-tauri`
  `check:runtime-layout` rejects both active `apps/hypervisor/src-tauri/src`
  and a root `ide/` product/artifact directory, rejects the retired
  `apps/hypervisor/scripts/dev-desktop.sh` Tauri launcher, and
  rejects active desktop probe wording that describes Hypervisor as a Tauri app
  or as the retired `Workspace IDE`.
  `check:hypervisor-code-editor-adapter-host-paths` verifies the tracked
  adapter path helper defaults to `code-editor-adapters/`
  active developer docs describe Hypervisor as a native operator client over
    Hypervisor Core and the IOI daemon, not as an Autopilot/Tauri desktop product
  editor adapter launch no longer owns configured local llama.cpp preloads;
    model discovery, routing, and mount state stay in Hypervisor App/Core and
    daemon-owned model-mounting paths
  `.gitignore` no longer preserves dead active `src-tauri` or `agent-ide`
  shadows

0A.1D active command-surface cleanup is implemented:
  the active Tauri app and root `ide/` product path are retired, and root
  `package.json` now exposes Hypervisor/App/Workbench command names instead of
  retired Autopilot-prefixed goal, validation, or test product aliases.
  `HypervisorClientRuntime` now emits
  `runtime_open_hypervisor_intent_requested` and invokes
  `reset_hypervisor_data`; `check:runtime-layout` rejects the retired
  `runtime_open_autopilot_intent_requested` and `reset_autopilot_data` bridge
  names from the active client runtime.
  active proof/helper APIs now use Hypervisor names:
  `hypervisor-campaign-processes.mjs`,
  `hypervisor-runtime-agent-service-inference.mjs`,
  `hypervisor-agent-chat-scenarios.mjs`,
  `hypervisorGuiHarnessContract`, `validateHypervisorGuiHarnessResult`,
  and `buildBlockedHypervisorGuiHarnessResult`; `check:runtime-layout`
  rejects the retired helper filenames, exported symbols, and
  Autopilot-stamped active proof schemas.
  active Agent SDK computer-use fixtures now identify the app target as
  Hypervisor rather than Autopilot; `check:runtime-layout` includes
  `packages/agent-sdk/test/computer-use.test.mjs` in the active fixture source
  bundle and rejects returned `appName` or `captureAppName` Autopilot targets.
  active dev-start probes no longer accept both `[Autopilot]` and
  `[Hypervisor]` log prefixes; the compatibility shim is cut and guarded.
  active harness/dev environment names now use the Hypervisor prefix:
  `HYPERVISOR_LOCAL_GPU_DEV`, `HYPERVISOR_RESET_DATA_ON_BOOT`,
  `HYPERVISOR_DEV_START_INTENT`, `HYPERVISOR_DATA_PROFILE`,
  `HYPERVISOR_HARNESS_DEFAULT_PROMOTION`, and
  `HYPERVISOR_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT`. The old
  `AUTOPILOT_*` harness/dev env family is rejected by `check:runtime-layout`.
  the code editor adapter shell patch path is retired entirely. The adapter host
  syncs the `ioi-code-editor-adapter` extension and launches a normal code-editor adapter
  target; Hypervisor Home, Sessions, Projects, Workbench, Foundry, Providers,
  Receipts, and Settings stay in the Hypervisor App/Web clients.
  `check:runtime-layout` rejects both the retired Autopilot shell-patch helper
  and the later Hypervisor shell-patch helper so adapter targets cannot regain
  product-shell duties.
  the tracked extension package is now `code-editor-adapters/ioi-code-editor-adapter`.
  It contributes no command-palette/product routes; it activates on startup and
  publishes one-way `codeEditor.contextSnapshot` and
  `codeEditor.inspectionTargetIndex` request envelopes through the adapter
  transport. The adapter no longer emits an open-surface request, exposes
  status/output UI, polls bridge command queues, reads daemon model-mount state,
  emits command-route receipt envelopes, or accepts product-shell routes such as
  command center, workflow, models, runs, policy, or connectors.
  the adapter-local Workflow Composer webview build command is retired; the
  `ioi-code-editor-adapter` directory is a code editor adapter implementation detail,
  not the public script/product name.
  tracked `.internal/plans` retired product and Tauri campaign guides are
  deleted from the live repo; the refined implementation guide and conformance
  guards are the continuation surface, and git history is the recovery handle.

0A.1E repo-facing map cleanup is implemented:
  README points new implementers to `apps/hypervisor`,
  `packages/hypervisor-workbench`, and `code-editor-adapters` instead of the
  retired `packages/agent-ide` / Hypervisor IDE framing.
  `check:runtime-layout` rejects a returned `packages/agent-ide` path, root
  `ide/` product path, active Tauri path, and README wording that makes
  Hypervisor an IDE product again.

0A.2 canonical shell routing is partially implemented:
  `PrimaryView` is now the canonical `HypervisorSurfaceId` union rather than
  an IDE-era alias set
  target shell routes are Home, Sessions, Projects, Missions, Workbench,
  Automations, Insights, Agents, Models, Privacy, Providers, Environments,
  Foundry, Authority, Receipts, and Settings
  the active `fleet` route and `packages/hypervisor-workbench/src/features/Fleet/*`
  feature module have been retired in favor of explicit Providers and
  Environments surfaces plus `EnvironmentEstateView`
  Projects, Privacy, Providers, Environments, Foundry, and Receipts have live
  placeholder surfaces instead of command-palette-only rail items
  `/sessions` is the canonical session shell route; `/chat` is no longer a
  named product route
  standalone `/pill`, `/chat-session`, and `/gate` React routes are retired;
  approvals, session recovery, and intervention review now route back through
  Hypervisor Sessions and Authority surfaces instead of alternate product
  windows.
  the dead package-level `ActivityBar` shell and aggregate `ConnectorsView`
  wrapper are deleted from `@ioi/hypervisor-workbench`; connector UI/hooks now
  live under the Hypervisor Capabilities surface, leaving the package with
  workflow components and runtime primitives only.
  `EnvironmentEstateView` now lives under `apps/hypervisor/src/surfaces/Environments`
  instead of `@ioi/hypervisor-workbench`, so provider/environment posture is a
  Hypervisor shell surface rather than a code-editor/workflow package surface.
  The old bridge/home/agents/builder/catalog subviews and
  catalog-stage modal are deleted. Automations mounts the workflow compositor
  directly; Agents, Models, Authority, Sessions, and Projects are first-class
  Hypervisor shell surfaces rather than nested workflow routes.
  Assistant handoff and session history sidebar components now live under the
  Hypervisor app shell; `@ioi/hypervisor-workbench` no longer exports product
  shell components. The browser-local session-history folder hook moved with
  the sidebar and uses Hypervisor-owned storage/event keys.
  workflow dogfood probes request `automations` as the initial shell surface
  `HYPERVISOR_IOI_REFERENCE_SHELL_REQUIREMENTS` binds the active shell to the
  `internal-docs/reverse-engineering/ioi` reference contract: source reference
  surfaces, translated Hypervisor surfaces, left navigation, New Session,
  session rail, session detail tabs, right inspectors, bottom inspectors,
  settings sections, editor adapter targets, and Agent Harness Adapters
  `ChatLocalActivityBar` derives keyboard navigation from that contract instead
  of a hand-maintained IDE-era list
  `check:runtime-layout` now guards this contract so Phase 0A remains tied to
  the IOI reference cockpit rather than ONA, Tauri, or singular-IDE framing
  active visible chat, workspace, connector, model, and harness-workflow
  surfaces now use Hypervisor labels instead of Autopilot labels; lowercase
  legacy protocol/model IDs remain a separate model-mount compatibility cut.
  workflow output-writer checkpoint identities now use
  `hypervisor.workflow_output_writer_transcript_staging.v1` and are guarded
  against retired `autopilot.workflow_*` checkpoint names.
  active client-owned namespaces now use Hypervisor terms:
  shell storage keys, chat launch keys, chat Vim-mode events, trace/share
  export prefixes, editor theme IDs, command-center route markers, boot
  fallback DOM hooks, capability custom-connection storage keys,
  Workbench local-first model route ids, and the
  `styles/hypervisor-shell/` directory are guarded by `check:runtime-layout`.
  active native-local model mount identities now use Hypervisor terms across
  the daemon defaults, Models surface, contract tests, desktop
  probe, auth audiences, catalog fixtures, and stream evidence refs:
  `provider.hypervisor.local`, `backend.hypervisor.native-local.fixture`,
  `endpoint.hypervisor.native-fixture`, `hypervisor:native-fixture`,
  `hypervisor:gui-lifecycle`, `hypervisor:gui-download`,
  `endpoint.hypervisor.gui-lifecycle`, `hypervisor-local-server`, and
  `fixture://catalog/hypervisor-native-3b-q4`.
  The native-local daemon fixture tests now use the same Hypervisor ids, and
  `check:runtime-layout` rejects the retired Autopilot mount identities.
  Model catalog E2E and CLI validation now search for `hypervisor` catalog
  entries instead of the retired `autopilot` product query, and
  `check:runtime-layout` rejects active `catalog/search?q=autopilot`,
  `catalog/search?query=autopilot`, snapshot `lastSearch.query` assertions, or
  `catalog-search --query autopilot` usage in the model-mounting path.
  Authority Center model-route fixtures now use Hypervisor ids
  (`model-capability:route.hypervisor`, `route.hypervisor`, and
  `model.route.hypervisor`) and `check:runtime-layout` rejects the retired
  `route.autopilot` authority/model-route contract shape.

0A.2 remaining visual implementation:
  Home now carries the full IOI-reference prompt cockpit view; do not add
  second-level session lists, doctrine dashboards, or architecture panels under
  the prompt composer. Active session history belongs in the left session rail
  and Sessions surface.
  the secondary project rail now has a normalized
  `ioi.hypervisor.project_state_projection.v1` loader and
  `/v1/hypervisor/project-state` public runtime route dispatching through
  `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_project_state`. Remaining work is
  deeper interactive project/session actions and broader non-fixture data
  coverage.
  the main canvas now has a first read-only Sessions operations cockpit backed
  by `HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE`; Home now has a
  normalized `ioi.hypervisor.home_cockpit_projection.v1` loader while the
  visible Home surface remains the clean IOI-reference prompt cockpit. Harness
  comparison and cockpit metrics stay in the projection model rather than
  becoming visible Home dashboard chrome.
  `/v1/hypervisor/home-cockpit` is implemented as a public runtime route that
  dispatches through `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_home_cockpit`, returning only the
  client projection body. The app-side hydration seam and daemon route are both
  guarded.
  Sessions now has a normalized
  `ioi.hypervisor.session_operations_projection.v1` loader and
  `/v1/hypervisor/session-operations` public runtime route dispatching through
  `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_session_operations`. The route
  returns only the client projection body and preserves explicit
  fixture-vs-daemon source markers. The projection now owns the visible session
  title, branch label, lifecycle timing labels, resource health, lifecycle step
  evidence, changed-file groups, and ports/services rows so the shell no longer
  hard-codes remote-VM or repository-change placeholders.
  Projects now preserves the same fixture-vs-daemon source marker while
  carrying workspace refs, adapter preference refs, Agentgres object heads,
  state roots, artifact refs, archive refs, restore refs, and receipt refs.
  right and bottom inspectors now render the first session operations panels
  for changes/authority/privacy/receipts/model-provider and
  ports/services/tasks/terminal/logs shape; session operations now have a
  first proposal path for access/log leases, port exposure, task run, terminal
  command review, archive, and restore. Approved operation execution now has a
  first daemon admission boundary that accepts only daemon-authored
  session/provider proposals after wallet approval, wallet lease, Agentgres
  operation refs, receipts, state-root refs, and required archive/restore refs
  are bound. Broader non-fixture project/session data coverage remains follow-up
  work.

0A.5 Workbench direct workspace session is implemented through the primary shell:
  `WorkspaceShell` now mounts the current project directly into the governed
  code-editor workspace substrate through `useWorkspaceSession` and
  `workspaceSessionHost`.
  Workbench no longer owns project creation, workspace gates, news rails,
  recents, favorites, or chooser landings. Projects owns project choice and
  creation; New Session and Settings own default code-editor adapter preference.
  Terminals, VMs, cloud providers, HypervisorOS nodes, and provider posture now
  belong to Sessions, Environments, Providers, and runtime operations rather than
  the Workbench editor-adapter surface.
  The old adapter-state bridge path is deleted: `workspaceAdapterState`,
  `workspaceAdapterStateLifecycle`, and `workspaceInspection` no longer project
  chat, workflows, runs, policy, connectors, artifacts, or product navigation
  into an editor/session adapter. Workspace sessions mount the governed
  files/editor/terminal substrate only; product state stays in Hypervisor
  Home/Sessions/Projects/Automations/Agents/Models/Authority/Receipts surfaces.
  The former Workbench chooser component and its tests are deleted instead of
  preserved as absence-test ballast.
  editor-adapter preference is a real New Session setting and shell launch
  request field
  `codeEditorAdapterPreferences.ts` now owns `CodeEditorAdapterLaunchPlan`,
  converting each adapter preference into a daemon-gated connection contract
  with access leases, authority scopes, receipt policy refs, typed executor
  lanes, typed control actions, and `no_durable_secret_release`. New Session
  receipt previews surface the launch plan and connection contract before
  launch, so editor targets are governed session routes rather than decorative
  editor choices.
  The primary left rail now exposes Workbench directly, and `WorkspaceShell`
  starts the governed code-editor workspace session for the active project
  without an intermediate chooser.
  `runtime-code-editor-adapter-launch-plan-admission.mjs` now admits those launch
  plans through `/v1/hypervisor/code-editor-adapter-launch-plans`, blocking durable
  secret release, adapter-runtime-truth claims, retired provider/VM/node/terminal
  adapter targets, and mismatched editor connection/control contracts.
  `requestCodeEditorAdapterLaunchPlanAdmission` now calls that daemon route from
  New Session launch. `HypervisorLaunchedSessionProjection` records the adapter
  admission as `daemon_admitted`, `daemon_blocked`, or `daemon_unavailable`,
  rather than treating adapter choice as local UI state.
  `CodeEditorAdapterLaunchPlan` and daemon launch admissions now carry
  adapter-specific `executor_lane`, `control_action`, and
  `control_channel_ref` fields for embedded Workbench, desktop editor, browser
  code-editor URL, and browser IDE paths.
  The runtime daemon validates that the control action matches the connection
  kind before admitting the launch plan. Product-facing adapter choice remains in
  New Session and Settings, not in a Workbench chooser.
  Sessions now render each launched session's adapter admission record and
  disable target entry unless the code editor adapter launch plan is
  `daemon_admitted`. `daemon_blocked` and `daemon_unavailable` launches remain
  inspectable as governed session records, but they cannot silently enter the
  target application surface. The session operations projection now also carries
  `selected_adapter_admission_state`, so the active session topbar can disable
  adapter entry from the projection itself instead of hard-coding open controls
  in the client.

0A.4 New Session is partially implemented:
  `HYPERVISOR_SESSION_LAUNCH_RECIPES` defines Mission, Workbench, Agent,
  Automation, Foundry Job, Provider/Environment Job, and Private Workspace
  launch recipes without the retired `fleet_job` identifier
  `HypervisorNewSessionModal` binds project, harness, model route, privacy
  posture, authority scope templates, and receipt preview before launch
  the activity rail and Home dashboard open the shell-level New Session modal
  modal launch routes through the Hypervisor shell controller to the selected
  canonical surface and seeds Sessions when the recipe is a Mission
  `HypervisorNewSessionLaunchSummary` now carries an
  `ioi.hypervisor.new_session_target_binding.v1` target binding for every
  launch. The binding preserves the selected recipe kind, surface, project,
  session route, operator-intent ref, and recipe-specific target refs for
  code editor adapter targets, agent templates, automation recipes, Foundry jobs,
  provider/environment candidates, and private workspaces. The New Session DOM,
  shell controller seed narrative, focused tests, runtime-layout guard, and
  built-shell contract all verify the binding.
  `HypervisorLaunchedSessionProjection` now records every New Session launch,
  regardless of target surface, as a daemon-admitted, daemon-blocked,
  daemon-unavailable, or daemon-admission-pending session route with recipe,
  surface, project, adapter, adapter launch admission, harness, model route,
  authority, privacy, and receipt refs. The Sessions cockpit renders those
  recent launches with admission labels/details and admission-gated surface
  entry, so
  Workbench, Agent, Automation, Foundry, Provider/Environment, and Private
  Workspace sessions remain inspectable as cross-session Hypervisor routes while
  still opening their target application surfaces. Recent launched sessions also
  expose a target-entry action back to the owning Hypervisor surface, making
  Sessions a cross-session switchboard rather than a passive receipt list.

0A.6 Automations / Workflow Compositor projection is implemented:
  `hypervisorAutomationCompositorModel.ts` defines
  `HypervisorAutomationCompositorProjection` for workflow template refs, run
  recipe refs, compositor graph refs, action proposal refs, Agentgres operation
  refs, state roots, receipt refs, context chamber refs, artifact refs, and
  selected project scope.
  `HypervisorShellContent` now wraps `AutomationsWorkflowComposerView` with a
  projection surface that marks fixture-vs-daemon source explicitly through
  `data-automation-compositor-source`. The Workflow Compositor remains the
  graph/proposal editor behind the projection; it is not runtime truth.
  `/v1/hypervisor/automation-compositor` is implemented as a public runtime
  route that dispatches through `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_automation_compositor`, returning
  only the client projection body.
  `check:runtime-layout`, focused app model tests, and public runtime route
  tests guard the schema, loader, source marker, daemon route, API docs, and
  Agentgres/receipt/state-root boundary. Remaining work is live recipe
  execution, schedule mutation, and package promotion after wallet authority
  and Agentgres admission.

0A.6B Insights reference surface is implemented:
  `HypervisorShellContent` now renders Insights as an IOI-reference Enterprise
  product surface with the reference dashboard visual, product actions, and
  usage/productivity/cost use cases. `RuntimeInsightsView` remains mounted
  only inside the hidden
  `data-insights-runtime-projection-boundary="hidden-runs-client"` client so
  runtime analytics can stay wired without becoming the visible product route.
  Focused shell/source tests guard the reference copy, dashboard asset,
  hidden-boundary wrapper, and the absence of a direct raw runs route.

0A.7 Models as infrastructure and setup is implemented:
  `hypervisorModelInfrastructureModel.ts` defines
  `HypervisorModelInfrastructureProjection` over daemon-owned model routes,
  provider endpoints, loaded instances, session bindings, model-weight custody
  policy refs, authority scopes, credential-scope refs, and receipts.
  `HypervisorShellContent` now wraps `ModelMountsSurfaceView` with a Models
  reference-style route workplane: a route list, selected-route detail panel,
  provider posture, session bindings, and policy/receipt chips. Fixture-vs-
  daemon source stays explicit through `data-model-infrastructure-source`, but
  boundary doctrine is not rendered as top-level product copy. The
  model-mounting UI remains a hidden configuration client behind the route
  projection; it does not become model-route or credential truth.
  `/v1/hypervisor/model-infrastructure` is implemented as a public runtime
  route that dispatches through `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_model_infrastructure`, binding
  `project_id` and `session_ref` to the projection request.
  `check:runtime-layout`, focused model tests, shell source tests, and public
  runtime route tests guard the schema, loader, source marker, daemon route,
  API docs, session binding, custody lane, authority scopes, receipt boundary,
  and the absence of the old summary/grid/card dashboard shape. Remaining work
  is live route mutation, provider credential lease flows, and deeper
  model-router admission hydration.

0A.8 first session operations cockpit is implemented:
  `hypervisorSessionOperationsModel.ts` defines
  `HypervisorSessionOperationsProjection` and a daemon-runtime fixture binding
  the canonical session rail, session detail tabs, right inspector panels,
  bottom inspector panels, provider/environment refs, access/log leases,
  archive/restore refs, services, tasks, terminal events, authority scopes, and
  latest receipt refs. The same projection now also binds display title, branch
  label, auto-stop/created/last-started labels, resource-health state,
  environment lifecycle evidence steps, and changed-file groups with receipt
  refs.
  `HypervisorShellContent` renders that projection in the Sessions surface as
  a read-only operations cockpit before the chat/work session view. This makes
  the IOI-reference session-detail tabs and ports/services/tasks/terminal
  inspector implementation-visible without making the client runtime truth.
  The Sessions surface now also exposes session operation proposal buttons for
  access lease, log lease, open port, run task, terminal command review,
  archive session, and restore session. Those actions call
  `/v1/hypervisor/session-operations/proposals`, dispatch through
  `projectRuntimeLifecycle` with
  `runtime.lifecycle_operation.hypervisor_session_operation_proposal`, and
  display an `ioi.hypervisor.session_operation_proposal.v1` proposal carrying
  wallet lease refs, required scope refs, Agentgres operation refs, receipt
  refs, state-root refs, archive refs, and restore refs. If the daemon route is
  unavailable, the client renders an explicitly `unverified` proposal instead
  of executing locally.
  Focused model and shell source tests guard the tab/inspector arrays, lease
  refs, restore refs, projected lifecycle steps, projected changed files,
  projected port/service rows, task rows, terminal events, session operation
  proposal schema, daemon route, and
  `runtimeTruthSource: "daemon-runtime"` boundary.

0A.9 first provider/environment surface cut is implemented:
  `hypervisorProviderPlacementModel.ts` defines
  `HypervisorProviderPlacementProjection` with direct provider candidates for
  local custody, customer/confidential cloud, Akash-style DePIN GPU, Filecoin
  encrypted archive storage, and generic GPU markets. Each candidate carries
  provider refs, privacy posture, wallet authority scopes, Agentgres receipt
  refs, storage policy refs, restore policy refs, and risk labels. The fixture
  explicitly says route catalogs may suggest candidates, but wallet.network
  authorizes spend/secret release and Agentgres records admitted truth.
  `HypervisorShellContent` now renders a Providers dashboard from that
  projection and mounts the live `EnvironmentEstateView` under the Environments
  surface. Providers/Environments therefore move beyond placeholders without
  recreating Fleet or treating a future cloud router as mandatory.
  Providers now has a normalized
  `ioi.hypervisor.provider_placement_projection.v1` loader and
  `/v1/hypervisor/provider-placement` public runtime route dispatching through
  `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_provider_placement`. The route
  returns only the client projection body and preserves explicit
  fixture-vs-daemon source markers.
  Provider cards now expose `request_access_lease`, `launch_session`,
  `zero_to_idle`, `archive`, and `restore` operation proposal buttons. Those
  actions call `/v1/hypervisor/provider-operations`, dispatch through
  `projectRuntimeLifecycle` with
  `runtime.lifecycle_operation.hypervisor_provider_operation_proposal`, and
  display the resulting `ioi.hypervisor.provider_operation_proposal.v1`
  proposal with wallet lease refs, required scope refs, Agentgres operation
  refs, receipt refs, state-root refs, archive refs, and restore refs. Provider
  actions therefore remain proposals until wallet.network grants a scoped lease
  and Agentgres admits lifecycle truth.
  Remaining work is executing the approved provider operation lifecycle against
  real provider adapters after wallet approval and Agentgres admission.

0A.8/0A.10 first receipt evidence surface is implemented:
  `hypervisorReceiptEvidenceModel.ts` defines
  `HypervisorReceiptEvidenceProjection` by composing session lifecycle,
  authority, environment lease, provider placement, artifact restore, and
  harness comparison receipt refs from the existing Hypervisor shell
  projections. Each record binds receipt ref, source projection, Agentgres
  operation refs, artifact refs, trace refs, state root ref, replay ref, and
  status. `HypervisorShellContent` now renders Receipts as an evidence surface
  instead of a placeholder, while tests guard that the client only renders
  daemon/Agentgres evidence projections and does not become receipt truth.
  Receipts now has a normalized
  `ioi.hypervisor.receipt_evidence_projection.v1` loader and
  `/v1/hypervisor/receipt-evidence` public runtime route dispatching through
  `projectRuntimeLifecycle` with
  `runtime.lifecycle_projection.hypervisor_receipt_evidence`, binding
  `project_id` and `session_ref` to the evidence request. The Receipts surface
  marks fixture-vs-daemon source explicitly through
  `data-receipt-evidence-source`, preserving the boundary that clients inspect
  receipt evidence while Agentgres admits receipt truth. Receipt filtering and
  drill-in replay detail are now implemented in the client projection surface:
  operators can filter by kind/status, select a receipt, and inspect replay,
  state-root, operation, artifact, and trace refs without making the client
  receipt truth. Remaining work is durable Agentgres-backed receipt pagination.

0A.8/0A.9 first Privacy/cTEE admission posture surface is implemented:
  `hypervisorPrivacyPostureModel.ts` defines
  `HypervisorPrivacyPostureProjection` for workspace custody segments,
  model-weight custody lanes, provider privacy candidates, admission controls,
  unsafe mount receipts, and runtime truth source. `HypervisorShellContent`
  now renders Privacy as a cTEE/model-custody admission surface instead of a
  placeholder. The fixture intentionally separates private workspace custody
  from proprietary model-weight custody: cTEE can block protected workspace
  plaintext on rented nodes, while proprietary weights require local/open,
  remote API, TEE/customer-cloud, explicit provider-trust, or forbidden mount
  lanes. Remaining work is live admission hydration from daemon model-mount
  routes, provider leases, wallet declassification policy, and Agentgres
  privacy receipts.

0A.3 Projects reference page is corrected and implemented:
  `hypervisorProjectStateModel.ts` defines `HypervisorProjectStateProjection`
  for project/workspace refs, current session refs, environment/provider refs,
  adapter preference, custody posture, restore state, Agentgres object heads,
  state roots, artifact refs, archive refs, restore refs, and latest receipts.
  `HypervisorShellContent` now renders Projects as the IOI-reference Projects
  page: top-level `Projects` heading, `Search projects`, centered `No projects`
  empty state, project education copy, and `New project` action. Project truth
  remains available as hidden `data-*` metadata for conformance/replay, but
  visible product chrome no longer exposes object heads, state roots, restore
  refs, raw Agentgres language, or a code-repository / pull-request console.
  This fixes the boundary: Projects is the project/template surface; Workbench
  owns code repositories, editor choice, terminal/browser adapters, and
  repository recents. Remaining work is live project projection hydration,
  archive/restore operation proposals in the appropriate inspector, and
  paginated project receipt history.

0A.2 first Home cockpit projection is implemented:
  `homeCockpitModel.ts` defines `HypervisorHomeCockpitProjection` by composing
  project restore, active session, privacy gates, provider posture, receipt
  evidence, and harness comparison metrics from the existing Hypervisor Core
  projections. `HomeView` now follows the IOI-reference shape by leading with a
  centered intent composer (`What do you want to get done today?`) that routes
  into New Session while showing project, harness, model-route, and cTEE
  privacy posture hints. The hard cut is visual as well as architectural: Home
  no longer reintroduces a doctrine dashboard under the composer. It uses the
  IOI-reference prompt cockpit as the primary workplane, while evidence,
  receipts, project state, provider posture, and harness comparison remain
  accessible through their owning surfaces. The Home intent composer now seeds
  New Session through the shell-owned modal state: `seed_intent` is normalized
  into `HypervisorNewSessionLaunchSummary`, included in the receipt preview
  binding, shown in the modal setup/summary, and carried into session launch
  seeding when the chosen recipe opens Sessions. This preserves the boundary
  that Home supplies operator intent while New Session binds the governed launch
  contract. Home quickstart templates also seed the initial New Session recipe
  destination for automation, workbench, and Foundry jobs; the modal validates
  the recipe against `HYPERVISOR_SESSION_LAUNCH_RECIPES` before selecting it.
  Durable selected-target parameters are implemented in the client launch
  contract through `HypervisorNewSessionTargetBinding`; remaining work is live
  projection hydration once daemon projections provide real project/session
  destinations.

0A.2 Agents reference-list cut is implemented:
  `HypervisorShellContent` now renders Agents as an IOI-reference list/detail
  workplane instead of a card grid with visible runtime-invariant banners. The
  surface keeps `data-runtime-truth-source`, `data-agent-harness-boundary`, and
  capability-lease attributes for conformance and replay, but the visible UX is
  product-facing: agent rows, status dots, execution labels, readable scope
  summaries, updated timestamps, and a selected detail inspector. Internal
  runtime ownership remains contract metadata only; it does not appear as a
  title, badge, column heading, action label, or explanatory paragraph. The
  source guard keeps the Agents surface on the cockpit-list shape and prevents
  architecture doctrine from becoming visible product copy. Machine-readable
  boundary attributes still preserve `daemon_owned` / `proposal_source_only`
  for replay and conformance. Current verification screenshot:
  `/tmp/hypervisor-agents-visible-boundary-cut/hypervisor-agents.png`.

0A.2 visible doctrine-copy sweep is implemented:
  Product surfaces keep runtime/authority/truth metadata in data attributes and
  model projections, but top-level headers and operation proposals no longer
  render raw invariant strings. Projects, Providers, Environments, Receipts,
  Privacy, and session/provider proposal panels now use operator-facing copy
  that explains the review or action available on that surface. Focused shell
  tests reject direct `*_invariant` JSX bindings and the old Hypervisor Core
  environment-estate header copy so implementation detail does not sit on top
  of the cockpit. Seed project/session/service/receipt labels were also
  renamed away from implementation-layer "Core" phrasing where they are visible
  in the shell.

0A.2 reference-product copy sweep is implemented:
  Home now carries the IOI-reference prompt surface without adding a second
  main-canvas Recent Sessions strip. Application surfaces stay behind the same
  shell, but visible copy avoids daemon/source-of-truth doctrine:
  Agents, Models, and Privacy render product labels such as Private workspace,
  Wallet authority, and Receipt recorded while preserving raw refs only as
  `data-*` attributes for conformance. The auxiliary chat pane remains
  restricted to the conversational Missions surface, so Home, Agents, Models,
  Privacy, and Automations do not show a right-side chat/daemon overlay. The
  focused seed-intent guard now rejects the old Agents doctrine labels, verifies
  the prompt-only Home canvas, and verifies that Models/Privacy format raw refs
  before display.
  The Privacy surface was also moved off the old dark architecture-card island
  and onto the same light reference content plane as Agents and Models; visible
  copy now says Encrypted state refs instead of exposing Agentgres naming.

0A.2 reference-shell cleanup is implemented:
  The left activity rail now follows the IOI reference shell posture more
  closely by rendering a Projects label plus quiet project skeleton rows instead
  of an empty session-list placeholder. This keeps the rail feeling like a
  workspace/session cockpit, not a daemon console.
  Visible boot and error copy now says "Opening the workspace" and "workspace
  shell" rather than "runtime bridge", so implementation plumbing does not sit
  above the product surface.
  Settings now exposes the Advanced section as an operator-configurable panel,
  and the code editor adapter controls render product labels such as Embedded
  code editor, Open embedded, Open desktop, and Local workspace while preserving
  executor lane and control-action refs as metadata. The old Code tab /
  embedded-editor phrasing is now guarded against returning.
  The old Home onboarding walkthrough, condition matrix, and direct editor
  walkthrough assets are deleted from the active tree. Runtime-layout guards
  assert those paths stay absent and that Home remains the IOI-reference prompt
  shell.
  Settings now describes the preference as a Default code editor target, and the
  shell contract rejects the old singular-editor label and helper copy.
  Active shell responsive styles now live in `chat-responsive.css`; the
  `chat-legacy-and-responsive.css` filename is retired and guarded so legacy
  chat naming cannot remain as active product ballast.
  Settings, capabilities, and workflow binding controls now use
  compatibility/previous-config language instead of visible "Legacy ..."
  product labels, while preserving compatibility fields where the graph model
  still needs them.
  Current comparison evidence:
    `/tmp/reference-ioi-current.png`
    `/tmp/hypervisor-agents-current.png`
    `/tmp/hypervisor-settings-current.png`

0A.2/0A.6 IOI-reference Home and Automations parity cut is implemented:
  `HomeView` now matches the IOI reference home posture: left rail session
  heading, centered prompt composer, project/add-context/model controls, prompt
  chips, and no extra main-canvas session table. The default prompt selector
  uses reference chrome (`5.5 Medium`) while model-mounting details remain
  available in Models and New Session instead of sitting on top of the home
  workplane.
  `HypervisorAutomationCompositorSurface` now matches the IOI reference
  automations posture: Webhooks and New actions in the topbar, three summary
  metrics, filter controls, an empty-state workplane, a wider suggested-template
  rail, and product copy for common engineering workflows. Workflow/compositor
  projection data remains present as hidden
  contract/data attributes and behind the editor boundary, but visible
  automation rows are not rendered until the user has created automations.
  Focused source guards reject the old Home recent strip and visible workflow
  template rows, and Playwright probes verify `No automations yet`, Webhooks,
  six suggestions, and zero visible `data-workflow-template-ref` rows.

0A.10 built-shell contract is implemented:
  `scripts/hypervisor-app-shell-contract.mjs` serves the built
  `apps/hypervisor/dist` bundle and verifies the IOI-reference Hypervisor shell
  contract in Chromium. The contract covers the Home prompt shell, New Session launch
  summary, external-harness plus cTEE privacy blocking, redacted-projection
  harness allowance, Projects reference empty state, direct Workbench workspace
  session surface, the reference left rail set
  (`Home`, `Projects`, `Automations`, `Insights`, `Sessions`), and Agents
  product-surface copy that keeps daemon, Agentgres, and wallet implementation
  truth out of the visible default chrome. It also verifies the Settings
  reference shell and governed code editor adapter controls.
  The command is exposed as `npm run check:hypervisor-app-shell` and
  guarded by `check:runtime-layout` plus the lightweight
  `npm run test:hypervisor-app-harness` contract.
```

Code migration posture:

```text
Do not preserve the old IDE-era shell as the parent product.
Do create a fresh Hypervisor Core client shell and progressively remount
valuable existing surfaces under it.
Do not delete model mounting, compositor/workflow, Policy, Settings, or
WorkspaceShell from Hypervisor; do delete adapter-local product chrome and
rehome valuable surfaces under the sharper IA.
Do not clone the IOI mirror literally; translate it:
  New Session, persistent sessions rail, session detail tabs, changes,
  ports/services/tasks/terminal, automations, settings, default code editor target.
Do not make model mounting a lonely infra page; make it contextual in launch.
Do not make Workbench the parent product; make it one surface.
Do not let a code-editor adapter submit chat, workflow, settings, policy,
connections, or product navigation actions back into the app. Code-editor
adapters publish passive context envelopes only; Hypervisor Home, Sessions,
Projects, Workbench, and New Session own product actions.
Do not let a root `ide/` artifact path or Electron/VS Code packaged host define
the product. Root `ide/` is retired; current code editor adapter-host metadata and
ignored local adapter artifacts belong under `code-editor-adapters/`.
Do not preserve Tauri compatibility shims in active app paths. Tauri is legacy;
the old Tauri tree is removed from the active repo, and `src-tauri` must not be
recreated as a live product path.
Do not leave Autopilot proof-runner names in active root package scripts after
their owning runner has a Hypervisor name. Do not keep tracked `.internal/plans`
campaign guides that present retired product shells, Tauri, root `ide/`, or
packages/agent-ide as executable continuation surfaces. Dated `docs/evidence`
may retain old labels as immutable run evidence, but active instructions belong
in this refined guide and current conformance checks.
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
   Insights, Agents, Models, Privacy, Providers, Environments, Foundry,
   Authority, Receipts, Settings.
4. Mount the active project directly in Workbench's code-editor workspace
   surface; keep project creation in Projects and adapter preference in New
   Session/Settings.
5. Add a New Session modal with fixture-backed choices and model/harness/privacy
   summary rows.
6. Add IOI-reference inspectors:
   Changes, Ports & Services, Tasks, Terminal, environment lifecycle,
   access/log leases, SCM auth requirements, and environment health.
7. Add tests/source scans for:
   - visible shell labels use Hypervisor/Home/Sessions/Projects/Workbench;
   - Workbench is a surface, not parent product;
   - model mounting appears in session setup and Models surface;
   - editor preference supports embedded and external adapter modes.
```

Verification ladder:

```text
npm run build --workspace=@ioi/hypervisor-workbench --if-present
npm run build --workspace=@ioi/workspace-substrate --if-present
npm run build --workspace=@ioi/hypervisor-app
node --check touched .mjs files
focused shell/navigation tests
Built-shell contract:
  / -> Hypervisor Home
  New Session opens
  code editor sessions open the current project workspace session
  Automations opens workflow/compositor templates
  Models surface opens daemon model-mount projection
  Changes/Authority/Privacy/Receipts inspector changes with selected session
  Ports & Services / Tasks / Terminal inspector renders for environment session
git diff --check -- apps/hypervisor packages/hypervisor-workbench internal-docs/implementation docs/architecture
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
    | "grok_build_cli"
    | "deepseek_tui"
    | "aider_cli"
    | "openhands"
    | "shell_tmux_agent"
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
| Docker/Podman container | Reproducible harness fixture runs and public workspace tasks. | Useful sandbox; not a root-provider privacy guarantee. |
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
| 0B.5 First public fixture run | Run the same non-sensitive fixture through two adapters where installed. | adapter runner tests, sample workspace | Receipts prove both were mediated by daemon gates. |
| 0B.6 cTEE/private workspace guard | Restrict external harnesses to public trunk/redacted projection unless explicitly allowed. | private workspace policy, adapter runner | Sensitive work cannot be mounted into plain external harness workspace by default. |
| 0B.7 Comparison dashboard | Add HarnessComparisonRun view to Workbench/Foundry. | Hypervisor App Workbench/Foundry surfaces | User can compare adapter output, cost, receipts, and verification results. |

Current implementation cut:

```text
0B.1 Adapter manifest fixtures are implemented in the Hypervisor shell model:
  `apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts`
  defines `AgentHarnessAdapterProfile`, `HarnessAdapterReceipt`,
  `HarnessComparisonRun`, and `HarnessAdapterTestbedFixture`.

  Static adapter manifests exist for:
    Default Harness Profile,
    Codex CLI,
    Codex Desktop Linux,
    Claude Code CLI,
    Grok Build CLI,
    DeepSeek TUI,
    Aider CLI,
    OpenHands,
    shell/tmux agent,
    Generic CLI Harness.

  Each external harness manifest is explicitly an `agent_harness_adapter` with
  `truth_boundary: "proposal_source_only"` and `runtimeTruthSource:
  "daemon-runtime"`.

  `HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE` and
  `HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE` provide a public-trunk fixture
  fixture and same-fixture comparison run before real adapter execution is
  wired. They bind candidate selection refs, acceptance criteria refs, draft
  receipt refs, and the harness adapter receipt schema.

  `HypervisorNewSessionModal` already lists these harness choices beside
  code editor adapter, model route, privacy posture, authority scopes, and receipt
  preview. Compatibility verdicts expose provider-trust, adapter-native-only,
  local-route-unavailable, compatible, and blocked states.

  0B.3's app-side guard is hardened: New Session no longer treats the
  `model-route:hypervisor/default-local` string as proof of local model
  availability. It consumes a `HypervisorModelMountInventorySnapshot` and the
  shared `modelRouteSupportsHypervisorMountFromInventory` verdict, which
  requires an active default-local route plus a mounted endpoint or loaded
  instance. `HypervisorShellWindow` now loads `/v1/model-mount/snapshot` from
  the configured model-mount daemon endpoint, normalizes it into that inventory
  contract, and passes it into New Session. If the daemon is offline, the shell
  remains usable with the fixture contract and visibly reports the fixture
  inventory state instead of silently falling back to a provider lane. Blocked
  and local-route-unavailable verdicts still disable launch.

  `harnessAdapterModel.test.ts` and `check:runtime-layout` guard the adapter
  inventory, daemon-truth boundary, public testbed custody, receipt schema,
  model-route compatibility rule, and anti-patterns.

  0B.4's container lane contract is implemented at the daemon boundary:
  `packages/runtime-daemon/src/runtime-harness-container-lane.mjs` defines
  `HarnessContainerLanePlan` and `HarnessContainerLaneReceipt` semantics for
  Docker/Podman adapter lanes. The plan/receipt bind the selected adapter,
  runtime, container image ref, command argv hash, explicit public/redacted
  mounts, network policy, env policy ref, authority scopes, privacy posture,
  Agentgres refs, artifact refs, and exit status. The contract blocks raw host
  paths, host container sockets, plaintext env maps, secret argv, plaintext
  workspace custody, and cTEE private workspace custody by default. Focused
  tests in `runtime-harness-container-lane.test.mjs` and `check:runtime-layout`
  guard this boundary. The public daemon route
  `/v1/hypervisor/harness-container-lanes` now exposes the same plan and
  not-executed receipt contract for governed adapter launch proposals.

  The executor seam is also mounted at the daemon boundary:
  `packages/runtime-daemon/src/runtime-harness-container-executor.mjs` defines
  `HarnessContainerInvocation` and `executeHarnessContainerLane`. It refuses to
  execute unless the caller supplies the canonical container-lane plan plus the
  exact `command_argv` whose hash matches the admitted plan. It resolves
  container images and workspace mount `source_ref`s through daemon-provided
  resolvers, blocks root paths and host container sockets, requires disabled
  networking for live execution, launches Docker/Podman with no inherited env
  or stdin, and records stdout/stderr only as hashed artifact refs in the
  daemon receipt. This makes the first live process seam implementation-grade
  without turning external harnesses into runtime truth.

  0B.5's first public fixture runner is implemented as a daemon-side contract:
  `packages/runtime-daemon/src/runtime-harness-public-fixture-run.mjs` compares
  installed adapter candidates against the same non-sensitive fixture through
  daemon-planned container lanes. It now passes the planned fixture command argv
  into the executor seam so the executor can verify the admitted command hash
  before launch. It still accepts an injected `executeContainerLane` executor
  for live runs, produces dry-run receipts when no executor is mounted, and
  preserves the container lane private-mount guard. Focused tests prove two
  installed adapters receive the same public fixture, success receipts bind
  Agentgres/artifact refs, insufficient installs block comparison, command hashes
  are preserved into the executor call, and cTEE or plaintext private workspace
  custody remains blocked. The public daemon route
  `/v1/hypervisor/harness-public-fixture-runs` now exposes that comparison
  contract under daemon gates and accepts an injected executor when the daemon
  has a live container lane runner mounted.

  0B.6's first private-workspace guard is implemented at New Session
  selection time: `buildHarnessCompatibilityVerdict` now receives the selected
  privacy posture and blocks external `AgentHarnessAdapter` selections when the
  requested posture is `privacy:ctee-private-workspace`. Default Harness Profile
  remains the compatible cTEE private-workspace path. External harnesses must
  use redacted or public projections unless a future explicit private-workspace
  policy adds a compatible grant.

  0B.7's comparison dashboard is implemented as a governed product path:
  Hypervisor Home keeps a compact New Session preview, and the Foundry surface
  renders a `HarnessComparisonRun` dashboard with candidate output summaries,
  cost estimates, verification status, receipt refs, and evidence posture from
  the same daemon-runtime fixture. Foundry can now request the daemon public
  fixture route through `requestHarnessPublicFixtureRun`; the app builds only
  the public container-adapter request, POSTs to
  `/v1/hypervisor/harness-public-fixture-runs`, normalizes daemon attempts back
  into comparison rows, and records daemon-unavailable state instead of
  executing harnesses locally. Workbench remains the adapter target surface;
  Foundry owns comparison/eval visibility.

  0B.2's launch contract is hardened: `HypervisorNewSessionModal` now emits an
  `ioi.hypervisor.new_session_launch_summary.v1` object binding recipe,
  project, code editor adapter target/custody, harness selection/kind/truth
  boundary, harness verdict, model-route availability, privacy posture,
  authority scopes, receipt preview, and daemon-gate requirement. The
  controller seeds sessions from that summary instead of reconstructing loose UI
  refs. `harnessAdapterModel.test.ts`, `hypervisorShellNavigationModel.test.mjs`,
  and `check:runtime-layout` guard the summary path.
```

First implementation slice:

```text
1. Define `AgentHarnessAdapterProfile`, `HarnessAdapterReceipt`, and
   `HarnessComparisonRun` fixtures. Done for static manifests, public fixture,
   daemon-planned container lanes, and the first daemon-owned executor seam.
2. Add adapter choices to New Session:
   Default Harness Profile, Codex CLI, codex-desktop-linux, Claude Code,
   Grok Build, DeepSeek TUI, Aider, OpenHands, shell/tmux agent, and Generic
   CLI. Done for shell/New Session selection.
3. Add model route choices from the daemon model-mount inventory. Done for the
   shell HTTP boundary: New Session has route options and an inventory-based
   compatibility contract; route labels alone no longer satisfy local
   availability. A future host-bridge command may replace the HTTP fetch, but it
   must preserve the same inventory contract.
4. Add compatibility states:
   compatible, adapter-native only, provider-trust, local-route unavailable.
   Done at static verdict level.
5. Add container lane dry-run receipt for a public fixture workspace. Done for
   the daemon-side Docker/Podman plan, public route, and not-executed receipt
   contract.
6. Add first public fixture comparison. Done for daemon-side injected execution:
   the fixture runner can compare two installed container adapters against the
   same public fixture through the public daemon route and return success or
   dry-run receipts without bypassing daemon gates. The live executor seam now
   verifies command hashes, resolves image/mount refs through the daemon, blocks
   unsafe mount/network cases, and stores output as artifact hashes.
7. Add cTEE/private workspace guard. Done at New Session compatibility level
   for the default external-adapter path; daemon container lanes also continue
   to reject cTEE/private and plaintext workspace mounts.
8. Add comparison dashboard. Done for the first read-only Foundry dashboard:
   Home exposes the compact preview, while Foundry renders output, cost,
   verification, receipts, and evidence from the same `HarnessComparisonRun`
   fixture. Product wiring from Foundry into the daemon public-fixture route is
   implemented through `buildHarnessPublicFixtureRunRequest`,
   `requestHarnessPublicFixtureRun`, and
   `normalizeHarnessComparisonRunFromPublicFixtureRun`.
9. Add source scans proving no external harness bypasses daemon gates. Done for
   static model and runtime-layout guard.
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
container executor seam test
git diff --check -- internal-docs/implementation docs/architecture apps/hypervisor packages/runtime-daemon
```

### Phase 1: Promote Broad Autonomous Labor Canon

| Field | Detail |
| --- | --- |
| Status | Implemented as a canonical docs slice; conformance guard added so aiagent remains an ontology-bound digital and embodied labor substrate rather than drifting back to a digital-worker-only marketplace. First daemon/API adoption implemented through worker-package install admission; live aiagent marketplace endpoints remain follow-up hardening. |
| Files | `aiagent/worker-marketplace.md`, new aiagent ontology/lifecycle docs, `_meta/source-of-truth-map.md`, `_meta/implementation-matrix.md`, `_meta/vocabulary.md`, `README.md`, `_meta/start-here.md` |
| Change | Move broad autonomous labor plan into canonical docs. |
| Acceptance | aiagent definition covers ontology-bound digital and embodied workers; digital-only phrasing is removed or qualified. |
| Verify | `npm run check:architecture-docs`; `git diff --check -- docs/architecture internal-docs/implementation`; `rg -n "DigitalWorkerOntology|VerticalOntologyPack|IntegrationSurface|ManagedWorkerInstanceLifecycle|ManagedAgentConsole|ontology-bound digital and embodied workers" docs/architecture/domains/aiagent docs/architecture/_meta docs/architecture/README.md docs/architecture/START_HERE.md` |

Implementation slice:

`packages/runtime-daemon/src/runtime-worker-package-install-admission.mjs`
now admits `WorkerPackage` install and managed-instance initialization requests
only when they bind the aiagent base ontology, vertical pack refs, integration
surfaces, `prim:*` execution requirements, `scope:*` wallet authority
requirements, policy/evidence/receipt refs, runtime and persistence profiles,
package artifact refs, wallet approval, install/license rights, Agentgres
operation refs, and receipts. Physical-action worker packages must also bind
`PhysicalActionPolicy`, `SafetyEnvelope`, and `EmergencyStopAuthority` refs.
The public route `/v1/hypervisor/worker-package-install-admissions` exposes
the same daemon gate and blocks `prim:*` scopes masquerading as authority,
vertical runtime forks, private-workspace cTEE installs without a cTEE policy,
and physical packages without safety refs.

### Phase 2: Add Physical Action Safety Owner

| Field | Detail |
| --- | --- |
| Status | Implemented as a canonical docs slice on 2026-06-17; daemon-side `PhysicalActionIntent` admission contract implemented, guarded, and exposed through the public Hypervisor daemon route. Live actuator adapters remain follow-up hardening. |
| Files | `foundations/physical-action-safety.md`, common objects, AIIP, DHP, source map, implementation matrix, vocabulary, README, architecture-doc checks |
| Change | Canonized `PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`, `HumanSupervisionPolicy`, `SensorEvidenceReceipt`, `ActuatorCommandReceipt`, and `PhysicalActionIncident` as the safety owner for embodied work. |
| Acceptance | Physical and embodied workers have explicit safety semantics and cannot execute actuator commands as generic tool calls. |
| Verify | `rg -n "PhysicalActionPolicy|SafetyEnvelope|ActuatorCommandReceipt|EmergencyStopAuthority" docs/architecture`; `npm run check:architecture-docs`; `npm run check:runtime-layout` |

Implementation slice:

`packages/runtime-daemon/src/runtime-physical-action-intent-admission.mjs`
now admits physical-action envelopes only when they bind `risk_class:
physical_action`, `prim:physical.*` primitives, `scope:physical.*` authority,
`PhysicalActionPolicy`, `SafetyEnvelope`, `EmergencyStopAuthority`, current
sensor evidence receipts, wallet authority, policy refs, Agentgres operation
refs, and execution receipts. The public route
`/v1/hypervisor/physical-action-intent-admissions` exposes the same daemon
gate. The contract blocks generic `tool.invoke` actuator paths, stale or
untested emergency-stop posture, simulation-only evidence masquerading as
execution, and human-in-loop actions without supervisor refs and wallet
approval.

### Phase 3: Execute Wallet Protocol Packaging Plan

| Field | Detail |
| --- | --- |
| Status | Initial package boundary implemented on 2026-06-17. First Hypervisor product import adoption implemented through the Authority Center grant-review path. Deeper Rust-derived generation remains follow-up hardening. |
| Files | `packages/wallet-protocol`, `packages/wallet-sdk`, `crates/types/src/app/wallet_network`, scripts, conformance |
| Change | Added checked-in wallet protocol package tied to Rust wallet truth and SDK helpers over it. |
| Acceptance | Packages build/test; schemas and fixtures exist; product repo imports packages. |
| Verify | `npm run test:wallet-protocol && npm run test:wallet-sdk && npm run check:wallet-protocol` |

Current hardening slice:

```text
AuthorityReview now carries `allowed_approval_modes` and
`recommended_presentation_profile` in @ioi/wallet-protocol schemas, fixtures,
TypeScript types, and @ioi/wallet-sdk builders. This closes the product/canon
gap where docs said Wallet authority can render as lite cards, standard review,
advanced console, CLI prompt, or mobile sheet while the package only carried a
single chosen approval mode. The package remains protocol truth; Wallet product
surfaces choose presentations from this contract instead of inventing local
authority UI semantics.

Hypervisor Authority Center now depends on `@ioi/wallet-sdk` and embeds a
canonical `AuthorityReview` when it builds scoped grant repair payloads. The
legacy local allowed/denied summary remains for the existing UI path, but the
review object carries canonical `scope:*` requested scopes, approval modes,
presentation profile, risk labels, policy checks, and receipt preview refs. The
wallet packaging conformance guard rejects a return to the retired
`autopilot-authority-center` audience and requires the product import to flow
through `@ioi/wallet-sdk`.
```

### Phase 4: Add cTEE and Model-Weight Custody Lane Table

| Field | Detail |
| --- | --- |
| Status | Canonized as `ModelWeightCustodyProfile` on 2026-06-17; daemon-side model-weight custody admission contract implemented, guarded, and exposed through the public Hypervisor daemon route. Deeper model-router route selection remains follow-up hardening. |
| Files | `private-workspace-ctee.md`, `runtime-nodes-tee-depin.md`, `model-router/doctrine.md`, model-mount API docs |
| Change | Distinguish workspace privacy, model-input privacy, model-output privacy, and model-weight custody. |
| Acceptance | A rented 3090 path cannot be presented as safe for proprietary weights unless TEE/customer/local custody applies. |
| Verify | `node --test packages/runtime-daemon/src/runtime-model-weight-custody-admission.test.mjs`; `npm run check:runtime-layout`; `rg -n "ModelWeightCustodyProfile|forbidden_plaintext_mount|tee_or_customer_cloud_mount|proprietary model weights" docs/architecture packages/runtime-daemon/src` |

Current hardening slice:

```text
`runtime-model-weight-custody-admission.mjs` adds a daemon-side
`ModelWeightCustodyAdmission` contract. It admits public/open, local,
remote-API, TEE/customer-cloud, and explicit provider-trust lanes only when the
required controls, scopes, disclosures, attestation/customer boundary, or trust
acceptance refs are present. It fails closed for forbidden plaintext mounts,
private weights readable by remote provider root, and provider-readable routes
that try to claim `private_native`. `check:runtime-layout` guards the contract
and `/v1/hypervisor/model-weight-custody-admissions` exposes the same admission
boundary through the public daemon API, so cTEE workspace privacy cannot be
confused with model-weight secrecy at route time.
```

### Phase 5: Harden Managed Instance Lifecycle

| Field | Detail |
| --- | --- |
| Status | Canonized on 2026-06-17; daemon-side managed worker lifecycle transition admission contract implemented, guarded, and exposed through the public Hypervisor daemon route. Live aiagent marketplace/product endpoint integration remains follow-up hardening. |
| Files | new `aiagent/managed-worker-instance-lifecycle.md`, worker endpoints, Agentgres artifact refs, wallet APIs |
| Change | Define install, initialize, active, idle, zero-to-idle, suspended, lapsed, archived, restored, exported, deleted. |
| Acceptance | Payment lapse and restore/export/delete behavior are explicit. |
| Verify | `node --test packages/runtime-daemon/src/runtime-managed-worker-instance-lifecycle-admission.test.mjs`; `npm run check:runtime-layout`; `rg -n "lapse|archive_policy|restore_policy|ManagedWorkerInstanceLifecycle" docs/architecture/domains/aiagent docs/architecture/_meta packages/runtime-daemon/src` |

Current hardening slice:

```text
`runtime-managed-worker-instance-lifecycle-admission.mjs` adds a daemon-side
`ManagedWorkerInstanceLifecycleAdmission` contract. It admits canonical
instance state transitions only when lifecycle, owner, Agentgres operation,
receipt, archive, restore, wallet approval, and authority-scope evidence is
present for the transition. It fails closed for payment-lapse deletion, restore
without import refs, archive without Agentgres archive refs/state roots, and
export/delete/forget transitions without explicit wallet authority.
`check:runtime-layout` guards the contract so long-lived aiagent instances
cannot treat subscription lapse, zero-to-idle, archive, restore, export, or
forget as product-console-only state. `/v1/hypervisor/managed-worker-lifecycle-admissions`
now exposes the same admission boundary through the public daemon API for
future aiagent and managed-agent product surfaces.
```

### Phase 6: Add Candidate Evidence Conformance

| Field | Detail |
| --- | --- |
| Status | Canonized and guarded on 2026-06-17; wallet protocol route/trade candidate-evidence validation implemented and guarded; protocol-level route/venue source adapter contracts are implemented and exposed through the Wallet SDK. First source-agnostic HTTP candidate-source client implemented in the Wallet SDK; provider-specific decentralized.exchange/decentralized.trade deployments remain follow-up integration. |
| Files | decentralized exchange/trade docs, Wallet product risk, API scopes, conformance docs |
| Change | Require source, adapter, timestamp, expiry, evidence refs, coverage state, failure conditions for route/trade candidates. |
| Acceptance | Candidate services cannot be hidden trust roots. |
| Verify | `npm run check:candidate-evidence`; `npm run test:wallet-protocol`; `npm run check:wallet-protocol`; `rg -n "CandidateEvidence|coverage_state|expires_at|adapter_id|assertExchangeIntentCandidateEvidence|assertTradeIntentCandidateEvidence" docs/architecture/domains/decentralized docs/architecture/components/wallet-network packages/wallet-protocol` |

Current hardening slice:

```text
`packages/wallet-protocol/src/validation.ts` adds executable candidate-evidence
validators for Wallet Exchange and Trade. `ExchangeIntent` and `TradeIntent`
now carry `candidate_evidence` directly, and the validators fail closed when the
selected route/venue candidate is missing, mismatched, expired, or not
`assessed`. JSON schemas, fixtures, protocol tests, and conformance scans guard
the binding so decentralized.exchange and decentralized.trade remain candidate
sources rather than hidden trust roots. `WalletCandidateSourceAdapter`,
`exchangeRouteSourceAdapter`, `tradeVenueSourceAdapter`, and
`buildCandidateEvidenceFromSourceAdapter` now provide the protocol contract for
route/venue sources to emit executable candidate evidence without becoming
authority, execution, or receipt truth; `@ioi/wallet-sdk` re-exports those
helpers as a thin facade over the protocol package. `@ioi/wallet-sdk` now also
exposes `createHttpCandidateSourceClient()`, a source-agnostic HTTP adapter
that can call route/venue candidate services and only returns evidence after
`assertCandidateEvidenceExecutable()` passes and the returned `source` /
`adapter_id` match the declared adapter. This is the first live network seam
for route-intelligence services while preserving the canon boundary: route
sources propose; Wallet verifies, authorizes, and receipts.
```

### Phase 7: Harden Service Composition Delivery

| Field | Detail |
| --- | --- |
| Status | Canonized and guarded on 2026-06-17; daemon-side `ServiceCompositionReceiptBundle` admission contract implemented, guarded, and exposed through the public Hypervisor daemon route. Live SAS marketplace/product endpoint integration remains follow-up hardening. |
| Files | sas marketplace/endpoints, daemon receipts, marketplace neutrality |
| Change | Add `ServiceCompositionReceiptBundle` defaults for nested contribution, verifier refs, private-data posture, and dispute evidence in service outcomes. |
| Acceptance | Delivery bundle includes worker contribution refs, verifier refs, private-data posture, and dispute evidence. |
| Verify | `node --test packages/runtime-daemon/src/runtime-service-composition-receipt-bundle.test.mjs`; `npm run check:service-composition-evidence`; `rg -n "ServiceCompositionReceiptBundle|ContributionReceipt|delivery bundle|dispute evidence|admitServiceCompositionReceiptBundle" docs/architecture/domains/sas docs/architecture/components/daemon-runtime packages/runtime-daemon/src` |

Current hardening slice:

```text
`runtime-service-composition-receipt-bundle.mjs` adds daemon-side admission for
`ServiceCompositionReceiptBundle`. It requires contribution, verifier, policy,
routing, receipt, dispute-evidence, Agentgres operation, state-root, artifact or
payload refs, and explicit private-data posture. It rejects raw delivery blobs
or provider logs as dispute truth, and blocks unsafe plaintext exceptions from
being marked settlement-ready by default. `check:service-composition-evidence`
guards the runtime contract and `/v1/hypervisor/service-composition-receipt-bundles`
public route alongside the SAS and daemon-runtime canon.
```

### Phase 8: Add Artifact Availability Incident Flow

| Field | Detail |
| --- | --- |
| Status | Canonized and guarded on 2026-06-17; daemon-side `ArtifactAvailabilityIncident` admission contract implemented, guarded, and exposed through the public Hypervisor daemon route. Live Agentgres artifact endpoint integration remains follow-up hardening. |
| Files | Agentgres artifact-ref plane, storage backend doctrine, receipts docs |
| Change | Define incident when payload bytes are missing, corrupt, stale, or unavailable. |
| Acceptance | Agentgres lifecycle and repair receipts govern backend failure. |
| Verify | `node --test packages/runtime-daemon/src/runtime-artifact-availability-incident.test.mjs`; `npm run check:artifact-availability-incident`; `rg -n "ArtifactAvailabilityIncident|missing|invalid|repair receipt|admitArtifactAvailabilityIncident" docs/architecture/components/agentgres docs/architecture/components/storage-backends packages/runtime-daemon/src` |

Current hardening slice:

```text
`runtime-artifact-availability-incident.mjs` adds daemon-side admission for
`ArtifactAvailabilityIncident`. It binds artifact refs, payload refs, storage
backend refs, affected Agentgres object refs, incident receipts, Agentgres
operation refs, and repair/verification/restore refs for fallback, quarantine,
repair, and close flows. It fails closed for missing integrity evidence on
hash/CID failures and blocks silent payload-byte mutation without repair
receipts. `check:artifact-availability-incident` guards the runtime contract
and `/v1/hypervisor/artifact-availability-incidents` public route beside the
Agentgres artifact plane and storage-backend canon.
```

### Phase 9: Update Start Here and Readability Entry Points

| Field | Detail |
| --- | --- |
| Status | Canonized and guarded on 2026-06-17. Further product screenshots/Playwright checks remain Phase 0A implementation work. |
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
- a Hypervisor App UX implementation plan from legacy editor-shell gravity to
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
npm run hypervisor-conformance:docs
npm run hypervisor-conformance:bridge
npm run hypervisor-conformance
rg -n "Executive Verdict|Edge-Case Stress Tests|Coherence Findings|Proposed Patch Plan|Final Doctrine Delta" internal-docs/implementation/refine-architecture.md
rg -n "Hypervisor App UX Master Plan|HypervisorSessionLaunchRecipe|CodeEditorAdapterPreference|HypervisorSessionDetailTab|HypervisorInspectorPanelId" internal-docs/implementation/refine-architecture.md
rg -n "Harness Adapter Testbed|AgentHarnessAdapterProfile|HarnessAdapterReceipt|HarnessComparisonRun" internal-docs/implementation/refine-architecture.md
```

Current conformance command contract:

```text
scripts/conformance/hypervisor-conformance.mjs
  owns the canon-named Hypervisor conformance entrypoint and tier runner.

package.json
  exposes npm run hypervisor-conformance plus docs, abi, bridge, receipts,
  ctee, app, compositor, negative, wallet, and candidates tier commands.

scripts/check-runtime-layout.mjs
  guards the command family so canon/source maps cannot point at a missing
  terminal proof command again.
```
