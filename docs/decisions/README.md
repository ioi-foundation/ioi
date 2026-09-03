# Architecture Decision Records

This directory contains accepted architecture decisions that should survive
implementation churn, documentation refactors, and context compaction.

ADRs record durable product/protocol/runtime decisions and their consequences.
Canonical architecture prose still lives under `docs/architecture/`; ADRs
explain the accepted decision when that history remains useful.

ADRs neither define nor close proof gates. **Canon defines no `PG-*` identifier
family and confers no authority through one.** Public capability claims bind to
the exact canonical owner status and, where applicable, a released protocol
manifest plus retained evidence. The retired `docs/conformance/` tree is not an
authority source. Any `PG-*` projection appearing in a tracked artifact is
oversight reporting only, never closure authority.

## Proposed ADRs

- [ADR 0039: Propose Finality Profiles Over The Agentgres Verifiable Batch Log](./0039-propose-finality-profiles-over-agentgres-verifiable-batch-log.md) (**Proposed — DESIGN ONLY; no runtime authority change**; supported for review by the M04.9 AFT/Solo parity experiment, while AFT remains the preserved control. Revised 2026-08-28: profile labels reconciled to the canonical `ioi.ordering-admission-finality-profile.v1` enum — the earlier `witnessed_threshold` label conflated admission threshold with witness non-equivocation and now decomposes; the proposed-effect → invariants/conflict-keys → recognition class → weakest-sufficient-mechanism → admitted-effect/receipt derivation added over seven relationship classes K1–K7, where private reasoning and monotone evidence stay authenticated causal evidence until compiled into an admitted operation, and an unknown effect or invariant domain resolves to the adjudication class rather than a weaker default; successor checkpoint/finality field binding and successor preconditions made explicit while `ReceiptCheckpoint` v1 and `ReceiptProofBundle` v1 keep their exact meaning without reinterpretation; a signature now supports only its declared verified claim and by itself proves no guarantee, ordering included. The K1–K7 classes are proposed vocabulary and are not a canonical member set)

## Accepted ADRs

- [ADR 0001: Remove SCS And Adopt `ioi-memory` For Product Memory](./0001-scs-deprecation-and-memory-runtime-successor.md)
- [ADR 0002: Make The IOI Daemon The Canonical Execution Endpoint](./0002-execution-authority-and-client-boundaries.md)
- [ADR 0003: Define Agentgres As Operation-Backed Domain Truth](./0003-agentgres-operation-backed-domain-truth.md)
- [ADR 0004: Define Worker, MoW, And Worker Training As Labor Architecture](./0004-worker-mow-and-training-doctrine.md)
- [ADR 0005: Make Domain Ontologies And Data Recipes The Semantic Data Plane](./0005-domain-ontologies-and-data-recipes.md)
- [ADR 0006: Define Capability, Authority, And Work-Graph Vocabulary](./0006-capability-authority-and-work-graph-vocabulary.md)
- [ADR 0007: Adopt IDE-First Hypervisor With Runtime And Workbench Substrates](./0007-autopilot-ide-first-two-substrate-architecture.md) (superseded by ADR 0013)
- [ADR 0008: Adopt IOI Authority Gateway As The Sidecar Adoption Wedge](./0008-ioi-authority-gateway-sidecar-adoption-wedge.md)
- [ADR 0009: Switch Hypervisor IDE Shell From Tauri To The Electron/VS Code Fork](./0009-switch-autopilot-ide-shell-from-tauri-to-electron-vscode-fork.md) (superseded by ADR 0013)
- [ADR 0010: Define Verifiable Bounded Agency As Execution-Boundary Alignment](./0010-verifiable-bounded-agency-and-execution-boundary-alignment.md)
- [ADR 0011: Canonicalize Hypervisor Nodes As Local Settlement Domains](./0011-hypervisor-nodes-and-governed-autonomous-system-chains.md) (superseded by ADR 0015)
- [ADR 0012: Define IOI As Autonomous-System Settlement Layer And AIIP As Work Interop](./0012-ioi-autonomous-system-settlement-and-aiip.md) (superseded by ADR 0015)
- [ADR 0013: Define Hypervisor Core, Clients, Surfaces, And Adapter Targets](./0013-hypervisor-core-clients-surfaces-and-adapters.md) (refined by ADRs 0014 and 0016)
- [ADR 0014: Make Hypervisor An IDE-Of-IDEs And Session Estate](./0014-hypervisor-ide-of-ides-and-session-estate.md) (refined by ADR 0016)
- [ADR 0015: Define IOI As The Open Operating Stack For Bounded Distributed Autonomous Systems](./0015-bounded-distributed-autonomous-systems-and-network-enrollment.md)
- [ADR 0016: Make Systems And Work The Hypervisor Product Spine](./0016-hypervisor-systems-work-and-application-taxonomy.md)
- [ADR 0017: Separate Goal Pursuit, Directed Work, Skills, Harnesses, And Tools](./0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md)
- [ADR 0018: Adopt Bounded Recursive Improvement Campaigns Without An RSI Engine](./0018-bounded-recursive-improvement-campaign-taxonomy.md)
- [ADR 0019: Adopt GoalRunActivation As The Product-Crossing Admission Contract](./0019-goal-run-activation-product-crossing.md)
- [ADR 0020: Unify GoalRun Admission And Require Resolved Admission Evidence](./0020-unified-goal-run-admission-and-resolved-evidence.md)
- [ADR 0021: Select Sovereign-Local Completeness As The First Flagship Proof](./0021-first-proof-selection-and-attach-lane-sequencing.md)
- [ADR 0022: Make Goal Orchestration An Application Layer And Strip Compatibility Machinery](./0022-goal-orchestration-application-layer-and-clean-slate.md) (amends ADRs 0019 and 0020)
- [ADR 0023: Generalize Improvement Campaigns To Typed Work Subjects And Make Assurance Executable](./0023-improvement-generalization-and-executable-assurance.md) (refines ADRs 0018 and 0022)
- [ADR 0024: Compose The Flagship Institution From Two Activation Modes On One Spine](./0024-two-mode-flagship-composition.md) (refines ADRs 0021 and 0022)
- [ADR 0025: Make The Hypervisor App The Primary Human Attach Journey After Binding](./0025-hypervisor-app-primary-attach-after-binding.md) (refines ADRs 0008, 0013, and 0021)
- [ADR 0026: Separate Deployment, Resource Relationship, And Autonomy Capabilities](./0026-separate-deployment-resource-relationship-and-autonomy-capabilities.md) (refines ADRs 0013, 0016, and 0021)
- [ADR 0027: Require Workload-Bound Isolation For Autonomous Execution](./0027-require-workload-bound-isolation-for-autonomous-execution.md) (refines ADRs 0010, 0013, and 0020)
- [ADR 0028: Reconcile Hypervisor Product-Surface Contracts And Cutover](./0028-reconcile-hypervisor-product-surface-contracts-and-cutover.md) (refines ADRs 0013, 0016, 0021, 0022, and 0024)
- [ADR 0029: Admit Direct GoalRun Paths Explicitly And Use Research For Non-Software Proof](./0029-goalrun-direct-path-admission-and-research-proof-profile.md) (refines ADRs 0017, 0020, and 0022)
- [ADR 0030: Rooms Are A Composition, Not A Primitive Family](./0030-rooms-are-a-composition-not-a-primitive-family.md) (refines ADRs 0003, 0015, 0020, and 0022)
- [ADR 0031: GoalRun Execution Composes Thread Orchestration](./0031-goalrun-execution-composes-thread-orchestration.md) (refines ADRs 0017, 0022, 0029, and 0030)
- [ADR 0032: Define "Independently Implemented Client" By Named Axes](./0032-independently-implemented-client-definition.md) (refines ADRs 0002 and 0013)
- [ADR 0033: License The Protocol Surface Permissively And Define The Licensed Work By Manifest](./0033-licensing-split-surface-and-license-manifest.md) (refines ADR 0015; external counsel review advised before public release relies on it)
- [ADR 0034: Thread Fork Is The Delegation Primitive; Subagents Are Its Surface](./0034-thread-fork-is-the-delegation-primitive-subagents-are-its-surface.md) (refines ADRs 0031 and 0022; agent-proposed under program authority and owner-reversible — review before the WorkLifecycle client interface freezes)
- [ADR 0035: An Environment Is Owned From Its First Durable Byte, And Every Handle To Its Bytes Authorizes](./0035-an-environment-is-owned-where-its-workspace-is-materialized-by-an-authorizing-request.md) (**Proposed — DESIGN ONLY, no code; REVISION 4**; revisions 1–3 were each defeated by their own review, and revision 3's filed dependency was withdrawn because the substrate change it claimed to need already ships under INV-37; closes defect 1a; agent-proposed under program authority and owner-reversible — merge-blocking adversarial review of the DESIGN precedes any implementation)
- [ADR 0036: Hosted Participation Is Native; Discovery Is The Cross-Domain Lane](./0036-hosted-participation-is-native-and-discovery-is-the-cross-domain-lane.md) (refines ADRs 0020, 0022, and 0030; CONTRACT LAYER ONLY — no runtime code lands under it; agent-implemented under program authority and owner-reversible — re-confirm before any daemon handler persists a participation request with a null `room_discovery_ref`)
- [ADR 0037: Room Attempts Retain The Exact Host Admission Owner](./0037-room-attempts-retain-the-exact-host-admission-owner.md) (refines ADRs 0030 and 0036; accepted from live M04.8 evidence so a System-hosted room never fabricates a domain alias)
- [ADR 0038: Split Deterministic Merge Verification From Wallet-Authority Soaks](./0038-split-deterministic-merge-verification-from-wallet-authority-soaks.md) (qualifies verifier claims by mechanism; preserves the full M04.8 real-chain journey as nightly/manual release evidence and tracks its latency as a defect)
- [ADR 0040: Make Machine Authority The Category And IOI Authority The Portable Protocol](./0040-make-machine-authority-the-category-and-ioi-authority-the-portable-protocol.md) (refines ADRs 0008, 0010, 0015, 0032, and 0033; doctrine and ownership only—no wire, runtime, release, or conformance claim change)
- [ADR 0041: Adopt Coordinate-Wise AFT Assurance And Refuse Evidence Laundering](./0041-adopt-coordinate-wise-aft-assurance-and-refuse-evidence-laundering.md) (refines ADR 0039; implemented through the M4 certificate-only/runtime-v3 no-laundering boundary; no externalization, economic, deployment, or final-release claim follows by itself)
- [ADR 0042: Select SLH-DSA For AFT Terminal Seals](./0042-select-slh-dsa-for-aft-terminal-seals.md) (selects FIPS 205 SLH-DSA-SHA2-128s with one enrolled key per terminal slot; release remains blocked on custody, conformance, benchmarks, and independent cryptographic review)
- [ADR 0043: Adopt Mutually Authenticated ML-KEM AFT Channels](./0043-adopt-mutually-authenticated-ml-kem-aft-channels.md) (selects transcript-bound ML-KEM-768, ML-DSA-44 and pairwise AEAD for the normative PQ channel; `channel_pq=true` remains blocked on production swarm integration and review)
- [ADR 0044: Adopt Effect-Native Atomic Externalization](./0044-adopt-effect-native-atomic-externalization.md) (binds consequence manifests before Agentgres admission and proves at-most-once mutation only for an exact atomic idempotency-register resource profile; arbitrary endpoints remain outside the theorem)
- [ADR 0045: Adopt Evidence-Qualified Economic Assurance](./0045-adopt-evidence-qualified-economic-assurance.md) (derives an exact native-asset floor from objective accountability evidence and distinct, live, unencumbered bond snapshots; T8 supply economics and silence remain outside the claim)
- [ADR 0046: Adopt Portable AFT Assurance Receipts](./0046-adopt-portable-aft-assurance-receipts.md) (defines the canonical ML-DSA-signed offline receipt, exact constituent/transform verification, CLI, golden vectors and independent clean-room reproduction; integrated production emission remains M8)
- [ADR 0047: Require Payload-Scoped PQ Path Evidence](./0047-require-payload-scoped-pq-path-evidence.md) (derives the demonstrated receipt's channel, terminal-seal and endpoint PQ coordinates only from exact rooted evidence; the result is payload-scoped and independent cryptographic/custody/channel review remains release-blocking)
- [ADR 0048: Make AFT PQ v1 A Clean Break And Isolate Hypervisor](./0048-make-aft-pq-v1-a-clean-break-and-isolate-hypervisor.md) (keeps the hash-only asynchronous liveness path, closes legacy production/CLI/scalar admission, requires external receipt trust roots, and removes consensus/validator/PQ-seal dependencies from the Hypervisor default profile)
- [ADR 0049: Accept Owner-Commissioned Automated Independent Review For AFT Research Gates](./0049-accept-owner-commissioned-automated-independent-review-for-aft-research-gates.md) (accepts context-isolated Daybreak review for owner-controlled M10/M12 gates with exact automated provenance; does not represent it as human peer review or external certification)
