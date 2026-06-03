# Canon Implementation Matrix

Status: canonical implementation index.
Canonical owner: this file for mapping major architecture concepts to canonical owner docs, current durable forms, object/projection status, code anchors, and conformance hooks.
Supersedes: ad hoc implementation-status tables in plans/specs when concept ownership or durable-form status conflicts.
Superseded by: none.
Last alignment pass: 2026-06-03.

## Purpose

This matrix answers the implementer question:

> **What is this concept, where is it canonically owned, and what durable form should I build today?**

Do not use this file to invent competing doctrine. If a row conflicts with its
canonical owner, update the owner doc first and then update this matrix.

Status values:

```text
canonical object
  needs stable identity, lifecycle, object heads, query, replay, or conflict handling

Agentgres operation
  should be admitted as operation-backed truth, but may not need its own object

event
  runtime-observable transition; may become receipt-backed or projected

receipt
  proof of an accountable transition, decision, invocation, or verification

projection
  rebuildable view over canonical operations, receipts, refs, or artifacts

profile
  configuration/contract applied by daemon/runtime/package

artifact ref
  Agentgres-governed reference to payload bytes held elsewhere
```

## Runtime and Harness Concepts

| Concept | Canonical owner | Current durable form | Promote or keep | Code anchor when known | Conformance hook |
| --- | --- | --- | --- | --- | --- |
| `DefaultHarnessProfile` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | profile metadata, harness activation/projection records, receipts | profile; not a peer runtime | `crates/types/src/app/harness/core.rs`, `crates/types/src/app/harness/receipts.rs` | DHP-1 through DHP-8 |
| `HypervisorOS` | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | bare-metal node profile, boot profile, node measurement receipts, daemon-rooted workload policy | profile; not a peer runtime and not a privacy substitute for cTEE | planned | daemon root rule; no unmanaged workload bypass; boot measurement receipt present |
| `HypervisorOSNode` | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | runtime node object/projection plus boot profile refs, daemon refs, cTEE policy refs, and receipt requirements | promote when node is persistent, billable, restorable, or settlement/dispute eligible | planned | Hypervisor Daemon is node root; forbidden bypasses enforced |
| `HypervisorOSBootProfile` | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | profile manifest binding image/kernel/initrd/daemon/package/driver hashes and secure-boot/TPM posture | profile; object if managed fleet/update/rollback lifecycle needs identity | planned | signed updates and rollback policy checked |
| `HypervisorOSBootReceipt` / `NodeMeasurementReceipt` | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt binding boot epoch, image hash, daemon hash, driver/package manifest hashes, measurement method, and privacy claim | receipt; never enough to claim consumer-GPU plaintext privacy without cTEE/TEE | planned | integrity receipt present; privacy claim cannot exceed measurement profile |
| `PrivateWorkspaceCtee` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | private workspace profile, daemon routing policy, encrypted refs/blobs, receipts | workspace/execution profile; not a hardware TEE claim | planned | private workspace conformance |
| `PrivateWorkspaceNode` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | runtime assignment + Agentgres refs + wallet policy | object/projection when node is persistent, billable, or restorable | planned | no-plaintext protected classes |
| `PrivateWorkspaceCapsule` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | task/workspace capsule envelope plus artifact refs and receipts | promote when replay/dispute/routing needs identity | planned | private workspace capsule checks |
| `PlaintextFreeRuntimeMounting` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | daemon mount discipline for tools, shells, filesystems, model servers, and model calls | profile/discipline; specialize as concrete mount/view objects where audit or replay needs identity | planned | no protected plaintext in untrusted runtime mounts |
| `PlaintextFreeModelMount` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | model mount profile/view, encrypted refs, redacted projections, private handles, `ModelMountReceipt` | promote mount/view when replay, dispute, leakage accounting, or model-route audit needs identity | planned | no protected plaintext in model context; mount receipt present |
| `CustodyType` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | type discipline for whether plaintext may be public, redacted, sealed, guardian-only, crypto-operator-only, capability-only, or never-remote-plaintext | compiler discipline by default; persist manifest hash in proof-bearing runs | planned | every edge into rented node has admissible custody type |
| `CustodyProof` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | verifier-facing proof object binding custody derivation, mount graph, lattice commitments, receipts, leakage budget, and state roots | required when acceptance/dispute/restore/settlement relies on no-plaintext-custody claim | planned | proof verifies against policy, receipts, and state roots |
| `PrivateAgencyTransform` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | reduction from secret-bearing agent step to public proposal plus private selection/declassification/authorization | compiler strategy by default | planned | protected task is candidate-selection-reducible or routed away from rented node |
| `CandidateCoverageProfile` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | scheduler profile for redundancy mass, redundancy phase, coverage target, candidate trace budget, public token budget, schedule, and fallback | promote when CLPD/CLE claims depend on measured coverage | planned | lattice width/depth chosen from coverage frontier, not guesswork |
| `CounterfactualLatticeExecution` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | high-assurance CLPD schedule that expands committed public lattices before private selection feedback | strategy when leakage budget requires lower online selection leakage | planned | lattice committed before private selection feedback |
| `CounterfactualLatticeReceipt` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt binding candidate lattice commitment, width/depth/token budget, generation/dedupe/padding rules, node ref, and state root | receipt when counterfactual selection-leakage claims matter | planned | cannot claim zero online branch-selection leakage without receipt |
| `ExecutionPrivacyPosture` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | posture label for private-native, redacted-API, provider-trust, or unsafe execution paths | required for workers/services/outcomes that may touch private workspace data | planned | private-native not claimed when sensitive plaintext reaches third-party model API |
| `CryptographicOperatorPlane` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | internal cTEE routing plane for FHE/MPC/garbled/ORAM/local/threshold protected subcomputations | discipline by default; concrete policy/receipt when protected operator execution needs audit | planned | protected work not plaintext on node; authority surface is default second party |
| `CryptographicOperatorPolicy` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | policy object with allowed operator families, fallback order, second-party refs, leakage budget, and receipt requirements | promote when workspace or service package relies on private operators | planned | operator policy exists before protected operator routing |
| `PrivateOperatorReceipt` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt binding operator family, protected input commitments, second party, output commitment, leakage profile, and no-plaintext claim | receipt by default; proof object when dispute/replay needs it | planned | protected private-operator result is not admitted without receipt |
| `CandidateLatticePrivateDecoding` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | default execution strategy, candidate lattice commitment, leakage budget fields, `PrivateInferenceReceipt` | strategy by default; promote candidate lattice only when replay, dispute, or verification needs identity | planned | no protected plaintext on node; candidate commitment and leakage budget present |
| `DeterrenceDetectionProfile` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | profile plus `DeterrenceDetectionReceipt`/`CanaryTripReceipt` evidence | profile/receipt; object when marketplace dispute, slashing, or provider attribution needs lifecycle | planned | synthetic canaries only; detection never authorizes plaintext mounting |
| `AutonomyLease` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | wallet authority lease plus policy receipt | canonical authority object when offline autonomy is allowed | planned | capability-exit checks |
| `AccessPointBinding` / `StepUpChallenge` | [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | wallet binding for SMS/email/chat/voice/webhook access points plus short-lived challenge pointer | canonical authority object for persistent agent access rails; challenge is event/receipt-backed pointer, not a grant | planned | low-assurance channels cannot decrypt, declassify, hold grants, release secrets, or approve high-risk actions without step-up |
| `IntentContract` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | run request, resolver receipt, operation payload | promote when multiple components query/rebase it | `crates/services/src/agentic/runtime/service/decision_loop/intent_resolver/instruction_contract.rs` | CIRC, DHP-1 |
| `RuntimePlan` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | plan receipt or projection | promote when plan epochs/replay matter | `crates/types/src/app/harness/core.rs` | DHP-1, DHP-4 |
| `ContextTopology` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | planner projection plus receipts | promote when repartition/replay/cross-actor routing needs object identity | planned | DHP-4 |
| `ContextChamber` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | scoped runtime state, context events, projections | promote when chamber state outlives one turn or is shared | runtime state and compaction paths | DHP-4 |
| `LoopStep` / `LoopIteration` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | event, receipt, trace segment | promote when loop-level replay/verification is first-class | `crates/services/src/agentic/runtime/service/decision_loop/mod.rs` | DHP-2, DHP-3 |
| `ModelPass` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | model invocation receipt plus redacted trace | keep as receipt/trace unless lineage query needs object | cognition and model-router paths | CEC, DHP-6 |
| `ActionProposal` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | action request, runtime item, event | promote when approval/replay/policy review needs identity | `crates/types/src/app/runtime/computer_use.rs`, `crates/node/src/bin/ioi-runtime-bridge.rs` | DHP-2 |
| `GateResult` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | policy/authority decision receipt | receipt now; object if long-lived approval/blocker | policy and approval handlers | DHP-2, CEC phase order |
| `ExecutionResult` | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | workload/tool/worker/service receipt | receipt; artifact refs for large outputs | tool execution processing paths | CEC execution/verification |
| `NormalizedObservation` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | typed event/projection payload | promote when reused by verifiers/downstream tasks | browser observation and completion receipt paths | DHP-3, DHP-6 |
| `OutputOwnershipPass` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | completion receipt plus terminal event | promote for delivery, dispute, replay, marketplace settlement | `crates/services/src/agentic/runtime/service/queue/processing/completion_receipts.rs` | DHP-6 |
| `Blocker` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`daemon-runtime/api.md`](../components/daemon-runtime/api.md) | event plus task state | object when user/operator action or long wait is needed | approval/blocker runtime handlers | DHP-2, DHP-4 |
| `AlphaSeal` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | encrypted/private strategy capsule artifact ref plus policy refs | object when strategy lifecycle, reuse, or audit matters | planned | private strategy checks |
| `DeclassificationGate` / `DeclassificationReceipt` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | policy gate plus receipt | receipt by default; object if long-lived policy state is queried | planned | capability-exit checks |
| `PrivateInferenceReceipt` | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt | proof object | planned | no plaintext on node claim |

## State, Memory, Artifact, and Receipt Concepts

| Concept | Canonical owner | Current durable form | Promote or keep | Code anchor when known | Conformance hook |
| --- | --- | --- | --- | --- | --- |
| `Run` | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md) | Agentgres runtime object | canonical object for serious runs | runtime thread/run records | DHP-1, DHP-7 |
| `Task` / `TaskState` | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md) | Agentgres runtime object | canonical object for serious runs | runtime state objects | DHP-4 |
| `ContextMutation` | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres/doctrine.md`](../components/agentgres/doctrine.md) | Agentgres operation/object-shaped memory admission | canonical when durable behavior-affecting memory changes | memory API and Agentgres object model | memory admission invariant |
| `AgentWiki` | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md) | memory/wiki surface plus projections; durable commits via `ContextMutation` | context-memory plane, not Agentgres truth by itself | memory runtime/API | memory admission invariant |
| `ioi-memory` | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md), [`daemon-runtime/api.md`](../components/daemon-runtime/api.md) | local/runtime memory plane, thread checkpoints, enrichment jobs | keep adjacent to Agentgres; admit durable changes through operations | memory runtime/API | memory admission invariant |
| `ArtifactRef` | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | Agentgres object/ref | canonical ref; bytes live in storage backends | artifact APIs | DHP-5, artifact-ref conformance |
| `PayloadRef` | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | operation payload ref | keep as operation/ref field unless lifecycle needs object | artifact APIs | DHP-5, artifact-ref conformance |
| `EvidenceBundle` | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | Agentgres-governed bundle ref plus receipt/artifact graph | promote when claims, verification, replay, or dispute need bundle identity | evidence/artifact APIs | DHP-5, verification receipt checks |
| `Receipt` | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt object/envelope, indexed through Agentgres | canonical proof object | `crates/types/src/app/harness/receipts.rs` | CEC, DHP-3 |
| `TraceRef` | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | trace ref plus storage payload | ref/projection; payload in storage backend | runtime trace exports | DHP-3 |
| `AgentStateArchive` | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md), [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md) | Agentgres archive ref plus encrypted payload bytes | canonical ref/object; payload in storage backend | planned archive/restore APIs | restore invariant |
| `ProjectionCheckpoint` | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md) | projection state/checkpoint ref | projection, invalidatable/rebuildable | Agentgres projection APIs | projection rebuild checks |
| `DeliveryBundle` | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | delivery artifact refs + receipt bundle + settlement state | object when marketplace/dispute acceptance applies | delivery APIs | DHP-6, DHP-7 |
| `PrivateUserAppStateRef` | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | Agentgres-governed encrypted payload ref plus policy, receipt, authority, and state-root linkage | ref by default; promote when lifecycle, query, restore, dispute, or cross-app portability needs object identity | planned app-state/artifact APIs | private-state split invariant |
| `StorageBackend` | [`storage-backends/doctrine.md`](../components/storage-backends/doctrine.md) | payload byte store profile/config | keep as backend profile unless domain policy needs object identity | storage/artifact APIs | storage backend conformance |
| `FilecoinCASBackend` | [`storage-backends/filecoin-cas.md`](../components/storage-backends/filecoin-cas.md) | storage backend profile | byte availability only; not authority layer | artifact APIs | storage backend conformance |
| Restore/import flow | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | Agentgres operations plus archive payload refs and receipts | operation-backed flow; never silent file mutation | planned archive/restore APIs | restore invariant |

## Authority, Interop, Marketplace, and Settlement Concepts

| Concept | Canonical owner | Current durable form | Promote or keep | Code anchor when known | Conformance hook |
| --- | --- | --- | --- | --- | --- |
| `AuthorityGrant` | [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md), [`wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | grant/lease/approval record | canonical authority object outside Agentgres truth | authority API and approval handlers | DHP-2 |
| `prim:*` | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | primitive execution capability vocabulary | keep as vocabulary, not authority grant | runtime contracts | CIRC capability gates |
| `scope:*` | [`wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md) | wallet/provider authority scope vocabulary | keep as authority vocabulary | authority scope APIs | DHP-2 |
| `WorkerPackage` | [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | manifest/package artifact ref plus registry/listing state | object/listing where installed, published, or routed | worker manifests and harness bindings | marketplace neutrality |
| `ServicePackage` | [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | service manifest/package artifact ref plus optional marketplace contract | object when ordered, installed, or delivered | service APIs | DHP-8 |
| `ServiceEngine` | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | runtime invocation state plus service receipts | object when long-lived or contract-bound | planned service runtime | DHP-2, DHP-6 |
| `MoWRoutingDecision` | [`mixture-of-workers.md`](../foundations/mixture-of-workers.md), [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md) | routing receipt plus Agentgres state | object when payment/reputation/dispute applies | routing receipts | DHP-8 |
| `AIIPEnvelope` | [`aiip.md`](../foundations/aiip.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | signed/sequenced packet envelope | canonical interop envelope | planned AIIP channel/router code | AIIP profile conformance |
| `AIIPChannel` | [`aiip.md`](../foundations/aiip.md) | channel/profile registration and policy state | object when cross-domain interop persists | planned AIIP registry/router | AIIP profile conformance |
| L1 settlement trigger | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) | settlement intent, local settlement receipt, optional L1 commitment | trigger-based commitment, not default runtime event | L1 contract interfaces | DHP-7 |
| Marketplace listing | [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md), [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | listing state, manifest refs, license/contract refs | canonical marketplace object | marketplace APIs | marketplace neutrality |
| ContributionReceipt | [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) | receipt plus attribution graph/projection | object when rewards/reputation/disputes apply | routing/receipt paths | DHP-8 |

## Build Rule

When unsure whether a concept should become a canonical object:

```text
If it only needs observability, emit an event.
If it proves an accountable transition, emit a receipt.
If it changes admitted truth, create an Agentgres operation.
If it is a rebuildable view, make it a projection.
If it points to bytes, create an ArtifactRef/PayloadRef.
If it needs lifecycle, query, replay, conflict handling, or settlement, promote it to a canonical object.
```
