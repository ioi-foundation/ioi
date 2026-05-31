# Canon Implementation Matrix

Status: canonical implementation index.
Canonical owner: this file for mapping major architecture concepts to canonical owner docs, current durable forms, object/projection status, code anchors, and conformance hooks.
Supersedes: ad hoc implementation-status tables in plans/specs when concept ownership or durable-form status conflicts.
Superseded by: none.
Last alignment pass: 2026-05-30.

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
